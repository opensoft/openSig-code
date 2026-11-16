// SPDX-License-Identifier: Apache-2.0
//
// The openSig HTTP application (T031). For every request, in this order:
// 1. a server-generated correlation ID (X-Correlation-Id, and correlation_id in errors);
// 2. routing against the registry: unknown paths, methods or malformed path parameters
//    are a uniform 404 (HEAD is served as GET without a body);
// 3. the Origin allowlist on mutating requests: a present Origin must be listed exactly,
//    and recipient or anonymous routes, which browsers call, must send one (403
//    origin_rejected); operator API clients may omit it;
// 4. authentication and authorization: operator routes need a bearer token accepted by
//    the T005 authenticator and the role and scopes of the matrix (401/403); any
//    Authorization header on a recipient route is a 401, because operators can never use
//    the recipient scheme;
// 5. a declared body length over the route limit is a 413 before any byte is read;
// 6. the handler, or 501 while the owning task has not landed;
// 7. security headers on every response, including errors (src/server/headers.ts).
// Errors are uniform contract Error bodies. An unexpected exception is a 500; the log
// records only its class name and first stack-frame location, never its message. Every
// request is logged once, without query string, headers or body.
//
// Connections (A-009 LBR-2, SEC-08; RFC 9112 section 9.6): requests on one connection are
// handled one at a time, in order. Once a response with `Connection: close` is decided (an
// error with an unread body, a body timeout, or a request that asked for close), the HTTP
// parser is detached from the socket, so no later byte is parsed as a request, and any
// pipelined request already parsed is never dispatched: it gets no handler, no response and
// no `request` log line (`pipelined_request_refused` instead).
//
// Body timing (A-010 LBR4-1, SEC-10): when the per-request body timer (src/server/body.ts)
// fires, the server answers 408 with `Connection: close` at once, whatever the handler is
// doing; the handler's later result is ignored.

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import { performance } from 'node:perf_hooks';

import { authorize, operationScheme, type OperationId } from '../api/auth/matrix.ts';
import type { OperatorAuthenticator, OperatorPrincipal } from '../api/auth/operator.ts';
import type { RouteDefinition } from '../api/routes.ts';
import { checkDeclaredLength, createBodyState, pdfBody, readJsonBody, type BodyState } from './body.ts';
import type { ServerConfig } from './config.ts';
import { errorBody, newCorrelationId } from './errors.ts';
import { RESERVED_HEADERS, securityHeaders, type Framing } from './headers.ts';
import type { Logger } from './redact.ts';
import { HttpError, type HandlerResult, type RequestContext, type StaticHandler } from './types.ts';

const PARAM = '([A-Za-z0-9_-]{16,64})';
const SAFE_METHODS = new Set(['GET', 'HEAD']);

interface CompiledRoute {
  route: RouteDefinition;
  pattern: RegExp;
  names: string[];
}

export interface AppOptions {
  routes: readonly RouteDefinition[];
  config: ServerConfig;
  logger: Logger;
  authenticator: OperatorAuthenticator | null;
  /** Exact allowed origins; may be filled after the listener is bound. */
  allowedOrigins: Set<string>;
  staticHandler?: StaticHandler | null;
  /** 'relay' serves operator routes only (the Hermes Unix-socket listener). */
  surface?: 'public' | 'relay';
}

export interface App {
  handle(req: IncomingMessage, res: ServerResponse): void;
  readonly locals: Map<string, unknown>;
}

function compile(route: RouteDefinition): CompiledRoute {
  const names: string[] = [];
  const source = route.path.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\\?\{([a-z_]+)\\?\}/g, (_match, name: string) => {
    names.push(name);
    return PARAM;
  });
  return { route, pattern: new RegExp(`^${source}$`), names };
}

function pathOf(url: string | undefined): string | null {
  if (url === undefined || !url.startsWith('/')) return null;
  const end = url.search(/[?#]/);
  return end < 0 ? url : url.slice(0, end);
}

/**
 * What an unexpected exception may contribute to the log: its class name and the first
 * stack frame's location. Never its message, which can carry arbitrary request or secret
 * text that no pattern can recognize.
 */
function exceptionSummary(error: unknown): { error_name: string; error_location: string | null } {
  if (!(error instanceof Error)) return { error_name: typeof error, error_location: null };
  const frame = (error.stack ?? '').split('\n').find((line) => line.trimStart().startsWith('at '));
  const location = frame === undefined ? null : (/\(?((?:file:\/\/)?\/[^\s()]+:\d+:\d+)\)?\s*$/.exec(frame)?.[1] ?? null);
  return { error_name: error.name, error_location: location };
}

const LINGER_MS = 2_000;
const LINGER_BYTES = 64 * 1024 * 1024;

const detached = new WeakSet<Socket>();

/**
 * Detach the HTTP parser from `socket` (SEC-08): every later byte goes to `onData` only, so
 * nothing more is parsed as a request. Node feeds its parser straight from the handle until a
 * `data` listener is added; adding ours first moves the input to `data` events, and removing
 * the listeners that were there before (the parser's) leaves ours as the only reader.
 */
function stopParsing(socket: Socket, onData: (chunk: Buffer) => void): void {
  if (detached.has(socket)) return;
  detached.add(socket);
  const parserInput = socket.listeners('data') as Array<(chunk: Buffer) => void>;
  socket.on('data', onData);
  for (const listener of parserInput) socket.removeListener('data', listener);
  socket.resume();
}

/**
 * Lingering close (RFC 9112 section 9.6) after an error response to a request whose body
 * was not read. Closing a socket with unread input makes the kernel reset the connection,
 * which can destroy the response before the client reads it. So the response is followed by
 * a half-close, and the remaining input is discarded (never buffered or parsed: the parser is
 * detached) until the client closes, for at most LINGER_MS or LINGER_BYTES; then the socket
 * is destroyed.
 */
function lingerAfterError(req: IncomingMessage): void {
  const socket = req.socket as Socket & { destroySoon?: () => void };
  const close = (): void => {
    socket.destroy();
  };
  const timer = setTimeout(close, LINGER_MS);
  timer.unref();
  let discarded = 0;
  // Node ends a non-keep-alive response with socket.destroySoon(); make that a half-close.
  socket.destroySoon = () => {
    socket.end();
  };
  socket.once('end', close);
  socket.once('close', () => clearTimeout(timer));
  stopParsing(socket, (chunk: Buffer) => {
    discarded += chunk.length;
    if (discarded > LINGER_BYTES) close();
  });
}

/** Whether the request itself ends the connection (`Connection: close`, or HTTP/1.0 without keep-alive). */
function requestsClose(req: IncomingMessage): boolean {
  const tokens = String(req.headers.connection ?? '')
    .toLowerCase()
    .split(',')
    .map((token) => token.trim());
  if (tokens.includes('close')) return true;
  return req.httpVersion === '1.0' && !tokens.includes('keep-alive');
}

interface Connection {
  /** A response with Connection: close was decided; nothing more is dispatched. */
  closing: boolean;
  /** Settles when the request being handled on this connection is done. */
  tail: Promise<void>;
}

function hasBody(req: IncomingMessage): boolean {
  return req.headers['transfer-encoding'] !== undefined || (req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0');
}

export function createApp(options: AppOptions): App {
  const surface = options.surface ?? 'public';
  const routes = options.routes.filter((route) => surface === 'public' || operationScheme(route.operationId) === 'operator').map(compile);
  const locals = new Map<string, unknown>();
  const logger = options.logger;
  const connections = new WeakMap<Socket, Connection>();

  const match = (method: string, path: string): { route: RouteDefinition; params: Record<string, string> } | null => {
    for (const compiled of routes) {
      if (compiled.route.method !== method) continue;
      const found = compiled.pattern.exec(path);
      if (found === null) continue;
      const params: Record<string, string> = {};
      compiled.names.forEach((name, index) => {
        params[name] = found[index + 1] ?? '';
      });
      return { route: compiled.route, params };
    }
    return null;
  };

  const send = (res: ServerResponse, status: number, framing: Framing, extra: Record<string, string>, body: Uint8Array | null, contentType: string | null): void => {
    for (const [name, value] of Object.entries(extra)) if (!RESERVED_HEADERS.has(name.toLowerCase())) res.setHeader(name, value);
    for (const [name, value] of Object.entries(securityHeaders(framing))) res.setHeader(name, value);
    if (contentType !== null) res.setHeader('content-type', contentType);
    res.setHeader('content-length', String(body?.length ?? 0));
    res.writeHead(status);
    res.end(body ?? undefined);
  };

  const handle = async (req: IncomingMessage, res: ServerResponse, connection: Connection): Promise<void> => {
    const correlationId = newCorrelationId();
    const started = performance.now();
    const bodyState: BodyState = createBodyState();
    const method = req.method ?? 'GET';
    const path = pathOf(req.url);
    let operation: OperationId | null = null;
    let status = 500;
    let errorCode: string | null = null;
    let settled = false;
    res.setHeader('x-correlation-id', correlationId);
    const timing = { idleMs: options.config.limits.bodyIdleMs, graceMs: options.config.limits.bodyRateGraceMs, minBytesPerSecond: options.config.limits.bodyMinBytesPerSecond };

    /** Answer with an error (once); an unread body or a body timeout also closes the connection. */
    const fail = (error: unknown): void => {
      if (settled) return;
      settled = true;
      const httpError = error instanceof HttpError ? error : new HttpError(500, 'internal');
      status = httpError.status;
      errorCode = httpError.code;
      if (!(error instanceof HttpError)) logger.error('handler_exception', { correlation_id: correlationId, operation, ...exceptionSummary(error) });
      if (res.headersSent) {
        res.destroy();
        return;
      }
      const unread = (hasBody(req) && !bodyState.consumed) || bodyState.timedOut;
      const headers: Record<string, string> = { ...httpError.headers };
      if (unread) {
        headers.connection = 'close';
        connection.closing = true;
        lingerAfterError(req);
      }
      const body = Buffer.from(JSON.stringify(errorBody(httpError.code, correlationId, httpError.details)));
      send(res, httpError.status, 'none', headers, body, 'application/json; charset=utf-8');
    };
    bodyState.onTimeout = fail;

    try {
      if (path === null) throw new HttpError(404, 'not_found');
      const lookupMethod = method === 'HEAD' ? 'GET' : method;
      const found = match(lookupMethod, path);
      let principal: OperatorPrincipal | null = null;

      const context = (operationId: OperationId | null, params: Record<string, string>): RequestContext => ({
        operationId,
        params: Object.freeze({ ...params }),
        principal,
        request: req,
        path,
        correlationId,
        logger: logger.child({ correlation_id: correlationId }),
        config: options.config,
        locals,
        json: () => readJsonBody(req, options.config.limits.jsonBytes, bodyState, timing),
        pdf: () => pdfBody(req, options.config.limits.pdfBytes, bodyState, timing),
      });

      if (found === null) {
        if (surface === 'public' && lookupMethod === 'GET' && options.staticHandler) {
          const served = await options.staticHandler(context(null, {}));
          if (served !== null && !settled) {
            settled = true;
            status = served.status;
            return respond(res, served, null);
          }
        }
        throw new HttpError(404, 'not_found');
      }

      const { route, params } = found;
      operation = route.operationId;
      const scheme = operationScheme(operation);

      if (!SAFE_METHODS.has(method)) {
        const origin = req.headers.origin;
        if (origin === undefined) {
          if (scheme !== 'operator') throw new HttpError(403, 'origin_rejected');
        } else if (!options.allowedOrigins.has(origin)) {
          throw new HttpError(403, 'origin_rejected');
        }
      }

      if (scheme === 'operator') {
        const result = options.authenticator
          ? options.authenticator.authenticate(req.headers)
          : ({ ok: false, wwwAuthenticate: 'Bearer' } as const);
        if (!result.ok) throw new HttpError(401, 'unauthenticated', { headers: { 'www-authenticate': result.wwwAuthenticate } });
        principal = result.principal;
        const decision = authorize(operation, principal);
        if (!decision.ok) throw new HttpError(decision.status, decision.code);
      } else if (scheme === 'recipient' && req.headers.authorization !== undefined) {
        throw new HttpError(401, 'unauthenticated');
      }

      if (route.body === 'json') checkDeclaredLength(req, options.config.limits.jsonBytes);
      if (route.body === 'pdf') checkDeclaredLength(req, options.config.limits.pdfBytes);

      const ctx = context(operation, params);
      let result: HandlerResult | null = null;
      if (route.handler !== null) result = await route.handler(ctx);
      else if (operation === 'openReviewShell' && options.staticHandler) result = await options.staticHandler(ctx);
      if (settled) return;
      if (result === null) throw new HttpError(501, 'internal');
      settled = true;
      status = result.status;
      respond(res, result, operation);
    } catch (error) {
      fail(error);
    } finally {
      const fields: Record<string, unknown> = {
        correlation_id: correlationId,
        method,
        path: path ?? '(invalid)',
        operation,
        status,
        duration_ms: Math.round((performance.now() - started) * 10) / 10,
        bytes_read: bodyState.bytesRead,
      };
      if (errorCode !== null) fields.error_code = errorCode;
      logger.info('request', fields);
    }
  };

  const respond = (res: ServerResponse, result: HandlerResult, operation: OperationId | null): void => {
    let body: Uint8Array | null = null;
    let contentType = result.contentType ?? null;
    if (result.json !== undefined) {
      body = Buffer.from(JSON.stringify(result.json));
      contentType = 'application/json; charset=utf-8';
    } else if (result.body !== undefined) {
      body = result.body;
      contentType ??= 'application/octet-stream';
    }
    const framing: Framing =
      operation === 'readRecipientDocument' && result.status === 200 && contentType?.split(';')[0]?.trim() === 'application/pdf' ? 'self' : 'none';
    send(res, result.status, framing, result.headers ?? {}, body, contentType);
  };

  return {
    locals,
    handle(req: IncomingMessage, res: ServerResponse): void {
      const socket = req.socket;
      let connection = connections.get(socket);
      if (connection === undefined) {
        connection = { closing: false, tail: Promise.resolve() };
        connections.set(socket, connection);
      }
      const current = connection;
      const previous = current.tail;
      let done: () => void = () => {};
      current.tail = new Promise<void>((resolveTail) => {
        done = resolveTail;
      });
      void previous.then(async () => {
        try {
          if (current.closing) {
            // SEC-08: a Connection: close response was decided before this pipelined request.
            logger.warn('pipelined_request_refused', { method: req.method ?? 'GET', path: pathOf(req.url) ?? '(invalid)' });
            return;
          }
          await handle(req, res, current);
          if (!current.closing && requestsClose(req)) {
            current.closing = true;
            stopParsing(socket, () => {});
          }
        } catch {
          if (!res.headersSent) res.destroy();
        } finally {
          done();
        }
      });
    },
  };
}
