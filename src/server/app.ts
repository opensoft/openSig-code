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
//
// Parser errors (A-010 LBR5-1, SEC-11): Node answers bytes its HTTP parser rejects with its own
// canned 400 and destroys the socket, even when a request before those bytes was complete and
// its handler is still working, so that request's response was lost. Pipelined bytes after a
// `Connection: close` request, or extra bytes after a complete body, did that. The server's
// 'clientError' handling (createAppServer) now keeps the pending response instead. The gate is
// the first pending request (the oldest request whose response has not finished): when the
// parser fails and that request is complete, the failing bytes lie after it, whichever later
// request they belong to (junk, a pipelined request after a close, or a malformed request
// already dispatched behind it). Then nothing is written; the parser is detached so nothing
// more is parsed; the connection is closing, so no request behind the first pending one is
// dispatched (as SEC-08); the first pending response is sent with `Connection: close`; and
// the connection closes with the lingering close. Every other client error keeps Node's
// default handling exactly: a malformed request with no response pending, or a malformed body
// inside the first pending request itself, still gets Node's canned 400 (or 413, 431).

import { createServer, STATUS_CODES, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import { performance } from 'node:perf_hooks';
import type { Duplex } from 'node:stream';

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
  /** The server's 'clientError' listener (SEC-11); createAppServer installs it. */
  clientError(error: Error & { code?: string }, socket: Duplex): void;
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
const lingering = new WeakMap<Socket, () => void>();

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
 * Prepare a lingering close (RFC 9112 section 9.6) of `socket`. Closing a socket with unread
 * input makes the kernel reset the connection, which can destroy the response before the
 * client reads it. So from now on the remaining input is discarded (never buffered or parsed:
 * the parser is detached), at most LINGER_BYTES of it, and Node's end-of-response close
 * becomes a half-close. Nothing is closed yet: the returned arm() starts the wait, after which
 * the socket is destroyed when the client closes its side, or after LINGER_MS. Idempotent per
 * socket.
 */
function prepareLinger(socket: Socket): () => void {
  const existing = lingering.get(socket);
  if (existing !== undefined) return existing;
  const close = (): void => {
    socket.destroy();
  };
  let discarded = 0;
  let armed = false;
  // Node ends a non-keep-alive response with socket.destroySoon(); make that a half-close.
  (socket as Socket & { destroySoon?: () => void }).destroySoon = () => {
    socket.end();
  };
  stopParsing(socket, (chunk: Buffer) => {
    discarded += chunk.length;
    if (discarded > LINGER_BYTES) close();
  });
  const arm = (): void => {
    if (armed) return;
    armed = true;
    const timer = setTimeout(close, LINGER_MS);
    timer.unref();
    socket.once('end', close);
    socket.once('close', () => clearTimeout(timer));
  };
  lingering.set(socket, arm);
  return arm;
}

/**
 * Lingering close after an error response to a request whose body was not read: the response
 * is followed by a half-close, and the wait starts at once.
 */
function lingerAfterError(req: IncomingMessage): void {
  prepareLinger(req.socket)();
}

// Node's own responses to client errors (node:_http_server), used unchanged whenever SEC-11
// does not apply.
const NODE_CLIENT_ERROR_STATUS: Readonly<Record<string, number>> = {
  HPE_HEADER_OVERFLOW: 431,
  HPE_CHUNK_EXTENSIONS_OVERFLOW: 413,
  ERR_HTTP_REQUEST_TIMEOUT: 408,
};

function nodeClientErrorResponse(code: string): Buffer {
  const status = NODE_CLIENT_ERROR_STATUS[code] ?? 400;
  return Buffer.from(`HTTP/1.1 ${status} ${STATUS_CODES[status] ?? ''}\r\nConnection: close\r\n\r\n`, 'ascii');
}

/** The response Node has attached to the socket (node:_http_server reads the same fields). */
type SocketWithMessage = Socket & { _httpMessage?: { _headerSent?: boolean } | null };

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
  /** Requests handed to the app, in order, whose response has not finished and that were not refused. */
  pending: IncomingMessage[];
  /** SEC-11: the first pending request when the parser failed; it is still served while closing. */
  lastServed: IncomingMessage | null;
  /** Called when `pending` empties (SEC-11: close once the pending response is sent). */
  whenIdle: (() => void) | null;
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

  const send = (
    res: ServerResponse,
    connection: Connection,
    status: number,
    framing: Framing,
    extra: Record<string, string>,
    body: Uint8Array | null,
    contentType: string | null,
  ): void => {
    for (const [name, value] of Object.entries(extra)) if (!RESERVED_HEADERS.has(name.toLowerCase())) res.setHeader(name, value);
    // A connection that will close says so in its last response (SEC-11).
    if (connection.closing) res.setHeader('connection', 'close');
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
      send(res, connection, httpError.status, 'none', headers, body, 'application/json; charset=utf-8');
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
            return respond(res, connection, served, null);
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
      respond(res, connection, result, operation);
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

  const respond = (res: ServerResponse, connection: Connection, result: HandlerResult, operation: OperationId | null): void => {
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
    send(res, connection, result.status, framing, result.headers ?? {}, body, contentType);
  };

  /**
   * Node's 'clientError' (SEC-11). Gated on the first pending request, not on the request
   * parsed last: when the parser fails and the first pending request is complete, the failing
   * bytes come after it (junk, or a later request, even one already dispatched with a malformed
   * body), and its response is kept. Nothing is written now, the parser is detached and the
   * rest of the input discarded, and the connection is closing. The first pending request is
   * still served (its handler may not have started yet), with Connection: close; every request
   * behind it is refused, as SEC-08 refuses requests after a decided close, so a malformed
   * request never reaches its handler. Once the pending responses are done, the connection
   * half-closes and lingers. Every other client error gets Node's default handling, unchanged:
   * an incomplete first pending request owns the failing bytes itself.
   */
  const clientError = (error: Error & { code?: string }, stream: Duplex): void => {
    const socket = stream as SocketWithMessage;
    const code = typeof error.code === 'string' ? error.code : '';
    const connection = connections.get(socket);
    const first = connection?.pending[0];
    if (
      connection !== undefined &&
      first !== undefined &&
      code.startsWith('HPE_') &&
      first.complete &&
      socket.writable &&
      !socket.destroyed
    ) {
      connection.closing = true;
      connection.lastServed ??= first;
      const arm = prepareLinger(socket);
      connection.whenIdle = () => {
        if (socket.destroyed) return;
        socket.end();
        arm();
      };
      logger.warn('parse_error_while_response_pending', { parser_error: code, pending_responses: connection.pending.length });
      return;
    }
    // Node's default (node:_http_server socketOnError): its canned response, unless a response
    // already started on this socket, then destroy the socket.
    const message = socket._httpMessage;
    if (socket.writable && (!message || !message._headerSent)) socket.write(nodeClientErrorResponse(code));
    socket.destroy(error);
  };

  return {
    locals,
    clientError,
    handle(req: IncomingMessage, res: ServerResponse): void {
      const socket = req.socket;
      let connection = connections.get(socket);
      if (connection === undefined) {
        connection = { closing: false, tail: Promise.resolve(), pending: [], lastServed: null, whenIdle: null };
        connections.set(socket, connection);
      }
      const current = connection;
      // Recorded at once, while Node may still be parsing the rest of the packet (SEC-11).
      current.pending.push(req);
      let released = false;
      const release = (): void => {
        if (released) return;
        released = true;
        // Responses finish in order, so this is almost always the first entry.
        if (current.pending[0] === req) current.pending.shift();
        else current.pending.splice(current.pending.indexOf(req), 1);
        if (current.pending.length === 0) current.whenIdle?.();
      };
      res.once('finish', release);
      res.once('close', release);
      const previous = current.tail;
      let done: () => void = () => {};
      current.tail = new Promise<void>((resolveTail) => {
        done = resolveTail;
      });
      void previous.then(async () => {
        try {
          if (current.closing && req !== current.lastServed) {
            // SEC-08: a Connection: close response was decided before this pipelined request
            // (or, SEC-11, the parser failed while an earlier response was pending).
            logger.warn('pipelined_request_refused', { method: req.method ?? 'GET', path: pathOf(req.url) ?? '(invalid)' });
            release();
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

/** An HTTP server for `app`: its request handler and its client-error handling (SEC-11). */
export function createAppServer(app: App): Server {
  const server = createServer(app.handle);
  server.on('clientError', app.clientError);
  return server;
}
