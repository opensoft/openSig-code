// SPDX-License-Identifier: Apache-2.0
//
// Shared server types (T031): the handler contract that later tasks implement in the
// route registry (src/api/routes.ts), and the HttpError that handlers throw to produce a
// uniform contract Error body.

import type { IncomingMessage } from 'node:http';

import type { OperatorPrincipal } from '../api/auth/operator.ts';
import type { OperationId } from '../api/auth/matrix.ts';
import type { ServerConfig } from './config.ts';
import type { Logger } from './redact.ts';

/** Contract Error codes (components.schemas.Error.properties.code). */
export type ErrorCode =
  | 'invalid_request'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'version_conflict'
  | 'state_conflict'
  | 'order_conflict'
  | 'idempotency_conflict'
  | 'confirmation_required'
  | 'confirmation_invalid'
  | 'not_completed'
  | 'payload_too_large'
  | 'unsupported_media_type'
  | 'unsupported_pdf'
  | 'field_out_of_bounds'
  | 'unsupported_characters'
  | 'rate_limited'
  | 'locked'
  | 'csrf_failed'
  | 'origin_rejected'
  | 'digest_mismatch'
  | 'consent_mismatch'
  | 'finalization_not_retryable'
  | 'destination_not_allowed'
  | 'precondition_required'
  | 'internal';

export interface ErrorDetail {
  field: string;
  code: string;
}

export class HttpError extends Error {
  readonly status: number;
  readonly code: ErrorCode;
  readonly details: readonly ErrorDetail[];
  readonly headers: Readonly<Record<string, string>>;

  constructor(status: number, code: ErrorCode, options: { details?: ErrorDetail[]; headers?: Record<string, string> } = {}) {
    super(code);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.details = options.details ?? [];
    this.headers = options.headers ?? {};
  }
}

export interface HandlerResult {
  status: number;
  /** A JSON body (serialized as application/json). */
  json?: unknown;
  /** A byte body, sent with `contentType`. */
  body?: Uint8Array;
  contentType?: string;
  /** Extra headers; security headers always override these. */
  headers?: Record<string, string>;
}

export interface RequestContext {
  readonly operationId: OperationId | null;
  readonly params: Readonly<Record<string, string>>;
  readonly principal: OperatorPrincipal | null;
  readonly request: IncomingMessage;
  readonly path: string;
  readonly correlationId: string;
  readonly logger: Logger;
  readonly config: ServerConfig;
  /** App-scoped storage for handler singletons (for example an opened database). */
  readonly locals: Map<string, unknown>;
  /** The JSON body (application/json, at most config.limits.jsonBytes; 413 while streaming). */
  json(): Promise<unknown>;
  /** The PDF body as chunks (application/pdf, at most config.limits.pdfBytes; 413 while streaming). */
  pdf(): AsyncIterable<Uint8Array>;
}

export type RouteHandler = (ctx: RequestContext) => Promise<HandlerResult>;

/** Optional static handler (src/server/static.ts, T035): returns null when it serves nothing. */
export type StaticHandler = (ctx: RequestContext) => Promise<HandlerResult | null>;
