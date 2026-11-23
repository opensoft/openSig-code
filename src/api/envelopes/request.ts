// SPDX-License-Identifier: Apache-2.0
//
// Request plumbing of the operator envelope handlers (T034): the authenticated principal,
// the contract's path parameters and headers, request bodies as JSON values, the mapping of
// domain errors onto contract Error responses, and response bodies.
//
// The server (src/server/app.ts, T031) has already routed the request, authenticated the
// operator and applied the role-by-operation matrix (401/403), and enforced the media type,
// body limits and JSON syntax. What is left here is the contract's request shape:
// - envelope_id and recipient_id match ^[A-Za-z0-9_-]{16,64}$: the router hands over only
//   parameters that match, and answers any other with its uniform 404 not_found before
//   authentication (T031 SEC-04; T006 reading (b) as re-ruled by request #16, row
//   T006-EC22). The handlers check the form again and fail the same way, 404 not_found;
// - Idempotency-Key is required on every mutation and matches ^[A-Za-z0-9_-]{16,128}$,
//   else 400 invalid_request;
// - If-Match on uploadDocument: missing is 428 precondition_required, and a value other than
//   a quoted version ("1", "2", ...) is 400 invalid_request (weak tags included);
// - a JSON body must be a JSON value the canonical module accepts (finite numbers, no lone
//   surrogates, bounded depth): it binds the Idempotency-Key through its RFC 8785 digest, so
//   a body that has no canonical form is 400 invalid_request, never a 500.
// Error details name the member, never its value.

import { CanonicalJsonError, canonicalize, type JsonValue } from '../../domain/canonical/index.ts';
import { EnvelopeError, type Actor } from '../../domain/envelopes/index.ts';
import { HttpError, type HandlerResult, type RequestContext } from '../../server/types.ts';
import { IDEMPOTENCY_KEY_PATTERN } from '../../storage/repositories/idempotency.ts';
import type { OperatorPrincipal } from '../auth/operator.ts';

/** Contract EnvelopeId and RecipientId. */
export const ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
/** Contract IfMatch: the expected envelope version as a quoted string. */
export const IF_MATCH_PATTERN = /^"([1-9][0-9]{0,9})"$/;

export const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';

export function invalid(field: string, code: string): HttpError {
  return new HttpError(400, 'invalid_request', { details: [{ field, code }] });
}

/** The operator principal the server authenticated (operator routes always carry one). */
export function principalOf(ctx: RequestContext): OperatorPrincipal {
  if (ctx.principal === null) throw new HttpError(401, 'unauthenticated');
  return ctx.principal;
}

/** The domain actor of a principal: its kind and opaque tenant-scoped reference. */
export function actorOf(principal: OperatorPrincipal): Actor {
  return { kind: principal.kind, ref: principal.ref };
}

/**
 * Human operators only (confirmSend, void, reissue, resendInvitation). The role matrix already
 * keeps service principals out of these operations; this is the handler's own check of the
 * principal kind (403 forbidden), in front of the domain's.
 */
export function requireHuman(principal: OperatorPrincipal): void {
  if (principal.kind !== 'human-operator') throw new HttpError(403, 'forbidden');
}

/**
 * A path parameter in the contract's identifier form. The router never hands over another;
 * if one arrived, it names nothing, so it is the uniform 404 not_found (request #16).
 */
export function pathId(ctx: RequestContext, name: 'envelope_id' | 'recipient_id'): string {
  const value = ctx.params[name];
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) throw new HttpError(404, 'not_found');
  return value;
}

/** One header value; a repeated header never yields a usable value. */
function header(ctx: RequestContext, name: string): string | undefined {
  const raw = ctx.request.headers[name];
  if (raw === undefined) return undefined;
  if (Array.isArray(raw)) return raw.length === 1 ? (raw[0] ?? '') : '';
  return raw;
}

/** Idempotency-Key (every operator mutation): required, contract pattern. */
export function idempotencyKeyOf(ctx: RequestContext): string {
  const value = header(ctx, 'idempotency-key');
  if (value === undefined) throw invalid('Idempotency-Key', 'required');
  if (!IDEMPOTENCY_KEY_PATTERN.test(value)) throw invalid('Idempotency-Key', 'invalid_format');
  return value;
}

/** If-Match (uploadDocument): missing is 428, a malformed or weak value 400; returns the version. */
export function ifMatchOf(ctx: RequestContext): number {
  const value = header(ctx, 'if-match');
  if (value === undefined) throw new HttpError(428, 'precondition_required');
  const match = IF_MATCH_PATTERN.exec(value);
  if (match === null || match[1] === undefined) throw invalid('If-Match', 'invalid_format');
  return Number(match[1]);
}

/** The JSON request body, checked to have a canonical form (it is digested for idempotency). */
export async function jsonBody(ctx: RequestContext): Promise<JsonValue> {
  const value = await ctx.json();
  try {
    canonicalize(value);
  } catch (error) {
    if (error instanceof CanonicalJsonError) throw invalid('', 'invalid_json');
    throw error;
  }
  return value as JsonValue;
}

/**
 * A domain refusal as the contract Error it names (EnvelopeError carries the code and the
 * status the contract declares for it); anything else is returned unchanged.
 */
export function httpErrorOf(error: unknown): unknown {
  if (error instanceof EnvelopeError) return new HttpError(error.status, error.code, { details: error.details.map((detail) => ({ field: detail.field, code: detail.code })) });
  return error;
}

/** A JSON response whose exact bytes are given (an idempotent replay returns the stored bytes). */
export function bytesResult(status: number, bytes: Uint8Array): HandlerResult {
  return { status, body: bytes, contentType: JSON_CONTENT_TYPE };
}
