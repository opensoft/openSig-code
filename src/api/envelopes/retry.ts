// SPDX-License-Identifier: Apache-2.0
//
// The retryFinalization route handler (T038; contracts/http-api.yaml,
// POST /v1/envelopes/{envelope_id}/finalization/retry, 202 Envelope; tenant_admin
// only, scope finalization:retry).
//
// The server (src/server/app.ts, T031) has already applied routing, the Origin
// allowlist, operator authentication and the role-by-operation matrix (401/403)
// and the declared body length. Then, as in T034's idempotent handlers
// (handlers.ts): the principal, the path identifier, the Idempotency-Key header
// (400) and the human-only check (403; a service principal can never retry,
// data-model.md § Authentication); then the key, before the body is
// validated: a complete body that is not JSON under a key this principal
// already used is 409 idempotency_conflict. The domain operation
// (src/domain/finalization/retry.ts) resolves the key, the body, the envelope,
// the version and the job in one transaction, audits a retry that makes an
// actual transition (A-010 request #80 (1)) and returns the exact response
// bytes, replayed byte for byte.
//
// Installation (row ARTIFACT-ROUTES): T038 exports FINALIZATION_HANDLERS and
// withFinalizationHandlers() and installs nothing; ROUTES keeps
// retryFinalization at 501 until the T031 US2 composition slot installs it,
// composes the FinalizationRetryApi under FINALIZATION_RETRY and amends SEC-04.
// A request whose app holds no FinalizationRetryApi is a 500 (fail closed).
// A-010 request #68 A1: this file imports nothing from the composer.

import type { RouteDefinition } from '../routes.ts';
import type { OperationId } from '../auth/matrix.ts';
import type { OperatorPrincipal } from '../auth/operator.ts';
import type { JsonValue } from '../../domain/canonical/index.ts';
import { FinalizationError } from '../../domain/finalization/errors.ts';
import { RETRY_ROUTE, retryFinalization } from '../../domain/finalization/retry.ts';
import type { AuditWriter } from '../../storage/audit/index.ts';
import type { Database } from '../../storage/db/index.ts';
import { findIdempotencyRecord, isIdempotencyRecordExpired } from '../../storage/repositories/idempotency.ts';
import { HttpError, type ErrorCode, type HandlerResult, type RequestContext, type RouteHandler } from '../../server/types.ts';
import { actorOf, bytesResult, idempotencyKeyOf, jsonBody, pathId, principalOf, requireHuman } from './request.ts';

/** The server locals key of the app's FinalizationRetryApi. */
export const FINALIZATION_RETRY = 'opensig.finalization-retry';

export interface FinalizationRetryOptions {
  readonly db: Database;
  readonly audit: AuditWriter;
  readonly clock: () => Date;
}

export class FinalizationRetryApi {
  readonly #options: FinalizationRetryOptions;

  constructor(options: FinalizationRetryOptions) {
    if (typeof options?.clock !== 'function') throw new TypeError('the finalization retry API needs an injected clock');
    this.#options = options;
  }

  /** Whether the key already has a live record for this principal (judged at arrival; a read, no transaction). */
  hasLiveRecord(principal: OperatorPrincipal, key: string): boolean {
    const record = findIdempotencyRecord(this.#options.db.forTenant(principal.tenant_id), RETRY_ROUTE, principal.ref, key);
    return record !== undefined && !isIdempotencyRecordExpired(record, this.#options.clock());
  }

  retry(principal: OperatorPrincipal, envelopeId: string, key: string, body: JsonValue): HandlerResult {
    try {
      const result = retryFinalization(
        this.#options.db,
        this.#options.audit,
        { tenantId: principal.tenant_id, envelopeId, actor: actorOf(principal), idempotency: { key, request: body } },
        { clock: this.#options.clock },
      );
      return bytesResult(result.status, result.bytes);
    } catch (error) {
      if (error instanceof FinalizationError) {
        throw new HttpError(error.status, error.code as ErrorCode, { details: error.details.map((detail) => ({ field: detail.field, code: detail.code })) });
      }
      throw error;
    }
  }
}

function retryApiOf(ctx: RequestContext): FinalizationRetryApi {
  const api = ctx.locals.get(FINALIZATION_RETRY);
  if (!(api instanceof FinalizationRetryApi)) throw new HttpError(500, 'internal');
  return api;
}

export const retryFinalizationHandler: RouteHandler = async (ctx) => {
  const api = retryApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const key = idempotencyKeyOf(ctx);
  requireHuman(principal);
  const recorded = api.hasLiveRecord(principal, key);
  let body: JsonValue;
  try {
    body = await jsonBody(ctx);
  } catch (error) {
    if (recorded && ctx.request.complete && error instanceof HttpError && error.status === 400) throw new HttpError(409, 'idempotency_conflict');
    throw error;
  }
  return api.retry(principal, envelopeId, key, body);
};

/** T038's operation and its handler (installed by the T031 US2 composition slot, never here). */
export const FINALIZATION_HANDLERS: Readonly<Partial<Record<OperationId, RouteHandler>>> = Object.freeze({
  retryFinalization: retryFinalizationHandler,
});

/** `routes` with the retry route's handler installed (every other route unchanged), for T038's tests and T031's slot. */
export function withFinalizationHandlers(routes: readonly RouteDefinition[]): readonly RouteDefinition[] {
  return Object.freeze(
    routes.map((definition) => {
      const handler = FINALIZATION_HANDLERS[definition.operationId];
      return handler === undefined ? definition : Object.freeze({ ...definition, handler });
    }),
  );
}
