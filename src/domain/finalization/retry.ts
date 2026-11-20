// SPDX-License-Identifier: Apache-2.0
//
// retryFinalization, the domain operation behind the tenant_admin route
// (T038; contracts/http-api.yaml retryFinalization; data-model.md
// § Transitions and races, item 3; A-010 requests #28, #59 (4) and (9), #61 (6)).
//
// One BEGIN IMMEDIATE transaction, in the order of T034's keyed mutations
// (src/domain/envelopes/service.ts). The clock is read first, inside the
// transaction (request #82, row RETRY-BOUND), so no other connection can
// commit between the reading and the reads it is compared with. The
// idempotency record's instants (its expiry check and its creation) use that
// reading; the job's instant is the later of it and the job's last write
// (step 4).
// 1. The Idempotency-Key: a live record with the same request digest and
//    principal kind replays its stored 202 bytes and writes nothing; a
//    different request under the key is 409 idempotency_conflict; a record
//    past its 24 hours is deleted and the request runs anew.
// 2. The body is VersionOnly: exactly { expected_version: integer >= 1 }
//    (400 invalid_request otherwise).
// 3. The envelope must exist in the tenant (404 not_found) and be at the
//    caller's expected_version (409 version_conflict). The retry changes the
//    job, never the envelope, so the envelope version stays the reserved
//    version that the publish compares against.
// 4. The retry is accepted only from `retryable` or `failed`; any other
//    status, or no job, is 409 finalization_not_retryable. From `failed` at
//    the limit, max_attempts rises by exactly one (request #59 (4)); once that
//    would pass 100 the answer is 409 finalization_not_retryable with detail
//    { field: 'envelope', code: 'attempt_ceiling' }. The job is written only
//    on an actual transition (request #80 (1), row RETRY-BOUND): the limit
//    raised, `failed` made `retryable`, or a later retry_at brought forward,
//    each leaving the job `retryable` with retry_at = updated_at = the
//    retry's instant. That instant is max(clock, job.updated_at) (request
//    #82), so a retry whose clock stepped back, was read stale or runs skewed
//    in another process finds that job already due and leaves it as it is,
//    and no job instant ever moves backwards. attempt_count is never written,
//    and no approval is created.
// 5. Only on that transition, the audit event `envelope.finalization_retried`,
//    with the operator as actor and the metadata envelope_version,
//    attempt_count and max_attempts. So each attempt is followed by at most
//    one retried event.
// 6. The 202 Envelope body, the envelope as it stands, and its idempotency
//    record; a retry that changed nothing answers the same way, and its key
//    replays that answer.
// A refusal at any step throws inside the transaction: nothing is written.

import { canonicalBytes, type JsonValue } from '../../domain/canonical/index.ts';
import type { AuditWriter } from '../../storage/audit/index.ts';
import type { Database } from '../../storage/db/index.ts';
import { loadEnvelope } from '../../storage/repositories/envelopes.ts';
import {
  deleteIdempotencyRecord,
  findIdempotencyRecord,
  IDEMPOTENCY_KEY_PATTERN,
  IdempotencyBodyTooLarge,
  idempotencyRequestDigest,
  insertIdempotencyRecord,
  isIdempotencyRecordExpired,
  recordedResponse,
} from '../../storage/repositories/idempotency.ts';
import { readJob, retryJob } from '../../storage/repositories/jobs.ts';
import { envelopeView } from '../envelopes/views.ts';
import { ATTEMPT_CEILING_DETAIL, FinalizationError } from './errors.ts';

export const RETRY_ROUTE = 'retryFinalization';
export const RETRY_STATUS = 202;
export const FINALIZATION_RETRIED = 'envelope.finalization_retried';

export interface RetryActor {
  readonly kind: 'human-operator' | 'service';
  readonly ref: string;
}

export interface RetryRequest {
  readonly tenantId: string;
  readonly envelopeId: string;
  readonly actor: RetryActor;
  readonly idempotency: { readonly key: string; readonly request: JsonValue };
}

export interface RetryResult {
  readonly status: number;
  /** The exact response bytes (the RFC 8785 form of the Envelope), replayed byte for byte. */
  readonly bytes: Buffer;
  readonly replayed: boolean;
}

function expectedVersionOf(body: JsonValue): number {
  const invalid = new FinalizationError('invalid_request', 'the request body is invalid', [{ field: 'expected_version', code: 'invalid' }]);
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw invalid;
  const keys = Object.keys(body);
  if (keys.length !== 1 || keys[0] !== 'expected_version') throw invalid;
  const value = (body as { readonly [key: string]: JsonValue })['expected_version'];
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) throw invalid;
  return value;
}

/** One reading of the retry's clock, refused when it is not a date. */
function readClock(clock: () => Date): Date {
  const now = clock();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('the retry clock returned an invalid date');
  return now;
}

export function retryFinalization(db: Database, audit: AuditWriter, request: RetryRequest, options: { readonly clock: () => Date }): RetryResult {
  const { key } = request.idempotency;
  if (typeof key !== 'string' || !IDEMPOTENCY_KEY_PATTERN.test(key)) {
    throw new FinalizationError('invalid_request', 'the Idempotency-Key is invalid', [{ field: 'Idempotency-Key', code: 'invalid_key' }]);
  }
  const digest = idempotencyRequestDigest({ route: RETRY_ROUTE, target: request.envelopeId, request: request.idempotency.request });
  const store = db.forTenant(request.tenantId);
  return db.transaction((): RetryResult => {
    // Inside BEGIN IMMEDIATE (request #82): no other connection commits between this reading and the reads below.
    const now = readClock(options.clock);
    const existing = findIdempotencyRecord(store, RETRY_ROUTE, request.actor.ref, key);
    if (existing !== undefined && isIdempotencyRecordExpired(existing, now)) {
      deleteIdempotencyRecord(store, existing);
    } else if (existing !== undefined) {
      if (existing.requestDigest !== digest || existing.principal.kind !== request.actor.kind) {
        throw new FinalizationError('idempotency_conflict', 'the Idempotency-Key was used with a different request');
      }
      const response = recordedResponse(existing);
      if (response.kind !== 'body') throw new FinalizationError('internal', 'the idempotency record holds no response body');
      return { status: existing.responseStatus, bytes: response.bytes, replayed: true };
    }

    const expectedVersion = expectedVersionOf(request.idempotency.request);
    const aggregate = loadEnvelope(store, request.envelopeId);
    if (aggregate === undefined) throw new FinalizationError('not_found', 'the envelope was not found');
    if (aggregate.envelope.version !== expectedVersion) throw new FinalizationError('version_conflict', 'the envelope version has changed');
    const outcome = retryJob(store, request.envelopeId, now);
    if (outcome.kind === 'refused') {
      throw new FinalizationError(
        'finalization_not_retryable',
        'finalization is not retryable in its current state',
        outcome.reason === 'attempt-ceiling' ? [ATTEMPT_CEILING_DETAIL] : [],
      );
    }
    if (outcome.kind === 'scheduled') {
      const job = readJob(store, request.envelopeId);
      if (job === undefined) throw new FinalizationError('internal', 'the retried job is missing');
      audit.append(request.tenantId, {
        type: FINALIZATION_RETRIED,
        actor: { kind: request.actor.kind, ref: request.actor.ref },
        envelopeId: request.envelopeId,
        metadata: { envelope_version: aggregate.envelope.version, attempt_count: job.attemptCount, max_attempts: job.maxAttempts },
      });
    }
    const refreshed = loadEnvelope(store, request.envelopeId);
    if (refreshed === undefined) throw new FinalizationError('internal', 'the retried envelope is missing');
    const body = envelopeView(refreshed, null);
    let bytes: Buffer | null;
    try {
      bytes = insertIdempotencyRecord(store, {
        route: RETRY_ROUTE,
        principal: { kind: request.actor.kind, ref: request.actor.ref },
        key,
        requestDigest: digest,
        responseStatus: RETRY_STATUS,
        response: { kind: 'body', body },
        resourceId: request.envelopeId,
        createdAt: now.toISOString(),
      });
    } catch (error) {
      if (error instanceof IdempotencyBodyTooLarge) throw new FinalizationError('internal', 'the response exceeds the idempotency record limit');
      throw error;
    }
    return { status: RETRY_STATUS, bytes: bytes ?? canonicalBytes(body), replayed: false };
  });
}
