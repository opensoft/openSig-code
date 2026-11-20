// SPDX-License-Identifier: Apache-2.0
//
// The fenced durable steps of a finalization attempt other than the publish
// (T038; data-model.md § Transitions and races, items 2 and 3; A-010 request
// #59 (5), (8) and request #61 (4), (5)). Each runs in its own BEGIN IMMEDIATE
// transaction and writes nothing once the attempt's lease is lost.
//
// - writeSealAnchor: the first attempt to begin composing writes
//   `envelope.seal_started` once; every later attempt reads it and uses its
//   server_time as T036's sealTime (request #59 (5)). It is the compose
//   phase's first durable write (request #61 (4)).
// - writeCompletionCheckpoint: T029's completion checkpoint (0006: unique per
//   envelope, append-only) is written once, at package assembly; a retry
//   reuses it and builds the receipt up to the head it records.
// - recordBlob: the FinalizationAttemptBlob record, before the blob write.
// - failAttempt and reclaimLease: a move into `failed`, at the limit or for a
//   non-retryable failure, writes `envelope.finalization_failed` to the outbox
//   (with the envelope's unchanged version) and the audit event of the same
//   type, once, in the transaction that sets the status (request #59 (8)). A
//   retryable outcome writes neither; the job row's last_error_code and
//   retry_at show it. reclaimLease is fenced on the strictly expired lease, so
//   exactly one reclaimer acts (request #61 (5)).
// Audit metadata name the attempt (`attempt`) and the code (`error_code`),
// never a token value, a key or document content.

import type { AuditWriter } from '../../storage/audit/index.ts';
import type { Database, TenantStore } from '../../storage/db/index.ts';
import { enqueueOutboxEvent } from '../../storage/outbox/index.ts';
import { getCompletionCheckpoint, type CompletionCheckpointRow } from '../../storage/repositories/artifacts.ts';
import { getEnvelope } from '../../storage/repositories/envelopes.ts';
import {
  leaseHeld,
  readJob,
  reclaimExpiredLease,
  recordAttemptBlob,
  recordAttemptFailure,
  type AttemptBlobRole,
  type FailureOutcome,
  type LeaseHolder,
  type ReclaimOutcome,
} from '../../storage/repositories/jobs.ts';
import type { FailureVerdict } from './failure.ts';

/** The audit actor of the finalization runner's events. */
export const FINALIZATION_ACTOR_REF = 'finalization-runner';
export const SEAL_STARTED = 'envelope.seal_started';
export const FINALIZATION_FAILED = 'envelope.finalization_failed';

export interface StepContext {
  readonly db: Database;
  readonly audit: AuditWriter;
  readonly tenantId: string;
  readonly clock: () => Date;
  /** Outbox event id source (default: T030's random id). */
  readonly newEventId?: () => string;
}

export interface SealAnchor {
  readonly seq: number;
  readonly digest: string;
  /** The anchor's server_time: T036's sealTime and the manifest's /M. */
  readonly sealTime: string;
}

function now(context: StepContext): Date {
  const value = context.clock();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new TypeError('the finalization clock returned an invalid date');
  return value;
}

function existingAnchor(store: TenantStore, envelopeId: string): SealAnchor | undefined {
  const row = store.list('audit_events', { envelope_id: envelopeId, type: SEAL_STARTED }, { orderBy: [['seq', 'asc']], limit: 1 })[0];
  if (row === undefined) return undefined;
  return { seq: Number(row['seq']), digest: String(row['event_digest']), sealTime: String(row['server_time']) };
}

/** The envelope's seal anchor, written once (fenced) or reused. Null: the lease is lost and nothing was written. */
export function writeSealAnchor(context: StepContext, holder: LeaseHolder): SealAnchor | null {
  const at = now(context);
  const store = context.db.forTenant(context.tenantId);
  return context.db.transaction((): SealAnchor | null => {
    if (!leaseHeld(store, holder, at)) return null;
    const existing = existingAnchor(store, holder.envelopeId);
    if (existing !== undefined) return existing;
    const appended = context.audit.append(context.tenantId, {
      type: SEAL_STARTED,
      actor: { kind: 'system', ref: FINALIZATION_ACTOR_REF },
      envelopeId: holder.envelopeId,
      metadata: { attempt: holder.fencingToken },
    });
    return { seq: appended.seq, digest: appended.digest, sealTime: appended.serverTime };
  });
}

/** The envelope's completion checkpoint, written once (fenced) or reused. Null: the lease is lost. */
export function writeCompletionCheckpoint(context: StepContext, holder: LeaseHolder): CompletionCheckpointRow | null {
  const at = now(context);
  const store = context.db.forTenant(context.tenantId);
  return context.db.transaction((): CompletionCheckpointRow | null => {
    if (!leaseHeld(store, holder, at)) return null;
    const existing = getCompletionCheckpoint(store, holder.envelopeId);
    if (existing !== undefined) return existing;
    const written = context.audit.checkpointCompletion(context.tenantId, holder.envelopeId);
    return { seq: written.seq, digest: written.digest, created_at: written.created_at };
  });
}

/** Record a blob ref before writing it (fenced). False: the lease is lost. */
export function recordBlob(context: StepContext, holder: LeaseHolder, blobRef: string, role: AttemptBlobRole): boolean {
  const at = now(context);
  const store = context.db.forTenant(context.tenantId);
  return context.db.transaction(() => recordAttemptBlob(store, holder, { blobRef, role, now: at }));
}

function announceFailure(context: StepContext, store: TenantStore, envelopeId: string, attempt: number, errorCode: string, at: Date): void {
  const envelope = getEnvelope(store, envelopeId);
  if (envelope === undefined) throw new TypeError('the failed job’s envelope is missing');
  context.audit.append(context.tenantId, {
    type: FINALIZATION_FAILED,
    actor: { kind: 'system', ref: FINALIZATION_ACTOR_REF },
    envelopeId,
    metadata: { attempt, error_code: errorCode },
  });
  enqueueOutboxEvent(context.db, context.tenantId, { type: FINALIZATION_FAILED, envelopeId, envelopeVersion: envelope.version }, { clock: () => at, newId: context.newEventId });
}

/** Record the attempt's failure under its lease; a move into `failed` is announced once. */
export function failAttempt(context: StepContext, holder: LeaseHolder, verdict: FailureVerdict): FailureOutcome {
  const at = now(context);
  const store = context.db.forTenant(context.tenantId);
  return context.db.transaction((): FailureOutcome => {
    const outcome = recordAttemptFailure(store, holder, { now: at, retryable: verdict.retryable, errorCode: verdict.errorCode });
    if (outcome === 'failed') announceFailure(context, store, holder.envelopeId, holder.fencingToken, verdict.errorCode, at);
    return outcome;
  });
}

/** Reclaim a strictly expired lease; at the limit the move into `failed` is announced once. */
export function reclaimLease(context: StepContext, envelopeId: string): ReclaimOutcome {
  const at = now(context);
  const store = context.db.forTenant(context.tenantId);
  return context.db.transaction((): ReclaimOutcome => {
    const before = readJob(store, envelopeId);
    const outcome = reclaimExpiredLease(store, envelopeId, at);
    if (outcome === 'failed' && before !== undefined && before.fencingToken !== null) {
      const after = readJob(store, envelopeId);
      announceFailure(context, store, envelopeId, before.fencingToken, after?.lastErrorCode ?? 'lease_expired.reclaimed', at);
    }
    return outcome;
  });
}
