// SPDX-License-Identifier: Apache-2.0
//
// Transactional outbox. enqueueOutboxEvent() inserts the event inside the
// caller's Database.transaction(), the same BEGIN IMMEDIATE transaction as the
// state change it announces, so the event exists exactly when that change
// committed. The event_id is fixed at insertion and the stored payload is the
// canonical (RFC 8785) WebhookEvent body including that event_id, so every
// delivery attempt sends identical bytes with the same event_id.
//
// The T003 schema backs this up: event_id is unique, identity and payload
// columns are immutable, attempts only grow, rows are never deleted, and an
// envelope has at most one envelope.completed event.

import { randomBytes } from 'node:crypto';

import { canonicalBytes, canonicalize, type JsonValue } from '../../domain/canonical/index.ts';
import type { Database } from '../db/connection.ts';
import { StorageUsageError } from '../db/errors.ts';

export const OUTBOX_SCHEMA_VERSION = '1';
export const WEBHOOK_EVENT_TYPES: readonly string[] = Object.freeze([
  'envelope.sent',
  'envelope.completed',
  'envelope.declined',
  'envelope.expired',
  'envelope.voided',
  'envelope.finalization_failed',
]);

const ID = /^[A-Za-z0-9_-]{16,64}$/;
const DIGEST = /^[0-9a-f]{64}$/;

export interface OutboxEventInput {
  readonly type: string;
  readonly envelopeId: string;
  /** The envelope version after the announced change (must be the current version). */
  readonly envelopeVersion: number;
  readonly artifactId?: string | null;
  readonly artifactDigest?: string | null;
}

/** The contract WebhookEvent body. */
export interface WebhookEventPayload {
  readonly event_id: string;
  readonly schema_version: string;
  readonly type: string;
  readonly envelope_id: string;
  readonly envelope_version: number;
  readonly artifact_id: string | null;
  readonly artifact_digest: string | null;
  readonly occurred_at: string;
}

export interface EnqueuedOutboxEvent {
  readonly eventId: string;
  readonly payload: WebhookEventPayload;
  /** The exact bytes every delivery attempt sends. */
  readonly body: Buffer;
}

export interface EnqueueOptions {
  readonly clock: () => Date;
  readonly newId?: () => string;
}

function defaultEventId(): string {
  return `evt-${randomBytes(16).toString('base64url')}`;
}

function checkInput(input: OutboxEventInput): void {
  if (typeof input !== 'object' || input === null) throw new StorageUsageError('outbox event input is required');
  if (!WEBHOOK_EVENT_TYPES.includes(input.type)) throw new StorageUsageError('outbox event type is not a webhook event type');
  if (typeof input.envelopeId !== 'string' || !ID.test(input.envelopeId)) throw new StorageUsageError('envelope id is malformed');
  if (!Number.isSafeInteger(input.envelopeVersion) || input.envelopeVersion < 1) {
    throw new StorageUsageError('envelope version must be a positive integer');
  }
  const artifactId = input.artifactId ?? null;
  const artifactDigest = input.artifactDigest ?? null;
  if (input.type === 'envelope.completed') {
    if (typeof artifactId !== 'string' || !ID.test(artifactId) || typeof artifactDigest !== 'string' || !DIGEST.test(artifactDigest)) {
      throw new StorageUsageError('envelope.completed needs the artifact id and digest');
    }
  } else if (artifactId !== null || artifactDigest !== null) {
    throw new StorageUsageError(`${input.type} carries no artifact`);
  }
}

/**
 * Insert an outbox event inside the caller's transaction. The envelope must
 * exist in the tenant and its current version must equal envelopeVersion.
 */
export function enqueueOutboxEvent(db: Database, tenantId: string, input: OutboxEventInput, options: EnqueueOptions): EnqueuedOutboxEvent {
  if (!db.inTransaction) throw new StorageUsageError('outbox events are inserted inside the transaction of the state change');
  if (typeof options?.clock !== 'function') throw new StorageUsageError('the outbox needs an injected clock');
  checkInput(input);
  const store = db.forTenant(tenantId);
  const envelope = store.get('envelopes', { id: input.envelopeId });
  if (envelope === undefined) throw new StorageUsageError('the announced envelope does not exist in this tenant');
  if (Number(envelope['version']) !== input.envelopeVersion) {
    throw new StorageUsageError('the event must announce the envelope version written in this transaction');
  }
  const now = options.clock();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new StorageUsageError('the outbox clock returned an invalid date');
  const occurredAt = now.toISOString();
  const eventId = (options.newId ?? defaultEventId)();
  if (!ID.test(eventId)) throw new StorageUsageError('generated event id is malformed');
  const payload: WebhookEventPayload = {
    event_id: eventId,
    schema_version: OUTBOX_SCHEMA_VERSION,
    type: input.type,
    envelope_id: input.envelopeId,
    envelope_version: input.envelopeVersion,
    artifact_id: input.artifactId ?? null,
    artifact_digest: input.artifactDigest ?? null,
    occurred_at: occurredAt,
  };
  store.insert('outbox_events', {
    event_id: eventId,
    envelope_id: input.envelopeId,
    envelope_version: input.envelopeVersion,
    type: input.type,
    schema_version: OUTBOX_SCHEMA_VERSION,
    payload_json: canonicalize(payload as unknown as JsonValue),
    created_at: occurredAt,
  });
  return { eventId, payload, body: canonicalBytes(payload as unknown as JsonValue) };
}
