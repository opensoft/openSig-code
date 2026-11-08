// SPDX-License-Identifier: Apache-2.0
//
// The audit event model and its digest.
//
// event_digest = SHA-256(RFC 8785(event without event_digest)), where the
// digested event is
//   { schema, tenant_id, seq, type, actor: {kind, ref}, server_time,
//     envelope_id, subject_digest, metadata, prev_digest }
// with null for an absent envelope_id, subject_digest or prev_digest (seq 1
// has prev_digest null). Every stored column of the row is covered, so an
// edit of any column is detected by recomputation. The canonical form comes
// from src/domain/canonical/, the project's single canonicalizer.

import { canonicalDigest, canonicalize, parseJson, type JsonValue } from '../../domain/canonical/index.ts';
import { StorageUsageError } from '../db/errors.ts';
import type { Row } from '../db/tenant-store.ts';

export const AUDIT_EVENT_SCHEMA = 'opensig.audit-event/1';

export type ActorKind = 'human-operator' | 'service' | 'recipient' | 'system';

export interface AuditActor {
  readonly kind: ActorKind;
  readonly ref: string;
}

export interface AuditEvent {
  readonly tenantId: string;
  readonly seq: number;
  readonly type: string;
  readonly actor: AuditActor;
  readonly serverTime: string;
  readonly envelopeId: string | null;
  readonly subjectDigest: string | null;
  readonly metadata: { readonly [key: string]: JsonValue };
  readonly prevDigest: string | null;
}

/** The record shape of the contract's AuditEventRecord (audit receipts). */
export interface AuditEventRecord {
  readonly seq: number;
  readonly type: string;
  readonly actor: AuditActor;
  readonly server_time: string;
  readonly subject_digest: string | null;
  readonly prev_digest: string | null;
  readonly event_digest: string;
}

export const ACTOR_KINDS: ReadonlySet<string> = new Set(['human-operator', 'service', 'recipient', 'system']);
export const EVENT_TYPE = /^[a-z][a-z0-9_.-]{1,60}$/;
export const DIGEST = /^[0-9a-f]{64}$/;
export const ID = /^[A-Za-z0-9_-]{16,64}$/;

/** The object whose RFC 8785 form is hashed into event_digest. */
export function digestInput(event: AuditEvent): { [key: string]: JsonValue } {
  return {
    schema: AUDIT_EVENT_SCHEMA,
    tenant_id: event.tenantId,
    seq: event.seq,
    type: event.type,
    actor: { kind: event.actor.kind, ref: event.actor.ref },
    server_time: event.serverTime,
    envelope_id: event.envelopeId,
    subject_digest: event.subjectDigest,
    metadata: event.metadata as JsonValue,
    prev_digest: event.prevDigest,
  };
}

export function eventDigest(event: AuditEvent): string {
  return canonicalDigest(digestInput(event));
}

function text(row: Row, column: string): string {
  const value = row[column];
  if (typeof value !== 'string') throw new StorageUsageError(`audit_events.${column} is not text`);
  return value;
}

function nullableText(row: Row, column: string): string | null {
  const value = row[column];
  if (value === null) return null;
  return text(row, column);
}

/** Rebuild the event from a stored audit_events row. */
export function eventFromRow(row: Row): AuditEvent {
  const metadata = parseJson(text(row, 'metadata_json'));
  if (metadata === null || typeof metadata !== 'object' || Array.isArray(metadata)) {
    throw new StorageUsageError('audit_events.metadata_json is not a JSON object');
  }
  const kind = text(row, 'actor_kind');
  if (!ACTOR_KINDS.has(kind)) throw new StorageUsageError('audit_events.actor_kind is unknown');
  return {
    tenantId: text(row, 'tenant_id'),
    seq: Number(row['seq']),
    type: text(row, 'type'),
    actor: { kind: kind as ActorKind, ref: text(row, 'actor_ref') },
    serverTime: text(row, 'server_time'),
    envelopeId: nullableText(row, 'envelope_id'),
    subjectDigest: nullableText(row, 'subject_digest'),
    metadata,
    prevDigest: nullableText(row, 'prev_digest'),
  };
}

/** The audit_events row values for an event (tenant_id is added by the store). */
export function rowValues(event: AuditEvent, digest: string): Record<string, string | number | null> {
  return {
    seq: event.seq,
    type: event.type,
    actor_kind: event.actor.kind,
    actor_ref: event.actor.ref,
    server_time: event.serverTime,
    envelope_id: event.envelopeId,
    subject_digest: event.subjectDigest,
    metadata_json: canonicalize(event.metadata),
    prev_digest: event.prevDigest,
    event_digest: digest,
  };
}

/** The contract AuditEventRecord of a stored row (for audit receipts). */
export function recordFromRow(row: Row): AuditEventRecord {
  const event = eventFromRow(row);
  return {
    seq: event.seq,
    type: event.type,
    actor: event.actor,
    server_time: event.serverTime,
    subject_digest: event.subjectDigest,
    prev_digest: event.prevDigest,
    event_digest: text(row, 'event_digest'),
  };
}
