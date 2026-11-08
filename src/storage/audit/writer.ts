// SPDX-License-Identifier: Apache-2.0
//
// The one restricted writer of the per-tenant audit hash chain. It is the only
// importer of src/storage/db/restricted-writer.ts (tests/audit-chain/ checks
// that boundary). Appends run inside the caller's Database.transaction(), so
// the event commits atomically with the state change it records, and the
// BEGIN IMMEDIATE lock serializes sequence allocation. The schema triggers
// (T003) independently refuse a seq gap, a broken prev_digest link, and any
// update or delete.
//
// Checkpoints: a cadence checkpoint at every multiple of CHECKPOINT_INTERVAL,
// written in the same transaction as that event, and a completion checkpoint
// per envelope through checkpointCompletion().

import { canonicalize, type JsonValue } from '../../domain/canonical/index.ts';
import type { Database } from '../db/connection.ts';
import { StorageUsageError } from '../db/errors.ts';
import { appendRestricted } from '../db/restricted-writer.ts';
import type { TenantStore } from '../db/tenant-store.ts';
import { ACTOR_KINDS, DIGEST, EVENT_TYPE, eventDigest, ID, rowValues, type AuditActor, type AuditEvent } from './event.ts';

export const CHECKPOINT_INTERVAL = 100;

/** Metadata limits: audit metadata is redacted, small and structural. */
export const MAX_METADATA_BYTES = 4096;
export const MAX_METADATA_STRING = 200;
const MAX_METADATA_DEPTH = 4;
// Member names that suggest a capability value, a secret, personal contact
// data or document content are refused. Names are split into words
// (snake_case, kebab-case, camelCase); "code" is allowed only as error_code or
// status_code and "key" only as key_id.
const FORBIDDEN_WORDS: ReadonlySet<string> = new Set([
  'token',
  'secret',
  'password',
  'passphrase',
  'passwd',
  'cookie',
  'csrf',
  'authorization',
  'bearer',
  'credential',
  'credentials',
  'pem',
  'pdf',
  'content',
  'email',
  'otp',
  'private',
]);

export function isForbiddenMetadataName(name: string): boolean {
  const words = name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((word) => word.length > 0);
  return words.some(
    (word, index) =>
      FORBIDDEN_WORDS.has(word) ||
      (word === 'code' && !['error', 'status'].includes(words[index - 1] ?? '')) ||
      (word === 'key' && words[index + 1] !== 'id'),
  );
}

export interface AuditEventInput {
  readonly type: string;
  readonly actor: AuditActor;
  readonly envelopeId?: string | null;
  readonly subjectDigest?: string | null;
  readonly metadata?: { readonly [key: string]: JsonValue };
}

export interface AuditHead {
  readonly seq: number;
  readonly digest: string;
}

export interface AppendedAuditEvent extends AuditHead {
  readonly prevDigest: string | null;
  readonly serverTime: string;
  /** True when this event also wrote a cadence checkpoint. */
  readonly checkpointed: boolean;
}

export interface CompletionCheckpoint {
  readonly seq: number;
  readonly digest: string;
  readonly created_at: string;
}

export interface AuditWriterOptions {
  /** Injected clock for unsigned server time. */
  readonly clock: () => Date;
}

function checkMetadata(value: JsonValue, depth: number, path: string): void {
  if (depth > MAX_METADATA_DEPTH) throw new StorageUsageError(`audit metadata nests deeper than ${MAX_METADATA_DEPTH}`);
  if (typeof value === 'string') {
    if (value.length > MAX_METADATA_STRING) throw new StorageUsageError(`audit metadata ${path} exceeds ${MAX_METADATA_STRING} characters`);
    if (value.includes('-----BEGIN')) throw new StorageUsageError(`audit metadata ${path} looks like a PEM block`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => checkMetadata(item, depth + 1, `${path}[${index}]`));
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [name, member] of Object.entries(value)) {
      if (isForbiddenMetadataName(name)) throw new StorageUsageError(`audit metadata member ${JSON.stringify(name)} is not allowed`);
      checkMetadata(member, depth + 1, `${path}.${name}`);
    }
  }
}

function checkInput(input: AuditEventInput): void {
  if (typeof input !== 'object' || input === null) throw new StorageUsageError('audit event input is required');
  if (typeof input.type !== 'string' || !EVENT_TYPE.test(input.type)) throw new StorageUsageError('audit event type is malformed');
  const actor = input.actor;
  if (typeof actor !== 'object' || actor === null || !ACTOR_KINDS.has(actor.kind)) throw new StorageUsageError('audit actor kind is unknown');
  if (typeof actor.ref !== 'string' || actor.ref.length < 1 || actor.ref.length > 100) {
    throw new StorageUsageError('audit actor ref must be 1..100 characters');
  }
  const envelopeId = input.envelopeId ?? null;
  if (envelopeId !== null && (typeof envelopeId !== 'string' || !ID.test(envelopeId))) throw new StorageUsageError('audit envelope id is malformed');
  const subject = input.subjectDigest ?? null;
  if (subject !== null && (typeof subject !== 'string' || !DIGEST.test(subject))) throw new StorageUsageError('audit subject digest is malformed');
  const metadata = input.metadata ?? {};
  if (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata)) {
    throw new StorageUsageError('audit metadata must be a JSON object');
  }
  if (Buffer.byteLength(canonicalize(metadata), 'utf8') > MAX_METADATA_BYTES) {
    throw new StorageUsageError(`audit metadata exceeds ${MAX_METADATA_BYTES} bytes`);
  }
  checkMetadata(metadata as JsonValue, 0, 'metadata');
}

export class AuditWriter {
  readonly #db: Database;
  readonly #clock: () => Date;

  constructor(db: Database, options: AuditWriterOptions) {
    if (typeof options?.clock !== 'function') throw new StorageUsageError('the audit writer needs an injected clock');
    this.#db = db;
    this.#clock = options.clock;
  }

  #now(): string {
    const now = this.#clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new StorageUsageError('the audit clock returned an invalid date');
    return now.toISOString();
  }

  #store(tenantId: string, operation: string): TenantStore {
    if (!this.#db.inTransaction) throw new StorageUsageError(`${operation} must run inside Database.transaction()`);
    return this.#db.forTenant(tenantId);
  }

  /** The tenant's chain head, or null for an empty chain. */
  head(tenantId: string): AuditHead | null {
    const row = this.#db.forTenant(tenantId).list('audit_events', {}, { orderBy: [['seq', 'desc']], limit: 1 })[0];
    return row === undefined ? null : { seq: Number(row['seq']), digest: String(row['event_digest']) };
  }

  /** Append one event to the tenant's chain (inside the caller's transaction). */
  append(tenantId: string, input: AuditEventInput): AppendedAuditEvent {
    const store = this.#store(tenantId, 'audit append');
    checkInput(input);
    const head = this.head(tenantId);
    const event: AuditEvent = {
      tenantId: store.tenantId,
      seq: (head?.seq ?? 0) + 1,
      type: input.type,
      actor: { kind: input.actor.kind, ref: input.actor.ref },
      serverTime: this.#now(),
      envelopeId: input.envelopeId ?? null,
      subjectDigest: input.subjectDigest ?? null,
      metadata: input.metadata ?? {},
      prevDigest: head?.digest ?? null,
    };
    const digest = eventDigest(event);
    appendRestricted(store, 'audit_events', rowValues(event, digest));
    const checkpointed = event.seq % CHECKPOINT_INTERVAL === 0;
    if (checkpointed) {
      appendRestricted(store, 'audit_checkpoints', {
        seq: event.seq,
        kind: 'cadence',
        event_digest: digest,
        envelope_id: null,
        created_at: event.serverTime,
      });
    }
    return { seq: event.seq, digest, prevDigest: event.prevDigest, serverTime: event.serverTime, checkpointed };
  }

  /**
   * Record the chain head at an envelope's completion as its completion
   * checkpoint (inside the publishing transaction). The returned value is the
   * chain head that goes into the audit receipt and the acceptance receipt.
   */
  checkpointCompletion(tenantId: string, envelopeId: string): CompletionCheckpoint {
    const store = this.#store(tenantId, 'completion checkpoint');
    if (typeof envelopeId !== 'string' || !ID.test(envelopeId)) throw new StorageUsageError('envelope id is malformed');
    const head = this.head(tenantId);
    if (head === null) throw new StorageUsageError('a completion checkpoint needs at least one audit event');
    const createdAt = this.#now();
    appendRestricted(store, 'audit_checkpoints', {
      seq: head.seq,
      kind: 'completion',
      event_digest: head.digest,
      envelope_id: envelopeId,
      created_at: createdAt,
    });
    return { seq: head.seq, digest: head.digest, created_at: createdAt };
  }
}
