// SPDX-License-Identifier: Apache-2.0
//
// Retention and disposal.
//
// BlobDisposer is the one disposal path, exported for every writer of
// DisposalRecords: retention (below) and the orphan collector of abandoned
// finalization-attempt blobs (T038, src/storage/retention/orphans.ts). One
// disposal, for one envelope:
// 1. In one BEGIN IMMEDIATE transaction, re-checks every candidate blob ref
//    against the current rows (a ref that is still referenced is kept, never
//    removed), inserts the DisposalRecord with its kind ('retention' or
//    'orphan-collection') and appends an audit event whose subject_digest is
//    the RFC 8785 digest of the record.
// 2. After the commit, removes each disposed blob in its own BEGIN IMMEDIATE
//    transaction that re-checks protection first (A-010 request #59 (7);
//    RET-09). A finalization attempt records a ref in its own transaction
//    before it writes the blob (T038), so a live attempt's blob is either
//    seen and kept, or removed before the attempt writes it again.
// resume() finishes step 2 for earlier records after a crash between the
// commit and the removal, the same way: a ref referenced again is kept.
//
// Reference rule (ReferenceProtection, exported as the single
// reference-protection predicate: backup computes its required blobs with it
// too, A-009 T30R-4). A row that references a blob protects it, except:
// - a document revision of an envelope that retention disposed (retention
//   always gives up the document revisions);
// - a final artifact of an envelope that retention disposed with scope 'all'
//   (scope 'documents' keeps the final artifacts, so they still protect);
// - for a retention disposal, the disposed envelope's own rows, by the same
//   two rules.
// An orphan collection never removes a ref that any final artifact references.
// Every referencing row is read (keyset iteration), never a truncated list.
//
// FinalizationAttemptBlob records (request #59 (7)): when the predicate is
// given the instant to judge attempts at (`attempts.now`, which the disposer
// always passes), a record protects its ref unless its attempt is collectable
// by data-model.md's rule (attemptCollectable in
// src/storage/repositories/jobs.ts: not published, lease ended, plus 24
// hours). The published attempt's records protect exactly as its envelope's
// final artifact does, so retention scope 'all' still gives them up. The
// records are read in referenced() only: protects(), and so backup's
// required-blob set, is unchanged, because a recorded ref may not be written
// yet (the record precedes the write) or may have been collected.
//
// A retention run, for one tenant:
// 1. Reads the tenant's policy; with no policy nothing is disposed.
// 2. Resumes interrupted blob removals.
// 3. Iterates envelopes in a terminal state (completed, declined, expired,
//    voided) last updated at or before now - dispose_after_days (injected
//    clock), skipping only envelopes that already have a retention
//    DisposalRecord (an orphan-collection record does not count). Each
//    request proposes the document revisions' refs and, for scope 'all', the
//    final artifact's three refs and every ref its published attempt
//    recorded (row ATTEMPT-ALL).
// 4. Disposes them in batches of up to RETENTION_BATCH_SIZE envelopes per
//    transaction, each envelope with its own record and audit event.
// Rows are never changed: completed evidence is not mutated in place; only
// blobs are removed, and the record keeps the final artifact digests.

import { randomBytes } from 'node:crypto';

import { canonicalDigest, parseJson } from '../../domain/canonical/index.ts';
import type { AuditWriter } from '../audit/writer.ts';
import type { BlobStore } from '../blobs/file-store.ts';
import { parseBlobRef } from '../blobs/refs.ts';
import type { Database } from '../db/connection.ts';
import { StorageUsageError } from '../db/errors.ts';
import type { Row, TenantStore } from '../db/tenant-store.ts';
import { attemptBlobsOfRef, attemptCollectable, listAttemptBlobs } from '../repositories/jobs.ts';
import { parseRetentionPolicy, type RetentionPolicy, type RetentionScope } from './policy.ts';

export const DISPOSAL_RECORD_SCHEMA = 'opensig.disposal-record/1';
export const TERMINAL_STATES: readonly string[] = Object.freeze(['completed', 'declined', 'expired', 'voided']);
export type DisposalKind = 'retention' | 'orphan-collection';
export const DISPOSAL_KINDS: readonly DisposalKind[] = Object.freeze(['retention', 'orphan-collection']);
/** Envelopes disposed per transaction by a retention run. */
export const RETENTION_BATCH_SIZE = 500;
const DAY_MS = 86_400_000;
const MAX_POLICY_REF = 200;

const EVENT: Readonly<Record<DisposalKind, { readonly type: string; readonly actor: string }>> = Object.freeze({
  retention: { type: 'retention.disposed', actor: 'retention' },
  'orphan-collection': { type: 'retention.orphans_collected', actor: 'orphan-collector' },
});

export interface DisposalRequest {
  readonly envelopeId: string;
  readonly kind: DisposalKind;
  readonly policyRef: string;
  /** Retention only: what the disposal gives up ('documents' or 'all'). */
  readonly scope?: RetentionScope;
  /** Candidate blob refs. Each is re-checked inside the disposal transaction. */
  readonly refs: readonly string[];
  /** Digests of the final artifact that stay recorded in the DisposalRecord. */
  readonly retainedArtifactDigests: readonly string[];
}

export interface DisposalOutcome {
  readonly envelopeId: string;
  readonly disposalId: string;
  readonly kind: DisposalKind;
  readonly disposedBlobRefs: readonly string[];
  /** Candidate refs kept because a row still references them. */
  readonly keptBlobRefs: readonly string[];
  readonly retainedArtifactDigests: readonly string[];
  /** RFC 8785 digest of the record, also the audit event's subject_digest. */
  readonly recordDigest: string;
}

export interface BlobDisposerOptions {
  readonly db: Database;
  readonly blobs: BlobStore;
  readonly audit: AuditWriter;
  /** Injected clock: the record's server_time comes from it. */
  readonly clock: () => Date;
  /** Identifier source for DisposalRecords (default: random). */
  readonly newId?: () => string;
}

export type RetentionServiceOptions = BlobDisposerOptions;

export interface RetentionRun {
  readonly tenantId: string;
  readonly policy: RetentionPolicy | null;
  readonly disposals: readonly DisposalOutcome[];
  /** Blob refs of earlier records whose removal this run completed. */
  readonly resumedBlobRefs: readonly string[];
  /** Blob refs left in place because another row still references them. */
  readonly keptSharedBlobRefs: readonly string[];
}

const ARTIFACT_REF_COLUMNS = ['pdf_blob_ref', 'evidence_blob_ref', 'package_blob_ref'] as const;

/** Whether a referencing row is a document revision or a final artifact. */
export type ReferenceKind = 'document' | 'artifact';

/** Every column that references a blob, with the kind of reference it is. */
export const BLOB_REFERENCE_COLUMNS: readonly { readonly table: string; readonly column: string; readonly kind: ReferenceKind }[] = Object.freeze([
  Object.freeze({ table: 'document_revisions', column: 'blob_ref', kind: 'document' as const }),
  ...ARTIFACT_REF_COLUMNS.map((column) => Object.freeze({ table: 'final_artifacts', column, kind: 'artifact' as const })),
]);

/** What one envelope has given up through retention. */
interface GivenUp {
  readonly documents: boolean;
  readonly artifacts: boolean;
}

/** A disposal being decided: its envelope counts as having given up what it gives up. */
export interface DisposalContext {
  readonly envelopeId: string;
  readonly kind: DisposalKind;
  readonly scope: RetentionScope | undefined;
}

/** How referenced() judges FinalizationAttemptBlob records (request #59 (7)). */
export interface ProtectionOptions {
  /**
   * The instant attempts are judged at, or a clock read once, on the first
   * attempt record met. Without it referenced() does not read attempt records.
   */
  readonly attempts?: { readonly now: Date | (() => Date) };
}

/** The scope of the envelope's retention disposal, from its audit event ('documents' when not recorded). */
function retentionScope(store: TenantStore, envelopeId: string): RetentionScope {
  for (const event of store.iterate('audit_events', { envelope_id: envelopeId, type: EVENT.retention.type })) {
    const metadata = parseJson(String(event['metadata_json']));
    if (metadata !== null && typeof metadata === 'object' && !Array.isArray(metadata) && metadata['scope'] === 'all') return 'all';
  }
  return 'documents';
}

function hasRetentionDisposal(store: TenantStore, envelopeId: string): boolean {
  return store.count('disposal_records', { envelope_id: envelopeId, kind: 'retention' }) > 0;
}

/**
 * The single reference-protection predicate (A-009 T30R-4), shared by the
 * disposer and by backup's required-blob set. protects() answers whether a
 * referencing row, of the given kind and owned by the given envelope, still
 * protects the blob it references:
 * - a document revision protects unless its envelope has a retention
 *   DisposalRecord;
 * - a final artifact protects unless its envelope was disposed by retention
 *   with scope 'all';
 * - with a disposal context, that disposal's envelope counts as having given
 *   up what the disposal gives up (a retention disposal: its documents, and
 *   its final artifacts for scope 'all'), and for an orphan collection every
 *   final artifact protects.
 * Orphan-collection records never make an envelope give anything up. With
 * `options.attempts`, referenced() also reads FinalizationAttemptBlob records
 * (see the header). An instance caches per envelope; use one instance per
 * consistent read.
 */
export class ReferenceProtection {
  readonly #store: TenantStore;
  readonly #context: DisposalContext | undefined;
  readonly #cache = new Map<string, GivenUp>();
  readonly #attemptsNow: Date | (() => Date) | undefined;
  #instant: Date | undefined = undefined;

  constructor(store: TenantStore, context?: DisposalContext, options: ProtectionOptions = {}) {
    this.#store = store;
    this.#context = context;
    this.#attemptsNow = options.attempts?.now;
  }

  #now(): Date {
    if (this.#instant === undefined) {
      const source = this.#attemptsNow;
      const now = typeof source === 'function' ? source() : source;
      if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new StorageUsageError('the attempt protection instant is not a valid date');
      this.#instant = now;
    }
    return this.#instant;
  }

  /** True while a FinalizationAttemptBlob record of `ref` still protects it. */
  #attemptProtects(ref: string): boolean {
    if (this.#attemptsNow === undefined) return false;
    for (const record of attemptBlobsOfRef(this.#store, ref)) {
      if (this.#store.count('final_artifacts', { envelope_id: record.envelopeId, fencing_token: record.fencingToken }) > 0) {
        // The published attempt: protected as its final artifact is.
        if (this.protects(record.envelopeId, 'artifact')) return true;
        continue;
      }
      if (!attemptCollectable(this.#store, record.envelopeId, record.fencingToken, this.#now())) return true;
    }
    return false;
  }

  #givenUp(envelopeId: string): GivenUp {
    const context = this.#context;
    if (context !== undefined && context.kind === 'retention' && envelopeId === context.envelopeId) {
      return { documents: true, artifacts: context.scope === 'all' };
    }
    let state = this.#cache.get(envelopeId);
    if (state === undefined) {
      const disposed = hasRetentionDisposal(this.#store, envelopeId);
      state = { documents: disposed, artifacts: disposed && retentionScope(this.#store, envelopeId) === 'all' };
      this.#cache.set(envelopeId, state);
    }
    return state;
  }

  protects(envelopeId: string, kind: ReferenceKind): boolean {
    if (kind === 'artifact' && this.#context?.kind === 'orphan-collection') return true;
    const givenUp = this.#givenUp(envelopeId);
    return kind === 'document' ? !givenUp.documents : !givenUp.artifacts;
  }

  /** True while any row that still protects `ref` references it (every row is read), or, with `attempts`, an attempt record protects it. */
  referenced(ref: string): boolean {
    for (const { table, column, kind } of BLOB_REFERENCE_COLUMNS) {
      for (const row of this.#store.iterate(table, { [column]: ref })) {
        if (this.protects(String(row['envelope_id']), kind)) return true;
      }
    }
    return this.#attemptProtects(ref);
  }
}

function defaultId(): string {
  return `disp-${randomBytes(16).toString('base64url')}`;
}

function strings(values: readonly unknown[]): string[] {
  return values.filter((value): value is string => typeof value === 'string');
}

function jsonStrings(row: Row, column: string): string[] {
  const parsed: unknown = JSON.parse(String(row[column]));
  if (!Array.isArray(parsed)) throw new StorageUsageError(`disposal_records.${column} is not an array`);
  return strings(parsed);
}

function checkKind(kind: unknown): DisposalKind {
  if (typeof kind !== 'string' || !(DISPOSAL_KINDS as readonly string[]).includes(kind)) {
    throw new StorageUsageError('disposal kind must be retention or orphan-collection');
  }
  return kind as DisposalKind;
}

function checkStrings(values: unknown, label: string): readonly string[] {
  if (!Array.isArray(values) || !values.every((value) => typeof value === 'string')) {
    throw new StorageUsageError(`${label} must be an array of strings`);
  }
  return values as readonly string[];
}

export class BlobDisposer {
  readonly #db: Database;
  readonly #blobs: BlobStore;
  readonly #audit: AuditWriter;
  readonly #clock: () => Date;
  readonly #newId: () => string;

  constructor(options: BlobDisposerOptions) {
    if (typeof options?.clock !== 'function') throw new StorageUsageError('disposal needs an injected clock');
    this.#db = options.db;
    this.#blobs = options.blobs;
    this.#audit = options.audit;
    this.#clock = options.clock;
    this.#newId = options.newId ?? defaultId;
  }

  #now(): Date {
    const now = this.#clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new StorageUsageError('the disposal clock returned an invalid date');
    return now;
  }

  /** The clock, read at most once per operation and only when an attempt record is met. */
  #onceNow(): () => Date {
    let instant: Date | undefined;
    return () => (instant ??= this.#now());
  }

  /** True while any row still protecting the ref (ReferenceProtection, attempts judged at `now`) references it. */
  #referenced(store: TenantStore, ref: string, context: DisposalContext, now: () => Date): boolean {
    return new ReferenceProtection(store, context, { attempts: { now } }).referenced(ref);
  }

  #removeBlob(tenantId: string, ref: string): boolean {
    const key = parseBlobRef(ref);
    if (key.tenantId !== tenantId) throw new StorageUsageError('a disposal blob ref belongs to another tenant');
    return this.#blobs.dispose(tenantId, key.digest);
  }

  /**
   * One removal (request #59 (7)): in its own BEGIN IMMEDIATE transaction,
   * re-check protection and remove the blob only when nothing protects it.
   * True when a blob was removed.
   */
  #removeUnprotected(store: TenantStore, tenantId: string, ref: string, context: DisposalContext, now: () => Date): boolean {
    return this.#db.transaction(() => (this.#referenced(store, ref, context, now) ? false : this.#removeBlob(tenantId, ref)));
  }

  #checkRequest(tenantId: string, request: DisposalRequest): DisposalContext & { readonly refs: readonly string[] } {
    if (typeof request !== 'object' || request === null) throw new StorageUsageError('a disposal request is required');
    const kind = checkKind(request.kind);
    if (typeof request.envelopeId !== 'string' || request.envelopeId.length === 0) throw new StorageUsageError('a disposal needs an envelope id');
    if (typeof request.policyRef !== 'string' || request.policyRef.length < 1 || request.policyRef.length > MAX_POLICY_REF) {
      throw new StorageUsageError(`a disposal policy reference must be 1..${MAX_POLICY_REF} characters`);
    }
    const scope = request.scope;
    if (kind === 'retention' && scope !== 'documents' && scope !== 'all') throw new StorageUsageError('a retention disposal needs scope documents or all');
    if (kind === 'orphan-collection' && scope !== undefined) throw new StorageUsageError('an orphan collection has no retention scope');
    const refs = [...new Set(checkStrings(request.refs, 'disposal refs'))].sort();
    for (const ref of refs) {
      if (parseBlobRef(ref).tenantId !== tenantId) throw new StorageUsageError('a disposal blob ref belongs to another tenant');
    }
    checkStrings(request.retainedArtifactDigests, 'retained artifact digests');
    return { envelopeId: request.envelopeId, kind, scope, refs };
  }

  /** True when the envelope has a retention DisposalRecord; orphan-collection records do not count. */
  hasRetentionDisposal(tenantId: string, envelopeId: string): boolean {
    return hasRetentionDisposal(this.#db.forTenant(tenantId), envelopeId);
  }

  /** Dispose one envelope's candidate refs (its own transaction; see disposeBatch). */
  dispose(tenantId: string, request: DisposalRequest): DisposalOutcome {
    const [outcome] = this.disposeBatch(tenantId, [request]);
    if (outcome === undefined) throw new StorageUsageError('the disposal produced no outcome');
    return outcome;
  }

  /**
   * Several disposals in one BEGIN IMMEDIATE transaction, decided in order
   * (a later request sees the records of earlier ones). The blobs are removed
   * after the commit, each in its own transaction that re-checks protection.
   * Refuses to run inside a caller's transaction, because blob removal must
   * follow the commit, and refuses (writing nothing) a retention disposal of
   * an envelope that already has one.
   */
  disposeBatch(tenantId: string, requests: readonly DisposalRequest[]): DisposalOutcome[] {
    if (this.#db.inTransaction) throw new StorageUsageError('a disposal runs its own transaction; call it outside Database.transaction()');
    if (!Array.isArray(requests)) throw new StorageUsageError('disposal requests must be an array');
    const checked = requests.map((request) => this.#checkRequest(tenantId, request));
    const store = this.#db.forTenant(tenantId);
    const now = this.#onceNow();
    const outcomes = this.#db.transaction(() =>
      checked.map((context, index): DisposalOutcome => {
        const request = requests[index] as DisposalRequest;
        if (context.kind === 'retention' && hasRetentionDisposal(store, context.envelopeId)) {
          throw new StorageUsageError('the envelope already has a retention disposal');
        }
        const disposedBlobRefs: string[] = [];
        const keptBlobRefs: string[] = [];
        for (const ref of context.refs) {
          if (this.#referenced(store, ref, context, now)) keptBlobRefs.push(ref);
          else disposedBlobRefs.push(ref);
        }
        const retainedArtifactDigests = [...new Set(request.retainedArtifactDigests)].sort();
        const disposalId = this.#newId();
        const serverTime = this.#now().toISOString();
        const recordDigest = canonicalDigest({
          schema: DISPOSAL_RECORD_SCHEMA,
          tenant_id: tenantId,
          id: disposalId,
          envelope_id: context.envelopeId,
          kind: context.kind,
          retained_artifact_digests: retainedArtifactDigests,
          disposed_blob_refs: disposedBlobRefs,
          policy_ref: request.policyRef,
          server_time: serverTime,
        });
        store.insert('disposal_records', {
          id: disposalId,
          envelope_id: context.envelopeId,
          kind: context.kind,
          retained_artifact_digests_json: JSON.stringify(retainedArtifactDigests),
          disposed_blob_refs_json: JSON.stringify(disposedBlobRefs),
          policy_ref: request.policyRef,
          server_time: serverTime,
        });
        this.#audit.append(tenantId, {
          type: EVENT[context.kind].type,
          actor: { kind: 'system', ref: EVENT[context.kind].actor },
          envelopeId: context.envelopeId,
          subjectDigest: recordDigest,
          metadata: {
            disposal_id: disposalId,
            kind: context.kind,
            ...(context.scope === undefined ? {} : { scope: context.scope }),
            disposed_blob_count: disposedBlobRefs.length,
            kept_blob_count: keptBlobRefs.length,
            retained_artifact_count: retainedArtifactDigests.length,
            policy_ref: request.policyRef,
          },
        });
        return {
          envelopeId: context.envelopeId,
          disposalId,
          kind: context.kind,
          disposedBlobRefs,
          keptBlobRefs,
          retainedArtifactDigests,
          recordDigest,
        };
      }),
    );
    outcomes.forEach((outcome, index) => {
      const context = checked[index] as DisposalContext;
      for (const ref of outcome.disposedBlobRefs) this.#removeUnprotected(store, tenantId, ref, context, now);
    });
    return outcomes;
  }

  /**
   * Finish blob removal for earlier records whose blobs still exist (a crash
   * between a record's commit and its blob removal). Each removal re-checks
   * protection in its own transaction; a ref referenced again is kept.
   * Returns the refs removed now.
   */
  resume(tenantId: string): string[] {
    const store = this.#db.forTenant(tenantId);
    const now = this.#onceNow();
    const resumed: string[] = [];
    for (const record of store.iterate('disposal_records', {}, { orderBy: [['server_time', 'asc']] })) {
      const envelopeId = String(record['envelope_id']);
      const kind = checkKind(record['kind']);
      let context: DisposalContext | undefined;
      for (const ref of jsonStrings(record, 'disposed_blob_refs_json')) {
        const key = parseBlobRef(ref);
        if (key.tenantId !== tenantId) throw new StorageUsageError('a disposal blob ref belongs to another tenant');
        if (this.#blobs.check(tenantId, key.digest) === 'missing') continue;
        context ??= { envelopeId, kind, scope: kind === 'retention' ? retentionScope(store, envelopeId) : undefined };
        if (this.#removeUnprotected(store, tenantId, ref, context, now)) resumed.push(ref);
      }
    }
    return resumed;
  }
}

export class RetentionService {
  readonly #db: Database;
  readonly #clock: () => Date;
  readonly #disposer: BlobDisposer;

  constructor(options: RetentionServiceOptions) {
    if (typeof options?.clock !== 'function') throw new StorageUsageError('retention needs an injected clock');
    this.#db = options.db;
    this.#clock = options.clock;
    this.#disposer = new BlobDisposer(options);
  }

  #now(): Date {
    const now = this.#clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new StorageUsageError('the retention clock returned an invalid date');
    return now;
  }

  #request(store: TenantStore, envelopeId: string, policy: RetentionPolicy): DisposalRequest {
    const artifact = store.get('final_artifacts', { envelope_id: envelopeId });
    const refs = new Set<string>();
    for (const revision of store.iterate('document_revisions', { envelope_id: envelopeId })) {
      const ref = revision['blob_ref'];
      if (typeof ref === 'string') refs.add(ref);
    }
    if (policy.scope === 'all' && artifact !== undefined) {
      for (const column of ARTIFACT_REF_COLUMNS) {
        const ref = artifact[column];
        if (typeof ref === 'string') refs.add(ref);
      }
      // Row ATTEMPT-ALL (request #75 (2)): every ref the published attempt recorded, the
      // composed PDF included, which no other path removes. The predicate re-checks each.
      const published = artifact['fencing_token'];
      for (const record of listAttemptBlobs(store, envelopeId)) {
        if (record.fencingToken === Number(published)) refs.add(record.blobRef);
      }
    }
    const retainedArtifactDigests =
      artifact === undefined ? [] : [...new Set(strings([artifact['artifact_digest'], artifact['package_digest']]))].sort();
    return { envelopeId, kind: 'retention', scope: policy.scope, policyRef: policy.policyRef, refs: [...refs].sort(), retainedArtifactDigests };
  }

  run(tenantId: string): RetentionRun {
    const store = this.#db.forTenant(tenantId);
    const tenant = store.get('tenants', {});
    if (tenant === undefined) throw new StorageUsageError('unknown tenant');
    const policy = parseRetentionPolicy(tenant['retention_json']);
    if (policy === null) {
      return { tenantId, policy, disposals: [], resumedBlobRefs: [], keptSharedBlobRefs: [] };
    }

    const resumedBlobRefs = this.#disposer.resume(tenantId);
    const now = this.#now();
    const cutoff = new Date(now.getTime() - policy.disposeAfterDays * DAY_MS).toISOString();
    const disposals: DisposalOutcome[] = [];
    const keptSharedBlobRefs: string[] = [];
    let batch: DisposalRequest[] = [];
    const flush = (): void => {
      if (batch.length === 0) return;
      for (const outcome of this.#disposer.disposeBatch(tenantId, batch)) {
        disposals.push(outcome);
        keptSharedBlobRefs.push(...outcome.keptBlobRefs);
      }
      batch = [];
    };
    const eligible = store.iterate(
      'envelopes',
      { state: { op: 'in', values: [...TERMINAL_STATES] }, updated_at: { op: '<=', value: cutoff } },
      { orderBy: [['id', 'asc']] },
    );
    for (const envelope of eligible) {
      const envelopeId = String(envelope['id']);
      if (this.#disposer.hasRetentionDisposal(tenantId, envelopeId)) continue;
      batch.push(this.#request(store, envelopeId, policy));
      if (batch.length >= RETENTION_BATCH_SIZE) flush();
    }
    flush();
    return { tenantId, policy, disposals, resumedBlobRefs, keptSharedBlobRefs };
  }
}
