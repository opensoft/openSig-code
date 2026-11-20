// SPDX-License-Identifier: Apache-2.0
//
// The bounded orphan collector (T038; data-model.md § Entities,
// FinalizationAttemptBlob, and § Transitions and races, item 2; FEN-04). It
// removes the blobs of abandoned finalization attempts through T029's one
// disposal path (BlobDisposer, service.ts), which writes a DisposalRecord of
// kind 'orphan-collection' and an audit event, re-checks every candidate in
// its BEGIN IMMEDIATE transaction, and never removes a ref that a final
// artifact references.
//
// Selection, per envelope with attempt records, all read synchronously and
// handed to the disposer in the same call (no await in between):
// - a ref is proposed only when every attempt record of it, in any envelope
//   of the tenant, is collectable by the one rule (attemptCollectable in
//   src/storage/repositories/jobs.ts: not the published attempt, its lease
//   ended, plus the 24-hour grace), and no protecting row references it
//   (T029's ReferenceProtection, orphan-collection context, in which every
//   final artifact protects);
// - an attempt's records are collected once: a record listed by an earlier
//   orphan-collection DisposalRecord of its envelope written at or after the
//   record is not proposed again, so each attempt adds at most one orphan
//   audit event (request #59 (9)). A later attempt that records the same
//   content-addressed ref again makes a new record, collected in its own turn;
// - an envelope with nothing to propose gets no disposal and no event.
// Each run handles at most `envelopesPerRun` envelopes, in envelope id order,
// after the `after` cursor when one is given. It returns `next`, the last
// envelope it handled, when envelopes are left, and null when it reached the
// end; the next run passes `next` back. Attempt records are never deleted, so
// a run that always started at the first envelope would never reach the rest.
//
// Not covered here (row UPLOAD-ORPHAN): upload blobs whose revision record was
// refused have no record to select by, and T028's store exposes no blob time
// for a grace period; T024 documents them until a ruled path exists.

import type { AuditWriter } from '../audit/writer.ts';
import type { BlobStore } from '../blobs/file-store.ts';
import type { Database } from '../db/connection.ts';
import { StorageUsageError } from '../db/errors.ts';
import type { TenantStore } from '../db/tenant-store.ts';
import { attemptBlobsOfRef, attemptCollectable, listAttemptBlobs, type AttemptBlobRecord } from '../repositories/jobs.ts';
import { BlobDisposer, ReferenceProtection, type DisposalOutcome } from './service.ts';

export const ORPHAN_POLICY_REF = 'orphan-collection';
export const DEFAULT_ORPHAN_ENVELOPES_PER_RUN = 100;
export const MAX_ORPHAN_ENVELOPES_PER_RUN = 10_000;

export interface OrphanCollectorOptions {
  readonly db: Database;
  readonly blobs: BlobStore;
  readonly audit: AuditWriter;
  /** Injected clock: the grace and the DisposalRecord's server_time come from it. */
  readonly clock: () => Date;
  readonly newId?: () => string;
  readonly envelopesPerRun?: number;
}

export interface OrphanRun {
  readonly tenantId: string;
  readonly disposals: readonly DisposalOutcome[];
  /** The cursor for the next run when this one stopped at envelopesPerRun with envelopes left; null at the end. */
  readonly next: string | null;
}

function collectedBefore(store: TenantStore, envelopeId: string): readonly { readonly refs: ReadonlySet<string>; readonly at: string }[] {
  const disposals: { refs: ReadonlySet<string>; at: string }[] = [];
  for (const row of store.iterate('disposal_records', { envelope_id: envelopeId, kind: 'orphan-collection' })) {
    const parsed: unknown = JSON.parse(String(row['disposed_blob_refs_json']));
    if (!Array.isArray(parsed)) throw new StorageUsageError('disposal_records.disposed_blob_refs_json is not an array');
    disposals.push({ refs: new Set(parsed.filter((ref): ref is string => typeof ref === 'string')), at: String(row['server_time']) });
  }
  return disposals;
}

export class OrphanCollector {
  readonly #db: Database;
  readonly #clock: () => Date;
  readonly #disposer: BlobDisposer;
  readonly #envelopesPerRun: number;

  constructor(options: OrphanCollectorOptions) {
    if (typeof options?.clock !== 'function') throw new StorageUsageError('the orphan collector needs an injected clock');
    const limit = options.envelopesPerRun ?? DEFAULT_ORPHAN_ENVELOPES_PER_RUN;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_ORPHAN_ENVELOPES_PER_RUN) {
      throw new StorageUsageError(`envelopesPerRun must be an integer in 1..${MAX_ORPHAN_ENVELOPES_PER_RUN}`);
    }
    this.#db = options.db;
    this.#clock = options.clock;
    this.#disposer = new BlobDisposer(options);
    this.#envelopesPerRun = limit;
  }

  #now(): Date {
    const now = this.#clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new StorageUsageError('the orphan collector clock returned an invalid date');
    return now;
  }

  /** The refs of `envelopeId` to propose now (see the header). */
  candidates(store: TenantStore, envelopeId: string, now: Date): string[] {
    const earlier = collectedBefore(store, envelopeId);
    const pending = listAttemptBlobs(store, envelopeId).filter(
      (record) => !earlier.some((disposal) => disposal.refs.has(record.blobRef) && disposal.at >= record.recordedAt),
    );
    const protection = new ReferenceProtection(store, { envelopeId, kind: 'orphan-collection', scope: undefined });
    const refs = new Set<string>();
    for (const ref of new Set(pending.map((record) => record.blobRef))) {
      const holders: readonly AttemptBlobRecord[] = attemptBlobsOfRef(store, ref);
      if (!holders.every((record) => attemptCollectable(store, record.envelopeId, record.fencingToken, now))) continue;
      if (protection.referenced(ref)) continue;
      refs.add(ref);
    }
    return [...refs].sort();
  }

  /** One bounded collection run for a tenant, after the `after` cursor (a previous run's `next`). */
  run(tenantId: string, after?: string): OrphanRun {
    if (after !== undefined && (typeof after !== 'string' || after.length === 0)) throw new StorageUsageError('the orphan cursor is a previous run’s next');
    const store = this.#db.forTenant(tenantId);
    const now = this.#now();
    const envelopes: string[] = [];
    let next: string | null = null;
    const where: Parameters<TenantStore['iterate']>[1] = after === undefined ? {} : { envelope_id: { op: '>' as const, value: after } };
    for (const row of store.iterate('finalization_attempt_blobs', where, { orderBy: [['envelope_id', 'asc']] })) {
      const envelopeId = String(row['envelope_id']);
      if (envelopes[envelopes.length - 1] === envelopeId) continue;
      if (envelopes.length >= this.#envelopesPerRun) {
        next = envelopes[envelopes.length - 1] ?? null;
        break;
      }
      envelopes.push(envelopeId);
    }
    const disposals: DisposalOutcome[] = [];
    for (const envelopeId of envelopes) {
      const refs = this.candidates(store, envelopeId, now);
      if (refs.length === 0) continue;
      const artifact = store.get('final_artifacts', { envelope_id: envelopeId });
      const retained = artifact === undefined ? [] : [artifact['artifact_digest'], artifact['package_digest']].filter((digest): digest is string => typeof digest === 'string');
      disposals.push(this.#disposer.dispose(tenantId, { envelopeId, kind: 'orphan-collection', policyRef: ORPHAN_POLICY_REF, refs, retainedArtifactDigests: retained }));
    }
    return { tenantId, disposals, next };
  }
}
