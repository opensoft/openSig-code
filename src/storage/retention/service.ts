// SPDX-License-Identifier: Apache-2.0
//
// Retention and disposal. A run, for one tenant:
// 1. Reads the tenant's policy; with no policy nothing is disposed.
// 2. Finishes blob removal for earlier DisposalRecords whose blobs still exist
//    (a crash between the record's commit and the blob removal), unless a
//    live envelope references the blob again.
// 3. Finds envelopes in a terminal state (completed, declined, expired,
//    voided) last updated at or before now - dispose_after_days (injected
//    clock), without a DisposalRecord.
// 4. For each, in one transaction: inserts the DisposalRecord and appends a
//    retention.disposed audit event whose subject_digest is the RFC 8785
//    digest of the record. After the commit it removes the blobs through the
//    blob store.
// Blob refs still referenced by another envelope that is not disposed are
// kept, never removed. Rows are never changed: completed evidence is not
// mutated in place; only blobs are removed, and the record keeps the final
// artifact digests.

import { randomBytes } from 'node:crypto';

import { canonicalDigest } from '../../domain/canonical/index.ts';
import type { AuditWriter } from '../audit/writer.ts';
import type { BlobStore } from '../blobs/file-store.ts';
import { parseBlobRef } from '../blobs/refs.ts';
import type { Database } from '../db/connection.ts';
import { StorageUsageError } from '../db/errors.ts';
import type { Row, TenantStore } from '../db/tenant-store.ts';
import { parseRetentionPolicy, type RetentionPolicy } from './policy.ts';

export const DISPOSAL_RECORD_SCHEMA = 'opensig.disposal-record/1';
export const TERMINAL_STATES: readonly string[] = Object.freeze(['completed', 'declined', 'expired', 'voided']);
const DAY_MS = 86_400_000;

export interface RetentionServiceOptions {
  readonly db: Database;
  readonly blobs: BlobStore;
  readonly audit: AuditWriter;
  /** Injected clock: the cutoff and the record's server_time come from it. */
  readonly clock: () => Date;
  /** Identifier source for DisposalRecords (default: random). */
  readonly newId?: () => string;
}

export interface DisposalOutcome {
  readonly envelopeId: string;
  readonly disposalId: string;
  readonly disposedBlobRefs: readonly string[];
  readonly retainedArtifactDigests: readonly string[];
  /** RFC 8785 digest of the record, also the audit event's subject_digest. */
  readonly recordDigest: string;
}

export interface RetentionRun {
  readonly tenantId: string;
  readonly policy: RetentionPolicy | null;
  readonly disposals: readonly DisposalOutcome[];
  /** Blob refs of earlier records whose removal this run completed. */
  readonly resumedBlobRefs: readonly string[];
  /** Blob refs left in place because another live envelope references them. */
  readonly keptSharedBlobRefs: readonly string[];
}

const ARTIFACT_REF_COLUMNS = ['pdf_blob_ref', 'evidence_blob_ref', 'package_blob_ref'] as const;

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

export class RetentionService {
  readonly #db: Database;
  readonly #blobs: BlobStore;
  readonly #audit: AuditWriter;
  readonly #clock: () => Date;
  readonly #newId: () => string;

  constructor(options: RetentionServiceOptions) {
    if (typeof options?.clock !== 'function') throw new StorageUsageError('retention needs an injected clock');
    this.#db = options.db;
    this.#blobs = options.blobs;
    this.#audit = options.audit;
    this.#clock = options.clock;
    this.#newId = options.newId ?? defaultId;
  }

  #now(): Date {
    const now = this.#clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new StorageUsageError('the retention clock returned an invalid date');
    return now;
  }

  /** True when an envelope outside `excluded` still references `ref`. */
  #referencedElsewhere(store: TenantStore, ref: string, excluded: ReadonlySet<string>): boolean {
    const rows = [
      ...store.list('document_revisions', { blob_ref: ref }),
      ...ARTIFACT_REF_COLUMNS.flatMap((column) => store.list('final_artifacts', { [column]: ref })),
    ];
    return rows.some((row) => !excluded.has(String(row['envelope_id'])));
  }

  #removeBlob(tenantId: string, ref: string): boolean {
    const key = parseBlobRef(ref);
    if (key.tenantId !== tenantId) throw new StorageUsageError('a disposal blob ref belongs to another tenant');
    return this.#blobs.dispose(tenantId, key.digest);
  }

  run(tenantId: string): RetentionRun {
    const store = this.#db.forTenant(tenantId);
    const tenant = store.get('tenants', {});
    if (tenant === undefined) throw new StorageUsageError('unknown tenant');
    const policy = parseRetentionPolicy(tenant['retention_json']);
    if (policy === null) {
      return { tenantId, policy, disposals: [], resumedBlobRefs: [], keptSharedBlobRefs: [] };
    }

    const records = store.list('disposal_records', {}, { orderBy: [['server_time', 'asc']] });
    const disposed = new Set(records.map((row) => String(row['envelope_id'])));
    const resumedBlobRefs: string[] = [];
    for (const record of records) {
      for (const ref of jsonStrings(record, 'disposed_blob_refs_json')) {
        if (this.#referencedElsewhere(store, ref, disposed)) continue;
        const key = parseBlobRef(ref);
        if (this.#blobs.check(tenantId, key.digest) !== 'missing' && this.#removeBlob(tenantId, ref)) resumedBlobRefs.push(ref);
      }
    }

    const now = this.#now();
    const cutoff = new Date(now.getTime() - policy.disposeAfterDays * DAY_MS).toISOString();
    const candidates = store
      .list('envelopes', { state: { op: 'in', values: [...TERMINAL_STATES] }, updated_at: { op: '<=', value: cutoff } }, { orderBy: [['id', 'asc']] })
      .map((row) => String(row['id']))
      .filter((id) => !disposed.has(id));

    const disposals: DisposalOutcome[] = [];
    const keptSharedBlobRefs: string[] = [];
    for (const envelopeId of candidates) {
      const excluded = new Set([...disposed, envelopeId]);
      const artifact = store.get('final_artifacts', { envelope_id: envelopeId });
      const refs = new Set(strings(store.list('document_revisions', { envelope_id: envelopeId }).map((row) => row['blob_ref'])));
      if (policy.scope === 'all' && artifact !== undefined) {
        for (const column of ARTIFACT_REF_COLUMNS) {
          const ref = artifact[column];
          if (typeof ref === 'string') refs.add(ref);
        }
      }
      const disposedBlobRefs: string[] = [];
      for (const ref of [...refs].sort()) {
        if (this.#referencedElsewhere(store, ref, excluded)) keptSharedBlobRefs.push(ref);
        else disposedBlobRefs.push(ref);
      }
      const retainedArtifactDigests =
        artifact === undefined ? [] : [...new Set(strings([artifact['artifact_digest'], artifact['package_digest']]))].sort();
      const disposalId = this.#newId();
      const serverTime = this.#now().toISOString();
      const recordDigest = canonicalDigest({
        schema: DISPOSAL_RECORD_SCHEMA,
        tenant_id: tenantId,
        id: disposalId,
        envelope_id: envelopeId,
        retained_artifact_digests: retainedArtifactDigests,
        disposed_blob_refs: disposedBlobRefs,
        policy_ref: policy.policyRef,
        server_time: serverTime,
      });

      this.#db.transaction(() => {
        store.insert('disposal_records', {
          id: disposalId,
          envelope_id: envelopeId,
          retained_artifact_digests_json: JSON.stringify(retainedArtifactDigests),
          disposed_blob_refs_json: JSON.stringify(disposedBlobRefs),
          policy_ref: policy.policyRef,
          server_time: serverTime,
        });
        this.#audit.append(tenantId, {
          type: 'retention.disposed',
          actor: { kind: 'system', ref: 'retention' },
          envelopeId,
          subjectDigest: recordDigest,
          metadata: {
            disposal_id: disposalId,
            disposed_blob_count: disposedBlobRefs.length,
            retained_artifact_count: retainedArtifactDigests.length,
            policy_ref: policy.policyRef,
          },
        });
      });
      for (const ref of disposedBlobRefs) this.#removeBlob(tenantId, ref);
      disposed.add(envelopeId);
      disposals.push({ envelopeId, disposalId, disposedBlobRefs, retainedArtifactDigests, recordDigest });
    }
    return { tenantId, policy, disposals, resumedBlobRefs, keptSharedBlobRefs };
  }
}
