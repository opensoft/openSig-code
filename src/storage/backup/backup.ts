// SPDX-License-Identifier: Apache-2.0
//
// Backup: a consistent copy of the database (SQLite online backup API), every
// tenant's blobs (read with digest verification, written with the expected
// digest), and a canonical manifest that binds the database file by SHA-256
// and records each tenant's audit chain head. A backup is refused when a
// tenant's audit chain does not verify, or does not contain the head already
// recorded in the exported-head ledger (a chain rolled back or rewritten
// after that head left the system), when a tenant with an exported head is
// missing, when a blob fails verification, or when a blob that a database
// row still requires is missing. A refused backup leaves the ledger
// unchanged. On success each tenant's head is recorded in the ledger, which
// requires ancestry again at write time.
//
// The ledger must exist; only the explicit firstBackup option (nothing has
// been exported yet) starts without one and creates it.
//
// Layout of the backup directory (created 0700, files 0600):
//   opensig.db      the database snapshot
//   blobs/          a blob store root (tenants/<tenant>/sha256/<digest>)
//   manifest.json   RFC 8785 canonical manifest

import { mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { backup, DatabaseSync } from 'node:sqlite';

import { canonicalBytes, parseJson, type JsonValue } from '../../domain/canonical/index.ts';
import { verifyChain } from '../audit/verify.ts';
import { openBlobStore } from '../blobs/file-store.ts';
import { parseBlobRef } from '../blobs/refs.ts';
import { openDatabase, type Database } from '../db/connection.ts';
import { StorageError, StorageUsageError } from '../db/errors.ts';
import { checkAbsolute, fileDigest, prepareEmptyDirectory, removeQuietly, syncDirectory, writePrivateFile } from './files.ts';
import { readLedger, recordExportedHead, type ExportedHead } from './ledger.ts';

export const BACKUP_SCHEMA = 'opensig.backup/1';
export const DATABASE_FILE = 'opensig.db';
export const BLOBS_DIRECTORY = 'blobs';
export const MANIFEST_FILE = 'manifest.json';

export interface BackupTenant {
  readonly tenant_id: string;
  readonly audit_head: { readonly seq: number; readonly digest: string } | null;
  readonly blob_count: number;
}

export interface BackupManifest {
  readonly schema: string;
  readonly created_at: string;
  readonly schema_version: number;
  readonly database: { readonly file: string; readonly sha256: string; readonly bytes: number };
  readonly tenants: readonly BackupTenant[];
}

export class BackupError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('backup_failed', message, options);
  }
}

export interface CreateBackupOptions {
  readonly databasePath: string;
  readonly blobRoot: string;
  /** A new or empty directory for the backup. */
  readonly outDir: string;
  readonly ledgerPath: string;
  readonly clock: () => Date;
  /**
   * The very first backup: proceed without an exported-head ledger and create
   * it. Without this option a missing ledger refuses the backup.
   */
  readonly firstBackup?: boolean;
}

const ARTIFACT_REF_COLUMNS = ['pdf_blob_ref', 'evidence_blob_ref', 'package_blob_ref'] as const;
const RETENTION_EVENT = 'retention.disposed';

/**
 * Blob refs that rows of the tenant still require. A row requires its ref
 * unless its envelope gave the ref up, by the rule of the retention disposal
 * path (T029): a document revision of an envelope with a retention
 * DisposalRecord, a final artifact of an envelope disposed with scope 'all'
 * (recorded in its retention.disposed audit event), or any ref the
 * envelope's own DisposalRecords list as disposed. A blob shared by several
 * envelopes therefore stays required exactly while some row that has not
 * given it up references it, so a shared blob removed by a later disposal is
 * not demanded. Every row is read with the keyset iterator, never a capped
 * list.
 */
export function requiredBlobRefs(db: Database, tenantId: string): Set<string> {
  const store = db.forTenant(tenantId);
  const disposed = new Map<string, Set<string>>();
  const retentionDisposed = new Set<string>();
  for (const record of store.iterate('disposal_records')) {
    const envelopeId = String(record['envelope_id']);
    if (record['kind'] === 'retention') retentionDisposed.add(envelopeId);
    const refs: unknown = JSON.parse(String(record['disposed_blob_refs_json']));
    const set = disposed.get(envelopeId) ?? new Set<string>();
    if (Array.isArray(refs)) for (const ref of refs) if (typeof ref === 'string') set.add(ref);
    disposed.set(envelopeId, set);
  }
  const scopeAll = new Map<string, boolean>();
  const artifactsGivenUp = (envelopeId: string): boolean => {
    if (!retentionDisposed.has(envelopeId)) return false;
    let all = scopeAll.get(envelopeId);
    if (all === undefined) {
      all = false;
      for (const event of store.iterate('audit_events', { envelope_id: envelopeId, type: RETENTION_EVENT })) {
        const metadata = parseJson(String(event['metadata_json']));
        if (metadata !== null && typeof metadata === 'object' && !Array.isArray(metadata) && metadata['scope'] === 'all') all = true;
      }
      scopeAll.set(envelopeId, all);
    }
    return all;
  };
  const required = new Set<string>();
  for (const row of store.iterate('document_revisions')) {
    const envelopeId = String(row['envelope_id']);
    const ref = row['blob_ref'];
    if (typeof ref !== 'string' || retentionDisposed.has(envelopeId) || disposed.get(envelopeId)?.has(ref) === true) continue;
    required.add(ref);
  }
  for (const row of store.iterate('final_artifacts')) {
    const envelopeId = String(row['envelope_id']);
    for (const column of ARTIFACT_REF_COLUMNS) {
      const ref = row[column];
      if (typeof ref !== 'string' || disposed.get(envelopeId)?.has(ref) === true || artifactsGivenUp(envelopeId)) continue;
      required.add(ref);
    }
  }
  return required;
}

/** Why a chain checked against the ledger's head failed, for the refusal message. */
function ledgerDetail(problems: readonly { readonly kind: string; readonly seq: number }[], recorded: ExportedHead | undefined): string {
  if (recorded === undefined) return '';
  if (problems.some((problem) => problem.kind === 'truncated' && problem.seq === recorded.seq)) {
    return `; its head is older than the last exported head (seq ${recorded.seq})`;
  }
  if (problems.some((problem) => problem.kind === 'head-mismatch')) return `; it diverges from the last exported head at seq ${recorded.seq}`;
  return '';
}

export async function createBackup(options: CreateBackupOptions): Promise<BackupManifest> {
  const databasePath = checkAbsolute(options?.databasePath, 'database path');
  const blobRoot = checkAbsolute(options.blobRoot, 'blob root');
  const outDir = checkAbsolute(options.outDir, 'backup directory');
  const ledgerPath = checkAbsolute(options.ledgerPath, 'ledger path');
  if (typeof options.clock !== 'function') throw new StorageUsageError('backup needs an injected clock');
  const firstBackup = options.firstBackup === true;
  // Read (and so require) the ledger before anything is written.
  const ledger = readLedger(ledgerPath, { allowMissing: firstBackup });
  const created = prepareEmptyDirectory(outDir);
  try {
    const databaseFile = join(outDir, DATABASE_FILE);
    writePrivateFile(databaseFile, new Uint8Array(0));
    const source = new DatabaseSync(databasePath, { timeout: 5_000, enableForeignKeyConstraints: true });
    try {
      await backup(source, databaseFile);
    } finally {
      source.close();
    }

    const tenants: BackupTenant[] = [];
    const chainDigests = new Map<string, Map<number, string>>();
    let schemaVersion: number;
    const snapshot = openDatabase({ path: databaseFile });
    try {
      schemaVersion = snapshot.checkSchema();
      const sourceBlobs = openBlobStore({ root: blobRoot });
      const blobDirectory = join(outDir, BLOBS_DIRECTORY);
      mkdirSync(blobDirectory, { mode: 0o700 });
      const targetBlobs = openBlobStore({ root: blobDirectory });
      const tenantIds = snapshot.listTenantIds();
      for (const [tenantId, recorded] of Object.entries(ledger)) {
        if (!tenantIds.includes(tenantId)) {
          throw new BackupError(`tenant ${tenantId}: the database has no audit chain for a tenant whose head was exported (seq ${recorded.seq})`);
        }
      }
      for (const tenantId of tenantIds) {
        const recorded = ledger[tenantId];
        const chain = verifyChain(snapshot, tenantId, recorded === undefined ? {} : { expectedHead: recorded });
        if (!chain.ok) {
          throw new BackupError(
            `tenant ${tenantId}: audit chain does not verify (${chain.problems.map((problem) => problem.kind).join(', ')})${ledgerDetail(chain.problems, recorded)}`,
          );
        }
        const digests = new Map<number, string>();
        const store = snapshot.forTenant(tenantId);
        for (const seq of [chain.head?.seq, recorded?.seq]) {
          if (seq === undefined) continue;
          const event = store.get('audit_events', { seq });
          if (event !== undefined) digests.set(seq, String(event['event_digest']));
        }
        chainDigests.set(tenantId, digests);
        const blobDigests = sourceBlobs.list(tenantId);
        for (const digest of blobDigests) targetBlobs.put(tenantId, sourceBlobs.read(tenantId, digest), { expectedDigest: digest });
        for (const ref of requiredBlobRefs(snapshot, tenantId)) {
          const key = parseBlobRef(ref);
          if (key.tenantId !== tenantId || targetBlobs.check(tenantId, key.digest) !== 'ok') {
            throw new BackupError(`tenant ${tenantId}: a blob required by the database is missing (${ref})`);
          }
        }
        tenants.push({ tenant_id: tenantId, audit_head: chain.head, blob_count: blobDigests.length });
      }
    } finally {
      snapshot.close();
    }

    const leftovers = readdirSync(outDir).filter((name) => name !== DATABASE_FILE && name !== BLOBS_DIRECTORY);
    if (leftovers.length > 0) throw new BackupError('the database snapshot left journal files behind');
    const database = fileDigest(databaseFile);
    const manifest: BackupManifest = {
      schema: BACKUP_SCHEMA,
      created_at: options.clock().toISOString(),
      schema_version: schemaVersion,
      database: { file: DATABASE_FILE, sha256: database.sha256, bytes: database.bytes },
      tenants,
    };
    writePrivateFile(join(outDir, MANIFEST_FILE), canonicalBytes(manifest as unknown as JsonValue));
    syncDirectory(outDir);
    // recordExportedHead re-reads the ledger and requires ancestry again, so a
    // ledger advanced meanwhile along another chain refuses this backup.
    for (const tenant of tenants) {
      if (tenant.audit_head === null) continue;
      const digests = chainDigests.get(tenant.tenant_id);
      recordExportedHead(ledgerPath, tenant.tenant_id, tenant.audit_head, {
        clock: options.clock,
        source: 'backup',
        digestAt: (seq) => digests?.get(seq),
        createIfMissing: firstBackup,
      });
    }
    return manifest;
  } catch (error) {
    if (created) removeQuietly(outDir);
    else for (const name of readdirSync(outDir)) removeQuietly(join(outDir, name));
    throw error;
  }
}
