// SPDX-License-Identifier: Apache-2.0
//
// Backup: a consistent copy of the database (SQLite online backup API), every
// tenant's blobs (read with digest verification, written with the expected
// digest), and a canonical manifest that binds the database file by SHA-256
// and records each tenant's audit chain head. A backup is refused when a
// tenant's audit chain does not verify, a blob fails verification, or a blob
// that a database row still requires is missing. On success each tenant's
// head is recorded in the exported-head ledger.
//
// Layout of the backup directory (created 0700, files 0600):
//   opensig.db      the database snapshot
//   blobs/          a blob store root (tenants/<tenant>/sha256/<digest>)
//   manifest.json   RFC 8785 canonical manifest

import { mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { backup, DatabaseSync } from 'node:sqlite';

import { canonicalBytes, type JsonValue } from '../../domain/canonical/index.ts';
import { verifyChain } from '../audit/verify.ts';
import { openBlobStore } from '../blobs/file-store.ts';
import { parseBlobRef } from '../blobs/refs.ts';
import { openDatabase, type Database } from '../db/connection.ts';
import { StorageError, StorageUsageError } from '../db/errors.ts';
import { checkAbsolute, fileDigest, prepareEmptyDirectory, removeQuietly, syncDirectory, writePrivateFile } from './files.ts';
import { recordExportedHead } from './ledger.ts';

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
}

const ARTIFACT_REF_COLUMNS = ['pdf_blob_ref', 'evidence_blob_ref', 'package_blob_ref'] as const;

/**
 * Blob refs that rows of the tenant still require: every document revision
 * and final artifact ref, except refs that a DisposalRecord of the same
 * envelope lists as disposed.
 */
export function requiredBlobRefs(db: Database, tenantId: string): Set<string> {
  const store = db.forTenant(tenantId);
  const disposed = new Map<string, Set<string>>();
  for (const record of store.list('disposal_records')) {
    const refs: unknown = JSON.parse(String(record['disposed_blob_refs_json']));
    const set = disposed.get(String(record['envelope_id'])) ?? new Set<string>();
    if (Array.isArray(refs)) for (const ref of refs) if (typeof ref === 'string') set.add(ref);
    disposed.set(String(record['envelope_id']), set);
  }
  const required = new Set<string>();
  const consider = (envelopeId: unknown, ref: unknown): void => {
    if (typeof ref !== 'string') return;
    if (disposed.get(String(envelopeId))?.has(ref) === true) return;
    required.add(ref);
  };
  for (const row of store.list('document_revisions')) consider(row['envelope_id'], row['blob_ref']);
  for (const row of store.list('final_artifacts')) for (const column of ARTIFACT_REF_COLUMNS) consider(row['envelope_id'], row[column]);
  return required;
}

export async function createBackup(options: CreateBackupOptions): Promise<BackupManifest> {
  const databasePath = checkAbsolute(options?.databasePath, 'database path');
  const blobRoot = checkAbsolute(options.blobRoot, 'blob root');
  const outDir = checkAbsolute(options.outDir, 'backup directory');
  const ledgerPath = checkAbsolute(options.ledgerPath, 'ledger path');
  if (typeof options.clock !== 'function') throw new StorageUsageError('backup needs an injected clock');
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
    let schemaVersion: number;
    const snapshot = openDatabase({ path: databaseFile });
    try {
      schemaVersion = snapshot.checkSchema();
      const sourceBlobs = openBlobStore({ root: blobRoot });
      const blobDirectory = join(outDir, BLOBS_DIRECTORY);
      mkdirSync(blobDirectory, { mode: 0o700 });
      const targetBlobs = openBlobStore({ root: blobDirectory });
      for (const tenantId of snapshot.listTenantIds()) {
        const chain = verifyChain(snapshot, tenantId);
        if (!chain.ok) {
          throw new BackupError(`tenant ${tenantId}: audit chain does not verify (${chain.problems.map((problem) => problem.kind).join(', ')})`);
        }
        const digests = sourceBlobs.list(tenantId);
        for (const digest of digests) targetBlobs.put(tenantId, sourceBlobs.read(tenantId, digest), { expectedDigest: digest });
        for (const ref of requiredBlobRefs(snapshot, tenantId)) {
          const key = parseBlobRef(ref);
          if (key.tenantId !== tenantId || targetBlobs.check(tenantId, key.digest) !== 'ok') {
            throw new BackupError(`tenant ${tenantId}: a blob required by the database is missing (${ref})`);
          }
        }
        tenants.push({ tenant_id: tenantId, audit_head: chain.head, blob_count: digests.length });
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
    for (const tenant of tenants) {
      if (tenant.audit_head !== null) recordExportedHead(ledgerPath, tenant.tenant_id, tenant.audit_head, { clock: options.clock, source: 'backup' });
    }
    return manifest;
  } catch (error) {
    if (created) removeQuietly(outDir);
    else for (const name of readdirSync(outDir)) removeQuietly(join(outDir, name));
    throw error;
  }
}
