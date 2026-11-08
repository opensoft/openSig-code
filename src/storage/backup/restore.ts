// SPDX-License-Identifier: Apache-2.0
//
// Restore. Everything is verified before anything is written to the target:
// - the manifest is canonical JSON of the expected shape, and the database
//   file matches its SHA-256 and size;
// - the database's applied migrations are a prefix of this code's set and
//   match the manifest's schema version;
// - every tenant's audit chain verifies (seq continuity, prev_digest links,
//   recomputed event digests, checkpoints), and contains the head recorded in
//   the exported-head ledger: a chain that ends before it is refused as
//   older than the last exported head, and a different digest at that seq as
//   a divergence;
// - every blob in the backup verifies against its digest, and every blob a
//   database row still requires is present.
// Only then are the blobs copied into the (new or empty) target blob root and
// the staged database renamed into place, last. A refused restore leaves the
// target as it was.

import { lstatSync, mkdtempSync, readdirSync, readFileSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

import { parseJson } from '../../domain/canonical/index.ts';
import { verifyChain, type ChainProblem } from '../audit/verify.ts';
import { openBlobStore, type FileBlobStore } from '../blobs/file-store.ts';
import { parseBlobRef } from '../blobs/refs.ts';
import { openDatabase, type Database } from '../db/connection.ts';
import { StorageError, StorageUsageError } from '../db/errors.ts';
import { BACKUP_SCHEMA, BLOBS_DIRECTORY, DATABASE_FILE, MANIFEST_FILE, requiredBlobRefs, type BackupManifest } from './backup.ts';
import { checkAbsolute, copyPrivateFile, fileDigest, prepareEmptyDirectory, removeQuietly, syncDirectory } from './files.ts';
import { readLedger, type Ledger } from './ledger.ts';

export class RestoreRefusedError extends StorageError {
  readonly reasons: readonly string[];

  constructor(reasons: readonly string[]) {
    super('restore_refused', `restore refused: ${reasons.join('; ')}`);
    this.reasons = reasons;
  }
}

export interface RestoredTenant {
  readonly tenant_id: string;
  readonly head: { readonly seq: number; readonly digest: string } | null;
  readonly events: number;
  readonly blobs: number;
}

export interface RestoreReport {
  readonly schema_version: number;
  readonly tenants: readonly RestoredTenant[];
}

export interface VerifyBackupOptions {
  readonly backupDir: string;
  readonly ledgerPath: string;
}

export interface RestoreOptions extends VerifyBackupOptions {
  /** Target database file; must not exist. */
  readonly databasePath: string;
  /** Target blob root; must be new or empty. */
  readonly blobRoot: string;
}

function readManifest(backupDir: string, reasons: string[]): BackupManifest | undefined {
  let value;
  try {
    value = parseJson(readFileSync(join(backupDir, MANIFEST_FILE), 'utf8'));
  } catch {
    reasons.push('manifest is missing or not valid JSON');
    return undefined;
  }
  const manifest = value as unknown as BackupManifest;
  const shapeOk =
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    manifest.schema === BACKUP_SCHEMA &&
    Number.isSafeInteger(manifest.schema_version) &&
    typeof manifest.database === 'object' &&
    manifest.database !== null &&
    manifest.database.file === DATABASE_FILE &&
    typeof manifest.database.sha256 === 'string' &&
    Number.isSafeInteger(manifest.database.bytes) &&
    Array.isArray(manifest.tenants);
  if (!shapeOk) {
    reasons.push('manifest does not have the expected shape');
    return undefined;
  }
  return manifest;
}

function describeProblem(tenantId: string, problem: ChainProblem, ledger: Ledger): string {
  const recorded = ledger[tenantId];
  if (problem.kind === 'truncated' && recorded !== undefined && problem.seq === recorded.seq) {
    return `tenant ${tenantId}: audit chain head is older than the last exported head (seq ${recorded.seq})`;
  }
  if (problem.kind === 'head-mismatch') {
    return `tenant ${tenantId}: audit chain diverges from the last exported head at seq ${problem.seq}`;
  }
  return `tenant ${tenantId}: audit chain ${problem.kind} at seq ${problem.seq}`;
}

interface Inspection {
  readonly report: RestoreReport;
  readonly blobs: FileBlobStore;
}

/** Run every check against a staged copy of the backup database. */
function inspect(db: Database, backupDir: string, manifest: BackupManifest, ledger: Ledger, reasons: string[]): Inspection | undefined {
  let schemaVersion = 0;
  try {
    schemaVersion = db.checkSchema();
  } catch (error) {
    reasons.push(`database schema refused: ${(error as Error).message}`);
    return undefined;
  }
  if (schemaVersion !== manifest.schema_version) reasons.push('database schema version differs from the manifest');

  const dbTenants = db.listTenantIds();
  const manifestTenants = manifest.tenants.map((tenant) => tenant.tenant_id).sort();
  if (dbTenants.join(',') !== manifestTenants.join(',')) reasons.push('the tenants in the database differ from the manifest');

  const blobs = openBlobStore({ root: join(backupDir, BLOBS_DIRECTORY) });
  const tenants: RestoredTenant[] = [];
  for (const tenantId of [...new Set([...dbTenants, ...Object.keys(ledger)])].sort()) {
    const recorded = ledger[tenantId];
    const chain = verifyChain(db, tenantId, recorded === undefined ? {} : { expectedHead: recorded });
    for (const problem of chain.problems) reasons.push(describeProblem(tenantId, problem, ledger));
    if (!dbTenants.includes(tenantId)) continue;
    const listed = manifest.tenants.find((tenant) => tenant.tenant_id === tenantId);
    const recordedHead = listed?.audit_head ?? null;
    const sameHead =
      recordedHead === null ? chain.head === null : chain.head !== null && recordedHead.seq === chain.head.seq && recordedHead.digest === chain.head.digest;
    if (listed !== undefined && !sameHead) {
      reasons.push(`tenant ${tenantId}: audit chain head differs from the manifest`);
    }
    const digests = blobs.list(tenantId);
    for (const digest of digests) {
      if (blobs.check(tenantId, digest) !== 'ok') reasons.push(`tenant ${tenantId}: blob ${digest} failed verification`);
    }
    for (const ref of requiredBlobRefs(db, tenantId)) {
      const key = parseBlobRef(ref);
      if (key.tenantId !== tenantId || !digests.includes(key.digest)) reasons.push(`tenant ${tenantId}: required blob ${ref} is missing`);
    }
    tenants.push({ tenant_id: tenantId, head: chain.head, events: chain.events, blobs: digests.length });
  }
  return { report: { schema_version: schemaVersion, tenants }, blobs };
}

/**
 * Stage the backup database at `staging`, open it and run every check.
 * Returns the open staged database and the inspection; throws
 * RestoreRefusedError (after closing and removing the staging copy) on any
 * problem.
 */
function stageAndInspect(backupDir: string, ledgerPath: string, staging: string): { readonly db: Database; readonly inspection: Inspection } {
  const reasons: string[] = [];
  const manifest = readManifest(backupDir, reasons);
  const ledger = readLedger(ledgerPath);
  if (manifest === undefined) throw new RestoreRefusedError(reasons);
  const databaseFile = join(backupDir, DATABASE_FILE);
  let digest;
  try {
    digest = fileDigest(databaseFile);
  } catch {
    throw new RestoreRefusedError(['database file is missing']);
  }
  if (digest.sha256 !== manifest.database.sha256 || digest.bytes !== manifest.database.bytes) {
    throw new RestoreRefusedError(['database file does not match the manifest digest']);
  }
  copyPrivateFile(databaseFile, staging);
  let db: Database | undefined;
  try {
    db = openDatabase({ path: staging });
    const inspection = inspect(db, backupDir, manifest, ledger, reasons);
    if (inspection === undefined || reasons.length > 0) throw new RestoreRefusedError(reasons);
    return { db, inspection };
  } catch (error) {
    db?.close();
    removeStaging(staging);
    throw error;
  }
}

function removeStaging(staging: string): void {
  for (const suffix of ['', '-wal', '-shm', '-journal']) removeQuietly(`${staging}${suffix}`);
}

/** Verify a backup without restoring it. */
export function verifyBackup(options: VerifyBackupOptions): RestoreReport {
  const backupDir = checkAbsolute(options?.backupDir, 'backup directory');
  const ledgerPath = checkAbsolute(options.ledgerPath, 'ledger path');
  const scratch = mkdtempSync(join(tmpdir(), 'opensig-restore-check-'));
  try {
    const { db, inspection } = stageAndInspect(backupDir, ledgerPath, join(scratch, DATABASE_FILE));
    db.close();
    return inspection.report;
  } finally {
    removeQuietly(scratch);
  }
}

/** Verify a backup, then restore it into a new database path and a new or empty blob root. */
export function restoreBackup(options: RestoreOptions): RestoreReport {
  const backupDir = checkAbsolute(options?.backupDir, 'backup directory');
  const ledgerPath = checkAbsolute(options.ledgerPath, 'ledger path');
  const databasePath = checkAbsolute(options.databasePath, 'target database path');
  const blobRoot = checkAbsolute(options.blobRoot, 'target blob root');
  if (lstatSync(databasePath, { throwIfNoEntry: false }) !== undefined) {
    throw new StorageUsageError('the target database path already exists; restore never overwrites a database');
  }
  const blobRootState = lstatSync(blobRoot, { throwIfNoEntry: false });
  if (blobRootState !== undefined && (!blobRootState.isDirectory() || readdirSync(blobRoot).length > 0)) {
    throw new StorageUsageError('the target blob root must be new or empty');
  }
  const staging = join(dirname(databasePath), `.${randomBytes(12).toString('hex')}.restoring`);
  const { db, inspection } = stageAndInspect(backupDir, ledgerPath, staging);
  let createdRoot = false;
  try {
    createdRoot = prepareEmptyDirectory(blobRoot);
    const target = openBlobStore({ root: blobRoot });
    for (const tenant of inspection.report.tenants) {
      for (const digest of inspection.blobs.list(tenant.tenant_id)) {
        target.put(tenant.tenant_id, inspection.blobs.read(tenant.tenant_id, digest), { expectedDigest: digest });
      }
    }
    db.close();
    for (const suffix of ['-wal', '-shm']) {
      if (lstatSync(`${staging}${suffix}`, { throwIfNoEntry: false }) !== undefined) {
        throw new StorageError('restore_failed', 'the staged database left journal files behind');
      }
    }
    renameSync(staging, databasePath);
    syncDirectory(dirname(databasePath));
    return inspection.report;
  } catch (error) {
    db.close();
    removeStaging(staging);
    if (createdRoot) removeQuietly(blobRoot);
    else if (lstatSync(blobRoot, { throwIfNoEntry: false }) !== undefined) for (const name of readdirSync(blobRoot)) removeQuietly(join(blobRoot, name));
    throw error;
  }
}
