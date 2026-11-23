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
//   a divergence. The ledger must exist: a missing ledger is refused unless
//   the explicit firstRestore option says nothing was exported yet;
// - the full ledger is read, retired entries included: a backup that
//   contains a retired tenant is refused (never restored or reported
//   verified), after its chain is checked against the retained head, so the
//   reason says whether it is older than that head, diverges from it, or
//   would reintroduce the tenant at it (there is no un-retire);
// - the directory is a published backup: a directory holding a staged
//   manifest (manifest.staged.json: staging under any name, a copy or a link
//   of one included), a staging directory name (`.staging-*`), and a
//   directory without its final manifest are refused; while a pending
//   committed staging exists, verify and restore report
//   committed-pending-publication and change nothing;
// - every blob in the backup verifies against its digest, and every blob a
//   database row still requires is present.
// Only then are the blobs copied into the (new or empty) target blob root and
// the staged database placed, without replacing anything (link, then unlink
// the staging name): a database that exists at the target, even one created
// during the run, is never touched. A refused restore leaves the target as it
// was. A first restore (firstRestore, ledger missing) takes the ledger lock
// first and, as its last step, writes every restored head in one replace. A
// failure before that commit point removes only what this run created (the
// database file it placed, its staging files and the blobs it wrote) and
// leaves the ledger byte-identical (refused). After the commit point nothing
// is removed: a failed ledger-directory fsync reports committed-unsynced
// (LedgerCommitUnsyncedError, exit 74) with the restored database in place.
// Any other restore never writes the ledger.

import { linkSync, lstatSync, mkdtempSync, readdirSync, readFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

import { parseJson } from '../../domain/canonical/index.ts';
import { verifyChain, type ChainProblem } from '../audit/verify.ts';
import { DEFAULT_MAX_BLOB_BYTES, MAX_BLOB_BYTES_LIMIT, openBlobStore, type FileBlobStore } from '../blobs/file-store.ts';
import { parseBlobRef } from '../blobs/refs.ts';
import { openDatabase, type Database } from '../db/connection.ts';
import { StorageError, StorageUsageError } from '../db/errors.ts';
import { BACKUP_SCHEMA, BLOBS_DIRECTORY, DATABASE_FILE, hasStagedManifest, MANIFEST_FILE, requiredBlobRefs, STAGED_MANIFEST_FILE, type BackupManifest } from './backup.ts';
import { checkAbsolute, copyPrivateFile, fileDigest, prepareEmptyDirectory, removeQuietly, syncDirectory } from './files.ts';
import { isStagingDirectory } from './backup.ts';
import {
  LedgerCommitUnsyncedError,
  ledgerDigest,
  LedgerSession,
  readLedgerDocument,
  refuseWhilePending,
  type HeadUpdate,
  type Ledger,
  type LedgerDocument,
  type LedgerIo,
  type RetiredTenant,
} from './ledger.ts';

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
  /**
   * The first restore of a system whose ledger never existed: proceed without
   * the exported-head ledger. Without this option a missing ledger is refused.
   */
  readonly firstRestore?: boolean;
}

export interface RestoreOptions extends VerifyBackupOptions {
  /** Target database file; must not exist. */
  readonly databasePath: string;
  /** Target blob root; must be new or empty. */
  readonly blobRoot: string;
  /** Clock for the exported_at of heads written by a first restore (default: now). */
  readonly clock?: () => Date;
  /** Internal seam for failure injection in tests; never exposed by the CLI. */
  readonly io?: Partial<LedgerIo>;
}

function readManifest(backupDir: string, reasons: string[], file: string): BackupManifest | undefined {
  let value;
  try {
    value = parseJson(readFileSync(join(backupDir, file), 'utf8'));
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
  // Backups made before the limit was recorded used the blob store's default.
  const limit = (value as Record<string, unknown>)['blob_max_bytes'] ?? DEFAULT_MAX_BLOB_BYTES;
  if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_BLOB_BYTES_LIMIT) {
    reasons.push('manifest blob size limit is malformed');
    return undefined;
  }
  return { ...manifest, blob_max_bytes: limit };
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

/**
 * A backup that contains a retired tenant is refused. Its chain is first
 * checked against the retained head, so the reason says which case it is.
 */
function describeRetired(tenantId: string, retained: RetiredTenant, problems: readonly ChainProblem[]): string[] {
  const never = 'a backup that contains a retired tenant is never restored or verified';
  const reasons: string[] = [];
  let placed = false;
  for (const problem of problems) {
    if (problem.kind === 'truncated' && problem.seq === retained.seq) {
      reasons.push(`tenant ${tenantId}: the tenant is retired; the backup's audit chain head is older than its retained head (seq ${retained.seq}); ${never}`);
      placed = true;
    } else if (problem.kind === 'head-mismatch') {
      reasons.push(`tenant ${tenantId}: the tenant is retired; the backup's audit chain diverges from its retained head at seq ${problem.seq}; ${never}`);
      placed = true;
    } else {
      reasons.push(`tenant ${tenantId}: audit chain ${problem.kind} at seq ${problem.seq}`);
    }
  }
  if (!placed) reasons.push(`tenant ${tenantId}: the tenant is retired; restoring this backup would reintroduce it at its retained head (seq ${retained.seq}); ${never}`);
  return reasons;
}

interface Inspection {
  readonly report: RestoreReport;
  readonly blobs: FileBlobStore;
  /** The manifest's blob size limit, used for the restored blob store too. */
  readonly blobLimit: number;
}

/** Run every check against a staged copy of the backup database. */
function inspect(db: Database, backupDir: string, manifest: BackupManifest, document: LedgerDocument, reasons: string[]): Inspection | undefined {
  const ledger = document.tenants;
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

  const blobs = openBlobStore({ root: join(backupDir, BLOBS_DIRECTORY), maxBytes: manifest.blob_max_bytes });
  const tenants: RestoredTenant[] = [];
  for (const tenantId of [...new Set([...dbTenants, ...Object.keys(ledger)])].sort()) {
    const recorded = ledger[tenantId];
    // A tenant is active or retired in the ledger, never both.
    const retained = Object.hasOwn(document.retired, tenantId) ? document.retired[tenantId] : undefined;
    const expectedHead = recorded ?? retained;
    const chain = verifyChain(db, tenantId, expectedHead === undefined ? {} : { expectedHead });
    if (retained !== undefined) reasons.push(...describeRetired(tenantId, retained, chain.problems));
    else for (const problem of chain.problems) reasons.push(describeProblem(tenantId, problem, ledger));
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
  return { report: { schema_version: schemaVersion, tenants }, blobs, blobLimit: manifest.blob_max_bytes };
}

/**
 * Stage the backup database at `staging`, open it and run every check.
 * Returns the open staged database and the inspection; throws
 * RestoreRefusedError (after closing and removing the staging copy) on any
 * problem.
 */
function stageAndInspect(backupDir: string, document: LedgerDocument, staging: string, manifestFile: string): { readonly db: Database; readonly inspection: Inspection } {
  const reasons: string[] = [];
  const manifest = readManifest(backupDir, reasons, manifestFile);
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
    const inspection = inspect(db, backupDir, manifest, document, reasons);
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

/** Staging is not a published backup: recognised by its staged manifest under any name, and by a staging name. */
function refuseStaging(backupDir: string): void {
  if (hasStagedManifest(backupDir)) {
    throw new RestoreRefusedError([`the directory holds a staged manifest (${STAGED_MANIFEST_FILE}): it is staging, not a published backup`]);
  }
  if (isStagingDirectory(backupDir)) throw new RestoreRefusedError(['a staging directory is not a published backup']);
}

/**
 * Full verification of a backup directory against a given ledger document
 * (active and retired tenants), reading the given manifest file (internal:
 * --complete-staged re-verifies a staged backup with its staged manifest).
 * Returns the report and the manifest.
 */
export function inspectBackupDirectory(backupDir: string, document: LedgerDocument, manifestFile: string = MANIFEST_FILE): { readonly report: RestoreReport; readonly manifest: BackupManifest } {
  const scratch = mkdtempSync(join(tmpdir(), 'opensig-restore-check-'));
  try {
    const { db, inspection } = stageAndInspect(backupDir, document, join(scratch, DATABASE_FILE), manifestFile);
    db.close();
    const manifest = parseJson(readFileSync(join(backupDir, manifestFile), 'utf8')) as unknown as BackupManifest;
    return { report: inspection.report, manifest };
  } finally {
    removeQuietly(scratch);
  }
}

/** Verify a backup without restoring it. */
export function verifyBackup(options: VerifyBackupOptions): RestoreReport {
  const backupDir = checkAbsolute(options?.backupDir, 'backup directory');
  const ledgerPath = checkAbsolute(options.ledgerPath, 'ledger path');
  refuseWhilePending(ledgerPath);
  refuseStaging(backupDir);
  const document = readLedgerDocument(ledgerPath, { allowMissing: options.firstRestore === true });
  return inspectBackupDirectory(backupDir, document).report;
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
  refuseWhilePending(ledgerPath);
  refuseStaging(backupDir);
  const clock = options.clock ?? (() => new Date());
  // A first restore of a system without a ledger writes the restored heads,
  // under the lock, all or nothing. Every other restore only reads it.
  const session = options.firstRestore === true && ledgerDigest(ledgerPath) === null ? LedgerSession.open(ledgerPath, { allowMissing: true }) : undefined;
  try {
    const writeHeads = session !== undefined && !session.existed;
    const document = session === undefined ? readLedgerDocument(ledgerPath, { allowMissing: options.firstRestore === true }) : session.document;
    const staging = join(dirname(databasePath), `.${randomBytes(12).toString('hex')}.restoring`);
    const { db, inspection } = stageAndInspect(backupDir, document, staging, MANIFEST_FILE);
    let createdRoot = false;
    let preparedRoot = false;
    let placed = false;
    let unsynced: { readonly previousDigest: string | null; readonly digest: string; readonly cause: unknown } | undefined;
    try {
      try {
        createdRoot = prepareEmptyDirectory(blobRoot);
        preparedRoot = true;
      } catch (error) {
        // Checked empty before the run: a change now is a refusal found during the run, not a usage error.
        if (error instanceof StorageUsageError) throw new RestoreRefusedError([`the target blob root changed during the restore: ${error.message}`]);
        throw error;
      }
      const target = openBlobStore({ root: blobRoot, maxBytes: inspection.blobLimit });
      for (const tenant of inspection.report.tenants) {
        for (const digest of inspection.blobs.list(tenant.tenant_id)) {
          target.put(tenant.tenant_id, inspection.blobs.read(tenant.tenant_id, digest), { expectedDigest: digest });
        }
      }
      let next;
      if (writeHeads && session !== undefined) {
        const heads = new Map<string, HeadUpdate>();
        for (const tenant of inspection.report.tenants) {
          if (tenant.head === null) continue;
          const store = db.forTenant(tenant.tenant_id);
          heads.set(tenant.tenant_id, {
            head: tenant.head,
            digestAt: (seq) => {
              const event = store.get('audit_events', { seq });
              return event === undefined ? undefined : String(event['event_digest']);
            },
          });
        }
        next = session.plan({ heads, source: 'first-restore', clock });
      }
      db.close();
      for (const suffix of ['-wal', '-shm']) {
        if (lstatSync(`${staging}${suffix}`, { throwIfNoEntry: false }) !== undefined) {
          throw new StorageError('restore_failed', 'the staged database left journal files behind');
        }
      }
      // Place without replacing: link fails if anything exists at the target.
      try {
        linkSync(staging, databasePath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
          // A refusal found during the run (refused, exit 1), not a usage error.
          throw new RestoreRefusedError(['the target database path appeared during the restore; restore never overwrites a database']);
        }
        throw error;
      }
      placed = true;
      unlinkSync(staging);
      syncDirectory(dirname(databasePath));
      if (next !== undefined && session !== undefined) {
        // The ledger write is the last step, the only one that is not undone:
        // commit() throws only before its commit point (the ledger is then
        // byte-identical, here still missing), and the catch below removes
        // the restored database and blobs again.
        const result = session.commit(next, { io: options.io });
        if (!result.durable) unsynced = { previousDigest: result.previousDigest, digest: result.digest, cause: result.cause };
      }
    } catch (error) {
      db.close();
      removeStaging(staging);
      // Only the database file this run placed; never journal files at the
      // target name, which this run did not create.
      if (placed) removeQuietly(databasePath);
      // Only what this run wrote: the root it created, or the entries of the
      // empty root it prepared; never a root that changed before that.
      if (createdRoot) removeQuietly(blobRoot);
      else if (preparedRoot && lstatSync(blobRoot, { throwIfNoEntry: false }) !== undefined) for (const name of readdirSync(blobRoot)) removeQuietly(join(blobRoot, name));
      throw error;
    }
    if (unsynced !== undefined) {
      // Post-commit: the restored database stays in place; nothing is rolled back.
      throw new LedgerCommitUnsyncedError(ledgerPath, unsynced.previousDigest, unsynced.digest, `the restored heads of ${inspection.report.tenants.length} tenant(s), with the database restored at ${databasePath},`, { cause: unsynced.cause });
    }
    return inspection.report;
  } finally {
    session?.release();
  }
}
