// SPDX-License-Identifier: Apache-2.0
//
// Backup (data-model.md § "Backups and the exported-head ledger", A-009): a
// consistent copy of the database (SQLite online backup API), every tenant's
// blobs (read with digest verification, written with the expected digest),
// and a canonical manifest that binds the database file by SHA-256 and
// records each tenant's audit chain head.
//
// Order of a backup:
// 1. Write it into a staging directory, `.staging-<random>-<final name>`,
//    beside the final directory.
// 2. Verify it: every tenant's chain verifies and contains the head recorded
//    in the exported-head ledger; a ledger tenant missing from the database,
//    or a retired tenant that reappears, refuses; every blob a row still
//    requires (T029's ReferenceProtection predicate) is present.
// 3. Under the ledger lock, taken before the snapshot is closed: re-read the
//    ledger and re-check every tenant against it, then commit every tenant's
//    new head in ONE atomic replace. The ledger rename is the commit point.
// 4. Still under the lock, publish: rename staging to the final name, fsync
//    the parent directory, and clear the publication record.
// Any refusal or failure before the commit point leaves the ledger
// byte-identical and removes this run's staging (BackupError, LedgerError,
// LedgerLockedError: status refused). After it, the staged backup is
// preserved under exactly one name and PendingPublicationError is raised
// (status committed-pending-publication): a failed ledger-directory fsync
// (then nothing is published), a failed staging rename, or a failed parent
// fsync. While a pending committed staging exists, a backup changes nothing.
//
// Blob size limit (Codex [17]): the backup opens the source and target blob
// stores with the source store's configured limit (maxBlobBytes, CLI
// --max-blob-bytes; default the blob store's default) and records it in the
// manifest as blob_max_bytes, so verify and restore use the same limit. A
// blob above the limit refuses the backup; nothing is truncated.
//
// Layout of a published backup directory (0700, files 0600):
//   opensig.db      the database snapshot
//   blobs/          a blob store root (tenants/<tenant>/sha256/<digest>)
//   manifest.json   RFC 8785 canonical manifest

import { randomBytes } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { backup, DatabaseSync } from 'node:sqlite';

import { canonicalBytes, type JsonValue } from '../../domain/canonical/index.ts';
import { verifyChain, type ChainProblem } from '../audit/verify.ts';
import { DEFAULT_MAX_BLOB_BYTES, MAX_BLOB_BYTES_LIMIT, openBlobStore } from '../blobs/file-store.ts';
import { parseBlobRef } from '../blobs/refs.ts';
import { openDatabase, type Database } from '../db/connection.ts';
import { StorageError, StorageUsageError } from '../db/errors.ts';
import { BLOB_REFERENCE_COLUMNS, ReferenceProtection } from '../retention/index.ts';
import { checkAbsolute, fileDigest, removeQuietly, syncDirectory, writePrivateFile } from './files.ts';
import {
  LedgerSession,
  PendingPublicationError,
  readLedgerDocument,
  refuseWhilePending,
  withDefaultIo,
  type ExportedHead,
  type HeadUpdate,
  type LedgerDocument,
  type LedgerIo,
} from './ledger.ts';

export const BACKUP_SCHEMA = 'opensig.backup/1';
export const DATABASE_FILE = 'opensig.db';
export const BLOBS_DIRECTORY = 'blobs';
export const MANIFEST_FILE = 'manifest.json';
const STAGING = /^\.staging-([0-9a-f]{24})-(.+)$/;

export interface BackupTenant {
  readonly tenant_id: string;
  readonly audit_head: { readonly seq: number; readonly digest: string } | null;
  readonly blob_count: number;
}

export interface BackupManifest {
  readonly schema: string;
  readonly created_at: string;
  readonly schema_version: number;
  /** The blob size limit the backup was made with; verify and restore use it. */
  readonly blob_max_bytes: number;
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
  /** The final backup directory: it must not exist, or be an empty directory. */
  readonly outDir: string;
  readonly ledgerPath: string;
  readonly clock: () => Date;
  /**
   * The very first backup: proceed without an exported-head ledger and create
   * it (empty when no tenant has audit events). Without this option a missing
   * ledger refuses the backup.
   */
  readonly firstBackup?: boolean;
  /**
   * The source blob store's configured size limit (default the blob store's
   * default). Recorded in the manifest; a larger blob refuses the backup.
   */
  readonly maxBlobBytes?: number;
  /** Internal seam for failure injection in tests; never exposed by the CLI. */
  readonly io?: Partial<LedgerIo>;
}

/** Validate a blob size limit (the blob store's own bounds). */
export function checkBlobLimit(value: unknown, name = 'blob size limit'): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > MAX_BLOB_BYTES_LIMIT) {
    throw new StorageUsageError(`${name} must be an integer in 1..${MAX_BLOB_BYTES_LIMIT}`);
  }
  return value;
}

/** True for a staging directory name (`.staging-<random>-<final name>`). */
export function isStagingDirectory(path: string): boolean {
  return STAGING.test(basename(path));
}

/** The final directory a staging directory publishes to. */
export function finalDirectoryOf(staging: string): string {
  const match = STAGING.exec(basename(staging));
  if (match === null) throw new StorageUsageError(`${staging} is not a staging directory`);
  return join(dirname(staging), match[2] as string);
}

function stagingDirectoryFor(final: string): string {
  return join(dirname(final), `.staging-${randomBytes(12).toString('hex')}-${basename(final)}`);
}

/**
 * Blob refs that rows of the tenant still require: every ref of a row that
 * still protects it under T029's ReferenceProtection predicate (the same rule
 * the disposer applies; backup keeps no copy of it). Every row is read with
 * the keyset iterator.
 */
export function requiredBlobRefs(db: Database, tenantId: string): Set<string> {
  const store = db.forTenant(tenantId);
  const protection = new ReferenceProtection(store);
  const required = new Set<string>();
  for (const { table, column, kind } of BLOB_REFERENCE_COLUMNS) {
    for (const row of store.iterate(table)) {
      const ref = row[column];
      if (typeof ref === 'string' && protection.protects(String(row['envelope_id']), kind)) required.add(ref);
    }
  }
  return required;
}

/** Why a chain checked against the ledger's head failed, for the refusal message. */
function ledgerDetail(problems: readonly ChainProblem[], recorded: ExportedHead | undefined): string {
  if (recorded === undefined) return '';
  if (problems.some((problem) => problem.kind === 'truncated' && problem.seq === recorded.seq)) {
    return `; its head is older than the last exported head (seq ${recorded.seq})`;
  }
  if (problems.some((problem) => problem.kind === 'head-mismatch')) return `; it diverges from the last exported head at seq ${recorded.seq}`;
  return '';
}

/** Ledger tenants absent from the database, and retired tenants present in it, refuse a backup. */
function checkTenantSet(document: LedgerDocument, tenantIds: readonly string[]): void {
  for (const [tenantId, recorded] of Object.entries(document.tenants)) {
    if (!tenantIds.includes(tenantId)) {
      throw new BackupError(
        `tenant ${tenantId}: the ledger has an exported head (seq ${recorded.seq}) but the database has no such tenant (deleted, or the database was replaced); if the tenant was removed on purpose, record that with --retire-tenant ${tenantId}`,
      );
    }
  }
  for (const tenantId of tenantIds) {
    if (Object.hasOwn(document.retired, tenantId)) {
      throw new BackupError(`tenant ${tenantId}: the tenant was retired in the ledger and has reappeared in the database`);
    }
  }
}

/** The final directory must not exist, or must be an empty directory (checked before and after staging). */
function checkFinalDirectory(final: string): void {
  const stat = lstatSync(final, { throwIfNoEntry: false });
  if (stat === undefined) return;
  if (!stat.isDirectory()) throw new StorageUsageError(`${final} must be a directory, not a link or file`);
  if (readdirSync(final).length > 0) throw new StorageUsageError(`${final} must be empty`);
}

export async function createBackup(options: CreateBackupOptions): Promise<BackupManifest> {
  const databasePath = checkAbsolute(options?.databasePath, 'database path');
  const blobRoot = checkAbsolute(options.blobRoot, 'blob root');
  const final = checkAbsolute(options.outDir, 'backup directory');
  const ledgerPath = checkAbsolute(options.ledgerPath, 'ledger path');
  if (typeof options.clock !== 'function') throw new StorageUsageError('backup needs an injected clock');
  if (isStagingDirectory(final)) throw new StorageUsageError('the backup directory name must not look like a staging directory');
  const firstBackup = options.firstBackup === true;
  const maxBlobBytes = checkBlobLimit(options.maxBlobBytes ?? DEFAULT_MAX_BLOB_BYTES);
  const io = withDefaultIo(options.io);
  // A pending committed staging blocks every backup; nothing is changed.
  refuseWhilePending(ledgerPath);
  // Read (and so require) the ledger before anything is written.
  const initial = readLedgerDocument(ledgerPath, { allowMissing: firstBackup });
  checkFinalDirectory(final);

  const staging = stagingDirectoryFor(final);
  mkdirSync(staging, { mode: 0o700 });
  syncDirectory(dirname(staging));
  let committed: { readonly digest: string } | undefined;
  try {
    const databaseFile = join(staging, DATABASE_FILE);
    writePrivateFile(databaseFile, new Uint8Array(0));
    const source = new DatabaseSync(databasePath, { timeout: 5_000, enableForeignKeyConstraints: true });
    try {
      await backup(source, databaseFile);
    } finally {
      source.close();
    }

    const tenants: BackupTenant[] = [];
    let schemaVersion: number;
    let session: LedgerSession | undefined;
    try {
      let next: LedgerDocument;
      const snapshot = openDatabase({ path: databaseFile });
      try {
        schemaVersion = snapshot.checkSchema();
        const sourceBlobs = openBlobStore({ root: blobRoot, maxBytes: maxBlobBytes });
        const blobDirectory = join(staging, BLOBS_DIRECTORY);
        mkdirSync(blobDirectory, { mode: 0o700 });
        const targetBlobs = openBlobStore({ root: blobDirectory, maxBytes: maxBlobBytes });
        const tenantIds = snapshot.listTenantIds();
        checkTenantSet(initial, tenantIds);
        for (const tenantId of tenantIds) {
          const recorded = initial.tenants[tenantId];
          const chain = verifyChain(snapshot, tenantId, recorded === undefined ? {} : { expectedHead: recorded });
          if (!chain.ok) {
            throw new BackupError(
              `tenant ${tenantId}: audit chain does not verify (${chain.problems.map((problem) => problem.kind).join(', ')})${ledgerDetail(chain.problems, recorded)}`,
            );
          }
          const blobDigests = sourceBlobs.list(tenantId);
          for (const digest of blobDigests) {
            let bytes: Buffer;
            try {
              bytes = sourceBlobs.read(tenantId, digest);
            } catch (error) {
              const message = (error as Error).message;
              const hint = /size limit/.test(message) ? `; this backup's blob size limit is ${maxBlobBytes} bytes: pass the source store's limit with --max-blob-bytes` : '';
              throw new BackupError(`tenant ${tenantId}: blob ${digest} failed verification (${message})${hint}`, { cause: error });
            }
            targetBlobs.put(tenantId, bytes, { expectedDigest: digest });
          }
          for (const ref of requiredBlobRefs(snapshot, tenantId)) {
            const key = parseBlobRef(ref);
            if (key.tenantId !== tenantId || targetBlobs.check(tenantId, key.digest) !== 'ok') {
              throw new BackupError(`tenant ${tenantId}: a blob required by the database is missing (${ref})`);
            }
          }
          tenants.push({ tenant_id: tenantId, audit_head: chain.head, blob_count: blobDigests.length });
        }

        // Take the lock and re-read the ledger before the snapshot closes, so
        // every tenant is checked against the ledger that will be replaced.
        session = LedgerSession.open(ledgerPath, { allowMissing: firstBackup });
        const current = session.document;
        checkTenantSet(current, tenantIds);
        const heads = new Map<string, HeadUpdate>();
        for (const tenant of tenants) {
          const store = snapshot.forTenant(tenant.tenant_id);
          const digestAt = (seq: number): string | undefined => {
            const event = store.get('audit_events', { seq });
            return event === undefined ? undefined : String(event['event_digest']);
          };
          const recorded = current.tenants[tenant.tenant_id];
          if (recorded !== undefined && digestAt(recorded.seq) !== recorded.digest) {
            const before = initial.tenants[tenant.tenant_id];
            const moved = before === undefined || before.seq !== recorded.seq || before.digest !== recorded.digest;
            const head = tenant.audit_head?.seq ?? 0;
            if (moved) {
              throw new BackupError(
                `tenant ${tenant.tenant_id}: the exported-head ledger advanced while this backup ran (now seq ${recorded.seq}; this snapshot's head is seq ${head}); nothing was recorded; run the backup again`,
              );
            }
            throw new BackupError(`tenant ${tenant.tenant_id}: the chain does not contain the last exported head (seq ${recorded.seq})`);
          }
          if (tenant.audit_head !== null) heads.set(tenant.tenant_id, { head: tenant.audit_head, digestAt });
        }
        next = session.plan({ heads, source: 'backup', clock: options.clock });
      } finally {
        snapshot.close();
      }

      const leftovers = readdirSync(staging).filter((name) => name !== DATABASE_FILE && name !== BLOBS_DIRECTORY);
      if (leftovers.length > 0) throw new BackupError('the database snapshot left journal files behind');
      const database = fileDigest(databaseFile);
      const manifest: BackupManifest = {
        schema: BACKUP_SCHEMA,
        created_at: options.clock().toISOString(),
        schema_version: schemaVersion,
        blob_max_bytes: maxBlobBytes,
        database: { file: DATABASE_FILE, sha256: database.sha256, bytes: database.bytes },
        tenants,
      };
      writePrivateFile(join(staging, MANIFEST_FILE), canonicalBytes(manifest as unknown as JsonValue));
      syncDirectory(staging);
      checkFinalDirectory(final);

      // The commit point: one atomic replace of the ledger.
      const result = session.commit(next, { publishing: { staging, final }, io: options.io });
      committed = { digest: result.digest };
      if (!result.durable) {
        throw new PendingPublicationError(staging, result.digest, 'the ledger directory fsync failed after the commit, so nothing was published', { cause: result.cause });
      }
      // Publish, still under the lock.
      try {
        io.rename(staging, final);
      } catch (cause) {
        throw new PendingPublicationError(staging, result.digest, 'renaming the staging directory to its final name failed', { cause });
      }
      try {
        io.syncDirectory(dirname(final));
        session.clearPublishing(options.io);
      } catch (cause) {
        throw new PendingPublicationError(final, result.digest, 'the parent directory fsync failed after the rename', { cause });
      }
      return manifest;
    } finally {
      session?.release();
    }
  } catch (error) {
    if (committed !== undefined) {
      // Post-commit: never delete the staged backup, never claim the ledger is unchanged.
      if (error instanceof PendingPublicationError) throw error;
      throw new PendingPublicationError(staging, committed.digest, 'publication failed after the commit', { cause: error });
    }
    removeQuietly(staging);
    throw error;
  }
}
