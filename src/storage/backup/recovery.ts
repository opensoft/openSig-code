// SPDX-License-Identifier: Apache-2.0
//
// Operator recovery for backups and the exported-head ledger (data-model.md
// § "Backups and the exported-head ledger", rules 3 and 5), each under the
// ledger lock:
// - completeStaged (--complete-staged <dir>, the staging or the final name):
//   re-verify the staged backup in full, require its heads to equal the
//   committed ledger heads for every tenant, then re-commit the ledger's
//   current bytes by a fresh atomic replace (never a bare re-fsync), rename
//   the directory if it is still staged, publish its final manifest, and
//   fsync the parent; published only after the parent fsync. A mismatch or a
//   failed verification refuses and touches nothing; a repeated I/O failure
//   is committed-pending-publication again.
// - discardStaged (--discard-staged <dir>): acts only on a directory under
//   its staging name, addressed by its exact current name (identified by
//   device and inode, whatever spelling of the path is given). It deletes
//   uncommitted staging; the pending committed staging only with
//   abandonCommitted (--abandon-committed <ledger-digest>) equal to the
//   current ledger digest, leaving the ledger as committed. It never deletes
//   a backup under its final name, and reports the path it deleted.
// - resyncLedger (--resync-ledger <ledger-digest>): after committed-unsynced,
//   re-commit the same ledger bytes by a fresh atomic replace when the
//   current digest is the given one; otherwise refuse and change nothing.
// - retireTenant (--retire-tenant <tenant_id>): record that a tenant absent
//   from the database is retired, with its last head.

import { lstatSync, readdirSync, realpathSync, type Stats } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { openDatabase } from '../db/connection.ts';
import { StorageError, StorageUsageError } from '../db/errors.ts';
import { finalDirectoryOf, isStagingDirectory, MANIFEST_FILE, STAGED_MANIFEST_FILE } from './backup.ts';
import { checkAbsolute, removeQuietly } from './files.ts';
import {
  LedgerCommitUnsyncedError,
  LedgerError,
  LedgerSession,
  PendingPublicationError,
  withDefaultIo,
  withLedgerSession,
  type LedgerIo,
  type PublishingRecord,
  type RetiredTenant,
} from './ledger.ts';
import { inspectBackupDirectory, RestoreRefusedError } from './restore.ts';

/** A recovery operation refused; nothing was changed. */
export class RecoveryRefusedError extends StorageError {
  readonly status = 'refused' as const;

  constructor(message: string, options?: { cause?: unknown }) {
    super('recovery_refused', message, options);
  }
}

export interface RecoveryOptions {
  readonly ledgerPath: string;
  /** Internal seam for failure injection in tests; never exposed by the CLI. */
  readonly io?: Partial<LedgerIo>;
}

export interface CompletedStaged {
  readonly status: 'published';
  readonly directory: string;
}

const statOf = (path: string): Stats | undefined => lstatSync(path, { throwIfNoEntry: false });
const exists = (path: string): boolean => statOf(path) !== undefined;

/** True when both paths name the same existing entry (device and inode), or are the same path once normalized. */
function samePath(a: string, b: string): boolean {
  if (resolve(a) === resolve(b)) return true;
  const left = statOf(a);
  const right = statOf(b);
  return left !== undefined && right !== undefined && left.dev === right.dev && left.ino === right.ino;
}

/** Where a staged backup lives now and where it publishes to. */
function locate(dir: string, pending: PublishingRecord | undefined): { readonly current: string; readonly final: string; readonly staged: boolean; readonly pending: boolean } {
  if (pending !== undefined) {
    if (samePath(dir, pending.staging)) {
      if (exists(pending.staging)) return { current: pending.staging, final: pending.final, staged: true, pending: true };
      if (exists(pending.final)) return { current: pending.final, final: pending.final, staged: false, pending: true };
      throw new RecoveryRefusedError(`${dir} does not exist, and the pending backup is not under its final name ${pending.final} either`);
    }
    if (samePath(dir, pending.final)) {
      if (!exists(pending.final)) throw new RecoveryRefusedError(`${dir} does not exist; the pending backup is still under its staging name ${pending.staging}`);
      return { current: pending.final, final: pending.final, staged: false, pending: true };
    }
  }
  if (!exists(dir)) throw new RecoveryRefusedError(`${dir} does not exist`);
  if (isStagingDirectory(dir)) return { current: dir, final: finalDirectoryOf(dir), staged: true, pending: false };
  return { current: dir, final: dir, staged: false, pending: false };
}

/** Re-verify a staged backup and publish it (see the module comment). */
export function completeStaged(dir: string, options: RecoveryOptions): CompletedStaged {
  checkAbsolute(dir, 'staged backup directory');
  const ledgerPath = checkAbsolute(options?.ledgerPath, 'ledger path');
  const io = withDefaultIo(options.io);
  return withLedgerSession(ledgerPath, { recovery: true }, (session) => {
    const where = locate(dir, session.pending);
    const stagedManifest = exists(join(where.current, STAGED_MANIFEST_FILE));
    if (stagedManifest && exists(join(where.current, MANIFEST_FILE))) {
      throw new RecoveryRefusedError(`${where.current} holds both a staged and a final manifest; nothing was changed`);
    }
    let manifest;
    try {
      ({ manifest } = inspectBackupDirectory(where.current, session.document.tenants, stagedManifest ? STAGED_MANIFEST_FILE : MANIFEST_FILE));
    } catch (error) {
      if (error instanceof RestoreRefusedError) throw new RecoveryRefusedError(`the staged backup does not verify: ${error.reasons.join('; ')}`, { cause: error });
      throw error;
    }
    const committed = session.document.tenants;
    const staged = new Map(manifest.tenants.map((tenant) => [tenant.tenant_id, tenant.audit_head]));
    for (const [tenantId, head] of Object.entries(committed)) {
      const stagedHead = staged.get(tenantId);
      if (stagedHead === undefined || stagedHead === null || stagedHead.seq !== head.seq || stagedHead.digest !== head.digest) {
        throw new RecoveryRefusedError(`tenant ${tenantId}: the staged head differs from the committed ledger head (seq ${head.seq}); nothing was changed`);
      }
    }
    for (const [tenantId, head] of staged) {
      if (head !== null && committed[tenantId] === undefined) {
        throw new RecoveryRefusedError(`tenant ${tenantId}: the staged backup has a head the committed ledger does not record; nothing was changed`);
      }
    }
    const digest = session.digest;
    if (digest === null) throw new LedgerError('the exported-head ledger is missing');
    if (where.staged && exists(where.final) && (!lstatSync(where.final).isDirectory() || readdirSync(where.final).length > 0)) {
      throw new RecoveryRefusedError(`${where.final} already exists; nothing was changed`);
    }
    let current = where.current;
    try {
      // A fresh replace of the committed bytes, not a retried fsync.
      const recommitted = session.recommit(options.io);
      if (!recommitted.durable) throw recommitted.cause ?? new Error('the ledger directory fsync failed');
      if (where.staged) {
        io.rename(where.current, where.final);
        current = where.final;
      }
      if (stagedManifest) {
        io.rename(join(where.final, STAGED_MANIFEST_FILE), join(where.final, MANIFEST_FILE));
        io.syncDirectory(where.final);
      }
      io.syncDirectory(dirname(where.final));
      if (where.pending) session.clearPublishing(options.io);
    } catch (cause) {
      throw new PendingPublicationError(current, digest, 'completing the publication failed again', { cause });
    }
    return { status: 'published', directory: where.final };
  });
}

export interface DiscardOptions extends RecoveryOptions {
  /** The current ledger digest, to abandon the pending committed staging. */
  readonly abandonCommitted?: string;
}

export interface Discarded {
  readonly status: 'discarded' | 'abandoned-committed';
  /** The directory actually deleted (its real path). */
  readonly directory: string;
  /** abandoned-committed: the ledger digest that stays committed. */
  readonly ledgerDigest?: string;
  /**
   * abandoned-committed: whether the abandoned backup's commit changed the
   * ledger heads (undefined when the publication record does not say). When
   * it did not, a published backup that carries those heads stays
   * restorable (T30D-1).
   */
  readonly headsChanged?: boolean;
}

/** Delete uncommitted staging, or (with abandonCommitted) the pending committed staging; never a final-named backup. */
export function discardStaged(dir: string, options: DiscardOptions): Discarded {
  checkAbsolute(dir, 'staged backup directory');
  const ledgerPath = checkAbsolute(options?.ledgerPath, 'ledger path');
  return withLedgerSession(ledgerPath, { recovery: true }, (session) => {
    const pending = session.pending;
    const stat = statOf(dir);
    if (pending !== undefined) {
      if (samePath(dir, pending.final)) {
        throw new RecoveryRefusedError(
          exists(pending.final)
            ? `${dir} is the pending committed backup under its final name; --discard-staged never deletes a backup under its final name; complete it with --complete-staged ${pending.final}; nothing was deleted`
            : `${dir} does not exist; the pending committed backup is under its staging name ${pending.staging}; nothing was deleted`,
        );
      }
      if (samePath(dir, pending.staging)) {
        if (stat === undefined) {
          const where = exists(pending.final)
            ? `the backup is now under its final name ${pending.final}, which --discard-staged never deletes; complete it with --complete-staged ${pending.final}`
            : `the backup is not under its final name ${pending.final} either`;
          throw new RecoveryRefusedError(`${dir} does not exist: ${where}; nothing was deleted`);
        }
        if (!stat.isDirectory()) throw new RecoveryRefusedError(`${dir} is not a directory; nothing was deleted`);
        if (options.abandonCommitted === undefined) {
          throw new RecoveryRefusedError(
            `${dir} is the pending committed staging (ledger digest ${pending.ledger_digest}); complete it with --complete-staged, or abandon it with --abandon-committed ${pending.ledger_digest}`,
          );
        }
        if (options.abandonCommitted !== session.digest) throw new RecoveryRefusedError('the --abandon-committed digest does not match the current ledger digest; nothing was changed');
        const deleted = realpathSync(dir);
        removeQuietly(deleted);
        session.clearPublishing(options.io);
        const headsChanged = pending.previous_digest === undefined ? undefined : pending.previous_digest !== pending.ledger_digest;
        return { status: 'abandoned-committed', directory: deleted, ledgerDigest: pending.ledger_digest, ...(headsChanged === undefined ? {} : { headsChanged }) };
      }
    }
    if (options.abandonCommitted !== undefined) throw new RecoveryRefusedError(`${dir} is not the pending committed staging; nothing was abandoned`);
    if (!isStagingDirectory(dir)) throw new RecoveryRefusedError(`${dir} is not a staging directory; only staging is discarded, never a backup under its final name`);
    if (stat === undefined) throw new RecoveryRefusedError(`${dir} does not exist; nothing was deleted`);
    if (!stat.isDirectory()) throw new RecoveryRefusedError(`${dir} is not a directory; nothing was deleted`);
    const deleted = realpathSync(dir);
    removeQuietly(deleted);
    return { status: 'discarded', directory: deleted };
  });
}

export interface LedgerSynced {
  readonly status: 'ledger-synced';
  readonly ledgerPath: string;
  readonly ledgerDigest: string;
}

const DIGEST = /^[0-9a-f]{64}$/;

/** --resync-ledger <ledger-digest>: re-commit the same ledger bytes by a fresh atomic replace (see the module comment). */
export function resyncLedger(digest: string, options: RecoveryOptions): LedgerSynced {
  const ledgerPath = checkAbsolute(options?.ledgerPath, 'ledger path');
  if (typeof digest !== 'string' || !DIGEST.test(digest)) throw new StorageUsageError('the ledger digest must be 64 lowercase hexadecimal characters');
  return withLedgerSession(ledgerPath, { recovery: true }, (session) => {
    if (session.digest !== digest) {
      throw new RecoveryRefusedError(
        `the ledger digest is ${session.digest}, not ${digest}: the ledger changed since (a later replace committed its own bytes, or a crash lost that write); nothing was changed; re-run the original command if its effect is missing`,
      );
    }
    const result = session.recommit(options.io);
    if (!result.durable) throw new LedgerCommitUnsyncedError(ledgerPath, result.previousDigest, result.digest, 'the re-committed ledger', { cause: result.cause });
    return { status: 'ledger-synced', ledgerPath, ledgerDigest: result.digest };
  });
}

export interface RetireTenantOptions {
  readonly databasePath: string;
  readonly ledgerPath: string;
  readonly tenantId: string;
  readonly clock: () => Date;
  /** Internal seam for failure injection in tests; never exposed by the CLI. */
  readonly io?: Partial<LedgerIo>;
}

/** Record, under the lock, that a tenant absent from the database is retired with its last head. */
export function retireTenant(options: RetireTenantOptions): RetiredTenant {
  const databasePath = checkAbsolute(options?.databasePath, 'database path');
  const ledgerPath = checkAbsolute(options.ledgerPath, 'ledger path');
  if (typeof options.tenantId !== 'string' || options.tenantId.length === 0) throw new StorageUsageError('a tenant id is required');
  if (typeof options.clock !== 'function') throw new StorageUsageError('retiring a tenant needs an injected clock');
  return withLedgerSession(ledgerPath, {}, (session: LedgerSession) => {
    const db = openDatabase({ path: databasePath });
    let present: boolean;
    try {
      db.checkSchema();
      present = db.listTenantIds().includes(options.tenantId);
    } finally {
      db.close();
    }
    if (present) throw new RecoveryRefusedError(`tenant ${options.tenantId} exists in the database; only an absent tenant can be retired`);
    const next = session.plan({ retire: [options.tenantId], source: 'retire', clock: options.clock });
    const retired = next.retired[options.tenantId];
    if (retired === undefined) throw new LedgerError('the tenant was not retired');
    const result = session.commit(next, options.io === undefined ? {} : { io: options.io });
    if (!result.durable) {
      throw new LedgerCommitUnsyncedError(ledgerPath, result.previousDigest, result.digest, `the retirement of tenant ${options.tenantId} (seq ${retired.seq})`, { cause: result.cause });
    }
    return retired;
  });
}
