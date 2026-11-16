// SPDX-License-Identifier: Apache-2.0
//
// Operator recovery for backups and the exported-head ledger (data-model.md
// § "Backups and the exported-head ledger", rules 3 and 5), each under the
// ledger lock:
// - completeStaged (--complete-staged <dir>): re-verify a staged backup in
//   full, require its heads to equal the committed ledger heads for every
//   tenant, then fsync the ledger directory, rename the directory if it is
//   still staged, and fsync the parent; published only after the parent
//   fsync. A mismatch or failed verification refuses and touches nothing; a
//   repeated I/O failure is committed-pending-publication again.
// - discardStaged (--discard-staged <dir>): delete uncommitted staging only.
//   The pending committed staging is deleted only with abandonCommitted
//   (--abandon-committed <ledger-digest>) equal to the current ledger
//   digest; the ledger stays as committed.
// - retireTenant (--retire-tenant <tenant_id>): record that a tenant absent
//   from the database is retired, with its last head.

import { lstatSync, readdirSync } from 'node:fs';
import { dirname } from 'node:path';

import { openDatabase } from '../db/connection.ts';
import { StorageError, StorageUsageError } from '../db/errors.ts';
import { finalDirectoryOf, isStagingDirectory } from './backup.ts';
import { checkAbsolute, removeQuietly } from './files.ts';
import { LedgerError, LedgerSession, pendingDirectory, PendingPublicationError, withDefaultIo, withLedgerSession, type LedgerIo, type RetiredTenant } from './ledger.ts';
import { inspectBackupDirectory, RestoreRefusedError } from './restore.ts';

/** A recovery operation refused; nothing was changed. */
export class RecoveryRefusedError extends StorageError {
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

const exists = (path: string): boolean => lstatSync(path, { throwIfNoEntry: false }) !== undefined;

/** Where a staged backup lives now and where it publishes to. */
function locate(dir: string, pending: { readonly staging: string; readonly final: string } | undefined): { readonly current: string; readonly final: string; readonly staged: boolean } {
  if (isStagingDirectory(dir)) {
    const final = pending !== undefined && pending.staging === dir ? pending.final : finalDirectoryOf(dir);
    if (exists(dir)) return { current: dir, final, staged: true };
    if (pending !== undefined && pending.staging === dir && exists(final)) return { current: final, final, staged: false };
    throw new RecoveryRefusedError(`${dir} does not exist`);
  }
  if (!exists(dir)) throw new RecoveryRefusedError(`${dir} does not exist`);
  return { current: dir, final: dir, staged: false };
}

/** Re-verify a staged backup and publish it (see the module comment). */
export function completeStaged(dir: string, options: RecoveryOptions): CompletedStaged {
  checkAbsolute(dir, 'staged backup directory');
  const ledgerPath = checkAbsolute(options?.ledgerPath, 'ledger path');
  const io = withDefaultIo(options.io);
  return withLedgerSession(ledgerPath, { recovery: true }, (session) => {
    const pending = session.pending;
    const where = locate(dir, pending);
    let manifest;
    try {
      ({ manifest } = inspectBackupDirectory(where.current, session.document.tenants));
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
      io.syncDirectory(dirname(ledgerPath));
      if (where.staged) {
        io.rename(where.current, where.final);
        current = where.final;
      }
      io.syncDirectory(dirname(where.final));
      if (pending !== undefined && (pending.staging === dir || pending.final === where.final)) session.clearPublishing(options.io);
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
  readonly directory: string;
}

/** Delete uncommitted staging, or (with abandonCommitted) the pending committed staging. */
export function discardStaged(dir: string, options: DiscardOptions): Discarded {
  checkAbsolute(dir, 'staged backup directory');
  const ledgerPath = checkAbsolute(options?.ledgerPath, 'ledger path');
  return withLedgerSession(ledgerPath, { recovery: true }, (session) => {
    const pending = session.pending;
    if (pending !== undefined && (dir === pending.staging || dir === pending.final)) {
      if (options.abandonCommitted === undefined) {
        throw new RecoveryRefusedError(
          `${dir} is the pending committed staging (ledger digest ${pending.ledger_digest}); complete it with --complete-staged, or abandon it with --abandon-committed ${pending.ledger_digest}`,
        );
      }
      if (options.abandonCommitted !== session.digest) throw new RecoveryRefusedError('the --abandon-committed digest does not match the current ledger digest; nothing was changed');
      // The staged backup lives under exactly one of its two names.
      removeQuietly(pendingDirectory(pending));
      session.clearPublishing(options.io);
      return { status: 'abandoned-committed', directory: dir };
    }
    if (options.abandonCommitted !== undefined) throw new RecoveryRefusedError(`${dir} is not the pending committed staging; nothing was abandoned`);
    if (!isStagingDirectory(dir)) throw new RecoveryRefusedError(`${dir} is not a staging directory; only staging is discarded`);
    const stat = lstatSync(dir, { throwIfNoEntry: false });
    if (stat === undefined) throw new RecoveryRefusedError(`${dir} does not exist`);
    if (!stat.isDirectory()) throw new RecoveryRefusedError(`${dir} is not a directory`);
    removeQuietly(dir);
    return { status: 'discarded', directory: dir };
  });
}

export interface RetireTenantOptions {
  readonly databasePath: string;
  readonly ledgerPath: string;
  readonly tenantId: string;
  readonly clock: () => Date;
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
    const result = session.commit(next);
    if (!result.durable) {
      throw new StorageError('ledger_commit_unsynced', `the retirement was committed to the ledger (digest ${result.digest}) but the ledger directory fsync failed`, { cause: result.cause });
    }
    const retired = next.retired[options.tenantId];
    if (retired === undefined) throw new LedgerError('the tenant was not retired');
    return retired;
  });
}
