// SPDX-License-Identifier: Apache-2.0
//
// The exported-head ledger (data-model.md § "Backups and the exported-head
// ledger", A-009): per tenant, the audit chain head (seq, event_digest) that
// has left the system, plus retired tenants. It is one file beside the
// backups, outside the database, so restoring an older database cannot roll
// it back, and backup and restore refuse any chain that does not contain the
// recorded head.
//
// Single locked writer path. This module is the only writer of the ledger
// file. A write (LedgerSession):
// 1. takes the exclusive lock `${ledger}.lock`, created with O_CREAT|O_EXCL
//    and recording pid, hostname, start time and a random nonce; contention
//    refuses at once (LedgerLockedError) and never waits. The owner keeps the
//    lock file descriptor open for the whole session, so a live owner is
//    visible in /proc/<pid>/fd and a crashed one loses it;
// 2. re-reads the ledger and the SHA-256 of its bytes under the lock;
// 3. checks ancestry for every tenant it updates: the chain a new head comes
//    from must contain the recorded head unchanged;
// 4. does ONE atomic replace (temp file, fsync, rename, directory fsync),
//    comparing the digest with the one read under the lock (CAS) right
//    before the rename;
// 5. releases the lock on every path, errors included: only when the lock
//    path is still the file it holds (device and inode) does it unlink it;
//    otherwise it never unlinks and reports the lock as lost (lock-lost,
//    exit 70 in scripts/backup.mjs, which observes onLedgerLockLost). It
//    then closes the descriptor. Only a crash leaves a lock behind.
// A stale lock is never broken automatically: breakLedgerLock() needs the
// lock's nonce, a lock recorded on this host, and a recorded pid that is not
// alive (the operator's --break-lock <nonce>). A damaged lock (no parsable
// record, so no nonce) is moved aside by --break-lock damaged only when it is
// older than 60 seconds and no process of the invoking user holds a
// descriptor on it (checked through /proc; refused when /proc or any of the
// user's processes cannot be inspected), re-checking its identity just
// before the move; a lock that parses is never touched by that path. Single host, local
// filesystem.
//
// Commit point (rule 3). The ledger rename is the commit point: everything
// before it returns is pre-commit (the ledger is byte-identical on any
// failure); from the moment it returns the run is post-commit, even if the
// directory fsync then fails. A writer other than a backup reports that case
// as committed-unsynced (LedgerCommitUnsyncedError, exit 74) and recovers
// with --resync-ledger <digest>, which re-commits the same bytes by a fresh
// replace; nothing is rolled back. A backup that commits records its
// publication intent first, in `${ledger}.publishing` (staging and final
// directory, and the digests of the ledger bytes before and after). While that record names
// the current ledger digest, the backup it names is the pending committed
// staging: every ledger writer except the recovery operations, and backup,
// verify and restore, report committed-pending-publication and change
// nothing. A record whose digest is not the ledger's (a crash before the
// commit point) is stale and is removed under the lock.
//
// A missing ledger fails closed. Only an explicit first backup or first
// restore (allowMissing) treats it as empty; a damaged ledger is always
// refused.
//
// Format (RFC 8785 canonical JSON, mode 0600):
//   { "schema": "opensig.exported-heads/1",
//     "tenants": { "<tenant_id>": { "seq", "digest", "exported_at", "source" } },
//     "retired": { "<tenant_id>": { "seq", "digest", "exported_at", "source", "retired_at" } } }
// ("retired" is present only when a tenant has been retired.)

import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { hostname } from 'node:os';
import { dirname, join } from 'node:path';

import { canonicalize, parseJson, type JsonValue } from '../../domain/canonical/index.ts';
import { StorageError, StorageUsageError } from '../db/errors.ts';
import { checkAbsolute, syncDirectory, writePrivateFile } from './files.ts';

export const LEDGER_SCHEMA = 'opensig.exported-heads/1';
export const LOCK_SCHEMA = 'opensig.ledger-lock/1';
export const PUBLISHING_SCHEMA = 'opensig.ledger-publishing/1';

/**
 * The filesystem steps around the commit point. Internal seam: tests replace
 * them to inject failures; scripts/backup.mjs never exposes it. The defaults
 * read the node:fs bindings at call time.
 */
export interface LedgerIo {
  /** Create a new private file exclusively, write it and fsync it. */
  readonly writeFile: (path: string, data: Uint8Array) => void;
  readonly rename: (from: string, to: string) => void;
  readonly syncDirectory: (path: string) => void;
}

export const DEFAULT_IO: LedgerIo = Object.freeze({
  writeFile: (path: string, data: Uint8Array) => writePrivateFile(path, data),
  rename: (from: string, to: string) => renameSync(from, to),
  syncDirectory: (path: string) => syncDirectory(path),
});

export function withDefaultIo(io: Partial<LedgerIo> | undefined): LedgerIo {
  return { ...DEFAULT_IO, ...io };
}

export interface ExportedHead {
  readonly seq: number;
  readonly digest: string;
  readonly exported_at: string;
  readonly source: string;
}

export interface RetiredTenant extends ExportedHead {
  readonly retired_at: string;
}

export type Ledger = Readonly<Record<string, ExportedHead>>;

export interface LedgerDocument {
  readonly tenants: Ledger;
  readonly retired: Readonly<Record<string, RetiredTenant>>;
}

export interface LockRecord {
  readonly pid: number;
  readonly hostname: string;
  readonly started_at: string;
  readonly nonce: string;
}

export class LedgerError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('ledger_invalid', message, options);
  }
}

/**
 * Post-commit: the ledger is committed (it may be ahead of every published
 * backup) and the backup it was committed for is not yet published. The
 * staged backup is preserved under exactly one name; recover with
 * --complete-staged, or --discard-staged with --abandon-committed.
 */
export class PendingPublicationError extends StorageError {
  readonly status = 'committed-pending-publication' as const;
  readonly directory: string;
  readonly ledgerDigest: string;
  readonly recovery: string;

  constructor(directory: string, ledgerDigest: string, detail?: string, options?: { cause?: unknown }) {
    const recovery = `--complete-staged ${directory}`;
    super(
      'committed_pending_publication',
      `the exported-head ledger is committed (digest ${ledgerDigest}) but the backup is not published${detail === undefined ? '' : ` (${detail})`}; the staged backup is preserved at ${directory}; recover with ${recovery}, or abandon it with --discard-staged ${directory} --abandon-committed ${ledgerDigest}`,
      options,
    );
    this.directory = directory;
    this.ledgerDigest = ledgerDigest;
    this.recovery = recovery;
  }
}

/**
 * Post-commit, for a ledger writer other than a backup (first restore,
 * --retire-tenant, recordExportedHead): the rename over the ledger returned
 * but the ledger-directory fsync failed. The new ledger is visible and may
 * not survive a crash. Nothing is rolled back; recover with --resync-ledger.
 */
export class LedgerCommitUnsyncedError extends StorageError {
  readonly status = 'committed-unsynced' as const;
  readonly ledgerPath: string;
  readonly previousDigest: string | null;
  readonly ledgerDigest: string;
  readonly recovery: string;

  constructor(ledgerPath: string, previousDigest: string | null, ledgerDigest: string, what: string, options?: { cause?: unknown }) {
    const recovery = `--resync-ledger ${ledgerDigest} --ledger ${ledgerPath}`;
    super(
      'committed_unsynced',
      `${what} was committed to the exported-head ledger ${ledgerPath} (previous digest ${previousDigest ?? 'none: the ledger did not exist'}; new digest ${ledgerDigest}), but the ledger directory fsync failed after the rename: the new ledger is visible and may not survive a crash. Nothing was rolled back; do not act on the new head until the ledger is resynced with ${recovery}`,
      options,
    );
    this.ledgerPath = ledgerPath;
    this.previousDigest = previousDigest;
    this.ledgerDigest = ledgerDigest;
    this.recovery = recovery;
  }
}

/** The ledger lock is held by another writer (or left by one that died). */
export class LedgerLockedError extends StorageError {
  readonly holder: LockRecord | undefined;

  constructor(holder: LockRecord | undefined) {
    super(
      'ledger_locked',
      holder === undefined
        ? 'the exported-head ledger is locked by another writer (the lock file is unreadable); nothing was written'
        : `the exported-head ledger is locked by pid ${holder.pid} on ${holder.hostname} since ${holder.started_at} (nonce ${holder.nonce}); nothing was written. A lock is never broken automatically; if that process is gone, use --break-lock ${holder.nonce}`,
    );
    this.holder = holder;
  }
}

const TENANT = /^[A-Za-z0-9_-]{16,64}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SOURCE = /^[a-z][a-z0-9_.-]{0,39}$/;
const NONCE = /^[0-9a-f]{32}$/;
const HEAD_KEYS = 'digest,exported_at,seq,source';
const RETIRED_KEYS = 'digest,exported_at,retired_at,seq,source';

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function checkTime(value: unknown, name: string): string {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) throw new LedgerError(`ledger ${name} is malformed`);
  return value;
}

function checkEntry(tenantId: string, value: unknown, keys: string): Record<string, unknown> {
  if (!TENANT.test(tenantId) || !isObject(value)) throw new LedgerError('ledger entry is malformed');
  if (Object.keys(value).sort().join(',') !== keys) throw new LedgerError('ledger entry has unexpected fields');
  const { seq, digest, source } = value;
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 1) throw new LedgerError('ledger seq is malformed');
  if (typeof digest !== 'string' || !DIGEST.test(digest)) throw new LedgerError('ledger digest is malformed');
  checkTime(value['exported_at'], 'exported_at');
  if (typeof source !== 'string' || !SOURCE.test(source)) throw new LedgerError('ledger source is malformed');
  return value;
}

function checkHead(tenantId: string, value: unknown): ExportedHead {
  const entry = checkEntry(tenantId, value, HEAD_KEYS);
  return { seq: entry['seq'] as number, digest: entry['digest'] as string, exported_at: entry['exported_at'] as string, source: entry['source'] as string };
}

function checkRetired(tenantId: string, value: unknown): RetiredTenant {
  const entry = checkEntry(tenantId, value, RETIRED_KEYS);
  return { ...checkHead(tenantId, { seq: entry['seq'], digest: entry['digest'], exported_at: entry['exported_at'], source: entry['source'] }), retired_at: checkTime(entry['retired_at'], 'retired_at') };
}

function parseDocument(bytes: Buffer): LedgerDocument {
  let value: JsonValue;
  try {
    value = parseJson(bytes.toString('utf8'));
  } catch (error) {
    throw new LedgerError('ledger is not valid JSON', { cause: error });
  }
  if (!isObject(value) || value['schema'] !== LEDGER_SCHEMA) throw new LedgerError('ledger schema is not recognized');
  const keys = Object.keys(value).sort().join(',');
  if (keys !== 'schema,tenants' && keys !== 'retired,schema,tenants') throw new LedgerError('ledger has unexpected members');
  const tenantsValue = value['tenants'];
  const retiredValue = value['retired'] ?? {};
  if (!isObject(tenantsValue) || !isObject(retiredValue)) throw new LedgerError('ledger tenants are malformed');
  const tenants: Record<string, ExportedHead> = {};
  for (const [tenantId, entry] of Object.entries(tenantsValue)) tenants[tenantId] = checkHead(tenantId, entry);
  const retired: Record<string, RetiredTenant> = {};
  for (const [tenantId, entry] of Object.entries(retiredValue)) {
    if (Object.hasOwn(tenants, tenantId)) throw new LedgerError('a tenant is both active and retired in the ledger');
    retired[tenantId] = checkRetired(tenantId, entry);
  }
  return { tenants, retired };
}

function serialize(document: LedgerDocument): Buffer {
  const value: Record<string, unknown> = { schema: LEDGER_SCHEMA, tenants: document.tenants };
  if (Object.keys(document.retired).length > 0) value['retired'] = document.retired;
  return Buffer.from(canonicalize(value as unknown as JsonValue), 'utf8');
}

const sha256 = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');

/** The ledger file's bytes, or null when it is missing; anything but a regular file is refused. */
function readLedgerBytes(path: string): Buffer | null {
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (stat === undefined) return null;
  if (!stat.isFile()) throw new LedgerError('ledger path is not a regular file');
  try {
    return readFileSync(path);
  } catch (error) {
    throw new LedgerError('ledger cannot be read', { cause: error });
  }
}

export interface ReadLedgerOptions {
  /**
   * Treat a missing ledger as empty. Only for the explicit first backup or
   * first restore; otherwise a missing ledger is refused.
   */
  readonly allowMissing?: boolean;
}

function missing(): LedgerError {
  return new LedgerError('the exported-head ledger is missing; only an explicit first backup or first restore may proceed without it');
}

/** Read the whole ledger document. A missing file is refused unless allowMissing is set. */
export function readLedgerDocument(path: string, options: ReadLedgerOptions = {}): LedgerDocument {
  checkAbsolute(path, 'ledger path');
  const bytes = readLedgerBytes(path);
  if (bytes === null) {
    if (options.allowMissing === true) return { tenants: {}, retired: {} };
    throw missing();
  }
  return parseDocument(bytes);
}

/** Read the active tenants' exported heads. A missing file is refused unless allowMissing is set. */
export function readLedger(path: string, options: ReadLedgerOptions = {}): Ledger {
  return readLedgerDocument(path, options).tenants;
}

// ------------------------------------------------- the publication record

export interface PublishingRecord {
  /** The staging directory and the final directory it publishes to. */
  readonly staging: string;
  readonly final: string;
  /** SHA-256 of the ledger bytes committed for this backup. */
  readonly ledger_digest: string;
  /**
   * SHA-256 of the ledger bytes before that commit (null: there was no
   * ledger). Equal to ledger_digest when the backup changed no head.
   * Undefined only in a record written before this field existed.
   */
  readonly previous_digest?: string | null;
  readonly created_at: string;
}

export function publishingPathOf(ledgerPath: string): string {
  return `${ledgerPath}.publishing`;
}

function readPublishing(ledgerPath: string): PublishingRecord | undefined {
  const path = publishingPathOf(ledgerPath);
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (stat === undefined) return undefined;
  if (!stat.isFile()) throw new LedgerError('the ledger publication record is not a regular file');
  let value: JsonValue;
  try {
    value = parseJson(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new LedgerError('the ledger publication record is damaged', { cause: error });
  }
  const keys = isObject(value) ? Object.keys(value).sort().join(',') : '';
  if (!isObject(value) || value['schema'] !== PUBLISHING_SCHEMA || (keys !== 'created_at,final,ledger_digest,previous_digest,schema,staging' && keys !== 'created_at,final,ledger_digest,schema,staging')) {
    throw new LedgerError('the ledger publication record is damaged');
  }
  const { staging, final, ledger_digest: digest, previous_digest: previous, created_at: createdAt } = value;
  if (typeof staging !== 'string' || typeof final !== 'string' || typeof digest !== 'string' || !DIGEST.test(digest) || typeof createdAt !== 'string') {
    throw new LedgerError('the ledger publication record is damaged');
  }
  if (previous !== undefined && previous !== null && (typeof previous !== 'string' || !DIGEST.test(previous))) {
    throw new LedgerError('the ledger publication record is damaged');
  }
  return { staging, final, ledger_digest: digest, ...(previous === undefined ? {} : { previous_digest: previous as string | null }), created_at: createdAt };
}

/** The current ledger digest, or null when the ledger is missing. */
export function ledgerDigest(ledgerPath: string): string | null {
  const bytes = readLedgerBytes(checkAbsolute(ledgerPath, 'ledger path'));
  return bytes === null ? null : sha256(bytes);
}

/**
 * The pending committed staging, if any: a publication record whose digest is
 * the current ledger digest. A stale record (a crash before the commit point)
 * is not pending.
 */
export function pendingPublication(ledgerPath: string): PublishingRecord | undefined {
  const record = readPublishing(checkAbsolute(ledgerPath, 'ledger path'));
  if (record === undefined) return undefined;
  return record.ledger_digest === ledgerDigest(ledgerPath) ? record : undefined;
}

/** Where the pending committed staging is now: its staging name, or its final name once renamed. */
export function pendingDirectory(record: PublishingRecord): string {
  return lstatSync(record.staging, { throwIfNoEntry: false }) === undefined && lstatSync(record.final, { throwIfNoEntry: false }) !== undefined
    ? record.final
    : record.staging;
}

/** Throw committed-pending-publication when a pending committed staging exists. */
export function refuseWhilePending(ledgerPath: string): void {
  const pending = pendingPublication(ledgerPath);
  if (pending !== undefined) {
    throw new PendingPublicationError(pendingDirectory(pending), pending.ledger_digest, 'a pending committed staging exists; nothing was changed');
  }
}

// ---------------------------------------------------------------- the lock

export function lockPathOf(ledgerPath: string): string {
  return `${ledgerPath}.lock`;
}

function parseLock(bytes: Buffer): LockRecord {
  let value: JsonValue;
  try {
    value = parseJson(bytes.toString('utf8'));
  } catch (error) {
    throw new LedgerError('the ledger lock file is damaged', { cause: error });
  }
  if (!isObject(value) || value['schema'] !== LOCK_SCHEMA || Object.keys(value).sort().join(',') !== 'hostname,nonce,pid,schema,started_at') {
    throw new LedgerError('the ledger lock file is damaged');
  }
  const { pid, hostname: host, started_at: startedAt, nonce } = value;
  if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid < 1) throw new LedgerError('the ledger lock file is damaged');
  if (typeof host !== 'string' || host.length === 0 || host.length > 255) throw new LedgerError('the ledger lock file is damaged');
  if (typeof startedAt !== 'string' || Number.isNaN(Date.parse(startedAt))) throw new LedgerError('the ledger lock file is damaged');
  if (typeof nonce !== 'string' || !NONCE.test(nonce)) throw new LedgerError('the ledger lock file is damaged');
  return { pid, hostname: host, started_at: startedAt, nonce };
}

/** The current lock holder, or undefined when unlocked. A damaged lock file is refused. */
export function readLedgerLock(ledgerPath: string): LockRecord | undefined {
  const path = lockPathOf(checkAbsolute(ledgerPath, 'ledger path'));
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (stat === undefined) return undefined;
  if (!stat.isFile()) throw new LedgerError('the ledger lock path is not a regular file');
  return parseLock(readFileSync(path));
}

function tryReadLock(ledgerPath: string): LockRecord | undefined {
  try {
    return readLedgerLock(ledgerPath);
  } catch {
    return undefined;
  }
}

/** A held lock: its record and the open descriptor the owner keeps for the whole session. */
interface LockHandle {
  readonly record: LockRecord;
  readonly fd: number;
}

function acquireLock(ledgerPath: string): LockHandle {
  const path = lockPathOf(ledgerPath);
  const record: LockRecord = { pid: process.pid, hostname: hostname(), started_at: new Date().toISOString(), nonce: randomBytes(16).toString('hex') };
  let fd: number;
  try {
    fd = openSync(path, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new LedgerLockedError(tryReadLock(ledgerPath));
    throw error;
  }
  const handle: LockHandle = { record, fd };
  try {
    const data = Buffer.from(canonicalize({ schema: LOCK_SCHEMA, ...record } as unknown as JsonValue), 'utf8');
    let offset = 0;
    while (offset < data.byteLength) offset += writeSync(fd, data, offset, data.byteLength - offset);
    fsyncSync(fd);
    syncDirectory(dirname(path));
  } catch (error) {
    try {
      releaseLock(ledgerPath, handle);
    } catch {
      // Reported through the original error; the next writer sees any lock left.
    }
    throw error;
  }
  // The descriptor stays open until releaseLock(): a live owner is visible in /proc.
  return handle;
}

/**
 * Remove the lock only while the lock path is still the file this handle
 * holds (same device and inode), then close the descriptor. Returns false
 * when the path is gone or is another file: the lock was lost, and a lock
 * that is not this handle's is never unlinked. The descriptor is closed in
 * every case.
 */
function releaseLock(ledgerPath: string, handle: LockHandle): boolean {
  const path = lockPathOf(ledgerPath);
  let removed = false;
  try {
    const held = fstatSync(handle.fd);
    const current = lstatSync(path, { throwIfNoEntry: false });
    if (current !== undefined && current.isFile() && current.dev === held.dev && current.ino === held.ino) {
      unlinkSync(path);
      removed = true;
      syncDirectory(dirname(path));
    }
  } finally {
    closeSync(handle.fd);
  }
  return removed;
}

function pidAlive(pid: number): boolean {
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** A lock found lost at release: its path was removed or replaced during the session. */
export interface LockLost {
  readonly lockPath: string;
  readonly nonce: string;
}

const lockLostListeners = new Set<(event: LockLost) => void>();

/**
 * Observe locks found lost at release (scripts/backup.mjs reports them as
 * lock-lost, exit 70). Without a listener a lost lock is reported as a
 * process warning. Returns the function that removes the listener.
 */
export function onLedgerLockLost(listener: (event: LockLost) => void): () => void {
  lockLostListeners.add(listener);
  return () => {
    lockLostListeners.delete(listener);
  };
}

/** The word --break-lock takes, instead of a nonce, for a damaged lock. */
export const DAMAGED_LOCK = 'damaged';
/** A damaged lock younger than this may belong to a writer still creating it. */
export const DAMAGED_LOCK_MIN_AGE_MS = 60_000;

/**
 * Break a stale ledger lock (the operator's --break-lock <nonce>). Refused
 * unless the nonce matches, the lock was taken on this host, and its pid is
 * no longer alive. Returns the removed lock. `--break-lock damaged` goes to
 * breakDamagedLock() instead.
 */
export function breakLedgerLock(ledgerPath: string, nonce: string): LockRecord {
  checkAbsolute(ledgerPath, 'ledger path');
  if (typeof nonce !== 'string' || !NONCE.test(nonce)) throw new StorageUsageError(`the lock nonce must be 32 hexadecimal characters (or "${DAMAGED_LOCK}" for a damaged lock)`);
  let holder: LockRecord | undefined;
  try {
    holder = readLedgerLock(ledgerPath);
  } catch (error) {
    if (error instanceof LedgerError) {
      throw new LedgerError(`${error.message}; a damaged lock has no nonce and is broken only with --break-lock ${DAMAGED_LOCK}`, { cause: error });
    }
    throw error;
  }
  if (holder === undefined) throw new LedgerError('the exported-head ledger is not locked; nothing to break');
  if (holder.nonce !== nonce) throw new LedgerError('the nonce does not match the ledger lock; the lock was not broken');
  if (holder.hostname !== hostname()) throw new LedgerError(`the ledger lock was taken on host ${holder.hostname}, not this host; the lock was not broken`);
  if (pidAlive(holder.pid)) throw new LedgerError(`the ledger lock holder (pid ${holder.pid}) is still alive; the lock was not broken`);
  unlinkSync(lockPathOf(ledgerPath));
  syncDirectory(dirname(ledgerPath));
  return holder;
}

interface DamagedLockIdentity {
  readonly dev: number;
  readonly ino: number;
  readonly mtimeMs: number;
  readonly digest: string;
}

/** Identify a damaged lock file; refuses a missing lock, a non-file and a lock that parses. */
function damagedLockIdentity(path: string): DamagedLockIdentity {
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (stat === undefined) throw new LedgerError('the exported-head ledger is not locked; nothing to break');
  if (!stat.isFile()) throw new LedgerError('the ledger lock path is not a regular file; the lock was not moved');
  const bytes = readFileSync(path);
  let parsed: LockRecord | undefined;
  try {
    parsed = parseLock(bytes);
  } catch {
    parsed = undefined;
  }
  if (parsed !== undefined) {
    throw new LedgerError(
      `the ledger lock parses (pid ${parsed.pid} on ${parsed.hostname}, nonce ${parsed.nonce}); a lock that parses is broken only with --break-lock <nonce>; the lock was not moved`,
    );
  }
  return { dev: stat.dev, ino: stat.ino, mtimeMs: stat.mtimeMs, digest: sha256(bytes) };
}

const errnoOf = (error: unknown): string | undefined => (error as NodeJS.ErrnoException)?.code;

/**
 * The processes of the invoking user that hold a descriptor on the file
 * (/proc/<pid>/fd entries resolving to its device and inode), and the
 * processes of that user (or of unknown owner) that could not be inspected.
 * Throws when /proc itself cannot be read: absence of a holder must be
 * shown, never assumed.
 */
function lockHolders(target: DamagedLockIdentity, candidates?: () => Iterable<number>): { readonly holders: readonly number[]; readonly uninspectable: readonly number[] } {
  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  let entries: string[];
  try {
    if (uid === undefined) throw new Error('no user id on this platform');
    entries = readdirSync('/proc');
    readdirSync('/proc/self/fd');
    if (candidates !== undefined) entries = [...candidates()].map(String);
  } catch (cause) {
    throw new LedgerError('/proc cannot be read, so it cannot be shown that no process holds the damaged lock; the lock was not moved', { cause });
  }
  const holders: number[] = [];
  const uninspectable: number[] = [];
  for (const name of entries) {
    if (!/^[0-9]+$/.test(name)) continue;
    const pid = Number(name);
    let owner: number;
    try {
      owner = statSync(`/proc/${name}`).uid;
    } catch (cause) {
      if (errnoOf(cause) !== 'ENOENT') uninspectable.push(pid);
      continue;
    }
    if (owner !== uid) continue;
    let fds: string[];
    try {
      fds = readdirSync(`/proc/${name}/fd`);
    } catch (cause) {
      if (errnoOf(cause) !== 'ENOENT') uninspectable.push(pid);
      continue;
    }
    for (const fd of fds) {
      let stat;
      try {
        stat = statSync(`/proc/${name}/fd/${fd}`);
      } catch (cause) {
        if (errnoOf(cause) === 'ENOENT') continue;
        uninspectable.push(pid);
        break;
      }
      if (stat.dev === target.dev && stat.ino === target.ino) {
        holders.push(pid);
        break;
      }
    }
  }
  return { holders, uninspectable };
}

export interface DamagedLockOptions {
  /** Clock for the 60-second rule, in epoch milliseconds (tests). */
  readonly now?: () => number;
  /**
   * Internal seam for tests; never exposed by the CLI: the processes to
   * inspect instead of every process listed in /proc (/proc must still be
   * readable).
   */
  readonly pids?: () => Iterable<number>;
}

/**
 * Move a damaged ledger lock aside (the operator's --break-lock damaged).
 * Only when all hold: its content still does not parse as a lock record; it
 * is older than 60 seconds; no process of the invoking user holds a
 * descriptor on it (/proc; refused, naming them, when /proc or any of the
 * user's processes cannot be inspected; the owner holds its descriptor for
 * the whole session, so this shows no live writer owns it); and, re-checked
 * just before the move, it is the same file (device, inode and digest). The file is moved to
 * `${ledger}.lock.damaged-<time>`, never deleted. Returns that path.
 */
export function breakDamagedLock(ledgerPath: string, options: DamagedLockOptions = {}): { readonly movedTo: string } {
  checkAbsolute(ledgerPath, 'ledger path');
  const path = lockPathOf(ledgerPath);
  const first = damagedLockIdentity(path);
  const now = (options.now ?? Date.now)();
  if (!Number.isFinite(now)) throw new StorageUsageError('the damaged-lock clock returned an invalid time');
  const age = now - first.mtimeMs;
  if (age < DAMAGED_LOCK_MIN_AGE_MS) {
    throw new LedgerError(`the damaged ledger lock is ${Math.max(0, Math.floor(age / 1000))} s old; it is moved aside only when older than ${DAMAGED_LOCK_MIN_AGE_MS / 1000} s; the lock was not moved`);
  }
  const { holders, uninspectable } = lockHolders(first, options.pids);
  if (holders.length > 0) throw new LedgerError(`the damaged ledger lock is held by pid ${holders.join(', ')}, a live writer; the lock was not moved`);
  if (uninspectable.length > 0) {
    throw new LedgerError(`process(es) ${uninspectable.join(', ')} of this user cannot be inspected, so it cannot be shown that none holds the damaged lock; the lock was not moved`);
  }
  const again = damagedLockIdentity(path);
  if (again.dev !== first.dev || again.ino !== first.ino || again.digest !== first.digest) {
    throw new LedgerError('the ledger lock changed while it was being checked; the lock was not moved');
  }
  const movedTo = `${path}.damaged-${new Date(now).toISOString().replace(/[:.]/g, '-')}`;
  // link + unlink: never replaces an existing file at the target.
  linkSync(path, movedTo);
  unlinkSync(path);
  syncDirectory(dirname(path));
  return { movedTo };
}

// ------------------------------------------------------- the locked writer

/** A new head for one tenant, with the chain it comes from. */
export interface HeadUpdate {
  readonly head: { readonly seq: number; readonly digest: string };
  /** The event_digest at a seq of that chain (undefined when it has no such event). */
  readonly digestAt: (seq: number) => string | undefined;
}

export interface SessionOptions extends ReadLedgerOptions {
  /**
   * The recovery operations (--complete-staged, --discard-staged) open the
   * session on a pending committed staging; every other writer refuses it.
   */
  readonly recovery?: boolean;
}

/** The outcome of a commit: the committed digest, and whether the directory fsync completed. */
export interface CommitResult {
  readonly digest: string;
  /** The digest of the ledger bytes the commit replaced (null: there was no ledger). */
  readonly previousDigest: string | null;
  /** False when the ledger rename returned but the directory fsync failed (post-commit). */
  readonly durable: boolean;
  readonly cause?: unknown;
}

/**
 * The ledger lock and the ledger state read under it. Every ledger write goes
 * through one session: open(), then at most one commit(), then release().
 */
export class LedgerSession {
  readonly path: string;
  /** False when the ledger was missing (allowed by allowMissing) at open. */
  readonly existed: boolean;
  readonly document: LedgerDocument;
  /** The pending committed staging (recovery sessions only). */
  readonly pending: PublishingRecord | undefined;
  /** A stale publication record removed when the session opened (a crash before its commit point). */
  readonly stale: PublishingRecord | undefined;
  readonly #digest: string | null;
  readonly #lock: LockHandle;
  #committed = false;
  #released = false;
  #releaseStatus: 'released' | 'lost' | 'failed' = 'released';

  private constructor(
    path: string,
    lock: LockHandle,
    bytes: Buffer | null,
    document: LedgerDocument,
    pending: PublishingRecord | undefined,
    stale: PublishingRecord | undefined,
  ) {
    this.path = path;
    this.#lock = lock;
    this.existed = bytes !== null;
    this.#digest = bytes === null ? null : sha256(bytes);
    this.document = document;
    this.pending = pending;
    this.stale = stale;
  }

  /**
   * Take the lock (refusing at once on contention), re-read the ledger and its
   * digest under it, and refuse a pending committed staging (except for
   * recovery). A stale publication record is removed.
   */
  static open(ledgerPath: string, options: SessionOptions = {}): LedgerSession {
    const path = checkAbsolute(ledgerPath, 'ledger path');
    const lock = acquireLock(path);
    try {
      const bytes = readLedgerBytes(path);
      if (bytes === null && options.allowMissing !== true) throw missing();
      const document = bytes === null ? { tenants: {}, retired: {} } : parseDocument(bytes);
      const record = readPublishing(path);
      let pending: PublishingRecord | undefined;
      let stale: PublishingRecord | undefined;
      if (record !== undefined) {
        if (bytes !== null && record.ledger_digest === sha256(bytes)) {
          if (options.recovery !== true) refuseWhilePending(path);
          pending = record;
        } else {
          stale = record;
          unlinkSync(publishingPathOf(path));
          syncDirectory(dirname(path));
        }
      }
      return new LedgerSession(path, lock, bytes, document, pending, stale);
    } catch (error) {
      try {
        releaseLock(path, lock);
      } catch {
        // Reported through the original error.
      }
      throw error;
    }
  }

  /** SHA-256 of the ledger bytes read under the lock (null when missing). */
  get digest(): string | null {
    return this.#digest;
  }

  get lock(): LockRecord {
    return this.#lock.record;
  }

  /**
   * The document after applying `heads` (ancestry checked for every tenant)
   * and `retire`. Pure: writes nothing.
   */
  plan(changes: { readonly heads?: ReadonlyMap<string, HeadUpdate>; readonly retire?: readonly string[]; readonly source: string; readonly clock: () => Date }): LedgerDocument {
    if (!SOURCE.test(changes.source)) throw new StorageUsageError('ledger source is malformed');
    const now = changes.clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new StorageUsageError('the ledger clock returned an invalid date');
    const tenants: Record<string, ExportedHead> = { ...this.document.tenants };
    const retired: Record<string, RetiredTenant> = { ...this.document.retired };
    for (const [tenantId, update] of changes.heads ?? new Map<string, HeadUpdate>()) {
      if (!TENANT.test(tenantId)) throw new StorageUsageError('tenant id is malformed');
      if (typeof update?.digestAt !== 'function') throw new StorageUsageError('recording an exported head needs digestAt for the ancestry check');
      if (Object.hasOwn(retired, tenantId)) throw new LedgerError(`tenant ${tenantId} was retired; a retired tenant cannot export a head again`);
      const candidate = checkHead(tenantId, { seq: update.head?.seq, digest: update.head?.digest, exported_at: now.toISOString(), source: changes.source });
      if (update.digestAt(candidate.seq) !== candidate.digest) throw new LedgerError(`tenant ${tenantId}: the head to record is not part of the given chain`);
      const existing = tenants[tenantId];
      if (existing !== undefined) {
        if (update.digestAt(existing.seq) !== existing.digest) {
          throw new LedgerError(`tenant ${tenantId}: the chain does not contain the last exported head (seq ${existing.seq}): it was rolled back or diverged`);
        }
        if (existing.seq >= candidate.seq) continue;
      }
      tenants[tenantId] = candidate;
    }
    for (const tenantId of changes.retire ?? []) {
      const last = tenants[tenantId];
      if (last === undefined) {
        throw new LedgerError(Object.hasOwn(retired, tenantId) ? `tenant ${tenantId} is already retired` : `tenant ${tenantId} has no exported head to retire`);
      }
      delete tenants[tenantId];
      retired[tenantId] = { ...last, retired_at: now.toISOString() };
    }
    return { tenants, retired };
  }

  /**
   * Write `next` with ONE atomic replace: (with `publishing`) the publication
   * record, then the private temp file and its fsync, a digest
   * compare-and-swap against the bytes read under the lock right before the
   * rename over the ledger (the commit point), and the directory fsync. Any
   * failure before the rename returns throws and leaves the ledger
   * byte-identical. After it returns, a failed directory fsync is reported as
   * durable: false, never thrown. At most once per session.
   */
  commit(next: LedgerDocument, options: { readonly publishing?: { readonly staging: string; readonly final: string }; readonly io?: Partial<LedgerIo> } = {}): CommitResult {
    this.#begin();
    if (this.pending !== undefined) throw new StorageUsageError('a pending committed staging must be completed or abandoned first');
    const bytes = serialize(next);
    // Validate what is about to be written exactly as a reader will.
    parseDocument(bytes);
    return this.#replace(bytes, options);
  }

  /**
   * Re-commit the ledger's current bytes by a fresh atomic replace (temp
   * file, fsync, rename, directory fsync), never a bare re-fsync: after an
   * earlier fsync error a retried fsync can succeed without the entry being
   * durable. Used by --resync-ledger and --complete-staged; allowed while a
   * pending committed staging exists (the bytes do not change). At most once
   * per session, instead of commit().
   */
  recommit(io?: Partial<LedgerIo>): CommitResult {
    this.#begin();
    const bytes = readLedgerBytes(this.path);
    if (bytes === null || this.#digest === null) throw missing();
    if (sha256(bytes) !== this.#digest) throw new LedgerError('the exported-head ledger changed while it was locked (digest mismatch); nothing was written');
    parseDocument(bytes);
    return this.#replace(bytes, io === undefined ? {} : { io });
  }

  #begin(): void {
    if (this.#released) throw new StorageUsageError('the ledger session was released');
    if (this.#committed) throw new StorageUsageError('a ledger session commits at most once');
    this.#committed = true;
  }

  #replace(bytes: Buffer, options: { readonly publishing?: { readonly staging: string; readonly final: string }; readonly io?: Partial<LedgerIo> }): CommitResult {
    const io = withDefaultIo(options.io);
    const digest = sha256(bytes);
    const previousDigest = this.#digest;
    const directory = dirname(this.path);
    const record = publishingPathOf(this.path);
    let recorded = false;
    const temp = join(directory, `.${randomBytes(12).toString('hex')}.tmp`);
    try {
      if (options.publishing !== undefined) {
        const value = {
          schema: PUBLISHING_SCHEMA,
          staging: options.publishing.staging,
          final: options.publishing.final,
          ledger_digest: digest,
          previous_digest: previousDigest,
          created_at: new Date().toISOString(),
        };
        io.writeFile(record, Buffer.from(canonicalize(value as unknown as JsonValue), 'utf8'));
        recorded = true;
        io.syncDirectory(directory);
      }
      io.writeFile(temp, bytes);
      // CAS immediately before the replace (rule 1).
      const current = readLedgerBytes(this.path);
      if ((current === null ? null : sha256(current)) !== previousDigest) {
        throw new LedgerError('the exported-head ledger changed while it was locked (digest mismatch); nothing was written');
      }
      io.rename(temp, this.path);
    } catch (error) {
      rmSync(temp, { force: true });
      if (recorded) rmSync(record, { force: true });
      throw error;
    }
    // Post-commit from here: the ledger may already show the new bytes.
    try {
      io.syncDirectory(directory);
    } catch (cause) {
      return { digest, previousDigest, durable: false, cause };
    }
    return { digest, previousDigest, durable: true };
  }

  /** Remove the publication record (after publication, or on abandon). */
  clearPublishing(io?: Partial<LedgerIo>): void {
    if (this.#released) throw new StorageUsageError('the ledger session was released');
    const record = publishingPathOf(this.path);
    if (lstatSync(record, { throwIfNoEntry: false }) === undefined) return;
    unlinkSync(record);
    withDefaultIo(io).syncDirectory(dirname(this.path));
  }

  /**
   * Release the lock and close its descriptor. 'released': the lock path was
   * still this session's file and was removed. 'lost': the path was gone or
   * another file, so it was not unlinked; this is reported to the
   * onLedgerLockLost listeners, or without one as a process warning
   * (OPENSIG_LEDGER_LOCK_LOST). 'failed': removing it failed after
   * the identity check (the descriptor is still closed; a lock file left
   * behind is reported to the next writer with its nonce).
   */
  release(): 'released' | 'lost' | 'failed' {
    if (this.#released) return this.#releaseStatus;
    this.#released = true;
    try {
      this.#releaseStatus = releaseLock(this.path, this.#lock) ? 'released' : 'lost';
    } catch {
      this.#releaseStatus = 'failed';
    }
    if (this.#releaseStatus === 'lost') {
      const event: LockLost = { lockPath: lockPathOf(this.path), nonce: this.#lock.record.nonce };
      if (lockLostListeners.size > 0) {
        for (const listener of lockLostListeners) listener(event);
      } else {
        process.emitWarning(`the exported-head ledger lock ${event.lockPath} was lost during the session (nonce ${event.nonce}): the lock path was removed or replaced; it was not unlinked`, {
          code: 'OPENSIG_LEDGER_LOCK_LOST',
        });
      }
    }
    return this.#releaseStatus;
  }
}

/** Run `fn` with an open session, always releasing the lock. */
export function withLedgerSession<T>(ledgerPath: string, options: SessionOptions, fn: (session: LedgerSession) => T): T {
  const session = LedgerSession.open(ledgerPath, options);
  try {
    return fn(session);
  } finally {
    session.release();
  }
}

export interface RecordOptions {
  readonly clock: () => Date;
  readonly source: string;
  /**
   * The event_digest at a seq of the chain that `head` comes from (undefined
   * when the chain has no such event). Used to require ancestry: the chain
   * must contain both `head` and the head already recorded.
   */
  readonly digestAt: (seq: number) => string | undefined;
  /** Create the ledger if it is missing (explicit first runs only). */
  readonly createIfMissing?: boolean;
  /** Internal seam for failure injection in tests; never exposed by the CLI. */
  readonly io?: Partial<LedgerIo>;
}

/**
 * Record that `head` left the system for `tenantId`, through the locked
 * writer path. Requires ancestry; keeps the more advanced head; refuses at
 * once when the ledger is locked. When the rename over the ledger returned
 * but the directory fsync failed, throws LedgerCommitUnsyncedError
 * (committed-unsynced): the head is recorded but must not be acted on until
 * --resync-ledger succeeds.
 */
export function recordExportedHead(path: string, tenantId: string, head: { readonly seq: number; readonly digest: string }, options: RecordOptions): ExportedHead {
  if (!TENANT.test(tenantId)) throw new StorageUsageError('tenant id is malformed');
  if (!SOURCE.test(options?.source)) throw new StorageUsageError('ledger source is malformed');
  if (typeof options.digestAt !== 'function') throw new StorageUsageError('recording an exported head needs digestAt for the ancestry check');
  return withLedgerSession(path, { allowMissing: options.createIfMissing === true }, (session) => {
    const next = session.plan({ heads: new Map([[tenantId, { head, digestAt: options.digestAt }]]), source: options.source, clock: options.clock });
    const entry = next.tenants[tenantId];
    if (entry === undefined) throw new LedgerError('the head was not recorded');
    if (session.existed && serialize(next).equals(serialize(session.document))) return entry;
    const result = session.commit(next, options.io === undefined ? {} : { io: options.io });
    if (!result.durable) {
      throw new LedgerCommitUnsyncedError(session.path, result.previousDigest, result.digest, `the exported head of tenant ${tenantId} (seq ${entry.seq})`, { cause: result.cause });
    }
    return entry;
  });
}
