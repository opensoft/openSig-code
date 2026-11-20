// SPDX-License-Identifier: Apache-2.0
//
// The exported-head ledger and backup publication (T030, data-model.md
// § "Backups and the exported-head ledger (A-009)"):
// OR-15 a refusal or failure before the commit point leaves the ledger
//       byte-identical (status refused), and every tenant's head is recorded
//       in one replace;
// OR-16 a crash after the commit point keeps the staged backup, holds the
//       lock, and reports committed-pending-publication until recovered;
// OR-17 the recovery flags --complete-staged, --discard-staged and
//       --abandon-committed;
// OR-18 the ledger lock, its nonce, --break-lock and the digest CAS;
// OR-19 two writers in two OS processes: the second is refused, nothing is
//       lost or regressed;
// OR-20 --first-backup creates the ledger, empty when no tenant has events;
// OR-21 the required-blob set uses T029's reference-protection predicate;
// OR-22 the ledger is re-read under the lock, with an accurate message when
//       it advanced during the backup;
// OR-23 --retire-tenant;
// OR-24 --first-restore writes the restored heads under the lock, all or
//       nothing;
// OR-26 an injected post-commit I/O failure (ledger-directory fsync, staging
//       rename, parent fsync) through the internal io seam keeps the staged
//       backup and reports exit 75;
// OR-27 the blob size limit is carried through backup, verify and restore;
// OR-28 a non-backup ledger writer whose directory fsync fails after the
//       rename reports committed-unsynced (exit 74); --resync-ledger;
// OR-29 a surviving intent record keeps a no-head-change staging pending,
//       and the abandon message is truthful;
// OR-30 a first restore removes only the database files it created, and
//       nothing after the commit point;
// OR-31 --discard-staged never deletes a backup under its final name;
// OR-32 staging is recognised by its staged manifest (copies and links);
// OR-33 the digest CAS sits immediately before the rename;
// OR-34 --discard-staged identifies the staging by its real path and reports
//       the path it deleted;
// OR-35 the lock descriptor is held for the whole session and released on
//       every path; --break-lock damaged (the cases that must move the lock
//       depend on no process this test does not own; T30R4-1);
// OR-38 a lock lost at release reports lock-lost, exit 70, over the
//       outcome's own exit, still naming that outcome and its recovery;
// OR-39 a refusal found during a run (a database appearing at the restore
//       target) is refused, exit 1; exit 2 means usage errors only;
// OR-41 a real non-dumpable live writer holding a torn, aged lock:
//       --break-lock damaged refuses, names it as uninspectable and leaves the
//       lock untouched; Linux only, otherwise skipped (VACUOUS, never a pass);
// OR-42 verify and restore read retired tenants' retained heads: a backup
//       containing a retired tenant is refused (exit 1) after the head check.
// All data is synthetic. The backup module is imported as a namespace so that
// every test reports its own failure against an older API.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs, {
  chmodSync,
  closeSync,
  constants as fsConstants,
  copyFileSync,
  cpSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { hostname } from 'node:os';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { after, mock, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalize } from '../../src/domain/canonical/index.ts';
import { verifyChain } from '../../src/storage/audit/index.ts';
import * as backupApi from '../../src/storage/backup/index.ts';
import * as blobsApi from '../../src/storage/blobs/index.ts';
import { openDatabase } from '../../src/storage/db/index.ts';
import * as retentionApi from '../../src/storage/retention/index.ts';
import { makeScratch } from '../storage/support/fixtures.mjs';
import {
  BASE_TIME,
  createTenant,
  envelopeRow,
  environment,
  fixedClock,
  hex,
  rawConnection,
  sid,
  steppingClock,
  syntheticBytes,
  terminalEnvelope,
  ts,
} from '../audit-chain/support/chain.mjs';

const { BackupError, createBackup, LedgerError, readLedger, recordExportedHead, requiredBlobRefs, restoreBackup, RestoreRefusedError, verifyBackup } = backupApi;
// A-009 additions.
const { breakLedgerLock, completeStaged, discardStaged, LedgerSession, pendingPublication, PendingPublicationError, readLedgerLock } = backupApi;
// A-010 additions.
const { breakDamagedLock, LedgerCommitUnsyncedError, readLedgerDocument, resyncLedger, withLedgerSession } = backupApi;
const { BlobDisposer, RetentionService } = retentionApi;

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..', '..');
const SCRIPT = join(REPO_ROOT, 'scripts', 'backup.mjs');
const CHILD = join(HERE, 'support', 'ledger-child.mjs');
const CLI_FAULT = join(HERE, 'support', 'cli-fault.mjs');
const LEDGER_FILE = 'exported-heads.json';
const LOCK_SCHEMA = 'opensig.ledger-lock/1';
const scratch = makeScratch();
after(() => scratch.cleanup());

const clock = steppingClock(BASE_TIME + 3_600_000);

// ------------------------------------------------------------------ helpers

/** A live system: tenants (sorted) with audit events, a blob store, a ledger directory and a backups directory. */
function system({ tenants = 2, events = 3, blobs = false } = {}) {
  const env = environment(scratch, steppingClock());
  const ids = Array.from({ length: tenants }, () => sid('tenant')).sort();
  for (const tenant of ids) createTenant(env.db, tenant);
  if (blobs) for (const tenant of ids) terminalEnvelope(env.db, env.blobs, tenant, { state: 'completed' });
  for (const tenant of ids) appendEvents(env, tenant, events);
  const ledgerDir = join(env.dir, 'ledger');
  const backups = join(env.dir, 'backups');
  mkdirSync(ledgerDir, { mode: 0o700 });
  mkdirSync(backups, { mode: 0o700 });
  return { ...env, tenants: ids, blobRoot: join(env.dir, 'blobs'), ledgerDir, ledgerPath: join(ledgerDir, LEDGER_FILE), backups };
}

function appendEvents(env, tenant, count) {
  if (count === 0) return;
  env.db.transaction(() => {
    for (let i = 0; i < count; i += 1) env.audit.append(tenant, { type: 'envelope.updated', actor: { kind: 'system', ref: 'test' }, envelopeId: null, metadata: { step: i } });
  });
}

const headOf = (sys, tenant) => verifyChain(sys.db, tenant).head;
const digestAtOf = (sys, tenant) => {
  const store = sys.db.forTenant(tenant);
  return (seq) => store.get('audit_events', { seq })?.event_digest;
};

function backup(sys, name, options = {}) {
  return createBackup({ databasePath: sys.path, blobRoot: sys.blobRoot, outDir: join(sys.backups, name), ledgerPath: sys.ledgerPath, clock, ...options });
}

function settle(promise) {
  return promise.then(
    (value) => ({ ok: true, value }),
    (error) => ({ ok: false, error }),
  );
}

const sha = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const seqs = (sys) => sys.tenants.map((tenant) => readLedger(sys.ledgerPath)[tenant]?.seq ?? null);
const stagingDirs = (sys) => readdirSync(sys.backups).filter((name) => name.startsWith('.staging-'));
const ledgerFiles = (sys) => readdirSync(sys.ledgerDir).sort();
const target = () => {
  const dir = scratch.dir();
  return { databasePath: join(dir, 'restored.db'), blobRoot: join(dir, 'blobs') };
};

/** Everything a run must leave alone. */
function state(sys) {
  return { ledger: sha(sys.ledgerPath), backups: readdirSync(sys.backups).sort(), ledgerDir: ledgerFiles(sys) };
}

/** A refusal before the commit point: ledger byte-identical, staging removed, nothing published, nothing left in the ledger directory. */
function assertPreCommit(sys, before, name, previous) {
  assert.equal(sha(sys.ledgerPath), before, 'the ledger is byte-identical');
  assert.deepEqual(stagingDirs(sys), [], "this run's uncommitted staging was removed");
  assert.equal(existsSync(join(sys.backups, name)), false, 'nothing was published');
  assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE], 'no temp file, publication record or lock is left');
  if (previous !== undefined) {
    const report = verifyBackup({ backupDir: join(sys.backups, previous), ledgerPath: sys.ledgerPath });
    const ledger = readLedger(sys.ledgerPath);
    assert.deepEqual(
      report.tenants.map((tenant) => tenant.head.seq),
      report.tenants.map((tenant) => ledger[tenant.tenant_id]?.seq),
      'the previous published backup still carries the exported heads (restorable)',
    );
  }
}

function ioError(code, path) {
  return Object.assign(new Error(`${code}: synthetic I/O failure, ${path}`), { code, syscall: 'synthetic', path: String(path) });
}

/** The real filesystem steps, for io seams that override only one step. */
function writeExclusive(path, data) {
  const fd = openSync(path, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
  try {
    let offset = 0;
    while (offset < data.byteLength) offset += writeSync(fd, data, offset, data.byteLength - offset);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function fsyncDirectory(path) {
  const fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Wrap a node:fs function for every importer (the same fault on any version of the code). */
function hookFs(method, wrap) {
  const real = fs[method];
  mock.method(fs, method, function (...args) {
    return wrap(real, ...args);
  });
  syncBuiltinESMExports();
}

function unhookFs() {
  mock.restoreAll();
  syncBuiltinESMExports();
}

function cli(...args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000 });
}

const lastJson = (text) => JSON.parse(text.trim().split('\n').pop() ?? 'null');

/** Run the ledger child to completion. */
function runChild(mode, op, config) {
  const run = spawnSync(process.execPath, [CHILD, mode, op, JSON.stringify(config)], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000 });
  let result;
  try {
    result = lastJson(run.stdout);
  } catch {
    result = undefined;
  }
  return { status: run.status, signal: run.signal, pid: run.pid, stderr: run.stderr, result };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Start a child held at the ledger rename, run `between` while it waits, then release it. */
async function interleave(op, config, between) {
  const barrier = scratch.dir('opensig-barrier-');
  const child = spawn(process.execPath, [CHILD, 'blocked', op, JSON.stringify({ ...config, barrier })], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  child.stdout.on('data', (chunk) => (out += chunk));
  child.stderr.on('data', (chunk) => (err += chunk));
  const exited = new Promise((resolveExit) => child.on('exit', (code, signal) => resolveExit({ code, signal })));
  try {
    for (let i = 0; i < 6000 && !existsSync(join(barrier, 'ready')); i += 1) await sleep(5);
    assert.ok(existsSync(join(barrier, 'ready')), `the blocked writer reached the ledger rename (${err.trim().split('\n').pop() ?? ''})`);
    const middle = await between();
    writeFileSync(join(barrier, 'go'), '');
    const exit = await exited;
    assert.equal(exit.code, 0, `the blocked writer exited cleanly (${err.trim().split('\n').pop() ?? ''})`);
    return { blocked: lastJson(out), middle };
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
}

function lockRecord({ pid, host = hostname(), nonce }) {
  return canonicalize({ schema: LOCK_SCHEMA, pid, hostname: host, started_at: new Date(BASE_TIME).toISOString(), nonce });
}

/** A pid that is not alive: a process that has already exited. */
function deadPid() {
  const run = spawnSync(process.execPath, ['-e', '0']);
  return run.pid;
}

/** scripts/backup.mjs with the ledger-directory fsync failing after the ledger rename (fault injected at node:fs in that process). */
function cliFault(ledgerPath, ...args) {
  return cliFaults('ledger-dir-fsync', ledgerPath, ...args);
}

/** scripts/backup.mjs with the named faults of support/cli-fault.mjs injected in that process. */
function cliFaults(faults, ledgerPath, ...args) {
  return spawnSync(process.execPath, [CLI_FAULT, faults, ledgerPath, ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000 });
}

/** io seam: the ledger-directory fsync fails once a rename onto the ledger has returned. */
function failDirFsync(ledgerPath) {
  let renamed = false;
  return {
    rename(from, to) {
      renameSync(from, to);
      if (to === ledgerPath) renamed = true;
    },
    syncDirectory(path) {
      if (renamed && path === dirname(ledgerPath)) throw ioError('EIO', path);
      fsyncDirectory(path);
    },
  };
}

/**
 * Whether --break-lock damaged would count `pid` as an inspectable process of
 * this user, by its own definition (lockHolders in ledger.ts): /proc/<pid> is
 * this user's, its fd directory lists, and every entry in it stats (an entry
 * that vanished meanwhile is skipped). Applied only to processes this test
 * owns: the test never inspects any other process.
 */
function inspectableByTheCli(pid) {
  let fds;
  try {
    if (statSync(`/proc/${pid}`).uid !== process.getuid()) return false;
    fds = readdirSync(`/proc/${pid}/fd`);
  } catch {
    return false;
  }
  for (const fd of fds) {
    try {
      statSync(`/proc/${pid}/fd/${fd}`);
    } catch (error) {
      if (error.code !== 'ENOENT') return false;
    }
  }
  return true;
}

/**
 * A live process this test owns, idle until stopped (only its own recorded
 * pid is ever signalled). The cases that must move a damaged lock hand the
 * library only such processes and this one.
 */
async function ownedIdleProcess() {
  const child = spawn(process.execPath, ['-e', "process.stdout.write('ready\\n'); setInterval(() => {}, 60_000);"], { stdio: ['ignore', 'pipe', 'ignore'] });
  const closed = new Promise((resolveClose) => child.on('close', (code, signal) => resolveClose({ code, signal })));
  await new Promise((resolveReady, rejectReady) => {
    child.stdout.on('data', (chunk) => {
      if (String(chunk).includes('ready')) resolveReady();
    });
    child.on('error', rejectReady);
    child.on('exit', () => rejectReady(new Error('the idle process exited before it was ready')));
  });
  return {
    pid: child.pid,
    async stop() {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await closed;
    },
  };
}

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const isPending = (error) => error?.code === 'committed_pending_publication';
const claimsUnchanged = (message) => /byte-identical|unchanged|nothing was (written|recorded|changed)/.test(message);

// ------------------------------------------------------------------- OR-15

test('[OR-15] a refusal or failure before the commit point leaves the ledger byte-identical (status refused), and two tenants are recorded in one replace', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    appendEvents(sys, sys.tenants[0], 2);
    appendEvents(sys, sys.tenants[1], 2);
    let before = sha(sys.ledgerPath);

    // The second ledger temp file cannot be created (ENOSPC), injected at
    // node:fs. A backup that writes the ledger once per tenant fails there
    // after the first tenant's head is already recorded.
    let tempOpens = 0;
    hookFs('openSync', (real, path, ...rest) => {
      if (dirname(String(path)) === sys.ledgerDir && String(path).endsWith('.tmp')) {
        tempOpens += 1;
        if (tempOpens === 2) throw ioError('ENOSPC', path);
      }
      return real.call(fs, path, ...rest);
    });
    let second;
    try {
      second = await settle(backup(sys, 'bk2'));
    } finally {
      unhookFs();
    }
    if (!second.ok) {
      assert.equal(sha(sys.ledgerPath), before, `a backup refused before its commit point leaves the ledger byte-identical (${second.error.code}: ${second.error.message})`);
    }
    assert.equal(tempOpens, 1, "every tenant's head is recorded in ONE replace");
    assert.equal(second.ok, true);
    assert.deepEqual(seqs(sys), [5, 5]);
    assert.deepEqual(stagingDirs(sys), []);
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE]);

    // The ledger temp write fails (io seam).
    appendEvents(sys, sys.tenants[0], 1);
    appendEvents(sys, sys.tenants[1], 1);
    before = sha(sys.ledgerPath);
    const failTemp = {
      writeFile(path, data) {
        if (path.endsWith('.tmp')) throw ioError('ENOSPC', path);
        writeExclusive(path, data);
      },
    };
    await assert.rejects(backup(sys, 'bk3', { io: failTemp }), (error) => error.code === 'ENOSPC' && !isPending(error));
    assertPreCommit(sys, before, 'bk3', 'bk2');

    // The rename over the ledger fails (io seam).
    const failRename = {
      rename(from, to) {
        if (to === sys.ledgerPath) throw ioError('EIO', to);
        renameSync(from, to);
      },
    };
    await assert.rejects(backup(sys, 'bk3', { io: failRename }), (error) => error.code === 'EIO' && !isPending(error));
    assertPreCommit(sys, before, 'bk3', 'bk2');

    // Lock contention: refused at once, through the API and the CLI (refused, exit 1).
    const holder = LedgerSession.open(sys.ledgerPath);
    try {
      await assert.rejects(backup(sys, 'bk3'), (error) => error.code === 'ledger_locked' && error.message.includes(holder.lock.nonce));
      assert.deepEqual(stagingDirs(sys), []);
      const refused = cli('create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', join(sys.backups, 'bk3'), '--ledger', sys.ledgerPath);
      assert.equal(refused.status, 1, refused.stderr);
      assert.match(refused.stdout, new RegExp(`^backup: refused ledger_locked: .*nonce ${holder.lock.nonce}`));
    } finally {
      holder.release();
    }
    assertPreCommit(sys, before, 'bk3', 'bk2');

    // A restore of the previous published backup still works.
    const restored = target();
    assert.deepEqual(
      restoreBackup({ backupDir: join(sys.backups, 'bk2'), ledgerPath: sys.ledgerPath, ...restored }).tenants.map((tenant) => tenant.head.seq),
      [5, 5],
    );
    assert.equal(sha(sys.ledgerPath), before, 'a restore never writes an existing ledger');

    // Verification refuses (tenant B forked below its exported head).
    const raw = rawConnection(sys.path);
    try {
      raw.exec('DROP TRIGGER IF EXISTS audit_events_append_only_delete');
      raw.prepare('DELETE FROM audit_events WHERE tenant_id = ? AND seq > 2').run(sys.tenants[1]);
    } finally {
      raw.close();
    }
    appendEvents(sys, sys.tenants[1], 6);
    await assert.rejects(backup(sys, 'bk3'), (error) => error instanceof BackupError && /diverges from the last exported head at seq 5/.test(error.message));
    assertPreCommit(sys, before, 'bk3', 'bk2');
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-16

test('[OR-16] a crash after the ledger rename keeps the staged backup and the lock; backup, verify and restore report exit 75 until --break-lock and --complete-staged', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    appendEvents(sys, sys.tenants[0], 2);
    appendEvents(sys, sys.tenants[1], 4);
    const before = sha(sys.ledgerPath);
    const final = join(sys.backups, 'bk2');

    const crash = runChild('crash-committed', 'backup', { databasePath: sys.path, blobRoot: sys.blobRoot, outDir: final, ledgerPath: sys.ledgerPath });
    assert.equal(crash.signal, 'SIGKILL', `the child was killed after the ledger rename (${crash.stderr.trim().split('\n').pop() ?? ''})`);
    assert.equal(existsSync(final), false, 'nothing was published under the final name');
    const staged = stagingDirs(sys);
    assert.equal(staged.length, 1, 'the staged backup is preserved under exactly one name');
    const staging = join(sys.backups, staged[0]);
    assert.deepEqual(readdirSync(staging).sort(), ['blobs', 'manifest.staged.json', 'opensig.db'], 'staging holds only the staged manifest');
    assert.notEqual(sha(sys.ledgerPath), before, 'the ledger is committed (post-commit)');
    assert.deepEqual(seqs(sys), [5, 7], 'every tenant is ahead, in the one replace');
    const manifest = JSON.parse(readFileSync(join(staging, 'manifest.staged.json'), 'utf8'));
    assert.deepEqual(manifest.tenants.map((tenant) => tenant.audit_head.seq), [5, 7]);
    const lock = readLedgerLock(sys.ledgerPath);
    assert.equal(lock.pid, crash.pid, 'the lock stays held by the dead writer');
    const digest = sha(sys.ledgerPath);
    assert.deepEqual(pendingPublication(sys.ledgerPath).staging, staging);

    // Every later run reports committed-pending-publication and changes nothing.
    const frozen = state(sys);
    await assert.rejects(backup(sys, 'bk3'), (error) => isPending(error) && error.directory === staging && error.ledgerDigest === digest);
    assert.throws(() => verifyBackup({ backupDir: join(sys.backups, 'bk1'), ledgerPath: sys.ledgerPath }), isPending);
    const refusedTarget = target();
    assert.throws(() => restoreBackup({ backupDir: join(sys.backups, 'bk1'), ledgerPath: sys.ledgerPath, ...refusedTarget }), isPending);
    assert.equal(existsSync(refusedTarget.databasePath), false);
    assert.equal(existsSync(refusedTarget.blobRoot), false);
    const pendingLine = new RegExp(`^backup: committed-pending-publication directory=${staging.replaceAll('.', '\\.')} ledger-digest=${digest} recover="--complete-staged `);
    for (const args of [
      ['create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', join(sys.backups, 'bk3'), '--ledger', sys.ledgerPath],
      ['verify', '--from', join(sys.backups, 'bk1'), '--ledger', sys.ledgerPath],
      ['restore', '--from', join(sys.backups, 'bk1'), '--ledger', sys.ledgerPath, '--db', refusedTarget.databasePath, '--blobs', refusedTarget.blobRoot],
    ]) {
      const run = cli(...args);
      assert.equal(run.status, 75, `${args[0]}: ${run.stdout}${run.stderr}`);
      assert.match(run.stdout, pendingLine);
    }
    assert.deepEqual(state(sys), frozen, 'nothing changed while the publication is pending');

    // Recovery needs the lock: --break-lock with its nonce, then --complete-staged.
    const locked = cli('--complete-staged', staging, '--ledger', sys.ledgerPath);
    assert.equal(locked.status, 1);
    assert.match(locked.stdout, new RegExp(`^backup: refused ledger_locked: .*--break-lock ${lock.nonce}`));
    const broken = cli('--break-lock', lock.nonce, '--ledger', sys.ledgerPath);
    assert.equal(broken.status, 0, broken.stdout + broken.stderr);
    assert.equal(broken.stdout, `backup: lock-broken pid=${crash.pid} host=${hostname()}\n`);
    const completed = cli('--complete-staged', staging, '--ledger', sys.ledgerPath);
    assert.equal(completed.status, 0, completed.stdout + completed.stderr);
    assert.equal(completed.stdout, `backup: published directory=${final}\n`);
    assert.equal(existsSync(staging), false);
    assert.deepEqual(readdirSync(final).sort(), ['blobs', 'manifest.json', 'opensig.db']);
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE], 'publication record and lock are gone');
    assert.equal(sha(sys.ledgerPath), digest, 'recovery never rolls the ledger back');

    assert.deepEqual(verifyBackup({ backupDir: final, ledgerPath: sys.ledgerPath }).tenants.map((tenant) => tenant.head.seq), [5, 7]);
    assert.throws(() => verifyBackup({ backupDir: join(sys.backups, 'bk1'), ledgerPath: sys.ledgerPath }), (error) => error instanceof RestoreRefusedError && /older than the last exported head/.test(error.message));
    const restored = target();
    assert.equal(restoreBackup({ backupDir: final, ledgerPath: sys.ledgerPath, ...restored }).tenants.length, 2);
    appendEvents(sys, sys.tenants[0], 1);
    await backup(sys, 'bk3');
    assert.deepEqual(seqs(sys), [6, 7]);
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-17

test('[OR-17] --discard-staged deletes only uncommitted staging; the pending committed staging needs --abandon-committed or --complete-staged', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const bk1 = join(sys.backups, 'bk1');
    const stagingName = (finalName) => join(sys.backups, `.staging-${'a'.repeat(12)}${createHash('sha256').update(finalName).digest('hex').slice(0, 12)}-${finalName}`);

    // An uncommitted staging (a published backup already carries its heads) is discarded.
    const copy = stagingName('bk1-copy');
    cpSync(bk1, copy, { recursive: true });
    const copyReal = realpathSync(copy);
    const discarded = cli('--discard-staged', copy, '--ledger', sys.ledgerPath);
    assert.equal(discarded.status, 0, discarded.stdout + discarded.stderr);
    assert.equal(discarded.stdout, `backup: discarded directory=${copyReal}\n`);
    assert.equal(existsSync(copy), false);
    // Verify and restore refuse a staging directory, whatever it holds.
    cpSync(bk1, copy, { recursive: true });
    assert.throws(() => verifyBackup({ backupDir: copy, ledgerPath: sys.ledgerPath }), (error) => error instanceof RestoreRefusedError && /a staging directory is not a published backup/.test(error.message));
    const stagedTarget = target();
    assert.throws(() => restoreBackup({ backupDir: copy, ledgerPath: sys.ledgerPath, ...stagedTarget }), (error) => error instanceof RestoreRefusedError && /a staging directory is not a published backup/.test(error.message));
    assert.equal(existsSync(stagedTarget.databasePath), false);
    assert.equal(discardStaged(copy, { ledgerPath: sys.ledgerPath }).status, 'discarded');
    const notStaging = cli('--discard-staged', bk1, '--ledger', sys.ledgerPath);
    assert.equal(notStaging.status, 1);
    assert.match(notStaging.stdout, /^backup: refused recovery_refused: .* is not a staging directory/);
    assert.ok(existsSync(join(bk1, 'manifest.json')), 'a published backup is never discarded');

    // A crash before the commit point: the staging is uncommitted, the ledger
    // byte-identical, the lock held; the previous backup stays restorable.
    appendEvents(sys, sys.tenants[0], 2);
    appendEvents(sys, sys.tenants[1], 2);
    const before = sha(sys.ledgerPath);
    const crash = runChild('crash-temp', 'backup', { databasePath: sys.path, blobRoot: sys.blobRoot, outDir: join(sys.backups, 'bk-crash'), ledgerPath: sys.ledgerPath });
    assert.equal(crash.signal, 'SIGKILL');
    assert.equal(sha(sys.ledgerPath), before, 'a crash before the ledger rename leaves the ledger byte-identical');
    assert.equal(existsSync(join(sys.backups, 'bk-crash')), false);
    const [crashed] = stagingDirs(sys);
    assert.ok(crashed !== undefined, 'the uncommitted staging is left by the crash');
    assert.equal(pendingPublication(sys.ledgerPath), undefined, 'a publication record for bytes never committed is stale, not pending');
    assert.equal(verifyBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath }).tenants.length, 2);
    const lock = readLedgerLock(sys.ledgerPath);
    assert.equal(lock.pid, crash.pid);
    await assert.rejects(backup(sys, 'bk2'), (error) => error.code === 'ledger_locked');
    assert.deepEqual(stagingDirs(sys), [crashed]);
    assert.equal(breakLedgerLock(sys.ledgerPath, lock.nonce).pid, crash.pid);
    assert.deepEqual(discardStaged(join(sys.backups, crashed), { ledgerPath: sys.ledgerPath }), { status: 'discarded', directory: realpathSync(sys.backups) + sep + crashed });
    assert.deepEqual(stagingDirs(sys), []);
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE], 'the stale publication record was removed under the lock');

    // The pending committed staging: the staging rename fails after the commit.
    const final = join(sys.backups, 'bk2');
    const failPublish = {
      rename(from, to) {
        if (to === final) throw ioError('EIO', to);
        renameSync(from, to);
      },
    };
    const failed = await settle(backup(sys, 'bk2', { io: failPublish }));
    assert.equal(isPending(failed.error), true);
    const pending = failed.error.directory;
    const digest = sha(sys.ledgerPath);
    assert.equal(failed.error.ledgerDigest, digest);
    assert.deepEqual(seqs(sys), [5, 5]);
    const frozen = state(sys);

    const noAbandon = cli('--discard-staged', pending, '--ledger', sys.ledgerPath);
    assert.equal(noAbandon.status, 1);
    assert.match(noAbandon.stdout, new RegExp(`^backup: refused recovery_refused: .*pending committed staging .*--abandon-committed ${digest}`));
    const wrongDigest = cli('--discard-staged', pending, '--ledger', sys.ledgerPath, '--abandon-committed', hex('not-the-ledger'));
    assert.equal(wrongDigest.status, 1);
    assert.match(wrongDigest.stdout, /does not match the current ledger digest; nothing was changed/);
    assert.deepEqual(state(sys), frozen, 'a refused discard changes nothing');

    // --complete-staged refuses a staging whose heads differ from the
    // committed heads (one ahead of them that verifies, made against another
    // ledger), and ones that do not verify (older, or altered); each is left
    // untouched.
    appendEvents(sys, sys.tenants[0], 1);
    const aheadDir = join(scratch.dir(), 'ahead');
    await createBackup({ databasePath: sys.path, blobRoot: sys.blobRoot, outDir: aheadDir, ledgerPath: join(scratch.dir(), 'other-ledger.json'), clock, firstBackup: true });
    const ahead = stagingName('bk-ahead');
    cpSync(aheadDir, ahead, { recursive: true });
    const mismatch = cli('--complete-staged', ahead, '--ledger', sys.ledgerPath);
    assert.equal(mismatch.status, 1);
    assert.match(mismatch.stdout, new RegExp(`^backup: refused recovery_refused: tenant ${sys.tenants[0]}: the staged head differs from the committed ledger head \\(seq 5\\); nothing was changed`));
    assert.ok(existsSync(join(ahead, 'manifest.json')));
    assert.equal(existsSync(join(sys.backups, 'bk-ahead')), false);
    const older = stagingName('bk-older');
    cpSync(bk1, older, { recursive: true });
    const stale = cli('--complete-staged', older, '--ledger', sys.ledgerPath);
    assert.equal(stale.status, 1);
    assert.match(stale.stdout, /^backup: refused recovery_refused: the staged backup does not verify: .*older than the last exported head \(seq 5\)/);
    assert.ok(existsSync(join(older, 'manifest.json')));
    assert.equal(existsSync(join(sys.backups, 'bk-older')), false);
    const tampered = stagingName('bk-tampered');
    cpSync(pending, tampered, { recursive: true });
    writeFileSync(join(tampered, 'opensig.db'), Buffer.concat([readFileSync(join(tampered, 'opensig.db')), Buffer.from([0])]));
    const unverified = cli('--complete-staged', tampered, '--ledger', sys.ledgerPath);
    assert.equal(unverified.status, 1);
    assert.match(unverified.stdout, /^backup: refused recovery_refused: the staged backup does not verify: database file does not match the manifest digest/);
    assert.equal(existsSync(join(sys.backups, 'bk-tampered')), false);
    assert.equal(sha(sys.ledgerPath), digest);
    assert.equal(pendingPublication(sys.ledgerPath).staging, pending, 'the pending staging is still pending');
    for (const extra of [ahead, older, tampered]) assert.equal(discardStaged(extra, { ledgerPath: sys.ledgerPath }).status, 'discarded');
    assert.deepEqual(state(sys), frozen);

    // Abandon with the matching digest: the staging is deleted, the ledger stays ahead.
    const pendingReal = realpathSync(pending);
    const abandoned = cli('--discard-staged', pending, '--ledger', sys.ledgerPath, '--abandon-committed', digest);
    assert.equal(abandoned.status, 0, abandoned.stdout + abandoned.stderr);
    assert.equal(
      abandoned.stdout,
      `backup: abandoned-committed directory=${pendingReal} ledger-digest=${digest}: the staged backup was deleted; the ledger stays as committed, ahead of every published backup; every restore refuses until a backup carrying the committed heads is published\n`,
    );
    assert.equal(existsSync(pending), false);
    assert.equal(sha(sys.ledgerPath), digest, 'the ledger stays as committed');
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE]);
    // Every restore refuses until the next backup publishes, and it descends from the committed heads.
    assert.throws(() => restoreBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath, ...target() }), (error) => error instanceof RestoreRefusedError && /older than the last exported head \(seq 5\)/.test(error.message));
    await backup(sys, 'bk2');
    assert.deepEqual(verifyBackup({ backupDir: final, ledgerPath: sys.ledgerPath }).tenants.map((tenant) => tenant.head.seq), [6, 5]);

    // --complete-staged by the final name (the rename succeeded, the parent fsync failed).
    appendEvents(sys, sys.tenants[1], 1);
    const final3 = join(sys.backups, 'bk3');
    let renamed = false;
    const failParent = {
      rename(from, to) {
        renameSync(from, to);
        if (to === final3) renamed = true;
      },
      syncDirectory(path) {
        if (renamed && path === sys.backups) throw ioError('EIO', path);
        fsyncDirectory(path);
      },
    };
    const kept = await settle(backup(sys, 'bk3', { io: failParent }));
    assert.equal(isPending(kept.error), true);
    assert.equal(kept.error.directory, final3, 'kept under the final name');
    assert.deepEqual(stagingDirs(sys), []);
    assert.deepEqual(completeStaged(final3, { ledgerPath: sys.ledgerPath }), { status: 'published', directory: final3 });
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE]);
    assert.deepEqual(verifyBackup({ backupDir: final3, ledgerPath: sys.ledgerPath }).tenants.map((tenant) => tenant.head.seq), [6, 6]);

  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-18

test('[OR-18] the ledger lock: contention and a stale lock refuse at once, --break-lock needs the nonce, this host and a dead pid, and the digest CAS refuses an out-of-band write', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const [tenantA, tenantB] = sys.tenants;
    appendEvents(sys, tenantA, 2);
    const lockPath = `${sys.ledgerPath}.lock`;
    const record = () => recordExportedHead(sys.ledgerPath, tenantA, headOf(sys, tenantA), { clock, source: 'receipt', digestAt: digestAtOf(sys, tenantA) });

    // A lock left by a writer that died is never broken automatically.
    const nonce = createHash('sha256').update('stale-lock-nonce').digest('hex').slice(0, 32);
    const dead = deadPid();
    writeFileSync(lockPath, lockRecord({ pid: dead, nonce }), { mode: 0o600, flag: 'wx' });
    const before = sha(sys.ledgerPath);
    const started = Date.now();
    assert.throws(record, (error) => error.code === 'ledger_locked' && error.message.includes(`pid ${dead}`) && error.message.includes(`--break-lock ${nonce}`));
    assert.ok(Date.now() - started < 2_000, 'contention refuses at once, without waiting');
    await assert.rejects(backup(sys, 'bk2'), (error) => error.code === 'ledger_locked');
    assert.equal(sha(sys.ledgerPath), before, 'nothing was written');
    assert.deepEqual(stagingDirs(sys), []);

    // --break-lock: the nonce must match, the host must be this host, the pid dead.
    assert.throws(() => breakLedgerLock(sys.ledgerPath, 'f'.repeat(32)), (error) => error instanceof LedgerError && /nonce does not match/.test(error.message));
    const badNonce = cli('--break-lock', 'not-a-nonce', '--ledger', sys.ledgerPath);
    assert.equal(badNonce.status, 2);
    const wrong = cli('--break-lock', 'e'.repeat(32), '--ledger', sys.ledgerPath);
    assert.equal(wrong.status, 1);
    assert.match(wrong.stdout, /^backup: refused ledger_invalid: the nonce does not match the ledger lock/);
    assert.ok(existsSync(lockPath));
    rmSync(lockPath);
    writeFileSync(lockPath, lockRecord({ pid: dead, nonce, host: 'other-host.example.test' }), { mode: 0o600, flag: 'wx' });
    assert.throws(() => breakLedgerLock(sys.ledgerPath, nonce), /taken on host other-host\.example\.test, not this host/);
    rmSync(lockPath);
    writeFileSync(lockPath, lockRecord({ pid: process.pid, nonce }), { mode: 0o600, flag: 'wx' });
    assert.throws(() => breakLedgerLock(sys.ledgerPath, nonce), new RegExp(`holder \\(pid ${process.pid}\\) is still alive`));
    rmSync(lockPath);
    writeFileSync(lockPath, lockRecord({ pid: dead, nonce }), { mode: 0o600, flag: 'wx' });
    const broken = cli('--break-lock', nonce, '--ledger', sys.ledgerPath);
    assert.equal(broken.status, 0, broken.stdout + broken.stderr);
    assert.equal(broken.stdout, `backup: lock-broken pid=${dead} host=${hostname()}\n`);
    assert.equal(existsSync(lockPath), false);
    const notLocked = cli('--break-lock', nonce, '--ledger', sys.ledgerPath);
    assert.equal(notLocked.status, 1);
    assert.match(notLocked.stdout, /not locked; nothing to break/);
    assert.equal(record().seq, 5, 'the next writer takes the lock');

    // A damaged lock file is refused, never treated as free.
    writeFileSync(lockPath, 'damaged', { mode: 0o600, flag: 'wx' });
    assert.throws(record, (error) => error.code === 'ledger_locked' && /lock file is unreadable/.test(error.message));
    assert.throws(() => breakLedgerLock(sys.ledgerPath, nonce), (error) => error instanceof LedgerError && /lock file is damaged/.test(error.message));
    rmSync(lockPath);

    // The lock a session holds: O_EXCL file, mode 0600, pid, host, start time and nonce.
    const session = LedgerSession.open(sys.ledgerPath);
    try {
      assert.equal(statSync(lockPath).mode & 0o777, 0o600);
      const text = readFileSync(lockPath, 'utf8');
      const value = JSON.parse(text);
      assert.equal(text, canonicalize(value));
      assert.deepEqual(Object.keys(value).sort(), ['hostname', 'nonce', 'pid', 'schema', 'started_at']);
      assert.deepEqual([value.schema, value.pid, value.hostname], [LOCK_SCHEMA, process.pid, hostname()]);
      assert.match(value.nonce, /^[0-9a-f]{32}$/);
      assert.equal(value.nonce, session.lock.nonce);
      assert.deepEqual(readLedgerLock(sys.ledgerPath), { pid: value.pid, hostname: value.hostname, started_at: value.started_at, nonce: value.nonce });
      assert.throws(() => LedgerSession.open(sys.ledgerPath), (error) => error.code === 'ledger_locked' && error.message.includes(value.nonce));
      assert.throws(() => breakLedgerLock(sys.ledgerPath, value.nonce), /still alive/);

      // CAS: an out-of-band write (one that ignores the lock) between the read
      // under the lock and the replace is refused; the session writes nothing.
      appendEvents(sys, tenantB, 1);
      const next = session.plan({ heads: new Map([[tenantB, { head: headOf(sys, tenantB), digestAt: digestAtOf(sys, tenantB) }]]), source: 'receipt', clock });
      const outOfBand = JSON.parse(readFileSync(sys.ledgerPath, 'utf8'));
      outOfBand.tenants[tenantA] = { ...outOfBand.tenants[tenantA], exported_at: new Date(BASE_TIME + 7_200_000).toISOString() };
      writeFileSync(sys.ledgerPath, canonicalize(outOfBand));
      const outOfBandDigest = sha(sys.ledgerPath);
      assert.throws(() => session.commit(next), (error) => error instanceof LedgerError && /changed while it was locked \(digest mismatch\); nothing was written/.test(error.message));
      assert.equal(sha(sys.ledgerPath), outOfBandDigest);
      assert.equal(readLedger(sys.ledgerPath)[tenantB].seq, 3);
    } finally {
      session.release();
    }
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE], 'released, with no temp file left');
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-19

test('[OR-19] two ledger writers in two OS processes: the second is refused while the first holds the lock, and no head is lost or regressed', async () => {
  // Different tenants, direct writers.
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const [tenantA, tenantB] = sys.tenants;
    appendEvents(sys, tenantA, 3);
    appendEvents(sys, tenantB, 3);
    const digests = (tenant) => {
      const at = digestAtOf(sys, tenant);
      return Object.fromEntries([3, 6].map((seq) => [String(seq), at(seq)]));
    };
    const configA = { ledgerPath: sys.ledgerPath, tenant: tenantA, head: headOf(sys, tenantA), digests: digests(tenantA) };
    const configB = { ledgerPath: sys.ledgerPath, tenant: tenantB, head: headOf(sys, tenantB), digests: digests(tenantB) };
    const { blocked, middle } = await interleave('record', configA, async () => runChild('free', 'record', configB));
    assert.deepEqual(middle.result, { ok: false, code: 'ledger_locked', message: middle.result?.message }, `the second writer is refused while the first holds the lock (got ${JSON.stringify(middle.result)})`);
    assert.match(middle.result.message, /nonce [0-9a-f]{32}/);
    assert.deepEqual(blocked, { ok: true, value: 6 });
    assert.deepEqual(seqs(sys), [6, 3], 'nothing was lost: the refused write never happened');
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE]);
    assert.deepEqual(runChild('free', 'record', configB).result, { ok: true, value: 6 }, 'a retry succeeds');
    assert.deepEqual(seqs(sys), [6, 6]);
  } finally {
    sys.db.close();
  }

  // The same tenant, two whole backups: the later snapshot cannot be overwritten by the earlier one.
  const one = system({ tenants: 1, events: 5 });
  try {
    await backup(one, 'bk1', { firstBackup: true });
    appendEvents(one, one.tenants[0], 5);
    const configA = { databasePath: one.path, blobRoot: one.blobRoot, outDir: join(one.backups, 'bkA'), ledgerPath: one.ledgerPath };
    const configB = { ...configA, outDir: join(one.backups, 'bkB'), clockStart: '2026-11-16T13:00:00.000Z' };
    const { blocked, middle } = await interleave('backup', configA, async () => {
      appendEvents(one, one.tenants[0], 2);
      return runChild('free', 'backup', configB);
    });
    assert.equal(middle.result?.code, 'ledger_locked', `the second backup is refused (got ${JSON.stringify(middle.result)})`);
    assert.equal(existsSync(configB.outDir), false);
    assert.deepEqual(blocked, { ok: true, heads: { [one.tenants[0]]: 10 } });
    assert.deepEqual(seqs(one), [10]);
    assert.deepEqual(stagingDirs(one), []);
    assert.deepEqual(runChild('free', 'backup', configB).result, { ok: true, heads: { [one.tenants[0]]: 12 } });
    assert.deepEqual(seqs(one), [12], 'the exported head never regresses');
    assert.throws(() => verifyBackup({ backupDir: configA.outDir, ledgerPath: one.ledgerPath }), /older than the last exported head \(seq 12\)/);
    assert.equal(verifyBackup({ backupDir: configB.outDir, ledgerPath: one.ledgerPath }).tenants[0].head.seq, 12);
  } finally {
    one.db.close();
  }

  // An unsynchronized race of two processes, retrying on contention: no read-back loss.
  const dir = scratch.dir();
  const ledgerPath = join(dir, LEDGER_FILE);
  const n = 20;
  const chain = Object.fromEntries(Array.from({ length: n }, (_, i) => [String(i + 1), hex(`race-${i + 1}`)]));
  const tenants = [sid('tenant'), sid('tenant')].sort();
  const outputs = await Promise.all(
    tenants.map(
      (tenant) =>
        new Promise((resolveRun) => {
          const child = spawn(process.execPath, [CHILD, 'free', 'loop', JSON.stringify({ ledgerPath, tenant, n, chain })], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
          let out = '';
          let err = '';
          child.stdout.on('data', (chunk) => (out += chunk));
          child.stderr.on('data', (chunk) => (err += chunk));
          child.on('exit', (code) => resolveRun({ code, out, err }));
        }),
    ),
  );
  for (const output of outputs) {
    assert.equal(output.code, 0, output.err.trim().split('\n').pop());
    assert.equal(lastJson(output.out).lost, 0);
  }
  assert.deepEqual(
    tenants.map((tenant) => readLedger(ledgerPath)[tenant].seq),
    [n, n],
  );
  assert.deepEqual(readdirSync(dir), [LEDGER_FILE]);
});

// ------------------------------------------------------------------- OR-20

test('[OR-20] --first-backup creates the ledger, empty when no tenant has audit events; the next backup needs no flag; a damaged ledger is refused even with the flag', async () => {
  const sys = system({ tenants: 1, events: 0 });
  try {
    const first = await backup(sys, 'bk1', { firstBackup: true });
    assert.equal(first.tenants[0].audit_head, null);
    assert.equal(existsSync(sys.ledgerPath), true, 'the first backup creates the ledger even when no tenant has audit events');
    assert.equal(readFileSync(sys.ledgerPath, 'utf8'), '{"schema":"opensig.exported-heads/1","tenants":{}}');
    assert.equal(statSync(sys.ledgerPath).mode & 0o777, 0o600);
    await backup(sys, 'bk2');
    assert.deepEqual(readLedger(sys.ledgerPath), {});
    appendEvents(sys, sys.tenants[0], 2);
    const created = cli('create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', join(sys.backups, 'bk3'), '--ledger', sys.ledgerPath);
    assert.equal(created.status, 0, created.stdout + created.stderr);
    assert.deepEqual(seqs(sys), [2]);

    writeFileSync(sys.ledgerPath, 'damaged');
    await assert.rejects(backup(sys, 'bk4', { firstBackup: true }), (error) => error instanceof LedgerError && /not valid JSON/.test(error.message));
    const refused = cli('create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', join(sys.backups, 'bk4'), '--ledger', sys.ledgerPath, '--first-backup');
    assert.equal(refused.status, 1);
    assert.match(refused.stdout, /^backup: refused ledger_invalid: ledger is not valid JSON/);
    assert.equal(readFileSync(sys.ledgerPath, 'utf8'), 'damaged', 'a damaged ledger is never replaced');
    assert.deepEqual(stagingDirs(sys), []);
    assert.equal(existsSync(join(sys.backups, 'bk4')), false);
  } finally {
    sys.db.close();
  }

  // No tenant at all.
  const empty = system({ tenants: 0 });
  try {
    const manifest = await backup(empty, 'bk1', { firstBackup: true });
    assert.deepEqual(manifest.tenants, []);
    assert.deepEqual(readLedger(empty.ledgerPath), {});
    await backup(empty, 'bk2');
  } finally {
    empty.db.close();
  }
});

// ------------------------------------------------------------------- OR-21

test("[OR-21] the required-blob set is T029's reference-protection predicate: an orphan-collected blob referenced again by a final artifact is required, and backup keeps no rule of its own", async () => {
  // The divergence: envelope E's abandoned attempt blob R is orphan-collected,
  // then E's final artifact is published with the same bytes (pdf_blob_ref R).
  const env = environment(scratch, steppingClock());
  try {
    const { db, blobs, audit } = env;
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const store = db.forTenant(tenant);
    const envelope = sid('env');
    const revision = sid('rev');
    const doc = blobs.put(tenant, syntheticBytes('or21-document', 2048));
    db.transaction(() => {
      store.insert('envelopes', envelopeRow(envelope));
      store.insert('document_revisions', { id: revision, envelope_id: envelope, content_digest: doc.digest, blob_ref: doc.ref, bytes: 2048, pages: 1, page_geometry_json: '[]', parse_report_json: '{}', created_at: ts(2), frozen_at: ts(3) });
    });
    const reused = blobs.put(tenant, syntheticBytes('or21-final-pdf', 4096));
    const disposer = new BlobDisposer({ db, blobs, audit, clock: steppingClock() });
    const collected = disposer.dispose(tenant, { envelopeId: envelope, kind: 'orphan-collection', policyRef: 'orphan-collection', refs: [reused.ref], retainedArtifactDigests: [] });
    assert.deepEqual(collected.disposedBlobRefs, [reused.ref]);
    const evidence = blobs.put(tenant, syntheticBytes('or21-evidence', 512));
    db.transaction(() => {
      // The legal walk to completed (A-010 ST11-FX): draft 1, prepared 2, sent 3, finalizing 4, completed 5.
      const walk = [
        { state: 'prepared', base_revision_id: revision, manifest_digest: hex(`m-${envelope}`), recipients_digest: hex(`r-${envelope}`) },
        { state: 'sent' },
        { state: 'finalizing', approvals_complete: 1 },
        { state: 'completed' },
      ];
      walk.forEach((step, index) => assert.equal(store.compareAndSet('envelopes', { id: envelope }, index + 1, { ...step, updated_at: ts(10) }), true, `${step.state} step`));
      // reserved_version is the version written on entering finalizing (data-model.md § Entities, SigningJob).
      store.insert('signing_jobs', { envelope_id: envelope, reserved_version: 4, status: 'succeeded', attempt_count: 2, max_attempts: 3, fencing_token: 2, created_at: ts(4), updated_at: ts(5) });
      store.insert('final_artifacts', { artifact_id: sid('art'), envelope_id: envelope, artifact_digest: reused.digest, approved_composition_digest: hex(`c-${envelope}`), approval_evidence_digest: hex('or21-approval-evidence'), pdf_blob_ref: reused.ref, evidence_blob_ref: evidence.ref, signer_certificate_sha256: hex('certificate'), development_certificate: 1, verifier_name: 'opensig-verifier', verifier_version: '0.0.0', verification_json: '{"integrity":"valid"}', fencing_token: 2, completed_at: ts(5) });
    });
    const required = requiredBlobRefs(db, tenant);
    assert.equal(required.has(reused.ref), true, 'a final artifact protects R, as the disposer decides');
    assert.equal(required.has(evidence.ref), true);
    assert.equal(blobs.check(tenant, reused.digest), 'missing');
    const outDir = join(env.dir, 'bk');
    const ledgerPath = join(env.dir, LEDGER_FILE);
    await assert.rejects(
      createBackup({ databasePath: env.path, blobRoot: join(env.dir, 'blobs'), outDir, ledgerPath, clock, firstBackup: true }),
      (error) => error instanceof BackupError && error.message.includes(`a blob required by the database is missing (${reused.ref})`),
    );
    assert.equal(existsSync(outDir), false);
    assert.equal(existsSync(ledgerPath), false);
    assertParity(db, tenant);
  } finally {
    env.db.close();
  }

  // Parity across retention disposals (scope documents, a shared document, a retained artifact).
  const DAY = 86_400_000;
  const retained = environment(scratch, steppingClock());
  try {
    const { db, blobs, audit } = retained;
    const tenant = sid('tenant');
    createTenant(db, tenant);
    db.transaction(() => db.forTenant(tenant).update('tenants', {}, { retention_json: JSON.stringify({ policy_ref: 'synthetic-retention', dispose_after_days: 30 }) }));
    terminalEnvelope(db, blobs, tenant, { state: 'declined', updatedMinutes: 10, documentSeed: 'or21-shared' });
    terminalEnvelope(db, blobs, tenant, { state: 'declined', updatedMinutes: 40 * 24 * 60, documentSeed: 'or21-shared' });
    terminalEnvelope(db, blobs, tenant, { state: 'completed', updatedMinutes: 10 });
    terminalEnvelope(db, blobs, tenant, { state: 'completed', updatedMinutes: 60 * 24 * 60 });
    assertParity(db, tenant);
    new RetentionService({ db, blobs, audit, clock: fixedClock(new Date(BASE_TIME + 31 * DAY).toISOString()) }).run(tenant);
    assertParity(db, tenant);
    new RetentionService({ db, blobs, audit, clock: fixedClock(new Date(BASE_TIME + 80 * DAY).toISOString()) }).run(tenant);
    assertParity(db, tenant);
  } finally {
    retained.db.close();
  }

  // One rule: backup imports the predicate and keeps no disposal logic of its own.
  const source = readFileSync(join(REPO_ROOT, 'src', 'storage', 'backup', 'backup.ts'), 'utf8');
  assert.match(source, /import \{[^}]*\bBLOB_REFERENCE_COLUMNS\b[^}]*\bReferenceProtection\b[^}]*\} from '\.\.\/retention\/index\.ts'/);
  for (const forbidden of ['disposal_records', 'retention.disposed', 'disposed_blob_refs', 'kept_blob_refs']) {
    assert.equal(source.includes(forbidden), false, `backup.ts has no ${forbidden} logic`);
  }
  for (const file of ['restore.ts', 'recovery.ts']) {
    const text = readFileSync(join(REPO_ROOT, 'src', 'storage', 'backup', file), 'utf8');
    assert.equal(text.includes('disposal_records'), false, `${file} has no disposal logic`);
  }
});

/** requiredBlobRefs equals the refs of the rows the predicate protects, for every reference column. */
function assertParity(db, tenantId) {
  const store = db.forTenant(tenantId);
  const protection = new retentionApi.ReferenceProtection(store);
  const expected = new Set();
  for (const { table, column, kind } of retentionApi.BLOB_REFERENCE_COLUMNS) {
    for (const row of store.iterate(table)) {
      const ref = row[column];
      if (typeof ref === 'string' && protection.protects(String(row.envelope_id), kind)) expected.add(ref);
    }
  }
  assert.deepEqual([...requiredBlobRefs(db, tenantId)].sort(), [...expected].sort());
}

// ------------------------------------------------------------------- OR-22

test('[OR-22] the ledger is re-read under the lock: a head another writer recorded during the backup refuses it with an accurate message, and that write is kept', async () => {
  const sys = system({ tenants: 2, events: 3, blobs: true });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const [tenantA, tenantB] = sys.tenants;
    appendEvents(sys, tenantA, 2);
    appendEvents(sys, tenantB, 2);
    let concurrent;
    // Another writer records B's next head while the backup copies blobs
    // (the first temp file in the backup's own blob store, not the source).
    hookFs('openSync', (real, path, ...rest) => {
      const text = String(path);
      if (concurrent === undefined && text.endsWith('.partial') && !text.startsWith(`${sys.blobRoot}${sep}`)) {
        concurrent = 'pending';
        appendEvents(sys, tenantB, 1);
        recordExportedHead(sys.ledgerPath, tenantB, headOf(sys, tenantB), { clock, source: 'receipt', digestAt: digestAtOf(sys, tenantB) });
        concurrent = sha(sys.ledgerPath);
      }
      return real.call(fs, path, ...rest);
    });
    let outcome;
    try {
      outcome = await settle(backup(sys, 'bk2'));
    } finally {
      unhookFs();
    }
    assert.match(concurrent ?? '', /^[0-9a-f]{64}$/, 'the concurrent writer ran during the backup');
    assert.equal(outcome.ok, false, 'the backup is refused');
    assert.doesNotMatch(outcome.error.message, /rolled back or diverged/, 'a concurrent advance is not reported as a rollback');
    assert.match(
      outcome.error.message,
      new RegExp(`tenant ${tenantB}: the exported-head ledger advanced while this backup ran \\(now seq 6; this snapshot's head is seq 5\\); nothing was recorded; run the backup again`),
    );
    assert.equal(sha(sys.ledgerPath), concurrent, 'the ledger holds exactly the concurrent write');
    assert.deepEqual(seqs(sys), [3, 6]);
    assert.deepEqual(stagingDirs(sys), []);
    assert.equal(existsSync(join(sys.backups, 'bk2')), false);
    await backup(sys, 'bk2');
    assert.deepEqual(seqs(sys), [5, 6], 'run again, the backup records both heads');
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-23

/** Delete a tenant as an operator with file access would (foreign keys off, delete triggers dropped and restored). */
function deleteTenant(sys, tenant) {
  const raw = rawConnection(sys.path);
  try {
    const triggers = ['audit_events_append_only_delete', 'audit_checkpoints_append_only_delete'].map((name) => raw.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?").get(name).sql);
    raw.exec('DROP TRIGGER audit_events_append_only_delete');
    raw.exec('DROP TRIGGER audit_checkpoints_append_only_delete');
    for (const table of ['audit_checkpoints', 'audit_events', 'tenants']) raw.prepare(`DELETE FROM ${table} WHERE tenant_id = ?`).run(tenant);
    for (const sql of triggers) raw.exec(sql);
  } finally {
    raw.close();
  }
}

test('[OR-23] a ledger tenant missing from the database refuses backup until --retire-tenant records it; a retired tenant that reappears refuses', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const [tenantA, tenantB] = sys.tenants;
    deleteTenant(sys, tenantB);
    let before = sha(sys.ledgerPath);
    await assert.rejects(
      backup(sys, 'bk2'),
      (error) =>
        error instanceof BackupError &&
        error.message ===
          `tenant ${tenantB}: the ledger has an exported head (seq 3) but the database has no such tenant (deleted, or the database was replaced); if the tenant was removed on purpose, record that with --retire-tenant ${tenantB}`,
    );
    assertPreCommit(sys, before, 'bk2');

    const present = cli('--retire-tenant', tenantA, '--db', sys.path, '--ledger', sys.ledgerPath);
    assert.equal(present.status, 1);
    assert.match(present.stdout, new RegExp(`^backup: refused recovery_refused: tenant ${tenantA} exists in the database; only an absent tenant can be retired`));
    assert.equal(sha(sys.ledgerPath), before);
    const unknown = sid('tenant');
    assert.equal(cli('--retire-tenant', unknown, '--db', sys.path, '--ledger', sys.ledgerPath).status, 1, 'a tenant without an exported head is not retired');

    const exported = readLedger(sys.ledgerPath)[tenantB];
    const retired = cli('--retire-tenant', tenantB, '--db', sys.path, '--ledger', sys.ledgerPath);
    assert.equal(retired.status, 0, retired.stdout + retired.stderr);
    assert.equal(retired.stdout, `backup: retired tenant=${tenantB} seq=3\n`);
    const document = JSON.parse(readFileSync(sys.ledgerPath, 'utf8'));
    assert.deepEqual(Object.keys(document.tenants), [tenantA]);
    assert.deepEqual(Object.keys(document.retired), [tenantB]);
    assert.deepEqual({ ...document.retired[tenantB], retired_at: undefined }, { ...exported, retired_at: undefined });
    assert.match(document.retired[tenantB].retired_at, /^\d{4}-\d\d-\d\dT/);
    assert.deepEqual(Object.keys(readLedger(sys.ledgerPath)), [tenantA]);
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE]);

    appendEvents(sys, tenantA, 1);
    await backup(sys, 'bk2');
    assert.deepEqual(readLedger(sys.ledgerPath)[tenantA].seq, 4);
    assert.deepEqual(Object.keys(JSON.parse(readFileSync(sys.ledgerPath, 'utf8')).retired), [tenantB], 'the retirement is kept');
    assert.match(cli('--retire-tenant', tenantB, '--db', sys.path, '--ledger', sys.ledgerPath).stdout, /already retired/);
    assert.throws(
      () => recordExportedHead(sys.ledgerPath, tenantB, { seq: 4, digest: hex('x') }, { clock, source: 'receipt', digestAt: () => hex('x') }),
      (error) => error instanceof LedgerError && /retired/.test(error.message),
    );

    // The retired tenant reappears.
    createTenant(sys.db, tenantB);
    appendEvents(sys, tenantB, 1);
    before = sha(sys.ledgerPath);
    await assert.rejects(backup(sys, 'bk3'), (error) => error instanceof BackupError && error.message === `tenant ${tenantB}: the tenant was retired in the ledger and has reappeared in the database`);
    assertPreCommit(sys, before, 'bk3', 'bk2');
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-24

test('[OR-24] --first-restore writes the restored heads under the lock, all or nothing; any other restore leaves the ledger bytes alone', async () => {
  const sys = system({ tenants: 2, events: 3, blobs: true });
  try {
    appendEvents(sys, sys.tenants[1], 2);
    await backup(sys, 'bk1', { firstBackup: true });
    const bk1 = join(sys.backups, 'bk1');
    const ledgers = scratch.dir();

    // Verification alone never writes the ledger.
    const fresh = join(ledgers, 'first.json');
    assert.equal(verifyBackup({ backupDir: bk1, ledgerPath: fresh, firstRestore: true }).tenants.length, 2);
    assert.equal(existsSync(fresh), false);

    const restored = target();
    const report = restoreBackup({ backupDir: bk1, ledgerPath: fresh, firstRestore: true, clock, ...restored });
    assert.deepEqual(report.tenants.map((tenant) => tenant.head.seq), [3, 5]);
    assert.equal(existsSync(fresh), true, 'the first restore writes the restored heads');
    const written = readLedger(fresh);
    for (const tenant of report.tenants) {
      assert.deepEqual([written[tenant.tenant_id].seq, written[tenant.tenant_id].digest, written[tenant.tenant_id].source], [tenant.head.seq, tenant.head.digest, 'first-restore']);
    }
    assert.equal(statSync(fresh).mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(ledgers), ['first.json'], 'no lock, record or temp file is left');

    // The next backup of the restored system needs no flag.
    const restoredBackups = scratch.dir();
    await createBackup({ databasePath: restored.databasePath, blobRoot: restored.blobRoot, outDir: join(restoredBackups, 'next'), ledgerPath: fresh, clock });
    assert.deepEqual(readLedger(fresh)[sys.tenants[1]].seq, 5);

    // All or nothing: the ledger write fails, so nothing is restored.
    const failing = join(ledgers, 'failing.json');
    const refusedTarget = target();
    const failRename = {
      rename(from, to) {
        if (to === failing) throw ioError('EIO', to);
        renameSync(from, to);
      },
    };
    assert.throws(() => restoreBackup({ backupDir: bk1, ledgerPath: failing, firstRestore: true, clock, io: failRename, ...refusedTarget }), (error) => error.code === 'EIO');
    assert.equal(existsSync(failing), false, 'the ledger is still missing');
    assert.equal(existsSync(refusedTarget.databasePath), false, 'no database was restored');
    assert.equal(existsSync(refusedTarget.blobRoot), false, 'no blob root was left');
    assert.deepEqual(readdirSync(dirname(refusedTarget.databasePath)), [], 'no staging file was left');
    assert.deepEqual(readdirSync(ledgers).sort(), ['first.json'], 'no lock, record or temp file is left');

    // Any other restore never writes the ledger.
    for (const firstRestore of [false, true]) {
      const before = sha(sys.ledgerPath);
      restoreBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath, firstRestore, clock, ...target() });
      assert.equal(sha(sys.ledgerPath), before, `a restore with an existing ledger leaves it byte-identical (firstRestore ${firstRestore})`);
    }

    // The lock is held: the first restore is refused and restores nothing.
    const contended = join(ledgers, 'contended.json');
    const holder = LedgerSession.open(contended, { allowMissing: true });
    const lockedTarget = target();
    try {
      assert.throws(() => restoreBackup({ backupDir: bk1, ledgerPath: contended, firstRestore: true, clock, ...lockedTarget }), (error) => error.code === 'ledger_locked');
    } finally {
      holder.release();
    }
    assert.equal(existsSync(contended), false);
    assert.equal(existsSync(lockedTarget.databasePath), false);
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-26

test('[OR-26] an injected post-commit I/O failure (ledger-directory fsync, staging rename, final manifest, parent fsync) keeps the staged backup and reports exit 75; nothing changes until --complete-staged, which re-commits the ledger by a fresh replace', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const bk1 = join(sys.backups, 'bk1');

    // --complete-staged re-commits the ledger by a fresh atomic replace (a
    // new file renamed over it), never a bare re-fsync of its directory.
    appendEvents(sys, sys.tenants[1], 1);
    const recommitFinal = join(sys.backups, 'bk-recommit');
    const unpublished = await settle(
      backup(sys, 'bk-recommit', {
        io: {
          rename(from, to) {
            if (to === recommitFinal) throw ioError('EXDEV', to);
            renameSync(from, to);
          },
        },
      }),
    );
    assert.equal(isPending(unpublished.error), true);
    const committedBytes = sha(sys.ledgerPath);
    const committedInode = statSync(sys.ledgerPath).ino;
    const recommitted = cli('--complete-staged', unpublished.error.directory, '--ledger', sys.ledgerPath);
    assert.equal(recommitted.status, 0, recommitted.stdout + recommitted.stderr);
    assert.equal(sha(sys.ledgerPath), committedBytes, 'the same ledger bytes');
    assert.notEqual(statSync(sys.ledgerPath).ino, committedInode, '--complete-staged replaced the ledger file by a fresh atomic replace, not only re-fsynced its directory');
    assert.deepEqual(readdirSync(recommitFinal).sort(), ['blobs', 'manifest.json', 'opensig.db']);

    // The ledger-directory fsync after the rename fails, injected at node:fs
    // (the same fault on any version of the code).
    appendEvents(sys, sys.tenants[0], 1);
    let renamed = false;
    hookFs('renameSync', (real, from, to) => {
      const result = real.call(fs, from, to);
      if (String(to) === sys.ledgerPath) renamed = true;
      return result;
    });
    hookFs('openSync', (real, path, ...rest) => {
      if (renamed && String(path) === sys.ledgerDir) throw ioError('EIO', path);
      return real.call(fs, path, ...rest);
    });
    let unsynced;
    try {
      unsynced = await settle(backup(sys, 'bk2'));
    } finally {
      unhookFs();
    }
    assert.equal(isPending(unsynced.error), true, `a failure after the ledger rename reports committed-pending-publication (got ${unsynced.error?.code}: ${unsynced.error?.message})`);
    assert.equal(claimsUnchanged(unsynced.error.message), false, 'no message says the ledger is unchanged');
    assert.equal(existsSync(join(sys.backups, 'bk2')), false, 'after a failed ledger-directory fsync nothing is published');
    assert.deepEqual(stagingDirs(sys).map((name) => join(sys.backups, name)), [unsynced.error.directory], 'the staged backup is preserved');
    assert.deepEqual(readdirSync(unsynced.error.directory).sort(), ['blobs', 'manifest.staged.json', 'opensig.db']);
    assert.equal(unsynced.error.ledgerDigest, sha(sys.ledgerPath));
    assert.deepEqual(seqs(sys), [4, 4], 'the ledger is committed');
    assert.equal(readLedgerLock(sys.ledgerPath), undefined, 'the failing run released the lock');
    assert.match(unsynced.error.message, /--complete-staged /);
    completeStaged(unsynced.error.directory, { ledgerPath: sys.ledgerPath });
    assert.equal(verifyBackup({ backupDir: join(sys.backups, 'bk2'), ledgerPath: sys.ledgerPath }).tenants[0].head.seq, 4);

    // The same three failures through the internal io seam.
    const cases = [
      {
        label: 'ledger-directory fsync',
        io: (final) => {
          let committed = false;
          return {
            rename(from, to) {
              renameSync(from, to);
              if (to === sys.ledgerPath) committed = true;
              if (to === final) assert.fail('the run must not publish after a failed ledger-directory fsync');
            },
            syncDirectory(path) {
              if (committed && path === sys.ledgerDir) throw ioError('EIO', path);
              fsyncDirectory(path);
            },
          };
        },
        kept: 'staging',
        listing: ['blobs', 'manifest.staged.json', 'opensig.db'],
        detail: /the ledger directory fsync failed after the commit, so nothing was published/,
      },
      {
        label: 'staging rename',
        io: (final) => ({
          rename(from, to) {
            if (to === final) throw ioError('EXDEV', to);
            renameSync(from, to);
          },
        }),
        kept: 'staging',
        listing: ['blobs', 'manifest.staged.json', 'opensig.db'],
        detail: /renaming the staging directory to its final name failed/,
      },
      {
        label: 'final manifest',
        io: (final) => ({
          rename(from, to) {
            if (to === join(final, 'manifest.json')) throw ioError('EIO', to);
            renameSync(from, to);
          },
        }),
        kept: 'final',
        listing: ['blobs', 'manifest.staged.json', 'opensig.db'],
        detail: /publishing the final manifest failed after the rename/,
      },
      {
        label: 'parent fsync',
        io: (final) => {
          let published = false;
          return {
            rename(from, to) {
              renameSync(from, to);
              if (to === final) published = true;
            },
            syncDirectory(path) {
              if (published && path === dirname(final)) throw ioError('EIO', path);
              fsyncDirectory(path);
            },
          };
        },
        kept: 'final',
        listing: ['blobs', 'manifest.json', 'opensig.db'],
        detail: /the parent directory fsync failed after the rename/,
      },
    ];
    let index = 3;
    for (const { label, io, kept, listing, detail } of cases) {
      appendEvents(sys, sys.tenants[1], 1);
      const name = `bk${index}`;
      index += 1;
      const final = join(sys.backups, name);
      const before = sha(sys.ledgerPath);
      const failed = await settle(backup(sys, name, { io: io(final) }));
      assert.equal(isPending(failed.error), true, `${label}: committed-pending-publication`);
      assert.match(failed.error.message, detail);
      assert.equal(claimsUnchanged(failed.error.message), false, `${label}: no message says the ledger is unchanged`);
      assert.notEqual(sha(sys.ledgerPath), before, `${label}: the ledger is committed`);
      const digest = sha(sys.ledgerPath);
      assert.equal(failed.error.ledgerDigest, digest);
      const staged = stagingDirs(sys);
      if (kept === 'staging') {
        assert.deepEqual(staged.map((entry) => join(sys.backups, entry)), [failed.error.directory], `${label}: kept under the staging name`);
        assert.equal(existsSync(final), false);
      } else {
        assert.deepEqual(staged, [], `${label}: kept under the final name only`);
        assert.equal(failed.error.directory, final);
      }
      assert.deepEqual(readdirSync(failed.error.directory).sort(), listing);
      assert.equal(readLedgerLock(sys.ledgerPath), undefined);

      // While it is pending: backup, verify and restore report 75 and change nothing.
      const frozen = state(sys);
      const pendingTarget = target();
      await assert.rejects(backup(sys, `${name}-again`), isPending);
      assert.throws(() => verifyBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath }), isPending);
      assert.throws(() => verifyBackup({ backupDir: failed.error.directory, ledgerPath: sys.ledgerPath }), isPending);
      assert.throws(() => restoreBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath, ...pendingTarget }), isPending);
      for (const args of [
        ['create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', join(sys.backups, `${name}-cli`), '--ledger', sys.ledgerPath],
        ['verify', '--from', bk1, '--ledger', sys.ledgerPath],
        ['restore', '--from', bk1, '--ledger', sys.ledgerPath, '--db', pendingTarget.databasePath, '--blobs', pendingTarget.blobRoot],
      ]) {
        const run = cli(...args);
        assert.equal(run.status, 75, `${label} ${args[0]}: ${run.stdout}${run.stderr}`);
        assert.match(run.stdout, new RegExp(`^backup: committed-pending-publication directory=\\S+ ledger-digest=${digest} recover="--complete-staged \\S+": `));
      }
      assert.equal(existsSync(pendingTarget.databasePath), false);
      assert.deepEqual(state(sys), frozen, `${label}: nothing changed while pending`);

      if (label === 'staging rename' || label === 'ledger-directory fsync') {
        // A repeated I/O failure during recovery (here the staging rename, or
        // the directory fsync after the re-commit) is pending again.
        assert.throws(() => completeStaged(failed.error.directory, { ledgerPath: sys.ledgerPath, io: io(final) }), isPending);
        assert.deepEqual(state(sys), frozen);
      }
      const inode = statSync(sys.ledgerPath).ino;
      const completed = cli('--complete-staged', failed.error.directory, '--ledger', sys.ledgerPath);
      assert.equal(completed.status, 0, completed.stdout + completed.stderr);
      assert.equal(completed.stdout, `backup: published directory=${final}\n`);
      assert.notEqual(statSync(sys.ledgerPath).ino, inode, `${label}: --complete-staged re-committed the ledger by a fresh replace`);
      assert.deepEqual(readdirSync(final).sort(), ['blobs', 'manifest.json', 'opensig.db']);
      assert.deepEqual(stagingDirs(sys), []);
      assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE]);
      assert.equal(sha(sys.ledgerPath), digest);
      assert.deepEqual(verifyBackup({ backupDir: final, ledgerPath: sys.ledgerPath }).tenants.map((tenant) => tenant.head.seq), seqs(sys));
    }

    // The seam is internal: the command line has no way to reach it.
    const script = readFileSync(SCRIPT, 'utf8');
    assert.equal(/\bio\s*:/.test(script), false, 'scripts/backup.mjs never passes an io seam');
    const seam = cli('create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', join(sys.backups, 'bk-seam'), '--ledger', sys.ledgerPath, '--io', 'fail');
    assert.equal(seam.status, 2);
    assert.match(seam.stderr, /^backup: USAGE unknown argument "--io"/);
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-27

test('[OR-27] the blob size limit is carried through backup, verify and restore: recorded in the manifest, refused cleanly above it, never truncated', async () => {
  const sys = system({ tenants: 1, events: 2 });
  try {
    const [tenant] = sys.tenants;
    const content = syntheticBytes('or27-blob', 4096);
    const blob = sys.blobs.put(tenant, content);

    // A backup made with a lower limit than a stored blob refuses cleanly.
    await assert.rejects(
      backup(sys, 'bk-low', { firstBackup: true, maxBlobBytes: 2048 }),
      (error) =>
        error instanceof BackupError &&
        error.message.startsWith(`tenant ${tenant}: blob ${blob.digest} failed verification (`) &&
        error.message.includes("this backup's blob size limit is 2048 bytes: pass the source store's limit with --max-blob-bytes"),
    );
    assert.deepEqual(readdirSync(sys.backups), [], 'nothing is left, no partial copy');
    assert.equal(existsSync(sys.ledgerPath), false);
    assert.deepEqual(sys.blobs.read(tenant, blob.digest), content, 'the source blob is untouched');

    // The limit the backup was made with is recorded, and used by verify and restore.
    const manifest = await backup(sys, 'bk1', { firstBackup: true, maxBlobBytes: 8192 });
    assert.equal(manifest.blob_max_bytes, 8192);
    const bk1 = join(sys.backups, 'bk1');
    assert.equal(JSON.parse(readFileSync(join(bk1, 'manifest.json'), 'utf8')).blob_max_bytes, 8192);
    assert.equal(verifyBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath }).tenants[0].blobs, 1);
    const restored = target();
    restoreBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath, ...restored });
    assert.deepEqual(blobsApi.openBlobStore({ root: restored.blobRoot }).read(tenant, blob.digest), content, 'restored byte for byte');
    assert.equal((await backup(sys, 'bk-default')).blob_max_bytes, blobsApi.DEFAULT_MAX_BLOB_BYTES, 'the default limit is recorded too');

    const withLimit = (limit) => {
      const copy = join(scratch.dir(), 'copy');
      cpSync(bk1, copy, { recursive: true });
      const value = JSON.parse(readFileSync(join(copy, 'manifest.json'), 'utf8'));
      if (limit === undefined) delete value.blob_max_bytes;
      else value.blob_max_bytes = limit;
      writeFileSync(join(copy, 'manifest.json'), canonicalize(value));
      return copy;
    };
    const lowered = withLimit(1024);
    assert.throws(() => verifyBackup({ backupDir: lowered, ledgerPath: sys.ledgerPath }), (error) => error instanceof RestoreRefusedError && error.reasons.some((reason) => reason.includes(`blob ${blob.digest} failed verification`)));
    const refusedTarget = target();
    assert.throws(() => restoreBackup({ backupDir: lowered, ledgerPath: sys.ledgerPath, ...refusedTarget }), RestoreRefusedError);
    assert.equal(existsSync(refusedTarget.databasePath), false);
    assert.equal(existsSync(refusedTarget.blobRoot), false);
    for (const malformed of [0, blobsApi.MAX_BLOB_BYTES_LIMIT + 1, '8192']) {
      assert.throws(() => verifyBackup({ backupDir: withLimit(malformed), ledgerPath: sys.ledgerPath }), (error) => error instanceof RestoreRefusedError && error.reasons.includes('manifest blob size limit is malformed'));
    }
    assert.equal(verifyBackup({ backupDir: withLimit(undefined), ledgerPath: sys.ledgerPath }).tenants.length, 1, 'a manifest without the field uses the default limit');

    // The command line carries the limit.
    const low = cli('create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', join(sys.backups, 'cli-low'), '--ledger', sys.ledgerPath, '--max-blob-bytes', '2048');
    assert.equal(low.status, 1);
    assert.match(low.stdout, /^backup: refused backup_failed: tenant .* failed verification .*--max-blob-bytes\n$/);
    const ok = cli('create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', join(sys.backups, 'cli-ok'), '--ledger', sys.ledgerPath, '--max-blob-bytes', '8192');
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    assert.equal(JSON.parse(readFileSync(join(sys.backups, 'cli-ok', 'manifest.json'), 'utf8')).blob_max_bytes, 8192);
    for (const value of ['0', 'abc', String(blobsApi.MAX_BLOB_BYTES_LIMIT + 1)]) {
      const run = cli('create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', join(sys.backups, 'cli-bad'), '--ledger', sys.ledgerPath, '--max-blob-bytes', value);
      assert.equal(run.status, 2, `${value}: ${run.stdout}${run.stderr}`);
    }
    assert.deepEqual(stagingDirs(sys), []);
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-28

test('[OR-28] a ledger writer other than a backup whose ledger-directory fsync fails after the rename reports committed-unsynced (exit 74), rolls nothing back, and recovers with --resync-ledger', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const [tenantA, tenantB] = sys.tenants;
    deleteTenant(sys, tenantB);
    const before = sha(sys.ledgerPath);

    // --retire-tenant, with the fault injected at node:fs in the CLI process.
    const retired = cliFault(sys.ledgerPath, '--retire-tenant', tenantB, '--db', sys.path, '--ledger', sys.ledgerPath);
    assert.equal(retired.status, 74, `committed-unsynced exits 74 (${retired.stdout}${retired.stderr})`);
    const after = sha(sys.ledgerPath);
    assert.notEqual(after, before, 'the retirement is visible: nothing was rolled back');
    assert.deepEqual(Object.keys(JSON.parse(readFileSync(sys.ledgerPath, 'utf8')).retired), [tenantB]);
    const prefix = `backup: committed-unsynced ledger=${sys.ledgerPath} previous-digest=${before} ledger-digest=${after} recover="--resync-ledger ${after} --ledger ${sys.ledgerPath}": `;
    assert.ok(retired.stdout.startsWith(prefix), retired.stdout);
    assert.match(retired.stdout, new RegExp(`previous digest ${before}; new digest ${after}`), 'the message names both digests');
    assert.doesNotMatch(retired.stdout, /unchanged|byte-identical|durable/i, 'it never says the ledger is unchanged, byte-identical or durable');
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE], 'the lock was released');

    // --resync-ledger with another digest refuses and changes nothing.
    const inode = statSync(sys.ledgerPath).ino;
    const stale = cli('--resync-ledger', before, '--ledger', sys.ledgerPath);
    assert.equal(stale.status, 1);
    assert.match(stale.stdout, new RegExp(`^backup: refused recovery_refused: the ledger digest is ${after}, not ${before}: .*nothing was changed`));
    assert.deepEqual([sha(sys.ledgerPath), statSync(sys.ledgerPath).ino], [after, inode]);
    assert.equal(cli('--resync-ledger', 'not-a-digest', '--ledger', sys.ledgerPath).status, 2);
    // With the current digest it re-commits the same bytes by a fresh atomic replace.
    const synced = cli('--resync-ledger', after, '--ledger', sys.ledgerPath);
    assert.equal(synced.status, 0, synced.stdout + synced.stderr);
    assert.equal(synced.stdout, `backup: ledger-synced ledger=${sys.ledgerPath} ledger-digest=${after}\n`);
    assert.equal(sha(sys.ledgerPath), after);
    assert.notEqual(statSync(sys.ledgerPath).ino, inode, 'a fresh replace, never a bare re-fsync');
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE]);

    // A first restore: the restored database stays in place.
    const firstLedgerDir = scratch.dir();
    const firstLedger = join(firstLedgerDir, LEDGER_FILE);
    const restoredTarget = target();
    const restored = cliFault(firstLedger, 'restore', '--from', join(sys.backups, 'bk1'), '--ledger', firstLedger, '--db', restoredTarget.databasePath, '--blobs', restoredTarget.blobRoot, '--first-restore');
    assert.equal(restored.status, 74, restored.stdout + restored.stderr);
    const firstDigest = sha(firstLedger);
    assert.ok(restored.stdout.startsWith(`backup: committed-unsynced ledger=${firstLedger} previous-digest=none ledger-digest=${firstDigest} recover="--resync-ledger ${firstDigest} --ledger ${firstLedger}": `), restored.stdout);
    assert.doesNotMatch(restored.stdout, /unchanged|byte-identical|durable/i);
    const restoredDb = openDatabase({ path: restoredTarget.databasePath });
    try {
      assert.deepEqual(restoredDb.listTenantIds(), sys.tenants, 'the restored database was not rolled back');
    } finally {
      restoredDb.close();
    }
    assert.deepEqual(Object.keys(readLedger(firstLedger)).sort(), sys.tenants);
    assert.deepEqual(readdirSync(firstLedgerDir), [LEDGER_FILE]);

    // recordExportedHead (library): the typed committed-unsynced status, and
    // nothing that depends on the new head runs.
    appendEvents(sys, tenantA, 1);
    const recordBefore = sha(sys.ledgerPath);
    let dependentEffect = false;
    assert.throws(
      () => {
        recordExportedHead(sys.ledgerPath, tenantA, headOf(sys, tenantA), { clock, source: 'receipt', digestAt: digestAtOf(sys, tenantA), io: failDirFsync(sys.ledgerPath) });
        dependentEffect = true; // for example, releasing a receipt that names the new head
      },
      (error) =>
        error instanceof LedgerCommitUnsyncedError &&
        error.status === 'committed-unsynced' &&
        error.code === 'committed_unsynced' &&
        error.previousDigest === recordBefore &&
        error.ledgerDigest === sha(sys.ledgerPath) &&
        error.recovery === `--resync-ledger ${sha(sys.ledgerPath)} --ledger ${sys.ledgerPath}` &&
        !/unchanged|byte-identical|durable/i.test(error.message),
    );
    assert.equal(dependentEffect, false, 'nothing that depends on the new head ran');
    assert.equal(readLedger(sys.ledgerPath)[tenantA].seq, 4, 'the head is recorded, not rolled back');
    const current = sha(sys.ledgerPath);
    assert.throws(() => resyncLedger(current, { ledgerPath: sys.ledgerPath, io: failDirFsync(sys.ledgerPath) }), (error) => error instanceof LedgerCommitUnsyncedError && error.ledgerDigest === current);
    assert.deepEqual(resyncLedger(current, { ledgerPath: sys.ledgerPath }), { status: 'ledger-synced', ledgerPath: sys.ledgerPath, ledgerDigest: current });

    // Exit 74 means only committed-unsynced: a backup in the same situation is 75.
    appendEvents(sys, tenantA, 1);
    const backupFault = cliFault(sys.ledgerPath, 'create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', join(sys.backups, 'bk-fault'), '--ledger', sys.ledgerPath);
    assert.equal(backupFault.status, 75, backupFault.stdout + backupFault.stderr);
    assert.match(backupFault.stdout, /^backup: committed-pending-publication /);
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-29

test('[OR-29] a surviving intent record keeps a staging that changed no head pending, and the abandon message is truthful about it (T30D-1)', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const bk1 = join(sys.backups, 'bk1');
    const digest = sha(sys.ledgerPath);
    // No event since bk1, so the next backup changes no head. It crashes
    // after writing its intent record, before the ledger rename.
    const crashWithIntent = () => {
      const crash = runChild('crash-temp', 'backup', { databasePath: sys.path, blobRoot: sys.blobRoot, outDir: join(sys.backups, 'bk2'), ledgerPath: sys.ledgerPath });
      assert.equal(crash.signal, 'SIGKILL');
      breakLedgerLock(sys.ledgerPath, readLedgerLock(sys.ledgerPath).nonce);
      const staged = stagingDirs(sys);
      assert.equal(staged.length, 1);
      return join(sys.backups, staged[0]);
    };
    let staging = crashWithIntent();
    assert.equal(sha(sys.ledgerPath), digest, 'the ledger bytes cannot show whether the rename happened');
    assert.equal(pendingPublication(sys.ledgerPath)?.staging, staging, 'the surviving intent record keeps the staging pending');
    assert.throws(() => verifyBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath }), isPending, 'pending even though bk1 carries the same heads');
    const stagingReal = realpathSync(staging);
    const abandoned = cli('--discard-staged', staging, '--ledger', sys.ledgerPath, '--abandon-committed', digest);
    assert.equal(abandoned.status, 0, abandoned.stdout + abandoned.stderr);
    assert.equal(
      abandoned.stdout,
      `backup: abandoned-committed directory=${stagingReal} ledger-digest=${digest}: the staged backup was deleted; the ledger stays as committed; this backup did not change the ledger heads, so a published backup that carries them stays restorable\n`,
    );
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE], 'abandoning clears the intent record');
    assert.equal(verifyBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath }).tenants.length, 2, 'the published backup with the same heads stays restorable');
    assert.equal(restoreBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath, ...target() }).tenants.length, 2);

    // Completing it instead publishes a second backup with the same heads.
    staging = crashWithIntent();
    const completed = cli('--complete-staged', staging, '--ledger', sys.ledgerPath);
    assert.equal(completed.status, 0, completed.stdout + completed.stderr);
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE], '--complete-staged clears the intent record');
    const heads = (dir) => verifyBackup({ backupDir: dir, ledgerPath: sys.ledgerPath }).tenants.map((tenant) => tenant.head);
    assert.deepEqual(heads(join(sys.backups, 'bk2')), heads(bk1));

    // A backup that changed the heads: the abandon message says the ledger is ahead, and restores refuse.
    appendEvents(sys, sys.tenants[0], 1);
    const final = join(sys.backups, 'bk3');
    const failed = await settle(
      backup(sys, 'bk3', {
        io: {
          rename(from, to) {
            if (to === final) throw ioError('EXDEV', to);
            renameSync(from, to);
          },
        },
      }),
    );
    assert.equal(isPending(failed.error), true);
    const ahead = sha(sys.ledgerPath);
    const pendingReal = realpathSync(failed.error.directory);
    const abandonedAhead = cli('--discard-staged', failed.error.directory, '--ledger', sys.ledgerPath, '--abandon-committed', ahead);
    assert.equal(abandonedAhead.status, 0, abandonedAhead.stdout + abandonedAhead.stderr);
    assert.equal(
      abandonedAhead.stdout,
      `backup: abandoned-committed directory=${pendingReal} ledger-digest=${ahead}: the staged backup was deleted; the ledger stays as committed, ahead of every published backup; every restore refuses until a backup carrying the committed heads is published\n`,
    );
    assert.throws(() => restoreBackup({ backupDir: join(sys.backups, 'bk2'), ledgerPath: sys.ledgerPath, ...target() }), (error) => error instanceof RestoreRefusedError && /older than the last exported head/.test(error.message));
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-30

test('[OR-30] a first restore that fails before its commit point removes only the database files it created, never a database that appears at the target, and nothing after the commit point (T30D-3)', async () => {
  const sys = system({ tenants: 1, events: 3, blobs: true });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const bk1 = join(sys.backups, 'bk1');

    // Journal files at the target name that this run did not create.
    const dir = scratch.dir();
    const databasePath = join(dir, 'restored.db');
    const blobRoot = join(dir, 'blobs');
    const foreign = new Map([
      [`${databasePath}-wal`, syntheticBytes('foreign-wal', 64)],
      [`${databasePath}-journal`, syntheticBytes('foreign-journal', 64)],
    ]);
    for (const [path, bytes] of foreign) writeFileSync(path, bytes);
    const ledgerDir = scratch.dir();
    const ledgerPath = join(ledgerDir, LEDGER_FILE);
    const failRename = {
      rename(from, to) {
        if (to === ledgerPath) throw ioError('EIO', to);
        renameSync(from, to);
      },
    };
    assert.throws(() => restoreBackup({ backupDir: bk1, ledgerPath, firstRestore: true, clock, io: failRename, databasePath, blobRoot }), (error) => error.code === 'EIO');
    for (const [path, bytes] of foreign) {
      assert.equal(existsSync(path), true, `${basename(path)} was not created by this run and is not removed`);
      assert.deepEqual(readFileSync(path), bytes);
    }
    assert.equal(existsSync(databasePath), false, 'the database file this run placed is removed');
    assert.equal(existsSync(blobRoot), false);
    assert.deepEqual(readdirSync(dir).sort(), [...foreign.keys()].map((path) => basename(path)).sort(), 'no staging file is left');
    assert.deepEqual(readdirSync(ledgerDir), [], 'the ledger is still missing, with no lock, record or temp file');

    // A database that appears at the target during the run is never replaced or removed.
    const raceDir = scratch.dir();
    const raceDb = join(raceDir, 'restored.db');
    const raceBlobs = join(raceDir, 'blobs');
    const another = syntheticBytes('another-database', 4096);
    hookFs('openSync', (real, path, ...rest) => {
      const text = String(path);
      if (!existsSync(raceDb) && text.startsWith(`${raceBlobs}${sep}`) && text.endsWith('.partial')) writeFileSync(raceDb, another);
      return real.call(fs, path, ...rest);
    });
    let raced;
    try {
      raced = await settle(Promise.resolve().then(() => restoreBackup({ backupDir: bk1, ledgerPath, firstRestore: true, clock, databasePath: raceDb, blobRoot: raceBlobs })));
    } finally {
      unhookFs();
    }
    assert.equal(raced.ok, false, 'the restore refuses rather than replace a database');
    assert.match(raced.error.message, /never overwrites a database/);
    assert.deepEqual(readFileSync(raceDb), another, 'the database that appeared is untouched');
    assert.equal(existsSync(raceBlobs), false);
    assert.deepEqual(readdirSync(raceDir), ['restored.db']);
    assert.deepEqual(readdirSync(ledgerDir), []);

    // After the commit point nothing is removed (committed-unsynced).
    const lateDir = scratch.dir();
    const lateLedger = join(scratch.dir(), LEDGER_FILE);
    const late = { databasePath: join(lateDir, 'restored.db'), blobRoot: join(lateDir, 'blobs') };
    assert.throws(() => restoreBackup({ backupDir: bk1, ledgerPath: lateLedger, firstRestore: true, clock, io: failDirFsync(lateLedger), ...late }), (error) => error instanceof LedgerCommitUnsyncedError);
    const lateDb = openDatabase({ path: late.databasePath });
    try {
      assert.deepEqual(lateDb.listTenantIds(), sys.tenants, 'the restored database stays');
    } finally {
      lateDb.close();
    }
    assert.equal(blobsApi.openBlobStore({ root: late.blobRoot }).list(sys.tenants[0]).length, 3, 'the restored blobs stay');
    assert.deepEqual(Object.keys(readLedger(lateLedger)), sys.tenants);
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-31

test('[OR-31] --discard-staged, with or without --abandon-committed, acts only on the exact staging name and never deletes a backup under its final name (T30D-4 rejected)', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    appendEvents(sys, sys.tenants[0], 1);
    const final = join(sys.backups, 'bk2');
    let renamed = false;
    const failParent = {
      rename(from, to) {
        renameSync(from, to);
        if (to === final) renamed = true;
      },
      syncDirectory(path) {
        if (renamed && path === sys.backups) throw ioError('EIO', path);
        fsyncDirectory(path);
      },
    };
    const kept = await settle(backup(sys, 'bk2', { io: failParent }));
    assert.equal(kept.error?.directory, final, 'the pending backup is under its final name');
    const record = pendingPublication(sys.ledgerPath);
    assert.notEqual(record.staging, final);
    const digest = sha(sys.ledgerPath);
    const listing = readdirSync(final).sort();
    for (const args of [[record.staging, '--abandon-committed', digest], [record.staging], [final, '--abandon-committed', digest], [final]]) {
      const run = cli('--discard-staged', args[0], '--ledger', sys.ledgerPath, ...args.slice(1));
      assert.equal(run.status, 1, `${args.join(' ')}: ${run.stdout}${run.stderr}`);
      assert.match(run.stdout, /^backup: refused recovery_refused: .*nothing was deleted\n$/);
      assert.ok(run.stdout.includes(`--complete-staged ${final}`), `the refusal says where the backup is: ${run.stdout}`);
      assert.deepEqual(readdirSync(final).sort(), listing, 'the backup under its final name is untouched');
    }
    assert.equal(pendingPublication(sys.ledgerPath)?.final, final, 'still pending');
    const completed = cli('--complete-staged', final, '--ledger', sys.ledgerPath);
    assert.equal(completed.status, 0, completed.stdout + completed.stderr);
    const published = cli('--discard-staged', final, '--ledger', sys.ledgerPath);
    assert.equal(published.status, 1);
    assert.match(published.stdout, /is not a staging directory/);
    assert.deepEqual(readdirSync(final).sort(), ['blobs', 'manifest.json', 'opensig.db'], 'a published backup is never discarded');
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-32

test('[OR-32] staging is recognised by its staged manifest: a copy of, or a link to, an uncommitted staging directory is refused by verify and restore (T30R2-3)', async () => {
  const sys = system({ tenants: 1, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    assert.deepEqual(readdirSync(join(sys.backups, 'bk1')).sort(), ['blobs', 'manifest.json', 'opensig.db'], 'a published backup holds only the final manifest');
    appendEvents(sys, sys.tenants[0], 2);
    const crash = runChild('crash-temp', 'backup', { databasePath: sys.path, blobRoot: sys.blobRoot, outDir: join(sys.backups, 'bk2'), ledgerPath: sys.ledgerPath });
    assert.equal(crash.signal, 'SIGKILL');
    const [name] = stagingDirs(sys);
    const staging = join(sys.backups, name);
    const copy = join(sys.backups, 'copy-of-staging');
    cpSync(staging, copy, { recursive: true });
    const link = join(sys.backups, 'link-to-staging');
    symlinkSync(staging, link);
    for (const dir of [copy, link]) {
      const verified = cli('verify', '--from', dir, '--ledger', sys.ledgerPath);
      assert.equal(verified.status, 1, `${basename(dir)} is not a published backup (${verified.stdout}${verified.stderr})`);
      assert.equal(verified.stdout, 'backup: refused 1 reason(s): the directory holds a staged manifest (manifest.staged.json): it is staging, not a published backup\n');
      const refusedTarget = target();
      assert.throws(() => restoreBackup({ backupDir: dir, ledgerPath: sys.ledgerPath, ...refusedTarget }), RestoreRefusedError);
      assert.equal(existsSync(refusedTarget.databasePath), false);
      assert.equal(existsSync(refusedTarget.blobRoot), false);
    }
    // Without its staged manifest it is still no backup: the final manifest is missing.
    rmSync(join(copy, 'manifest.staged.json'));
    assert.throws(() => verifyBackup({ backupDir: copy, ledgerPath: sys.ledgerPath }), (error) => error instanceof RestoreRefusedError && error.reasons.includes('manifest is missing or not valid JSON'));
    assert.deepEqual(readdirSync(staging).sort(), ['blobs', 'manifest.staged.json', 'opensig.db']);
    breakLedgerLock(sys.ledgerPath, readLedgerLock(sys.ledgerPath).nonce);
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-33

test('[OR-33] the digest CAS sits immediately before the rename: a replacement made out of protocol during the temp write is refused, never overwritten (T30R2-4)', () => {
  const dir = scratch.dir();
  const ledgerPath = join(dir, LEDGER_FILE);
  const tenant = sid('tenant');
  const chain = { 1: hex('cas-1'), 2: hex('cas-2') };
  const digestAt = (seq) => chain[seq];
  recordExportedHead(ledgerPath, tenant, { seq: 1, digest: chain[1] }, { clock, source: 'receipt', digestAt, createIfMissing: true });
  const session = LedgerSession.open(ledgerPath);
  let outOfBand;
  try {
    const next = session.plan({ heads: new Map([[tenant, { head: { seq: 2, digest: chain[2] }, digestAt }]]), source: 'receipt', clock });
    const io = {
      writeFile(path, data) {
        writeExclusive(path, data);
        if (path.endsWith('.tmp')) {
          // A writer that ignores the lock replaces the ledger while the temp file is written.
          const value = JSON.parse(readFileSync(ledgerPath, 'utf8'));
          value.tenants[tenant] = { ...value.tenants[tenant], exported_at: new Date(BASE_TIME + 9_000_000).toISOString() };
          writeFileSync(ledgerPath, canonicalize(value));
          outOfBand = sha(ledgerPath);
        }
      },
    };
    assert.throws(() => session.commit(next, { io }), (error) => error instanceof LedgerError && /changed while it was locked \(digest mismatch\); nothing was written/.test(error.message));
  } finally {
    session.release();
  }
  assert.match(outOfBand ?? '', /^[0-9a-f]{64}$/);
  assert.equal(sha(ledgerPath), outOfBand, 'the replacement made during the temp write is kept, not overwritten');
  assert.equal(readLedger(ledgerPath)[tenant].seq, 1);
  assert.deepEqual(readdirSync(dir), [LEDGER_FILE], 'the temp file was removed and the lock released');
});

// ------------------------------------------------------------------- OR-34

test('[OR-34] --discard-staged identifies the staging by its real path, under any spelling, and reports the directory it actually deleted (T30R2-5)', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    appendEvents(sys, sys.tenants[1], 1);
    const final = join(sys.backups, 'bk2');
    const failed = await settle(
      backup(sys, 'bk2', {
        io: {
          rename(from, to) {
            if (to === final) throw ioError('EXDEV', to);
            renameSync(from, to);
          },
        },
      }),
    );
    assert.equal(isPending(failed.error), true);
    const staging = failed.error.directory;
    const real = realpathSync(staging);
    const alias = join(dirname(sys.backups), 'backups-alias');
    symlinkSync(sys.backups, alias);
    const spellings = [join(alias, basename(staging)), `${sys.backups}${sep}..${sep}${basename(sys.backups)}${sep}${basename(staging)}`];
    const digest = sha(sys.ledgerPath);
    for (const spelling of spellings) {
      const refused = cli('--discard-staged', spelling, '--ledger', sys.ledgerPath);
      assert.equal(refused.status, 1, `the pending committed staging is refused under the spelling ${spelling} (${refused.stdout})`);
      assert.match(refused.stdout, /is the pending committed staging/);
      assert.ok(existsSync(join(staging, 'manifest.staged.json')), 'nothing was deleted');
    }
    const abandoned = cli('--discard-staged', spellings[0], '--ledger', sys.ledgerPath, '--abandon-committed', digest);
    assert.equal(abandoned.status, 0, abandoned.stdout + abandoned.stderr);
    assert.ok(abandoned.stdout.startsWith(`backup: abandoned-committed directory=${real} ledger-digest=${digest}: `), `the deleted path is reported, not the name given (${abandoned.stdout})`);
    assert.equal(existsSync(real), false);
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE]);

    const copy = join(sys.backups, `.staging-${'b'.repeat(24)}-bk-copy`);
    cpSync(join(sys.backups, 'bk1'), copy, { recursive: true });
    const copyReal = realpathSync(copy);
    const discarded = cli('--discard-staged', join(alias, basename(copy)), '--ledger', sys.ledgerPath);
    assert.equal(discarded.stdout, `backup: discarded directory=${copyReal}\n`);
    assert.equal(existsSync(copy), false);
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-35

test('[OR-35] the lock owner holds its descriptor for the whole session and releases it on every path; --break-lock damaged moves aside only an unparseable lock older than 60 s that no live writer holds (T30R2-1)', async () => {
  const sys = system({ tenants: 2, events: 3 });
  let idle;
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const lockPath = `${sys.ledgerPath}.lock`;
    const age = (path, seconds) => {
      const time = new Date(Date.now() - seconds * 1000);
      utimesSync(path, time, time);
    };
    const torn = Buffer.from('{"schema":"opensig.ledger-lock/1","pid":');

    // (a) A live writer in another process holds the session; its lock
    // content is torn and older than 60 s. The damaged path refuses.
    const barrier = scratch.dir('opensig-barrier-');
    const holder = spawn(process.execPath, [CHILD, 'free', 'hold', JSON.stringify({ ledgerPath: sys.ledgerPath, barrier })], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    const holderExit = new Promise((resolveExit) => holder.on('exit', (code, signal) => resolveExit({ code, signal })));
    try {
      for (let i = 0; i < 6000 && !existsSync(join(barrier, 'ready')); i += 1) await sleep(5);
      assert.ok(existsSync(join(barrier, 'ready')), 'the writer holds the lock');
      const held = statSync(lockPath);
      writeFileSync(lockPath, torn); // in place: the same file the writer holds
      age(lockPath, 120);
      const refused = cli('--break-lock', 'damaged', '--ledger', sys.ledgerPath);
      assert.equal(refused.status, 1, `a damaged lock whose writer is live is not broken (${refused.stdout}${refused.stderr})`);
      assert.match(refused.stdout, new RegExp(`^backup: refused ledger_invalid: the damaged ledger lock is held by pid ${holder.pid}, a live writer; the lock was not moved`));
      const still = statSync(lockPath);
      assert.deepEqual([still.dev, still.ino], [held.dev, held.ino], '(a) the lock is untouched');
      assert.deepEqual(readFileSync(lockPath), torn);

      // (b) The writer crashes: the same aged, torn lock is moved aside.
      holder.kill('SIGKILL');
      assert.equal((await holderExit).signal, 'SIGKILL');
    } finally {
      if (holder.exitCode === null && holder.signalCode === null) holder.kill('SIGKILL');
    }
    // The cases that must move the lock, or reach its identity re-check, give
    // the library only processes this test owns and keeps alive: itself and an
    // idle child, each first shown inspectable by the command line's own
    // definition. No other process of this user on the host can decide them.
    idle = await ownedIdleProcess();
    const owned = [process.pid, idle.pid];
    const ownedScan = { pids: () => owned };
    const assertOwnedInspectable = () => {
      for (const pid of owned) assert.ok(inspectableByTheCli(pid), `pid ${pid}, owned by this test, is inspectable`);
    };

    // Through the CLI the whole of /proc is inspected, so its outcome depends
    // on every process of this user on the host: it moves the lock, or it
    // refuses, naming the processes it could not clear (a non-dumpable one
    // such as ssh-agent, or one exiting), and leaves the lock untouched. Both
    // hold under any host state; the uninspectable-peer refusal itself is
    // asserted by OR-41 and by case (d).
    const tornLock = statSync(lockPath);
    const moved = cli('--break-lock', 'damaged', '--ledger', sys.ledgerPath);
    let movedTo;
    if (moved.status === 0) {
      movedTo = /^backup: damaged-lock-moved path=(\S+)\n$/.exec(moved.stdout)?.[1];
    } else {
      assert.equal(moved.status, 1, moved.stdout + moved.stderr);
      assert.match(
        moved.stdout,
        /^backup: refused ledger_invalid: (?:process\(es\) [0-9]+(?:, [0-9]+)* of this user cannot be inspected, so it cannot be shown that none holds the damaged lock|the damaged ledger lock is held by pid [0-9]+(?:, [0-9]+)*, a live writer); the lock was not moved\n$/,
      );
      const still = statSync(lockPath);
      assert.deepEqual([still.dev, still.ino, readFileSync(lockPath)], [tornLock.dev, tornLock.ino, torn], 'refused: the lock is untouched');
      assertOwnedInspectable();
      movedTo = breakDamagedLock(sys.ledgerPath, ownedScan).movedTo;
    }
    assert.match(movedTo ?? '', new RegExp(`^${escapeRegExp(lockPath)}\\.damaged-\\d{4}-\\d\\d-\\d\\dT\\d\\d-\\d\\d-\\d\\d-\\d{3}Z$`), moved.stdout);
    assert.deepEqual(readFileSync(movedTo), torn, '(b) moved aside, never deleted');
    assert.equal(existsSync(lockPath), false);
    LedgerSession.open(sys.ledgerPath).release();
    rmSync(movedTo);

    // The 60 s rule, on the file's mtime and an injectable clock.
    writeFileSync(lockPath, torn, { flag: 'wx', mode: 0o600 });
    const mtime = statSync(lockPath).mtimeMs;
    const young = cli('--break-lock', 'damaged', '--ledger', sys.ledgerPath);
    assert.equal(young.status, 1);
    assert.match(young.stdout, /it is moved aside only when older than 60 s; the lock was not moved/);
    assert.throws(() => breakDamagedLock(sys.ledgerPath, { ...ownedScan, now: () => mtime + 59_000 }), /only when older than 60 s/);
    assertOwnedInspectable();
    const aged = breakDamagedLock(sys.ledgerPath, { ...ownedScan, now: () => mtime + 61_000 });
    assert.deepEqual(readFileSync(aged.movedTo), torn);
    rmSync(aged.movedTo);

    // (c) A lock that parses is never touched by the damaged path.
    const nonce = createHash('sha256').update('or35-parsable').digest('hex').slice(0, 32);
    writeFileSync(lockPath, lockRecord({ pid: deadPid(), nonce }), { flag: 'wx', mode: 0o600 });
    age(lockPath, 120);
    const parsable = statSync(lockPath);
    const parsableBytes = readFileSync(lockPath);
    const notDamaged = cli('--break-lock', 'damaged', '--ledger', sys.ledgerPath);
    assert.equal(notDamaged.status, 1);
    assert.match(notDamaged.stdout, /the ledger lock parses \(pid \d+ on .*\); a lock that parses is broken only with --break-lock <nonce>; the lock was not moved/);
    assert.deepEqual([readFileSync(lockPath), statSync(lockPath).ino], [parsableBytes, parsable.ino], '(c) untouched');
    assert.equal(cli('--break-lock', nonce, '--ledger', sys.ledgerPath).status, 0);

    // (d) /proc, or one of this user's processes, cannot be inspected: refused.
    writeFileSync(lockPath, torn, { flag: 'wx', mode: 0o600 });
    age(lockPath, 120);
    hookFs('readdirSync', (real, path, ...rest) => {
      if (String(path) === '/proc') throw ioError('EACCES', path);
      return real.call(fs, path, ...rest);
    });
    try {
      assert.throws(() => breakDamagedLock(sys.ledgerPath), (error) => error instanceof LedgerError && /\/proc cannot be read/.test(error.message));
    } finally {
      unhookFs();
    }
    hookFs('readdirSync', (real, path, ...rest) => {
      if (String(path) === `/proc/${process.pid}/fd`) throw ioError('EACCES', path);
      return real.call(fs, path, ...rest);
    });
    try {
      assert.throws(
        () => breakDamagedLock(sys.ledgerPath, ownedScan),
        (error) => error instanceof LedgerError && new RegExp(`process\\(es\\) (?:[0-9]+, )*${process.pid}(?:, [0-9]+)* of this user cannot be inspected`).test(error.message),
      );
    } finally {
      unhookFs();
    }
    assert.deepEqual(readFileSync(lockPath), torn, '(d) untouched');

    // (e) The lock is replaced between the check and the move: it is not moved.
    const replacement = Buffer.from('another damaged lock');
    let swapped = false;
    hookFs('readdirSync', (real, path, ...rest) => {
      if (!swapped && String(path) === '/proc') {
        swapped = true;
        rmSync(lockPath);
        writeFileSync(lockPath, replacement, { flag: 'wx', mode: 0o600 });
        age(lockPath, 120);
      }
      return real.call(fs, path, ...rest);
    });
    assertOwnedInspectable();
    try {
      assert.throws(() => breakDamagedLock(sys.ledgerPath, ownedScan), (error) => error instanceof LedgerError && /changed while it was being checked; the lock was not moved/.test(error.message));
    } finally {
      unhookFs();
    }
    assert.ok(swapped);
    assert.deepEqual(readFileSync(lockPath), replacement, '(e) the replacement stays in place');
    assert.equal(ledgerFiles(sys).some((entry) => entry.includes('.damaged-')), false, 'nothing was moved aside');
    rmSync(lockPath);

    // (f) Every session path releases: no lock file remains, and this process
    // holds no descriptor on the lock afterwards.
    const identities = [];
    const capture = () => {
      const stat = statSync(lockPath);
      identities.push({ dev: stat.dev, ino: stat.ino });
    };
    const holdsDescriptor = ({ dev, ino }) =>
      readdirSync('/proc/self/fd').some((fd) => {
        try {
          const stat = statSync(`/proc/self/fd/${fd}`);
          return stat.dev === dev && stat.ino === ino;
        } catch {
          return false;
        }
      });
    const assertReleased = (label) => {
      const identity = identities.at(-1);
      assert.ok(identity !== undefined, `${label}: the session held the lock`);
      assert.equal(holdsDescriptor(identity), false, `${label}: the lock descriptor is closed`);
      assert.equal(existsSync(lockPath), false, `${label}: no lock file remains`);
      identities.length = 0;
    };
    const [tenantA] = sys.tenants;
    const capturing = (digestAt) => (seq) => {
      capture();
      return digestAt(seq);
    };
    // While a session runs, this process holds the descriptor.
    const live = LedgerSession.open(sys.ledgerPath);
    capture();
    assert.equal(holdsDescriptor(identities.at(-1)), true, 'the owner holds the lock descriptor during the session');
    live.release();
    assertReleased('explicit release');
    appendEvents(sys, tenantA, 1);
    recordExportedHead(sys.ledgerPath, tenantA, headOf(sys, tenantA), { clock, source: 'receipt', digestAt: capturing(digestAtOf(sys, tenantA)) });
    assertReleased('success');
    assert.throws(
      () => recordExportedHead(sys.ledgerPath, tenantA, { seq: 99, digest: hex('not-in-chain') }, { clock, source: 'receipt', digestAt: capturing((seq) => (seq === 99 ? hex('not-in-chain') : hex('other'))) }),
      LedgerError,
    );
    assertReleased('refused');
    appendEvents(sys, tenantA, 1);
    assert.throws(
      () => recordExportedHead(sys.ledgerPath, tenantA, headOf(sys, tenantA), { clock, source: 'receipt', digestAt: capturing(digestAtOf(sys, tenantA)), io: failDirFsync(sys.ledgerPath) }),
      LedgerCommitUnsyncedError,
    );
    assertReleased('committed-unsynced (exit 74)');
    appendEvents(sys, tenantA, 1);
    const finalF = join(sys.backups, 'bk-f');
    await assert.rejects(
      backup(sys, 'bk-f', {
        io: {
          rename(from, to) {
            if (to === finalF) {
              capture();
              throw ioError('EXDEV', to);
            }
            renameSync(from, to);
          },
        },
      }),
      isPending,
    );
    assertReleased('committed-pending-publication (exit 75)');
    assert.throws(
      () =>
        withLedgerSession(sys.ledgerPath, { recovery: true }, () => {
          capture();
          throw new Error('synthetic failure inside the session');
        }),
      /synthetic failure inside the session/,
    );
    assertReleased('thrown error');
    const pendingStaging = pendingPublication(sys.ledgerPath).staging;
    completeStaged(pendingStaging, { ledgerPath: sys.ledgerPath, io: { syncDirectory: (path) => (capture(), fsyncDirectory(path)) } });
    assertReleased('recovery');

    // A lock replaced during a session is lost: never unlinked, reported, and the descriptor is closed.
    const lostSession = LedgerSession.open(sys.ledgerPath);
    capture();
    rmSync(lockPath);
    writeFileSync(lockPath, 'a lock that is not this session\'s', { flag: 'wx', mode: 0o600 });
    const warnings = [];
    const onWarning = (warning) => warnings.push(warning);
    process.on('warning', onWarning);
    let status;
    try {
      status = lostSession.release();
      await new Promise((resolveTick) => setImmediate(resolveTick));
    } finally {
      process.off('warning', onWarning);
    }
    assert.equal(status, 'lost');
    assert.equal(readFileSync(lockPath, 'utf8'), "a lock that is not this session's", 'a lock that is not the session\'s is never unlinked');
    assert.equal(holdsDescriptor(identities.at(-1)), false, 'the descriptor is closed');
    assert.ok(warnings.some((warning) => warning.code === 'OPENSIG_LEDGER_LOCK_LOST'), 'the lost lock is reported');
    rmSync(lockPath);
  } finally {
    await idle?.stop();
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-38

test('[OR-38] a lock lost at release reports lock-lost, exit 70, over the outcome\'s own exit code, and the status line still names that outcome and its recovery (T30R3-3)', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const lockPath = `${sys.ledgerPath}.lock`;
    const foreign = "a lock that is not this run's";
    const lostLine = (run, underlying) => {
      assert.equal(run.status, 70, `lock-lost exits 70 (${run.stdout}${run.stderr})`);
      assert.ok(
        run.stdout.startsWith(
          `backup: lock-lost lock=${lockPath}: the exported-head ledger lock was removed or replaced during this run, so another writer may have run at the same time; run verify before trusting the outcome; outcome=${underlying}`,
        ),
        run.stdout,
      );
      assert.equal(readFileSync(lockPath, 'utf8'), foreign, 'the lock path that is not this run\'s is never unlinked');
      rmSync(lockPath);
    };

    // A published backup (exit 0 on its own).
    appendEvents(sys, sys.tenants[0], 1);
    const final = join(sys.backups, 'bk2');
    lostLine(cliFaults('lock-swap', sys.ledgerPath, 'create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', final, '--ledger', sys.ledgerPath), `published directory=${final} tenants=2 blobs=0 schema=`);
    assert.equal(verifyBackup({ backupDir: final, ledgerPath: sys.ledgerPath }).tenants[0].head.seq, 4, 'the outcome itself happened; verify confirms it');

    // A refusal (exit 1 on its own).
    lostLine(cliFaults('lock-swap', sys.ledgerPath, '--resync-ledger', hex('not-the-ledger'), '--ledger', sys.ledgerPath), 'refused recovery_refused: the ledger digest is ');

    // committed-unsynced (exit 74 on its own): the recovery command is still named.
    const tenantB = sys.tenants[1];
    deleteTenant(sys, tenantB);
    const unsynced = cliFaults('ledger-dir-fsync,lock-swap', sys.ledgerPath, '--retire-tenant', tenantB, '--db', sys.path, '--ledger', sys.ledgerPath);
    const unsyncedDigest = sha(sys.ledgerPath);
    lostLine(unsynced, `committed-unsynced ledger=${sys.ledgerPath} previous-digest=`);
    assert.ok(unsynced.stdout.includes(`recover="--resync-ledger ${unsyncedDigest} --ledger ${sys.ledgerPath}"`), unsynced.stdout);
    assert.equal(cli('--resync-ledger', unsyncedDigest, '--ledger', sys.ledgerPath).status, 0);

    // committed-pending-publication (exit 75 on its own): the recovery command is still named.
    appendEvents(sys, sys.tenants[0], 1);
    const pendingFinal = join(sys.backups, 'bk3');
    const pending = cliFaults('ledger-dir-fsync,lock-swap', sys.ledgerPath, 'create', '--db', sys.path, '--blobs', sys.blobRoot, '--out', pendingFinal, '--ledger', sys.ledgerPath);
    lostLine(pending, 'committed-pending-publication directory=');
    const [staged] = stagingDirs(sys);
    assert.ok(pending.stdout.includes(`recover="--complete-staged ${join(sys.backups, staged)}"`), pending.stdout);
    assert.equal(cli('--complete-staged', join(sys.backups, staged), '--ledger', sys.ledgerPath).status, 0);

    // Exit 70 means only lock-lost: the same runs without the fault keep their own status.
    assert.equal(cli('--resync-ledger', hex('not-the-ledger'), '--ledger', sys.ledgerPath).status, 1);
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE]);
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-39

test('[OR-39] a refusal found during a run is refused (exit 1): a database appearing at the restore target, the target blob root or the backup directory changing; exit 2 means usage errors only (T30R3-5)', async () => {
  const sys = system({ tenants: 1, events: 3, blobs: true });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const bk1 = join(sys.backups, 'bk1');

    // A database appears at the restore target during the run.
    const raced = target();
    const run = cliFaults('target-db-appears', sys.ledgerPath, 'restore', '--from', bk1, '--ledger', sys.ledgerPath, '--db', raced.databasePath, '--blobs', raced.blobRoot);
    assert.equal(run.status, 1, `refused, never a usage error (${run.stdout}${run.stderr})`);
    assert.equal(run.stdout, 'backup: refused 1 reason(s): the target database path appeared during the restore; restore never overwrites a database\n');
    assert.equal(run.stderr, '');
    assert.equal(readFileSync(raced.databasePath, 'utf8'), 'a database another process created during the restore', 'it is never overwritten');
    assert.equal(existsSync(raced.blobRoot), false);

    // The target blob root, empty when checked, changes before it is prepared.
    const changed = target();
    hookFs('openSync', (real, path, ...rest) => {
      if (String(path).endsWith('.restoring') && !existsSync(changed.blobRoot)) {
        mkdirSync(changed.blobRoot);
        writeFileSync(join(changed.blobRoot, 'other.txt'), 'written by another process');
      }
      return real.call(fs, path, ...rest);
    });
    let blobRace;
    try {
      blobRace = await settle(Promise.resolve().then(() => restoreBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath, ...changed })));
    } finally {
      unhookFs();
    }
    assert.ok(blobRace.error instanceof RestoreRefusedError && /the target blob root changed during the restore/.test(blobRace.error.message), String(blobRace.error));
    assert.equal(readFileSync(join(changed.blobRoot, 'other.txt'), 'utf8'), 'written by another process', 'nothing this run did not write is removed');
    assert.equal(existsSync(changed.databasePath), false);

    // The backup directory, empty when checked, changes during the backup.
    appendEvents(sys, sys.tenants[0], 1);
    const final = join(sys.backups, 'bk2');
    hookFs('openSync', (real, path, ...rest) => {
      if (String(path).endsWith('manifest.staged.json') && !existsSync(final)) {
        mkdirSync(final);
        writeFileSync(join(final, 'other.txt'), 'written by another process');
      }
      return real.call(fs, path, ...rest);
    });
    let dirRace;
    try {
      dirRace = await settle(backup(sys, 'bk2'));
    } finally {
      unhookFs();
    }
    assert.ok(dirRace.error instanceof BackupError && /the backup directory changed during the backup/.test(dirRace.error.message), String(dirRace.error));
    assert.deepEqual(readdirSync(final), ['other.txt']);
    assert.deepEqual(stagingDirs(sys), []);

    // Exit 2 means only a usage error: a target that exists before the run.
    const existing = cli('restore', '--from', bk1, '--ledger', sys.ledgerPath, '--db', raced.databasePath, '--blobs', join(scratch.dir(), 'blobs'));
    assert.equal(existing.status, 2);
    assert.match(existing.stderr, /^backup: USAGE the target database path already exists/);
  } finally {
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-41

test('[OR-41] a real non-dumpable live writer (an execute-only copy of the pinned node) holds a torn, aged lock: --break-lock damaged refuses, names it as uninspectable and leaves the lock untouched; the writer then completes and releases (T30R3-4)', async (t) => {
  // The premise is the kernel's: a process run from a binary it cannot read
  // is marked non-dumpable, and then a peer of the same user cannot read its
  // /proc/<pid>/fd. Where that cannot be set up the test skips with the
  // reason, so the mode is VACUOUS, never a pass. No host setting is touched.
  if (process.platform !== 'linux') {
    t.skip(`the non-dumpable writer needs Linux /proc; this platform is ${process.platform}`);
    return;
  }
  if (typeof process.getuid !== 'function' || process.getuid() === 0) {
    t.skip('running as root, which can read every process\'s /proc/<pid>/fd, so a writer its peers cannot inspect cannot be set up');
    return;
  }
  const sys = system({ tenants: 1, events: 3 });
  const binDir = scratch.dir('opensig-execute-only-');
  const writerNode = join(binDir, 'node');
  const barrier = scratch.dir('opensig-barrier-');
  let writer;
  let ended;
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const lockPath = `${sys.ledgerPath}.lock`;
    copyFileSync(process.execPath, writerNode);
    chmodSync(writerNode, 0o111);

    // The writer opens its session and holds it, the lock descriptor open, until <barrier>/go.
    writer = spawn(writerNode, [CHILD, 'free', 'hold', JSON.stringify({ ledgerPath: sys.ledgerPath, barrier })], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    writer.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    writer.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    const exit = new Promise((resolveExit) => {
      writer.on('error', (error) => resolveExit({ error }));
      writer.on('close', (code, signal) => resolveExit({ code, signal }));
    });
    exit.then((result) => {
      ended = result;
    });
    for (let i = 0; i < 6000 && ended === undefined && !existsSync(join(barrier, 'ready')); i += 1) await sleep(5);
    if (ended?.error !== undefined) {
      t.skip(`the execute-only copy of node cannot be run here (${ended.error.code ?? ended.error.message}), so the non-dumpable writer cannot be set up`);
      return;
    }
    assert.ok(existsSync(join(barrier, 'ready')), `the writer holds its session (${stdout}${stderr})`);
    const pid = Number(readFileSync(join(barrier, 'ready'), 'utf8'));
    assert.equal(pid, writer.pid);
    assert.equal(readLedgerLock(sys.ledgerPath)?.pid, pid, 'the lock is the writer\'s');
    assert.deepEqual(JSON.parse(readFileSync(join(barrier, 'held.json'), 'utf8')), { pid, ownLockDescriptor: true }, 'the writer itself sees its open descriptor on the lock');
    assert.equal(statSync(`/proc/${pid}`).uid, process.getuid(), 'the writer is a process of this user');

    // The premise: a peer process of this user cannot read the writer's /proc/<pid>/fd.
    const peer = spawnSync(process.execPath, ['-e', `try { require('node:fs').readdirSync('/proc/${pid}/fd'); console.log('readable'); } catch (error) { console.log(error.code); }`], { encoding: 'utf8', timeout: 60_000 });
    if (peer.stdout.trim() === 'readable') {
      t.skip(`a peer process can read /proc/${pid}/fd of the execute-only writer, so this kernel did not make it non-dumpable; the premise cannot be set up`);
      return;
    }
    assert.equal(peer.stdout.trim(), 'EACCES', `a peer cannot read the live writer's /proc/${pid}/fd (${peer.stdout}${peer.stderr})`);

    // The lock is torn in place (the same inode the writer holds) and aged past 60 s.
    const held = statSync(lockPath);
    writeFileSync(lockPath, Buffer.from('{"schema":"opensig.ledger-lock/1","pid":'));
    const aged = new Date(Date.now() - 120_000);
    utimesSync(lockPath, aged, aged);
    const torn = statSync(lockPath);
    assert.deepEqual([torn.dev, torn.ino], [held.dev, held.ino], 'torn in place');
    assert.ok(Date.now() - torn.mtimeMs > 60_000, 'older than 60 s');
    const digest = sha(lockPath);
    const untouched = (what) => {
      const now = statSync(lockPath);
      assert.deepEqual([now.dev, now.ino, sha(lockPath)], [held.dev, held.ino, digest], `${what}: the lock is untouched (same device, inode and digest)`);
      assert.deepEqual(readdirSync(dirname(lockPath)).filter((name) => name.includes('.damaged-')), [], `${what}: nothing was moved aside`);
    };

    // The command line inspects every process of this user. It refuses and
    // names the writer among the uninspectable (other non-dumpable processes
    // of this user, such as ssh-agent, may be named too).
    const refused = cli('--break-lock', 'damaged', '--ledger', sys.ledgerPath);
    assert.equal(refused.status, 1, `refused (${refused.stdout}${refused.stderr})`);
    const named = /^backup: refused ledger_invalid: process\(es\) ([0-9, ]+) of this user cannot be inspected, so it cannot be shown that none holds the damaged lock; the lock was not moved\n$/.exec(refused.stdout);
    assert.ok(named, refused.stdout);
    assert.ok(named[1].split(', ').map(Number).includes(pid), `the writer, pid ${pid}, is named as uninspectable: ${refused.stdout}`);
    untouched('the command line');

    // The library, with the writer as the only candidate process.
    assert.throws(
      () => breakDamagedLock(sys.ledgerPath, { pids: () => [pid] }),
      (error) => error instanceof LedgerError && error.message === `process(es) ${pid} of this user cannot be inspected, so it cannot be shown that none holds the damaged lock; the lock was not moved`,
    );
    untouched('the library');

    // The writer completes: it releases its lock (the path is still its file), never reporting it lost.
    writeFileSync(join(barrier, 'go'), '');
    assert.deepEqual(await exit, { code: 0, signal: null }, stdout + stderr);
    assert.equal(stdout, '{"ok":true}\n');
    assert.doesNotMatch(stderr, /OPENSIG_LEDGER_LOCK_LOST|lost/);
    assert.equal(existsSync(lockPath), false, 'the writer released the lock');
    LedgerSession.open(sys.ledgerPath).release();
  } finally {
    if (writer !== undefined && ended === undefined) {
      writeFileSync(join(barrier, 'go'), '');
      for (let i = 0; i < 2000 && ended === undefined; i += 1) await sleep(5);
      if (ended === undefined) writer.kill('SIGKILL');
    }
    rmSync(binDir, { recursive: true, force: true });
    sys.db.close();
  }
});

// ------------------------------------------------------------------- OR-42

test('[OR-42] verify and restore read retired tenants\' retained heads: a backup containing a retired tenant is refused (exit 1) after the head check, as older, divergent or a reintroduction; a backup without it restores (A-010 Codex [18])', async () => {
  const sys = system({ tenants: 2, events: 1 });
  try {
    const [tenant, other] = sys.tenants;
    const bk1 = join(sys.backups, 'bk1');
    const bk2 = join(sys.backups, 'bk2');
    const fork = join(sys.backups, 'fork');

    // Codex's reproduction: a seq-1 backup is refused once seq 2 is exported.
    await backup(sys, 'bk1', { firstBackup: true });
    appendEvents(sys, tenant, 1);
    await backup(sys, 'bk2');
    const exported = readLedger(sys.ledgerPath)[tenant];
    assert.equal(exported.seq, 2);
    assert.throws(
      () => verifyBackup({ backupDir: bk1, ledgerPath: sys.ledgerPath }),
      (error) => error instanceof RestoreRefusedError && error.reasons.join() === `tenant ${tenant}: audit chain head is older than the last exported head (seq 2)`,
    );

    // A backup whose chain forks from the exported one at seq 2, made against a separate ledger.
    const raw = rawConnection(sys.path);
    try {
      const trigger = raw.prepare("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'audit_events_append_only_delete'").get().sql;
      raw.exec('DROP TRIGGER audit_events_append_only_delete');
      raw.prepare('DELETE FROM audit_events WHERE tenant_id = ? AND seq > 1').run(tenant);
      raw.exec(trigger);
    } finally {
      raw.close();
    }
    appendEvents(sys, tenant, 1);
    const forked = headOf(sys, tenant);
    assert.equal(forked.seq, 2);
    assert.notEqual(forked.digest, exported.digest);
    await createBackup({ databasePath: sys.path, blobRoot: sys.blobRoot, outDir: fork, ledgerPath: join(scratch.dir(), LEDGER_FILE), clock, firstBackup: true });

    // The tenant leaves the system and is retired at its last exported head.
    deleteTenant(sys, tenant);
    const retire = cli('--retire-tenant', tenant, '--db', sys.path, '--ledger', sys.ledgerPath);
    assert.equal(retire.status, 0, retire.stdout + retire.stderr);
    const retained = readLedgerDocument(sys.ledgerPath).retired[tenant];
    assert.deepEqual([retained?.seq, retained?.digest], [2, exported.digest]);
    assert.equal(readLedger(sys.ledgerPath)[tenant], undefined, 'the active heads no longer list it');

    // Every backup that contains the retired tenant stays refused, through the
    // library and the command line, and nothing is restored.
    const never = 'a backup that contains a retired tenant is never restored or verified';
    const cases = [
      [bk1, `tenant ${tenant}: the tenant is retired; the backup's audit chain head is older than its retained head (seq 2); ${never}`],
      [fork, `tenant ${tenant}: the tenant is retired; the backup's audit chain diverges from its retained head at seq 2; ${never}`],
      [bk2, `tenant ${tenant}: the tenant is retired; restoring this backup would reintroduce it at its retained head (seq 2); ${never}`],
    ];
    const ledgerBefore = sha(sys.ledgerPath);
    for (const [dir, reason] of cases) {
      const label = basename(dir);
      const refusedWithReason = (error) => error instanceof RestoreRefusedError && error.reasons.length === 1 && error.reasons[0] === reason;
      assert.throws(() => verifyBackup({ backupDir: dir, ledgerPath: sys.ledgerPath }), refusedWithReason, `${label}: verify`);
      const into = target();
      assert.throws(() => restoreBackup({ backupDir: dir, ledgerPath: sys.ledgerPath, ...into }), refusedWithReason, `${label}: restore`);
      assert.deepEqual(readdirSync(dirname(into.databasePath)), [], `${label}: nothing restored`);
      const verified = cli('verify', '--from', dir, '--ledger', sys.ledgerPath);
      assert.deepEqual([verified.status, verified.stdout, verified.stderr], [1, `backup: refused 1 reason(s): ${reason}\n`, ''], `${label}: verify, command line`);
      const viaCli = target();
      const restored = cli('restore', '--from', dir, '--ledger', sys.ledgerPath, '--db', viaCli.databasePath, '--blobs', viaCli.blobRoot);
      assert.deepEqual([restored.status, restored.stdout, restored.stderr], [1, `backup: refused 1 reason(s): ${reason}\n`, ''], `${label}: restore, command line`);
      assert.deepEqual(readdirSync(dirname(viaCli.databasePath)), [], `${label}: nothing restored by the command line`);
    }
    assert.equal(sha(sys.ledgerPath), ledgerBefore, 'verify and restore never write the ledger');
    assert.ok(Object.hasOwn(readLedgerDocument(sys.ledgerPath).retired, tenant), 'there is no un-retire');

    // A backup without the retired tenant verifies and restores.
    await backup(sys, 'bk3');
    const bk3 = join(sys.backups, 'bk3');
    assert.deepEqual(verifyBackup({ backupDir: bk3, ledgerPath: sys.ledgerPath }).tenants.map((entry) => entry.tenant_id), [other]);
    const into = target();
    assert.deepEqual(restoreBackup({ backupDir: bk3, ledgerPath: sys.ledgerPath, ...into }).tenants.map((entry) => entry.tenant_id), [other]);
    assert.ok(existsSync(into.databasePath));
  } finally {
    sys.db.close();
  }
});
