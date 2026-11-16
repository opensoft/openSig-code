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
// OR-27 the blob size limit is carried through backup, verify and restore.
// All data is synthetic. The backup module is imported as a namespace so that
// every test reports its own failure against an older API.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs, {
  closeSync,
  constants as fsConstants,
  cpSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { hostname } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { after, mock, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalize } from '../../src/domain/canonical/index.ts';
import { verifyChain } from '../../src/storage/audit/index.ts';
import * as backupApi from '../../src/storage/backup/index.ts';
import * as blobsApi from '../../src/storage/blobs/index.ts';
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
const { BlobDisposer, RetentionService } = retentionApi;

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..', '..');
const SCRIPT = join(REPO_ROOT, 'scripts', 'backup.mjs');
const CHILD = join(HERE, 'support', 'ledger-child.mjs');
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
    assert.deepEqual(readdirSync(staging).sort(), ['blobs', 'manifest.json', 'opensig.db']);
    assert.notEqual(sha(sys.ledgerPath), before, 'the ledger is committed (post-commit)');
    assert.deepEqual(seqs(sys), [5, 7], 'every tenant is ahead, in the one replace');
    const manifest = JSON.parse(readFileSync(join(staging, 'manifest.json'), 'utf8'));
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
    const discarded = cli('--discard-staged', copy, '--ledger', sys.ledgerPath);
    assert.equal(discarded.status, 0, discarded.stdout + discarded.stderr);
    assert.equal(discarded.stdout, `backup: discarded directory=${copy}\n`);
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
    assert.deepEqual(discardStaged(join(sys.backups, crashed), { ledgerPath: sys.ledgerPath }), { status: 'discarded', directory: join(sys.backups, crashed) });
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
    const abandoned = cli('--discard-staged', pending, '--ledger', sys.ledgerPath, '--abandon-committed', digest);
    assert.equal(abandoned.status, 0, abandoned.stdout + abandoned.stderr);
    assert.equal(abandoned.stdout, `backup: abandoned-committed directory=${pending}\n`);
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

    // Abandoned by its staging name while it lives under the final name: it is deleted wherever it is.
    appendEvents(sys, sys.tenants[0], 1);
    const final4 = join(sys.backups, 'bk4');
    renamed = false;
    const failParent4 = { ...failParent, rename(from, to) { renamed ||= to === final4; renameSync(from, to); } };
    const kept4 = await settle(backup(sys, 'bk4', { io: failParent4 }));
    assert.equal(kept4.error.directory, final4);
    const record = pendingPublication(sys.ledgerPath);
    assert.notEqual(record.staging, final4);
    assert.equal(discardStaged(record.staging, { ledgerPath: sys.ledgerPath, abandonCommitted: sha(sys.ledgerPath) }).status, 'abandoned-committed');
    assert.equal(existsSync(final4), false, 'the abandoned backup is gone under either name');
    assert.deepEqual(ledgerFiles(sys), [LEDGER_FILE]);
    assert.deepEqual(seqs(sys), [7, 6], 'the ledger stays as committed');
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
      store.compareAndSet('envelopes', { id: envelope }, 1, { state: 'completed', base_revision_id: revision, manifest_digest: hex(`m-${envelope}`), recipients_digest: hex(`r-${envelope}`), approvals_complete: 1, updated_at: ts(10) });
      store.insert('signing_jobs', { envelope_id: envelope, reserved_version: 2, status: 'succeeded', attempt_count: 2, max_attempts: 3, fencing_token: 2, created_at: ts(4), updated_at: ts(5) });
      store.insert('final_artifacts', { artifact_id: sid('art'), envelope_id: envelope, artifact_digest: reused.digest, approved_composition_digest: hex(`c-${envelope}`), pdf_blob_ref: reused.ref, evidence_blob_ref: evidence.ref, signer_certificate_sha256: hex('certificate'), development_certificate: 1, verifier_name: 'opensig-verifier', verifier_version: '0.0.0', verification_json: '{"integrity":"valid"}', fencing_token: 2, completed_at: ts(5) });
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

test('[OR-26] an injected post-commit I/O failure (ledger-directory fsync, staging rename, parent fsync) keeps the staged backup and reports exit 75; nothing changes until it is completed', async () => {
  const sys = system({ tenants: 2, events: 3 });
  try {
    await backup(sys, 'bk1', { firstBackup: true });
    const bk1 = join(sys.backups, 'bk1');

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
    assert.deepEqual(readdirSync(unsynced.error.directory).sort(), ['blobs', 'manifest.json', 'opensig.db']);
    assert.equal(unsynced.error.ledgerDigest, sha(sys.ledgerPath));
    assert.deepEqual(seqs(sys), [4, 3], 'the ledger is committed');
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
        detail: /renaming the staging directory to its final name failed/,
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
        detail: /the parent directory fsync failed after the rename/,
      },
    ];
    let index = 3;
    for (const { label, io, kept, detail } of cases) {
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
      assert.deepEqual(readdirSync(failed.error.directory).sort(), ['blobs', 'manifest.json', 'opensig.db']);
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

      if (label === 'staging rename') {
        // A repeated I/O failure during recovery is pending again.
        assert.throws(() => completeStaged(failed.error.directory, { ledgerPath: sys.ledgerPath, io: io(final) }), isPending);
        assert.deepEqual(state(sys), frozen);
      }
      const completed = cli('--complete-staged', failed.error.directory, '--ledger', sys.ledgerPath);
      assert.equal(completed.status, 0, completed.stdout + completed.stderr);
      assert.equal(completed.stdout, `backup: published directory=${final}\n`);
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
