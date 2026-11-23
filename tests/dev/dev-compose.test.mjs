// SPDX-License-Identifier: Apache-2.0
//
// T004 DV-04 (A-010 row DEV-COMPOSE, request #30): the dev launcher provides what the composed
// server requires (the T004 line; data-model.md § Keys and secrets).
// - Unless OPENSIG_CHALLENGE_KEY_FILE is set, a per-run key of 32 random bytes in a fresh mkdtemp
//   directory outside the tree (directory 0700, file 0600), passed by path, and the directory
//   removed when the launcher exits, however the server ended.
// - The database at OPENSIG_DATABASE (default var/data/opensig.db) created and migrated through
//   the storage layer's migration API when absent or behind, left alone when current, refused
//   (and left unchanged) when it cannot be opened or migrated.
// The in-process cases (prepareDatabase and createRunKey) are in dev-compose-units.test.mjs.
// The first case starts the real composed src/server/main.ts through the launcher and sees its
// `listening` line. It runs in a temporary layout that links the real src/, so the spool, the
// data directory and the database live in that layout, never in the repository; the launcher's
// TMPDIR is a scratch directory too, so its per-run key directory can be watched and is never
// left on the host. Other subprocess cases use a stand-in entrypoint that reports what the
// launcher handed it (it stands in for T031's server, not for the launcher under test). Every
// key and database is synthetic and created at run time; no key byte is printed or asserted on.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { loadMigrations } from '../../src/storage/schema/migrations.ts';

const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const DEV = join(REPO, 'scripts', 'dev.mjs');
const EXPECTED_VERSION = loadMigrations().length;
// The launcher's per-run key, as the T004 line and scripts/dev.mjs state it. Restated here so these
// subprocess cases depend on the launcher's behaviour only, not on its exports.
const CHALLENGE_KEY_BYTES = 32;
const KEY_DIR_PREFIX = 'opensig-dev-key-';
const KEY_FILE_NAME = 'challenge-hmac.key';
/**
 * The bound for the composed server's `listening` line. Startup settles T033's sandbox plan
 * first, and its probe may take up to 10 s for each of its two launcher kinds; three times that
 * worst case leaves room for a loaded host. A server that never listens fails here, never hangs.
 */
const LISTENING_BOUND_MS = 60_000;
/** The bound for the launcher to exit after SIGTERM (the server's shutdown has no work to drain). */
const EXIT_BOUND_MS = 30_000;
const temps = [];

after(() => {
  for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

function scratch(label) {
  const dir = mkdtempSync(join(tmpdir(), `opensig-dv04-${label}-`));
  temps.push(dir);
  return dir;
}

function inside(parent, child) {
  const path = relative(realpathSync(parent), realpathSync(child));
  return path === '' || (!path.startsWith('..') && !isAbsolute(path));
}

/** The per-run key directories the launcher left in `tmp`. */
function keyDirs(tmp) {
  return readdirSync(tmp).filter((name) => name.startsWith(KEY_DIR_PREFIX));
}

/** The schema version and applied rows of the database at `path`, read through a read-only connection. */
function schemaOf(path) {
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    const version = Number(raw.prepare('PRAGMA user_version').get().user_version);
    const rows = raw.prepare('SELECT version, name, sha256, applied_at FROM schema_migrations ORDER BY version').all().map((row) => ({ ...row }));
    return { version, rows };
  } finally {
    raw.close();
  }
}

/** A temporary layout that links the real src/: the launcher starts the real composed server. */
function composedLayout() {
  const root = scratch('layout');
  mkdirSync(join(root, 'scripts'));
  copyFileSync(DEV, join(root, 'scripts', 'dev.mjs'));
  copyFileSync(join(REPO, '.node-version'), join(root, '.node-version'));
  copyFileSync(join(REPO, 'package.json'), join(root, 'package.json'));
  symlinkSync(join(REPO, 'src'), join(root, 'src'), 'dir');
  return root;
}

// Reports what the launcher handed it, then exits with OPENSIG_STANDIN_EXIT (default 0).
const REPORT_SERVER = `import { statSync } from 'node:fs';
const keyFile = process.env.OPENSIG_CHALLENGE_KEY_FILE ?? null;
let key = null;
if (keyFile !== null) {
  const stat = statSync(keyFile);
  key = { file: stat.isFile(), mode: stat.mode & 0o777, size: stat.size };
}
process.stdout.write('SERVER ' + JSON.stringify({ keyFile, key, database: process.env.OPENSIG_DATABASE ?? null }) + '\\n');
process.exit(Number(process.env.OPENSIG_STANDIN_EXIT ?? '0'));
`;

/** A temporary layout with a stand-in entrypoint and the real storage layer. */
function standInLayout(serverSource = REPORT_SERVER) {
  const root = scratch('standin');
  mkdirSync(join(root, 'scripts'));
  copyFileSync(DEV, join(root, 'scripts', 'dev.mjs'));
  copyFileSync(join(REPO, '.node-version'), join(root, '.node-version'));
  writeFileSync(join(root, 'package.json'), '{ "private": true, "type": "module" }\n');
  mkdirSync(join(root, 'src', 'server'), { recursive: true });
  writeFileSync(join(root, 'src', 'server', 'main.ts'), serverSource);
  symlinkSync(join(REPO, 'src', 'storage'), join(root, 'src', 'storage'), 'dir');
  return root;
}

function launcherEnv(tmp, extra = {}) {
  return { PATH: process.env.PATH ?? '', HOME: tmp, LANG: 'C', TMPDIR: tmp, ...extra };
}

function runDev(root, tmp, extra = {}) {
  return spawnSync(process.execPath, [join(root, 'scripts', 'dev.mjs'), '--port', '0'], { cwd: root, encoding: 'utf8', env: launcherEnv(tmp, extra), timeout: 30_000 });
}

/** The launcher's own lines (a stand-in's report is not the launcher's output). */
function launcherLines(run) {
  return (run.stdout + run.stderr)
    .split('\n')
    .filter((line) => line.startsWith('dev: '))
    .join('\n');
}

function report(run) {
  const line = run.stdout.split('\n').find((candidate) => candidate.startsWith('SERVER '));
  assert.ok(line, `the stand-in reported (status ${run.status}; stderr: ${run.stderr})`);
  return JSON.parse(line.slice('SERVER '.length));
}

/** Resolve with the first stdout line matching `predicate`; reject when the launcher exits first or after `boundMs`. */
function lineFrom(child, output, predicate, boundMs, label) {
  return new Promise((resolveLine, reject) => {
    let timer;
    const check = () => {
      const line = output.stdout.split('\n').find(predicate);
      if (line === undefined) return;
      finish();
      resolveLine(line);
    };
    const exited = (code, signal) => {
      finish();
      reject(new Error(`${label}: the launcher exited (${code ?? signal}) first; stderr: ${output.stderr}`));
    };
    const finish = () => {
      clearTimeout(timer);
      child.stdout.off('data', check);
      child.off('exit', exited);
    };
    timer = setTimeout(() => {
      finish();
      reject(new Error(`${label}: not seen within ${boundMs} ms; stderr: ${output.stderr}`));
    }, boundMs);
    child.stdout.on('data', check);
    child.once('exit', exited);
    check();
  });
}

function bounded(promise, boundMs, label) {
  let timer;
  return Promise.race([
    promise.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label}: not within ${boundMs} ms`)), boundMs);
    }),
  ]);
}

function get(port, path) {
  return new Promise((resolveResponse, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method: 'GET', agent: false }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolveResponse({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('[DV-04] the launcher starts the real composed src/server/main.ts, which logs its listening line, with a per-run key outside the tree and a database it created and migrated; the key directory is removed when it exits', async () => {
  const root = composedLayout();
  const tmp = scratch('tmp');
  assert.equal(inside(root, tmp), false, 'premise: the launcher TMPDIR lies outside the layout');
  const database = join(root, 'var', 'data', 'opensig.db');
  assert.equal(existsSync(database), false, 'premise: no database yet');
  // Its own process group (the launcher's recorded PID leads it, and the server joins it), so a
  // failed run can stop both; a clean run never needs that.
  const child = spawn(process.execPath, [join(root, 'scripts', 'dev.mjs'), '--port', '0'], { cwd: root, env: launcherEnv(tmp), stdio: ['ignore', 'pipe', 'pipe'], detached: true });
  let stopped = false;
  const output = { stdout: '', stderr: '' };
  child.stdout.setEncoding('utf8').on('data', (chunk) => (output.stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk) => (output.stderr += chunk));
  const exited = new Promise((resolveExit) => child.on('exit', (code, signal) => resolveExit({ code, signal })));
  try {
    const line = await lineFrom(child, output, (candidate) => candidate.includes('"event":"listening"'), LISTENING_BOUND_MS, 'the listening line');
    const listening = JSON.parse(line);
    assert.equal(listening.host, '127.0.0.1', 'the composed server listens on loopback');
    assert.ok(Number.isInteger(listening.port) && listening.port > 0, 'on an OS-chosen port');
    assert.match(output.stdout, new RegExp(`^dev: database created at schema version ${EXPECTED_VERSION}$`, 'm'));
    assert.match(output.stdout, /^dev: challenge key generated for this run \(32 bytes, mode 0600, outside the tree; removed at exit\)$/m);

    // The per-run key, while the server runs: one fresh directory under TMPDIR, outside the tree.
    const dirs = keyDirs(tmp);
    assert.equal(dirs.length, 1, `one per-run key directory in the launcher's TMPDIR (found ${dirs.length})`);
    const keyDir = join(tmp, dirs[0]);
    assert.equal(inside(root, keyDir), false, 'the key directory is outside the tree');
    assert.equal(statSync(keyDir).mode & 0o777, 0o700, 'the key directory is 0700');
    assert.deepEqual(readdirSync(keyDir), [KEY_FILE_NAME], 'it holds the key file only');
    const keyStat = statSync(join(keyDir, KEY_FILE_NAME));
    assert.ok(keyStat.isFile(), 'the key is a regular file');
    assert.equal(keyStat.mode & 0o777, 0o600, 'the key file is 0600');
    assert.equal(keyStat.size, CHALLENGE_KEY_BYTES, 'the key is 32 bytes');
    if (typeof process.getuid === 'function') assert.equal(keyStat.uid, process.getuid(), 'owned by the server user');
    const keyBytes = readFileSync(join(keyDir, KEY_FILE_NAME));
    const printed = output.stdout + output.stderr;
    const leaked = [keyBytes.toString('hex'), keyBytes.toString('base64'), keyBytes.toString('base64url')].some((form) => printed.includes(form));
    keyBytes.fill(0);
    assert.equal(leaked, false, 'no form of the key bytes is printed');

    // The database the launcher created and migrated through the storage layer.
    assert.equal(statSync(database).mode & 0o777, 0o600, 'the database file is 0600');
    const schema = schemaOf(database);
    assert.equal(schema.version, EXPECTED_VERSION, 'the database is at the code\'s schema version');
    assert.deepEqual(
      schema.rows.map((row) => row.name),
      loadMigrations().map((migration) => migration.name),
      'every migration of the code is applied, in order',
    );

    // The composed server serves: a recipient read without a session is its 401.
    const answer = await get(listening.port, '/v1/recipient-session');
    assert.equal(answer.status, 401, `the composed server answers (got ${answer.status} ${answer.text})`);

    child.kill('SIGTERM');
    const { code, signal } = await bounded(exited, EXIT_BOUND_MS, 'the launcher exit after SIGTERM');
    // The launcher exits only after the server did, so a 0 here means both are gone.
    stopped = code === 0 && signal === null;
    assert.deepEqual([code, signal], [0, null], `SIGTERM is forwarded and the server's status returned (stderr: ${output.stderr})`);
    assert.match(output.stdout, /"event":"closed"/, 'the server shut down in order');
    assert.equal(existsSync(keyDir), false, 'the per-run key directory is removed when the launcher exits');
    assert.deepEqual(keyDirs(tmp), [], 'no key directory is left behind');
    assert.equal(schemaOf(database).version, EXPECTED_VERSION, 'the development database persists');
  } finally {
    if (!stopped) {
      try {
        process.kill(-child.pid, 'SIGKILL');
      } catch {
        // The group is already gone.
      }
    }
  }
});

test('[DV-04] a configured OPENSIG_CHALLENGE_KEY_FILE is passed through unchanged and no key is generated; a generated key is removed even when the server fails', () => {
  const root = standInLayout();
  const tmp = scratch('tmp');
  const configured = join(scratch('ownkey'), 'challenge-hmac.key');
  writeFileSync(configured, randomBytes(32), { mode: 0o600 });

  const passed = runDev(root, tmp, { OPENSIG_CHALLENGE_KEY_FILE: configured });
  assert.equal(passed.status, 0, passed.stderr);
  const given = report(passed);
  assert.equal(given.keyFile, configured, 'the configured key file reaches the server unchanged');
  assert.equal(given.database, join(root, 'var', 'data', 'opensig.db'), 'the server gets the prepared database');
  assert.match(passed.stdout, /^dev: challenge key from OPENSIG_CHALLENGE_KEY_FILE$/m);
  assert.deepEqual(keyDirs(tmp), [], 'no key is generated');
  assert.equal(existsSync(configured), true, 'the configured key file is never removed');
  assert.equal(launcherLines(passed).includes(configured), false, 'the launcher does not print its path');

  // No key configured, and the server fails at once: the run's key existed for it and is gone.
  const failed = runDev(root, tmp, { OPENSIG_STANDIN_EXIT: '7' });
  assert.equal(failed.status, 7, `the server's status is returned (stderr: ${failed.stderr})`);
  const generated = report(failed);
  assert.ok(generated.keyFile !== null && generated.keyFile.startsWith(join(tmp, KEY_DIR_PREFIX)), 'the server got a per-run key under TMPDIR');
  assert.deepEqual(generated.key, { file: true, mode: 0o600, size: CHALLENGE_KEY_BYTES }, 'a 32-byte 0600 regular file');
  assert.equal(existsSync(generated.keyFile), false, 'removed when the launcher exits');
  assert.deepEqual(keyDirs(tmp), []);
});

test('[DV-04] a database it cannot migrate, a relative setting, or a temporary directory inside the tree is refused by name before anything starts, and leaves no key behind', () => {
  const marker = `import { writeFileSync } from 'node:fs';
writeFileSync(new URL('../../server-started.marker', import.meta.url), 'started\\n');
`;
  const root = standInLayout(marker);
  const tmp = scratch('tmp');
  const started = join(root, 'server-started.marker');
  const garbage = join(scratch('garbage'), 'opensig.db');
  writeFileSync(garbage, randomBytes(4096), { mode: 0o600 });
  const garbageBytes = readFileSync(garbage);
  const inTree = join(root, 'tmp');
  mkdirSync(inTree);

  const cases = [
    ['a database that cannot be opened', { OPENSIG_DATABASE: garbage }, /^dev: refused: the database at OPENSIG_DATABASE cannot be opened: /m],
    ['a relative OPENSIG_DATABASE', { OPENSIG_DATABASE: 'var/data/other.db' }, /^dev: refused: OPENSIG_DATABASE must be an absolute path$/m],
    ['a relative OPENSIG_CHALLENGE_KEY_FILE', { OPENSIG_CHALLENGE_KEY_FILE: 'keys/challenge.key' }, /^dev: refused: OPENSIG_CHALLENGE_KEY_FILE must be an absolute path$/m],
    ['TMPDIR inside the tree', { TMPDIR: inTree }, /^dev: refused: the temporary directory \(TMPDIR\) is inside the repository/m],
  ];
  for (const [label, extra, pattern] of cases) {
    const run = runDev(root, tmp, extra);
    assert.equal(run.status, 1, `${label}: exit 1 (stderr: ${run.stderr})`);
    assert.match(run.stderr, pattern, `${label}: refused by name`);
    assert.equal(existsSync(started), false, `${label}: nothing started`);
    assert.deepEqual(keyDirs(tmp), [], `${label}: no key left in TMPDIR`);
    for (const value of Object.values(extra)) assert.equal(launcherLines(run).includes(value), false, `${label}: the value is never printed`);
  }
  assert.ok(readFileSync(garbage).equals(garbageBytes), 'the database it could not migrate is unchanged');
  assert.deepEqual(readdirSync(inTree), [], 'no key directory was left inside the tree');
});
