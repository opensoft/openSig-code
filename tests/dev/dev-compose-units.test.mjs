// SPDX-License-Identifier: Apache-2.0
//
// T004 DV-04 (A-010 row DEV-COMPOSE, request #30), the launcher's provisioning functions in
// process; the subprocess cases are in dev-compose.test.mjs.
// - prepareDatabase creates and migrates the database through the storage layer's migration API
//   when it is absent or behind, leaves a current one alone, and refuses, leaving it unchanged, one
//   it cannot open or migrate; the refusal names OPENSIG_DATABASE, never the path.
// - createRunKey makes the run's 32-byte key in a fresh 0700 mkdtemp directory outside the tree,
//   file 0600, refuses a temporary directory inside the tree, and removes the directory on request.
// Every key and database is synthetic, created at run time in mkdtemp directories; no key byte is
// printed or asserted on.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { CHALLENGE_KEY_BYTES, createRunKey, KEY_DIR_PREFIX, KEY_FILE_NAME, LauncherRefusal, prepareDatabase, resolveDevConfig } from '../../scripts/dev.mjs';
import { openDatabase } from '../../src/storage/db/index.ts';
import { loadMigrations } from '../../src/storage/schema/migrations.ts';

const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const EXPECTED_VERSION = loadMigrations().length;
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

/** A database at `path` migrated through the storage layer to `version` (a prefix of the code's migrations). */
function migratedTo(path, version) {
  const db = openDatabase({ path });
  try {
    db.migrate(loadMigrations().slice(0, version));
  } finally {
    db.close();
  }
}

test('[DV-04] the database is created and migrated through the storage layer when absent or behind, left alone when current, and refused, unchanged, when it cannot be opened or migrated', async () => {
  const dir = scratch('db');
  const configFor = (path) => {
    const resolved = resolveDevConfig({ root: REPO, env: { OPENSIG_DATABASE: path } });
    assert.equal(resolved.ok, true, JSON.stringify(resolved.problems));
    assert.equal(resolved.config.database, path, 'OPENSIG_DATABASE names the database');
    return resolved.config;
  };
  assert.equal(resolveDevConfig({ root: REPO, env: {} }).config.database, join(REPO, 'var', 'data', 'opensig.db'), 'the default is var/data/opensig.db');

  // Absent: created (0600) and migrated to the code's version.
  const absent = join(dir, 'absent.db');
  assert.deepEqual(await prepareDatabase(configFor(absent)), { created: true, from: 0, to: EXPECTED_VERSION });
  assert.equal(statSync(absent).mode & 0o777, 0o600);
  assert.equal(schemaOf(absent).version, EXPECTED_VERSION);

  // Current: left alone (no migration recorded again).
  const before = schemaOf(absent);
  assert.deepEqual(await prepareDatabase(configFor(absent)), { created: false, from: EXPECTED_VERSION, to: EXPECTED_VERSION });
  assert.deepEqual(schemaOf(absent), before, 'a current database is left as it is');

  // Behind: migrated from where it is.
  const behindVersion = Math.max(1, EXPECTED_VERSION - 3);
  assert.ok(behindVersion < EXPECTED_VERSION, 'premise: the code has migrations beyond the behind version');
  const behind = join(dir, 'behind.db');
  migratedTo(behind, behindVersion);
  const kept = schemaOf(behind).rows;
  assert.deepEqual(await prepareDatabase(configFor(behind)), { created: false, from: behindVersion, to: EXPECTED_VERSION });
  const after = schemaOf(behind);
  assert.equal(after.version, EXPECTED_VERSION);
  assert.deepEqual(after.rows.slice(0, behindVersion), kept, 'the migrations already applied are kept as they were');

  // Refused, and left unchanged: an applied migration that differs from the code, a schema newer
  // than the code, a file that is not a database, and a group-readable database file.
  const tampered = join(dir, 'tampered.db');
  migratedTo(tampered, EXPECTED_VERSION);
  const rawTamper = new DatabaseSync(tampered);
  rawTamper.prepare('UPDATE schema_migrations SET sha256 = ? WHERE version = 1').run('0'.repeat(64));
  rawTamper.close();
  const ahead = join(dir, 'ahead.db');
  migratedTo(ahead, EXPECTED_VERSION);
  const rawAhead = new DatabaseSync(ahead);
  rawAhead.prepare('INSERT INTO schema_migrations (version, name, sha256, applied_at) VALUES (?, ?, ?, ?)').run(EXPECTED_VERSION + 1, `${String(EXPECTED_VERSION + 1).padStart(4, '0')}-synthetic-ahead.sql`, 'a'.repeat(64), new Date(0).toISOString());
  rawAhead.exec(`PRAGMA user_version = ${EXPECTED_VERSION + 1}`);
  rawAhead.close();
  const garbage = join(dir, 'garbage.db');
  writeFileSync(garbage, randomBytes(4096), { mode: 0o600 });
  const loose = join(dir, 'loose.db');
  migratedTo(loose, EXPECTED_VERSION);
  chmodSync(loose, 0o640);

  const refusals = [
    ['an applied migration that differs from the code', tampered, /^the database at OPENSIG_DATABASE cannot be migrated: applied migration 1 .*differs from the code/],
    ['a schema newer than the code', ahead, /^the database at OPENSIG_DATABASE cannot be migrated: .*newer than this code's migrations/],
    ['a file that is not a database', garbage, /^the database at OPENSIG_DATABASE cannot be opened: /],
    ['a group-readable database file', loose, /^the database at OPENSIG_DATABASE cannot be opened: .*group- or other-accessible/],
  ];
  for (const [label, path, pattern] of refusals) {
    const bytes = readFileSync(path);
    const mode = statSync(path).mode & 0o777;
    await assert.rejects(prepareDatabase(configFor(path)), (error) => error instanceof LauncherRefusal && pattern.test(error.message) && !error.message.includes(dir), `${label}: refused, naming the setting and never the path`);
    assert.ok(readFileSync(path).equals(bytes), `${label}: the file is unchanged`);
    assert.equal(statSync(path).mode & 0o777, mode, `${label}: its mode is unchanged`);
  }
});

test('[DV-04] the per-run key is 32 random bytes in a fresh 0700 directory outside the tree, file 0600, never inside the repository, and removed on request', () => {
  const root = scratch('keyroot');
  const base = scratch('keybase');
  const first = createRunKey(root, base);
  const second = createRunKey(root, base);
  try {
    for (const key of [first, second]) {
      assert.equal(inside(root, key.dir), false, 'outside the tree');
      assert.ok(key.dir.startsWith(join(base, KEY_DIR_PREFIX)), 'a mkdtemp directory in the temporary directory');
      assert.equal(statSync(key.dir).mode & 0o777, 0o700);
      assert.equal(key.path, join(key.dir, KEY_FILE_NAME));
      assert.equal(statSync(key.path).mode & 0o777, 0o600);
      assert.equal(statSync(key.path).size, CHALLENGE_KEY_BYTES);
    }
    assert.notEqual(first.dir, second.dir, 'a fresh directory per run');
    const a = readFileSync(first.path);
    const b = readFileSync(second.path);
    const same = a.equals(b);
    a.fill(0);
    b.fill(0);
    assert.equal(same, false, 'fresh random bytes per run');
  } finally {
    first.remove();
    second.remove();
  }
  assert.equal(existsSync(first.dir), false, 'remove() deletes the directory');
  first.remove();

  // A temporary directory inside the tree is refused, and nothing is left there.
  const inTree = join(root, 'tmp');
  mkdirSync(inTree);
  assert.throws(() => createRunKey(root, inTree), (error) => error instanceof LauncherRefusal && /inside the repository/.test(error.message));
  assert.deepEqual(readdirSync(inTree), [], 'no key directory is left inside the tree');
});
