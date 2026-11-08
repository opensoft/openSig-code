// SPDX-License-Identifier: Apache-2.0
//
// Versioned, append-only migrations (T003). PINNED_MIGRATIONS embeds the
// SHA-256 of every migration file T003 created. Later tasks may only append
// new numbered files; editing, renaming or removing a pinned file fails here.

import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';

import { MigrationError } from '../../src/storage/db/index.ts';
import { loadMigrations, sha256Hex, validateMigrationSet } from '../../src/storage/schema/migrations.ts';
import { makeScratch, openTemp } from './support/fixtures.mjs';

const PINNED_MIGRATIONS = Object.freeze([
  { version: 1, name: '0001-tenants-consent.sql', sha256: '400f99b8a9b57766c0bade2f844bcf8284d61a25b0be299b6ee0793f53399638' },
  { version: 2, name: '0002-envelopes.sql', sha256: '5a653271c4c8bf2ed0b0ccc9129512583f0cf05e67f15cdbb1f252125da01e3e' },
  { version: 3, name: '0003-recipient-ceremony.sql', sha256: '63c4c04bd9d198200caa55d4fbd9ccb4c405cd1c4877f201dd11eba70ad906c0' },
  { version: 4, name: '0004-idempotency-jobs.sql', sha256: '5cfd7d2627c22fbbb1e0bfde31705f9d41356fe3dd1f19266e3a6de9b0e8c986' },
  { version: 5, name: '0005-artifacts.sql', sha256: '79153c45dc4d16dfa6de4c87f1fe5b7c4742b868a21404cd119282d74d88329d' },
  { version: 6, name: '0006-audit-retention.sql', sha256: '1f7ad14b709cb88be3db0616d7e1ce5d6c4c693b34dfb6f1f9f6007ae51ee0e0' },
  { version: 7, name: '0007-outbox-webhooks-consumers.sql', sha256: '1f2d4c513318285ca5384f98eb691e42caa946e22649f6dc02ec521fac9b02ed' },
]);

const scratch = makeScratch();
after(() => scratch.cleanup());

function migration(version, name, sql) {
  return { version, name, sql, sha256: sha256Hex(Buffer.from(sql, 'utf8')) };
}

function rawRows(path, sql) {
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    return raw.prepare(sql).all();
  } finally {
    raw.close();
  }
}

test('[DB-06] the T003 migration files are pinned by SHA-256 and later files only append', () => {
  const migrations = loadMigrations();
  assert.ok(migrations.length >= PINNED_MIGRATIONS.length, 'no pinned migration was removed');
  for (const pinned of PINNED_MIGRATIONS) {
    const actual = migrations[pinned.version - 1];
    assert.ok(actual, `migration ${pinned.version} exists`);
    assert.deepEqual(
      { version: actual.version, name: actual.name, sha256: actual.sha256 },
      pinned,
      `migration ${pinned.version} is unchanged: append a new migration instead of editing this one`,
    );
  }
  migrations.forEach((entry, index) => assert.equal(entry.version, index + 1, 'versions run 1..N without gaps'));
});

test('[DB-07] migrate applies every version once, records name, digest and user_version, and is idempotent', () => {
  const { db, path } = openTemp(scratch, { migrate: false });
  try {
    assert.equal(db.checkSchema(), 0, 'a new database has no schema');
    const migrations = loadMigrations();
    const first = db.migrate(undefined, () => '2026-11-08T10:00:00.000Z');
    assert.deepEqual(first.applied, migrations.map((entry) => entry.version));
    assert.equal(first.version, migrations.length);
    const second = db.migrate();
    assert.deepEqual(second.applied, [], 'a second run applies nothing');
    assert.equal(db.checkSchema(), migrations.length);

    const recorded = rawRows(path, 'SELECT version, name, sha256, applied_at FROM schema_migrations ORDER BY version');
    assert.deepEqual(
      recorded.map((row) => ({ ...row })),
      migrations.map((entry) => ({
        version: entry.version,
        name: entry.name,
        sha256: entry.sha256,
        applied_at: '2026-11-08T10:00:00.000Z',
      })),
    );
    assert.equal(rawRows(path, 'PRAGMA user_version')[0].user_version, migrations.length);
  } finally {
    db.close();
  }
});

test('[DB-08] an edited, renamed or unknown applied migration is refused and nothing changes', () => {
  const { db, path } = openTemp(scratch, { migrate: false });
  try {
    const base = [
      migration(1, '0001-one.sql', 'CREATE TABLE one (tenant_id TEXT NOT NULL) STRICT;'),
      migration(2, '0002-two.sql', 'CREATE TABLE two (tenant_id TEXT NOT NULL) STRICT;'),
    ];
    assert.deepEqual(db.migrate(base).applied, [1, 2]);

    const edited = [base[0], migration(2, '0002-two.sql', 'CREATE TABLE two (tenant_id TEXT NOT NULL, x TEXT) STRICT;')];
    const appended = migration(3, '0003-three.sql', 'CREATE TABLE three (tenant_id TEXT NOT NULL) STRICT;');
    assert.throws(() => db.migrate([...edited, appended]), (error) => error instanceof MigrationError && /append-only/.test(error.message));
    assert.throws(() => db.checkSchema(edited), MigrationError);

    const renamed = [base[0], { ...base[1], name: '0002-renamed.sql' }];
    assert.throws(() => db.migrate(renamed), MigrationError);

    assert.throws(
      () => db.migrate([base[0]]),
      (error) => error instanceof MigrationError && /newer than this code/.test(error.message),
    );

    const tables = rawRows(path, `SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name`).map((row) => row.name);
    assert.deepEqual(tables, ['one', 'schema_migrations', 'two'], 'the refused runs created nothing');
    assert.equal(rawRows(path, 'PRAGMA user_version')[0].user_version, 2);
    assert.deepEqual(db.migrate([...base, appended]).applied, [3], 'appending is accepted');
  } finally {
    db.close();
  }
});

test('[DB-09] the loader refuses gaps, duplicates, stray entries, bad names and invalid text', () => {
  const write = (dir, name, content) => writeFileSync(join(dir, name), content);
  const table = 'CREATE TABLE t (tenant_id TEXT NOT NULL) STRICT;\n';

  const good = scratch.dir();
  write(good, '0001-first.sql', table);
  write(good, '0002-second-step.sql', table.replace(' t ', ' u '));
  assert.deepEqual(
    loadMigrations(good).map((entry) => [entry.version, entry.name]),
    [
      [1, '0001-first.sql'],
      [2, '0002-second-step.sql'],
    ],
  );

  const cases = [
    ['gap', [['0001-a.sql', table], ['0003-c.sql', table]]],
    ['duplicate version', [['0001-a.sql', table], ['0001-b.sql', table]]],
    ['does not start at 1', [['0002-b.sql', table]]],
    ['stray file', [['0001-a.sql', table], ['notes.txt', 'x']]],
    ['upper-case name', [['0001-First.sql', table]]],
    ['three-digit version', [['001-a.sql', table]]],
    ['invalid UTF-8', [['0001-a.sql', Buffer.from([0x2d, 0x2d, 0x20, 0xff, 0xfe, 0x0a])]]],
    ['byte order mark', [['0001-a.sql', `﻿${table}`]]],
  ];
  for (const [label, files] of cases) {
    const dir = scratch.dir();
    for (const [name, content] of files) write(dir, name, content);
    assert.throws(() => loadMigrations(dir), MigrationError, label);
  }

  const tampered = { ...migration(1, '0001-a.sql', table), sql: `${table}-- changed\n` };
  assert.throws(() => validateMigrationSet([tampered]), /does not match its recorded digest/);
});

test('[DB-10] a failing migration, or one that controls transactions, pragmas or attachments, leaves nothing applied', () => {
  const { db, path } = openTemp(scratch, { migrate: false });
  try {
    const first = migration(1, '0001-one.sql', 'CREATE TABLE one (tenant_id TEXT NOT NULL) STRICT;');
    assert.deepEqual(db.migrate([first]).applied, [1]);

    const refused = [
      ['failing statement', 'CREATE TABLE partial (tenant_id TEXT NOT NULL) STRICT;\nINSERT INTO no_such_table VALUES (1);'],
      ['transaction control', 'CREATE TABLE partial (tenant_id TEXT NOT NULL) STRICT;\nCOMMIT;'],
      ['savepoint', 'SAVEPOINT s1;\nCREATE TABLE partial (tenant_id TEXT NOT NULL) STRICT;'],
      ['pragma', 'CREATE TABLE partial (tenant_id TEXT NOT NULL) STRICT;\nPRAGMA foreign_keys = OFF;'],
      ['attach', "ATTACH DATABASE ':memory:' AS side;\nCREATE TABLE partial (tenant_id TEXT NOT NULL) STRICT;"],
    ];
    for (const [label, sql] of refused) {
      assert.throws(() => db.migrate([first, migration(2, '0002-two.sql', sql)]), MigrationError, label);
      assert.equal(db.inTransaction, false, `${label}: no transaction left open`);
      const tables = rawRows(path, `SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name`).map((row) => row.name);
      assert.deepEqual(tables, ['one', 'schema_migrations'], `${label}: nothing created`);
      assert.equal(rawRows(path, 'SELECT count(*) AS n FROM schema_migrations')[0].n, 1, `${label}: not recorded`);
      assert.equal(rawRows(path, 'PRAGMA user_version')[0].user_version, 1, `${label}: version unchanged`);
    }
  } finally {
    db.close();
  }
});
