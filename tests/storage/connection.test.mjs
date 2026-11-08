// SPDX-License-Identifier: Apache-2.0
//
// node:sqlite connection and transaction helpers (T003): pragmas and file
// mode, BEGIN IMMEDIATE transactions, rollback, the bounded busy timeout, and
// serialized writers in separate OS processes.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmodSync, closeSync, mkdirSync, openSync, statSync, symlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  DEFAULT_BUSY_TIMEOUT_MS,
  MAX_BUSY_TIMEOUT_MS,
  openDatabase,
  StorageBusyError,
  StorageUsageError,
} from '../../src/storage/db/index.ts';
import { createTenant, makeScratch, openTemp, sid, ts } from './support/fixtures.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const scratch = makeScratch();
after(() => scratch.cleanup());

test('[DB-01] openDatabase configures WAL, FULL sync, foreign keys, trusted_schema off and a 0600 file, and refuses unsafe options', () => {
  const { db, path, dir } = openTemp(scratch, { busyTimeoutMs: 1234 });
  try {
    assert.equal(db.busyTimeoutMs, 1234);
    const raw = new DatabaseSync(path, { readOnly: true });
    try {
      assert.equal(raw.prepare('PRAGMA journal_mode').get().journal_mode, 'wal');
    } finally {
      raw.close();
    }
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(statSync(`${path}-wal`).mode & 0o777, 0o600);
    assert.equal(db.inTransaction, false);
  } finally {
    db.close();
  }

  const usage = (options, label) => assert.throws(() => openDatabase(options), StorageUsageError, label);
  usage({ path: 'relative/opensig.db' }, 'relative path');
  usage({ path: ':memory:' }, 'memory database');
  usage({ path: `file:${join(dir, 'x.db')}` }, 'URI path');
  usage({ path: join(dir, 'missing', 'x.db') }, 'missing directory');
  for (const busyTimeoutMs of [0, -1, 1.5, MAX_BUSY_TIMEOUT_MS + 1, Number.NaN, '100']) {
    usage({ path: join(dir, 'timeout.db'), busyTimeoutMs }, `busy timeout ${String(busyTimeoutMs)}`);
  }
  assert.equal(DEFAULT_BUSY_TIMEOUT_MS, 5_000);

  const loose = join(dir, 'loose.db');
  closeSync(openSync(loose, 'w', 0o600));
  chmodSync(loose, 0o644);
  usage({ path: loose }, 'group/other readable file');
  const link = join(dir, 'link.db');
  symlinkSync(path, link);
  usage({ path: link }, 'symbolic link');
  const directory = join(dir, 'a-directory.db');
  mkdirSync(directory);
  usage({ path: directory }, 'directory');

  const fresh = openDatabase({ path: join(dir, 'default.db') });
  try {
    assert.equal(fresh.busyTimeoutMs, DEFAULT_BUSY_TIMEOUT_MS);
  } finally {
    fresh.close();
  }
});

test('[DB-02] transaction() holds the write lock from BEGIN (IMMEDIATE) while WAL readers still read', () => {
  const { db, path } = openTemp(scratch, { busyTimeoutMs: 200 });
  const tenant = sid('tenant');
  const other = new DatabaseSync(path, { timeout: 50 });
  try {
    db.transaction(() => {
      assert.equal(db.inTransaction, true);
      // No statement has run yet, so only an IMMEDIATE begin can hold the lock.
      assert.throws(() => other.exec('BEGIN IMMEDIATE'), /database is locked/);
      assert.equal(other.prepare('SELECT count(*) AS n FROM tenants').get().n, 0);
      db.forTenant(tenant).insert('tenants', {
        oidc_issuer: 'https://issuer.example.test',
        oidc_audience: 'opensig-api',
        role_claim: 'roles',
        role_map_json: '{}',
        principal_kind_claim: 'principal_kind',
        allowed_roles_json: '[]',
        created_at: ts(0),
        updated_at: ts(0),
      });
      assert.equal(other.prepare('SELECT count(*) AS n FROM tenants').get().n, 0, 'uncommitted row is invisible');
    });
    assert.equal(db.inTransaction, false);
    assert.equal(other.prepare('SELECT count(*) AS n FROM tenants').get().n, 1, 'committed row is visible');
    other.exec('BEGIN IMMEDIATE');
    other.exec('ROLLBACK');
  } finally {
    other.close();
    db.close();
  }
});

test('[DB-03] a throwing, nested or asynchronous transaction rolls back, and writes outside a transaction are refused', async () => {
  const { db } = openTemp(scratch);
  const tenant = sid('tenant');
  try {
    createTenant(db, tenant);
    const store = db.forTenant(tenant);
    const envelope = (id) => ({
      id,
      source_app: 'manual',
      source_record: 'record-1',
      source_version: 'v1',
      state: 'draft',
      created_by_kind: 'human-operator',
      created_by_ref: 'operator-1',
      expires_at: ts(60),
      recipients_count: 1,
      created_at: ts(1),
      updated_at: ts(1),
    });

    const failure = new Error('synthetic failure after a write');
    assert.throws(
      () =>
        db.transaction(() => {
          store.insert('envelopes', envelope(sid('env')));
          throw failure;
        }),
      (error) => error === failure,
    );
    assert.equal(store.count('envelopes'), 0, 'the write before the throw was rolled back');
    assert.equal(db.inTransaction, false);

    assert.throws(
      () => db.transaction(() => db.transaction(() => store.insert('envelopes', envelope(sid('env'))))),
      (error) => error instanceof StorageUsageError && /nested/.test(error.message),
    );
    assert.equal(store.count('envelopes'), 0);

    let late;
    assert.throws(
      () =>
        db.transaction(async () => {
          store.insert('envelopes', envelope(sid('env')));
          await null;
          try {
            store.insert('envelopes', envelope(sid('env')));
          } catch (error) {
            late = error;
          }
        }),
      (error) => error instanceof StorageUsageError && /synchronous/.test(error.message),
    );
    await new Promise((settle) => setImmediate(settle));
    assert.ok(late instanceof StorageUsageError, 'a write after the await is refused outside the transaction');
    assert.equal(store.count('envelopes'), 0, 'the asynchronous callback was rolled back');

    assert.throws(() => store.insert('envelopes', envelope(sid('env'))), /requires a transaction/);
    assert.throws(() => store.update('envelopes', { id: 'x'.repeat(16) }, { state: 'voided' }), /requires a transaction/);
    assert.throws(() => store.delete('recipients', { id: 'x'.repeat(16) }), /requires a transaction/);

    const id = sid('env');
    assert.equal(db.transaction(() => (store.insert('envelopes', envelope(id)), 'returned')), 'returned');
    assert.equal(store.get('envelopes', { id })?.state, 'draft');
  } finally {
    db.close();
  }
});

test('[DB-04] the busy timeout bounds the wait for the write lock, then StorageBusyError', () => {
  const busyTimeoutMs = 300;
  const { db, path } = openTemp(scratch, { busyTimeoutMs });
  const holder = new DatabaseSync(path);
  try {
    holder.exec('BEGIN IMMEDIATE');
    const started = performance.now();
    assert.throws(
      () => db.transaction(() => 'never runs'),
      (error) => error instanceof StorageBusyError && error.code === 'storage_busy',
    );
    const waited = performance.now() - started;
    assert.ok(waited >= busyTimeoutMs * 0.8, `waited ${Math.round(waited)} ms, at least about the busy timeout`);
    assert.ok(waited < busyTimeoutMs + 3_000, `waited ${Math.round(waited)} ms, bounded`);
    assert.equal(db.inTransaction, false);
    holder.exec('ROLLBACK');
    assert.equal(
      db.transaction(() => 'ran'),
      'ran',
      'the lock is available once released',
    );
  } finally {
    holder.close();
    db.close();
  }
});

function runWorker(path, tenant, iterations) {
  return new Promise((done, fail) => {
    const child = spawn(process.execPath, [join(HERE, 'support', 'cas-worker.mjs'), path, tenant, String(iterations)], {
      cwd: resolve(HERE, '..', '..'),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.on('error', fail);
    child.on('close', (code) => done({ code, stdout, stderr }));
  });
}

test('[DB-05] writers in separate OS processes are serialized by BEGIN IMMEDIATE: no lost compare-and-set', async () => {
  const { db, path } = openTemp(scratch);
  const tenant = sid('tenant');
  createTenant(db, tenant);
  db.close();

  const workers = 4;
  const iterations = 40;
  const results = await Promise.all(Array.from({ length: workers }, () => runWorker(path, tenant, iterations)));
  for (const result of results) {
    assert.equal(result.code, 0, `worker failed: ${result.stderr.slice(0, 400)}`);
    assert.deepEqual(JSON.parse(result.stdout), { iterations, lost: 0 });
  }

  const reopened = openDatabase({ path });
  try {
    assert.equal(reopened.forTenant(tenant).get('tenants', {})?.version, 1 + workers * iterations);
  } finally {
    reopened.close();
  }
});
