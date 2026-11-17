// SPDX-License-Identifier: Apache-2.0
//
// T010, migration 0017: approval_receipts keeps the exact receipt bytes of each approval and
// the digest of the request that produced them, so an exact retry replays the original
// receipt and a changed retry is refused (AP-06). These rows are approval evidence, and they
// resist the routes already ruled for stored evidence (A-010 rows I1, REPLACE-ENV, ROWID-ENV,
// I2 and ROWID-CER; the route list of T007's ST-16 and T008's CH-08):
// - INSERT OR REPLACE (and REPLACE) by the key (tenant_id, approval_id) or by the recipient
//   (tenant_id, recipient_id): refused by approval_receipts_key_exists before conflict
//   resolution, whatever the conflict clause;
// - INSERT OR REPLACE naming an existing hidden rowid (spelled rowid, _rowid_ or oid) with a
//   new key, then a re-insert of the old key: both refused by the same trigger;
// - any UPDATE (a column, the rowid, the key), including UPDATE OR REPLACE of another row
//   onto the victim's rowid, key or recipient: refused by approval_receipts_immutable_update;
// - DELETE, and delete followed by a re-insert: refused by approval_receipts_immutable_delete
//   (then key_exists);
// - rowids 0, -1 and -2: refused by approval_receipts_rowid_positive.
// Each route runs on a raw connection to the file with foreign keys off, on, and on but
// deferred within one transaction; every statement must be refused by its trigger and leave
// the whole table, rowids included, unchanged. A duplicate through the tenant-scoped store is
// the same trigger constraint (storage_constraint), the store refuses update and delete of
// the immutable table, and an ordinary approval still writes its receipt. 0017 is appended
// after 0016 and pinned by SHA-256; 0001..0016 are untouched. Hash and receipt values are
// generated in memory; messages carry labels only.

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

import { StorageConstraintError, StorageUsageError } from '../../src/storage/db/index.ts';
import { insertApprovalReceipt } from '../../src/storage/repositories/approvals.ts';
import { loadMigrations } from '../../src/storage/schema/migrations.ts';
import { approvalBody, createWorld, openSession, postApproval, sentEnvelope, sid } from './support.mjs';

/** 0017 (T010), pinned: later changes append a migration. */
const PINNED_0017 = Object.freeze({ version: 17, name: '0017-approval-receipts.sql', sha256: 'ad826817cbb869667d0ba75df4b9b63479fd44c5a98832dddedf1fda1dd64922' });
/** The migrations before T010, by name: 0017 is appended after them. */
const BEFORE_0017 = Object.freeze([
  '0001-tenants-consent.sql',
  '0002-envelopes.sql',
  '0003-recipient-ceremony.sql',
  '0004-idempotency-jobs.sql',
  '0005-artifacts.sql',
  '0006-audit-retention.sql',
  '0007-outbox-webhooks-consumers.sql',
  '0008-disposal-record-kind.sql',
  '0009-blob-ref-indexes.sql',
  '0010-envelope-freeze-version-graph.sql',
  '0011-idempotency-response-body.sql',
  '0012-idempotency-body-bound.sql',
  '0013-recipient-ceremony-monotonic.sql',
  '0014-recipient-ceremony-no-replace.sql',
  '0015-envelopes-no-replace.sql',
  '0016-recipient-ceremony-rowid-fixed.sql',
]);

const TABLE = 'approval_receipts';
const KEY_EXISTS = /^approval_receipts key exists: a receipt is never replaced$/;
const IMMUTABLE = /^approval_receipts rows are immutable$/;
const ROWID_POSITIVE = /^approval_receipts rowid must be positive$/;
const TRIGGERS = Object.freeze(['approval_receipts_immutable_delete', 'approval_receipts_immutable_update', 'approval_receipts_key_exists', 'approval_receipts_rowid_positive']);
const SPELLINGS = Object.freeze(['rowid', '_rowid_', 'oid']);
const FK_MODES = Object.freeze(['off', 'on', 'deferred']);
const SQLITE_CONSTRAINT_TRIGGER = 1811;
const SQLITE_KINDS = new Map([
  [275, 'check'],
  [787, 'foreign-key'],
  [1299, 'not-null'],
  [1555, 'primary-key'],
  [1811, 'trigger'],
  [2067, 'unique'],
]);

function freshBody() {
  const body = Buffer.from(`{"synthetic":"${randomBytes(12).toString('hex')}"}`, 'utf8');
  return { receipt_body: body, receipt_digest: createHash('sha256').update(body).digest('hex') };
}

/** The table's state as `raw` sees it: every column and the hidden rowid. */
function stateOn(raw) {
  const rows = raw.prepare(`SELECT rowid AS hidden_rowid, * FROM ${TABLE} ORDER BY rowid`).all();
  return JSON.stringify(rows.map((row) => Object.fromEntries(Object.entries(row).map(([column, value]) => [column, value instanceof Uint8Array ? `bytes:${Buffer.from(value).toString('hex')}` : value]))));
}

function describe(error) {
  return `${SQLITE_KINDS.get(error?.errcode) ?? 'another error'}: ${String(error?.message).slice(0, 120)}`;
}

/** An INSERT of `values`, optionally naming a rowid ({ spelling, value }) first. */
function insertStatement(verb, values, rowid = null) {
  const columns = Object.keys(values);
  const names = rowid === null ? columns : [rowid.spelling, ...columns];
  const params = rowid === null ? columns.map((column) => values[column]) : [rowid.value, ...columns.map((column) => values[column])];
  return { sql: `${verb} INTO ${TABLE} (${names.join(', ')}) VALUES (${names.map(() => '?').join(', ')})`, params };
}

/**
 * Run a route's steps on a raw connection in foreign-key mode `mode`, inside one transaction.
 * Each step must be refused by a trigger whose message matches `refusedBy`, and the table must be
 * unchanged; every miss is pushed onto `problems`. A route that ran or changed anything is rolled
 * back so it cannot affect the next; a fully refused route commits its empty transaction.
 */
function attempt(problems, path, tag, mode, steps) {
  problems.attempts += 1;
  const raw = new DatabaseSync(path, { enableForeignKeyConstraints: mode !== 'off' });
  try {
    raw.exec(mode === 'deferred' ? 'BEGIN; PRAGMA defer_foreign_keys = ON;' : 'BEGIN');
    const before = stateOn(raw);
    let ran = false;
    for (const step of steps) {
      let error = null;
      try {
        raw.prepare(step.sql).run(...step.params);
      } catch (caught) {
        error = caught;
      }
      if (error === null) {
        ran = true;
        problems.push(`${tag}: ${step.label}: ran`);
      } else if (error.errcode !== SQLITE_CONSTRAINT_TRIGGER || !step.refusedBy.test(String(error.message))) {
        problems.push(`${tag}: ${step.label}: refused by ${describe(error)}`);
      }
    }
    const changed = stateOn(raw) !== before;
    if (changed) problems.push(`${tag}: the table changed`);
    raw.exec(ran || changed ? 'ROLLBACK' : 'COMMIT');
  } finally {
    raw.close();
  }
}

function readOnly(world, fn) {
  const raw = new DatabaseSync(world.path, { readOnly: true });
  try {
    return fn(raw);
  } finally {
    raw.close();
  }
}

test('[AP-13] approval receipts are never replaced, re-keyed, moved through their hidden rowid, updated or deleted; an ordinary approval still writes its receipt; migration 0017 is appended and pinned', async () => {
  const world = await createWorld();
  try {
    // Two approved envelopes: the victim's receipt and another receipt for the UPDATE OR REPLACE routes.
    const receipts = [];
    for (let index = 0; index < 2; index += 1) {
      const { token } = await sentEnvelope(world);
      const session = await openSession(world, token);
      const response = await postApproval(world, session, approvalBody(session.state));
      assert.equal(response.status, 200, `premise: approval ${index + 1}`);
      receipts.push(response);
    }
    const rows = world.rows(TABLE);
    assert.equal(rows.length, 2, 'premise: two receipts');
    const [victim, other] = rows;
    const tableBefore = readOnly(world, stateOn);
    const rowidOf = (row) => readOnly(world, (raw) => raw.prepare(`SELECT rowid AS r FROM ${TABLE} WHERE tenant_id = ? AND approval_id = ?`).get(row.tenant_id, row.approval_id).r);
    const victimRowid = rowidOf(victim);
    const otherRowid = rowidOf(other);
    assert.ok(victimRowid > 0 && otherRowid > 0, 'premise: ordinary inserts have positive rowids');
    const freeRowid = Math.max(victimRowid, otherRowid) + 1_000_000;
    const freshKey = () => ({ approval_id: sid('appr'), recipient_id: sid('rcpt') });

    const problems = [];
    problems.attempts = 0;
    const reinsert = { label: 'then INSERT of the old key with other bytes', ...insertStatement('INSERT', { ...victim, ...freshBody() }), refusedBy: KEY_EXISTS };
    const byKey = [victim.tenant_id, victim.approval_id];
    const otherKey = [other.tenant_id, other.approval_id];
    for (const mode of FK_MODES) {
      const tag = (route) => `${route} [foreign keys ${mode}]`;
      for (const verb of ['INSERT OR REPLACE', 'REPLACE']) {
        attempt(problems, world.path, tag(`${verb} by key`), mode, [{ label: `${verb} with the same key and other bytes`, ...insertStatement(verb, { ...victim, ...freshBody() }), refusedBy: KEY_EXISTS }]);
        attempt(problems, world.path, tag(`${verb} by recipient`), mode, [{ label: `${verb} with a fresh approval id and the same recipient`, ...insertStatement(verb, { ...victim, ...freshBody(), approval_id: sid('appr') }), refusedBy: KEY_EXISTS }]);
      }
      for (const spelling of SPELLINGS) {
        attempt(problems, world.path, tag(`insert by ${spelling}`), mode, [
          { label: `INSERT OR REPLACE naming its ${spelling} with a new key`, ...insertStatement('INSERT OR REPLACE', { ...victim, ...freshBody(), ...freshKey() }, { spelling, value: victimRowid }), refusedBy: KEY_EXISTS },
          reinsert,
        ]);
      }
      attempt(problems, world.path, tag('update a column'), mode, [
        { label: 'UPDATE of the receipt bytes', sql: `UPDATE ${TABLE} SET receipt_body = ?, receipt_digest = ? WHERE tenant_id = ? AND approval_id = ?`, params: [...Object.values(freshBody()), ...byKey], refusedBy: IMMUTABLE },
      ]);
      attempt(problems, world.path, tag('update the request digest'), mode, [
        { label: 'UPDATE of the request digest', sql: `UPDATE ${TABLE} SET request_digest = ? WHERE tenant_id = ? AND approval_id = ?`, params: [createHash('sha256').update(randomBytes(8)).digest('hex'), ...byKey], refusedBy: IMMUTABLE },
      ]);
      attempt(problems, world.path, tag('update the rowid'), mode, [
        { label: 'UPDATE of its rowid to a free value', sql: `UPDATE ${TABLE} SET rowid = ? WHERE tenant_id = ? AND approval_id = ?`, params: [freeRowid, ...byKey], refusedBy: IMMUTABLE },
      ]);
      attempt(problems, world.path, tag('another row onto its rowid'), mode, [
        { label: 'UPDATE OR REPLACE of another row onto its rowid', sql: `UPDATE OR REPLACE ${TABLE} SET rowid = ? WHERE tenant_id = ? AND approval_id = ?`, params: [victimRowid, ...otherKey], refusedBy: IMMUTABLE },
        reinsert,
      ]);
      attempt(problems, world.path, tag('another row onto its key'), mode, [
        { label: 'UPDATE OR REPLACE of another row onto its key', sql: `UPDATE OR REPLACE ${TABLE} SET approval_id = ? WHERE tenant_id = ? AND approval_id = ?`, params: [victim.approval_id, ...otherKey], refusedBy: IMMUTABLE },
        reinsert,
      ]);
      attempt(problems, world.path, tag('another row onto its recipient'), mode, [
        { label: 'UPDATE OR REPLACE of another row onto its recipient', sql: `UPDATE OR REPLACE ${TABLE} SET recipient_id = ? WHERE tenant_id = ? AND approval_id = ?`, params: [victim.recipient_id, ...otherKey], refusedBy: IMMUTABLE },
      ]);
      attempt(problems, world.path, tag('delete and re-insert'), mode, [
        { label: 'DELETE', sql: `DELETE FROM ${TABLE} WHERE tenant_id = ? AND approval_id = ?`, params: byKey, refusedBy: IMMUTABLE },
        reinsert,
      ]);
      attempt(problems, world.path, tag('delete every row'), mode, [{ label: 'DELETE of the whole table', sql: `DELETE FROM ${TABLE}`, params: [], refusedBy: IMMUTABLE }]);
      for (const value of [0, -1, -2]) {
        attempt(problems, world.path, tag(`rowid ${value}`), mode, [
          { label: `INSERT with rowid ${value} and a fresh key`, ...insertStatement('INSERT', { ...victim, ...freshBody(), ...freshKey() }, { spelling: 'rowid', value }), refusedBy: ROWID_POSITIVE },
        ]);
      }
    }
    assert.equal(problems.attempts, 3 * (4 + 3 + 8 + 3), 'every route in every foreign-key mode');
    assert.deepEqual([...problems], [], 'every route is refused by its trigger and leaves the table unchanged');
    assert.equal(readOnly(world, stateOn), tableBefore, 'the table, rowids included, is unchanged');

    // Through the tenant-scoped store: a duplicate is the same trigger constraint; update and delete are refused.
    const store = world.store('alpha');
    assert.throws(
      () => world.db.transaction(() => insertApprovalReceipt(store, { approvalId: victim.approval_id, envelopeId: victim.envelope_id, recipientId: victim.recipient_id, requestDigest: victim.request_digest, body: Buffer.from('{"other":true}'), createdAt: victim.created_at })),
      (error) => error instanceof StorageConstraintError && error.constraint === 'trigger' && KEY_EXISTS.test(error.message),
      'a duplicate receipt through the store',
    );
    assert.throws(() => world.db.transaction(() => store.update(TABLE, { approval_id: victim.approval_id }, { request_digest: victim.request_digest })), StorageUsageError, 'the store refuses an update');
    assert.throws(() => world.db.transaction(() => store.delete(TABLE, { approval_id: victim.approval_id })), /immutable/, 'the store refuses a delete');
    assert.equal(readOnly(world, stateOn), tableBefore, 'still unchanged');

    // The replay still serves the untouched bytes, and an ordinary approval writes its receipt.
    assert.ok(Buffer.from(victim.receipt_body).equals(receipts[0].bytes), 'the stored bytes are the bytes sent');
    const { token } = await sentEnvelope(world);
    const session = await openSession(world, token);
    assert.equal((await postApproval(world, session, approvalBody(session.state))).status, 200, 'an ordinary approval succeeds');
    assert.equal(world.rows(TABLE).length, 3, 'and writes its receipt');

    // Inventory: the keys, the triggers and the migration.
    const uniqueKeys = readOnly(world, (raw) =>
      raw
        .prepare(`PRAGMA index_list(${TABLE})`)
        .all()
        .filter((index) => index.unique === 1)
        .map((index) => raw.prepare(`PRAGMA index_info(${JSON.stringify(index.name)})`).all().sort((a, b) => a.seqno - b.seqno).map((column) => column.name).join(','))
        .sort(),
    );
    assert.deepEqual(uniqueKeys, ['tenant_id,approval_id', 'tenant_id,recipient_id'], 'every unique key is one the routes above try');
    const triggers = readOnly(world, (raw) => raw.prepare("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name = ? ORDER BY name").all(TABLE).map((row) => row.name));
    assert.deepEqual(triggers, [...TRIGGERS], 'exactly the four 0017 triggers');
    const strict = readOnly(world, (raw) => raw.prepare('SELECT strict FROM pragma_table_list WHERE name = ?').get(TABLE).strict);
    assert.equal(strict, 1, 'STRICT');

    const migrations = loadMigrations();
    assert.ok(migrations.length >= 17, 'migration 17 exists');
    assert.deepEqual(migrations.slice(0, 16).map((entry) => entry.name), [...BEFORE_0017], '0001..0016 are untouched and in order');
    const actual = migrations[PINNED_0017.version - 1];
    assert.deepEqual({ version: actual.version, name: actual.name, sha256: actual.sha256 }, PINNED_0017, 'migration 17 is unchanged: append a new one instead');
    const applied = world.rows('schema_migrations', 'WHERE version = 17');
    assert.equal(applied.length, 1, '0017 is applied');
    assert.equal(applied[0].sha256, PINNED_0017.sha256);
  } finally {
    await world.close();
  }
});
