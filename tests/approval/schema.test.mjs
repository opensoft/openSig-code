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
//
// AP-13 (extended), migration 0018 (A-010 row ROWID-APJ): the approvals (0003) and
// signing_jobs (0004) rows T010 writes resist the same routes. Victims: the approval of
// recipient 1 of a two-recipient envelope, and the reservation of a one-recipient envelope
// after the finalization runner was granted a lease (attempt 1, fencing token 1):
// - approvals: INSERT OR REPLACE and REPLACE by the key (tenant_id, id) and by the recipient
//   (tenant_id, recipient_id) (the four-column key contains the first and cannot conflict
//   without it); INSERT OR REPLACE naming the hidden rowid (rowid, _rowid_, oid) with a new
//   key (recipient 2, which has no approval yet), then a re-insert of the old key; any UPDATE,
//   UPDATE OR REPLACE onto the victim's rowid, key or recipient, and DELETE (0003's triggers);
//   rowids 0, -1 and -2. Refused by approvals_key_exists, approvals_rowid_positive and 0003;
// - signing_jobs: INSERT OR REPLACE and REPLACE by (tenant_id, envelope_id) with the
//   attempts, fencing token and lease reset; the rowid routes with a new key (an envelope with
//   no reservation), then a re-insert of the old key; an UPDATE of the rowid, the envelope or
//   the tenant; UPDATE OR REPLACE of another job onto the victim's rowid or key; DELETE
//   (0004); rowids 0, -1 and -2. Refused by signing_jobs_key_exists,
//   signing_jobs_rowid_positive, signing_jobs_rowid_key_fixed and 0004 (a key change may be
//   refused by 0004's signing_jobs_monotonic first; either trigger is accepted there).
// Every route runs in foreign-key modes off, on and deferred, and must leave both tables,
// rowids included, unchanged. The positive case: the updates the finalization runner and the
// operator retry make (lease grant and renewal, attempts and fencing tokens, retryable with a
// retry time, failed, retry, succeeded; data-model.md § Transitions and races, items 2 and 3)
// still succeed through the store's compare-and-set and on raw connections in every mode, and
// a new approval still inserts its approval and reservation. 0018 is appended and pinned by
// SHA-256, and 0001..0017 are byte-identical (pinned by SHA-256).

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

import { StorageConstraintError, StorageUsageError } from '../../src/storage/db/index.ts';
import { insertApproval, insertApprovalReceipt, insertFinalizationReservation } from '../../src/storage/repositories/approvals.ts';
import { loadMigrations } from '../../src/storage/schema/migrations.ts';
import { MINUTE, approvalBody, approvedByFirst, createWorld, openSession, postApproval, sentEnvelope, sid } from './support.mjs';

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

/** The state of `tables` as `raw` sees it: every column and the hidden rowid of every row. */
function stateOn(raw, tables = [TABLE]) {
  return JSON.stringify(
    tables.map((table) =>
      raw
        .prepare(`SELECT rowid AS hidden_rowid, * FROM ${table} ORDER BY rowid`)
        .all()
        .map((row) => Object.fromEntries(Object.entries(row).map(([column, value]) => [column, value instanceof Uint8Array ? `bytes:${Buffer.from(value).toString('hex')}` : value]))),
    ),
  );
}

function describe(error) {
  return `${SQLITE_KINDS.get(error?.errcode) ?? 'another error'}: ${String(error?.message).slice(0, 120)}`;
}

/** An INSERT of `values` into `table`, optionally naming a rowid ({ spelling, value }) first. */
function insertStatement(verb, values, rowid = null, table = TABLE) {
  const columns = Object.keys(values);
  const names = rowid === null ? columns : [rowid.spelling, ...columns];
  const params = rowid === null ? columns.map((column) => values[column]) : [rowid.value, ...columns.map((column) => values[column])];
  return { sql: `${verb} INTO ${table} (${names.join(', ')}) VALUES (${names.map(() => '?').join(', ')})`, params };
}

/**
 * Run a route's steps on a raw connection in foreign-key mode `mode`, inside one transaction.
 * Each step must be refused by a trigger whose message matches `refusedBy`, and `tables` must be
 * unchanged; every miss is pushed onto `problems`. A route that ran or changed anything is rolled
 * back so it cannot affect the next; a fully refused route commits its empty transaction.
 */
function attempt(problems, path, tag, mode, steps, tables = [TABLE]) {
  problems.attempts += 1;
  const raw = new DatabaseSync(path, { enableForeignKeyConstraints: mode !== 'off' });
  try {
    raw.exec(mode === 'deferred' ? 'BEGIN; PRAGMA defer_foreign_keys = ON;' : 'BEGIN');
    const before = stateOn(raw, tables);
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
    const changed = stateOn(raw, tables) !== before;
    if (changed) problems.push(`${tag}: ${tables.length === 1 ? 'the table' : 'a table'} changed`);
    raw.exec(ran || changed ? 'ROLLBACK' : 'COMMIT');
  } finally {
    raw.close();
  }
}

/**
 * The positive counterpart on a raw connection: every step must run and change exactly one row.
 * The transaction is always rolled back, so the rows stay as they were.
 */
function legitimateRaw(problems, path, tag, mode, steps) {
  problems.attempts += 1;
  const raw = new DatabaseSync(path, { enableForeignKeyConstraints: mode !== 'off' });
  try {
    raw.exec(mode === 'deferred' ? 'BEGIN; PRAGMA defer_foreign_keys = ON;' : 'BEGIN');
    for (const step of steps) {
      try {
        const { changes } = raw.prepare(step.sql).run(...step.params);
        if (Number(changes) !== 1) problems.push(`${tag}: ${step.label}: changed ${changes} rows`);
      } catch (error) {
        problems.push(`${tag}: ${step.label}: refused by ${describe(error)}`);
      }
    }
    raw.exec('ROLLBACK');
  } finally {
    raw.close();
  }
}

/** A legitimate compare-and-set through the tenant-scoped store: it must commit and match its row. */
function legitimate(world, label, fn) {
  let matched;
  try {
    matched = world.db.transaction(fn);
  } catch (error) {
    assert.fail(`positive: ${label}: refused by ${describe(error?.cause ?? error)}`);
  }
  assert.equal(matched, true, `positive: ${label}: the compare-and-set matched its row`);
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

// --- AP-13 (extended): approvals and signing_jobs, migration 0018 (A-010 ROWID-APJ) -----------

/** 0001..0017, byte-identical: 0018 is appended after them. */
const PINNED_0001_0017 = Object.freeze([
  { version: 1, name: '0001-tenants-consent.sql', sha256: '400f99b8a9b57766c0bade2f844bcf8284d61a25b0be299b6ee0793f53399638' },
  { version: 2, name: '0002-envelopes.sql', sha256: '5a653271c4c8bf2ed0b0ccc9129512583f0cf05e67f15cdbb1f252125da01e3e' },
  { version: 3, name: '0003-recipient-ceremony.sql', sha256: '63c4c04bd9d198200caa55d4fbd9ccb4c405cd1c4877f201dd11eba70ad906c0' },
  { version: 4, name: '0004-idempotency-jobs.sql', sha256: '5cfd7d2627c22fbbb1e0bfde31705f9d41356fe3dd1f19266e3a6de9b0e8c986' },
  { version: 5, name: '0005-artifacts.sql', sha256: '79153c45dc4d16dfa6de4c87f1fe5b7c4742b868a21404cd119282d74d88329d' },
  { version: 6, name: '0006-audit-retention.sql', sha256: '1f7ad14b709cb88be3db0616d7e1ce5d6c4c693b34dfb6f1f9f6007ae51ee0e0' },
  { version: 7, name: '0007-outbox-webhooks-consumers.sql', sha256: '1f2d4c513318285ca5384f98eb691e42caa946e22649f6dc02ec521fac9b02ed' },
  { version: 8, name: '0008-disposal-record-kind.sql', sha256: '4af3cab3c3e48f0eaf8238848bf1f420dabc1723d7d69b6d2febc00e2db1130a' },
  { version: 9, name: '0009-blob-ref-indexes.sql', sha256: 'fe6255721a5d15a5fc983f086ea221aa1ea7ff2893010eb5cc018ca44b3b0118' },
  { version: 10, name: '0010-envelope-freeze-version-graph.sql', sha256: 'b52503d539f794ecfddd44d2c9638a78fa16268bfd5c5f369aa072086aeca57d' },
  { version: 11, name: '0011-idempotency-response-body.sql', sha256: 'adf11be692fe9ef40b0484334696f85c4ea5001431e7ce71d4beab3d77737c1c' },
  { version: 12, name: '0012-idempotency-body-bound.sql', sha256: '3d5460527f5e7595122194567c79bf3cd8327002dcf403854431761a8ddf332c' },
  { version: 13, name: '0013-recipient-ceremony-monotonic.sql', sha256: '559da84c135b46149691cf15bf424a706c7f7d40820ad9110677df4c0c6cd07d' },
  { version: 14, name: '0014-recipient-ceremony-no-replace.sql', sha256: '20dfbb5ad613e1016ca7bb940ec5a37d5cb8887b3d80335164cd8183e25d8116' },
  { version: 15, name: '0015-envelopes-no-replace.sql', sha256: '3d059beac414363f597ba8ae1b1e1080f284d4245d07852a94aa35248ece8d7a' },
  { version: 16, name: '0016-recipient-ceremony-rowid-fixed.sql', sha256: 'a217a3ea6b2982a35ff687ed9c2db74046dc707cdd761bdc61a3c7e3936bc460' },
  { version: 17, name: '0017-approval-receipts.sql', sha256: 'ad826817cbb869667d0ba75df4b9b63479fd44c5a98832dddedf1fda1dd64922' },
]);
/** 0018 (T010 follow-up, ROWID-APJ), pinned: later changes append a migration. */
const PINNED_0018 = Object.freeze({ version: 18, name: '0018-approvals-jobs-no-replace.sql', sha256: 'd9f0b9e0337b0f3016e574b35c1d0be01a82489a81a31d3dec91ab4e442b348a' });

const APPROVALS = 'approvals';
const JOBS = 'signing_jobs';
const BOTH = Object.freeze([APPROVALS, JOBS]);
const APPROVAL_KEY_EXISTS = /^approvals key exists: an approval is never replaced$/;
const APPROVAL_ROWID_POSITIVE = /^approvals rowid must be positive$/;
const APPROVAL_IMMUTABLE = /^approvals rows are immutable$/;
const JOB_KEY_EXISTS = /^signing_jobs key exists: a reservation is never replaced$/;
const JOB_ROWID_POSITIVE = /^signing_jobs rowid must be positive$/;
const JOB_ROWID_KEY_FIXED = /^signing_jobs rowid and key never change$/;
/** A key change: 0018's rowid-and-key trigger, or 0004's monotonic trigger, whichever fires first. */
const JOB_KEY_CHANGE = /^(signing_jobs rowid and key never change|signing_jobs attempts, fencing tokens and reservation never move backward)$/;
const JOB_NEVER_DELETED = /^signing_jobs rows are never deleted$/;
const APPROVAL_TRIGGERS = Object.freeze(['approvals_consent_binding', 'approvals_immutable_delete', 'approvals_immutable_update', 'approvals_key_exists', 'approvals_rowid_positive', 'approvals_sequence']);
const JOB_TRIGGERS = Object.freeze(['signing_jobs_immutable_delete', 'signing_jobs_key_exists', 'signing_jobs_monotonic', 'signing_jobs_rowid_key_fixed', 'signing_jobs_rowid_positive']);
/** Routes per foreign-key mode: approvals 4 + 3 + 7 + 3, signing_jobs 2 + 3 + 7 + 3. */
const APPROVAL_ROUTES = 17;
const JOB_ROUTES = 15;

function randomDigest() {
  return createHash('sha256').update(randomBytes(16)).digest('hex');
}

function uniqueKeysOf(raw, table) {
  return raw
    .prepare(`PRAGMA index_list(${table})`)
    .all()
    .filter((index) => index.unique === 1)
    .map((index) => raw.prepare(`PRAGMA index_info(${JSON.stringify(index.name)})`).all().sort((a, b) => a.seqno - b.seqno).map((column) => column.name).join(','))
    .sort();
}

test('[AP-13] approvals and signing jobs are never replaced by key, moved through their hidden rowid, re-keyed or deleted, in every foreign-key mode; the finalization runner\'s and the operator retry\'s job updates still succeed; migration 0018 is appended and pinned (A-010 ROWID-APJ)', async () => {
  const world = await createWorld();
  try {
    // A two-recipient envelope approved by recipient 1 (the victim approval; recipient 2 has none
    // yet), and two one-recipient envelopes approved and reserved (the victim and the other job).
    const two = await approvedByFirst(world, { recipients: 2 });
    const singles = [await approvedByFirst(world, { recipients: 1 }), await approvedByFirst(world, { recipients: 1 })];
    const [victimApproval] = world.rows(APPROVALS, 'WHERE envelope_id = ?', [two.envelope.id]);
    const [otherApproval] = world.rows(APPROVALS, 'WHERE envelope_id = ?', [singles[0].envelope.id]);
    const [secondRecipient] = world.rows('recipients', 'WHERE envelope_id = ? AND ordinal = 2', [two.envelope.id]);
    const [victimJob] = world.rows(JOBS, 'WHERE envelope_id = ?', [singles[0].envelope.id]);
    const [otherJob] = world.rows(JOBS, 'WHERE envelope_id = ?', [singles[1].envelope.id]);
    assert.ok(victimApproval && otherApproval && secondRecipient && victimJob && otherJob, 'premise: the approvals, the second recipient and the reservations exist');
    assert.equal(world.rows(APPROVALS, 'WHERE recipient_id = ?', [secondRecipient.id]).length, 0, 'premise: recipient 2 has no approval yet');
    assert.equal(world.rows(JOBS, 'WHERE envelope_id = ?', [two.envelope.id]).length, 0, 'premise: the two-recipient envelope has no reservation');
    assert.deepEqual([victimJob.status, victimJob.attempt_count, victimJob.version], ['pending', 0, 1], 'premise: a fresh reservation');

    // The runner leases the victim job (positive case, first step): its attempt and fencing token now count.
    const store = world.store('alpha');
    const jobAt = (job, minutes) => new Date(Date.parse(job.created_at) + minutes * MINUTE).toISOString();
    legitimate(world, 'the runner is granted a lease (running, attempt 1, fencing token 1)', () =>
      store.compareAndSet(JOBS, { envelope_id: victimJob.envelope_id }, victimJob.version, { status: 'running', attempt_count: 1, fencing_token: 1, lease_owner: 'runner-ap13-1', lease_expires_at: jobAt(victimJob, 5), updated_at: jobAt(victimJob, 1) }),
    );
    const [leased] = world.rows(JOBS, 'WHERE envelope_id = ?', [victimJob.envelope_id]);
    assert.deepEqual([leased.status, leased.attempt_count, leased.fencing_token], ['running', 1, 1], 'premise: the lease was granted');

    const rowidOf = (table, where, params) => readOnly(world, (raw) => raw.prepare(`SELECT rowid AS r FROM ${table} WHERE ${where}`).get(...params).r);
    const maxRowid = (table) => readOnly(world, (raw) => raw.prepare(`SELECT max(rowid) AS r FROM ${table}`).get().r);
    const approvalKey = [victimApproval.tenant_id, victimApproval.id];
    const otherApprovalKey = [otherApproval.tenant_id, otherApproval.id];
    const jobKey = [leased.tenant_id, leased.envelope_id];
    const otherJobKey = [otherJob.tenant_id, otherJob.envelope_id];
    const approvalRowid = rowidOf(APPROVALS, 'tenant_id = ? AND id = ?', approvalKey);
    const jobRowid = rowidOf(JOBS, 'tenant_id = ? AND envelope_id = ?', jobKey);
    assert.ok(approvalRowid > 0 && jobRowid > 0, 'premise: ordinary inserts have positive rowids');
    const freeApprovalRowid = maxRowid(APPROVALS) + 1_000_000;
    const freeJobRowid = maxRowid(JOBS) + 1_000_000;
    const before = readOnly(world, (raw) => stateOn(raw, BOTH));

    // Other evidence for the victim's key; a new approval key (recipient 2, its prior the victim's digest).
    const otherEvidence = () => ({ field_values_json: '[]', field_values_digest: randomDigest(), approval_digest: randomDigest(), server_time: new Date(Date.parse(victimApproval.server_time) + MINUTE).toISOString() });
    const freshApprovalKey = () => ({ id: sid('appr'), recipient_id: secondRecipient.id, prior_approval_digest: victimApproval.approval_digest });
    const approvalReinsert = { label: 'then INSERT of the old key with other evidence', ...insertStatement('INSERT', { ...victimApproval, ...otherEvidence() }, null, APPROVALS), refusedBy: APPROVAL_KEY_EXISTS };
    // The job reset a replacement would perform; a new job key (the envelope with no reservation).
    const reset = { status: 'pending', attempt_count: 0, fencing_token: null, lease_owner: null, lease_expires_at: null, retry_at: null, last_error_code: null, version: 1, updated_at: leased.created_at };
    const freshJobKey = () => ({ envelope_id: two.envelope.id });
    const jobReinsert = { label: 'then INSERT of the old key with attempts, fencing token and lease reset', ...insertStatement('INSERT', { ...leased, ...reset }, null, JOBS), refusedBy: JOB_KEY_EXISTS };

    const problems = { approvals: Object.assign([], { attempts: 0 }), jobs: Object.assign([], { attempts: 0 }), positive: Object.assign([], { attempts: 0 }) };
    for (const mode of FK_MODES) {
      const tag = (route) => `${route} [foreign keys ${mode}]`;
      const approvalRoute = (route, steps) => attempt(problems.approvals, world.path, tag(`approvals ${route}`), mode, steps, BOTH);
      const jobRoute = (route, steps) => attempt(problems.jobs, world.path, tag(`signing_jobs ${route}`), mode, steps, BOTH);

      // approvals
      for (const verb of ['INSERT OR REPLACE', 'REPLACE']) {
        approvalRoute(`${verb} by key`, [{ label: `${verb} with the same key and other evidence`, ...insertStatement(verb, { ...victimApproval, ...otherEvidence() }, null, APPROVALS), refusedBy: APPROVAL_KEY_EXISTS }]);
        approvalRoute(`${verb} by recipient`, [{ label: `${verb} with a fresh id and the same recipient`, ...insertStatement(verb, { ...victimApproval, ...otherEvidence(), id: sid('appr') }, null, APPROVALS), refusedBy: APPROVAL_KEY_EXISTS }]);
      }
      for (const spelling of SPELLINGS) {
        approvalRoute(`insert by ${spelling}`, [
          { label: `INSERT OR REPLACE naming its ${spelling} with a new key`, ...insertStatement('INSERT OR REPLACE', { ...victimApproval, ...otherEvidence(), ...freshApprovalKey() }, { spelling, value: approvalRowid }, APPROVALS), refusedBy: APPROVAL_KEY_EXISTS },
          approvalReinsert,
        ]);
      }
      approvalRoute('update a column', [{ label: 'UPDATE of the approval digest', sql: `UPDATE ${APPROVALS} SET approval_digest = ? WHERE tenant_id = ? AND id = ?`, params: [randomDigest(), ...approvalKey], refusedBy: APPROVAL_IMMUTABLE }]);
      approvalRoute('update the rowid', [{ label: 'UPDATE of its rowid to a free value', sql: `UPDATE ${APPROVALS} SET rowid = ? WHERE tenant_id = ? AND id = ?`, params: [freeApprovalRowid, ...approvalKey], refusedBy: APPROVAL_IMMUTABLE }]);
      approvalRoute('another row onto its rowid', [{ label: 'UPDATE OR REPLACE of another approval onto its rowid', sql: `UPDATE OR REPLACE ${APPROVALS} SET rowid = ? WHERE tenant_id = ? AND id = ?`, params: [approvalRowid, ...otherApprovalKey], refusedBy: APPROVAL_IMMUTABLE }, approvalReinsert]);
      approvalRoute('another row onto its key', [{ label: 'UPDATE OR REPLACE of another approval onto its key', sql: `UPDATE OR REPLACE ${APPROVALS} SET id = ? WHERE tenant_id = ? AND id = ?`, params: [victimApproval.id, ...otherApprovalKey], refusedBy: APPROVAL_IMMUTABLE }, approvalReinsert]);
      approvalRoute('another row onto its recipient', [{ label: 'UPDATE OR REPLACE of another approval onto its recipient', sql: `UPDATE OR REPLACE ${APPROVALS} SET recipient_id = ? WHERE tenant_id = ? AND id = ?`, params: [victimApproval.recipient_id, ...otherApprovalKey], refusedBy: APPROVAL_IMMUTABLE }]);
      approvalRoute('delete and re-insert', [{ label: 'DELETE', sql: `DELETE FROM ${APPROVALS} WHERE tenant_id = ? AND id = ?`, params: approvalKey, refusedBy: APPROVAL_IMMUTABLE }, approvalReinsert]);
      approvalRoute('delete every row', [{ label: 'DELETE of the whole table', sql: `DELETE FROM ${APPROVALS}`, params: [], refusedBy: APPROVAL_IMMUTABLE }]);
      for (const value of [0, -1, -2]) {
        approvalRoute(`rowid ${value}`, [{ label: `INSERT with rowid ${value} and a fresh key`, ...insertStatement('INSERT', { ...victimApproval, ...otherEvidence(), ...freshApprovalKey() }, { spelling: 'rowid', value }, APPROVALS), refusedBy: APPROVAL_ROWID_POSITIVE }]);
      }

      // signing_jobs
      for (const verb of ['INSERT OR REPLACE', 'REPLACE']) {
        jobRoute(`${verb} by key after the lease`, [{ label: `${verb} of (tenant_id, envelope_id) with attempts, fencing token and lease reset`, ...insertStatement(verb, { ...leased, ...reset }, null, JOBS), refusedBy: JOB_KEY_EXISTS }]);
      }
      for (const spelling of SPELLINGS) {
        jobRoute(`insert by ${spelling}`, [
          { label: `INSERT OR REPLACE naming its ${spelling} with a new key`, ...insertStatement('INSERT OR REPLACE', { ...leased, ...reset, ...freshJobKey() }, { spelling, value: jobRowid }, JOBS), refusedBy: JOB_KEY_EXISTS },
          jobReinsert,
        ]);
      }
      jobRoute('update the rowid', [{ label: 'UPDATE of its rowid to a free value', sql: `UPDATE ${JOBS} SET rowid = ? WHERE tenant_id = ? AND envelope_id = ?`, params: [freeJobRowid, ...jobKey], refusedBy: JOB_ROWID_KEY_FIXED }]);
      jobRoute('update the envelope', [{ label: 'UPDATE of its envelope_id', sql: `UPDATE ${JOBS} SET envelope_id = ? WHERE tenant_id = ? AND envelope_id = ?`, params: [two.envelope.id, ...jobKey], refusedBy: JOB_KEY_CHANGE }]);
      jobRoute('update the tenant', [{ label: 'UPDATE of its tenant_id', sql: `UPDATE ${JOBS} SET tenant_id = ? WHERE tenant_id = ? AND envelope_id = ?`, params: [world.tenantId('beta'), ...jobKey], refusedBy: JOB_KEY_CHANGE }]);
      jobRoute('another job onto its rowid', [{ label: 'UPDATE OR REPLACE of another job onto its rowid', sql: `UPDATE OR REPLACE ${JOBS} SET rowid = ? WHERE tenant_id = ? AND envelope_id = ?`, params: [jobRowid, ...otherJobKey], refusedBy: JOB_ROWID_KEY_FIXED }, jobReinsert]);
      jobRoute('another job onto its key', [{ label: 'UPDATE OR REPLACE of another job onto its key', sql: `UPDATE OR REPLACE ${JOBS} SET envelope_id = ? WHERE tenant_id = ? AND envelope_id = ?`, params: [leased.envelope_id, ...otherJobKey], refusedBy: JOB_KEY_CHANGE }, jobReinsert]);
      jobRoute('delete and re-insert', [{ label: 'DELETE', sql: `DELETE FROM ${JOBS} WHERE tenant_id = ? AND envelope_id = ?`, params: jobKey, refusedBy: JOB_NEVER_DELETED }, jobReinsert]);
      jobRoute('delete every row', [{ label: 'DELETE of the whole table', sql: `DELETE FROM ${JOBS}`, params: [], refusedBy: JOB_NEVER_DELETED }]);
      for (const value of [0, -1, -2]) {
        jobRoute(`rowid ${value}`, [{ label: `INSERT with rowid ${value} and a fresh key`, ...insertStatement('INSERT', { ...leased, ...reset, ...freshJobKey() }, { spelling: 'rowid', value }, JOBS), refusedBy: JOB_ROWID_POSITIVE }]);
      }
    }
    assert.equal(problems.approvals.attempts, 3 * APPROVAL_ROUTES, 'every approvals route in every foreign-key mode');
    assert.equal(problems.jobs.attempts, 3 * JOB_ROUTES, 'every signing_jobs route in every foreign-key mode');
    assert.deepEqual([...problems.approvals], [], `approvals: every route is refused by its trigger and leaves both tables unchanged (${problems.approvals.length} problems; first: ${problems.approvals[0]})`);
    assert.deepEqual([...problems.jobs], [], `signing_jobs: every route is refused by its trigger and leaves both tables unchanged (${problems.jobs.length} problems; first: ${problems.jobs[0]})`);
    assert.equal(readOnly(world, (raw) => stateOn(raw, BOTH)), before, 'both tables, rowids included, are unchanged');

    // Through the tenant-scoped store: a duplicate is the same trigger constraint; a job delete is refused.
    assert.throws(
      () => world.db.transaction(() => insertFinalizationReservation(store, { envelopeId: leased.envelope_id, reservedVersion: leased.reserved_version, maxAttempts: 5, now: leased.created_at })),
      (error) => error instanceof StorageConstraintError && error.constraint === 'trigger' && JOB_KEY_EXISTS.test(error.message),
      'a second reservation through the repository',
    );
    assert.throws(
      () =>
        world.db.transaction(() =>
          insertApproval(store, {
            id: victimApproval.id,
            envelopeId: victimApproval.envelope_id,
            recipientId: victimApproval.recipient_id,
            documentDigest: victimApproval.document_digest,
            manifestDigest: victimApproval.manifest_digest,
            priorApprovalDigest: victimApproval.prior_approval_digest,
            consentTextId: victimApproval.consent_text_id,
            consentVersion: victimApproval.consent_version,
            consentTextDigest: victimApproval.consent_text_digest,
            fieldValuesJson: '[]',
            fieldValuesDigest: randomDigest(),
            serverTime: victimApproval.server_time,
            approvalDigest: randomDigest(),
          }),
        ),
      (error) => error instanceof StorageConstraintError && error.constraint === 'trigger' && APPROVAL_KEY_EXISTS.test(error.message),
      'a second approval through the repository',
    );
    assert.throws(() => world.db.transaction(() => store.delete(JOBS, { envelope_id: leased.envelope_id })), (error) => error instanceof StorageConstraintError && error.constraint === 'trigger' && JOB_NEVER_DELETED.test(error.message), 'the store’s delete of a job');
    assert.equal(readOnly(world, (raw) => stateOn(raw, BOTH)), before, 'still unchanged');

    // The positive case, continued: every update the runner and the operator retry make still lands.
    let version = leased.version;
    const step = (label, values) => {
      legitimate(world, label, () => store.compareAndSet(JOBS, { envelope_id: leased.envelope_id }, version, values));
      version += 1;
    };
    step('the runner renews its lease', { lease_expires_at: jobAt(leased, 10), updated_at: jobAt(leased, 2) });
    step('the attempt fails: retryable, with a retry time and an error code', { status: 'retryable', lease_owner: null, lease_expires_at: null, retry_at: jobAt(leased, 4), last_error_code: 'seal.unavailable', updated_at: jobAt(leased, 3) });
    step('the runner is granted a second lease (attempt 2, fencing token 2)', { status: 'running', attempt_count: 2, fencing_token: 2, lease_owner: 'runner-ap13-2', lease_expires_at: jobAt(leased, 10), retry_at: null, updated_at: jobAt(leased, 5) });
    step('the attempt fails: failed', { status: 'failed', lease_owner: null, lease_expires_at: null, last_error_code: 'verify.failed', updated_at: jobAt(leased, 6) });
    step('the operator retries: retryable now, max_attempts raised', { status: 'retryable', retry_at: jobAt(leased, 7), max_attempts: leased.max_attempts + 1, updated_at: jobAt(leased, 7) });
    step('the runner is granted a third lease (attempt 3, fencing token 3)', { status: 'running', attempt_count: 3, fencing_token: 3, lease_owner: 'runner-ap13-3', lease_expires_at: jobAt(leased, 12), retry_at: null, updated_at: jobAt(leased, 8) });
    step('the attempt succeeds', { status: 'succeeded', lease_owner: null, lease_expires_at: null, updated_at: jobAt(leased, 9) });
    const [done] = world.rows(JOBS, 'WHERE envelope_id = ?', [leased.envelope_id]);
    assert.deepEqual(
      { status: done.status, attempt_count: done.attempt_count, fencing_token: done.fencing_token, max_attempts: done.max_attempts, version: done.version, reserved_version: done.reserved_version, rowid: rowidOf(JOBS, 'tenant_id = ? AND envelope_id = ?', jobKey) },
      { status: 'succeeded', attempt_count: 3, fencing_token: 3, max_attempts: leased.max_attempts + 1, version: leased.version + 7, reserved_version: leased.reserved_version, rowid: jobRowid },
      'every legitimate update landed on the same row, rowid, key and reservation',
    );
    for (const mode of FK_MODES) {
      legitimateRaw(problems.positive, world.path, `signing_jobs legitimate updates [foreign keys ${mode}]`, mode, [
        { label: 'a lease grant', sql: `UPDATE ${JOBS} SET status = 'running', attempt_count = attempt_count + 1, fencing_token = attempt_count + 1, lease_owner = ?, lease_expires_at = ?, version = version + 1, updated_at = ? WHERE tenant_id = ? AND envelope_id = ?`, params: ['runner-ap13-raw', jobAt(otherJob, 5), jobAt(otherJob, 1), ...otherJobKey] },
        { label: 'a failure with a retry time', sql: `UPDATE ${JOBS} SET status = 'retryable', lease_owner = NULL, lease_expires_at = NULL, retry_at = ?, last_error_code = ?, version = version + 1, updated_at = ? WHERE tenant_id = ? AND envelope_id = ?`, params: [jobAt(otherJob, 4), 'seal.unavailable', jobAt(otherJob, 3), ...otherJobKey] },
      ]);
    }
    assert.equal(problems.positive.attempts, FK_MODES.length);
    assert.deepEqual([...problems.positive], [], `positive: the raw lease grant and failure update run in every foreign-key mode (first: ${problems.positive[0]})`);

    // A new approval still inserts its approval and its reservation.
    const approvalsBefore = world.rows(APPROVALS).length;
    const jobsBefore = world.rows(JOBS).length;
    const fresh = await approvedByFirst(world, { recipients: 1 });
    assert.equal(world.rows(APPROVALS).length, approvalsBefore + 1, 'an ordinary approval inserts');
    assert.equal(world.rows(JOBS, 'WHERE envelope_id = ?', [fresh.envelope.id]).length, 1, 'and its reservation');
    assert.equal(world.rows(JOBS).length, jobsBefore + 1);
    assert.ok(rowidOf(JOBS, 'tenant_id = ? AND envelope_id = ?', [leased.tenant_id, fresh.envelope.id]) > 0, 'with a positive rowid');

    // Inventory: the keys, the triggers and the migrations.
    assert.deepEqual(readOnly(world, (raw) => uniqueKeysOf(raw, APPROVALS)), ['tenant_id,envelope_id,recipient_id,id', 'tenant_id,id', 'tenant_id,recipient_id'], 'every approvals unique key is one the routes above try');
    assert.deepEqual(readOnly(world, (raw) => uniqueKeysOf(raw, JOBS)), ['tenant_id,envelope_id'], 'the signing_jobs key is the one the routes above try');
    const triggersOf = (table) => readOnly(world, (raw) => raw.prepare("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name = ? ORDER BY name").all(table).map((row) => row.name));
    assert.deepEqual(triggersOf(APPROVALS), [...APPROVAL_TRIGGERS], 'the 0003 and 0018 triggers on approvals');
    assert.deepEqual(triggersOf(JOBS), [...JOB_TRIGGERS], 'the 0004 and 0018 triggers on signing_jobs');
    for (const table of BOTH) assert.equal(readOnly(world, (raw) => raw.prepare('SELECT strict FROM pragma_table_list WHERE name = ?').get(table).strict), 1, `${table} is STRICT`);

    const migrations = loadMigrations();
    assert.ok(migrations.length >= 18, 'migration 18 exists');
    assert.deepEqual(migrations.slice(0, 17).map((entry) => ({ version: entry.version, name: entry.name, sha256: entry.sha256 })), PINNED_0001_0017.map((entry) => ({ ...entry })), '0001..0017 are byte-identical and in order');
    const actual = migrations[PINNED_0018.version - 1];
    assert.deepEqual({ version: actual.version, name: actual.name, sha256: actual.sha256 }, PINNED_0018, 'migration 18 is unchanged: append a new one instead');
    const applied = world.rows('schema_migrations', 'WHERE version = 18');
    assert.equal(applied.length, 1, '0018 is applied');
    assert.equal(applied[0].sha256, PINNED_0018.sha256);
  } finally {
    await world.close();
  }
});
