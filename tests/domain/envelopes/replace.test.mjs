// SPDX-License-Identifier: Apache-2.0
//
// No envelope row is ever replaced, re-keyed or deleted (T007 slot; A-010
// REPLACE-ENV and ROWID-ENV; migration 0015). The 0010 guards are UPDATE
// triggers. REPLACE resolves a key conflict by deleting the row that holds the
// key, and with recursive triggers off, the default, that implicit delete fires
// no delete trigger and the new row meets no update trigger; a plain DELETE
// meets no update trigger either. An envelope is a rowid table, so its hidden
// rowid (spelled rowid, _rowid_ or oid) is a key as well. ST-16 tries every
// route on a raw connection to the file, with foreign keys off, on, and on but
// deferred inside one transaction (where a delete and a re-insert satisfy every
// referencing row again by COMMIT):
// - INSERT OR REPLACE and REPLACE of the existing key, rolling the envelope back;
// - INSERT OR REPLACE naming the envelope's rowid with a new key, then a
//   re-insert under the old key;
// - UPDATE OR REPLACE of another envelope onto this one's rowid or key;
// - DELETE, then a re-insert under the old key;
// - explicit rowids -1, 0 and -2.
// Each is refused by a 0015 trigger and the envelope, with its referencing rows,
// is unchanged. An ordinary insert still succeeds, and a duplicate key surfaces
// as a trigger constraint, which the store reports as storage_constraint.

import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';

import { StorageConstraintError } from '../../../src/storage/db/index.ts';
import { createInput, createTenant, envelopeRow, hex, makeScratch, rawConnection, req, sentEnvelope, setup, sid } from './support.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

/** SQLite's extended result code for a RAISE(ABORT) in a trigger. */
const SQLITE_CONSTRAINT_TRIGGER = 1811;
const KEY_EXISTS = /envelopes key exists: an envelope row is never replaced/;
const KEY_FIXED = /envelopes key and rowid never change/;
const NO_DELETE = /envelopes rows are never deleted/;
const ROWID_POSITIVE = /envelopes rowid must be positive/;
const CHILDREN = ['recipients', 'document_revisions', 'field_definitions', 'field_manifests'];
const MODES = ['foreign keys off', 'foreign keys on', 'foreign keys deferred'];
const ALIASES = ['rowid', '_rowid_', 'oid'];
/** A draft without frozen references: a row any route could insert with no dangling foreign key. */
const DRAFT = Object.freeze({ state: 'draft', version: 1, base_revision_id: null, manifest_digest: null, recipients_digest: null, approvals_complete: 0, reissue_of: null, reissued_as: null });

function thrown(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

function connect(path, mode) {
  return mode === 'foreign keys off' ? new DatabaseSync(path, { enableForeignKeyConstraints: false }) : rawConnection(path);
}

/**
 * Run `statements` ([sql, params]) on a fresh raw connection in `mode`; deferred
 * mode runs them inside one transaction with defer_foreign_keys on and commits
 * only if every one ran. Returns the error of each statement (undefined if it
 * ran), stopping at nothing, so a route's later step is tried too.
 */
function attempt(path, mode, statements) {
  const raw = connect(path, mode);
  try {
    if (mode === 'foreign keys deferred') raw.exec('BEGIN; PRAGMA defer_foreign_keys = ON;');
    const errors = statements.map(([sql, params]) => thrown(() => raw.prepare(sql).run(...params)));
    if (mode === 'foreign keys deferred') {
      if (errors.every((error) => error === undefined)) {
        const commit = thrown(() => raw.exec('COMMIT'));
        if (commit !== undefined) {
          raw.exec('ROLLBACK');
          errors.push(commit);
        }
      } else {
        raw.exec('ROLLBACK');
      }
    }
    return errors;
  } finally {
    raw.close();
  }
}

function snapshot(path, tenant, id) {
  const raw = rawConnection(path);
  try {
    const row = raw.prepare('SELECT rowid AS rid, * FROM envelopes WHERE tenant_id = ? AND id = ?').get(tenant, id);
    const children = Object.fromEntries(
      CHILDREN.map((table) => [table, raw.prepare(`SELECT count(*) AS n FROM ${table} WHERE tenant_id = ? AND envelope_id = ?`).get(tenant, id).n]),
    );
    return { row: row === undefined ? undefined : { ...row }, children };
  } finally {
    raw.close();
  }
}

/** An INSERT of `row`; `rowid` names the rowid column spelling and value when given. */
function insert(verb, row, rowid) {
  const columns = Object.keys(row);
  const names = rowid === undefined ? columns : [rowid.name, ...columns];
  const params = rowid === undefined ? columns.map((name) => row[name]) : [rowid.value, ...columns.map((name) => row[name])];
  return [`${verb} envelopes (${names.join(', ')}) VALUES (${names.map(() => '?').join(', ')})`, params];
}

function stored(snap) {
  const row = { ...snap.row };
  delete row.rid;
  return row;
}

function assertRefused(error, pattern, what) {
  assert.equal(error?.errcode, SQLITE_CONSTRAINT_TRIGGER, `${what}: refused (${error === undefined ? 'it ran' : `${error.errcode} ${error.message}`})`);
  assert.match(error.message, pattern, `${what}: by the 0015 trigger`);
}

/** A sent envelope with its recipients, revision, fields and manifest, and its snapshot. */
function world() {
  const ctx = setup(scratch);
  const sent = sentEnvelope(ctx);
  const before = snapshot(ctx.path, ctx.tenant, sent.id);
  assert.equal(before.row.state, 'sent');
  assert.ok(before.row.manifest_digest && before.row.recipients_digest && before.row.base_revision_id, 'the sent envelope carries its frozen digests');
  assert.ok(Object.values(before.children).every((n) => n > 0), 'the envelope has referencing rows');
  return { ctx, sent, before };
}

test('[ST-16] INSERT OR REPLACE and REPLACE of an existing key cannot roll back its state, version or frozen digests, with foreign keys off, on or deferred', () => {
  const { ctx, sent, before } = world();
  try {
    const rollbacks = {
      'back to draft at version 1 without its frozen digests': DRAFT,
      'back to version 1': { version: 1 },
      'to other frozen digests': { manifest_digest: hex('st16-replaced-manifest'), recipients_digest: hex('st16-replaced-recipients') },
    };
    for (const mode of MODES) {
      for (const verb of ['INSERT OR REPLACE INTO', 'REPLACE INTO']) {
        for (const [label, change] of Object.entries(rollbacks)) {
          const [error] = attempt(ctx.path, mode, [insert(verb, { ...stored(before), ...change })]);
          assertRefused(error, KEY_EXISTS, `${mode}, ${verb}, ${label}`);
          assert.deepEqual(snapshot(ctx.path, ctx.tenant, sent.id), before, `${mode}, ${verb}, ${label}: unchanged`);
        }
      }
      // An upsert's DO UPDATE is an UPDATE; 0015 refuses the insert before it.
      const [upsert] = attempt(ctx.path, mode, [insert('INSERT INTO', { ...stored(before), version: 1 })].map(([sql, params]) => [`${sql} ON CONFLICT (tenant_id, id) DO UPDATE SET version = excluded.version`, params]));
      assertRefused(upsert, KEY_EXISTS, `${mode}, upsert`);
      assert.deepEqual(snapshot(ctx.path, ctx.tenant, sent.id), before, `${mode}, upsert: unchanged`);
    }
  } finally {
    ctx.db.close();
  }
});

test('[ST-16] INSERT OR REPLACE naming the envelope\'s rowid (rowid, _rowid_, oid) with a new key, then a re-insert under the old key, is refused in every foreign-key mode', () => {
  const { ctx, sent, before } = world();
  try {
    for (const mode of MODES) {
      for (const alias of ALIASES) {
        const moved = { ...stored(before), ...DRAFT, id: sid('st16-moved') };
        const back = { ...stored(before), ...DRAFT };
        const [step1, step2] = attempt(ctx.path, mode, [insert('INSERT OR REPLACE INTO', moved, { name: alias, value: before.row.rid }), insert('INSERT INTO', back)]);
        assertRefused(step1, KEY_EXISTS, `${mode}, ${alias}: the replacement by rowid`);
        assertRefused(step2, KEY_EXISTS, `${mode}, ${alias}: the re-insert under the old key`);
        assert.deepEqual(snapshot(ctx.path, ctx.tenant, sent.id), before, `${mode}, ${alias}: unchanged`);
        assert.equal(snapshot(ctx.path, ctx.tenant, moved.id).row, undefined, `${mode}, ${alias}: no row under the new key`);
      }
    }
  } finally {
    ctx.db.close();
  }
});

test('[ST-16] UPDATE OR REPLACE of another envelope onto this one\'s rowid or key, and any change of a rowid or key, is refused in every foreign-key mode', () => {
  const { ctx, sent, before } = world();
  try {
    const other = ctx.service.create(req(ctx.tenant), createInput(1)).body;
    const otherBefore = snapshot(ctx.path, ctx.tenant, other.id);
    const back = { ...stored(before), ...DRAFT };
    for (const mode of MODES) {
      for (const alias of ALIASES) {
        const [update, reinsert] = attempt(ctx.path, mode, [
          [`UPDATE OR REPLACE envelopes SET ${alias} = ? WHERE tenant_id = ? AND id = ?`, [before.row.rid, ctx.tenant, other.id]],
          insert('INSERT INTO', back),
        ]);
        assertRefused(update, KEY_FIXED, `${mode}, UPDATE OR REPLACE onto the ${alias}`);
        assertRefused(reinsert, KEY_EXISTS, `${mode}, ${alias}: the re-insert under the old key`);
      }
      const [onKey] = attempt(ctx.path, mode, [[`UPDATE OR REPLACE envelopes SET id = ? WHERE tenant_id = ? AND id = ?`, [sent.id, ctx.tenant, other.id]]]);
      assertRefused(onKey, KEY_FIXED, `${mode}, UPDATE OR REPLACE onto the key`);
      const free = before.row.rid + 1_000;
      for (const [label, sql, params] of [
        ['a plain rowid change', 'UPDATE envelopes SET rowid = ? WHERE tenant_id = ? AND id = ?', [free, ctx.tenant, sent.id]],
        ['a new id', 'UPDATE envelopes SET id = ? WHERE tenant_id = ? AND id = ?', [sid('st16-renamed'), ctx.tenant, sent.id]],
      ]) {
        const [error] = attempt(ctx.path, mode, [[sql, params]]);
        assertRefused(error, KEY_FIXED, `${mode}, ${label}`);
      }
      assert.deepEqual(snapshot(ctx.path, ctx.tenant, sent.id), before, `${mode}: this envelope is unchanged`);
      assert.deepEqual(snapshot(ctx.path, ctx.tenant, other.id), otherBefore, `${mode}: the other envelope is unchanged`);
    }
  } finally {
    ctx.db.close();
  }
});

test('[ST-16] a plain DELETE of an envelope, then a re-insert under its key, is refused in every foreign-key mode', () => {
  const { ctx, sent, before } = world();
  try {
    for (const mode of MODES) {
      const [deleted, reinsert] = attempt(ctx.path, mode, [
        ['DELETE FROM envelopes WHERE tenant_id = ? AND id = ?', [ctx.tenant, sent.id]],
        insert('INSERT INTO', { ...stored(before), ...DRAFT }),
      ]);
      assertRefused(deleted, NO_DELETE, `${mode}, DELETE`);
      assertRefused(reinsert, KEY_EXISTS, `${mode}, the re-insert under the key`);
      assert.deepEqual(snapshot(ctx.path, ctx.tenant, sent.id), before, `${mode}: unchanged`);
    }
  } finally {
    ctx.db.close();
  }
});

test('[ST-16] explicit rowids -1, 0 and -2 cannot be stored, so no zero or negative rowid can stand in for an omitted one', () => {
  const { ctx, sent, before } = world();
  try {
    for (const value of [-1, 0, -2]) {
      for (const verb of ['INSERT INTO', 'INSERT OR REPLACE INTO']) {
        const row = { tenant_id: ctx.tenant, ...envelopeRow(sid('st16-sentinel')) };
        const [error] = attempt(ctx.path, 'foreign keys on', [insert(verb, row, { name: 'rowid', value })]);
        assertRefused(error, ROWID_POSITIVE, `${verb} at rowid ${value}`);
        assert.equal(snapshot(ctx.path, ctx.tenant, row.id).row, undefined, `rowid ${value}: nothing stored`);
      }
    }
    const raw = rawConnection(ctx.path);
    try {
      assert.equal(raw.prepare('SELECT count(*) AS n FROM envelopes WHERE rowid <= 0').get().n, 0, 'no stored rowid is 0 or less');
    } finally {
      raw.close();
    }
    assert.deepEqual(snapshot(ctx.path, ctx.tenant, sent.id), before);
  } finally {
    ctx.db.close();
  }
});

test('[ST-16] ordinary semantics: an insert without a rowid succeeds, and a duplicate key surfaces as a trigger constraint, reported as storage_constraint', (t) => {
  const { ctx, sent, before } = world();
  const raw = rawConnection(ctx.path);
  try {
    // NEW.rowid is undefined in a BEFORE INSERT trigger when no rowid is given; 0015 relies on it never equalling a stored rowid.
    raw.exec('CREATE TEMP TABLE st16_seen (v ANY); CREATE TEMP TRIGGER st16_seen_rowid BEFORE INSERT ON main.envelopes BEGIN INSERT INTO st16_seen VALUES (NEW.rowid); END;');
    const fresh = { tenant_id: ctx.tenant, ...envelopeRow(sid('st16-fresh')) };
    const [sql, params] = insert('INSERT INTO', fresh);
    raw.prepare(sql).run(...params);
    const seen = raw.prepare('SELECT v FROM st16_seen').get().v;
    t.diagnostic(`NEW.rowid in BEFORE INSERT without a rowid: ${seen}`);
    assert.ok(seen === null || (Number.isInteger(seen) && seen <= 0), 'it can never equal a stored rowid, all of which are positive');
    assert.equal(snapshot(ctx.path, ctx.tenant, fresh.id).row.state, 'draft', 'the ordinary insert succeeded');
    raw.exec('DROP TRIGGER temp.st16_seen_rowid; DROP TABLE temp.st16_seen;');

    assert.equal(ctx.service.create(req(ctx.tenant), createInput(1)).body.version, 1, 'the domain creates as before');
    const otherTenant = sid('st16-tenant');
    createTenant(ctx.db, otherTenant);
    const sameIdElsewhere = insert('INSERT INTO', { tenant_id: otherTenant, ...envelopeRow(sent.id) });
    raw.prepare(sameIdElsewhere[0]).run(...sameIdElsewhere[1]);
    assert.equal(snapshot(ctx.path, otherTenant, sent.id).row.version, 1, 'the same id in another tenant is another key, and inserts');

    const [duplicateSql, duplicateParams] = insert('INSERT INTO', stored(before));
    const duplicate = thrown(() => raw.prepare(duplicateSql).run(...duplicateParams));
    assertRefused(duplicate, KEY_EXISTS, 'a plain duplicate insert');
    const values = stored(before);
    delete values.tenant_id;
    const viaStore = thrown(() => ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).insert('envelopes', values)));
    assert.ok(viaStore instanceof StorageConstraintError, `the store reports a constraint error: ${viaStore}`);
    assert.equal(viaStore.code, 'storage_constraint');
    assert.equal(viaStore.constraint, 'trigger', 'a trigger constraint, not the primary key');
    assert.deepEqual(snapshot(ctx.path, ctx.tenant, sent.id), before, 'the original envelope is untouched');
  } finally {
    raw.close();
    ctx.db.close();
  }
});
