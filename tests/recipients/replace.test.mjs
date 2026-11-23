// SPDX-License-Identifier: Apache-2.0
//
// T008, review finding F3: migration 0014 refuses every insert whose key
// already exists on invitations, challenges and recipient_sessions, so
// INSERT OR REPLACE cannot reset a wrong-code count, a locked challenge, a
// supersession, a revocation or a CSRF secret (CH-08).
//
// The keys are every uniqueness constraint of those tables (0003): the
// composite primary key (tenant_id, id) on all three, and the global
// UNIQUE (token_hash) on invitations and UNIQUE (value_hash) on
// recipient_sessions. REPLACE deletes the row holding any of them, so each
// table is tried by every route it has: (1) the same tenant and id; (2) a fresh
// id with an existing hash in the same tenant; (3) a fresh id with an existing
// hash in another tenant. Each statement runs on a raw connection to the file,
// with foreign keys off (the default of any new connection, and the case where
// nothing else would stop the replacement) and on. Hash and capability values
// are generated in memory only; messages carry labels.
//
// A-010 ROWID-CER: every row of those rowid tables also has a hidden integer
// rowid (one column spelled rowid, _rowid_ or oid), unique as well, which
// 0014's key check does not see. Migration 0016 closes that route, and the
// second CH-08 case tries every way through it (the route list of T007's
// ST-16): INSERT OR REPLACE naming an existing rowid with a new key and then a
// re-insert of the old key, in each spelling; a plain UPDATE of the rowid;
// UPDATE OR REPLACE of another row onto the rowid, onto the key and onto the
// hash; a delete followed by a re-insert; and rowids -1, 0 and -2. Each runs on
// a raw connection with foreign keys off, on, and on but deferred within one
// transaction. Every statement must be refused by its trigger and leave the
// whole table, rowids included, unchanged. An ordinary insert still succeeds,
// and a duplicate key still surfaces as a trigger constraint, which the app
// reports as storage_constraint.

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

import { StorageConstraintError } from '../../src/storage/db/index.ts';
import { loadMigrations } from '../../src/storage/schema/migrations.ts';
import { createTenant } from '../storage/support/fixtures.mjs';
import { COOKIE, ORIGIN, createSession, createWorld, openSession, readAs, requestChallenge, requestCode, sentEnvelope, sid, wrongCode } from './support.mjs';

/** The 0016 file (A-010 ROWID-CER), pinned as 0013 and 0014 are: later changes append a migration. */
const PINNED_0016 = Object.freeze({ version: 16, name: '0016-recipient-ceremony-rowid-fixed.sql', sha256: 'a217a3ea6b2982a35ff687ed9c2db74046dc707cdd761bdc61a3c7e3936bc460' });

/** The 0014 file, pinned as 0013 is (CH-05): later changes append a migration. */
const PINNED_0014 = Object.freeze({ version: 14, name: '0014-recipient-ceremony-no-replace.sql', sha256: '20dfbb5ad613e1016ca7bb940ec5a37d5cb8887b3d80335164cd8183e25d8116' });

const KEY_EXISTS = Object.freeze({
  invitations: /invitations key exists: an invitation row is never replaced/,
  challenges: /challenges key exists: a challenge row is never replaced/,
  recipient_sessions: /recipient_sessions key exists: a session row is never replaced/,
});

/** 0016's refusals. */
const ROWID_EXISTS = Object.freeze({
  invitations: /^invitations rowid exists: a row is never replaced through its rowid$/,
  challenges: /^challenges rowid exists: a row is never replaced through its rowid$/,
  recipient_sessions: /^recipient_sessions rowid exists: a row is never replaced through its rowid$/,
});
const ROWID_KEY_FIXED = Object.freeze({
  invitations: /^invitations rowid and key never change$/,
  challenges: /^challenges rowid and key never change$/,
  recipient_sessions: /^recipient_sessions rowid and key never change$/,
});
const ROWID_POSITIVE = Object.freeze({
  invitations: /^invitations rowid must be positive$/,
  challenges: /^challenges rowid must be positive$/,
  recipient_sessions: /^recipient_sessions rowid must be positive$/,
});
/** A key change: 0016's trigger, or 0003's bound-column trigger (both refuse it; whichever SQLite fires first). */
const KEY_CHANGE = Object.freeze({
  invitations: /^(invitations rowid and key never change|invitations binding columns are immutable)$/,
  challenges: /^(challenges rowid and key never change|challenges binding columns are immutable)$/,
  recipient_sessions: /^(recipient_sessions rowid and key never change|recipient_sessions binding columns are immutable)$/,
});
/** Deletes: 0013 on invitations and challenges, 0016 on recipient_sessions. */
const RETAINED = Object.freeze({
  invitations: /^invitations rows are retained$/,
  challenges: /^challenges rows are retained$/,
  recipient_sessions: /^recipient_sessions rows are retained$/,
});
/** What a replacement would reset, per table (fresh values for each call). */
const RESET = Object.freeze({
  invitations: () => ({ cumulative_wrong_codes: 0, revoked_at: null }),
  challenges: () => ({ attempts: 0, consumed_at: null, superseded_at: null }),
  recipient_sessions: () => ({ revoked_at: null, csrf_secret: randomBytes(32) }),
});
const HASH_COLUMN = Object.freeze({ invitations: 'token_hash', challenges: null, recipient_sessions: 'value_hash' });
const SPELLINGS = Object.freeze(['rowid', '_rowid_', 'oid']);
/** Foreign keys off; on; on but deferred, with every step of the route in one transaction. */
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

/** Every trigger on the three tables once 0016 is applied: 0003, 0013, 0014 and 0016. */
const CEREMONY_TRIGGERS = Object.freeze([
  'challenges_attempts_monotonic',
  'challenges_bound_columns',
  'challenges_key_exists',
  'challenges_retained',
  'challenges_rowid_exists',
  'challenges_rowid_key_fixed',
  'challenges_rowid_positive',
  'challenges_single_use',
  'challenges_supersession_final',
  'invitations_bound_columns',
  'invitations_expiry_fixed',
  'invitations_key_exists',
  'invitations_retained',
  'invitations_revocation_final',
  'invitations_rowid_exists',
  'invitations_rowid_key_fixed',
  'invitations_rowid_positive',
  'invitations_wrong_codes_monotonic',
  'recipient_sessions_bound_columns',
  'recipient_sessions_csrf_immutable',
  'recipient_sessions_csrf_required',
  'recipient_sessions_key_exists',
  'recipient_sessions_retained',
  'recipient_sessions_revocation_final',
  'recipient_sessions_rowid_exists',
  'recipient_sessions_rowid_key_fixed',
  'recipient_sessions_rowid_positive',
]);

/** Every uniqueness constraint 0003 declares on the three tables; CH-08 tries each of them. */
const UNIQUE_KEYS = Object.freeze({
  invitations: [['tenant_id', 'id'], ['token_hash']],
  challenges: [['tenant_id', 'id']],
  recipient_sessions: [['tenant_id', 'id'], ['value_hash']],
});

function freshHash() {
  return createHash('sha256').update(randomBytes(32)).digest('hex');
}

/** The whole table, every column of every row and its rowid, in rowid order (BLOBs as hex). */
function tableState(world, table) {
  const raw = new DatabaseSync(world.path, { readOnly: true });
  try {
    const rows = raw.prepare(`SELECT rowid AS hidden_rowid, * FROM ${table} ORDER BY rowid`).all();
    return JSON.stringify(rows.map((row) => Object.fromEntries(Object.entries(row).map(([column, value]) => [column, value instanceof Uint8Array ? `bytes:${Buffer.from(value).toString('hex')}` : value]))));
  } finally {
    raw.close();
  }
}

/** INSERT OR REPLACE `values` on a raw connection; returns the error, or null when the statement ran. */
function replaceRow(world, table, values, foreignKeys) {
  const raw = new DatabaseSync(world.path);
  try {
    raw.exec(`PRAGMA foreign_keys = ${foreignKeys ? 'ON' : 'OFF'}`);
    const columns = Object.keys(values);
    raw.prepare(`INSERT OR REPLACE INTO ${table} (${columns.join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`).run(...columns.map((column) => values[column]));
    return null;
  } catch (error) {
    return error;
  } finally {
    raw.close();
  }
}

function uniqueKeysOf(world, table) {
  const raw = new DatabaseSync(world.path, { readOnly: true });
  try {
    return raw
      .prepare(`PRAGMA index_list(${table})`)
      .all()
      .filter((index) => index.unique === 1)
      .map((index) => raw.prepare(`PRAGMA index_info(${JSON.stringify(index.name)})`).all().sort((a, b) => a.seqno - b.seqno).map((column) => column.name))
      .sort((a, b) => a.join(',').localeCompare(b.join(',')));
  } finally {
    raw.close();
  }
}

/** The hidden rowid of the row with this key (read only). */
function rowidOf(world, table, tenantId, id) {
  const raw = new DatabaseSync(world.path, { readOnly: true });
  try {
    return raw.prepare(`SELECT rowid AS r FROM ${table} WHERE tenant_id = ? AND id = ?`).get(tenantId, id)?.r;
  } finally {
    raw.close();
  }
}

/** The largest rowid in the table (read only). */
function maxRowid(world, table) {
  const raw = new DatabaseSync(world.path, { readOnly: true });
  try {
    return raw.prepare(`SELECT max(rowid) AS r FROM ${table}`).get().r;
  } finally {
    raw.close();
  }
}

/** An INSERT of `values`, optionally naming a rowid ({ spelling, value }) first. */
function insertStatement(verb, table, values, rowid = null) {
  const columns = Object.keys(values);
  const names = rowid === null ? columns : [rowid.spelling, ...columns];
  const params = rowid === null ? columns.map((column) => values[column]) : [rowid.value, ...columns.map((column) => values[column])];
  return { sql: `${verb} INTO ${table} (${names.join(', ')}) VALUES (${names.map(() => '?').join(', ')})`, params };
}

/** A refusal described by its kind and its (schema-defined) message; never a value. */
function describe(error) {
  return `${SQLITE_KINDS.get(error?.errcode) ?? 'another error'}: ${String(error?.message).slice(0, 120)}`;
}

/** The table's state as `raw` sees it (inside its own transaction): every column and the rowid. */
function stateOn(raw, table) {
  const rows = raw.prepare(`SELECT rowid AS hidden_rowid, * FROM ${table} ORDER BY rowid`).all();
  return JSON.stringify(rows.map((row) => Object.fromEntries(Object.entries(row).map(([column, value]) => [column, value instanceof Uint8Array ? `bytes:${Buffer.from(value).toString('hex')}` : value]))));
}

/**
 * Run a route's steps on a raw connection in foreign-key mode `mode`, inside one transaction
 * (with foreign keys deferred in 'deferred'). Each step must be refused by a trigger whose message
 * matches its `refusedBy`, and the table, rowids included, must be unchanged. Every miss is pushed
 * onto `problems` (labels and refusal kinds only), so a failing run names every open route.
 *
 * Each route is judged on the seeded state alone: when anything ran or changed, the transaction is
 * rolled back (in 'deferred', after asking SQLite's deferred foreign-key check whether the commit
 * would have been refused), so no route's damage reaches the next. When everything was refused,
 * the empty transaction is committed, as the route would be.
 */
function attempt(problems, path, tag, table, mode, steps) {
  problems.attempts += 1;
  const raw = new DatabaseSync(path, { enableForeignKeyConstraints: mode !== 'off' });
  try {
    raw.exec(mode === 'deferred' ? 'BEGIN; PRAGMA defer_foreign_keys = ON;' : 'BEGIN');
    const before = stateOn(raw, table);
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
    const changed = stateOn(raw, table) !== before;
    if (changed) problems.push(`${tag}: the table changed`);
    if (ran || changed) {
      if (mode === 'deferred' && raw.prepare('PRAGMA foreign_key_check').all().length > 0) problems.push(`${tag}: the deferred foreign-key check would refuse the commit`);
      raw.exec('ROLLBACK');
    } else {
      raw.exec('COMMIT');
    }
  } finally {
    raw.close();
  }
}

/**
 * A world whose envelope 1 has a live invitation with five wrong codes; a consumed, a superseded
 * and a locked challenge; and a session ended by its recipient (revoked, with its CSRF secret).
 * Envelope 2 has an invitation revoked by a resend. A second tenant exists.
 */
async function seeded(world) {
  // Envelope 1: a live invitation with five wrong codes; a consumed, a superseded and a locked
  // challenge; and a session ended by its recipient (revoked, with its CSRF secret).
  const first = await sentEnvelope(world);
  const opened = await openSession(world, first.token);
  const ended = await world.http({ method: 'DELETE', path: '/v1/recipient-session', headers: { origin: ORIGIN, cookie: `${COOKIE}=${opened.session}`, 'x-csrf-token': opened.csrf } });
  assert.equal(ended.status, 204, 'the session is ended');
  assert.ok((await requestCode(world, first.token)) !== null, 'a code that the next request supersedes');
  const lockedCode = await requestCode(world, first.token);
  assert.ok(lockedCode !== null);
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    assert.equal((await createSession(world, first.token, wrongCode(lockedCode, attempt))).status, 401, `wrong code ${attempt}`);
  }
  assert.equal((await createSession(world, first.token, lockedCode)).status, 429, 'the challenge is locked');
  // Envelope 2: an invitation revoked by a resend.
  const second = await sentEnvelope(world);
  await world.ceremony.run(() => world.db.transaction(() => world.ceremony.resendInvitation(world.store(), second.envelope.id, second.envelope.recipients[0].id)));
  assert.equal(world.takeMails('recipient_invitation').length, 1, 'the resend mails a fresh invitation');
  const otherTenant = sid('tenant');
  createTenant(world.db, otherTenant);

  const invitations = world.rows('invitations');
  const live = invitations.find((row) => row.envelope_id === first.envelope.id);
  const revoked = invitations.find((row) => row.envelope_id === second.envelope.id && row.revoked_at !== null);
  const challenges = world.rows('challenges').filter((row) => row.invitation_id === live.id);
  const superseded = challenges.find((row) => row.superseded_at !== null);
  const locked = challenges.find((row) => row.attempts === 5);
  const [session] = world.rows('recipient_sessions');
  assert.equal(live.cumulative_wrong_codes, 5, 'premise: the live invitation counts five wrong codes');
  assert.notEqual(revoked.revoked_at, null, 'premise: a revoked invitation');
  assert.ok(superseded && locked && locked.superseded_at === null && locked.consumed_at === null, 'premise: a superseded and a locked open challenge');
  assert.notEqual(session.revoked_at, null, 'premise: a revoked session');
  assert.ok(session.csrf_secret instanceof Uint8Array && session.csrf_secret.length >= 16, 'premise: the session has its CSRF secret');
  return { first, opened, lockedCode, second, otherTenant, live, revoked, superseded, locked, session };
}

test('[CH-08] INSERT OR REPLACE cannot replace an invitation, a challenge or a recipient session by any key: counters, the locked challenge, supersession, revocation and the CSRF secret stay as they were; migration 0014 is appended and pinned', async () => {
  const world = await createWorld();
  try {
    const { first, opened, lockedCode, second, otherTenant, live, revoked, superseded, locked, session } = await seeded(world);

    const routes = [];
    for (const [label, row] of [
      ['live invitation with five wrong codes', live],
      ['revoked invitation', revoked],
    ]) {
      const reset = { cumulative_wrong_codes: 0, revoked_at: null, expires_at: new Date(Date.parse(row.expires_at) + 60_000).toISOString() };
      routes.push(['invitations', `${label}: (1) same tenant and id, fresh token hash`, { ...row, ...reset, token_hash: freshHash() }]);
      routes.push(['invitations', `${label}: (2) fresh id, existing token hash, same tenant`, { ...row, ...reset, id: sid('inv') }]);
      routes.push(['invitations', `${label}: (3) fresh id, existing token hash, another tenant`, { ...row, ...reset, tenant_id: otherTenant, id: sid('inv') }]);
    }
    for (const [label, row] of [
      ['locked challenge', locked],
      ['superseded challenge', superseded],
    ]) {
      routes.push(['challenges', `${label}: (1) same tenant and id`, { ...row, attempts: 0, superseded_at: null, consumed_at: null }]);
    }
    const unrevoked = { revoked_at: null, csrf_secret: randomBytes(32) };
    routes.push(['recipient_sessions', 'revoked session: (1) same tenant and id, fresh value hash', { ...session, ...unrevoked, value_hash: freshHash() }]);
    routes.push(['recipient_sessions', 'revoked session: (2) fresh id, existing value hash, same tenant', { ...session, ...unrevoked, id: sid('sess') }]);
    routes.push(['recipient_sessions', 'revoked session: (3) fresh id, existing value hash, another tenant', { ...session, ...unrevoked, tenant_id: otherTenant, id: sid('sess') }]);

    // Each route is tried in turn and recorded: whether the statement ran, whether 0014 refused it,
    // and whether its table changed. Every route must be refused by 0014 with its table unchanged.
    const ran = [];
    const notRefused = [];
    const changed = [];
    for (const foreignKeys of [false, true]) {
      for (const [table, label, values] of routes) {
        const tag = `${table} ${label} (foreign keys ${foreignKeys ? 'on' : 'off'})`;
        const before = tableState(world, table);
        const error = replaceRow(world, table, values, foreignKeys);
        if (error === null) ran.push(tag);
        if (error === null || !KEY_EXISTS[table].test(String(error.message))) notRefused.push(tag);
        if (tableState(world, table) !== before) changed.push(tag);
      }
    }
    assert.equal(routes.length * 2, 22, 'eleven routes, each with foreign keys off and on');
    assert.deepEqual({ ran, notRefused, changed }, { ran: [], notRefused: [], changed: [] }, 'every route is refused by 0014 and leaves its table unchanged');

    // The originals are unchanged, field by field, and no row reached the other tenant.
    const after = (table, id) => world.rows(table).find((row) => row.id === id);
    assert.deepEqual(after('invitations', live.id), live, 'the live invitation keeps its count, expiry and tenant');
    assert.deepEqual(after('invitations', revoked.id), revoked, 'the revoked invitation stays revoked');
    assert.deepEqual(after('challenges', locked.id), locked, 'the locked challenge keeps its five attempts');
    assert.deepEqual(after('challenges', superseded.id), superseded, 'the superseded challenge stays superseded');
    assert.deepEqual(after('recipient_sessions', session.id), session, 'the session stays revoked with its CSRF secret');
    for (const table of Object.keys(KEY_EXISTS)) {
      assert.equal(world.rows(table, `WHERE tenant_id = '${otherTenant}'`).length, 0, `${table}: nothing in the other tenant`);
    }

    // The behaviour follows: the locked challenge is still locked, even for its right code; the
    // ended session and the revoked invitation stay dead.
    assert.equal((await createSession(world, first.token, lockedCode)).status, 429, 'the locked challenge stays locked');
    assert.equal((await readAs(world, opened.session)).status, 401, 'the ended session stays ended');
    assert.equal((await requestChallenge(world, second.token)).status, 202);
    assert.equal(world.takeMails('recipient_challenge').length, 0, 'the revoked invitation gets no code');

    // Through the tenant-scoped store a duplicate key is refused by the same trigger.
    assert.throws(
      () =>
        world.db.transaction(() =>
          world.store().insert('challenges', { id: locked.id, invitation_id: locked.invitation_id, code_hmac: locked.code_hmac, created_at: locked.created_at, expires_at: locked.expires_at }),
        ),
      (error) => error instanceof StorageConstraintError && error.constraint === 'trigger' && KEY_EXISTS.challenges.test(error.message),
      'a duplicate challenge through the store',
    );

    // Every uniqueness constraint of the three tables is a key tried above.
    for (const [table, keys] of Object.entries(UNIQUE_KEYS)) {
      assert.deepEqual(uniqueKeysOf(world, table), [...keys].sort((a, b) => a.join(',').localeCompare(b.join(','))), `${table}: its unique keys are exactly the ones CH-08 covers`);
    }

    // 0014 is appended after 0013 with its own pinned digest, applied, and installs the three triggers.
    const migrations = loadMigrations();
    const actual = migrations[PINNED_0014.version - 1];
    assert.ok(actual, 'migration 14 exists');
    assert.deepEqual({ version: actual.version, name: actual.name, sha256: actual.sha256 }, PINNED_0014, 'migration 14 is unchanged: append a new one instead');
    assert.equal(migrations[12].name, '0013-recipient-ceremony-monotonic.sql', '0014 follows 0013');
    const applied = world.rows('schema_migrations', 'WHERE version = 14');
    assert.equal(applied.length, 1);
    assert.equal(applied[0].sha256, PINNED_0014.sha256);
    const raw = new DatabaseSync(world.path, { readOnly: true });
    try {
      const names = raw
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name IN ('invitations', 'challenges', 'recipient_sessions') AND sql LIKE '% BEFORE INSERT %' AND name LIKE '%key_exists' ORDER BY name")
        .all()
        .map((entry) => entry.name);
      // 0014's key checks (0016's rowid checks beside them are inventoried by the rowid case below).
      assert.deepEqual(names, ['challenges_key_exists', 'invitations_key_exists', 'recipient_sessions_key_exists']);
    } finally {
      raw.close();
    }
  } finally {
    await world.close();
  }
});

test('[CH-08] no invitation, challenge or recipient session is replaced, moved or deleted through its hidden rowid: every route of ST-16 is refused with the table unchanged, an ordinary insert still succeeds, and migration 0016 is appended and pinned (A-010 ROWID-CER)', async () => {
  const world = await createWorld();
  try {
    const { first, opened, lockedCode, second, live, revoked, superseded, locked, session } = await seeded(world);
    const now = world.time.now.toISOString();
    const later = new Date(world.time.now.getTime() + 10 * 60_000).toISOString();

    // One more row per table, inserted the ordinary way (no rowid named): the "other row" the
    // UPDATE OR REPLACE routes move onto a victim. Each is revoked or superseded, so it changes no
    // ceremony outcome.
    const others = {
      invitations: { tenant_id: world.tenant, id: sid('inv'), envelope_id: revoked.envelope_id, recipient_id: revoked.recipient_id, revision_id: revoked.revision_id, manifest_digest: revoked.manifest_digest, token_hash: freshHash(), sent_at: revoked.sent_at, expires_at: revoked.expires_at, revoked_at: now },
      challenges: { tenant_id: world.tenant, id: sid('chal'), invitation_id: revoked.id, code_hmac: freshHash(), created_at: now, expires_at: later, superseded_at: now },
      recipient_sessions: { tenant_id: world.tenant, id: sid('sess'), value_hash: freshHash(), envelope_id: session.envelope_id, recipient_id: session.recipient_id, revision_id: session.revision_id, manifest_digest: session.manifest_digest, csrf_secret: randomBytes(32), created_at: now, last_seen_at: now, revoked_at: now },
    };
    world.db.transaction(() => {
      for (const [table, row] of Object.entries(others)) {
        const { tenant_id: _tenant, ...values } = row;
        world.store().insert(table, values);
      }
    });
    for (const [table, row] of Object.entries(others)) assert.ok(rowidOf(world, table, row.tenant_id, row.id) > 0, `${table}: an ordinary insert succeeds with a positive rowid`);
    const freeRowid = Object.fromEntries(Object.keys(others).map((table) => [table, maxRowid(world, table) + 1_000_000]));

    const targets = [
      ['invitations', 'live invitation with five wrong codes', live],
      ['invitations', 'revoked invitation', revoked],
      ['challenges', 'locked challenge', locked],
      ['challenges', 'superseded challenge', superseded],
      ['recipient_sessions', 'revoked session', session],
    ];
    const problems = [];
    problems.attempts = 0;
    for (const [table, label, victim] of targets) {
      const rid = rowidOf(world, table, victim.tenant_id, victim.id);
      assert.ok(Number.isSafeInteger(rid) && rid > 0, `premise: the ${label} has a positive rowid`);
      const other = others[table];
      const hash = HASH_COLUMN[table];
      const freshKey = () => ({ id: sid('fresh'), ...(hash === null ? {} : { [hash]: freshHash() }) });
      const reinsert = { label: 'then INSERT of the old key with reset state', ...insertStatement('INSERT', table, { ...victim, ...RESET[table]() }), refusedBy: KEY_EXISTS[table] };
      const byKey = [victim.tenant_id, victim.id];
      const otherKey = [other.tenant_id, other.id];
      for (const mode of FK_MODES) {
        const tag = (route) => `${table} ${label} [${route}; foreign keys ${mode}]`;
        for (const spelling of SPELLINGS) {
          attempt(problems, world.path, tag(`insert by ${spelling}`), table, mode, [
            { label: `INSERT OR REPLACE naming its ${spelling} with a new key`, ...insertStatement('INSERT OR REPLACE', table, { ...victim, ...RESET[table](), ...freshKey() }, { spelling, value: rid }), refusedBy: ROWID_EXISTS[table] },
            reinsert,
          ]);
        }
        attempt(problems, world.path, tag('update its rowid'), table, mode, [
          { label: 'UPDATE of its rowid to a free value', sql: `UPDATE ${table} SET rowid = ? WHERE tenant_id = ? AND id = ?`, params: [freeRowid[table], ...byKey], refusedBy: ROWID_KEY_FIXED[table] },
        ]);
        attempt(problems, world.path, tag('another row onto its rowid'), table, mode, [
          { label: 'UPDATE OR REPLACE of another row onto its rowid', sql: `UPDATE OR REPLACE ${table} SET rowid = ? WHERE tenant_id = ? AND id = ?`, params: [rid, ...otherKey], refusedBy: ROWID_KEY_FIXED[table] },
          reinsert,
        ]);
        attempt(problems, world.path, tag('another row onto its key'), table, mode, [
          { label: 'UPDATE OR REPLACE of another row onto its key', sql: `UPDATE OR REPLACE ${table} SET tenant_id = ?, id = ? WHERE tenant_id = ? AND id = ?`, params: [...byKey, ...otherKey], refusedBy: KEY_CHANGE[table] },
          reinsert,
        ]);
        if (hash !== null) {
          attempt(problems, world.path, tag(`another row onto its ${hash}`), table, mode, [
            { label: `UPDATE OR REPLACE of another row onto its ${hash}`, sql: `UPDATE OR REPLACE ${table} SET ${hash} = ? WHERE tenant_id = ? AND id = ?`, params: [victim[hash], ...otherKey], refusedBy: KEY_CHANGE[table] },
            reinsert,
          ]);
        }
        attempt(problems, world.path, tag('delete, then insert again'), table, mode, [
          { label: 'DELETE', sql: `DELETE FROM ${table} WHERE tenant_id = ? AND id = ?`, params: byKey, refusedBy: RETAINED[table] },
          reinsert,
        ]);
      }
    }
    // Rowids of 0 or less: never stored, so -1 (what NEW.rowid holds for an insert that names no
    // rowid) can never match a row and lock ordinary inserts out.
    for (const table of Object.keys(others)) {
      for (const mode of ['off', 'on']) {
        for (const value of [-1, 0, -2]) {
          const fresh = () => ({ ...others[table], id: sid('sentinel'), ...(HASH_COLUMN[table] === null ? {} : { [HASH_COLUMN[table]]: freshHash() }) });
          attempt(problems, world.path, `${table} [rowid ${value}; foreign keys ${mode}]`, table, mode, [
            { label: `INSERT at rowid ${value}`, ...insertStatement('INSERT', table, fresh(), { spelling: 'rowid', value }), refusedBy: ROWID_POSITIVE[table] },
            { label: `INSERT OR REPLACE at rowid ${value}`, ...insertStatement('INSERT OR REPLACE', table, fresh(), { spelling: 'rowid', value }), refusedBy: ROWID_POSITIVE[table] },
          ]);
        }
      }
    }
    assert.equal(problems.attempts, 2 * 3 * 8 + 2 * 3 * 7 + 1 * 3 * 8 + 3 * 2 * 3, 'every route was tried in every foreign-key mode');
    assert.deepEqual([...problems], [], 'every rowid route is refused by its trigger and leaves its table, rowids included, unchanged');

    // The originals keep every column, and no row reached a rowid of 0 or less.
    const after = (table, id) => world.rows(table).find((row) => row.id === id);
    assert.deepEqual(after('invitations', live.id), live, 'the live invitation keeps its count, expiry and tenant');
    assert.deepEqual(after('invitations', revoked.id), revoked, 'the revoked invitation stays revoked');
    assert.deepEqual(after('challenges', locked.id), locked, 'the locked challenge keeps its five attempts');
    assert.deepEqual(after('challenges', superseded.id), superseded, 'the superseded challenge stays superseded');
    assert.deepEqual(after('recipient_sessions', session.id), session, 'the session stays revoked with its CSRF secret');
    for (const table of Object.keys(others)) assert.equal(world.rows(table, 'WHERE rowid <= 0').length, 0, `${table}: no rowid of 0 or less`);

    // The behaviour follows: the locked challenge is still locked, even for its right code; the
    // ended session and the revoked invitation stay dead.
    assert.equal((await createSession(world, first.token, lockedCode)).status, 429, 'the locked challenge stays locked');
    assert.equal((await readAs(world, opened.session)).status, 401, 'the ended session stays ended');
    assert.equal((await requestChallenge(world, second.token)).status, 202);
    assert.equal(world.takeMails('recipient_challenge').length, 0, 'the revoked invitation gets no code');

    // Ordinary semantics through the app's store: an insert that names no rowid succeeds (this pins
    // the runtime's NEW.rowid for an omitted rowid: a value that matched a row would refuse it), and
    // a duplicate key is a trigger constraint, reported as storage_constraint.
    const ordinary = { id: sid('sess'), value_hash: freshHash(), envelope_id: session.envelope_id, recipient_id: session.recipient_id, revision_id: session.revision_id, manifest_digest: session.manifest_digest, csrf_secret: randomBytes(32), created_at: now, last_seen_at: now, revoked_at: now };
    world.db.transaction(() => world.store().insert('recipient_sessions', ordinary));
    assert.ok(rowidOf(world, 'recipient_sessions', world.tenant, ordinary.id) > 0, 'an ordinary insert succeeds with a positive rowid');
    assert.throws(
      () => world.db.transaction(() => world.store().insert('recipient_sessions', { ...ordinary, value_hash: freshHash() })),
      (error) => error instanceof StorageConstraintError && error.constraint === 'trigger' && error.code === 'storage_constraint' && KEY_EXISTS.recipient_sessions.test(error.message),
      'a duplicate key through the store',
    );

    // The three tables carry exactly the triggers of 0003, 0013, 0014 and 0016.
    const inventory = new DatabaseSync(world.path, { readOnly: true });
    try {
      const names = inventory
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name IN ('invitations', 'challenges', 'recipient_sessions') ORDER BY name")
        .all()
        .map((entry) => entry.name);
      assert.deepEqual(names, [...CEREMONY_TRIGGERS], 'the three tables carry exactly these triggers');
    } finally {
      inventory.close();
    }

    // The key form of the UPDATE route is closed by 0016's own trigger: with 0003's bound-column
    // triggers dropped (in this test's disposable database only), a key change is still refused,
    // now by 0016's message alone. Run after the trigger list; only the pin, which reads the files, follows.
    const dropper = new DatabaseSync(world.path);
    try {
      dropper.exec('DROP TRIGGER invitations_bound_columns; DROP TRIGGER challenges_bound_columns; DROP TRIGGER recipient_sessions_bound_columns;');
    } finally {
      dropper.close();
    }
    const alone = [];
    alone.attempts = 0;
    for (const [table, label, victim] of targets) {
      const other = others[table];
      for (const mode of FK_MODES) {
        attempt(alone, world.path, `${table} ${label} [another row onto its key, 0016 alone; foreign keys ${mode}]`, table, mode, [
          { label: 'UPDATE OR REPLACE of another row onto its key', sql: `UPDATE OR REPLACE ${table} SET tenant_id = ?, id = ? WHERE tenant_id = ? AND id = ?`, params: [victim.tenant_id, victim.id, other.tenant_id, other.id], refusedBy: ROWID_KEY_FIXED[table] },
        ]);
        if (HASH_COLUMN[table] !== null) {
          attempt(alone, world.path, `${table} ${label} [another row onto its ${HASH_COLUMN[table]}, 0016 alone; foreign keys ${mode}]`, table, mode, [
            { label: `UPDATE OR REPLACE of another row onto its ${HASH_COLUMN[table]}`, sql: `UPDATE OR REPLACE ${table} SET ${HASH_COLUMN[table]} = ? WHERE tenant_id = ? AND id = ?`, params: [victim[HASH_COLUMN[table]], other.tenant_id, other.id], refusedBy: ROWID_KEY_FIXED[table] },
          ]);
        }
      }
    }
    assert.equal(alone.attempts, 3 * (2 * 2 + 2 * 1 + 1 * 2));
    assert.deepEqual([...alone], [], 'with 0003\'s bound-column triggers gone, 0016 alone refuses every key change');

    // 0016 is appended after 0015 with its own pinned digest, and applied.
    const migrations = loadMigrations();
    const actual = migrations[PINNED_0016.version - 1];
    assert.ok(actual, 'migration 16 exists');
    assert.deepEqual({ version: actual.version, name: actual.name, sha256: actual.sha256 }, PINNED_0016, 'migration 16 is unchanged: append a new one instead');
    assert.equal(migrations[14]?.version, 15, '0016 follows 0015');
    assert.equal(migrations[13]?.name, '0014-recipient-ceremony-no-replace.sql');
    const applied = world.rows('schema_migrations', 'WHERE version = 16');
    assert.equal(applied.length, 1);
    assert.equal(applied[0].sha256, PINNED_0016.sha256);
  } finally {
    await world.close();
  }
});
