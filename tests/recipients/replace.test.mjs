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

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

import { StorageConstraintError } from '../../src/storage/db/index.ts';
import { loadMigrations } from '../../src/storage/schema/migrations.ts';
import { createTenant } from '../storage/support/fixtures.mjs';
import { COOKIE, ORIGIN, createSession, createWorld, openSession, readAs, requestChallenge, requestCode, sentEnvelope, sid, wrongCode } from './support.mjs';

/** The 0014 file, pinned as 0013 is (CH-05): later changes append a migration. */
const PINNED_0014 = Object.freeze({ version: 14, name: '0014-recipient-ceremony-no-replace.sql', sha256: '20dfbb5ad613e1016ca7bb940ec5a37d5cb8887b3d80335164cd8183e25d8116' });

const KEY_EXISTS = Object.freeze({
  invitations: /invitations key exists: an invitation row is never replaced/,
  challenges: /challenges key exists: a challenge row is never replaced/,
  recipient_sessions: /recipient_sessions key exists: a session row is never replaced/,
});

/** Every uniqueness constraint 0003 declares on the three tables; CH-08 tries each of them. */
const UNIQUE_KEYS = Object.freeze({
  invitations: [['tenant_id', 'id'], ['token_hash']],
  challenges: [['tenant_id', 'id']],
  recipient_sessions: [['tenant_id', 'id'], ['value_hash']],
});

function freshHash() {
  return createHash('sha256').update(randomBytes(32)).digest('hex');
}

/** The whole table, every column of every row, in rowid order (BLOBs as hex). */
function tableState(world, table) {
  const raw = new DatabaseSync(world.path, { readOnly: true });
  try {
    const rows = raw.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all();
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

test('[CH-08] INSERT OR REPLACE cannot replace an invitation, a challenge or a recipient session by any key: counters, the locked challenge, supersession, revocation and the CSRF secret stay as they were; migration 0014 is appended and pinned', async () => {
  const world = await createWorld();
  try {
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
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name IN ('invitations', 'challenges', 'recipient_sessions') AND sql LIKE '% BEFORE INSERT %' ORDER BY name")
        .all()
        .map((entry) => entry.name);
      assert.deepEqual(names, ['challenges_key_exists', 'invitations_key_exists', 'recipient_sessions_key_exists']);
    } finally {
      raw.close();
    }
  } finally {
    await world.close();
  }
});
