// SPDX-License-Identifier: Apache-2.0
//
// T008, A-008 obligation P16: migration 0013 makes the ceremony's counters and
// markers monotonic (CH-04) and the recipient session's CSRF secret required
// and immutable (CH-05). Each rule is checked through the tenant-scoped store
// and through a raw connection to the same file, as any writer would have it,
// and the 0003 constraints still report their own kind.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

import { loadMigrations } from '../../src/storage/schema/migrations.ts';
import { StorageConstraintError } from '../../src/storage/db/index.ts';
import { createWorld, hex, openSession, requestCode, sentEnvelope, sid, wrongCode, createSession } from './support.mjs';

/** The 0013 file, pinned like 0010..0012 (ST-12): later changes append a migration. */
const PINNED_0013 = Object.freeze({ version: 13, name: '0013-recipient-ceremony-monotonic.sql', sha256: '559da84c135b46149691cf15bf424a706c7f7d40820ad9110677df4c0c6cd07d' });

function refused(world, fn, kind, pattern, label) {
  assert.throws(
    () => world.db.transaction(() => fn(world.store())),
    (error) => error instanceof StorageConstraintError && error.constraint === kind && pattern.test(error.message),
    label,
  );
}

function accepted(world, fn, label) {
  assert.doesNotThrow(() => world.db.transaction(() => fn(world.store())), label);
}

function rawRefused(world, sql, params, pattern, label) {
  const raw = new DatabaseSync(world.path);
  try {
    assert.throws(() => raw.prepare(sql).run(...params), (error) => pattern.test(String(error?.message)), label);
  } finally {
    raw.close();
  }
}

/** A world with one sent envelope, a challenge and a session. */
async function seeded() {
  const world = await createWorld();
  const { token } = await sentEnvelope(world);
  const code = await requestCode(world, token);
  assert.equal((await createSession(world, token, wrongCode(code))).status, 401, 'one wrong code is counted');
  await openSession(world, token);
  const invitation = world.rows('invitations')[0];
  const challenges = world.rows('challenges');
  const session = world.rows('recipient_sessions')[0];
  return { world, invitation, challenges, session };
}

test('[CH-04] invitation expiry is fixed at issue, cumulative wrong codes never decrease, and invitation rows are retained', async () => {
  const { world, invitation } = await seeded();
  try {
    assert.equal(invitation.cumulative_wrong_codes, 1);
    const id = { id: invitation.id };
    const later = new Date(Date.parse(invitation.expires_at) + 60_000).toISOString();
    const earlier = new Date(Date.parse(invitation.expires_at) - 60_000).toISOString();
    refused(world, (s) => s.update('invitations', id, { expires_at: later }), 'trigger', /expires_at is fixed at issue/, 'extending the expiry');
    refused(world, (s) => s.update('invitations', id, { expires_at: earlier }), 'trigger', /expires_at is fixed at issue/, 'moving the expiry');
    accepted(world, (s) => s.update('invitations', id, { expires_at: invitation.expires_at }), 'writing the same expiry changes nothing');
    refused(world, (s) => s.update('invitations', id, { cumulative_wrong_codes: 0 }), 'trigger', /never decreases/, 'resetting the wrong-code count');
    accepted(world, (s) => s.update('invitations', id, { cumulative_wrong_codes: 2 }), 'counting up');
    refused(world, (s) => s.update('invitations', id, { cumulative_wrong_codes: 1 }), 'trigger', /never decreases/, 'counting down');
    refused(world, (s) => s.delete('invitations', id), 'trigger', /invitations rows are retained/, 'deleting the invitation (which would reset its counters)');
    // 0003's constraints keep their own kind: 20 without revocation is a CHECK failure.
    refused(world, (s) => s.update('invitations', id, { cumulative_wrong_codes: 20 }), 'check', /cumulative_wrong_codes/, '20 wrong codes need revoked_at');
    accepted(world, (s) => s.update('invitations', id, { cumulative_wrong_codes: 20, revoked_at: world.time.now.toISOString() }), 'the lockout revokes');
    refused(world, (s) => s.update('invitations', id, { cumulative_wrong_codes: 19 }), 'trigger', /never decreases/, 'no way back from the lockout');
    refused(world, (s) => s.update('invitations', id, { revoked_at: null }), 'trigger', /revocation is final/, 'revocation stays final (0003)');

    rawRefused(world, 'UPDATE invitations SET cumulative_wrong_codes = 0, revoked_at = NULL WHERE id = ?', [invitation.id], /never decreases|revocation is final/, 'a raw reset');
    rawRefused(world, 'UPDATE invitations SET expires_at = ? WHERE id = ?', [later, invitation.id], /fixed at issue/, 'a raw extension');
    rawRefused(world, 'DELETE FROM invitations WHERE id = ?', [invitation.id], /retained/, 'a raw delete');
    const after = world.rows('invitations')[0];
    assert.equal(after.cumulative_wrong_codes, 20);
    assert.equal(after.expires_at, invitation.expires_at);
  } finally {
    await world.close();
  }
});

test('[CH-04] challenge attempts never decrease, supersession is final, and challenge rows are retained', async () => {
  const { world, challenges } = await seeded();
  try {
    assert.equal(challenges.length, 2);
    const [superseded, consumed] = challenges;
    assert.notEqual(superseded.superseded_at, null, 'the first challenge was superseded by the second');
    assert.equal(superseded.attempts, 1);
    assert.equal(consumed.attempts, 1);
    const first = { id: superseded.id };
    refused(world, (s) => s.update('challenges', first, { attempts: 0 }), 'trigger', /attempts never decreases/, 'resetting attempts');
    accepted(world, (s) => s.update('challenges', first, { attempts: 4 }), 'counting up');
    refused(world, (s) => s.update('challenges', first, { attempts: 3 }), 'trigger', /attempts never decreases/, 'counting down');
    refused(world, (s) => s.update('challenges', first, { attempts: 6 }), 'check', /attempts/, 'more than 5 is a CHECK failure (0003)');
    refused(world, (s) => s.update('challenges', first, { superseded_at: null }), 'trigger', /supersession is final/, 'reviving a superseded challenge');
    const moved = new Date(Date.parse(superseded.superseded_at) + 1).toISOString();
    refused(world, (s) => s.update('challenges', first, { superseded_at: moved }), 'trigger', /supersession is final/, 'moving the supersession');
    accepted(world, (s) => s.update('challenges', first, { superseded_at: superseded.superseded_at }), 'writing the same marker changes nothing');
    const second = { id: consumed.id };
    accepted(world, (s) => s.update('challenges', second, { superseded_at: world.time.now.toISOString() }), 'a first supersession is allowed');
    refused(world, (s) => s.update('challenges', second, { consumed_at: null }), 'trigger', /single use/, 'consumption stays final (0003)');
    refused(world, (s) => s.delete('challenges', first), 'trigger', /challenges rows are retained/, 'deleting a challenge');
    rawRefused(world, 'UPDATE challenges SET attempts = 0, superseded_at = NULL WHERE id = ?', [superseded.id], /never decreases|supersession is final/, 'a raw reset');
    rawRefused(world, 'DELETE FROM challenges WHERE id = ?', [superseded.id], /retained/, 'a raw delete');
    assert.equal(world.rows('challenges')[0].attempts, 4);
  } finally {
    await world.close();
  }
});

test('[CH-05] every recipient session has a CSRF secret, which never changes; migration 0013 is appended and pinned', async () => {
  const { world, session } = await seeded();
  try {
    const row = (overrides) => ({
      id: sid('sess'),
      value_hash: hex(`session-${randomBytes(8).toString('hex')}`),
      envelope_id: session.envelope_id,
      recipient_id: session.recipient_id,
      revision_id: session.revision_id,
      manifest_digest: session.manifest_digest,
      csrf_secret: randomBytes(32),
      created_at: world.time.now.toISOString(),
      last_seen_at: world.time.now.toISOString(),
      ...overrides,
    });
    refused(world, (s) => s.insert('recipient_sessions', row({ csrf_secret: null })), 'trigger', /csrf_secret is required/, 'a session without a CSRF secret');
    refused(world, (s) => s.insert('recipient_sessions', row({ csrf_secret: randomBytes(8) })), 'check', /csrf_secret/, 'a short secret is a CHECK failure (0003)');
    accepted(world, (s) => s.insert('recipient_sessions', row({})), 'a session with its secret');
    const id = { id: session.id };
    refused(world, (s) => s.update('recipient_sessions', id, { csrf_secret: randomBytes(32) }), 'trigger', /csrf_secret is immutable/, 'replacing the secret');
    refused(world, (s) => s.update('recipient_sessions', id, { csrf_secret: null }), 'trigger', /csrf_secret is immutable/, 'clearing the secret');
    accepted(world, (s) => s.update('recipient_sessions', id, { csrf_secret: Buffer.from(session.csrf_secret) }), 'writing the same secret changes nothing');
    accepted(world, (s) => s.update('recipient_sessions', id, { last_seen_at: world.time.now.toISOString() }), 'the session stays otherwise usable');
    const raw = new DatabaseSync(world.path);
    try {
      assert.throws(
        () => raw.prepare('INSERT INTO recipient_sessions (tenant_id, id, value_hash, envelope_id, recipient_id, revision_id, manifest_digest, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(world.tenant, sid('sess'), hex('raw-session'), session.envelope_id, session.recipient_id, session.revision_id, session.manifest_digest, world.time.now.toISOString(), world.time.now.toISOString()),
        /csrf_secret is required/,
        'a raw insert without the secret',
      );
      assert.throws(() => raw.prepare('UPDATE recipient_sessions SET csrf_secret = ? WHERE id = ?').run(randomBytes(32), session.id), /csrf_secret is immutable/, 'a raw replacement');
    } finally {
      raw.close();
    }
    assert.ok(Buffer.from(world.rows('recipient_sessions')[0].csrf_secret).equals(Buffer.from(session.csrf_secret)), 'the stored secret is unchanged');

    // 0013 is appended after 0012 with its own pinned digest, and applied.
    const migrations = loadMigrations();
    const actual = migrations[PINNED_0013.version - 1];
    assert.ok(actual, 'migration 13 exists');
    assert.deepEqual({ version: actual.version, name: actual.name, sha256: actual.sha256 }, PINNED_0013, 'migration 13 is unchanged: append a new one instead');
    assert.equal(migrations[11].name, '0012-idempotency-body-bound.sql', '0013 follows 0012');
    const applied = world.rows('schema_migrations', 'WHERE version = 13');
    assert.equal(applied.length, 1);
    assert.equal(applied[0].sha256, PINNED_0013.sha256);
    const triggers = new DatabaseSync(world.path, { readOnly: true });
    try {
      const names = triggers
        // 0013's AFTER triggers; 0016's AFTER INSERT rowid checks are inventoried with every other trigger by CH-08.
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name IN ('invitations', 'challenges', 'recipient_sessions') AND sql LIKE '% AFTER %' AND name NOT LIKE '%rowid_positive' ORDER BY name")
        .all()
        .map((entry) => entry.name);
      assert.deepEqual(names, [
        'challenges_attempts_monotonic',
        'challenges_retained',
        'challenges_supersession_final',
        'invitations_expiry_fixed',
        'invitations_retained',
        'invitations_wrong_codes_monotonic',
        'recipient_sessions_csrf_immutable',
        'recipient_sessions_csrf_required',
      ]);
    } finally {
      triggers.close();
    }
  } finally {
    await world.close();
  }
});
