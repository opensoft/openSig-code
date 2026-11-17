// SPDX-License-Identifier: Apache-2.0
//
// T008 recipient ceremony: requestChallenge and the code checks of
// createRecipientSession. CH-02 (generic 202, supersession, rate limits),
// CH-03 (cumulative lockout after 20 wrong codes per invitation, recovered only
// by a resend), SC002-10 (expired challenge) and SC002-15 (the sixth wrong code
// is 429 locked). Every response is checked against the vendored contract.
// CH-02 compares every response header, name as sent and value, in order,
// except date and x-correlation-id (F2).

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';

import {
  MINUTE,
  ORIGIN,
  comparableHeaders,
  contractErrors,
  createSession,
  createWorld,
  openSession,
  requestChallenge,
  requestCode,
  sentEnvelope,
  tokenOf,
  wrongCode,
} from './support.mjs';

function invitationRow(world) {
  const rows = world.rows('invitations', 'WHERE revoked_at IS NULL');
  assert.equal(rows.length, 1, 'one live invitation');
  return rows[0];
}

function assertError(response, status, code, label) {
  assert.equal(response.status, status, `${label}: status`);
  assert.equal(response.json?.code, code, `${label}: code`);
  assert.deepEqual(contractErrors('Error', response.json), [], `${label}: a contract Error body`);
}

test('[CH-02] requestChallenge answers the same generic 202 whatever the invitation, and mails a code only for a live one', async () => {
  const world = await createWorld();
  try {
    const live = await sentEnvelope(world);
    const revoked = await sentEnvelope(world);
    const expired = await sentEnvelope(world, { expiresAt: new Date(world.time.now.getTime() + 2 * 60 * MINUTE).toISOString() });
    // Revoke one through a resend (its old token is dead), and let one lapse.
    await world.ceremony.run(() =>
      world.db.transaction(() => {
        const recipient = revoked.envelope.recipients[0];
        world.ceremony.resendInvitation(world.store(), revoked.envelope.id, recipient.id);
      }),
    );
    assert.equal(world.takeMails('recipient_invitation').length, 1, 'the resend mails a fresh invitation');
    world.time.advance(3 * 60 * MINUTE);
    const fresh = await sentEnvelope(world);
    const unknown = randomBytes(32).toString('base64url');

    const cases = [
      ['live invitation', fresh.token, 1],
      ['unknown token', unknown, 0],
      ['revoked invitation', revoked.token, 0],
      ['expired invitation', expired.token, 0],
    ];
    const bodies = [];
    const headerSets = [];
    for (const [label, token, mailed] of cases) {
      const response = await requestChallenge(world, token);
      assert.equal(response.status, 202, `${label}: 202`);
      assert.deepEqual(response.json, { status: 'accepted' }, `${label}: the generic body`);
      assert.deepEqual(contractErrors('Accepted', response.json), [], `${label}: a contract Accepted body`);
      assert.equal(response.headers['set-cookie'], undefined, `${label}: no cookie`);
      assert.ok(typeof response.headers.date === 'string' && typeof response.headers['x-correlation-id'] === 'string', `${label}: date and x-correlation-id are present (the only headers left out of the comparison)`);
      bodies.push(response.bytes.toString('utf8'));
      headerSets.push([label, comparableHeaders(response)]);
      assert.equal(world.takeMails('recipient_challenge').length, mailed, `${label}: ${mailed} code mailed`);
    }
    assert.equal(new Set(bodies).size, 1, 'the bodies are byte-identical');
    const [, liveHeaders] = headerSets[0];
    assert.ok(liveHeaders.length >= 5, 'the comparison covers the full header set');
    for (const [label, headers] of headerSets.slice(1)) {
      assert.deepEqual(headers, liveHeaders, `${label}: every header, name and value, matches the live invitation's (except date and x-correlation-id)`);
    }
    assert.equal(world.rows('challenges').length, 1, 'only the live invitation got a challenge');
    void live;

    // Schema violations are 400 for every caller alike, and mail nothing.
    for (const [label, body] of [
      ['short token', { invitation: 'abc' }],
      ['token with a dot', { invitation: `${unknown.slice(0, 42)}.` }],
      ['unknown member', { invitation: unknown, extra: true }],
      ['missing member', {}],
      ['array body', [unknown]],
    ]) {
      const response = await world.http({ method: 'POST', path: '/v1/recipient-session/challenges', headers: { origin: ORIGIN }, body });
      assertError(response, 400, 'invalid_request', label);
    }
    assertError(await world.http({ method: 'POST', path: '/v1/recipient-session/challenges', body: { invitation: unknown } }), 403, 'origin_rejected', 'no Origin');
    assert.equal(world.takeMails('recipient_challenge').length, 0);
  } finally {
    await world.close();
  }
});

test('[CH-02] a new code supersedes the previous one, and requests are limited per invitation and per client address without revealing which tokens exist', async () => {
  const world = await createWorld({
    limits: {
      challengePerInvitation: { limit: 3, windowMs: 10 * MINUTE },
      challengePerAddress: { limit: 6, windowMs: 10 * MINUTE },
    },
  });
  try {
    const { token } = await sentEnvelope(world);
    const first = await requestCode(world, token);
    const second = await requestCode(world, token);
    assert.ok(first !== null && second !== null && first !== second, 'each request mails a fresh code');
    const challenges = world.rows('challenges');
    assert.equal(challenges.length, 2);
    assert.equal(challenges[0].superseded_at, world.time.now.toISOString(), 'the first challenge is superseded');
    assert.equal(challenges[1].superseded_at, null);
    assertError(await createSession(world, token, first), 401, 'unauthenticated', 'the superseded code');
    assert.equal(world.rows('recipient_sessions').length, 0);

    // Per invitation: the third request is the last in the window, for a live and an unknown token alike.
    assert.equal((await requestChallenge(world, token)).status, 202);
    world.takeMails('recipient_challenge');
    const limited = await requestChallenge(world, token);
    assertError(limited, 429, 'rate_limited', 'fourth request for one invitation');
    assert.ok(Number(limited.headers['retry-after']) >= 1, 'Retry-After in whole seconds');
    const unknown = randomBytes(32).toString('base64url');
    for (let i = 0; i < 3; i += 1) assert.equal((await requestChallenge(world, unknown)).status, 202);
    const unknownLimited = await requestChallenge(world, unknown);
    assertError(unknownLimited, 429, 'rate_limited', 'fourth request for an unknown token');
    assert.equal(unknownLimited.headers['retry-after'], limited.headers['retry-after'], 'the same answer for a token that names nothing');
    assert.deepEqual(comparableHeaders(unknownLimited), comparableHeaders(limited), 'every 429 header, name and value, matches (except date and x-correlation-id)');
    assert.equal(world.takeMails('recipient_challenge').length, 0, 'refused requests mail nothing');

    // Per client address: 6 accepted requests in the window from 127.0.0.1, whatever the token
    // (the two refused ones above took no budget).
    const other = randomBytes(32).toString('base64url');
    const byAddress = await requestChallenge(world, other);
    assertError(byAddress, 429, 'rate_limited', 'a seventh request from one address');

    // The window slides: later requests are accepted again, and the live invitation still works.
    world.time.advance(10 * MINUTE);
    const third = await requestCode(world, token);
    assert.ok(third !== null);
    assert.equal((await createSession(world, token, third)).status, 201, 'the newest code opens a session');
  } finally {
    await world.close();
  }
});

test('[SC002-10] an expired challenge is rejected without counting a wrong code, and a fresh challenge works', async () => {
  const world = await createWorld();
  try {
    const { token } = await sentEnvelope(world);
    const code = await requestCode(world, token);
    world.time.advance(10 * MINUTE);
    assertError(await createSession(world, token, code), 401, 'unauthenticated', 'right code, challenge 10 minutes old');
    assert.equal(world.rows('recipient_sessions').length, 0, 'no session');
    const challenge = world.rows('challenges')[0];
    assert.equal(challenge.consumed_at, null, 'nothing consumed');
    assert.equal(challenge.attempts, 0, 'an expired challenge is never compared');
    assert.equal(invitationRow(world).cumulative_wrong_codes, 0);

    // Just inside the TTL the right code works.
    const fresh = await requestCode(world, token);
    world.time.advance(10 * MINUTE - 1);
    const created = await createSession(world, token, fresh);
    assert.equal(created.status, 201);
    assert.deepEqual(contractErrors('RecipientSessionState', created.json), []);
  } finally {
    await world.close();
  }
});

test('[SC002-15] five wrong codes lock the challenge: the sixth attempt is 429 locked, even with the right code', async () => {
  const world = await createWorld();
  try {
    const { token } = await sentEnvelope(world);
    const code = await requestCode(world, token);
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      assertError(await createSession(world, token, wrongCode(code, attempt)), 401, 'unauthenticated', `wrong code ${attempt}`);
      assert.equal(world.rows('challenges')[0].attempts, attempt, `attempt ${attempt} counted`);
    }
    assertError(await createSession(world, token, wrongCode(code, 6)), 429, 'locked', 'sixth wrong code');
    assertError(await createSession(world, token, code), 429, 'locked', 'the right code on a locked challenge');
    const challenge = world.rows('challenges')[0];
    assert.equal(challenge.attempts, 5, 'a locked challenge is not compared again');
    assert.equal(challenge.consumed_at, null);
    assert.equal(invitationRow(world).cumulative_wrong_codes, 5, 'the invitation counts the five wrong codes');
    assert.equal(world.rows('recipient_sessions').length, 0, 'no session');

    // The lock is per challenge: a new code opens a session.
    const { state } = await openSession(world, token);
    assert.equal(state.turn, 'yours');
  } finally {
    await world.close();
  }
});

test('[CH-03] twenty wrong codes over an invitation revoke it: every later attempt is 429 locked, no code is mailed, and only a resend recovers', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world);
    let total = 0;
    for (let round = 1; round <= 4; round += 1) {
      const code = await requestCode(world, token);
      assert.ok(code !== null, `round ${round}: a code is mailed`);
      for (let attempt = 1; attempt <= 5; attempt += 1) {
        total += 1;
        assertError(await createSession(world, token, wrongCode(code, attempt)), 401, 'unauthenticated', `wrong code ${total}`);
      }
      world.time.advance(MINUTE);
    }
    const revoked = world.rows('invitations')[0];
    assert.equal(revoked.cumulative_wrong_codes, 20, 'twenty wrong codes counted');
    assert.notEqual(revoked.revoked_at, null, 'the twentieth wrong code revoked the invitation');
    assertError(await createSession(world, token, 'ABCDEFGHJK'), 429, 'locked', 'after the lockout');
    assert.equal((await requestChallenge(world, token)).status, 202, 'requestChallenge stays generic');
    assert.equal(world.takeMails('recipient_challenge').length, 0, 'but mails no code');
    assert.equal(world.rows('invitations')[0].cumulative_wrong_codes, 20, 'nothing more is counted');
    assert.equal(world.rows('recipient_sessions').length, 0);

    // A resend (the invitation half of T034's resendInvitation) issues a fresh invitation that works.
    const recipient = envelope.recipients[0];
    await world.ceremony.run(() => world.db.transaction(() => world.ceremony.resendInvitation(world.store(), envelope.id, recipient.id)));
    const mails = world.takeMails('recipient_invitation', 'signer.one@example.test');
    assert.equal(mails.length, 1, 'the resend mails one invitation');
    const fresh = tokenOf(mails[0]);
    assert.ok(fresh !== token, 'a new token');
    const { state } = await openSession(world, fresh);
    assert.equal(state.turn, 'yours');
    assertError(await createSession(world, token, 'ABCDEFGHJK'), 429, 'locked', 'the locked invitation stays locked');
    assert.equal(world.rows('invitations').length, 2);
  } finally {
    await world.close();
  }
});
