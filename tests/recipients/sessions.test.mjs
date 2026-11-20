// SPDX-License-Identifier: Apache-2.0
//
// T008 recipient ceremony: the bound session. SC002-11 (expired invitation),
// SC002-12 (idle expiry), SC002-13 (consumed challenge replay), SC002-14
// (revocation by reissue and resend), SC002-16 (CSRF in front of approval) and
// RC-02 (RecipientSessionState: every approval input, contract-conformant, for
// both recipients of a two-recipient envelope).

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';

import {
  COOKIE,
  CONSENT_WORDING,
  DAY,
  MINUTE,
  ORIGIN,
  approveFirst,
  contractErrors,
  cookieOf,
  createSession,
  createWorld,
  logsFreeOf,
  openSession,
  readAs,
  requestChallenge,
  requestCode,
  sentEnvelope,
  sha256,
  tokenOf,
} from './support.mjs';

function assertError(response, status, code, label) {
  assert.equal(response.status, status, `${label}: status`);
  assert.equal(response.json?.code, code, `${label}: code`);
  assert.deepEqual(contractErrors('Error', response.json), [], `${label}: a contract Error body`);
}

test('[SC002-11] an expired invitation is rejected: no code is mailed and a code issued before expiry opens no session', async () => {
  const world = await createWorld();
  try {
    // The envelope lives 20 days, so the invitation's own 7-day lifetime is what ends it.
    const { token } = await sentEnvelope(world, { expiresAt: new Date(world.time.now.getTime() + 20 * DAY).toISOString() });
    const invitation = world.rows('invitations')[0];
    assert.equal(Date.parse(invitation.expires_at) - Date.parse(invitation.sent_at), 7 * DAY);
    world.time.advance(7 * DAY - 5 * MINUTE);
    const code = await requestCode(world, token);
    assert.ok(code !== null, 'a code is mailed 5 minutes before the invitation expires');
    world.time.advance(6 * MINUTE);
    assertError(await createSession(world, token, code), 401, 'unauthenticated', 'right code, unexpired challenge, expired invitation');
    assert.equal(world.rows('recipient_sessions').length, 0, 'no session');
    assert.equal(world.rows('challenges')[0].attempts, 0, 'the code was never compared');
    assert.equal((await requestChallenge(world, token)).status, 202, 'requestChallenge stays generic');
    assert.equal(world.takeMails('recipient_challenge').length, 0, 'and mails nothing for an expired invitation');

    // An envelope expiring before 7 days caps the invitation at the envelope's expiry.
    const capped = await createWorld();
    try {
      const expiresAt = new Date(capped.time.now.getTime() + 2 * DAY).toISOString();
      const { token: short } = await sentEnvelope(capped, { expiresAt });
      assert.equal(capped.rows('invitations')[0].expires_at, expiresAt, 'expires_at = min(+7 days, envelope expiry)');
      capped.time.advance(2 * DAY);
      assert.equal((await requestChallenge(capped, short)).status, 202);
      assert.equal(capped.takeMails('recipient_challenge').length, 0, 'nothing mailed at the capped expiry');
    } finally {
      await capped.close();
    }
  } finally {
    await world.close();
  }
});

test('[SC002-12] a session idle for 30 minutes is 401; reads keep it alive, and a prefetch does not extend it', async () => {
  const world = await createWorld();
  try {
    const { token } = await sentEnvelope(world);
    const { session, state } = await openSession(world, token);
    assert.equal(Date.parse(state.session_expires_at) - world.time.now.getTime(), 30 * MINUTE, 'the idle expiry is 30 minutes after creation');

    world.time.advance(30 * MINUTE - 1);
    const kept = await readAs(world, session);
    assert.equal(kept.status, 200, 'a read just inside the idle window');
    assert.equal(Date.parse(kept.json.session_expires_at) - world.time.now.getTime(), 30 * MINUTE, 'the read moved the idle expiry');

    world.time.advance(20 * MINUTE);
    const prefetched = await readAs(world, session, '/v1/recipient-session', { headers: { 'sec-purpose': 'prefetch' } });
    assert.equal(prefetched.status, 200, 'a prefetch is served');
    world.time.advance(10 * MINUTE);
    assertError(await readAs(world, session), 401, 'unauthenticated', '30 minutes after the last real read (the prefetch did not count)');
    assertError(await readAs(world, session, '/v1/recipient-session/document'), 401, 'unauthenticated', 'the document');
    assertError(await readAs(world, session, '/v1/recipient-session/manifest'), 401, 'unauthenticated', 'the manifest');
    assert.equal(world.rows('recipient_sessions')[0].revoked_at, null, 'idle expiry needs no write');
  } finally {
    await world.close();
  }
});

test('[SC002-13] replaying a consumed challenge is rejected and opens no second session', async () => {
  const world = await createWorld();
  try {
    const { token } = await sentEnvelope(world);
    const code = await requestCode(world, token);
    const created = await createSession(world, token, code);
    assert.equal(created.status, 201);
    const first = cookieOf(created);
    assertError(await createSession(world, token, code), 401, 'unauthenticated', 'the same invitation and code again');
    world.time.advance(MINUTE);
    assertError(await createSession(world, token, code), 401, 'unauthenticated', 'a minute later');
    const sessions = world.rows('recipient_sessions');
    assert.equal(sessions.length, 1, 'exactly one session');
    const challenge = world.rows('challenges')[0];
    assert.notEqual(challenge.consumed_at, null, 'the challenge is consumed');
    assert.equal(challenge.attempts, 1, 'one attempt: the one that consumed it');
    assert.equal(world.rows('invitations')[0].cumulative_wrong_codes, 0, 'a replay is not a guess');
    assert.equal((await readAs(world, first)).status, 200, 'the original session is unaffected');
    assert.ok(logsFreeOf(world, [token, code, first]), 'no log line carries a capability value');
  } finally {
    await world.close();
  }
});

test('[SC002-14] a session revoked by reissue, or by a resend of its invitation, is 401', async () => {
  const world = await createWorld();
  try {
    // Envelope reissue (T007): every outstanding capability of the prior envelope is revoked.
    const { envelope, token } = await sentEnvelope(world);
    const { session } = await openSession(world, token);
    assert.equal((await readAs(world, session)).status, 200);
    // The decline transition at storage level (T010 owns the decline handler), so the session is
    // still live when the reissue runs and only the reissue can revoke it.
    world.db.transaction(() => {
      assert.equal(world.store().compareAndSet('envelopes', { id: envelope.id }, envelope.version, { state: 'declined', updated_at: world.time.now.toISOString() }), true);
    });
    assert.equal(world.rows('recipient_sessions')[0].revoked_at, null);
    world.time.advance(MINUTE);
    const reissued = world.service.reissue(world.req(), envelope.id, { expected_version: envelope.version + 1 });
    assert.equal(reissued.status, 201);
    assertError(await readAs(world, session), 401, 'unauthenticated', 'after the reissue');
    assertError(await readAs(world, session, '/v1/recipient-session', { headers: { 'sec-purpose': 'prefetch' } }), 401, 'unauthenticated', 'a prefetch after the reissue');
    assert.equal(world.rows('recipient_sessions')[0].revoked_at, world.time.now.toISOString(), 'the reissue revoked the session');
    assert.equal(world.rows('invitations')[0].revoked_at, world.time.now.toISOString(), 'and the invitation');
    assert.equal((await requestChallenge(world, token)).status, 202);
    assert.equal(world.takeMails('recipient_challenge').length, 0, 'the revoked invitation gets no code');

    // Resend: the recipient's old invitation and sessions are revoked, a fresh invitation works.
    const second = await sentEnvelope(world);
    const opened = await openSession(world, second.token);
    world.time.advance(MINUTE);
    await world.ceremony.run(() => world.db.transaction(() => world.ceremony.resendInvitation(world.store(), second.envelope.id, second.envelope.recipients[0].id)));
    assertError(await readAs(world, opened.session), 401, 'unauthenticated', 'after the resend');
    assertError(await readAs(world, opened.session, '/v1/recipient-session/document', { headers: { purpose: 'prefetch' } }), 401, 'unauthenticated', 'a prefetch after the resend');
    assert.equal((await requestChallenge(world, second.token)).status, 202);
    assert.equal(world.takeMails('recipient_challenge').length, 0, 'the old invitation gets no code');
    const resent = world.takeMails('recipient_invitation', 'signer.one@example.test');
    assert.equal(resent.length, 1);
    const fresh = await openSession(world, tokenOf(resent[0]));
    assert.equal(fresh.state.turn, 'yours');

    // Void (T007) revokes too.
    world.service.void(world.req(), second.envelope.id, { expected_version: second.envelope.version, reason_code: 'sender-cancelled' });
    assertError(await readAs(world, fresh.session), 401, 'unauthenticated', 'after void');
    assertError(await readAs(world, fresh.session, '/v1/recipient-session/manifest', { headers: { 'sec-purpose': 'prefetch' } }), 401, 'unauthenticated', 'a prefetch after void');
  } finally {
    await world.close();
  }
});

test('[SC002-16] approval without a valid CSRF token is 403 and records nothing; the session-bound token passes the guard', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world);
    const { session, csrf } = await openSession(world, token);
    const other = await sentEnvelope(world);
    const otherSession = await openSession(world, other.token);
    assert.ok(otherSession.csrf !== csrf, 'each session has its own token');
    const approve = (headers) =>
      world.http({ method: 'POST', path: '/v1/recipient-session/approval', headers: { origin: ORIGIN, cookie: `${COOKIE}=${session}`, ...headers }, body: { consent: true } });
    const before = world.snapshot({ recipient_sessions: ['last_seen_at'] });

    assertError(await approve({}), 403, 'csrf_failed', 'no X-CSRF-Token');
    assertError(await approve({ 'x-csrf-token': randomBytes(32).toString('base64url') }), 403, 'csrf_failed', 'a random token');
    assertError(await approve({ 'x-csrf-token': otherSession.csrf }), 403, 'csrf_failed', "another session's token");
    assertError(await approve({ 'x-csrf-token': csrf.slice(0, -1) }), 403, 'csrf_failed', 'a truncated token');
    assertError(await approve({ 'x-csrf-token': `${csrf}A` }), 403, 'csrf_failed', 'an extended token');
    assertError(
      await world.http({ method: 'POST', path: '/v1/recipient-session/approval', headers: { origin: ORIGIN, 'x-csrf-token': csrf }, body: { consent: true } }),
      401,
      'unauthenticated',
      'a valid token without the session cookie',
    );
    assertError(await approve({ 'x-csrf-token': csrf, origin: 'https://evil.example.test' }), 403, 'origin_rejected', 'a foreign Origin');
    assert.deepEqual(world.snapshot({ recipient_sessions: ['last_seen_at'] }), before, 'no approval, version, state or capability change');
    assert.equal(world.rows('approvals').length, 0);
    assert.equal(world.rows('envelopes', `WHERE id = '${envelope.id}'`)[0].version, envelope.version);

    // The session-bound token passes the CSRF guard (T010 supplies the approval handler behind it).
    const passed = await approve({ 'x-csrf-token': csrf });
    assert.ok(![401, 403].includes(passed.status), 'the right token is not refused by the session or CSRF checks');
    assert.notEqual(passed.json?.code, 'csrf_failed');
    // Decline has the same guard.
    assertError(
      await world.http({ method: 'POST', path: '/v1/recipient-session/decline', headers: { origin: ORIGIN, cookie: `${COOKIE}=${session}` }, body: {} }),
      403,
      'csrf_failed',
      'decline without a token',
    );

    // endRecipientSession needs the token too; with it the session ends and the cookie is cleared.
    const end = (headers) => world.http({ method: 'DELETE', path: '/v1/recipient-session', headers: { origin: ORIGIN, cookie: `${COOKIE}=${session}`, ...headers } });
    assertError(await end({}), 403, 'csrf_failed', 'end without a token');
    assert.equal((await readAs(world, session)).status, 200, 'the session survives a refused end');
    const ended = await end({ 'x-csrf-token': csrf });
    assert.equal(ended.status, 204);
    assert.equal(ended.bytes.length, 0);
    const cleared = [ended.headers['set-cookie']].flat()[0];
    assert.match(cleared, /^__Host-opensig_rs=; Path=\/; Max-Age=0; Secure; HttpOnly; SameSite=Strict$/);
    assertError(await readAs(world, session), 401, 'unauthenticated', 'after end');
    assert.ok(logsFreeOf(world, [token, session, csrf, otherSession.session, otherSession.csrf]), 'no log line carries a capability value');
  } finally {
    await world.close();
  }
});

test('[RC-02] the session state carries every approval input for its own recipient, conforms to the contract, and follows the turn', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    const code = await requestCode(world, token);
    const created = await createSession(world, token, code);
    assert.equal(created.status, 201);
    const cookie = [created.headers['set-cookie']].flat()[0];
    assert.ok(/^__Host-opensig_rs=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict$/.test(cookie), 'a host-only, HTTPS-only, script-inaccessible, same-site cookie');
    const session = cookieOf(created);
    const state = created.json;
    assert.deepEqual(contractErrors('RecipientSessionState', state), []);
    const read = await readAs(world, session);
    assert.equal(read.status, 200);
    assert.deepEqual(contractErrors('RecipientSessionState', read.json), []);
    const comparable = (value) => sha256(JSON.stringify({ ...value, session_expires_at: null }));
    assert.equal(comparable(read.json), comparable(state), 'read returns what create returned');

    const recipient1 = envelope.recipients.find((entry) => entry.ordinal === 1);
    assert.equal(state.envelope_id, envelope.id);
    assert.equal(state.envelope_version, envelope.version);
    assert.equal(state.envelope_state, 'sent');
    assert.deepEqual(state.recipient, { id: recipient1.id, ordinal: 1, role: 'approver', email_masked: 's***e@example.test', status: 'invited' });
    assert.equal(state.turn, 'yours');
    assert.deepEqual(state.document, envelope.document, 'the frozen document summary');
    assert.equal(state.manifest_digest, envelope.manifest_digest);
    assert.deepEqual(state.fields.map((field) => field.key), ['date_1', 'sig_1'], "only this recipient's fields");
    assert.ok(state.fields.every((field) => field.recipient_id === recipient1.id));
    assert.equal(state.prior_approval_digest, null, 'recipient 1 has no prior approval');
    assert.deepEqual(state.consent, { version: '2026.11-synthetic', text_digest: sha256(Buffer.from(CONSENT_WORDING, 'utf8')), text: CONSENT_WORDING }, 'the exact consent text, version and digest');
    assert.equal(state.assurance.method, 'mailbox-challenge');
    assert.equal(state.assurance.level, 'mailbox-control');
    assert.match(state.assurance.statement, /mailbox control only/);
    assert.match(state.assurance.statement, /does not verify your legal identity/);
    assert.match(state.seal_notice, /organization’s certificate/);
    assert.match(state.seal_notice, /not signed with a personal certificate/);
    assert.ok(/^[A-Za-z0-9_-]{43}$/.test(state.csrf_token), 'a 256-bit CSRF token');
    assert.ok(read.json.csrf_token === state.csrf_token, 'stable for the session');
    assert.equal(Object.keys(state).includes('email'), false);
    assert.equal(JSON.stringify(state).includes('signer.two@example.test'), false, "no other recipient's address");
    assert.equal(JSON.stringify(state).includes(token), false, 'no invitation');
    assert.equal(JSON.stringify(state).includes(session), false, 'no session value');
    const stored = world.rows('recipient_sessions')[0];
    assert.equal(stored.envelope_id, envelope.id);
    assert.equal(stored.recipient_id, recipient1.id);
    assert.equal(stored.manifest_digest, envelope.manifest_digest);
    assert.ok(stored.value_hash === sha256(Buffer.from(session, 'ascii')), 'only the SHA-256 of the session value is stored');
    assert.equal(stored.csrf_secret.length, 32, 'a 256-bit CSRF secret');
    assert.equal(Buffer.from(stored.csrf_secret).toString('base64url') === state.csrf_token, false, 'the token is derived, never the stored secret itself');

    // Recipient 2 is invited only after recipient 1's approval, and sees its prior approval digest.
    const { approval, outcome, token: token2 } = await approveFirst(world, envelope);
    assert.equal(outcome.state, 'in-progress');
    assert.ok(token2 !== null, "recipient 2's invitation is mailed after the approval commits");
    const two = await openSession(world, token2, 'signer.two@example.test');
    assert.deepEqual(contractErrors('RecipientSessionState', two.state), []);
    assert.equal(two.state.recipient.ordinal, 2);
    assert.equal(two.state.turn, 'yours');
    assert.equal(two.state.envelope_state, 'in-progress');
    assert.equal(two.state.prior_approval_digest, approval.digest, "recipient 1's approval digest");
    assert.deepEqual(two.state.fields.map((field) => field.key), ['sig_2']);
    const after = await readAs(world, session);
    assert.equal(after.json.turn, 'done', 'recipient 1 has approved');
    assert.equal(after.json.recipient.status, 'approved');
    assert.equal(after.json.envelope_version, envelope.version + 1);

    // An operator credential is never a recipient credential.
    assertError(await readAs(world, session, '/v1/recipient-session', { headers: { authorization: 'Bearer operator.token.synthetic' } }), 401, 'unauthenticated', 'an Authorization header');
    // An ambiguous or malformed cookie never authenticates.
    assertError(await world.http({ path: '/v1/recipient-session', headers: { cookie: `${COOKIE}=${session}; ${COOKIE}=${two.session}` } }), 401, 'unauthenticated', 'two session cookies');
    assertError(await world.http({ path: '/v1/recipient-session', headers: { cookie: `${COOKIE}=not-a-session` } }), 401, 'unauthenticated', 'a malformed cookie');
    assertError(await world.http({ path: '/v1/recipient-session', headers: { cookie: `${COOKIE}=${randomBytes(32).toString('base64url')}` } }), 401, 'unauthenticated', 'an unknown session');
  } finally {
    await world.close();
  }
});
