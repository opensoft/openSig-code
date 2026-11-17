// SPDX-License-Identifier: Apache-2.0
//
// T010 decline through the real server (contracts/sessions-events-adapters.md § Recipient
// ceremony, item 6): the recipient whose turn it is declines; the envelope moves to declined
// through the compare-and-set it shares with approval, void and expiry (version + 1); the
// recipient is declined and every other recipient still pending or invited is revoked, as on
// void (A-010, request #24, ruling (5)); every outstanding invitation and session of the
// envelope is revoked and that revocation is in the audit chain; envelope.declined is in the
// outbox exactly once, written in the decline's transaction (ruling (6)); the response is the
// generic DeclineOutcome. A decline out of turn, at a stale version, of an envelope that no
// longer takes approvals, or with a reason outside the contract's enumeration is refused and
// records nothing, no outbox event included.
// Everything is synthetic (see support.mjs).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  GUARD_TOUCH,
  approvalBody,
  assertError,
  auditEvents,
  contractErrors,
  createWorld,
  envelopeRow,
  metadataOf,
  openSession,
  outboxOf,
  postApproval,
  postDecline,
  readSession,
  secondToken,
  sentEnvelope,
} from './support.mjs';

test('[AP-10] a decline moves the envelope to declined through the shared compare-and-set, revokes every outstanding capability with an audit record, and records nothing when refused', async () => {
  const world = await createWorld();
  try {
    // 1. Recipient 1 of two declines with a reason.
    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    const session = await openSession(world, token);
    const v = session.state.envelope_version;
    const before = world.snapshot(GUARD_TOUCH);
    for (const [label, body] of [
      ['a reason outside the enumeration', { expected_version: v, reason_code: 'bored' }],
      ['a free-text reason member', { expected_version: v, reason: 'free text' }],
      ['no expected_version', { reason_code: 'other' }],
      ['a fractional expected_version', { expected_version: v + 0.5 }],
      ['an array body', [v]],
      ['JSON that does not parse', '{"expected_version":'],
    ]) {
      assertError(await postDecline(world, session, body), 400, 'invalid_request', label);
    }
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'a malformed decline records nothing');

    const declined = await postDecline(world, session, { expected_version: v, reason_code: 'not-my-document' });
    assert.equal(declined.status, 200, 'the decline succeeds');
    assert.equal(declined.text, '{"envelope_state":"declined"}', 'the generic outcome');
    const row = envelopeRow(world, envelope.id);
    assert.deepEqual({ state: row.state, version: row.version, approvals_complete: row.approvals_complete }, { state: 'declined', version: v + 1, approvals_complete: 0 }, 'declined at version + 1');
    const recipients = world.rows('recipients', 'WHERE envelope_id = ?', [envelope.id]).sort((x, y) => x.ordinal - y.ordinal);
    assert.deepEqual(recipients.map((entry) => entry.status), ['declined', 'revoked'], 'recipient 1 declined; recipient 2, who can never be invited, is revoked');
    const invitations = world.rows('invitations', 'WHERE envelope_id = ?', [envelope.id]);
    const sessions = world.rows('recipient_sessions', 'WHERE envelope_id = ?', [envelope.id]);
    assert.ok(invitations.length >= 1 && invitations.every((entry) => entry.revoked_at !== null), 'every invitation is revoked');
    assert.ok(sessions.length >= 1 && sessions.every((entry) => entry.revoked_at !== null), 'every session is revoked');
    assert.equal(world.rows('approvals', 'WHERE envelope_id = ?', [envelope.id]).length, 0, 'no approval');
    assert.equal(world.rows('signing_jobs', 'WHERE envelope_id = ?', [envelope.id]).length, 0, 'no reservation');

    // The audit chain: the decline with its reason, then what it revoked, by id only.
    const declinedEvents = auditEvents(world, 'recipient.declined').filter((event) => event.envelope_id === envelope.id);
    assert.equal(declinedEvents.length, 1);
    assert.equal(declinedEvents[0].actor_kind, 'recipient');
    assert.equal(declinedEvents[0].actor_ref, recipients[0].id);
    assert.deepEqual(metadataOf(declinedEvents[0]), { envelope_version: v + 1, reason: 'not-my-document', recipient_id: recipients[0].id, recipient_ordinal: 1 });
    const revokedEvents = auditEvents(world, 'recipient.capabilities_revoked').filter((event) => event.envelope_id === envelope.id);
    assert.equal(revokedEvents.length, 1, 'one revocation record');
    const revoked = metadataOf(revokedEvents[0]);
    const at = row.updated_at;
    assert.deepEqual([...revoked.invitation_ids].sort(), invitations.filter((entry) => entry.revoked_at === at).map((entry) => entry.id).sort(), 'it names every invitation the decline revoked');
    assert.deepEqual([...revoked.session_ids].sort(), sessions.filter((entry) => entry.revoked_at === at).map((entry) => entry.id).sort(), 'it names every session the decline revoked');
    assert.ok(sessions.some((entry) => entry.revoked_at === at && revoked.session_ids.includes(entry.id)), 'the declining session is among them');
    assert.equal(revoked.envelope_version, v + 1);
    assert.ok(revokedEvents[0].seq > declinedEvents[0].seq, 'recorded after the decline');

    // The webhook announcement: envelope.declined, exactly once, at the declined version.
    const announced = outboxOf(world, envelope.id, 'envelope.declined');
    assert.equal(announced.length, 1, 'exactly one envelope.declined event');
    assert.equal(announced[0].envelope_version, v + 1);
    assert.deepEqual(contractErrors('WebhookEvent', announced[0].payload), [], 'a contract WebhookEvent');
    assert.deepEqual(
      { type: announced[0].payload.type, envelope_id: announced[0].payload.envelope_id, envelope_version: announced[0].payload.envelope_version, occurred_at: announced[0].payload.occurred_at },
      { type: 'envelope.declined', envelope_id: envelope.id, envelope_version: v + 1, occurred_at: row.updated_at },
      'it names the envelope, the declined version and the decline instant',
    );
    assert.equal(world.rows('outbox_events', 'WHERE envelope_id = ?', [envelope.id]).length, 1, 'and no other event for the envelope');

    // The session that declined is no longer live: a repeated decline or an approval is 401.
    const afterDecline = world.snapshot();
    assertError(await postDecline(world, session, { expected_version: v + 1 }), 401, 'unauthenticated', 'a repeated decline');
    assertError(await postApproval(world, session, approvalBody(session.state)), 401, 'unauthenticated', 'an approval after the decline');
    assert.equal((await readSession(world, session)).status, 401, 'the session cannot be read');
    assert.deepEqual(world.snapshot(), afterDecline, 'nothing changes');

    // 2. Recipient 2 declines after recipient 1 approved (in-progress -> declined); recipient 1's
    // session is revoked too.
    const second = await sentEnvelope(world, { recipients: 2 });
    const firstSession = await openSession(world, second.token);
    assert.equal((await postApproval(world, firstSession, approvalBody(firstSession.state))).status, 200, 'recipient 1 approves');
    const secondSession = await openSession(world, secondToken(world), 'signer.two@example.test');
    const w = secondSession.state.envelope_version;
    const beforeSecond = world.snapshot(GUARD_TOUCH);
    assertError(await postDecline(world, secondSession, { expected_version: w - 1 }), 409, 'version_conflict', 'recipient 2 at a stale version');
    assertError(await postDecline(world, firstSession, { expected_version: w }), 409, 'order_conflict', 'recipient 1, who has approved, cannot decline');
    assert.deepEqual(world.snapshot(GUARD_TOUCH), beforeSecond, 'nothing is recorded');
    const ok = await postDecline(world, secondSession, { expected_version: w });
    assert.equal(ok.status, 200, 'recipient 2 declines');
    assert.equal(envelopeRow(world, second.envelope.id).state, 'declined');
    assert.equal(envelopeRow(world, second.envelope.id).version, w + 1);
    assert.equal((await readSession(world, firstSession)).status, 401, 'recipient 1’s session is revoked as well');
    assert.equal(world.rows('approvals', 'WHERE envelope_id = ?', [second.envelope.id]).length, 1, 'recipient 1’s approval stays as evidence');
    assert.equal(world.rows('signing_jobs', 'WHERE envelope_id = ?', [second.envelope.id]).length, 0, 'no reservation');
    assert.deepEqual(metadataOf(auditEvents(world, 'recipient.declined').find((event) => event.envelope_id === second.envelope.id)).reason, null, 'no reason given is recorded as null');
    assert.deepEqual(world.rows('recipients', 'WHERE envelope_id = ?', [second.envelope.id]).sort((x, y) => x.ordinal - y.ordinal).map((entry) => entry.status), ['approved', 'declined'], 'the approved recipient stays approved');
    assert.equal(outboxOf(world, second.envelope.id, 'envelope.declined').length, 1, 'exactly one envelope.declined event');
    assert.equal(outboxOf(world, second.envelope.id, 'envelope.declined')[0].envelope_version, w + 1);

    // 3. A fully approved envelope cannot be declined: 409 state_conflict, nothing recorded.
    const third = await sentEnvelope(world);
    const thirdSession = await openSession(world, third.token);
    const approved = await postApproval(world, thirdSession, approvalBody(thirdSession.state));
    assert.equal(approved.json.envelope_state, 'finalizing', 'premise: fully approved');
    const beforeThird = world.snapshot(GUARD_TOUCH);
    assertError(await postDecline(world, thirdSession, { expected_version: approved.json.envelope_version }), 409, 'state_conflict', 'declining a finalizing envelope');
    assert.deepEqual(world.snapshot(GUARD_TOUCH), beforeThird, 'nothing is recorded');
    assert.equal(world.rows('signing_jobs', 'WHERE envelope_id = ?', [third.envelope.id]).length, 1, 'the reservation stands');
    assert.equal(world.rows('outbox_events', 'WHERE envelope_id = ?', [third.envelope.id]).length, 0, 'a refused decline announces nothing');
  } finally {
    await world.close();
  }
});
