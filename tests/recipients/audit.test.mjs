// SPDX-License-Identifier: Apache-2.0
//
// T008, row CEREMONY-AUDIT (CH-06): the ceremony writes its steps to the
// tenant's audit chain through the T029 writer, in the transaction of the step:
// recipient.invited, recipient.challenge_verified, recipient.session_created,
// recipient.locked_out and recipient.capabilities_revoked. Their metadata holds
// ids, ordinals and digests only; no audit row carries a capability value, a
// code, an email address, or a stored capability hash or HMAC (spec.md
// clarification: no audit event contains a link, token or code). The chain
// still verifies.
//
// The clock stands still from the resend to the void, so the void's
// revocation event must leave out what the resend and the ended session had
// already revoked at the same instant.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { verifyChain } from '../../src/storage/audit/index.ts';
import {
  COOKIE,
  HOUR,
  HUMAN,
  ORIGIN,
  approveFirst,
  createSession,
  createWorld,
  lockOut,
  openSession,
  requestCode,
  resend,
  sentEnvelope,
  wrongCode,
} from './support.mjs';

const TYPES = Object.freeze(['recipient.invited', 'recipient.challenge_verified', 'recipient.session_created', 'recipient.locked_out', 'recipient.capabilities_revoked']);
const ID = /^[A-Za-z0-9_-]{16,64}$/;
const SYSTEM = Object.freeze({ kind: 'system', ref: 'recipient-ceremony' });

/** Metadata members and the shape of their values: ids, lists of ids, or ordinals. */
const MEMBERS = Object.freeze({
  invitation_id: 'id',
  challenge_id: 'id',
  session_id: 'id',
  recipient_id: 'id',
  revision_id: 'id',
  invitation_ids: 'ids',
  session_ids: 'ids',
  recipient_ordinal: 'ordinal',
  attempt: 'ordinal',
  wrong_attempt: 'ordinal',
  envelope_version: 'ordinal',
});

function events(world, envelopeId) {
  return world
    .rows('audit_events', `WHERE envelope_id = '${envelopeId}'`)
    .filter((row) => row.type.startsWith('recipient.'))
    .map((row) => ({ type: row.type, actor: { kind: row.actor_kind, ref: row.actor_ref }, subject: row.subject_digest, metadata: JSON.parse(row.metadata_json) }));
}

function recipientOf(envelope, ordinal) {
  return envelope.recipients.find((entry) => entry.ordinal === ordinal);
}

function invitationIds(world, envelopeId, recipientId) {
  return world.rows('invitations', `WHERE envelope_id = '${envelopeId}' AND recipient_id = '${recipientId}'`).map((row) => row.id);
}

test('[CH-06] the ceremony writes recipient.* audit events in the step\'s transaction, with ids, ordinals and digests only, never a capability value, code or email', async () => {
  const world = await createWorld();
  try {
    const secrets = [];
    // A: two recipients. Recipient 1 is invited at send, verifies on the second attempt and opens a session.
    const a = await sentEnvelope(world, { recipients: 2 });
    secrets.push(a.token);
    const r1 = recipientOf(a.envelope, 1);
    const r2 = recipientOf(a.envelope, 2);
    const code = await requestCode(world, a.token);
    secrets.push(code);
    assert.equal((await createSession(world, a.token, wrongCode(code))).status, 401);
    const created = await createSession(world, a.token, code);
    assert.equal(created.status, 201);
    const s1 = world.rows('recipient_sessions')[0];
    const cookie1 = /^__Host-opensig_rs=([^;]+);/.exec([created.headers['set-cookie']].flat()[0])[1];
    secrets.push(cookie1, created.json.csrf_token);
    const [inviteR1] = invitationIds(world, a.envelope.id, r1.id);
    const verifiedR1 = world.rows('challenges').find((row) => row.consumed_at !== null);

    // Recipient 1 approves: recipient 2 is invited (a system step); an operator resends to recipient 2.
    const approved = await approveFirst(world, a.envelope);
    secrets.push(approved.token);
    const [firstR2] = invitationIds(world, a.envelope.id, r2.id);
    const freshR2Token = await resend(world, a.envelope, r2, HUMAN);
    secrets.push(freshR2Token);
    const secondR2 = invitationIds(world, a.envelope.id, r2.id).find((id) => id !== firstR2);
    // Recipient 1 ends their session; recipient 2 opens one.
    const ended = await world.http({ method: 'DELETE', path: '/v1/recipient-session', headers: { origin: ORIGIN, cookie: `${COOKIE}=${cookie1}`, 'x-csrf-token': created.json.csrf_token } });
    assert.equal(ended.status, 204);
    const opened2 = await openSession(world, freshR2Token, 'signer.two@example.test');
    secrets.push(opened2.session, opened2.csrf);
    const s2 = world.rows('recipient_sessions').find((row) => row.recipient_id === r2.id);
    const verifiedR2 = world.rows('challenges').find((row) => row.consumed_at !== null && row.invitation_id === secondR2);
    // The operator voids A at the same instant.
    const current = world.service.read(world.req(), a.envelope.id);
    world.service.void(world.req(), a.envelope.id, { expected_version: current.version, reason_code: 'sender-cancelled' });

    // B: twenty wrong codes lock the invitation out.
    const b = await sentEnvelope(world);
    secrets.push(b.token);
    await lockOut(world, b.token);
    const [inviteB] = invitationIds(world, b.envelope.id, recipientOf(b.envelope, 1).id);
    const lastB = world.rows('challenges').filter((row) => world.rows('invitations').some((inv) => inv.id === row.invitation_id && inv.envelope_id === b.envelope.id)).at(-1);

    // C: a session, then the envelope expires (a system step).
    const c = await sentEnvelope(world, { expiresAt: new Date(world.time.now.getTime() + 2 * HOUR).toISOString() });
    secrets.push(c.token);
    const openedC = await openSession(world, c.token);
    secrets.push(openedC.session, openedC.csrf);
    const rc = recipientOf(c.envelope, 1);
    const [inviteC] = invitationIds(world, c.envelope.id, rc.id);
    const sC = world.rows('recipient_sessions').find((row) => row.envelope_id === c.envelope.id);
    const verifiedC = world.rows('challenges').find((row) => row.invitation_id === inviteC && row.consumed_at !== null);
    world.time.advance(3 * HOUR);
    assert.equal(world.service.expireIfDue(world.tenant, c.envelope.id), true, 'C expires');

    // Reissuing the voided A revokes nothing more, so it writes no recipient event.
    const voided = world.service.read(world.req(), a.envelope.id);
    world.service.reissue(world.req(), a.envelope.id, { expected_version: voided.version });

    const manifestA = a.envelope.manifest_digest;
    const operator = { kind: HUMAN.kind, ref: HUMAN.ref };
    const asRecipient = (recipient) => ({ kind: 'recipient', ref: recipient.id });
    const expectedA = [
      { type: 'recipient.invited', actor: operator, subject: manifestA, metadata: { invitation_id: inviteR1, recipient_id: r1.id, recipient_ordinal: 1, revision_id: s1.revision_id } },
      { type: 'recipient.challenge_verified', actor: asRecipient(r1), subject: manifestA, metadata: { invitation_id: inviteR1, challenge_id: verifiedR1.id, recipient_id: r1.id, recipient_ordinal: 1, attempt: 2 } },
      { type: 'recipient.session_created', actor: asRecipient(r1), subject: manifestA, metadata: { session_id: s1.id, invitation_id: inviteR1, recipient_id: r1.id, recipient_ordinal: 1, revision_id: s1.revision_id } },
      { type: 'recipient.invited', actor: SYSTEM, subject: manifestA, metadata: { invitation_id: firstR2, recipient_id: r2.id, recipient_ordinal: 2, revision_id: s1.revision_id } },
      { type: 'recipient.capabilities_revoked', actor: operator, subject: manifestA, metadata: { recipient_id: r2.id, recipient_ordinal: 2, invitation_ids: [firstR2], session_ids: [] } },
      { type: 'recipient.invited', actor: operator, subject: manifestA, metadata: { invitation_id: secondR2, recipient_id: r2.id, recipient_ordinal: 2, revision_id: s1.revision_id } },
      { type: 'recipient.capabilities_revoked', actor: asRecipient(r1), subject: manifestA, metadata: { recipient_id: r1.id, recipient_ordinal: 1, invitation_ids: [], session_ids: [s1.id] } },
      { type: 'recipient.challenge_verified', actor: asRecipient(r2), subject: manifestA, metadata: { invitation_id: secondR2, challenge_id: verifiedR2.id, recipient_id: r2.id, recipient_ordinal: 2, attempt: 1 } },
      { type: 'recipient.session_created', actor: asRecipient(r2), subject: manifestA, metadata: { session_id: s2.id, invitation_id: secondR2, recipient_id: r2.id, recipient_ordinal: 2, revision_id: s1.revision_id } },
      // The void names only what it revoked: not recipient 2's first invitation (the resend) or session 1 (ended).
      { type: 'recipient.capabilities_revoked', actor: operator, subject: manifestA, metadata: { envelope_version: current.version + 1, invitation_ids: [inviteR1, secondR2], session_ids: [s2.id] } },
    ];
    assert.deepEqual(events(world, a.envelope.id), expectedA, 'envelope A: invitations, verification, sessions, resend, end and void, in order');

    const manifestB = b.envelope.manifest_digest;
    const rb = recipientOf(b.envelope, 1);
    assert.deepEqual(events(world, b.envelope.id), [
      { type: 'recipient.invited', actor: operator, subject: manifestB, metadata: { invitation_id: inviteB, recipient_id: rb.id, recipient_ordinal: 1, revision_id: world.rows('invitations').find((row) => row.id === inviteB).revision_id } },
      { type: 'recipient.locked_out', actor: SYSTEM, subject: manifestB, metadata: { invitation_id: inviteB, challenge_id: lastB.id, recipient_id: rb.id, recipient_ordinal: 1, wrong_attempt: 20 } },
    ], 'envelope B: the twentieth wrong code locks the invitation out, and no verification is recorded');

    const manifestC = c.envelope.manifest_digest;
    assert.deepEqual(events(world, c.envelope.id), [
      { type: 'recipient.invited', actor: operator, subject: manifestC, metadata: { invitation_id: inviteC, recipient_id: rc.id, recipient_ordinal: 1, revision_id: sC.revision_id } },
      { type: 'recipient.challenge_verified', actor: asRecipient(rc), subject: manifestC, metadata: { invitation_id: inviteC, challenge_id: verifiedC.id, recipient_id: rc.id, recipient_ordinal: 1, attempt: 1 } },
      { type: 'recipient.session_created', actor: asRecipient(rc), subject: manifestC, metadata: { session_id: sC.id, invitation_id: inviteC, recipient_id: rc.id, recipient_ordinal: 1, revision_id: sC.revision_id } },
      { type: 'recipient.capabilities_revoked', actor: SYSTEM, subject: manifestC, metadata: { envelope_version: c.envelope.version + 1, invitation_ids: [inviteC], session_ids: [sC.id] } },
    ], 'envelope C: the expiry (a system step) revokes the invitation and the session');

    // Every recipient event, whatever its envelope: a known type and actor, a digest subject, and
    // metadata of ids, ordinals and digests only. The reissued draft has no invitation and no event.
    const rows = world.rows('audit_events');
    const ceremonyRows = rows.filter((row) => row.type.startsWith('recipient.'));
    assert.equal(ceremonyRows.length, expectedA.length + 2 + 4, 'every recipient event is one of those above');
    for (const row of ceremonyRows) {
      const label = `seq ${row.seq} ${row.type}`;
      assert.ok(TYPES.includes(row.type), `${label}: a ceremony event type`);
      assert.ok(['human-operator', 'service', 'recipient', 'system'].includes(row.actor_kind), `${label}: actor kind`);
      assert.ok(row.actor_kind !== 'recipient' || ID.test(row.actor_ref), `${label}: a recipient actor is named by its id`);
      assert.ok(/^[0-9a-f]{64}$/.test(row.subject_digest), `${label}: the subject is the manifest digest`);
      for (const [name, value] of Object.entries(JSON.parse(row.metadata_json))) {
        const shape = MEMBERS[name];
        assert.ok(shape !== undefined, `${label}: metadata member ${name} is an id, a list of ids or an ordinal`);
        if (shape === 'id') assert.ok(typeof value === 'string' && ID.test(value), `${label}: ${name} is an id`);
        if (shape === 'ids') assert.ok(Array.isArray(value) && value.every((entry) => typeof entry === 'string' && ID.test(entry)), `${label}: ${name} lists ids`);
        if (shape === 'ordinal') assert.ok(Number.isSafeInteger(value) && value >= 1, `${label}: ${name} is an ordinal`);
      }
    }

    // No audit row, of any type, carries a capability value, a code, an email address, or a stored
    // token hash, session hash, code HMAC or CSRF secret.
    const text = JSON.stringify(rows);
    const stored = [
      ...world.rows('invitations').map((row) => row.token_hash),
      ...world.rows('recipient_sessions').flatMap((row) => [row.value_hash, Buffer.from(row.csrf_secret).toString('hex'), Buffer.from(row.csrf_secret).toString('base64url')]),
      ...world.rows('challenges').map((row) => row.code_hmac),
    ];
    assert.ok(secrets.every((value) => typeof value === 'string' && value.length >= 10), 'the capability values were collected');
    assert.equal(secrets.filter((value) => text.includes(value)).length, 0, 'no capability value or code appears in the audit chain');
    assert.equal(stored.filter((value) => text.includes(value)).length, 0, 'no stored capability hash, HMAC or CSRF secret appears in the audit chain');
    assert.ok(!text.includes('@'), 'no email address appears in the audit chain');

    // The chain the ceremony appended to verifies end to end.
    const report = verifyChain(world.db, world.tenant);
    assert.deepEqual(report.problems, [], 'the chain verifies');
    assert.equal(report.ok, true);
    assert.equal(report.events, rows.length);
  } finally {
    await world.close();
  }
});
