// SPDX-License-Identifier: Apache-2.0
//
// T034 sending (SC002-24, EA-05; contracts/sessions-events-adapters.md § Sending and human
// confirmation; data-model.md § Envelope states, `sent`).
//
// - A send needs a valid human SendConfirmation when the envelope is service-created or the
//   sender is a service (A-010): without one it is 409 confirmation_required; with another
//   envelope's or a consumed reference it is 409 confirmation_invalid. A service calling
//   confirmSend is 403. A human sender of a human-created envelope needs none.
// - Invitations reach the recipient by mail only: the send response carries no link, token or
//   code, and neither do the logs.
// - resendInvitation passes the authenticated operator to the ceremony, so its audit events
//   name that operator, never the system (EA-05, row T008FU-D8). The resend is made by a
//   second operator, distinct from the envelope's creator, so the events must name the one
//   who resent (row T034R-EA05).
// - void and reissue are human-only (403 for a service, from the router and from the handler's
//   own check), void revokes the outstanding capabilities, and reissue makes a linked draft.
// Every request goes through the real router; mail goes to the local spool only.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { HttpError } from '../../../src/server/types.ts';
import {
  assertSameRows,
  confirmRequest,
  contractErrors,
  createInput,
  createWorld,
  newKey,
  preparedEnvelope,
  readEnvelope,
  readPreview,
  resendRequest,
  sendRequest,
  sentEnvelope,
  takeInvitation,
  voidRequest,
} from './support.mjs';

/** A second sender of tenant alpha, distinct from the fixture's sender (synthetic subject; T034R-EA05). */
const SECOND_SENDER_SUBJECT = 'alpha-sender-0002';

let world;
before(async () => {
  world = await createWorld();
});
after(async () => {
  await world?.close();
});

/** The response carries none of `values`, in its body or its headers, and no link to the review shell. */
function assertNoCapability(response, values, label) {
  const headers = JSON.stringify(response.rawHeaders);
  for (const value of values) {
    assert.ok(!response.text.includes(value), `${label}: the body carries no capability value`);
    assert.ok(!headers.includes(value), `${label}: the headers carry no capability value`);
  }
  assert.ok(!/\/sign#|#i=/.test(response.text), `${label}: no review-shell link`);
}

test('[SC002-24] a service-created envelope is sent only with a human operator\'s confirmation: 409 confirmation_required without one, 403 for a service confirmSend, 200 with a human authorization_reference', async () => {
  const prepared = await preparedEnvelope(world, { who: 'service' });
  assert.equal(prepared.created_by.kind, 'service');
  assert.equal(prepared.send_confirmation.required, true, 'the view says a confirmation is required');
  const servicePreview = await readPreview(world, { who: 'service', envelope: prepared });
  assert.equal(servicePreview.requires_human_confirmation, true);

  const rows = world.snapshot();
  const unconfirmed = await sendRequest(world, { who: 'service', envelope: prepared });
  assert.deepEqual([unconfirmed.status, unconfirmed.json?.code], [409, 'confirmation_required'], 'a service send without a confirmation');
  const humanUnconfirmed = await sendRequest(world, { who: 'sender', envelope: prepared });
  assert.deepEqual([humanUnconfirmed.status, humanUnconfirmed.json?.code], [409, 'confirmation_required'], 'a service-created envelope needs a confirmation whoever sends it');
  const serviceConfirm = await confirmRequest(world, { who: 'service', envelope: prepared });
  assert.deepEqual([serviceConfirm.status, serviceConfirm.json?.code], [403, 'forbidden'], 'a service principal can never confirm a send');
  assertSameRows(world.snapshot(), rows, 'the refusals changed nothing');
  assert.equal(world.mails().length, 0, 'and mailed nothing');

  // A human confirms the preview; the service sends with the single-use reference.
  const confirmed = await confirmRequest(world, { who: 'sender', envelope: prepared });
  assert.equal(confirmed.status, 201);
  assert.deepEqual(contractErrors('SendConfirmation', confirmed.json), []);
  assert.equal(confirmed.json.confirmed_by.kind, 'human-operator');
  assert.equal(confirmed.json.envelope_version, prepared.version, 'a confirmation does not change the version');
  const reference = confirmed.json.authorization_reference;
  const sent = await sendRequest(world, { who: 'service', envelope: prepared, reference });
  assert.equal(sent.status, 200, `the confirmed send (${sent.json?.code ?? 'no code'})`);
  assert.equal(sent.json.state, 'sent');
  assert.equal(sent.json.version, prepared.version + 1);
  const token = takeInvitation(world);
  assertNoCapability(sent, [token], 'the service send');
  assert.ok(!world.logText().includes(token), 'no log line carries the invitation');

  // The reference was consumed: another send with it is confirmation_invalid.
  const again = await preparedEnvelope(world, { who: 'service' });
  const reused = await sendRequest(world, { who: 'service', envelope: again, reference });
  assert.deepEqual([reused.status, reused.json?.code], [409, 'confirmation_invalid'], 'a consumed reference, or one for another envelope, is invalid');
  assert.equal(world.mails().length, 1, 'only the confirmed send mailed');
});

test('[SC002-24] a service send of a human-created envelope also needs a human confirmation (A-010), while a human sender needs none', async () => {
  const prepared = await preparedEnvelope(world, { who: 'sender' });
  assert.equal(prepared.created_by.kind, 'human-operator');
  assert.equal(prepared.send_confirmation.required, false, 'the creator rule alone does not require one');
  assert.equal((await readPreview(world, { who: 'service', envelope: prepared })).requires_human_confirmation, true, 'the preview applies the rule to the reading service');
  assert.equal((await readPreview(world, { who: 'sender', envelope: prepared })).requires_human_confirmation, false);

  const unconfirmed = await sendRequest(world, { who: 'service', envelope: prepared });
  assert.deepEqual([unconfirmed.status, unconfirmed.json?.code], [409, 'confirmation_required'], 'a service send of a human-created envelope without a confirmation');
  assert.equal(world.takeMails('recipient_invitation').length, 0);

  const other = await preparedEnvelope(world, { who: 'sender' });
  const otherReference = (await confirmRequest(world, { who: 'sender', envelope: other })).json.authorization_reference;
  const misbound = await sendRequest(world, { who: 'service', envelope: prepared, reference: otherReference });
  assert.deepEqual([misbound.status, misbound.json?.code], [409, 'confirmation_invalid'], 'another envelope\'s confirmation');

  const reference = (await confirmRequest(world, { who: 'admin', envelope: prepared })).json.authorization_reference;
  const sent = await sendRequest(world, { who: 'service', envelope: prepared, reference });
  assert.equal(sent.status, 200, `the service send with a tenant admin's confirmation (${sent.json?.code ?? 'no code'})`);
  takeInvitation(world);

  // A human sender of a human-created envelope sends without a confirmation.
  const plain = await sendRequest(world, { who: 'sender', envelope: other });
  assert.equal(plain.status, 200);
  assert.equal(plain.json.state, 'sent');
  const token = takeInvitation(world);
  assertNoCapability(plain, [token], 'the human send');
});

test('[EA-05] resendInvitation names the operator who resent, a second operator distinct from the envelope\'s creator, as the actor of its audit events, revokes the old invitation and mails a new one', async () => {
  const { envelope, token: first } = await sentEnvelope(world);
  const creator = envelope.created_by;
  assert.equal(creator.kind, 'human-operator');
  const recipient = envelope.recipients[0];

  // A second operator of the tenant (T034R-EA05): another human sender, with its own subject.
  // Its reference is learnt from the API itself, through an envelope it creates.
  const asSecondOperator = { overrides: { sub: SECOND_SENDER_SUBJECT } };
  const theirs = await world.op({ ...asSecondOperator, method: 'POST', path: '/v1/envelopes', body: createInput(1) });
  assert.equal(theirs.status, 201);
  const resender = theirs.json.created_by;
  assert.equal(resender.kind, 'human-operator');
  assert.notEqual(resender.ref, creator.ref, 'the second operator is an identity distinct from the creator');
  const seq = Math.max(0, ...world.rows('audit_events', 'WHERE tenant_id = ?', [world.tenantId('alpha')]).map((row) => Number(row.seq)));

  const resent = await resendRequest(world, { ...asSecondOperator, envelope, recipient });
  assert.equal(resent.status, 202);
  assert.deepEqual(resent.json, { status: 'accepted' });
  assert.deepEqual(contractErrors('Accepted', resent.json), []);
  const second = takeInvitation(world);
  assert.ok(second !== first, 'a fresh invitation was mailed');
  assertNoCapability(resent, [first, second], 'the resend');

  const events = world.rows('audit_events', 'WHERE tenant_id = ? AND seq > ? AND envelope_id = ?', [world.tenantId('alpha'), seq, envelope.id]);
  const types = events.map((row) => row.type);
  assert.ok(types.includes('recipient.capabilities_revoked'), 'the resend recorded what it revoked');
  assert.ok(types.includes('recipient.invited'), 'and the new invitation');
  for (const row of events) {
    assert.equal(row.actor_kind, 'human-operator', `${row.type}: the actor is an operator, not the system`);
    assert.equal(row.actor_ref, resender.ref, `${row.type}: the actor is the operator who resent`);
    assert.notEqual(row.actor_ref, creator.ref, `${row.type}: not the envelope's creator`);
  }
  const invitations = world.rows('invitations', 'WHERE envelope_id = ?', [envelope.id]);
  assert.equal(invitations.length, 2);
  assert.equal(invitations.filter((row) => row.revoked_at === null).length, 1, 'only the new invitation is live');
  assert.equal((await readEnvelope(world, { envelope })).version, envelope.version, 'a resend leaves the envelope version');

  // Only the current-turn, invited recipient of an approving envelope can be resent.
  const stale = await resendRequest(world, { envelope, recipient, version: envelope.version + 1 });
  assert.deepEqual([stale.status, stale.json?.code], [409, 'version_conflict']);
  const service = await resendRequest(world, { who: 'service', envelope, recipient });
  assert.deepEqual([service.status, service.json?.code], [403, 'forbidden'], 'a service principal cannot resend');
  const two = await sentEnvelope(world, { recipients: 2 });
  const notYet = await resendRequest(world, { envelope: two.envelope, recipient: two.envelope.recipients[1] });
  assert.deepEqual([notYet.status, notYet.json?.code], [409, 'order_conflict'], 'recipient 2 before its turn');
  const voided = await voidRequest(world, { envelope });
  assert.equal(voided.status, 200);
  const afterVoid = await resendRequest(world, { envelope: voided.json, recipient });
  assert.deepEqual([afterVoid.status, afterVoid.json?.code], [409, 'state_conflict'], 'nothing to resend on a voided envelope');
  assert.equal(world.takeMails('recipient_invitation').length, 0, 'the refusals mailed nothing');
});

test('[EH-01] void and reissue are human-only: void revokes the outstanding capabilities, reissue makes a linked draft that copies the document and recipients', async () => {
  const { envelope } = await sentEnvelope(world, { recipients: 2 });
  const serviceVoid = await voidRequest(world, { who: 'service', envelope });
  assert.deepEqual([serviceVoid.status, serviceVoid.json?.code], [403, 'forbidden'], 'the router refuses a service void');
  // The handler's own check, behind the router's.
  const principal = Object.freeze({ scheme: 'operator', tenant_id: world.tenantId('alpha'), kind: 'service', roles: Object.freeze(['service']), scopes: Object.freeze(['envelopes:void']), ref: 'svc-synthetic-ref-01', issuer: 'https://issuer.alpha.test', expires_at: 0 });
  const refusedByHandler = (error) => error instanceof HttpError && error.status === 403 && error.code === 'forbidden';
  await assert.rejects(async () => world.api.void(principal, envelope.id, newKey(), { expected_version: envelope.version, reason_code: 'other' }), refusedByHandler);
  await assert.rejects(async () => world.api.confirmSend(principal, envelope.id, newKey(), {}), refusedByHandler);
  await assert.rejects(async () => world.api.reissue(principal, envelope.id, newKey(), { expected_version: envelope.version }), refusedByHandler);
  await assert.rejects(async () => world.api.resend(principal, envelope.id, envelope.recipients[0].id, newKey(), { expected_version: envelope.version }), refusedByHandler);
  assert.equal(world.rows('envelopes', 'WHERE id = ?', [envelope.id])[0].state, 'sent', 'the refused calls changed nothing');

  const voided = await voidRequest(world, { who: 'admin', envelope });
  assert.equal(voided.status, 200);
  assert.equal(voided.json.state, 'voided');
  assert.equal(voided.json.version, envelope.version + 1);
  assert.ok(voided.json.recipients.every((recipient) => recipient.status === 'revoked'), 'every open recipient is revoked');
  assert.equal(world.rows('invitations', 'WHERE envelope_id = ? AND revoked_at IS NULL', [envelope.id]).length, 0, 'no live invitation is left');
  const late = await voidRequest(world, { envelope: voided.json });
  assert.deepEqual([late.status, late.json?.code], [409, 'state_conflict'], 'a voided envelope is terminal');

  const reissued = await world.op({ method: 'POST', path: `/v1/envelopes/${envelope.id}/reissue`, body: { expected_version: voided.json.version } });
  assert.equal(reissued.status, 201);
  assert.deepEqual(contractErrors('Envelope', reissued.json), []);
  assert.equal(reissued.json.state, 'draft');
  assert.equal(reissued.json.reissue_of, envelope.id);
  assert.equal(reissued.json.version, 2, 'version 1 at insert, + 1 for the copied document');
  assert.equal(reissued.json.document.digest, envelope.document.digest, 'the document is copied');
  assert.deepEqual(reissued.json.recipients.map((r) => [r.ordinal, r.email, r.status]), envelope.recipients.map((r) => [r.ordinal, r.email, 'pending']), 'the recipients are copied, never the approvals');
  const prior = await readEnvelope(world, { envelope });
  assert.equal(prior.reissued_as, reissued.json.id);
  const twice = await world.op({ method: 'POST', path: `/v1/envelopes/${envelope.id}/reissue`, body: { expected_version: prior.version } });
  assert.deepEqual([twice.status, twice.json?.code], [409, 'state_conflict'], 'an envelope is reissued once');
  assert.equal(world.takeMails('recipient_invitation').length, 0, 'void and reissue mail no invitation');
});
