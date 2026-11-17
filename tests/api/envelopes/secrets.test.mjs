// SPDX-License-Identifier: Apache-2.0
//
// T034 stored idempotency bodies (EA-04; row IDEMP-N3; data-model.md § IdempotencyRecord).
// A record keeps the exact bytes its response carried, and an operator response never
// carries a capability value. After a send and a resend, with a recipient session opened in
// between, no stored response body holds any invitation token, challenge code, session value
// or CSRF token.
//
// The raw values are taken from the mail spool (invitations and the code) and from the
// session-create response (the session cookie and the CSRF token), kept in memory only, and
// compared as booleans: no value is ever put in a test name, an assertion message or a log.
// The check is not vacuous: it first requires the records of the send and the resend to exist
// with their bodies, and requires every value to be a non-empty string of its contract shape.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { RESEND_ROUTE } from '../../../src/api/envelopes/index.ts';
import { confirmRequest, createWorld, openSession, preparedEnvelope, resendRequest, sendRequest, takeInvitation } from './support.mjs';

let world;
before(async () => {
  world = await createWorld();
});
after(async () => {
  await world?.close();
});

const CAPABILITY_SHAPE = /^[A-Za-z0-9_-]{43,128}$/;
const CODE_SHAPE = /^[0-9A-HJKMNP-TV-Z]{10}$/;

/** How many of `texts` contain the raw `value`. */
function containing(texts, value) {
  return texts.filter((text) => text.includes(value)).length;
}

test('[EA-04] after send and resend, no stored idempotency body carries an invitation token, challenge code, session value or CSRF token', async () => {
  // A service-created envelope, so the confirmSend record (with its authorization_reference) is among the bodies too.
  const prepared = await preparedEnvelope(world, { who: 'service' });
  const confirmed = await confirmRequest(world, { who: 'sender', envelope: prepared });
  assert.equal(confirmed.status, 201);
  const sent = await sendRequest(world, { who: 'service', envelope: prepared, reference: confirmed.json.authorization_reference });
  assert.equal(sent.status, 200);
  const firstInvitation = takeInvitation(world);

  // The recipient proves mailbox control: a challenge code and a session with its CSRF token.
  const first = await openSession(world, firstInvitation);

  // The resend revokes that invitation and session and mails a new invitation; a second session follows.
  const recipient = sent.json.recipients[0];
  const resent = await resendRequest(world, { who: 'sender', envelope: sent.json, recipient });
  assert.equal(resent.status, 202);
  const secondInvitation = takeInvitation(world);
  const second = await openSession(world, secondInvitation);

  const values = {
    'invitation token (send)': firstInvitation,
    'invitation token (resend)': secondInvitation,
    'challenge code (first)': first.code,
    'challenge code (second)': second.code,
    'session value (first)': first.session,
    'session value (second)': second.session,
    'CSRF token (first)': first.csrf,
    'CSRF token (second)': second.csrf,
  };
  for (const [label, value] of Object.entries(values)) {
    const shape = label.startsWith('challenge code') ? CODE_SHAPE : CAPABILITY_SHAPE;
    assert.ok(typeof value === 'string' && shape.test(value), `${label}: a value of its contract shape was captured`);
  }
  assert.equal(new Set(Object.values(values)).size, Object.keys(values).length, 'every captured value is distinct');

  const records = world.rows('idempotency_records', 'WHERE tenant_id = ?', [world.tenantId('alpha')]);
  const routes = records.map((row) => row.route);
  for (const route of ['createEnvelope', 'uploadDocument', 'prepareEnvelope', 'confirmSend', 'sendEnvelope', RESEND_ROUTE]) {
    assert.ok(routes.includes(route), `a stored record of ${route} exists`);
  }
  const withBody = records.filter((row) => row.response_body instanceof Uint8Array && row.response_body.length > 0);
  assert.equal(withBody.length, records.length, 'every envelope record keeps its response body');
  const bodies = withBody.map((row) => Buffer.from(row.response_body).toString('utf8'));
  const keys = records.map((row) => String(row.key));
  for (const [label, value] of Object.entries(values)) {
    assert.equal(containing(bodies, value), 0, `${label}: in none of the ${bodies.length} stored response bodies`);
    assert.equal(containing(keys, value), 0, `${label}: in no stored key`);
  }
  // The operator responses themselves carried none of them either.
  for (const [label, value] of Object.entries(values)) {
    assert.ok(!sent.text.includes(value) && !resent.text.includes(value) && !confirmed.text.includes(value), `${label}: in no operator response`);
  }
});
