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
//
// Evidence hygiene (row T034R-DIFF): a failing table-snapshot comparison names the tables, row
// counts and columns that changed, never a value, so it can print no token hash, digest or
// other secret-derived material. The second test forces such a failure and checks it.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { inspect } from 'node:util';

import { RESEND_ROUTE } from '../../../src/api/envelopes/index.ts';
import { assertSameRows, confirmRequest, createWorld, openSession, preparedEnvelope, resendRequest, sendRequest, sentEnvelope, takeInvitation } from './support.mjs';

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

test('[EA-04] a failing table-snapshot comparison names what changed and never prints a hash, a digest or a capability value (T034R-DIFF)', async () => {
  // A resend changes rows with hash columns: a new invitation (its token hash), the old one
  // revoked, audit events (chain hashes) and an idempotency record (request and body digests).
  const { envelope } = await sentEnvelope(world);
  const before = world.snapshot();
  const resent = await resendRequest(world, { envelope, recipient: envelope.recipients[0] });
  assert.equal(resent.status, 202);
  const token = takeInvitation(world);
  const after = world.snapshot();

  let failure = null;
  try {
    assertSameRows(after, before, 'forced mismatch');
  } catch (error) {
    failure = error;
  }
  assert.ok(failure instanceof assert.AssertionError, 'the comparison of the two snapshots fails');
  const shown = [String(failure.message), inspect(failure.actual, { depth: null }), inspect(failure.expected, { depth: null })].join('\n');

  // What the failure must never show: any run of 32 or more hex digits, any stored hash or
  // digest of the changed rows, or the capability itself. Compared as booleans and counts.
  assert.equal(/[0-9a-f]{32,}/i.test(shown), false, 'the failure shows no run of 32 or more hex digits');
  const stored = [
    ...world.rows('invitations', 'WHERE envelope_id = ?', [envelope.id]).map((row) => String(row.token_hash)),
    ...world.rows('idempotency_records', 'WHERE resource_id = ?', [envelope.recipients[0].id]).flatMap((row) => [String(row.request_digest), String(row.response_body_digest)]),
  ].filter((value) => value.length >= 32);
  assert.ok(stored.length >= 3, `the changed rows hold hashes and digests to look for (${stored.length})`);
  assert.equal(stored.filter((value) => shown.includes(value)).length, 0, `none of the ${stored.length} stored hashes and digests is shown`);
  assert.equal(shown.includes(token), false, 'the invitation itself is not shown');

  // What it shows instead: the tables that changed, by name.
  for (const table of ['invitations', 'audit_events', 'idempotency_records']) {
    assert.ok(failure.message.includes(table), `the failure names the changed table ${table}`);
  }

  // A snapshot printed on its own is masked too.
  assert.equal(/[0-9a-f]{32,}/i.test(inspect(after, { depth: null })), false, 'a printed snapshot shows no run of 32 or more hex digits');
});
