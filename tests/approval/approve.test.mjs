// SPDX-License-Identifier: Apache-2.0
//
// T010 approval through the real server: the order of recipients, the expected version, the
// digests every approval binds (document, manifest, prior approval and consent text), the
// sequential approval digests and the finalization reservation, and the exact and changed
// retry, malformed or not (SC002-01, SC002-03..SC002-06; AP-05..AP-07). Every refusal is checked to record
// nothing: the snapshot of every approval table is unchanged except the session's
// last_seen_at, which the T008 guard moves before the approval runs (GUARD_TOUCH).
// Everything is synthetic (see support.mjs).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalDigest, canonicalize } from '../../src/domain/canonical/index.ts';
import {
  GUARD_TOUCH,
  MINUTE,
  approvalBody,
  assertError,
  auditEvents,
  contractErrors,
  createWorld,
  envelopeRow,
  forgeSession,
  metadataOf,
  openSession,
  postApproval,
  postDecline,
  secondToken,
  sentEnvelope,
  sha256,
  sid,
  stateOf,
  ts,
} from './support.mjs';

/** A digest that names nothing. */
const NOWHERE = sha256(Buffer.from('a digest of nothing in particular', 'utf8'));

/** The same lowercase hex digest with its last character changed. */
function flipped(digest) {
  return digest.slice(0, -1) + (digest.endsWith('0') ? '1' : '0');
}

/**
 * The contract ApprovalRecord of a stored approval, rebuilt from the row, the recipient row
 * and the receipt's server-filled dates, without approval_digest: the digest preimage
 * (data-model.md: approval_digest = SHA-256(JCS(record without approval_digest))).
 */
function recordOf(row, recipient, receipt) {
  return {
    approval_id: row.id,
    recipient: { id: recipient.id, ordinal: recipient.ordinal, role: recipient.role, email: recipient.email },
    assurance: { method: row.assurance_method, level: row.assurance_level },
    consent_version: row.consent_version,
    consent_text_digest: row.consent_text_digest,
    document_digest: row.document_digest,
    manifest_digest: row.manifest_digest,
    prior_approval_digest: row.prior_approval_digest,
    field_values: JSON.parse(row.field_values_json),
    date_values: receipt.date_values,
    field_values_digest: row.field_values_digest,
    server_time: row.server_time,
  };
}

test('[SC002-01] the second recipient cannot approve or decline before the first: 409 order_conflict, no approval, nothing recorded', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    const first = await openSession(world, token);
    const second = envelope.recipients.find((entry) => entry.ordinal === 2);
    // A live session for recipient 2 bound to the frozen revision and manifest: the T008 guard
    // accepts it, so the refusal below is the approval's own order check.
    const forged = forgeSession(world, 'alpha', envelope.id, second.id);
    const state = await stateOf(world, forged);
    assert.equal(state.recipient.id, second.id, 'premise: the session is recipient 2’s');
    assert.equal(state.turn, 'waiting-for-prior', 'premise: recipient 2 is waiting for recipient 1');
    assert.equal(state.envelope_version, envelope.version, 'premise: the envelope version is current');

    const before = world.snapshot(GUARD_TOUCH);
    for (const prior of [null, first.state.manifest_digest, NOWHERE]) {
      const response = await postApproval(world, forged, approvalBody(state, { overrides: { prior_approval_digest: prior } }));
      assertError(response, 409, 'order_conflict', `recipient 2 approves first (prior ${prior === null ? 'null' : 'a digest'})`);
    }
    const drawn = await postApproval(world, forged, approvalBody(state, { drawn: true }));
    assertError(drawn, 409, 'order_conflict', 'recipient 2 approves first with a drawn signature');
    assertError(await postDecline(world, forged, { expected_version: state.envelope_version }), 409, 'order_conflict', 'recipient 2 declines out of turn');
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');
    assert.equal(world.rows('approvals').length, 0, 'no approval exists');
    assert.equal(world.rows('signing_jobs').length, 0, 'no reservation exists');
    assert.equal(envelopeRow(world, envelope.id).state, 'sent', 'the envelope is still sent');

    // Recipient 1's turn is untouched: it approves, and only then does recipient 2's turn come.
    const approved = await postApproval(world, first, approvalBody(first.state));
    assert.equal(approved.status, 200, 'recipient 1 approves');
    assert.equal(approved.json.envelope_state, 'in-progress');
    assert.equal(secondToken(world).length >= 43, true, 'recipient 2 is invited only after recipient 1 approved');
  } finally {
    await world.close();
  }
});

test('[SC002-03] a stale or future expected_version is 409 version_conflict for approval and decline, recording nothing', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    const first = await openSession(world, token);
    const v = first.state.envelope_version;
    assert.equal(v, envelope.version, 'premise: the session shows the current version');
    assert.ok(v >= 3, 'premise: a sent envelope has moved past version 2');

    let before = world.snapshot(GUARD_TOUCH);
    for (const version of [v - 1, v + 1, 1]) {
      assertError(await postApproval(world, first, approvalBody(first.state, { overrides: { expected_version: version } })), 409, 'version_conflict', `approval at version ${version} of ${v}`);
      assertError(await postDecline(world, first, { expected_version: version }), 409, 'version_conflict', `decline at version ${version} of ${v}`);
    }
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');

    // A real stale read: recipient 2 presents the version from before recipient 1's approval.
    assert.equal((await postApproval(world, first, approvalBody(first.state))).status, 200, 'recipient 1 approves');
    const second = await openSession(world, secondToken(world), 'signer.two@example.test');
    assert.equal(second.state.envelope_version, v + 1, 'premise: the approval moved the version by one');
    before = world.snapshot(GUARD_TOUCH);
    assertError(await postApproval(world, second, approvalBody(second.state, { overrides: { expected_version: v } })), 409, 'version_conflict', 'recipient 2 at the version before recipient 1 approved');
    assertError(await postDecline(world, second, { expected_version: v }), 409, 'version_conflict', 'recipient 2 declines at the old version');
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');
    assert.equal(envelopeRow(world, envelope.id).version, v + 1, 'the envelope stays at its version');
    assert.equal((await postApproval(world, second, approvalBody(second.state))).status, 200, 'the current version is accepted');
  } finally {
    await world.close();
  }
});

test('[SC002-04] a document_digest that is not the frozen revision’s is 409 digest_mismatch, recording nothing', async () => {
  const world = await createWorld();
  try {
    const { token } = await sentEnvelope(world);
    const session = await openSession(world, token);
    const other = await sentEnvelope(world);
    const otherState = (await openSession(world, other.token)).state;
    assert.notEqual(otherState.document.digest, session.state.document.digest, 'premise: the two documents differ');

    const before = world.snapshot(GUARD_TOUCH);
    for (const [label, digest] of [
      ['a digest of nothing', NOWHERE],
      ['the frozen digest with one character changed', flipped(session.state.document.digest)],
      ['another envelope’s document', otherState.document.digest],
      ['the manifest digest in the document slot', session.state.manifest_digest],
    ]) {
      const response = await postApproval(world, session, approvalBody(session.state, { overrides: { document_digest: digest } }));
      assertError(response, 409, 'digest_mismatch', label);
      assert.deepEqual(response.json.details, [{ field: 'document_digest', code: 'mismatch' }], `${label}: the detail names the member`);
    }
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');
    assert.equal((await postApproval(world, session, approvalBody(session.state))).status, 200, 'the frozen digest is accepted');
  } finally {
    await world.close();
  }
});

test('[SC002-05] a manifest_digest that is not the frozen manifest’s is 409 digest_mismatch, recording nothing', async () => {
  const world = await createWorld();
  try {
    const { token } = await sentEnvelope(world);
    const session = await openSession(world, token);
    const other = await sentEnvelope(world);
    const otherState = (await openSession(world, other.token)).state;
    assert.notEqual(otherState.manifest_digest, session.state.manifest_digest, 'premise: the two manifests differ');

    const before = world.snapshot(GUARD_TOUCH);
    for (const [label, digest] of [
      ['a digest of nothing', NOWHERE],
      ['the frozen digest with one character changed', flipped(session.state.manifest_digest)],
      ['another envelope’s manifest', otherState.manifest_digest],
      ['the document digest in the manifest slot', session.state.document.digest],
    ]) {
      const response = await postApproval(world, session, approvalBody(session.state, { overrides: { manifest_digest: digest } }));
      assertError(response, 409, 'digest_mismatch', label);
      assert.deepEqual(response.json.details, [{ field: 'manifest_digest', code: 'mismatch' }], `${label}: the detail names the member`);
    }
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');
    assert.equal((await postApproval(world, session, approvalBody(session.state))).status, 200, 'the frozen digest is accepted');
  } finally {
    await world.close();
  }
});

test('[SC002-06] a wrong prior_approval_digest is 409 digest_mismatch for either recipient, recording nothing', async () => {
  const world = await createWorld();
  try {
    const { token } = await sentEnvelope(world, { recipients: 2 });
    const first = await openSession(world, token);
    assert.equal(first.state.prior_approval_digest, null, 'premise: recipient 1 has no prior approval');

    let before = world.snapshot(GUARD_TOUCH);
    for (const [label, prior] of [
      ['recipient 1 names a prior approval', NOWHERE],
      ['recipient 1 names its own manifest as prior', first.state.manifest_digest],
    ]) {
      const response = await postApproval(world, first, approvalBody(first.state, { overrides: { prior_approval_digest: prior } }));
      assertError(response, 409, 'digest_mismatch', label);
      assert.deepEqual(response.json.details, [{ field: 'prior_approval_digest', code: 'mismatch' }], `${label}: the detail names the member`);
    }
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');

    const approved = await postApproval(world, first, approvalBody(first.state));
    assert.equal(approved.status, 200, 'recipient 1 approves');
    const second = await openSession(world, secondToken(world), 'signer.two@example.test');
    assert.equal(second.state.prior_approval_digest, approved.json.approval_digest, 'premise: recipient 2 is shown recipient 1’s approval digest');

    before = world.snapshot(GUARD_TOUCH);
    for (const [label, prior] of [
      ['recipient 2 names no prior approval', null],
      ['recipient 2 names recipient 1’s digest with one character changed', flipped(approved.json.approval_digest)],
      ['recipient 2 names a digest of nothing', NOWHERE],
      ['recipient 2 names the manifest as prior', second.state.manifest_digest],
    ]) {
      const response = await postApproval(world, second, approvalBody(second.state, { overrides: { prior_approval_digest: prior } }));
      assertError(response, 409, 'digest_mismatch', label);
      assert.deepEqual(response.json.details, [{ field: 'prior_approval_digest', code: 'mismatch' }], `${label}: the detail names the member`);
    }
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');
    assert.equal(world.rows('approvals').length, 1, 'only recipient 1’s approval exists');
    assert.equal((await postApproval(world, second, approvalBody(second.state))).status, 200, 'recipient 1’s approval digest is accepted');
  } finally {
    await world.close();
  }
});

test('[AP-05] approvals chain in recipient order: each approval_digest recomputes from its record, the receipts are contract-valid, and the last approval reserves finalization in its own transition', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    const v = envelope.version;
    const first = await openSession(world, token);
    const firstResponse = await postApproval(world, first, approvalBody(first.state, { text: 'Synthetic Signer One' }));
    assert.equal(firstResponse.status, 200, 'recipient 1 approves');
    assert.match(String(firstResponse.headers['content-type']), /^application\/json; charset=utf-8$/);
    const r1 = firstResponse.json;
    assert.deepEqual(contractErrors('ApprovalReceipt', r1), [], 'recipient 1’s receipt is a contract ApprovalReceipt');
    assert.equal(firstResponse.text, canonicalize(r1), 'the receipt is sent as RFC 8785 JSON');
    assert.equal(r1.envelope_version, v + 1, 'the first approval moves the version by one');
    assert.equal(r1.envelope_state, 'in-progress');
    assert.equal(r1.server_time, ts(0), 'server time is the injected clock');
    assert.deepEqual(r1.date_values, [{ key: 'date_1', value: ts(0).slice(0, 10) }], 'the date field is filled by the server');
    assert.equal(world.rows('signing_jobs').length, 0, 'the first of two approvals reserves nothing');
    assert.equal(envelopeRow(world, envelope.id).approvals_complete, 0);
    assert.equal((await stateOf(world, first)).turn, 'done', 'recipient 1 is done');

    world.time.advance(MINUTE);
    const second = await openSession(world, secondToken(world), 'signer.two@example.test');
    assert.equal(second.state.prior_approval_digest, r1.approval_digest, 'recipient 2 is shown recipient 1’s approval digest');
    const secondResponse = await postApproval(world, second, approvalBody(second.state, { drawn: true }));
    assert.equal(secondResponse.status, 200, 'recipient 2 approves');
    const r2 = secondResponse.json;
    assert.deepEqual(contractErrors('ApprovalReceipt', r2), [], 'recipient 2’s receipt is a contract ApprovalReceipt');
    assert.equal(r2.envelope_version, v + 2);
    assert.equal(r2.envelope_state, 'finalizing', 'the last approval moves the envelope to finalizing (fully approved, never completed)');
    assert.deepEqual(r2.date_values, [], 'recipient 2 has no date field');
    assert.equal(r2.server_time, ts(1));

    // The envelope: finalizing, approvals complete, at version v + 2; both recipients approved.
    const row = envelopeRow(world, envelope.id);
    assert.deepEqual({ state: row.state, version: row.version, approvals_complete: row.approvals_complete }, { state: 'finalizing', version: v + 2, approvals_complete: 1 });
    const recipients = world.rows('recipients', 'WHERE envelope_id = ?', [envelope.id]).sort((a, b) => a.ordinal - b.ordinal);
    const approvals = world.rows('approvals', 'WHERE envelope_id = ?', [envelope.id]);
    assert.equal(approvals.length, 2, 'two approvals');
    for (const [recipient, receipt] of [
      [recipients[0], r1],
      [recipients[1], r2],
    ]) {
      const stored = approvals.find((entry) => entry.recipient_id === recipient.id);
      assert.ok(stored, `recipient ${recipient.ordinal} has an approval row`);
      assert.equal(recipient.status, 'approved');
      assert.equal(recipient.approval_id, stored.id, 'the recipient names its approval');
      assert.equal(stored.id, receipt.approval_id);
      const record = recordOf(stored, recipient, receipt);
      assert.equal(stored.field_values_json, canonicalize(record.field_values), 'the values are stored as RFC 8785 text');
      assert.equal(canonicalDigest({ field_values: record.field_values, date_values: record.date_values }), stored.field_values_digest, 'field_values_digest binds the values and the server-filled dates');
      assert.equal(canonicalDigest(record), stored.approval_digest, `recipient ${recipient.ordinal}: approval_digest is SHA-256 of the RFC 8785 record without it`);
      assert.equal(receipt.approval_digest, stored.approval_digest, 'the receipt carries the stored digest');
      assert.deepEqual(contractErrors('ApprovalRecord', { ...record, approval_digest: stored.approval_digest }), [], 'the record is a contract ApprovalRecord');
      assert.equal(stored.document_digest, first.state.document.digest, 'bound to the frozen document');
      assert.equal(stored.manifest_digest, first.state.manifest_digest, 'bound to the frozen manifest');
      assert.equal(stored.consent_version, world.consent.alpha.version, 'bound to the consent version in force');
      assert.equal(stored.consent_text_digest, world.consent.alpha.digest, 'bound to the consent text digest in force');
    }
    const one = approvals.find((entry) => entry.recipient_id === recipients[0].id);
    const two = approvals.find((entry) => entry.recipient_id === recipients[1].id);
    assert.equal(one.prior_approval_digest, null, 'recipient 1 has no prior');
    assert.equal(two.prior_approval_digest, one.approval_digest, 'recipient 2 chains to recipient 1');
    assert.deepEqual(JSON.parse(two.field_values_json), [{ key: 'sig_2', type: 'signature', mode: 'drawn', strokes: [[[0, 0], [5000, 2500], [10000, 10000]]] }], 'a drawn value is stored as integer strokes');

    // The finalization reservation: one SigningJob, reserved at the version the transition wrote.
    const jobs = world.rows('signing_jobs', 'WHERE envelope_id = ?', [envelope.id]);
    assert.equal(jobs.length, 1, 'exactly one reservation');
    assert.deepEqual(
      { reserved_version: jobs[0].reserved_version, status: jobs[0].status, attempt_count: jobs[0].attempt_count, max_attempts: jobs[0].max_attempts, lease_owner: jobs[0].lease_owner, created_at: jobs[0].created_at },
      { reserved_version: v + 2, status: 'pending', attempt_count: 0, max_attempts: 5, lease_owner: null, created_at: ts(1) },
      'pending, no attempt yet, reserved at the finalizing version',
    );

    // One receipt row per approval, holding the exact bytes sent.
    const receipts = world.rows('approval_receipts', 'WHERE envelope_id = ?', [envelope.id]);
    assert.equal(receipts.length, 2);
    assert.ok(Buffer.from(receipts.find((entry) => entry.recipient_id === recipients[0].id).receipt_body).equals(firstResponse.bytes), 'recipient 1’s receipt bytes are stored');
    assert.ok(Buffer.from(receipts.find((entry) => entry.recipient_id === recipients[1].id).receipt_body).equals(secondResponse.bytes), 'recipient 2’s receipt bytes are stored');

    // The audit chain names each approval by its digest, with ids, ordinal, version and state only.
    const events = auditEvents(world, 'recipient.approved').filter((event) => event.envelope_id === envelope.id);
    assert.deepEqual(
      events.map((event) => ({ actor: `${event.actor_kind}:${event.actor_ref}`, subject: event.subject_digest, metadata: metadataOf(event) })),
      [
        { actor: `recipient:${recipients[0].id}`, subject: one.approval_digest, metadata: { approval_id: one.id, envelope_state: 'in-progress', envelope_version: v + 1, recipient_id: recipients[0].id, recipient_ordinal: 1 } },
        { actor: `recipient:${recipients[1].id}`, subject: two.approval_digest, metadata: { approval_id: two.id, envelope_state: 'finalizing', envelope_version: v + 2, recipient_id: recipients[1].id, recipient_ordinal: 2 } },
      ],
      'one recipient.approved event per approval',
    );
    const text = events.map((event) => `${event.metadata_json}\n${event.subject_digest}`).join('\n');
    assert.ok(!text.includes('Synthetic Signer One') && !text.includes('example.test') && !text.includes('signer.'), 'no field value or address reaches the approval events');

    // Sessions stay readable and show the outcome.
    assert.equal((await stateOf(world, second)).turn, 'done');
    assert.equal((await stateOf(world, first)).envelope_state, 'finalizing');
  } finally {
    await world.close();
  }
});

test('[AP-06] an exact retry returns the original receipt byte for byte, also after the envelope moved on; a changed retry is 409 and records nothing', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    const first = await openSession(world, token);
    const body = approvalBody(first.state, { text: 'Synthetic Retry Signer' });
    const original = await postApproval(world, first, body);
    assert.equal(original.status, 200, 'the first request approves');
    const afterFirst = world.snapshot(GUARD_TOUCH);
    const approvedEvents = auditEvents(world, 'recipient.approved').length;

    // The same request again, and again with its members reordered and whitespace added.
    world.time.advance(MINUTE);
    const again = await postApproval(world, first, body);
    assert.equal(again.status, 200, 'an exact retry is 200');
    assert.ok(again.bytes.equals(original.bytes), 'an exact retry returns the original receipt bytes');
    const reordered = Object.fromEntries(Object.entries(body).reverse());
    reordered.field_values = [...body.field_values].reverse().map((value) => Object.fromEntries(Object.entries(value).reverse()));
    const spaced = await postApproval(world, first, JSON.stringify(reordered, null, 2));
    assert.equal(spaced.status, 200, 'the same request in another member order is an exact retry');
    assert.ok(spaced.bytes.equals(original.bytes), 'member order and whitespace do not change the request');
    assert.deepEqual(world.snapshot(GUARD_TOUCH), afterFirst, 'an exact retry records nothing');
    assert.equal(auditEvents(world, 'recipient.approved').length, approvedEvents, 'no second audit event');

    // Changed retries: every member that the request binds.
    const changes = [
      ['another typed text', approvalBody(first.state, { text: 'Synthetic Other Signer' })],
      ['a drawn signature instead', approvalBody(first.state, { drawn: true })],
      ['the version the approval wrote', { ...body, expected_version: original.json.envelope_version }],
    ];
    for (const [label, changed] of changes) {
      assertError(await postApproval(world, first, changed), 409, 'state_conflict', `changed retry: ${label}`);
    }
    // A changed retry that is malformed is 409 as well: the earlier approval is decided before
    // the body (A-010, request #24, ruling (8)), so the body's 400 or 422 never shows.
    for (const [label, changed] of [
      ['an unknown member', { ...body, extra: true }],
      ['a typed text of 81 characters', approvalBody(first.state, { text: 'A'.repeat(81) })],
      ['a typed text outside WinAnsiEncoding', approvalBody(first.state, { text: 'Synthetic \u0100' })],
      ['a fractional coordinate', approvalBody(first.state, { drawn: true, overrides: {} })],
      ['an array', [body]],
      ['JSON that does not parse', '{"expected_version":'],
    ]) {
      if (label === 'a fractional coordinate') changed.field_values.find((value) => value.type === 'signature').strokes = [[[0, 0], [0.5, 0]]];
      assertError(await postApproval(world, first, changed), 409, 'state_conflict', `malformed changed retry: ${label}`);
    }
    assert.deepEqual(world.snapshot(GUARD_TOUCH), afterFirst, 'a changed retry records nothing');

    // The envelope moves on (recipient 2 approves): the exact retry still gets the original bytes,
    // which still say in-progress at version v + 1.
    const second = await openSession(world, secondToken(world), 'signer.two@example.test');
    assert.equal((await postApproval(world, second, approvalBody(second.state))).status, 200, 'recipient 2 approves');
    assert.equal(envelopeRow(world, envelope.id).state, 'finalizing', 'premise: the envelope moved on');
    world.time.advance(MINUTE);
    const late = await postApproval(world, first, body);
    assert.equal(late.status, 200, 'the exact retry after the envelope moved on is 200');
    assert.ok(late.bytes.equals(original.bytes), 'it returns the original receipt bytes');
    assert.equal(late.json.envelope_state, 'in-progress', 'the original receipt, not the current state');
    const afterSecond = world.snapshot(GUARD_TOUCH);
    assertError(await postApproval(world, first, changes[0][1]), 409, 'state_conflict', 'a changed retry after the envelope moved on');
    assert.deepEqual(world.snapshot(GUARD_TOUCH), afterSecond, 'nothing is recorded');
    assert.equal(world.rows('approvals', 'WHERE envelope_id = ?', [envelope.id]).length, 2, 'still exactly two approvals');
    assert.equal(world.rows('signing_jobs').length, 1, 'still exactly one reservation');
  } finally {
    await world.close();
  }
});

test('[AP-07] the approval binds the consent text in force by version and digest: a stale or wrong consent is 409 consent_mismatch, no consent is 400, and the stored approval names the text in force', async () => {
  const world = await createWorld();
  try {
    const { token } = await sentEnvelope(world);
    const session = await openSession(world, token);
    const before = world.snapshot(GUARD_TOUCH);
    for (const [label, overrides] of [
      ['a digest of another text', { consent_text_digest: sha256(Buffer.from('Some other synthetic consent wording.', 'utf8')) }],
      ['the digest with one character changed', { consent_text_digest: flipped(session.state.consent.text_digest) }],
      ['another version', { consent_version: '2026.10-synthetic' }],
    ]) {
      assertError(await postApproval(world, session, approvalBody(session.state, { overrides })), 409, 'consent_mismatch', label);
    }
    assertError(await postApproval(world, session, approvalBody(session.state, { overrides: { consent: false } })), 400, 'invalid_request', 'consent false');
    const { consent: _omitted, ...withoutConsent } = approvalBody(session.state);
    assertError(await postApproval(world, session, withoutConsent), 400, 'invalid_request', 'consent missing');
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');

    // A new consent text comes into force after the recipient read the old one.
    const wording = 'I have reviewed this synthetic document, version two, and I approve it as shown.';
    const next = { id: sid('consent'), version: '2026.12-synthetic', digest: sha256(Buffer.from(wording, 'utf8')) };
    world.db.transaction(() => {
      const store = world.store('alpha');
      store.insert('consent_texts', { id: next.id, version: next.version, locale: 'en', text: wording, text_digest: next.digest, effective_from: ts(0), created_at: ts(0) });
      store.update('tenants', {}, { consent_text_id: next.id });
    });
    assertError(await postApproval(world, session, approvalBody(session.state)), 409, 'consent_mismatch', 'the consent the recipient read is no longer in force');
    const fresh = await stateOf(world, session);
    assert.deepEqual({ version: fresh.consent.version, digest: fresh.consent.text_digest }, { version: next.version, digest: next.digest }, 'premise: the session now shows the new text');
    const accepted = await postApproval(world, session, approvalBody(fresh));
    assert.equal(accepted.status, 200, 'the consent in force is accepted');
    const [stored] = world.rows('approvals');
    assert.deepEqual(
      { id: stored.consent_text_id, version: stored.consent_version, digest: stored.consent_text_digest },
      { id: next.id, version: next.version, digest: next.digest },
      'the approval names the consent text in force by id, version and digest',
    );
  } finally {
    await world.close();
  }
});
