// SPDX-License-Identifier: Apache-2.0
//
// T011 US1-01 (plan.md § Case catalogs, US1; request #35): the two-recipient flow in Chromium
// against the composed server (harness.mjs), through the operator routes and the real review
// shell.
// - The sender prepares and sends; only recipient 1 is invited.
// - Until recipient 1's approval commits, recipient 2 has NO invitation, challenge or session:
//   neither in the store (a read-only connection) nor in the spool. This is checked after
//   send, while recipient 1 reviews, and after recipient 2's early attempt.
// - Before then, recipient 2's OWN browser context (no invitation, so no session) tries
//   approveAsHuman from the shell's origin: 401 unauthenticated, logged by the server, with no
//   approval and no version change.
// - Recipient 1 reviews, consents and approves with a drawn signature; only then does recipient
//   2's invitation appear, in the store and the spool.
// - At recipient 2's turn, the sender's bearer token beside recipient 2's own cookie and CSRF
//   token gets 401 unauthenticated, with no change in the server's record.
// - Recipient 2 approves with a typed name, binding recipient 1's approval. The shell says
//   "fully approved" with no completed or sealed claim; readEnvelope says finalizing with
//   approvals_complete, never completed.
// The real __Host- session cookie is proven held and sent on plain loopback http (row
// LOOPBACK-COOKIE). In recipient 1's review step, the viewer iframe's own request answers 200
// application/pdf, inline, with frame-ancestors 'self', and its body's SHA-256 equals the
// session's document digest (request #37 (a)); whether the viewer draws the PDF is not
// observable headless and is recorded as not observed.
// Row US1-MASK (A-010 requests #47 and #48; US1-01 amended without weakening): at all six places
// where this flow waits for its own request's answer (recipient 1's approval here; the challenge
// and the session in each of the two openSession() calls; recipient 2's approveTyped()), the wait
// and the action start together (browser.mjs respondedTo), so the first rejection surfaces and no
// wait is left unhandled. While the two pages are open, the first error, browser.isConnected()
// and both pages' state are recorded before anything is closed, each close runs in its own
// guard, and the first error is rethrown (browser.mjs whilePagesOpen). Every assertion is kept,
// and no timeout changes.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import {
  approvalFromState,
  approveFromPage,
  approveTyped,
  assertFullyApprovedNotCompleted,
  assertRealCookie,
  closeAll,
  cookieHeader,
  drawWithMouse,
  launchLocked,
  openPage,
  openSession,
  proveCookieSent,
  recordEvidence,
  respondedTo,
  step,
  watchFrameDocument,
  whilePagesOpen,
} from './browser.mjs';
import { changedTables, PATHS, startWorld } from './harness.mjs';

let world;
let browser;
let locked;

before(async () => {
  world = await startWorld();
  ({ browser, locked } = await launchLocked());
});

after(() => closeAll([() => browser?.close(), () => world?.close()]));

const NOTHING = Object.freeze({ invitations: 0, challenges: 0, sessions: 0 });
const pick = (entry) => entry && { method: entry.method, path: entry.path, operation: entry.operation, status: entry.status, error: entry.error };

test('[US1-01] two sequential recipients: recipient 2 has no invitation, challenge or session and cannot approve until recipient 1 approval commits; the sender bearer beside recipient 2 session is refused; the result is fully approved, shown distinct from completed', async () => {
  const first = world.address('first');
  const second = world.address('second');
  const sent = await world.sentEnvelope({ recipients: [first, second] });
  const id = sent.envelope.id;

  /** Recipient 2 does not exist yet as a party that can act: nothing in the spool, nothing in the store. */
  const absent = (when) => {
    assert.deepEqual(world.mailsTo(second).map((mail) => mail.kind), [], `${when}: the spool holds no mail to recipient 2`);
    assert.deepEqual(world.footprint(id, 2), NOTHING, `${when}: the store holds no invitation, challenge or session of recipient 2`);
  };
  absent('after send');
  assert.deepEqual(
    sent.envelope.recipients.map((recipient) => recipient.status),
    ['invited', 'pending'],
    'after send, only recipient 1 is invited',
  );

  const one = await openPage(browser);
  const two = await openPage(browser);
  let firstReceipt;
  let cookie;
  let frame;
  let frameWatch = null;
  const closers = [() => frameWatch?.stop(), two.close, one.close];
  await whilePagesOpen({ caseId: 'US1-01', section: 'recipients one and two', browser, pages: { one: one.page, two: two.page }, closers }, async () => {
    // Recipient 1 opens a session and reaches the review step, without approving yet.
    frameWatch = await watchFrameDocument(one.page);
    const state = await openSession(one.page, world, sent.invitation, first);
    cookie = await assertRealCookie(one.context, world);
    await proveCookieSent(one.page, world);
    assert.equal(state.turn, 'yours');
    assert.equal(state.document.digest, sent.entry.sha256, 'the session binds the frozen document');

    // The review step's viewer iframe loads exactly the session's document (request #37 (a)).
    frame = await frameWatch.result(10_000);
    await frameWatch.stop();
    frameWatch = null;
    assert.equal(frame.missing, undefined, 'the viewer iframe requested the document within 10 s');
    assert.equal(frame.error, undefined, `the iframe's response was read in flight (${frame.error ?? ''})`);
    assert.deepEqual(
      { path: frame.path, method: frame.method, resourceType: frame.resourceType, subframe: frame.subframe, status: frame.status },
      { path: PATHS.document, method: 'GET', resourceType: 'Document', subframe: true, status: 200 },
      "the iframe's own request: a subframe document GET of the document path, answered 200",
    );
    assert.match(frame.headers['content-type'] ?? '', /^application\/pdf(?:;|$)/, "the iframe's response is application/pdf");
    assert.equal(frame.headers['content-disposition'], 'inline', "the iframe's response is inline");
    assert.match(frame.headers['content-security-policy'] ?? '', /(?:^|;\s*)frame-ancestors 'self'(?:;|$)/, "the iframe's response allows framing by 'self' only");
    assert.equal(frame.sha256, state.document.digest, "the iframe's response body is the session's document (SHA-256)");
    assert.equal(frame.bytes, state.document.bytes, 'and its length');
    const frameLogged = await world.loggedRequest(frame.headers['x-correlation-id']);
    assert.deepEqual(pick(frameLogged), { method: 'GET', path: PATHS.document, operation: 'readRecipientDocument', status: 200, error: null }, 'the server logged the iframe request');
    assert.equal(await one.page.locator('#document-frame').getAttribute('src'), PATHS.document, 'the viewer iframe points at the document (src/autograph/flow.ts:379)');
    assert.deepEqual(state.fields.map((field) => field.key).sort(), ['date_1', 'sig_1'], 'recipient 1 sees only its own fields');
    absent('while recipient 1 reviews');

    // Recipient 2's own browser, before its turn: the shell finds no session, and an approval
    // attempt from that context is 401, with no approval and no version change.
    const beforeEarly = { envelope: await world.readEnvelope(id), snapshot: world.snapshot() };
    await two.page.goto(`${world.origin}${PATHS.shell}`);
    await step(two.page, 'no-invitation');
    const early = await approveFromPage(two.page, {
      expected_version: beforeEarly.envelope.version,
      document_digest: sent.entry.sha256,
      manifest_digest: sent.preview.manifest_digest,
      prior_approval_digest: null,
      consent_version: world.consent.version,
      consent_text_digest: world.consent.digest,
      consent: true,
      field_values: [
        { key: 'sig_2', type: 'signature', mode: 'typed', text: 'Early Attempt' },
        { key: 'date_2', type: 'date' },
      ],
    });
    assert.equal(early.status, 401, "recipient 2's approveAsHuman before its turn, from its own browser context: 401");
    assert.equal(early.code, 'unauthenticated');
    assert.deepEqual(
      pick(await world.loggedRequest(early.correlation)),
      { method: 'POST', path: PATHS.approval, operation: 'approveAsHuman', status: 401, error: 'unauthenticated' },
      'the server logged the early attempt as a refused approveAsHuman',
    );
    const afterEarly = await world.readEnvelope(id);
    assert.equal(afterEarly.version, beforeEarly.envelope.version, 'the early attempt changes no version');
    assert.deepEqual(afterEarly.recipients.map((recipient) => recipient.status), ['invited', 'pending']);
    assert.equal(world.rows('approvals', id).length, 0, 'the early attempt records no approval');
    assert.deepEqual(changedTables(beforeEarly.snapshot, world.snapshot()), [], "the early attempt changes nothing else in the server's record");
    absent("after recipient 2's early attempt");

    // Recipient 1: drawn signature, consent, approve.
    await one.page.getByRole('radio', { name: 'Draw my signature' }).check();
    await drawWithMouse(one.page, 'sig_1', [
      [
        [0.1, 0.6],
        [0.3, 0.25],
        [0.5, 0.7],
        [0.7, 0.3],
        [0.9, 0.6],
      ],
    ]);
    await one.page.getByRole('checkbox', { name: 'I have read the consent text above and I agree to it.' }).check();
    const response = await respondedTo(one.page, world.origin, PATHS.approval, 'POST', () => one.page.getByRole('button', { name: 'Approve the document' }).click());
    assert.equal(response.status(), 200, 'recipient 1 approval answers 200');
    firstReceipt = await response.json();
    assert.equal(firstReceipt.envelope_state, 'in-progress');
    await step(one.page, 'approved');
    assert.equal(await one.page.locator('#approval-outcome').textContent(), 'Your approval is recorded. The next recipient is invited to approve.');

    // Recipient 1's approval has committed: now, and only now, recipient 2 is invited.
    const middle = await world.readEnvelope(id);
    assert.equal(middle.state, 'in-progress');
    assert.equal(middle.approvals_complete, false);
    assert.deepEqual(middle.recipients.map((recipient) => recipient.status), ['approved', 'invited']);
    assert.deepEqual(world.footprint(id, 2), { invitations: 1, challenges: 0, sessions: 0 }, "recipient 2's invitation appears in the store once recipient 1's approval commits");
    const invitation = world.invitation(second);

    // Recipient 2, in the same browser context that was refused before: review, then refusals, then approval.
    // Its page still shows /sign from the early attempt. The shell reads the fragment once, at
    // load (src/autograph/main.ts:19), and a change of fragment alone is a same-document
    // navigation, so the page first leaves /sign, as a person does before opening the mail link
    // (run01 timed out waiting for the invitation step without this).
    await two.page.goto('about:blank');
    const state2 = await openSession(two.page, world, invitation, second);
    await assertRealCookie(two.context, world);
    assert.equal(state2.prior_approval_digest, firstReceipt.approval_digest, 'recipient 2 binds recipient 1 approval');
    assert.deepEqual(state2.fields.map((field) => field.key).sort(), ['date_2', 'sig_2'], 'recipient 2 sees only its own fields');

    // At recipient 2's turn: the sender's bearer beside recipient 2's own cookie and CSRF token: 401, no change.
    const atTurn = { envelope: await world.readEnvelope(id), snapshot: world.snapshot() };
    const beside = await world.operator('sender', {
      method: 'POST',
      path: PATHS.approval,
      headers: { origin: world.origin, cookie: await cookieHeader(two.context, world), 'x-csrf-token': state2.csrf_token },
      body: approvalFromState(state2, 'sig_2', 'Not The Recipient'),
    });
    assert.equal(beside.status, 401, "the sender's bearer beside recipient 2's cookie and CSRF token: 401");
    assert.equal(beside.json?.code, 'unauthenticated');
    assert.deepEqual(
      pick(await world.loggedRequest(beside.headers['x-correlation-id'])),
      { method: 'POST', path: PATHS.approval, operation: 'approveAsHuman', status: 401, error: 'unauthenticated' },
      'the server logged the refusal',
    );
    assert.equal((await world.readEnvelope(id)).version, atTurn.envelope.version, 'the refusal changes no version');
    assert.deepEqual(changedTables(atTurn.snapshot, world.snapshot()), [], "the refusal changes nothing in the server's record");

    // Recipient 2's own approval, typed.
    const { body, receipt } = await approveTyped(two.page, world, two.requests, 'sig_2', 'Grace Example');
    assert.equal(body.prior_approval_digest, firstReceipt.approval_digest);
    assert.equal(receipt.envelope_state, 'finalizing');
    await assertFullyApprovedNotCompleted(two.page);
  });

  const final = await world.readEnvelope(id);
  assert.equal(final.state, 'finalizing', 'readEnvelope: fully approved is the finalizing state, never completed');
  assert.equal(final.approvals_complete, true);
  assert.deepEqual(final.recipients.map((recipient) => recipient.status), ['approved', 'approved']);
  assert.equal(world.rows('approvals', id).length, 2, 'exactly two approvals are recorded');
  recordEvidence({
    browser,
    locked,
    caseId: 'US1-01',
    cookie,
    frame: { status: frame.status, content_type: frame.headers['content-type'], content_disposition: frame.headers['content-disposition'], frame_ancestors: "'self'", body_sha256_equals_document_digest: true },
  });
});
