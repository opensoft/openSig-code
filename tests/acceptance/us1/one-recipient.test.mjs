// SPDX-License-Identifier: Apache-2.0
//
// T011 US1-02 (plan.md § Case catalogs, US1; request #35): the one-recipient flow in Chromium
// against the composed server (harness.mjs), and the refusal of every approval attempt made
// with operator credentials.
// - The single recipient approves; the envelope is fully approved at once (sent -> finalizing,
//   approvals_complete, never completed), and the shell says "fully approved" with no completed
//   or sealed claim.
// - Neither the sender (a human operator) nor the service principal can approve: each calls
//   approveAsHuman (POST /v1/recipient-session/approval) with a valid Approval body, first with
//   its bearer token alone, then with its token beside the recipient's own session cookie and
//   CSRF token. Each request carries the shell's Origin, as a browser would: without one, the
//   server's Origin check answers 403 before authentication (src/server/app.ts:394-401). The
//   contract answers 401 unauthenticated (an Authorization header on a recipient route is
//   refused, app.ts:411-412, and approveAsHuman's own check, src/api/recipients/approval.ts:143),
//   each refusal is in the server's request log, and there is no approval and no version change.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import {
  approvalFromState,
  approveTyped,
  assertFullyApprovedNotCompleted,
  assertRealCookie,
  cookieHeader,
  launchLocked,
  openPage,
  openSession,
  proveCookieSent,
  recordEvidence,
} from './browser.mjs';
import { changedTables, PATHS, startWorld } from './harness.mjs';

let world;
let browser;
let locked;

before(async () => {
  world = await startWorld();
  ({ browser, locked } = await launchLocked());
});

after(async () => {
  await browser?.close();
  await world?.close();
});

test('[US1-02] one recipient: approval makes the envelope fully approved at once, shown distinct from completed', async () => {
  const recipient = world.address('only');
  const sent = await world.sentEnvelope({ recipients: [recipient] });
  const { page, context, requests, close } = await openPage(browser);
  let cookie;
  try {
    const state = await openSession(page, world, sent.invitation, recipient);
    cookie = await assertRealCookie(context, world);
    await proveCookieSent(page, world);
    assert.equal(state.prior_approval_digest, null);
    const { body, receipt } = await approveTyped(page, world, requests, 'sig_1', 'Ada Example');
    assert.equal(body.document_digest, sent.entry.sha256, 'the approval binds the bytes the browser received');
    assert.deepEqual(
      body.field_values.find((value) => value.key === 'date_1'),
      { key: 'date_1', type: 'date' },
      'the browser sends no date; the server sets it',
    );
    assert.equal(receipt.envelope_state, 'finalizing');
    await assertFullyApprovedNotCompleted(page);
  } finally {
    await close();
  }
  const final = await world.readEnvelope(sent.envelope.id);
  assert.equal(final.state, 'finalizing', 'readEnvelope: fully approved is the finalizing state, never completed');
  assert.equal(final.approvals_complete, true);
  recordEvidence({ browser, locked, caseId: 'US1-02', cookie });
});

test('[US1-02] neither the sender nor the service principal can approve as the recipient, alone or beside the recipient cookie and CSRF token: 401 unauthenticated, no approval, no version change', async () => {
  const recipient = world.address('target');
  const sent = await world.sentEnvelope({ recipients: [recipient] });
  const id = sent.envelope.id;
  const { page, context, requests, close } = await openPage(browser);
  try {
    const state = await openSession(page, world, sent.invitation, recipient);
    await assertRealCookie(context, world);
    const baseline = { envelope: await world.readEnvelope(id), snapshot: world.snapshot() };
    assert.equal(world.rows('approvals', id).length, 0);
    // A valid Approval body, as the review shell would send it, signed with a name not the recipient's.
    const approval = approvalFromState(state, 'sig_1', 'Not The Recipient');
    const session = await cookieHeader(context, world);
    for (const who of ['sender', 'service']) {
      for (const [how, headers] of [
        ['alone', { origin: world.origin }],
        ["beside the recipient's own cookie and CSRF token", { origin: world.origin, cookie: session, 'x-csrf-token': state.csrf_token }],
      ]) {
        const attempt = await world.operator(who, { method: 'POST', path: PATHS.approval, headers, body: approval });
        assert.equal(attempt.status, 401, `${who} bearer ${how}: 401`);
        assert.equal(attempt.json?.code, 'unauthenticated', `${who} bearer ${how}: unauthenticated`);
        const logged = await world.loggedRequest(attempt.headers['x-correlation-id']);
        assert.deepEqual(
          logged && { method: logged.method, path: logged.path, operation: logged.operation, status: logged.status, error: logged.error },
          { method: 'POST', path: PATHS.approval, operation: 'approveAsHuman', status: 401, error: 'unauthenticated' },
          `${who} bearer ${how}: the server logged a refused approveAsHuman`,
        );
      }
    }
    const afterAttempts = await world.readEnvelope(id);
    assert.equal(afterAttempts.version, baseline.envelope.version, 'no version change');
    assert.equal(afterAttempts.state, 'sent');
    assert.equal(world.rows('approvals', id).length, 0, 'no approval recorded');
    assert.deepEqual(changedTables(baseline.snapshot, world.snapshot()), [], "the attempts change nothing in the server's record");

    // The recipient's own approval still works afterwards: the attempts consumed nothing.
    const { receipt } = await approveTyped(page, world, requests, 'sig_1', 'Ada Example');
    assert.equal(receipt.envelope_state, 'finalizing');
    assert.equal(world.rows('approvals', id).length, 1);
  } finally {
    await close();
  }
  recordEvidence({ browser, locked, caseId: 'US1-02' });
});
