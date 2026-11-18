// SPDX-License-Identifier: Apache-2.0
//
// T011 SC004-04 (plan.md § Case catalogs; request #35, option (a), logged): opening, reloading
// or prefetching the invitation link causes no approval or version change, in Chromium against
// the composed server (harness.mjs).
//
// The traffic, and what counts:
// - a mail scanner outside any page (Playwright's request client): GET and HEAD of the link
//   with browser prefetch headers (Sec-Purpose and Purpose: prefetch), and a GET with the token
//   moved into a query string; each is counted;
// - Chromium's own <link rel="prefetch"> from a blank page, attempted and recorded as observed
//   or not observed AT THE SERVER (a new GET /sign line in its request log within a bounded
//   wait, with nothing else running); counted only when observed;
// - Chromium opening the link, reloading it, and opening it again in a fresh context; each is
//   counted.
// A counted request is one whose X-Correlation-Id is found in the server's own request log as
// openReviewShell answered 200 (src/server/app.ts:328 and :430-440), BEFORE the comparison; no
// prefetch counts unless it was seen at the server.
//
// "No change" is read from the server's own record, not the page: the content of every state
// table through a read-only connection (changedTables); readEnvelope as the sender (version,
// state, recipients, updated_at); the ceremony's challenge-work counts; the mail spool; and the
// request log, which holds no mutating request in the window and none after any browser action.
// A POSITIVE CONTROL then shows that the same comparison sees a change: an explicit request
// for a code (requestChallenge, found in the log) changes the challenges table.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { launchLocked, openPage, recordEvidence, responseTo, step } from './browser.mjs';
import { changedTables, CORRELATION_HEADER, PATHS, startWorld } from './harness.mjs';

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

const READ_ONLY = new Set(['GET', 'HEAD']);
const PREFETCH_HEADERS = Object.freeze({ 'Sec-Purpose': 'prefetch', Purpose: 'prefetch' });
/** How long the browser prefetch is waited for at the server before it is recorded as not observed. */
const PREFETCH_WAIT_MS = 3_000;
/** Operations a read of the link may reach: the shell, its assets (no operation) and the shell's own session read. */
const READ_OPERATIONS = new Set([null, 'openReviewShell', 'readRecipientSession']);

test('[SC004-04] opening, reloading and prefetching the link, each seen in the server request log, change nothing in the server record (no approval, no version change, no challenge, no mail); a positive control shows the comparison sees a change', async () => {
  const recipient = world.address('link');
  const sent = await world.sentEnvelope({ recipients: [recipient] });
  const id = sent.envelope.id;
  await world.running.composition.ceremony.drain();
  const baseline = { envelope: await world.readEnvelope(id), snapshot: world.snapshot(), work: world.running.composition.ceremony.challengeWorkStats() };
  const from = world.lines.length;
  const counted = [];

  /** Count one request: its correlation id must be in the server's own request log as the review shell, 200. */
  const count = async (label, correlation, method) => {
    assert.match(correlation ?? '', /^[A-Za-z0-9_-]{16,64}$/, `${label}: the response carries its correlation id`);
    const logged = await world.loggedRequest(correlation);
    assert.ok(logged !== null, `${label}: the request appears in the server's request log`);
    assert.deepEqual(
      { method: logged.method, path: logged.path, operation: logged.operation, status: logged.status },
      { method, path: PATHS.shell, operation: 'openReviewShell', status: 200 },
      `${label}: logged as the review shell, answered 200`,
    );
    counted.push({ label, correlation });
  };
  /** The server's request log since `mark` holds no mutating request. */
  const noMutation = (label, mark) => {
    const mutating = world.requestsSince(mark).filter((entry) => !READ_ONLY.has(entry.method));
    assert.deepEqual(
      mutating.map((entry) => `${entry.method} ${entry.path} ${entry.operation} ${entry.status}`),
      [],
      `${label}: the server's request log holds no mutating request`,
    );
  };

  // 1. A mail scanner, outside any page.
  const scanner = await browser.newContext();
  try {
    for (const method of ['GET', 'HEAD']) {
      const response = await scanner.request.fetch(sent.invitation.url, { method, headers: PREFETCH_HEADERS, maxRedirects: 0 });
      assert.equal(response.status(), 200, `scanner ${method} with prefetch headers: 200`);
      await count(`scanner ${method} with prefetch headers`, response.headers()[CORRELATION_HEADER], method);
    }
    const copied = await scanner.request.get(`${world.origin}${PATHS.shell}?i=${sent.invitation.token}`, { headers: PREFETCH_HEADERS, maxRedirects: 0 });
    assert.equal(copied.status(), 200, 'scanner GET with the token in a query string: 200');
    await count('scanner GET with the token in a query string', copied.headers()[CORRELATION_HEADER], 'GET');
  } finally {
    await scanner.close();
  }

  // 2. Chromium's own prefetch, from a blank page: observed at the server, or not.
  let prefetch = 'not observed';
  const prefetching = await openPage(browser);
  try {
    const mark = world.lines.length;
    await prefetching.page.setContent(`<!doctype html><link rel="prefetch" href="${sent.invitation.url}">`);
    const line = await world.nextRequest(mark, (entry) => entry.path === PATHS.shell, PREFETCH_WAIT_MS);
    if (line !== null) {
      prefetch = 'observed';
      await count('browser <link rel=prefetch>', line.correlation, 'GET');
    }
    noMutation('browser prefetch', mark);
  } finally {
    await prefetching.close();
  }

  // 3. Chromium opens the link, reloads it, and opens it again in a fresh context. Each waits
  // for the network to settle, so anything the shell would send on load has reached the server
  // before the log is read.
  const opener = await openPage(browser);
  try {
    let mark = world.lines.length;
    const opened = await opener.page.goto(sent.invitation.url, { waitUntil: 'networkidle' });
    assert.ok(opened !== null, 'the open is a navigation with a response');
    await count('browser open', opened.headers()[CORRELATION_HEADER], 'GET');
    noMutation('browser open', mark);
    await step(opener.page, 'invitation');
    mark = world.lines.length;
    const reloaded = await opener.page.reload({ waitUntil: 'networkidle' });
    assert.ok(reloaded !== null, 'the reload is a navigation with a response');
    await count('browser reload', reloaded.headers()[CORRELATION_HEADER], 'GET');
    noMutation('browser reload', mark);
    await step(opener.page, 'no-invitation');
  } finally {
    await opener.close();
  }
  const again = await openPage(browser);
  try {
    const mark = world.lines.length;
    const opened = await again.page.goto(sent.invitation.url, { waitUntil: 'networkidle' });
    assert.ok(opened !== null, 'the open in a fresh context is a navigation with a response');
    await count('browser open in a fresh context', opened.headers()[CORRELATION_HEADER], 'GET');
    noMutation('browser open in a fresh context', mark);
    await step(again.page, 'invitation');
  } finally {
    await again.close();
  }

  // 4. Before the comparison: every counted request is in the server's request log, and the
  // window holds read operations only.
  await world.running.composition.ceremony.drain();
  const expected = 6 + (prefetch === 'observed' ? 1 : 0);
  assert.equal(counted.length, expected, `${expected} counted requests: 3 by the scanner, 3 browser opens and reloads, ${prefetch === 'observed' ? '1' : 'no'} browser prefetch`);
  assert.equal(new Set(counted.map((entry) => entry.correlation)).size, counted.length, 'each counted request is a distinct server request');
  const traffic = world.requestsSince(from);
  for (const entry of counted) assert.ok(traffic.some((line) => line.correlation === entry.correlation), `${entry.label}: in the server's request log before the comparison`);
  noMutation('the whole window', from);
  for (const line of traffic) assert.ok(READ_OPERATIONS.has(line.operation), `only read operations reached the server (found ${line.operation})`);

  // 5. The comparison, from the server's own record.
  assert.deepEqual(changedTables(baseline.snapshot, world.snapshot()), [], "the server's database record is unchanged, table by table");
  const afterTraffic = await world.readEnvelope(id);
  assert.deepEqual(
    { version: afterTraffic.version, state: afterTraffic.state, updated_at: afterTraffic.updated_at, recipients: afterTraffic.recipients },
    { version: baseline.envelope.version, state: baseline.envelope.state, updated_at: baseline.envelope.updated_at, recipients: baseline.envelope.recipients },
    'readEnvelope: no approval and no version change',
  );
  assert.deepEqual(world.running.composition.ceremony.challengeWorkStats(), baseline.work, 'no challenge work started');
  assert.deepEqual(world.takeMails('recipient_challenge', recipient), [], 'no code mailed');

  // 6. Positive control: an explicit request for a code, seen at the server, is a change the same comparison sees.
  const actor = await openPage(browser);
  let control;
  try {
    await actor.page.goto(sent.invitation.url);
    await step(actor.page, 'invitation');
    const challenge = responseTo(actor.page, world.origin, PATHS.challenge, 'POST');
    await actor.page.getByRole('button', { name: 'Email me a code' }).click();
    const answered = await challenge;
    assert.equal(answered.status(), 202, 'the positive control: requestChallenge answers 202');
    control = answered.headers()[CORRELATION_HEADER];
  } finally {
    await actor.close();
  }
  const logged = await world.loggedRequest(control);
  assert.deepEqual(
    logged && { method: logged.method, path: logged.path, operation: logged.operation, status: logged.status },
    { method: 'POST', path: PATHS.challenge, operation: 'requestChallenge', status: 202 },
    'the positive control reached the server',
  );
  await world.running.composition.ceremony.drain();
  const changed = changedTables(baseline.snapshot, world.snapshot());
  assert.ok(changed.includes('challenges'), `the positive control: the same comparison sees the code request (changed: ${changed.join(', ') || 'nothing'})`);
  assert.equal(changed.includes('approvals'), false, 'and still no approval');
  assert.equal((await world.readEnvelope(id)).version, baseline.envelope.version, 'and still no version change');
  assert.equal(world.takeMails('recipient_challenge', recipient).length, 1, 'and its code was mailed');
  recordEvidence({ browser, locked, caseId: 'SC004-04', prefetch });
});
