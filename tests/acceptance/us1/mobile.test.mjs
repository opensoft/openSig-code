// SPDX-License-Identifier: Apache-2.0
//
// T011 SC004-02: mobile emulation with no horizontal overflow, in Chromium against the
// composed server (harness.mjs). Two named Playwright devices with the chromium default
// browser type: "Galaxy S9+" (320 CSS pixels wide, the narrowest) and "Pixel 7" (412), each
// with its viewport, device scale factor, mobile meta-viewport handling, touch and user agent.
// On each, the whole flow runs by touch through ONE CDP touch session (browser.mjs
// touchInput), every touch ended, for consistency (dispatch-T011-prep Addendum A4): tap "Email
// me a code", enter the code, tap Continue, tap "Draw my signature", draw the signature, tap the
// consent label and tap Approve. No touch goes through any other path (no Playwright tap), and
// every trusted pointer the page saw was a touch. Each stroke's finger rests before it lifts
// (browser.mjs FINGER_REST_MS): that rest, not the single path, is what lets the taps after the
// drawing click (the T009 recheck's R15 and R16). "No horizontal overflow" at every step
// (invitation, code, review once the bytes are checked, after drawing, receipt) means all
// three of: the document and the body are no wider than the viewport's client width; no
// rendered element (the off-screen skip link aside, src/autograph/review.css:61-73) ends past
// the right edge; and a sideways scroll leaves window.scrollX at 0.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { devices } from 'playwright';

import { assertFullyApprovedNotCompleted, assertNoHorizontalOverflow, inputCounts, launchLocked, openPage, recordEvidence, responseTo, step, touchInput, verified } from './browser.mjs';
import { PATHS, startWorld } from './harness.mjs';

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

test('[SC004-02] on Galaxy S9+ (320 px) and Pixel 7 (412 px) emulation, every step fits the viewport with no horizontal overflow, and touch alone, through one touch path, completes the approval', async () => {
  for (const name of ['Galaxy S9+', 'Pixel 7']) {
    const device = devices[name];
    assert.ok(device && device.isMobile && device.hasTouch && device.defaultBrowserType === 'chromium', `${name} is a chromium mobile device descriptor`);
    const recipient = world.address('mobile');
    const sent = await world.sentEnvelope({ recipients: [recipient] });
    const { page, close } = await openPage(browser, { ...device });
    let touch = null;
    try {
      touch = await touchInput(page);
      const overflow = (where) => assertNoHorizontalOverflow(page, `${name} ${where}`);
      await page.goto(sent.invitation.url);
      await step(page, 'invitation');
      await overflow('invitation');
      await openSessionFromInvitation(page, recipient, touch, overflow);
      await overflow('review');
      await touch.tap(page.locator('label[for="mode-drawn-sig_1"]'));
      await touch.draw('sig_1', [
        [
          [0.1, 0.7],
          [0.3, 0.2],
          [0.5, 0.75],
          [0.7, 0.25],
          [0.9, 0.6],
        ],
      ]);
      await overflow('review after drawing');
      await touch.tap(page.locator('label[for="consent"]'));
      await page.locator('#consent:checked').waitFor();
      const answer = responseTo(page, world.origin, PATHS.approval, 'POST');
      await touch.tap(page.getByRole('button', { name: 'Approve the document' }));
      assert.equal((await answer).status(), 200, `${name}: the approval is recorded`);
      await assertFullyApprovedNotCompleted(page);
      await overflow('receipt');
      const counts = await inputCounts(page);
      assert.deepEqual(counts.pointerTypes, ['touch'], `${name}: every pointer the page saw was a touch`);
      assert.ok(counts.touchstart >= 6, `${name}: the flow was driven by touch (${counts.touchstart} touches)`);
    } finally {
      await touch?.detach();
      await close();
    }
    assert.equal((await world.readEnvelope(sent.envelope.id)).state, 'finalizing', `${name}: the server recorded the approval`);
  }
  recordEvidence({ browser, locked, caseId: 'SC004-02' });
});

/**
 * The invitation and code steps by touch, from a page already on the invitation step: the same
 * requests and checks as browser.mjs openSession(), each press a tap through the one touch
 * session, plus an overflow check on the code step.
 */
async function openSessionFromInvitation(page, recipient, touch, overflow) {
  const challenge = responseTo(page, world.origin, PATHS.challenge, 'POST');
  await touch.tap(page.getByRole('button', { name: 'Email me a code' }));
  assert.equal((await challenge).status(), 202, 'requestChallenge answers 202');
  await step(page, 'code');
  await overflow('code');
  await page.getByRole('textbox', { name: 'One-time code' }).fill(await world.code(recipient));
  const created = responseTo(page, world.origin, PATHS.session, 'POST');
  await touch.tap(page.getByRole('button', { name: 'Continue' }));
  assert.equal((await created).status(), 201, 'createRecipientSession answers 201');
  await step(page, 'review');
  await verified(page);
}
