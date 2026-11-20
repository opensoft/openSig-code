// SPDX-License-Identifier: Apache-2.0
//
// T011 SC004-01: keyboard-only completion with zero pointer events, in Chromium against the
// composed server (harness.mjs). From the invitation link to the receipt, every step uses keys
// only: Tab, Enter, Space and typing. On the review step, Tab reaches the named document links
// (#document-download, #document-open; src/autograph/flow.ts:333-334) first and then the
// signature and consent controls (#mode-typed-<key>, #typed-<key>, #consent, #approve;
// flow.ts:251-253, 313-314); the built-in viewer's iframe (#document-frame, tabindex -1,
// flow.ts:298-303) stays out of the tab order and focus never enters it; the walk ends at End
// this session (#end-session, flow.ts:122), Tab leaves it and Shift+Tab walks back, so focus is
// never trapped. Each step change focuses its heading (#step-title, flow.ts:116). The counters
// of trusted pointerdown, mousedown and touchstart stay at zero.
// Row US1-MASK (request #48): the part with the page open runs under browser.mjs whilePagesOpen
// (first error recorded before any close, each close guarded), and after() uses closeAll.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { approveTyped, assertFullyApprovedNotCompleted, closeAll, focused, inputCounts, launchLocked, openPage, openSession, recordEvidence, tabTo, whilePagesOpen } from './browser.mjs';
import { startWorld } from './harness.mjs';

let world;
let browser;
let locked;

before(async () => {
  world = await startWorld();
  ({ browser, locked } = await launchLocked());
});

after(() => closeAll([() => browser?.close(), () => world?.close()]));

test('[SC004-01] keyboard only, invitation to receipt, zero pointer events: Tab reaches the document links, then signature and consent, never the viewer iframe, never trapped', async () => {
  const recipient = world.address('keys');
  const sent = await world.sentEnvelope({ recipients: [recipient] });
  const { page, requests, close } = await openPage(browser);
  await whilePagesOpen({ caseId: 'SC004-01', section: 'recipient (keyboard)', browser, pages: { page }, closers: [close] }, async () => {
    await openSession(page, world, sent.invitation, recipient, { keyboard: true });
    assert.equal(await focused(page), 'h2#step-title', 'the review heading takes focus');
    assert.equal(await page.locator('#document-frame').getAttribute('tabindex'), '-1', 'the viewer iframe is not a tab stop');
    assert.ok(((await page.locator('#document-frame').getAttribute('title')) ?? '').length > 0, 'the viewer iframe has a title');

    // The walk ends when focus leaves the page content: to the browser (body) or, wrapping,
    // to the skip link (#skip-link, index.html:14) or the first stop again.
    const stops = [];
    let enteredFrame = false;
    for (let press = 0; press < 40; press += 1) {
      await page.keyboard.press('Tab');
      const now = await focused(page);
      if (now.startsWith('iframe') || (await page.evaluate(() => document.activeElement?.tagName === 'IFRAME'))) enteredFrame = true;
      if (now === 'body' || now === 'a#skip-link' || now === stops[0]) break;
      stops.push(now);
    }
    assert.equal(enteredFrame, false, 'focus never entered the viewer iframe');
    assert.deepEqual(stops.slice(0, 2), ['a#document-download', 'a#document-open'], 'the first stops are the named document links');
    const at = (name) => stops.indexOf(name);
    for (const control of ['input#mode-typed-sig_1', 'input#typed-sig_1', 'input#consent', 'button#approve']) assert.ok(at(control) > 1, `${control} is reached after the links`);
    assert.ok(at('input#typed-sig_1') < at('input#consent') && at('input#consent') < at('button#approve'), 'signature, then consent, then Approve');
    assert.equal(stops[stops.length - 1], 'button#end-session', 'Tab walks the whole step and then leaves it');
    await page.locator('#end-session').focus();
    await page.keyboard.press('Tab');
    assert.notEqual(await focused(page), 'button#end-session', 'Tab leaves the last control');
    await page.locator('#end-session').focus();
    await tabTo(page, '#document-download', { key: 'Shift+Tab', max: stops.length + 2 });

    const { receipt } = await approveTyped(page, world, requests, 'sig_1', 'Ada Keyboard', { keyboard: true });
    assert.equal(receipt.envelope_state, 'finalizing');
    await assertFullyApprovedNotCompleted(page);
    assert.equal(await focused(page), 'h2#step-title', 'the receipt heading takes focus');
    const counts = await inputCounts(page);
    assert.deepEqual({ pointerdown: counts.pointerdown, mousedown: counts.mousedown, touchstart: counts.touchstart }, { pointerdown: 0, mousedown: 0, touchstart: 0 }, 'zero pointer events');
  });
  assert.equal((await world.readEnvelope(sent.envelope.id)).state, 'finalizing', 'the server recorded the keyboard approval');
  recordEvidence({ browser, locked, caseId: 'SC004-01' });
});
