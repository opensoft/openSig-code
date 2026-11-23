// SPDX-License-Identifier: Apache-2.0
//
// T009 review shell: the keyboard path and accessibility, driven in Chromium against the real
// server (world.mjs).
//   AG-04  keyboard only, from the invitation to the receipt, with the typed signature: no
//          pointer, mouse or touch input at all; a name the document font (WinAnsi) cannot
//          show is refused before anything is sent.
//   AG-05  accessible names for every control, the heading, landmark and live-region
//          structure, a Tab order that follows the DOM, Shift+Tab that reverses it, no focus
//          trap (the drawing pad and the embedded viewer are not tab stops), and focus moved
//          to each new step's heading. A keyboard-only case (A-010 request #34 B3): the
//          viewer's iframe stays out of the tab order with a title naming the document, and
//          Tab reaches the adjacent named links (open in a new tab, download) and then the
//          signature and consent controls, never entering the iframe and never trapped.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { accessibilityTree, expectedTabOrder, focused, inputCounts, launchBrowser, openPage, responseTo, signIn, signInByKeyboard, step, tabTo } from './browser.mjs';
import { APPROVAL_PATH, CHALLENGE_PATH, startWorld } from './world.mjs';

let world;
let browser;

before(async () => {
  world = await startWorld();
  browser = await launchBrowser();
});

after(async () => {
  try {
    await browser?.close();
  } finally {
    await world?.close();
  }
});

const CONTROL_ROLES = new Set(['button', 'link', 'checkbox', 'radio', 'textbox', 'searchbox', 'combobox', 'spinbutton', 'slider', 'switch', 'DisclosureTriangle', 'Iframe', 'iframe']);

/** Interactive nodes of the main frame's accessibility tree, with their computed names. */
async function controls(page) {
  const nodes = await accessibilityTree(page);
  return nodes.filter((node) => !node.ignored && CONTROL_ROLES.has(node.role?.value)).map((node) => ({ role: node.role.value, name: String(node.name?.value ?? '').trim() }));
}

test('[AG-04] keyboard only, invitation to receipt, typed signature: no pointer, mouse or touch input; a name the document font cannot show is refused before anything is sent', async () => {
  const sent = await world.sentEnvelope();
  const { page, requests, close } = await openPage(browser);
  try {
    await signInByKeyboard(page, world, sent);

    await tabTo(page, '#typed-sig_1');
    await page.keyboard.type('Snow \u2603 Man');
    await tabTo(page, '#consent');
    await page.keyboard.press('Space');
    assert.equal(await page.locator('#consent').isChecked(), true);
    await tabTo(page, '#approve');
    await page.keyboard.press('Enter');
    await page.locator('#alert', { hasText: "These characters cannot be shown in the document's font: \u2603" }).waitFor();
    assert.equal(
      requests.some((request) => request.url === `${world.origin}${APPROVAL_PATH}`),
      false,
      'nothing is sent while the typed name has an unsupported character',
    );

    await tabTo(page, '#typed-sig_1', { key: 'Shift+Tab' });
    await page.keyboard.press('Control+A');
    await page.keyboard.type('Ada Lovelace-Byron');
    await tabTo(page, '#approve');
    const answer = responseTo(page, world.origin, APPROVAL_PATH, 'POST');
    await page.keyboard.press('Enter');
    const response = await answer;
    assert.equal(response.status(), 200);
    const posted = requests.filter((request) => request.url === `${world.origin}${APPROVAL_PATH}`);
    assert.equal(posted.length, 1, 'exactly one approval was sent');
    assert.deepEqual(
      JSON.parse(posted[0].body).field_values.find((value) => value.key === 'sig_1'),
      { key: 'sig_1', type: 'signature', mode: 'typed', text: 'Ada Lovelace-Byron' },
    );
    await step(page, 'approved');
    assert.equal(await focused(page), 'h2#step-title[]', 'the receipt heading takes focus');
    const counts = await inputCounts(page);
    assert.deepEqual({ pointerdown: counts.pointerdown, mousedown: counts.mousedown, touchstart: counts.touchstart }, { pointerdown: 0, mousedown: 0, touchstart: 0 }, 'no pointer, mouse or touch input was used');
  } finally {
    await close();
  }
});

test('[AG-05] every control has an accessible name at every step, with one h1, a step h2, landmarks, a status and an alert region, grouped radio choices and labelled page outlines', async () => {
  const sent = await world.sentEnvelope();
  const { page, close } = await openPage(browser);
  try {
    await page.goto(sent.url);
    await step(page, 'invitation');
    assert.equal(await page.locator('html').getAttribute('lang'), 'en');
    for (const control of await controls(page)) assert.notEqual(control.name, '', `a ${control.role} at the invitation step has a name`);

    const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
    await page.getByRole('button', { name: 'Email me a code' }).click();
    assert.equal((await challenge).status(), 202);
    await step(page, 'code');
    for (const control of await controls(page)) assert.notEqual(control.name, '', `a ${control.role} at the code step has a name`);
    await world.code(sent.recipients[0]);
  } finally {
    await close();
  }

  const reviewer = await openPage(browser);
  try {
    const page = reviewer.page;
    await signIn(page, world, await world.sentEnvelope());
    await page.getByRole('radio', { name: 'Draw my signature' }).check();
    const found = await controls(page);
    for (const control of found) assert.notEqual(control.name, '', `a ${control.role} at the review step has a name`);
    const names = found.map((control) => `${control.role}:${control.name}`);
    for (const wanted of [
      'link:Skip to the main content',
      'link:Download the document (PDF)',
      'link:Open the document in a new tab',
      'radio:Type my name',
      'radio:Draw my signature',
      'button:Clear the drawing in field sig_1',
      'checkbox:I have read the consent text above and I agree to it.',
      'button:Approve the document',
      'button:End this session',
    ]) {
      assert.ok(names.includes(wanted), `the review step has ${wanted}`);
    }
    assert.equal(await page.getByRole('main').count(), 1);
    assert.equal(await page.getByRole('banner').count(), 1);
    assert.equal(await page.getByRole('contentinfo').count(), 1);
    assert.equal(await page.getByRole('heading', { level: 1 }).count(), 1);
    assert.deepEqual(await page.getByRole('heading', { level: 2 }).allTextContents(), ['Review and approve']);
    assert.equal(await page.getByRole('status').count(), 1);
    assert.equal(await page.getByRole('alert').count(), 1);
    assert.equal(await page.getByRole('group', { name: 'How do you want to sign?' }).count(), 1);
    assert.equal(await page.getByRole('img', { name: /^Page 3 of 3: 2 fields for you$/ }).count(), 1, 'the page outline is labelled');
    assert.equal(await page.getByRole('img', { name: /^Drawing area for the signature in field sig_1\./ }).count(), 1, 'the drawing area says how to sign with the keyboard');
    assert.equal(await page.getByRole('figure').count(), 1);
  } finally {
    await reviewer.close();
  }
});

test('[AG-05] Tab follows the DOM order, Shift+Tab reverses it, focus is never trapped (the pad and the embedded viewer are not tab stops), and each step change focuses its heading', async () => {
  const sent = await world.sentEnvelope();
  const { page, close } = await openPage(browser);
  try {
    await signIn(page, world, sent);
    assert.equal(await focused(page), 'h2#step-title[]', 'the review heading takes focus after the code');
    await tabTo(page, '#mode-typed-sig_1');
    await page.keyboard.press('ArrowDown');
    assert.equal(await page.locator('#mode-drawn-sig_1').isChecked(), true, 'arrow keys choose within the radio group');
    await page.locator('#draw-panel-sig_1').waitFor();

    await page.locator('#step-title').focus();
    const expected = (await expectedTabOrder(page)).filter((entry) => entry.after).map((entry) => entry.name);
    assert.ok(expected.length >= 8, 'the review step has its controls');
    assert.equal(expected.some((name) => name.startsWith('svg') || name.startsWith('iframe')), false);

    const forward = [];
    for (let press = 0; press < expected.length; press += 1) {
      await page.keyboard.press('Tab');
      forward.push(await focused(page));
    }
    assert.deepEqual(forward, expected, 'Tab visits every control once, in DOM order');

    const backward = [await focused(page)];
    for (let press = 1; press < expected.length; press += 1) {
      await page.keyboard.press('Shift+Tab');
      backward.push(await focused(page));
    }
    assert.deepEqual(backward, [...expected].reverse(), 'Shift+Tab visits them in reverse');

    await page.locator('#end-session').focus();
    await page.keyboard.press('Tab');
    assert.notEqual(await focused(page), expected[expected.length - 1], 'Tab leaves the last control: no trap');
  } finally {
    await close();
  }
});

test('[AG-05] keyboard only: the viewer stays out of the tab order with a title naming the document, and Tab reaches the named open and download links, then the signature and consent controls, never entering the iframe and never trapped', async () => {
  const sent = await world.sentEnvelope();
  const { page, close } = await openPage(browser);
  try {
    await signInByKeyboard(page, world, sent);
    const frame = page.locator('iframe#document-frame');
    assert.equal(await frame.getAttribute('tabindex'), '-1', 'the viewer iframe is not a tab stop');
    assert.match((await frame.getAttribute('title')) ?? '', /^The document under review \(PDF, 3 pages\)/, 'its title names the document');
    assert.equal(await page.getByRole('link', { name: 'Open the document in a new tab' }).count(), 1);
    assert.equal(await page.getByRole('link', { name: 'Download the document (PDF)' }).count(), 1);
    const adjacent = await page.evaluate(() => {
      const links = document.querySelector('p.document-links');
      return links !== null && links.previousElementSibling?.id === 'document-frame';
    });
    assert.equal(adjacent, true, 'the links sit right after the viewer');

    // From the review heading, Tab through the whole step: every stop is recorded.
    // The walk ends when focus leaves the page content: to the browser (body) or, wrapping,
    // to the skip link or the first stop again.
    const stops = [];
    const inside = [];
    for (let press = 0; press < 40; press += 1) {
      await page.keyboard.press('Tab');
      const now = await focused(page);
      inside.push(await page.evaluate(() => document.activeElement?.tagName === 'IFRAME'));
      if (now === 'body' || now === 'a#skip-link[]' || now === stops[0]) break;
      stops.push(now);
    }
    assert.ok(stops.length >= 6 && stops.length < 40, `Tab walked the step and left it (${stops.length} stops)`);
    assert.equal(inside.some(Boolean), false, 'focus never entered the viewer iframe');
    assert.equal(stops.some((stop) => stop.startsWith('iframe')), false);
    const at = (name) => stops.indexOf(name);
    assert.deepEqual(stops.slice(0, 2), ['a#document-download[]', 'a#document-open[]'], 'the first stops are the named document links');
    for (const control of ['input#mode-typed-sig_1[mode-sig_1]', 'input#typed-sig_1[]', 'input#consent[]', 'button#approve[]']) {
      assert.ok(at(control) > at('a#document-open[]'), `${control} is reached after the links`);
    }
    assert.ok(at('input#typed-sig_1[]') < at('input#consent[]') && at('input#consent[]') < at('button#approve[]'), 'signature, then consent, then Approve');
    assert.equal(stops[stops.length - 1], 'button#end-session[]', 'the last stop of the step is End this session');

    // Not trapped at either end: Tab leaves the last control, and Shift+Tab walks back to the first link.
    await page.locator('#end-session').focus();
    await page.keyboard.press('Tab');
    assert.notEqual(await focused(page), 'button#end-session[]', 'Tab leaves the last control');
    await page.locator('#end-session').focus();
    await tabTo(page, '#document-download', { key: 'Shift+Tab', max: stops.length + 2 });

    const counts = await inputCounts(page);
    assert.deepEqual({ pointerdown: counts.pointerdown, mousedown: counts.mousedown, touchstart: counts.touchstart }, { pointerdown: 0, mousedown: 0, touchstart: 0 }, 'keyboard only');
  } finally {
    await close();
  }
});
