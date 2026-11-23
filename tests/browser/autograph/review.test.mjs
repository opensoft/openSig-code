// SPDX-License-Identifier: Apache-2.0
//
// T009 review shell: consent, the drawn signature and the server-set date, driven in Chromium
// against the real server (world.mjs).
//   AG-03  the exact consent text with its version and digest, the assurance statement and the
//          organization-seal notice; drawn strokes within the caps, previewed exactly as
//          submitted; the date labelled as set by the server and never sent by the browser;
//          "fully approved" never presented as completed.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { drawWithMouse, launchBrowser, openPage, previewStrokes, responseTo, signIn, step } from './browser.mjs';
import { APPROVAL_PATH, ASSURANCE, CONSENT_TEXT, CONSENT_VERSION, SEAL_NOTICE, SESSION_PATH, startWorld } from './world.mjs';

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

const DRAWING = [
  [
    [0.08, 0.6],
    [0.2, 0.25],
    [0.35, 0.7],
    [0.5, 0.3],
    [0.65, 0.75],
    [0.8, 0.35],
    [0.92, 0.6],
  ],
  [
    [0.15, 0.85],
    [0.85, 0.82],
  ],
];

test('[AG-03] consent shows the exact text, version, assurance statement and seal notice; a drawn signature is previewed exactly as submitted; the date is set by the server, never sent', async () => {
  const sent = await world.sentEnvelope();
  const { page, requests, close } = await openPage(browser);
  try {
    const state = await signIn(page, world, sent);
    assert.equal(state.consent.text, CONSENT_TEXT);
    assert.equal(await page.locator('#consent-text').textContent(), CONSENT_TEXT, 'the consent text is shown exactly, line break and apostrophe included');
    assert.match(await page.locator('#consent-version').textContent(), new RegExp(`version ${CONSENT_VERSION.replace(/\./g, '\\.')}\\.$`));
    assert.equal(await page.locator('#assurance-statement').textContent(), ASSURANCE.statement);
    assert.equal(await page.locator('#seal-notice').textContent(), SEAL_NOTICE);
    const dateText = await page.locator('p.date-field[data-field="date_1"]').textContent();
    assert.match(dateText, /The server sets it to its own UTC date when you approve/);
    assert.match(dateText, /unsigned server time, not a trusted timestamp/);
    assert.equal(await page.locator('input[data-field="date_1"], [data-field="date_1"] input').count(), 0, 'the date has no input');

    await page.getByRole('radio', { name: 'Draw my signature' }).check();
    await drawWithMouse(page, 'sig_1', DRAWING);
    const preview = await previewStrokes(page, 'sig_1');
    assert.equal(preview.length, DRAWING.length, 'one previewed stroke per drawn stroke');
    for (const stroke of preview) {
      assert.ok(stroke.length >= 2 && stroke.length <= 1000);
      for (const [x, y] of stroke) assert.ok(Number.isInteger(x) && Number.isInteger(y) && x >= 0 && x <= 10000 && y >= 0 && y <= 10000);
    }
    assert.match(await page.locator('#pad-status-sig_1').textContent(), /^2 strokes drawn \(\d+ of at most 10000 points\)\.$/);

    await page.getByRole('button', { name: 'Approve the document' }).click();
    await page.locator('#alert', { hasText: 'Confirm that you have read and agree to the consent text.' }).waitFor();
    assert.equal(
      requests.some((request) => request.url === `${world.origin}${APPROVAL_PATH}`),
      false,
      'nothing is sent before consent is given',
    );

    await page.getByRole('checkbox', { name: 'I have read the consent text above and I agree to it.' }).check();
    const answer = responseTo(page, world.origin, APPROVAL_PATH, 'POST');
    await page.getByRole('button', { name: 'Approve the document' }).click();
    const response = await answer;
    const body = JSON.parse(requests.find((request) => request.url === `${world.origin}${APPROVAL_PATH}`).body);
    assert.deepEqual(body, {
      expected_version: state.envelope_version,
      document_digest: sent.entry.sha256,
      manifest_digest: state.manifest_digest,
      prior_approval_digest: null,
      consent_version: CONSENT_VERSION,
      consent_text_digest: world.consent.digest,
      consent: true,
      // One value per field, in the order the session gives its fields.
      field_values: state.fields.map((field) => (field.type === 'date' ? { key: field.key, type: 'date' } : { key: field.key, type: 'signature', mode: 'drawn', strokes: preview })),
    });
    assert.deepEqual(state.fields.map((field) => field.key).sort(), ['date_1', 'sig_1']);
    assert.equal(response.status(), 200);
    const receipt = await response.json();
    assert.equal(receipt.envelope_state, 'finalizing');
    await step(page, 'approved');
    const outcome = await page.locator('#approval-outcome').textContent();
    assert.match(outcome, /^Fully approved: every required approval is recorded\. The document is not completed yet/);
    const date = receipt.date_values.find((value) => value.key === 'date_1');
    assert.match(date.value, /^\d{4}-\d{2}-\d{2}$/);
    const dateLine = await page.locator('#date-values li[data-field="date_1"]').textContent();
    assert.ok(dateLine.includes(date.value) && dateLine.includes('set by the server') && dateLine.includes('unsigned server time'), 'the date is shown as server-set');
    const timeLine = await page.locator('#server-time').textContent();
    assert.ok(timeLine.includes(receipt.server_time) && timeLine.includes('unsigned server time, not a trusted timestamp'));
  } finally {
    await close();
  }
});

test('[AG-03] the approval binds what the session showed; after recipient 1 the next recipient is invited, and after the last "fully approved" is never "completed"', async () => {
  const first = world.address('first');
  const second = world.address('second');
  const sent = await world.sentEnvelope({ recipients: [first, second] });
  const one = await openPage(browser);
  let firstReceipt;
  try {
    const state = await signIn(one.page, world, sent);
    assert.deepEqual(
      state.fields.map((field) => field.key).sort(),
      ['date_1', 'sig_1'],
      'the session shows this recipient its own fields only',
    );
    await one.page.getByRole('textbox', { name: 'Type your full name' }).fill('  Ada Example  ');
    await one.page.getByRole('checkbox', { name: 'I have read the consent text above and I agree to it.' }).check();
    const answer = responseTo(one.page, world.origin, APPROVAL_PATH, 'POST');
    await one.page.getByRole('button', { name: 'Approve the document' }).click();
    const response = await answer;
    assert.equal(response.status(), 200);
    const body = JSON.parse(one.requests.find((request) => request.url === `${world.origin}${APPROVAL_PATH}`).body);
    assert.deepEqual(
      body.field_values,
      state.fields.map((field) => (field.type === 'date' ? { key: field.key, type: 'date' } : { key: field.key, type: 'signature', mode: 'typed', text: 'Ada Example' })),
      'the typed name is trimmed; the date carries no value',
    );
    firstReceipt = await response.json();
    assert.equal(firstReceipt.envelope_state, 'in-progress');
    await step(one.page, 'approved');
    const outcome = await one.page.locator('#approval-outcome').textContent();
    assert.equal(outcome, 'Your approval is recorded. The next recipient is invited to approve.');
  } finally {
    await one.close();
  }

  const token = world.invitation(second);
  const two = await openPage(browser);
  try {
    const state = await signIn(two.page, world, { ...sent, token, url: `${world.origin}/sign#i=${token}`, recipients: [second] });
    assert.equal(state.prior_approval_digest, firstReceipt.approval_digest, 'recipient 2 binds recipient 1 approval');
    assert.deepEqual(
      state.fields.map((field) => field.key),
      ['sig_2'],
    );
    await two.page.getByRole('textbox', { name: 'Type your full name' }).fill('Grace Example');
    await two.page.getByRole('checkbox', { name: 'I have read the consent text above and I agree to it.' }).check();
    const answer = responseTo(two.page, world.origin, APPROVAL_PATH, 'POST');
    await two.page.getByRole('button', { name: 'Approve the document' }).click();
    const response = await answer;
    assert.equal(response.status(), 200);
    const body = JSON.parse(two.requests.find((request) => request.url === `${world.origin}${APPROVAL_PATH}`).body);
    assert.equal(body.prior_approval_digest, firstReceipt.approval_digest);
    assert.equal((await response.json()).envelope_state, 'finalizing');
    await step(two.page, 'approved');
    const outcome = await two.page.locator('#approval-outcome').textContent();
    assert.match(outcome, /^Fully approved/);
    assert.match(outcome, /not completed yet: it is completed only after the organization seal is applied and verified\.$/);
    assert.equal(await two.page.locator('#date-values li').count(), 0, 'recipient 2 has no date field');
  } finally {
    await two.close();
  }
});

test('[AG-03] a consent text that does not match its digest is flagged and blocks the approval', async () => {
  const sent = await world.sentEnvelope();
  const { page, requests, close } = await openPage(browser);
  try {
    await signIn(page, world, sent);
    // The session is re-read on reload; the browser receives a consent text altered in transit.
    await page.route(`${world.origin}${SESSION_PATH}`, async (route) => {
      if (route.request().method() !== 'GET') return route.continue();
      const response = await route.fetch();
      const json = await response.json();
      json.consent.text = `${json.consent.text} (altered)`;
      return route.fulfill({ response, json });
    });
    await page.reload();
    await step(page, 'review');
    await page.locator('#alert', { hasText: 'The consent text does not match its digest.' }).waitFor();
    await page.getByRole('textbox', { name: 'Type your full name' }).fill('Ada Example');
    await page.getByRole('checkbox', { name: 'I have read the consent text above and I agree to it.' }).check();
    // Clear the notice, so the one that follows is Approve's own answer.
    await page.locator('#alert').evaluate((alert) => {
      alert.textContent = '';
    });
    await page.getByRole('button', { name: 'Approve the document' }).click();
    await page.locator('#alert', { hasText: 'The consent text does not match its digest. Do not approve' }).waitFor();
    assert.equal(
      requests.some((request) => request.url === `${world.origin}${APPROVAL_PATH}`),
      false,
      'no approval is sent with a consent text that does not match its digest',
    );
  } finally {
    await close();
  }
});
