// SPDX-License-Identifier: Apache-2.0
//
// T009 review shell: the mobile layout, driven in Chromium with phone emulation (360 by 740
// CSS pixels, touch, device scale 2) against the real server (world.mjs).
//   AG-06  no sideways scrolling at any step, touch targets of at least 44 by 44 pixels, the
//          drawing surface takes real touch strokes (CDP touch input, not synthetic events)
//          without scrolling the page, and taps alone take the flow to the receipt, in the
//          normal order: draw, then consent, then Approve. Each stroke's finger rests before it
//          lifts (browser.mjs FINGER_REST_MS), and that rest is what lets the tap after the
//          drawing click: run04 and run05, without it, gave no click, and the recheck's R15 and
//          R16 showed the rest, not the touch path, to be the cure (dispatch Addendum 8; the
//          cause of the dropped click is unproven). From the drawing on, every touch goes through
//          one CDP touch path with every touch ended, for consistency (browser.mjs touchInput).
//          After the drawing the test records and asserts that the consent target
//          is in the viewport and hit at its tap point, and records the touch, pointer and click
//          events the page received, in order.
//          AG-06 explains its own failure at Approve (the SHELL-HASHCHANGE dispatch, Addendum 4):
//          full run 1 failed with one trusted click on Approve, an empty alert and no approval
//          response, and its cause stays undetermined because nothing kept the page, network or
//          server evidence. watchApproval() below now keeps it; the success path, its assertions
//          and the 10 s wait are unchanged.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { countClicks, fitsWidth, inputCounts, launchBrowser, openPage, previewStrokes, responseTo, step, touchInput, touchLog, verified } from './browser.mjs';
import { APPROVAL_PATH, CHALLENGE_PATH, SESSION_PATH, startWorld } from './world.mjs';

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

const PHONE = Object.freeze({ viewport: { width: 360, height: 740 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });

/** Rendered targets smaller than 44 by 44 CSS pixels, described. */
function smallTargets(page) {
  return page.evaluate(() => {
    const selector = 'button, .document-links a, .mode, .consent-choice, details.decline summary, input[type="text"]';
    const small = [];
    for (const element of document.querySelectorAll(selector)) {
      if (element.closest('[hidden]') !== null) continue;
      const details = element.closest('details');
      if (details !== null && !details.open && element.tagName !== 'SUMMARY') continue;
      const box = element.getBoundingClientRect();
      if (box.width === 0 && box.height === 0) continue;
      if (box.height < 43.5 || box.width < 43.5) small.push(`${element.tagName.toLowerCase()}.${element.className} ${Math.round(box.width)}x${Math.round(box.height)}`);
    }
    return small;
  });
}

/**
 * The evidence for a failed approval (the SHELL-HASHCHANGE dispatch, Addendum 4). From the page's
 * opening it records, passively, the approval POST's lifecycle (request; response, with its
 * status and correlation ID; requestfailed, with its errorText; requestfinished) and the page's
 * errors (pageerror messages and console errors). tapped() marks the start of the tap on Approve,
 * from which every event is timed in ms (negative: before the tap). report() is read on failure
 * only. It gives the lifecycle, or "approval request: NOT SENT" when no request event occurred;
 * the page and console errors; the server log's lines for the approval path (method, path,
 * operation, status, correlation ID and duration only: no bodies, no tokens); and the current
 * step with the #alert and #status texts. Nothing here waits or asserts.
 */
function watchApproval(page) {
  const approvalUrl = `${world.origin}${APPROVAL_PATH}`;
  const isApproval = (request) => request.url() === approvalUrl && request.method() === 'POST';
  const serverFrom = world.lines.length;
  const lifecycle = [];
  const errors = [];
  let tappedAt = null;
  page.on('request', (request) => {
    if (isApproval(request)) lifecycle.push({ at: performance.now(), what: 'request' });
  });
  page.on('response', (response) => {
    if (isApproval(response.request())) lifecycle.push({ at: performance.now(), what: `response ${response.status()} correlation ${response.headers()['x-correlation-id'] ?? '(none)'}` });
  });
  page.on('requestfailed', (request) => {
    if (isApproval(request)) lifecycle.push({ at: performance.now(), what: `requestfailed ${request.failure()?.errorText ?? '(no errorText)'}` });
  });
  page.on('requestfinished', (request) => {
    if (isApproval(request)) lifecycle.push({ at: performance.now(), what: 'requestfinished' });
  });
  page.on('pageerror', (error) => errors.push({ at: performance.now(), what: `pageerror ${error.message}` }));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push({ at: performance.now(), what: `console error ${message.text()}` });
  });
  const timed = (entry) => {
    if (tappedAt === null) return `${entry.what} (before any tap)`;
    const ms = Math.round(entry.at - tappedAt);
    return `${entry.what} at ${ms >= 0 ? '+' : ''}${ms} ms`;
  };
  const serverLines = () => {
    const lines = [];
    for (const line of world.lines.slice(serverFrom)) {
      let record;
      try {
        record = JSON.parse(line);
      } catch {
        continue;
      }
      if (record.event !== 'request' || record.path !== APPROVAL_PATH) continue;
      lines.push(`${record.method} ${record.path} ${record.operation} ${record.status} correlation ${record.correlation_id} ${record.duration_ms} ms`);
    }
    return lines;
  };
  return {
    tapped() {
      tappedAt = performance.now();
    },
    async report() {
      const flow = lifecycle.some((entry) => entry.what === 'request') ? `approval request: ${lifecycle.map(timed).join(', ')}` : 'approval request: NOT SENT';
      const state = await page
        .evaluate(() => ({
          step: document.getElementById('app')?.getAttribute('data-step') ?? null,
          alert: document.getElementById('alert')?.textContent ?? null,
          status: document.getElementById('status')?.textContent ?? null,
        }))
        .catch((error) => ({ unreadable: String(error?.message ?? error).split('\n')[0] }));
      return { flow, errors: errors.map(timed), server: serverLines(), state };
    },
  };
}

test('[AG-06] at 360 px with touch: no sideways scrolling at any step, 44 px targets, the pad takes touch strokes without scrolling the page, and taps alone reach the receipt (draw, consent, approve)', async (t) => {
  const sent = await world.sentEnvelope();
  const { page, requests, close } = await openPage(browser, PHONE);
  const approval = watchApproval(page);
  try {
    await page.goto(sent.url);
    await step(page, 'invitation');
    assert.equal(await fitsWidth(page), true, 'the invitation step fits 360 px');
    assert.deepEqual(await smallTargets(page), []);
    const challenge = responseTo(page, world.origin, CHALLENGE_PATH, 'POST');
    await page.getByRole('button', { name: 'Email me a code' }).tap();
    assert.equal((await challenge).status(), 202);
    await step(page, 'code');
    assert.equal(await fitsWidth(page), true, 'the code step fits 360 px');
    assert.deepEqual(await smallTargets(page), []);
    const code = await world.code(sent.recipients[0]);
    await page.getByRole('textbox', { name: 'One-time code' }).fill(code);
    const created = responseTo(page, world.origin, SESSION_PATH, 'POST');
    await page.getByRole('button', { name: 'Continue' }).tap();
    assert.equal((await created).status(), 201);
    await step(page, 'review');
    await verified(page);
    assert.equal(await fitsWidth(page), true, 'the review step fits 360 px');
    assert.deepEqual(await smallTargets(page), []);
    const frameBox = await page.locator('#document-frame').boundingBox();
    assert.ok(frameBox && frameBox.x >= 0 && frameBox.x + frameBox.width <= 360, 'the viewer frame stays inside the viewport');
    for (const outline of await page.locator('svg.page-outline').all()) {
      const box = await outline.boundingBox();
      assert.ok(box && box.x >= 0 && box.x + box.width <= 360, 'each page outline stays inside the viewport');
    }

    // A tap's click is synthesized after the touch sequence is acknowledged: wait for its effect.
    await page.locator('label[for="mode-drawn-sig_1"]').tap();
    await page.locator('#mode-drawn-sig_1:checked').waitFor({ state: 'attached' });
    const surface = page.locator('svg.pad-surface[data-field="sig_1"]');
    assert.equal(await surface.evaluate((element) => getComputedStyle(element).touchAction), 'none');
    await surface.scrollIntoViewIfNeeded();
    const box = await surface.boundingBox();
    assert.ok(box && box.x >= 0 && box.x + box.width <= 360 && box.height >= 40, 'the drawing surface fits and is usable');
    const scrolled = await page.evaluate(() => [window.scrollX, window.scrollY]);
    const events = await touchLog(page);
    // From here every touch goes through one CDP touch path, for consistency: draw, then consent,
    // then Approve. The finger rest at the end of each stroke (touch.draw) is what lets the taps
    // after the drawing click (dispatch Addendum 8).
    const touch = await touchInput(page);
    let response;
    let preview;
    try {
      await touch.draw('sig_1', [
        [
          [0.1, 0.7],
          [0.25, 0.2],
          [0.45, 0.75],
          [0.65, 0.25],
          [0.9, 0.6],
        ],
        [
          [0.2, 0.85],
          [0.8, 0.85],
        ],
      ]);
      assert.deepEqual(await page.evaluate(() => [window.scrollX, window.scrollY]), scrolled, 'drawing does not scroll the page');
      preview = await previewStrokes(page, 'sig_1');
      assert.equal(preview.length, 2, 'both touch strokes are previewed');
      assert.ok((await inputCounts(page)).pointerTypes.includes('touch'), 'the strokes came from touch input');

      // The consent target after the drawing: in the viewport, and what is hit at its tap point.
      const consentLabel = page.locator('label[for="consent"]');
      await consentLabel.scrollIntoViewIfNeeded();
      const target = await consentLabel.evaluate((label) => {
        const rect = label.getBoundingClientRect();
        const x = rect.left + rect.width / 2;
        const y = rect.top + rect.height / 2;
        const hit = document.elementFromPoint(x, y);
        const name = (element) => (element === null ? null : `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ''}${element.getAttribute('for') ? `[for=${element.getAttribute('for')}]` : ''}`);
        return {
          box: { x: Math.round(rect.left), y: Math.round(rect.top), width: Math.round(rect.width), height: Math.round(rect.height) },
          row: Math.round(label.parentElement?.getBoundingClientRect().height ?? 0),
          viewport: { width: window.innerWidth, height: window.innerHeight },
          hit: name(hit),
          hitsTarget: hit !== null && (hit === label || label.contains(hit)),
          inViewport: rect.left >= 0 && rect.top >= 0 && rect.right <= window.innerWidth && rect.bottom <= window.innerHeight,
        };
      });
      t.diagnostic(`consent target after drawing: ${JSON.stringify(target)}`);
      assert.ok(target.inViewport && target.hitsTarget, `after drawing, the consent target is in the viewport and hit at its tap point (${JSON.stringify(target)})`);
      assert.ok(target.row >= 43.5, 'its row is at least 44 px tall');

      const labelClicks = await countClicks(page, 'label[for="consent"]');
      await touch.tap(consentLabel);
      await page
        .locator('#consent:checked')
        .waitFor({ state: 'attached', timeout: 10_000 })
        .catch(async () => assert.fail(`a tap on the consent label after drawing did not check it (trusted clicks on the label: ${await labelClicks()}; events: ${(await events()).join(' ')})`));

      const approveClicks = await countClicks(page, '#approve');
      const answer = page.waitForResponse((candidate) => candidate.url() === `${world.origin}${APPROVAL_PATH}` && candidate.request().method() === 'POST', { timeout: 10_000 });
      approval.tapped();
      await touch.tap(page.getByRole('button', { name: 'Approve the document' }));
      response = await answer.catch(async (error) => {
        // On failure only: what was observed, in that order, with the token and the code redacted.
        const seen = await approval.report();
        const clicks = await approveClicks().catch(() => 'unreadable');
        const received = await events()
          .then((list) => list.join(' '))
          .catch(() => 'unreadable');
        const hide = (text) => text.split(sent.token).join('[token redacted]').split(code).join('[code redacted]');
        assert.fail(
          hide(
            `no approval response within 10 s of the tap on Approve; ${seen.flow}; trusted clicks on Approve: ${clicks}; events: ${received}; wait: ${String(error?.message ?? error).split('\n')[0]}; ` +
              `page and console errors: ${JSON.stringify(seen.errors)}; server log for the approval path: ${JSON.stringify(seen.server)}; ` +
              ('unreadable' in seen.state ? `page state unreadable: ${seen.state.unreadable}` : `step: ${seen.state.step}; alert: ${JSON.stringify(seen.state.alert)}; status: ${JSON.stringify(seen.state.status)}`),
          ),
        );
      });
    } finally {
      await touch.detach();
    }
    t.diagnostic(`touch, pointer and click events the page received from the drawing on (moves left out): ${(await events()).join(' ')}`);
    assert.equal(response.status(), 200);
    const body = JSON.parse(requests.find((request) => request.url === `${world.origin}${APPROVAL_PATH}`).body);
    assert.deepEqual(
      body.field_values.find((value) => value.key === 'sig_1'),
      { key: 'sig_1', type: 'signature', mode: 'drawn', strokes: preview },
    );
    await step(page, 'approved');
    assert.equal(await fitsWidth(page), true, 'the receipt fits 360 px');
    assert.deepEqual(await smallTargets(page), []);
  } finally {
    await close();
  }
});
