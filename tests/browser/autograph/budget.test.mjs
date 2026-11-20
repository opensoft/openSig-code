// SPDX-License-Identifier: Apache-2.0
//
// T009 review shell: the drawn-signature budget (AG-07, an additional case beyond the frozen
// runner's AG-01..AG-06 minimum, with no runner change: A-010 request #34 B2).
//   AG-07  coordinates quantized to integers 0..10000; strokes simplified, with the smallest
//          tolerance that fits, to at most 1,000 points per stroke, 10,000 per value and
//          15,000 per approval (each of n signature fields gets min(10000, floor(15000 / n)));
//          the preview shows exactly what is submitted; and a maximal two-field capture stays
//          under the 256 KiB JSON body limit.
// The first test is the arithmetic, on src/autograph/strokes.ts itself (its only import is a
// type import, erased by Node's type stripping); the second drives the shell in Chromium
// against the real server (world.mjs).

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import {
  COLLAPSE_TOLERANCE,
  MAX_POINTS_PER_APPROVAL,
  MAX_POINTS_PER_STROKE,
  MAX_POINTS_PER_VALUE,
  budgetPerValue,
  countPoints,
  fitStrokes,
  quantize,
  simplifyStroke,
} from '../../../src/autograph/strokes.ts';
import { launchBrowser, openPage, previewStrokes, responseTo, signIn, step } from './browser.mjs';
import { APPROVAL_PATH, JSON_BODY_LIMIT, startWorld } from './world.mjs';

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

/** n points with x strictly increasing and y oscillating: nothing collinear to drop for free. */
function wave(n, phase) {
  return Array.from({ length: n }, (_, index) => [Math.round(100 + (9800 * index) / (n - 1)), Math.round(5000 + 4500 * Math.sin(index * 0.9 + phase))]);
}

function chunk(points, size) {
  const out = [];
  for (let start = 0; start < points.length; start += size) out.push(points.slice(start, start + size));
  return out;
}

test('[AG-07] the stroke arithmetic: quantization to 0..10000, per-field budgets, the minimal simplification within 1,000 per stroke, 10,000 per value and 15,000 per approval, and the maximal body under 256 KiB', () => {
  assert.deepEqual(
    [quantize(-0.5), quantize(0), quantize(0.00004), quantize(0.00005), quantize(0.5), quantize(0.99995), quantize(1), quantize(1.7), quantize(Number.NaN), quantize(Number.POSITIVE_INFINITY)],
    [0, 0, 0, 1, 5000, 10000, 10000, 10000, 0, 10000],
  );
  assert.deepEqual([1, 2, 3, 4, 7].map(budgetPerValue), [10000, 7500, 5000, 3750, 2142]);
  for (let fields = 1; fields <= 20; fields += 1) {
    assert.ok(fields * budgetPerValue(fields) <= MAX_POINTS_PER_APPROVAL, `${fields} fields stay within the approval budget`);
    assert.ok(budgetPerValue(fields) <= MAX_POINTS_PER_VALUE);
  }

  // Within budget, nothing is removed: the preview is the drawing.
  const convex = [0, 1, 2].map((offset) => Array.from({ length: 31 }, (_, index) => [index * 50 + offset * 1000, index * index * 3 + offset * 100]));
  const kept = fitStrokes(convex, 10000);
  assert.deepEqual(kept.strokes, convex);
  assert.equal(kept.tolerance, 0);

  // Over budget: 50 strokes, one of 4,000 points, the rest of 400 (23,600 points).
  const raw = [wave(4000, 0), ...Array.from({ length: 49 }, (_, index) => wave(400, index + 1))];
  for (const budget of [budgetPerValue(2), budgetPerValue(1)]) {
    const fit = fitStrokes(raw, budget);
    assert.equal(fit.strokes.length, 50, 'no stroke is dropped');
    assert.ok(fit.points <= budget && fit.points === countPoints(fit.strokes), `at most ${budget} points`);
    assert.ok(fit.tolerance > 0 && fit.tolerance < COLLAPSE_TOLERANCE);
    fit.strokes.forEach((stroke, index) => {
      assert.ok(stroke.length >= 2 && stroke.length <= MAX_POINTS_PER_STROKE, 'each stroke has 2..1000 points');
      assert.deepEqual(stroke[0], raw[index][0], 'the stroke starts where it was drawn');
      assert.deepEqual(stroke[stroke.length - 1], raw[index][raw[index].length - 1], 'and ends there');
      for (const [x, y] of stroke) assert.ok(Number.isInteger(x) && Number.isInteger(y) && x >= 0 && x <= 10000 && y >= 0 && y <= 10000);
    });
    // Minimal: one unit less tolerance does not fit.
    const looser = raw.map((stroke) => simplifyStroke(stroke, fit.tolerance - 1));
    assert.ok(countPoints(looser) > budget || looser.some((stroke) => stroke.length > MAX_POINTS_PER_STROKE), 'the tolerance is the smallest that fits');
    assert.deepEqual(fit.strokes, raw.map((stroke) => simplifyStroke(stroke, fit.tolerance)), 'the fit is the simplification at that tolerance, deterministic');
  }
  assert.throws(() => fitStrokes(Array.from({ length: 51 }, () => [[0, 0], [1, 1]]), 10000), RangeError);
  assert.throws(() => fitStrokes(raw, 99), RangeError, 'a budget below two points per stroke is refused');

  // The largest approval the budgets allow: two fields of 7,500 points at [10000,10000] in
  // strokes of 1,000, a date field, the longest keys and version, every digest present.
  const digest = 'f'.repeat(64);
  const field = (key) => ({ key, type: 'signature', mode: 'drawn', strokes: chunk(Array.from({ length: budgetPerValue(2) }, () => [10000, 10000]), MAX_POINTS_PER_STROKE) });
  const body = {
    expected_version: 2147483647,
    document_digest: digest,
    manifest_digest: digest,
    prior_approval_digest: digest,
    consent_version: 'v'.repeat(40),
    consent_text_digest: digest,
    consent: true,
    field_values: [field('a'.repeat(40)), field('b'.repeat(40)), { key: 'c'.repeat(40), type: 'date' }],
  };
  const bytes = Buffer.byteLength(JSON.stringify(body), 'utf8');
  assert.equal(countPoints(body.field_values[0].strokes) + countPoints(body.field_values[1].strokes), MAX_POINTS_PER_APPROVAL);
  assert.ok(bytes <= MAX_POINTS_PER_APPROVAL * '[10000,10000],'.length + 1024, `the maximal body is about 14 bytes per point (${bytes})`);
  assert.ok(bytes < JSON_BODY_LIMIT, `the maximal body (${bytes} bytes) is under 256 KiB`);
});

test('[AG-07] a maximal two-field capture in the browser: 50 strokes per field simplified to the 7,500-point budgets and 1,000 per stroke, a 51st stroke refused, the preview exactly what is submitted, and the body under 256 KiB', async () => {
  const fields = [
    { key: 'sig_a', recipient_ordinal: 1, page: 3, type: 'signature', rect: { x: 0.06, y: 0.62, width: 0.42, height: 0.1 } },
    { key: 'sig_b', recipient_ordinal: 1, page: 3, type: 'signature', rect: { x: 0.52, y: 0.62, width: 0.42, height: 0.1 } },
    { key: 'date_a', recipient_ordinal: 1, page: 3, type: 'date', rect: { x: 0.06, y: 0.78, width: 0.2, height: 0.05 } },
  ];
  const sent = await world.sentEnvelope({ fields });
  const { page, requests, close } = await openPage(browser);
  try {
    const state = await signIn(page, world, sent);
    for (const key of ['sig_a', 'sig_b']) {
      await page.locator(`#mode-drawn-${key}`).check();
      await page.evaluate(
        ({ field, strokes, longPoints, shortPoints }) => {
          const surface = document.querySelector(`svg.pad-surface[data-field="${field}"]`);
          surface.scrollIntoView({ block: 'center' });
          const box = surface.getBoundingClientRect();
          const fire = (type, fx, fy) =>
            surface.dispatchEvent(
              new PointerEvent(type, {
                bubbles: true,
                cancelable: true,
                composed: true,
                pointerId: 41,
                pointerType: 'pen',
                isPrimary: true,
                button: type === 'pointermove' ? -1 : 0,
                buttons: type === 'pointerup' ? 0 : 1,
                clientX: box.left + fx * box.width,
                clientY: box.top + fy * box.height,
              }),
            );
          for (let stroke = 0; stroke < strokes; stroke += 1) {
            const count = stroke === 0 ? longPoints : shortPoints;
            let fx = 0;
            let fy = 0;
            for (let index = 0; index < count; index += 1) {
              fx = 0.01 + (0.98 * index) / (count - 1);
              fy = 0.5 + 0.45 * Math.sin(index * 0.9 + stroke);
              fire(index === 0 ? 'pointerdown' : 'pointermove', fx, fy);
            }
            fire('pointerup', fx, fy);
          }
          fire('pointerdown', 0.5, 0.5);
          fire('pointerup', 0.5, 0.5);
        },
        { field: key, strokes: 50, longPoints: 2500, shortPoints: 300 },
      );
      await page.locator('#status', { hasText: 'This field holds at most 50 strokes.' }).waitFor();
      assert.match(await page.locator(`#pad-status-${key}`).textContent(), /^50 strokes drawn \(\d+ of at most 7500 points\)\.$/);
    }

    const previews = { sig_a: await previewStrokes(page, 'sig_a'), sig_b: await previewStrokes(page, 'sig_b') };
    let total = 0;
    for (const [key, strokes] of Object.entries(previews)) {
      assert.equal(strokes.length, 50, `${key} keeps 50 strokes (the 51st was refused)`);
      const points = countPoints(strokes);
      assert.ok(points > 1000 && points <= 7500, `${key} uses its budget and stays within 7,500 points`);
      assert.ok(strokes.every((stroke) => stroke.length >= 2 && stroke.length <= 1000), `${key} strokes have 2..1000 points`);
      assert.ok(strokes[0].length < 2500, `${key}: the long stroke was simplified`);
      total += points;
    }
    assert.ok(total <= MAX_POINTS_PER_APPROVAL);

    await page.getByRole('checkbox', { name: 'I have read the consent text above and I agree to it.' }).check();
    const answer = responseTo(page, world.origin, APPROVAL_PATH, 'POST');
    await page.getByRole('button', { name: 'Approve the document' }).click();
    const response = await answer;
    const raw = requests.find((request) => request.url === `${world.origin}${APPROVAL_PATH}`).body;
    const body = JSON.parse(raw);
    assert.deepEqual(
      body.field_values,
      state.fields.map((field) => (field.type === 'date' ? { key: field.key, type: 'date' } : { key: field.key, type: 'signature', mode: 'drawn', strokes: previews[field.key] })),
      'what was previewed is exactly what was submitted, one value per field in the order the session gives',
    );
    assert.deepEqual(state.fields.map((field) => field.key).sort(), ['date_a', 'sig_a', 'sig_b']);
    assert.ok(Buffer.byteLength(raw, 'utf8') < JSON_BODY_LIMIT, 'the body is under 256 KiB');
    assert.equal(response.status(), 200, 'the server accepts the maximal capture');
    await step(page, 'approved');
  } finally {
    await close();
  }
});
