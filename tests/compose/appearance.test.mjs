// SPDX-License-Identifier: Apache-2.0
//
// Compose tests (T036): rotation-correct placement (CP-03), appearance streams
// in non-embedded Helvetica with WinAnsiEncoding and as vector paths, with 422
// unsupported_characters (CP-04), and exact fixed-point stroke rendering
// (contract 0.2.3, CP-09).
//
// Expected placements come from the T004 manifest's page geometry and a
// trigonometric model of /Rotate (the page turned clockwise by r degrees when
// displayed), not from the composer's case table. Expected stroke operands are
// computed with BigInt from the appearance's own /BBox.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { checkRequest } from '../../src/cryptograph/compose/compose.ts';
import { ComposeError, composeSealRevision } from '../../src/cryptograph/compose/index.ts';
import { parsePdf } from '../../src/pdf/service.ts';
import {
  approval,
  composeRequest,
  dated,
  DOCUMENTS,
  drawn,
  exactDecimal,
  field,
  fixture,
  lastSection,
  literalOf,
  micro,
  numberList,
  RECIPIENT_1,
  refOf,
  sectionObjects,
  typed,
  ZIGZAG,
} from './support.mjs';

const MANIFEST = JSON.parse(readFileSync(join(DOCUMENTS, 'manifest.json'), 'utf8'));
const geometryOf = (file) => MANIFEST.documents.find((doc) => doc.file === file).pages;

/** The content of a stream object's text. */
const contentOf = (text) => /stream\r?\n([\s\S]*?)\r?\nendstream/.exec(text)[1];

/** The user-space rectangle of a normalized field on a page, by rotating the page model. */
function expectedRect(page, rect) {
  const [llx, lly, urx, ury] = page.media_box;
  const r = (page.rotate * Math.PI) / 180;
  const turn = ([x, y]) => [x * Math.cos(r) + y * Math.sin(r), -x * Math.sin(r) + y * Math.cos(r)];
  const unturn = ([x, y]) => [x * Math.cos(r) - y * Math.sin(r), x * Math.sin(r) + y * Math.cos(r)];
  const corners = [
    [llx, lly],
    [urx, lly],
    [urx, ury],
    [llx, ury],
  ].map(turn);
  const minX = Math.min(...corners.map((c) => c[0]));
  const minY = Math.min(...corners.map((c) => c[1]));
  const width = Math.max(...corners.map((c) => c[0])) - minX;
  const height = Math.max(...corners.map((c) => c[1])) - minY;
  const toUser = (dx, dy) => unturn([dx + minX, height - dy + minY]);
  const points = [
    [rect.x, rect.y],
    [rect.x + rect.width, rect.y],
    [rect.x, rect.y + rect.height],
    [rect.x + rect.width, rect.y + rect.height],
  ].map(([fx, fy]) => toUser(fx * width, fy * height));
  return {
    rect: [Math.min(...points.map((p) => p[0])), Math.min(...points.map((p) => p[1])), Math.max(...points.map((p) => p[0])), Math.max(...points.map((p) => p[1]))],
    shown: [rect.width * width, rect.height * height],
    turn,
  };
}

const near = (actual, expected, what, tolerance = 0.011) => assert.ok(Math.abs(actual - expected) <= tolerance, `${what}: ${actual} is not within ${tolerance} of ${expected}`);

/**
 * The one-em-per-character fit, read from a text appearance and checked exactly in
 * micropoints: count x size <= BBox width - 2 x the left offset, size > 0, and the line
 * between the bottom and the top of the BBox.
 */
function assertFits(appearance, count) {
  const content = contentOf(appearance);
  const size = micro(/\/Helv (\S+) Tf/.exec(content)[1]);
  const [x, y] = /^(\S+) (\S+) Td$/m.exec(content).slice(1, 3).map(micro);
  const box = /\/BBox \[0 0 (\S+) (\S+)\]/.exec(appearance);
  const width = micro(box[1]);
  const height = micro(box[2]);
  assert.ok(size > 0n, 'the size is above zero');
  assert.ok(BigInt(count) * size <= width - 2n * x, `${count} x ${size} fits ${width} - 2 x ${x} micropoints`);
  assert.ok(y >= 0n && y + size <= height, 'the line fits the height');
}

test('[CP-03] widgets land on the displayed rectangle for /Rotate 0, 90, 180 and 270, including a non-zero MediaBox origin, with upright appearances', async () => {
  const base = fixture('rotated-pages.pdf');
  const pages = geometryOf('rotated-pages.pdf');
  assert.deepEqual(
    pages.map((page) => page.rotate),
    [90, 270, 180, 0, 270],
  );
  const parsed = await parsePdf(base);
  assert.ok(parsed.ok);
  const rect = { x: 0.1, y: 0.2, width: 0.3, height: 0.1 };
  const fields = pages.map((page) => field(`sig_p${page.number}`, page.number, rect));
  const values = pages.map((page) => drawn(`sig_p${page.number}`, ZIGZAG));
  const revision = await composeSealRevision(composeRequest(base, fields, [approval(RECIPIENT_1, values)]));
  const objects = sectionObjects(revision.bytes, lastSection(revision.bytes));

  pages.forEach((page, index) => {
    const widget = objects.get(revision.objects.widgets[index]);
    const appearance = objects.get(revision.objects.appearances[index]);
    const expected = expectedRect(page, rect);
    const placed = numberList(widget, 'Rect');
    placed.forEach((value, at) => near(value, expected.rect[at], `page ${page.number} /Rect[${at}]`));
    assert.equal(refOf(widget, 'P'), parsed.report.pages[index].ref[0], `page ${page.number}: /P`);
    assert.match(widget, new RegExp(`/MK << /R ${page.rotate} >>`));

    const box = numberList(appearance, 'BBox');
    assert.deepEqual(box.slice(0, 2), [0, 0]);
    near(box[2], expected.shown[0], `page ${page.number} BBox width`);
    near(box[3], expected.shown[1], `page ${page.number} BBox height`);
    // The appearance's axes, turned with the page, point right and up on the display.
    const [a, b, c, d] = numberList(appearance, 'Matrix');
    const right = expected.turn([a, b]);
    const up = expected.turn([c, d]);
    near(right[0], 1, `page ${page.number} form x-axis`, 1e-9);
    near(right[1], 0, `page ${page.number} form x-axis`, 1e-9);
    near(up[0], 0, `page ${page.number} form y-axis`, 1e-9);
    near(up[1], 1, `page ${page.number} form y-axis`, 1e-9);
  });
});

test('[CP-04] typed text and dates use non-embedded Helvetica with WinAnsi bytes in hex strings; drawn values are vector paths only', async () => {
  const base = fixture('single-page.pdf');
  const name = 'Zoë Ångström – €Œ';
  // WinAnsiEncoding (ISO 32000-1, Annex D.2): e-diaeresis EB, A-ring C5, o-diaeresis F6,
  // en dash 96, euro 80, OE 8C; ASCII as itself.
  const expectedName = Buffer.from([0x5a, 0x6f, 0xeb, 0x20, 0xc5, 0x6e, 0x67, 0x73, 0x74, 0x72, 0xf6, 0x6d, 0x20, 0x96, 0x20, 0x80, 0x8c]).toString('hex').toUpperCase();
  const request = composeRequest(
    base,
    [
      field('sig_1', 1, { x: 0.1, y: 0.6, width: 0.4, height: 0.06 }),
      field('sig_2', 1, { x: 0.1, y: 0.7, width: 0.4, height: 0.08 }),
      field('date_1', 1, { x: 0.6, y: 0.6, width: 0.25, height: 0.04 }, { type: 'date' }),
    ],
    [approval(RECIPIENT_1, [typed('sig_1', name), drawn('sig_2', ZIGZAG), dated('date_1')], [{ key: 'date_1', value: '2026-11-18' }])],
  );
  const revision = await composeSealRevision(request);
  const objects = sectionObjects(revision.bytes, lastSection(revision.bytes));
  const [typedAp, drawnAp, dateAp] = revision.objects.appearances.map((num) => objects.get(num));

  for (const text of [typedAp, drawnAp, dateAp]) assert.match(text, /\/Type \/XObject \/Subtype \/Form/);
  const fontNum = Number(/\/Font << \/Helv (\d+) 0 R >>/.exec(typedAp)[1]);
  assert.equal(fontNum, revision.objects.font);
  assert.equal(Number(/\/Font << \/Helv (\d+) 0 R >>/.exec(dateAp)[1]), fontNum, 'one shared font');
  const font = objects.get(fontNum);
  assert.match(font, /\/Subtype \/Type1/);
  assert.match(font, /\/BaseFont \/Helvetica\b/);
  assert.match(font, /\/Encoding \/WinAnsiEncoding/);
  assert.doesNotMatch(font, /FontFile|FontDescriptor|Widths/, 'nothing is embedded');

  const shows = (text, hex) => {
    const content = contentOf(text);
    assert.ok(content.includes(`<${hex}> Tj`), 'the text is a hex string of WinAnsi bytes');
    assert.equal((content.match(/ Tj$/gm) ?? []).length, 1, 'one line of text');
    assert.doesNotMatch(content, /\)\s*Tj/, 'no literal string');
    assertFits(text, hex.length / 2);
  };
  shows(typedAp, expectedName);
  shows(dateAp, Buffer.from('2026-11-18', 'latin1').toString('hex').toUpperCase());
  const widgets = revision.objects.widgets.map((num) => objects.get(num));
  assert.equal(literalOf(widgets[2], 'Contents'), 'Date from unsigned server time (UTC)', 'the date widget names its time source');
  assert.equal(literalOf(widgets[0], 'Contents'), null);

  const drawnContent = contentOf(drawnAp);
  assert.match(drawnAp, /\/Resources << >>/);
  for (const line of drawnContent.split('\n')) {
    const operator = line.trim().split(/\s+/).pop();
    assert.ok(['q', 'Q', 'G', 'J', 'j', 'w', 'm', 'l', 'S'].includes(operator), `path operators only: ${operator}`);
  }
  const update = Buffer.from(revision.bytes.subarray(revision.documentLength)).toString('latin1');
  assert.doesNotMatch(update, /\/Subtype \/Image|\bBI\b|\/FontFile/, 'no image and no embedded font in the update');
});

test('[CP-04] a typed character outside WinAnsiEncoding is refused with 422 unsupported_characters, after every 400 rule', async () => {
  const base = fixture('single-page.pdf');
  const rect = { x: 0.1, y: 0.7, width: 0.4, height: 0.06 };
  const refused = ['中文', 'tab\there', 'c1\u0081', 'gap\u008d', 'lone\ud800', 'emoji\u{1f600}', 'line\nbreak'];
  for (const text of refused) {
    await assert.rejects(composeSealRevision(composeRequest(base, [field('sig_1', 1, rect)], [approval(RECIPIENT_1, [typed('sig_1', text)])])), (error) => {
      assert.ok(error instanceof ComposeError);
      assert.equal(error.status, 422);
      assert.equal(error.code, 'unsupported_characters');
      assert.deepEqual(error.details, [{ field: 'approvals[0].field_values[0].text', code: 'unsupported_characters' }]);
      assert.equal(error.retryable, false);
      assert.ok(!error.message.includes(text), 'the message carries no value');
      return true;
    });
  }
  // The edges of the encoding compose: no-break space, soft hyphen, y-diaeresis, Y-diaeresis, small tilde.
  for (const text of ['A B', 'co­op', 'ÿ', 'Ÿ', '˜']) {
    assert.doesNotThrow(() => checkRequest(composeRequest(base, [field('sig_1', 1, rect)], [approval(RECIPIENT_1, [typed('sig_1', text)])])), text);
  }
  // A shape defect is judged first: an unknown field key gives 400 even beside an unsupported character.
  assert.throws(
    () => checkRequest(composeRequest(base, [field('sig_1', 1, rect)], [approval(RECIPIENT_1, [typed('sig_1', '中'), typed('ghost', 'x')])])),
    (error) => error instanceof ComposeError && error.status === 400 && error.details[0].code === 'unknown_field',
  );
});

test('[CP-04] text fits at one em per character in the narrowest valid field: 80 characters, and two characters, one centipoint wide', async () => {
  const base = fixture('single-page.pdf');
  // One centipoint on the 612-point page: x0 = round(0.5 x 61200) = 30600, x1 = 30601.
  const narrow = { x: 0.5, y: 0.6, width: 1 / 61200, height: 0.05 };
  const request = composeRequest(
    base,
    [field('sig_1', 1, narrow), field('sig_2', 1, { ...narrow, y: 0.7 })],
    [approval(RECIPIENT_1, [typed('sig_1', 'W'.repeat(80)), typed('sig_2', 'WW')])],
  );
  const revision = await composeSealRevision(request);
  const objects = sectionObjects(revision.bytes, lastSection(revision.bytes));
  revision.objects.appearances.forEach((num, index) => {
    const appearance = objects.get(num);
    assert.equal(numberList(appearance, 'BBox')[2], 0.01, 'the field is one centipoint wide');
    assertFits(appearance, index === 0 ? 80 : 2);
  });
});

test('[CP-09] drawn strokes render from integer fixed-point coordinates exactly: x/10000 of the field width and y/10000 of its height from the top-left', async () => {
  const base = fixture('single-page.pdf');
  const strokes = [
    [
      [0, 0],
      [10000, 10000],
    ],
    [
      [0, 10000],
      [10000, 0],
    ],
    [
      [1, 9999],
      [3333, 6667],
      [9999, 1],
    ],
    [
      [5000, 5000],
      [5000, 5000],
    ],
  ];
  const request = composeRequest(base, [field('sig_1', 1, { x: 0.1, y: 0.5, width: 0.2357, height: 0.0411 })], [approval(RECIPIENT_1, [drawn('sig_1', strokes)])]);
  const revision = await composeSealRevision(request);
  const appearance = sectionObjects(revision.bytes, lastSection(revision.bytes)).get(revision.objects.appearances[0]);
  const [, , boxWidth, boxHeight] = numberList(appearance, 'BBox');
  // The BBox is the field in points with at most two decimals: the field size in centipoints.
  const width = BigInt(Math.round(boxWidth * 100));
  const height = BigInt(Math.round(boxHeight * 100));
  assert.equal(exactDecimal(width, 2), String(boxWidth));
  assert.equal(exactDecimal(height, 2), String(boxHeight));

  const content = contentOf(appearance);
  const path = [...content.matchAll(/^(\S+) (\S+) ([ml])$/gm)].map((m) => [m[1], m[2], m[3]]);
  const expected = strokes.flatMap((stroke) =>
    stroke.map(([px, py], index) => [exactDecimal(BigInt(px) * width, 6), exactDecimal(BigInt(10000 - py) * height, 6), index === 0 ? 'm' : 'l']),
  );
  assert.deepEqual(path, expected, 'every operand is the exact fixed-point value');
  assert.deepEqual(path[0], ['0', String(boxHeight), 'm'], '(0, 0) is the top-left corner');
  assert.deepEqual(path[1], [String(boxWidth), '0', 'l'], '(10000, 10000) is the bottom-right corner');
  assert.equal((content.match(/^S$/gm) ?? []).length, strokes.length, 'one painted subpath per stroke');
  for (const [x, y] of path) for (const operand of [x, y]) assert.match(operand, /^\d+(\.\d{1,6})?$/, 'plain decimals, no exponent');
  const lineWidth = Number(/^(\S+) w$/m.exec(content)[1]);
  assert.ok(lineWidth >= 0.5 && lineWidth <= 2, 'the pen is 0.5 to 2 points wide');
});

test('[CP-09] coordinates outside the integer range 0..10000 and over-budget strokes are refused with 400 before anything renders', () => {
  const base = fixture('single-page.pdf');
  const rect = { x: 0.1, y: 0.5, width: 0.3, height: 0.06 };
  const one = (strokes) => composeRequest(base, [field('sig_1', 1, rect)], [approval(RECIPIENT_1, [drawn('sig_1', strokes)])]);
  const refusedWith = (request, code) =>
    assert.throws(
      () => checkRequest(request),
      (error) => error instanceof ComposeError && error.status === 400 && error.code === 'invalid_request' && error.details[0].code === code,
      code,
    );
  for (const bad of [10001, -1, 1.5, '5', null, Number.NaN]) {
    refusedWith(
      one([
        [
          [0, 0],
          [bad, 10],
        ],
      ]),
      'invalid_coordinate',
    );
  }
  refusedWith(one([[[0, 0]]]), 'invalid_count');
  refusedWith(one(Array.from({ length: 51 }, () => [[0, 0], [1, 1]])), 'invalid_count');
  refusedWith(one(Array.from({ length: 11 }, () => Array.from({ length: 1000 }, (_, i) => [i, i]))), 'point_budget');

  // The approval budget: 15000 points pass, 15001 do not (two values of one recipient).
  const two = (first, second) =>
    composeRequest(
      base,
      [field('sig_1', 1, rect), field('sig_2', 1, { ...rect, y: 0.7 })],
      [approval(RECIPIENT_1, [drawn('sig_1', first), drawn('sig_2', second)])],
    );
  const points = (count) => Array.from({ length: Math.ceil(count / 1000) }, (_, s) => Array.from({ length: Math.min(1000, count - s * 1000) }, (_, i) => [i, s]));
  assert.doesNotThrow(() => checkRequest(two(points(7500), points(7500))));
  refusedWith(two(points(7501), points(7500)), 'point_budget');
});
