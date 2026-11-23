// SPDX-License-Identifier: Apache-2.0
//
// Compose tests (T036 follow-up, commit 3; row T036-RESIDUAL, request #46): the residual
// ways an upload-accepted document could strand after approval. Every case goes through
// the actual parse service, with synthetic PDFs built at runtime.
// - A key named __proto__ is data: the predicate examines it like any other key.
// - xref_size, page_box and name_character: the predicate reports them, and the composer
//   refuses with the same 422 detail, not retryable. The predicate and the composer agree
//   on all eight details, which the predicate lists in one fixed order.
// - The composer's check of where the base's last cross-reference section starts accepts
//   exactly the layouts T033's parser accepts.
// - The field-placement rule exported for T007 is the function the composer itself uses.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import * as appearance from '../../src/cryptograph/compose/appearance.ts';
import * as bounds from '../../src/cryptograph/compose/bounds.ts';
import * as compose from '../../src/cryptograph/compose/index.ts';
import { sectionStartsAt, tailStartxref } from '../../src/cryptograph/compose/report.ts';
import { parsePdf } from '../../src/pdf/service.ts';
import {
  adversarialDocument,
  approval,
  classicDocument,
  COMPOSE_SOURCES,
  composeRequest,
  drawn,
  field,
  fixture,
  lastSection,
  maximalRequest,
  numberList,
  plainBodies,
  plainDocument,
  RECIPIENT_1,
  roundTripReason,
  sectionObjects,
  twoPageDocument,
  xrefStreamDocument,
  ZIGZAG,
} from './support.mjs';

const { ComposeError, composeSealRevision, estimateSealedSize } = compose;

const reportOf = async (bytes, what = 'the base') => {
  const outcome = await parsePdf(bytes);
  assert.ok(outcome.ok, `${what} parses: ${outcome.ok ? '' : `${outcome.reason} ${outcome.detail}`}`);
  return outcome.report;
};
const RECT = { x: 0.1, y: 0.7, width: 0.35, height: 0.08 };
/** One drawn signature on page `page`: no typed value, so no font object. */
const onPage = (document, page = 1) => composeRequest(document, [field('sig_1', page, RECT)], [approval(RECIPIENT_1, [drawn('sig_1', ZIGZAG)])]);
const refusedWith = (detail) => (error) =>
  error instanceof ComposeError && error.status === 422 && error.code === 'unsupported_pdf' && error.detail === detail && error.retryable === false;
/** The predicate gives exactly `[{ detail, refs }]` and the composer refuses `request` with that detail. */
async function agree(document, request, detail, refs, what) {
  const report = await reportOf(document, what);
  assert.deepEqual(estimateSealedSize(report).refusals, [{ detail, refs }], `${what}: predicate`);
  await assert.rejects(composeSealRevision(request), refusedWith(detail), `${what}: composer`);
}
/** The predicate finds nothing and the composer composes `request`. */
async function sealable(document, request, what) {
  const report = await reportOf(document, what);
  assert.deepEqual(estimateSealedSize(report).refusals, [], `${what}: predicate`);
  const revision = await composeSealRevision(request);
  assert.ok(revision.bytes.length > document.length, `${what}: composer`);
  return revision;
}

test('[CP-08] a key named __proto__ is data: the parser keeps it, the predicate examines it, and an exponent number under it is number_range', async () => {
  // plainDocument: catalog 1, page 3.
  const page = plainDocument({ page: '/__proto__ 0.0000001' });
  const report = await reportOf(page);
  assert.ok(Object.hasOwn(report.objects['3'].value.dict, '__proto__'), 'the parser keeps the key as an own key');
  await agree(page, onPage(page), 'number_range', [[3, 0]], 'a page');
  // An inline AcroForm, whose dictionary the composer copies into the catalog.
  const form = plainDocument({ catalog: '/AcroForm << /Fields [] /__proto__ 0.0000001 >>' });
  await agree(form, onPage(form), 'number_range', [[1, 0]], 'an inline AcroForm');
  // An indirect AcroForm (6), rewritten in place.
  const indirect = classicDocument([...plainBodies({ catalog: '/AcroForm 6 0 R' }), '<< /Fields [] /__proto__ 0.0000001 >>']);
  await agree(indirect, onPage(indirect), 'number_range', [[6, 0]], 'an indirect AcroForm');
  // A NUL under the same key is name_character, and a plain value under it composes and is written.
  const nul = plainDocument({ page: '/__proto__ /A#00B' });
  await agree(nul, onPage(nul), 'name_character', [[3, 0]], 'a NUL under __proto__');
  const plain = plainDocument({ page: '/__proto__ 7' });
  const revision = await sealable(plain, onPage(plain), 'a plain value');
  assert.match(sectionObjects(revision.bytes, lastSection(revision.bytes)).get(3), /\/__proto__ 7\b/, 'the key is written as data');
});

test('[CP-08] xref_size: the predicate refuses where the new objects would pass object number 8,388,607, exactly where the composer does', async () => {
  // A classic base without a form: the largest request adds 44 objects (a font, 20 appearance
  // and widget pairs, the seal field, the signature and a new AcroForm), numbered from /Size.
  const last = plainDocument({ size: 8_388_564 });
  const revision = await sealable(last, maximalRequest(last, 1), '/Size 8,388,564');
  assert.equal(lastSection(revision.bytes).size, 8_388_608, 'the last new object is 8,388,607');
  const over = plainDocument({ size: 8_388_565 });
  await agree(over, maximalRequest(over, 1), 'xref_size', [], '/Size 8,388,565');
  // The predicate covers every request: a smaller one may still fit.
  assert.ok((await composeSealRevision(onPage(over))).bytes.length > over.length, 'five new objects fit');
  // A /Size past the limit itself.
  const huge = plainDocument({ size: 9_000_000 });
  await agree(huge, onPage(huge), 'xref_size', [], '/Size 9,000,000');
});

test('[CP-08] page_box: a coordinate above 1,000,000 or a side under one centipoint, on any page, is reported, and the composer refuses it whichever page gets the widget', async () => {
  // twoPageDocument: pages 3 and 6; the widget is always on page 1 (object 3).
  const refused = [
    ['/MediaBox [0 0 1000000.5 792]', 'a coordinate above 1,000,000'],
    ['/MediaBox [-1000000.5 0 612 792]', 'a coordinate below -1,000,000'],
    ['/MediaBox [0 0 0.004 792]', 'a width under one centipoint'],
    ['/MediaBox [0 0 612 0.004]', 'a height under one centipoint'],
  ];
  for (const [box, what] of refused) {
    const document = twoPageDocument({ page2: box });
    await agree(document, onPage(document, 1), 'page_box', [[6, 0]], what);
  }
  // The limits themselves are allowed.
  for (const [box, what] of [
    ['/MediaBox [-1000000 -1000000 1000000 1000000]', '+-1,000,000'],
    ['/MediaBox [0 0 0.005 792]', 'one centipoint after rounding'],
  ]) {
    const document = twoPageDocument({ page2: box });
    await sealable(document, onPage(document, 1), what);
  }
});

test('[CP-08] name_character: a NUL in a name or a key of a reported object is reported, and the composer refuses it; one in an object the report does not carry never matters', async () => {
  const name = twoPageDocument({ page2: '/X /A#00B' });
  await agree(name, onPage(name, 1), 'name_character', [[6, 0]], 'a name on a page without a widget');
  const key = plainDocument({ catalog: '/K#00 1' });
  await agree(key, onPage(key), 'name_character', [[1, 0]], 'a key in the catalog');
  const nested = plainDocument({ page: '/X << /Y [/Z#00] >>' });
  await agree(nested, onPage(nested), 'name_character', [[3, 0]], 'a nested name');
  // The font (object 4) is not reported.
  const unreported = plainDocument({ font: '/X /A#00B' });
  await sealable(unreported, onPage(unreported), 'an unreported object');
});

test('[CP-08] the predicate and the composer agree on all eight details, which the predicate lists in one fixed order', async () => {
  assert.deepEqual(
    [...compose.SEAL_REFUSAL_DETAILS],
    ['composition_too_large', 'number_range', 'dangling_form_reference', 'annots_shape', 'acroform_shape', 'xref_size', 'page_box', 'name_character'],
  );
  const annots = classicDocument([...plainBodies({ page: '/Annots 6 0 R' }), '<< /X 1 >>']);
  const pageForm = plainDocument({ catalog: '/AcroForm 3 0 R' });
  const cases = [
    ['composition_too_large', adversarialDocument(1_000_000), (document) => maximalRequest(document, 20)],
    ['number_range', plainDocument({ page: '/X 0.0000001' }), onPage],
    ['dangling_form_reference', plainDocument({ page: '/Annots 98 0 R' }), onPage],
    ['annots_shape', annots, onPage],
    ['acroform_shape', plainDocument({ catalog: '/AcroForm [1 2]' }), onPage],
    ['acroform_shape', plainDocument({ catalog: '/AcroForm << /Fields 5 >>' }), onPage],
    ['acroform_shape', pageForm, onPage],
    ['xref_size', plainDocument({ size: 9_000_000 }), onPage],
    ['page_box', twoPageDocument({ page2: '/MediaBox [0 0 1000001 792]' }), onPage],
    ['name_character', plainDocument({ page: '/X /A#00' }), onPage],
  ];
  for (const [detail, document, request] of cases) {
    const report = await reportOf(document, detail);
    const refusals = estimateSealedSize(report).refusals;
    assert.deepEqual(
      refusals.map((refusal) => refusal.detail),
      [detail],
      `${detail}: the predicate's only refusal`,
    );
    assert.ok(refusals[0].refs.every((ref) => Array.isArray(ref) && ref.length === 2 && ref.every(Number.isSafeInteger)), `${detail}: references only`);
    await assert.rejects(composeSealRevision(request(document)), refusedWith(detail), `${detail}: the composer`);
  }
  // Several at once: each kind once, in that order.
  const several = plainDocument({ catalog: '/K#00 1 /X 0.0000001', page: '/Annots 98 0 R /MediaBox [0 0 1000001 792]', size: 9_000_000 });
  assert.deepEqual(estimateSealedSize(await reportOf(several, 'several')).refusals, [
    { detail: 'number_range', refs: [[1, 0]] },
    { detail: 'dangling_form_reference', refs: [[3, 0]] },
    { detail: 'xref_size', refs: [] },
    { detail: 'page_box', refs: [[3, 0]] },
    { detail: 'name_character', refs: [[1, 0]] },
  ]);
});

test('[CP-01] the base\'s last cross-reference section may start in every layout T033\'s parser accepts, and in none it refuses', async () => {
  const bodies = plainBodies();
  // Layouts T033 accepts (Parser.readChain, readIndirect; Lexer.atKeyword, skipWhitespace, readUnsigned).
  const accepted = [
    ['a table with a comment after xref', classicDocument(bodies, { head: 'xref%c\n' }), 'table'],
    ['a form feed after xref', classicDocument(bodies, { head: 'xref\f' }), 'table'],
    ['whitespace before a stream header', xrefStreamDocument(bodies, { lead: '\n \t\f\x00\r\n' }), 'stream'],
    ['a comment before a stream header', xrefStreamDocument(bodies, { lead: '%c\r' }), 'stream'],
    ['leading zeros', xrefStreamDocument(bodies, { head: (num) => `00${num} 00 obj` }), 'stream'],
    ['fifteen digits', xrefStreamDocument(bodies, { head: (num) => `${String(num).padStart(15, '0')} ${'0'.repeat(15)} obj` }), 'stream'],
    ['a six-digit generation', xrefStreamDocument(bodies, { head: (num) => `${num} 000000 obj` }), 'stream'],
    ['comments between the parts', xrefStreamDocument(bodies, { head: (num) => `${num}%a\n0%b\nobj` }), 'stream'],
    ['a delimiter after obj', xrefStreamDocument(bodies, { head: (num) => `${num} 0 obj%c` }), 'stream'],
  ];
  for (const [what, document, kind] of accepted) {
    const report = await reportOf(document, what);
    assert.equal(report.xref.kind, kind, what);
    assert.equal(sectionStartsAt(document, report.xref.startxref, kind), true, `${what}: the composer's check`);
    const revision = await composeSealRevision(onPage(document));
    assert.equal(roundTripReason(await parsePdf(revision.bytes)), '422 already-signed', `${what}: round trip`);
  }
  // Layouts T033 refuses: the composer's check refuses them too, as either kind.
  const refused = [
    ['whitespace before xref', classicDocument(bodies, { lead: ' ' })],
    ['a regular byte after xref', classicDocument(bodies, { head: 'xrefs\n' })],
    ['sixteen digits', xrefStreamDocument(bodies, { head: (num) => `${String(num).padStart(16, '0')} 0 obj` })],
    ['a sixteen-digit generation', xrefStreamDocument(bodies, { head: (num) => `${num} ${'0'.repeat(16)} obj` })],
    ['a regular byte after obj', xrefStreamDocument(bodies, { head: (num) => `${num} 0 objx` })],
    ['no generation', xrefStreamDocument(bodies, { head: (num) => `${num} obj` })],
    ['a sign', xrefStreamDocument(bodies, { head: (num) => `+${num} 0 obj` })],
  ];
  for (const [what, document] of refused) {
    const outcome = await parsePdf(document);
    assert.equal(outcome.ok, false, `${what}: T033 refuses it`);
    const at = tailStartxref(document);
    assert.ok(at !== null, what);
    assert.equal(sectionStartsAt(document, at, 'table'), false, `${what}: not a table`);
    assert.equal(sectionStartsAt(document, at, 'stream'), false, `${what}: not a stream`);
  }
});

test('[CP-03] the field-placement rule exported for T007 is the composer\'s own pure function, over the page geometry the parse report gives', async () => {
  assert.equal(compose.placeField, appearance.placeField, 'index.ts exports the function appearance.ts defines');
  assert.equal(compose.centipointBox, bounds.centipointBox, 'and the page-box conversion bounds.ts defines');
  const strip = (file) =>
    readFileSync(join(COMPOSE_SOURCES, file), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/.*$/gm, '');
  const composeSource = strip('compose.ts');
  assert.match(composeSource, /import \{[^}]*\bplaceField\b[^}]*\} from '\.\/appearance\.ts'/, 'compose.ts imports it');
  assert.match(composeSource, /\bplaceField\(page, field\.rect\)/, 'and calls it for every field');
  assert.doesNotMatch(composeSource, /function placeField\b|const placeField\b/, 'with no local copy');
  const reportSource = strip('report.ts');
  assert.match(reportSource, /import \{[^}]*\bcentipointBox\b[^}]*\} from '\.\/bounds\.ts'/, 'report.ts imports the conversion');
  assert.match(reportSource, /\bcentipointBox\(media\)/, 'and gives every page its box with it');

  // Through the parse service: T007's call over the report's page geometry predicts the composer exactly.
  const base = fixture('rotated-pages.pdf');
  const report = await reportOf(base);
  const rects = [
    { x: 0.1, y: 0.2, width: 0.3, height: 0.1 },
    { x: 0.5, y: 0.6, width: 1 / 61_200, height: 0.05 },
    { x: 0.5, y: 0.6, width: 0.000001, height: 0.05 },
    { x: 0, y: 0.9, width: 0.999999, height: 0.000001 },
  ];
  for (const page of report.pages) {
    for (const rect of rects) {
      const placement = compose.placeField({ rotate: page.rotate, box: compose.centipointBox(page.media_box) }, rect);
      const request = composeRequest(base, [field('sig_1', page.number, rect)], [approval(RECIPIENT_1, [drawn('sig_1', ZIGZAG)])]);
      const what = `page ${page.number}, ${JSON.stringify(rect)}`;
      if (placement === null) {
        await assert.rejects(composeSealRevision(request), (error) => error instanceof ComposeError && error.status === 400 && error.details[0].code === 'field_too_small', what);
      } else {
        const revision = await composeSealRevision(request);
        const widget = sectionObjects(revision.bytes, lastSection(revision.bytes)).get(revision.objects.widgets[0]);
        assert.deepEqual(numberList(widget, 'Rect'), placement.rect.map((value) => value / 100), what);
      }
    }
  }
});
