// SPDX-License-Identifier: Apache-2.0
//
// Compose tests (T036 follow-up; requests #44 and #45, rows SIZE-BOUND, T036-NUMRANGE
// and T036-FIXES): the sealed-PDF bound, its module's import closure and restated
// constants, the upload predicate's domination of the composer (CP-01), the bound as
// the composer's invariant, and the predicate's report-only refusals, which the
// composer makes with the same details (CP-08).

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import * as bounds from '../../src/cryptograph/compose/bounds.ts';
import { checkRequest, composeFromReport } from '../../src/cryptograph/compose/compose.ts';
import * as compose from '../../src/cryptograph/compose/index.ts';
import { MAX_FIELD_VALUES } from '../../src/domain/approval/values.ts';
import { DEFAULT_PARSER_LIMITS, MAX_DOCUMENT_BYTES, reportBudget } from '../../src/pdf/limits.ts';
import { parsePdf } from '../../src/pdf/service.ts';
import {
  adversarialDocument,
  approval,
  COMPOSE_SOURCES,
  composeRequest,
  drawn,
  field,
  fixture,
  formDocument,
  largestCertificate,
  maximalRequest,
  numberDocument,
  plainDocument,
  RECIPIENT_1,
  sharedAnnotsDocument,
  ZIGZAG,
} from './support.mjs';

const { ComposeError, estimateSealedSize, MAX_SEALED_PDF_BYTES, withinSealedBound } = compose;

const reportOf = async (bytes) => {
  const outcome = await parsePdf(bytes);
  assert.ok(outcome.ok, `the base parses: ${outcome.ok ? '' : outcome.reason}`);
  return outcome.report;
};

test('[CP-01] bounds.ts imports nothing, restates its two foreign constants exactly, states 48 MiB and its derived bounds, and the public surface re-exports them', () => {
  const code = readFileSync(join(COMPOSE_SOURCES, 'bounds.ts'), 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '');
  assert.doesNotMatch(code, /\bimport\b|\brequire\s*\(|\bexport\s+\*\s+from\b|\bfrom\s+['"]/, 'the import closure of bounds.ts is bounds.ts alone');
  assert.equal(bounds.MAX_FIELD_VALUES, MAX_FIELD_VALUES, 'restated from src/domain/approval/values.ts');
  assert.equal(bounds.MAX_DOCUMENT_BYTES, MAX_DOCUMENT_BYTES, 'restated from src/pdf/limits.ts');
  assert.equal(bounds.REPORT_BYTE_BUDGET, reportBudget(DEFAULT_PARSER_LIMITS).bytes);
  assert.equal(bounds.MAX_SEALED_PDF_BYTES, 50_331_648);
  assert.equal(bounds.UPDATE_BOUND, bounds.UPDATE_REQUEST_BOUND + 65 * bounds.REPORT_BYTE_BUDGET + 22 * bounds.REWRITE_OVERHEAD_BYTES);
  assert.deepEqual([...bounds.SEAL_REFUSAL_DETAILS], ['composition_too_large', 'number_range', 'dangling_form_reference', 'annots_shape', 'acroform_shape']);
  for (const name of ['MAX_SEALED_PDF_BYTES', 'UPDATE_BOUND', 'UPDATE_REQUEST_BOUND', 'SEAL_REFUSAL_DETAILS', 'estimateSealedSize', 'withinSealedBound']) {
    assert.equal(compose[name], bounds[name], `index.ts re-exports ${name}`);
  }
  assert.equal(typeof compose.byteRangeText, 'function', 'index.ts exports byteRangeText');
  assert.equal(compose.byteRangeText(1, 2, 3).length, compose.BYTE_RANGE_WIDTH);
  assert.equal(withinSealedBound(MAX_SEALED_PDF_BYTES), true, 'a composition of exactly the bound is allowed');
  assert.equal(withinSealedBound(MAX_SEALED_PDF_BYTES + 1), false, 'one byte more is not');
  for (const bad of [-1, 1.5, Number.NaN]) assert.equal(withinSealedBound(bad), false);
});

test('[CP-01] for every base, the predicate worst case is at least what the largest request composes', async () => {
  const bases = [
    ['single-page', fixture('single-page.pdf'), 1],
    ['xref-stream', fixture('agreement-xref-stream.pdf'), 3],
    ['rotated', fixture('rotated-pages.pdf'), 5],
    ['form, indirect arrays', formDocument({ form: 'indirect', fields: 'indirect', annots: 'indirect' }), 1],
    ['form, inline', formDocument({ form: 'inline', fields: 'inline', annots: 'inline' }), 1],
    ['shared /Annots', sharedAnnotsDocument(), 2],
    ['ceiling page', plainDocument({ page: '/MediaBox [-1000000 -1000000 1000000 1000000]' }), 1],
  ];
  const certificateDer = largestCertificate();
  for (const [name, base, pages] of bases) {
    const report = await reportOf(base);
    const estimate = estimateSealedSize(report);
    const revision = composeFromReport(checkRequest(maximalRequest(base, pages, { certificateDer })), report);
    assert.ok(estimate.worstCaseBytes >= revision.bytes.length, `${name}: ${estimate.worstCaseBytes} >= ${revision.bytes.length}`);
    assert.equal(estimate.exceedsBound, false, `${name} is sealable`);
    assert.deepEqual(estimate.refusals, [], `${name}: no refusal`);
  }
});

test('[CP-01] an adversarial shared-array base has a worst case above 48 MiB, and the composer refuses it as an invariant', async () => {
  const started = performance.now();
  // Catalog 1, AcroForm 4, the shared array 5 (its /Fields and every page's /Annots), pages 6..25.
  const base = adversarialDocument(1_000_000);
  const report = await reportOf(base);
  const estimate = estimateSealedSize(report);
  assert.ok(estimate.exceedsBound, `the worst case ${estimate.worstCaseBytes} is above ${MAX_SEALED_PDF_BYTES}: T034 refuses it at upload`);
  const counted = [1, 4, 5, ...Array.from({ length: 20 }, (_, i) => 6 + i)].map((num) => [num, 0]);
  assert.deepEqual(estimate.refusals, [{ detail: 'composition_too_large', refs: counted }], 'the objects the worst case counts, by reference only');
  assert.throws(
    () => composeFromReport(checkRequest(maximalRequest(base, 20, { certificateDer: largestCertificate() })), report),
    (error) =>
      error instanceof ComposeError &&
      error.status === 422 &&
      error.code === 'unsupported_pdf' &&
      error.reason === 'composition-too-large' &&
      error.detail === 'composition_too_large' &&
      error.retryable === false,
  );
  // A diagnostic only, never a pass criterion: the case's cost on this bench.
  console.log(`adversarial case: base ${base.length} bytes, worst case ${estimate.worstCaseBytes}, ${Math.round(performance.now() - started)} ms`);
});

test('[CP-08] the predicate names, by object reference only, every object the composer may write an exponent-form number from', async () => {
  // numberDocument: catalog 1, page 2 is object 4, its /Annots array 6, Info 8 (never reported).
  const cases = [
    [{ page2: '0.0000001' }, [[4, 0]]],
    [{ catalog: '0.0000001' }, [[1, 0]]],
    [{ annots: '0.0000001' }, [[6, 0]]],
    [{ catalog: '0.0000001', page2: '0.0000001', annots: '0.0000001' }, [[1, 0], [4, 0], [6, 0]]],
    [{ info: '0.0000001' }, null],
    [{ page2: '0.000001', catalog: '0.000001', annots: '0.000001' }, null],
  ];
  for (const [numbers, refs] of cases) {
    const estimate = estimateSealedSize(await reportOf(numberDocument(numbers)));
    assert.deepEqual(estimate.refusals, refs === null ? [] : [{ detail: 'number_range', refs }], JSON.stringify(numbers));
    assert.equal(estimate.exceedsBound, false);
  }
  // A catalog the composer does not rewrite (the AcroForm is indirect) is not a finding, nor
  // is the /SigFlags value it replaces; formDocument: catalog 1, AcroForm 8, page 3.
  const form = formDocument({ form: 'indirect', fields: 'inline', annots: 'inline' });
  const report = structuredClone(await reportOf(form));
  report.objects['1'].value.dict.X = 1e-7;
  report.objects['8'].value.dict.SigFlags = 1e-7;
  assert.deepEqual(estimateSealedSize(report).refusals, []);
  report.objects['8'].value.dict.X = 1e-7;
  assert.deepEqual(estimateSealedSize(report).refusals, [{ detail: 'number_range', refs: [[8, 0]] }]);
});

test('[CP-08] the predicate reports every refusal the composer could make from the report alone, by object reference only, and the composer makes the same one', async () => {
  const rect = { x: 0.1, y: 0.7, width: 0.35, height: 0.08 };
  const request = (document) => checkRequest(composeRequest(document, [field('sig_1', 1, rect)], [approval(RECIPIENT_1, [drawn('sig_1', ZIGZAG)])]));
  const same = (detail) => (error) =>
    error instanceof ComposeError && error.status === 422 && error.code === 'unsupported_pdf' && error.detail === detail && error.retryable === false;

  // Through the parse service; plainDocument is catalog 1 and page 3.
  const parsed = [
    ['dangling_form_reference', plainDocument({ catalog: '/AcroForm << /Fields 97 0 R >>' }), [[1, 0]]],
    ['dangling_form_reference', plainDocument({ page: '/Annots 98 0 R' }), [[3, 0]]],
    ['number_range', plainDocument({ page: '/X 0.0000001' }), [[3, 0]]],
  ];
  for (const [detail, document, refs] of parsed) {
    const report = await reportOf(document);
    assert.deepEqual(estimateSealedSize(report).refusals, [{ detail, refs }], `${detail} ${JSON.stringify(refs)}`);
    assert.throws(() => composeFromReport(request(document), report), same(detail), `${detail} ${JSON.stringify(refs)}`);
  }

  // Shapes, from an edited honest report.
  const base = plainDocument();
  const honest = await reportOf(base);
  const catalog = (r) => r.objects['1'].value.dict;
  const page = (r) => r.objects['3'].value.dict;
  const edited = [
    ['annots_shape', (r) => (page(r).Annots = { name: 'NotAnArray' }), [[3, 0]]],
    [
      'annots_shape',
      (r) => {
        r.objects['5'] = { gen: 0, value: { dict: {} } };
        page(r).Annots = { ref: [5, 0] };
      },
      [[3, 0]],
    ],
    ['acroform_shape', (r) => (catalog(r).AcroForm = [1, 2]), [[1, 0]]],
    ['acroform_shape', (r) => (catalog(r).AcroForm = { dict: { Fields: { name: 'NotAnArray' } } }), [[1, 0]]],
    ['acroform_shape', (r) => (catalog(r).AcroForm = { ref: [3, 0] }), [[3, 0]]],
    ['dangling_form_reference', (r) => (catalog(r).AcroForm = { ref: [5, 0] }), [[1, 0]]],
  ];
  for (const [detail, mutate, refs] of edited) {
    const report = structuredClone(honest);
    mutate(report);
    assert.deepEqual(estimateSealedSize(report).refusals, [{ detail, refs }], `${detail} ${JSON.stringify(refs)}`);
    assert.throws(() => composeFromReport(request(base), report), same(detail), `${detail} ${JSON.stringify(refs)}`);
  }

  // Several at once, in SEAL_REFUSAL_DETAILS order, each kind once.
  const both = await reportOf(plainDocument({ catalog: '/X 0.0000001', page: '/Annots 98 0 R' }));
  assert.deepEqual(estimateSealedSize(both).refusals, [
    { detail: 'number_range', refs: [[1, 0]] },
    { detail: 'dangling_form_reference', refs: [[3, 0]] },
  ]);
});
