// SPDX-License-Identifier: Apache-2.0
//
// Compose tests (T036): defensive refusal of a page whose effective CropBox
// differs from its MediaBox (A-008 S2, CP-07), and the parse-service boundary
// (A-009 LBR-3/LBR-4, CP-08): the composer passes parsePdf the document only and
// accepts no option, and it treats the parse report, above all its `objects`,
// `trailer` and page references, as untrusted input. Lying reports are built by
// editing an honest report from the real parse service.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { checkRequest, composeFromReport } from '../../src/cryptograph/compose/compose.ts';
import { ComposeError, composeSealRevision, fromParseOutcome } from '../../src/cryptograph/compose/index.ts';
import { parsePdf } from '../../src/pdf/service.ts';
import { approval, composeRequest, composeSources, field, fixture, lastSection, plainDocument, RECIPIENT_1, sectionObjects, simpleRequest, typed } from './support.mjs';

const honestReport = async (bytes) => {
  const outcome = await parsePdf(bytes);
  assert.ok(outcome.ok, 'the base parses');
  return outcome.report;
};

const reportInvalid = (detail) => (error) =>
  error instanceof ComposeError && error.status === 500 && error.code === 'internal' && error.reason === 'report-invalid' && error.detail === detail && error.retryable === false;

test('[CP-07] a report page whose CropBox differs from its MediaBox is refused with 422 cropbox_differs, whichever page it is', async () => {
  const base = fixture('agreement-multipage.pdf');
  const report = await honestReport(base);
  const request = checkRequest(simpleRequest(base, 1));
  assert.ok(composeFromReport(request, structuredClone(report)).bytes.length > base.length, 'the honest report composes');
  for (const index of [0, 2]) {
    const lying = structuredClone(report);
    lying.pages[index].crop_box = [0, 0, 600, 792];
    assert.throws(
      () => composeFromReport(request, lying),
      (error) =>
        error instanceof ComposeError &&
        error.status === 422 &&
        error.code === 'unsupported_pdf' &&
        error.reason === 'unsupported-feature' &&
        error.detail === 'cropbox_differs' &&
        error.details[0].field === `pages[${index + 1}]`,
      `page ${index + 1}`,
    );
  }
});

test('[CP-07] through the parse service a cropped page gives the same 422 detail, and a CropBox covering the whole MediaBox composes', async () => {
  await assert.rejects(
    composeSealRevision(simpleRequest(plainDocument({ page: '/CropBox [0 0 600 792]' }))),
    (error) => error instanceof ComposeError && error.status === 422 && error.code === 'unsupported_pdf' && error.detail === 'cropbox_differs',
  );
  const whole = plainDocument({ page: '/CropBox [0 0 612 792]' });
  assert.ok((await composeSealRevision(simpleRequest(whole))).bytes.length > whole.length);
});

test('[CP-08] parsePdf receives the document only: one argument, no test seam, and no request member can carry an option', async () => {
  const calls = [];
  for (const { name, text } of composeSources()) {
    const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    for (const match of code.matchAll(/\bparsePdf\s*\(/g)) {
      let depth = 1;
      let index = match.index + match[0].length;
      const start = index;
      while (index < code.length && depth > 0) {
        if (code[index] === '(') depth += 1;
        else if (code[index] === ')') depth -= 1;
        index += 1;
      }
      calls.push({ name, args: code.slice(start, index - 1) });
    }
    assert.doesNotMatch(code, /createParseServiceForTests|workerEntry|launchers\s*:|LaunchSeam/, `${name} reaches no parse-service test seam`);
  }
  assert.equal(calls.length, 1, 'the composer parses in one place');
  for (const { name, args } of calls) {
    let depth = 0;
    let commas = 0;
    for (const char of args) {
      if ('([{'.includes(char)) depth += 1;
      else if (')]}'.includes(char)) depth -= 1;
      else if (char === ',' && depth === 0) commas += 1;
    }
    assert.equal(commas, 0, `${name}: parsePdf gets one argument`);
    assert.doesNotMatch(args, /\.\.\./, `${name}: no spread argument`);
  }

  const base = fixture('single-page.pdf');
  for (const extra of [{ limits: { maxPages: 1000 } }, { service: { wallMs: 1 } }, { options: {} }]) {
    await assert.rejects(
      composeSealRevision({ ...simpleRequest(base), ...extra }),
      (error) => error instanceof ComposeError && error.status === 400 && error.details[0].code === 'unknown_member',
      Object.keys(extra)[0],
    );
  }
  // The default parse limits stay in force: 51 pages are refused by the parse service.
  await assert.rejects(composeSealRevision(simpleRequest(fixture('pages-51.pdf'))), (error) => error instanceof ComposeError && error.status === 422 && error.reason === 'page-limit');
});

test('[CP-08] every report member the composer uses is checked against the document and bounded, failing closed with 500 report-invalid', async () => {
  const base = fixture('single-page.pdf');
  const report = await honestReport(base);
  const request = checkRequest(simpleRequest(base));
  const nested = () => {
    let value = null;
    for (let i = 0; i < 80; i += 1) value = [value];
    return value;
  };
  const catalog = (r) => r.objects['1'].value.dict;
  const page = (r) => r.objects['4'].value.dict;
  const cases = [
    ['bytes', (r) => (r.bytes += 1)],
    ['digest', (r) => (r.digest = '0'.repeat(64))],
    ['xref-startxref', (r) => (r.xref.startxref += 1)],
    ['xref-startxref', (r) => (r.xref.startxref = base.length + 10)],
    ['xref-kind', (r) => (r.xref.kind = 'stream')],
    ['xref-shape', (r) => (r.xref.kind = 'hybrid')],
    ['xref-size', (r) => (r.xref.size = 8_388_609)],
    ['xref-size', (r) => (r.xref.size = 8_388_605)],
    ['trailer-root', (r) => (r.trailer.root = [99, 0])],
    ['catalog-type', (r) => (r.trailer.root = [4, 0])],
    ['trailer-id', (r) => (r.trailer.id = ['zz', 'zz'])],
    ['pages', (r) => (r.pages = [])],
    ['page-rotate', (r) => (r.pages[0].rotate = 45)],
    ['page-box', (r) => (r.pages[0].media_box = [0, 0, Number.NaN, 792])],
    ['page-geometry', (r) => (r.pages[0].width = 600)],
    ['page-ref', (r) => (r.pages[0].ref = [70, 0])],
    ['page-type', (r) => (r.pages[0].ref = [1, 0])],
    ['page-missing', (r) => (r.pages[0].ref = [4, 1])],
    ['objects-count', (r) => ['2', '3', '5', '6'].forEach((key) => (r.objects[key] = { gen: 0, value: null }))],
    ['object-number', (r) => (r.objects['70'] = r.objects['1'])],
    ['object-number', (r) => (r.objects['01'] = r.objects['1'])],
    ['object-shape', (r) => (r.objects['1'].gen = 70000)],
    ['object-shape', (r) => (r.objects['1'].extra = true)],
    ['catalog-missing', (r) => delete r.objects['1']],
    ['report-depth', (r) => (catalog(r).Deep = nested())],
    ['name-character', (r) => (catalog(r).Bad = { name: 'xĀ' })],
    ['name-character', (r) => (catalog(r)['K\u0000'] = 1)],
    ['string-not-hex', (r) => (catalog(r).Bad = { hex: 'zz' })],
    ['value-shape', (r) => (catalog(r).Bad = { dict: {}, name: 'x' })],
    ['value-shape', (r) => (catalog(r).Bad = 'text')],
    ['number-not-finite', (r) => (catalog(r).Bad = Number.POSITIVE_INFINITY)],
    ['number-range', (r) => (catalog(r).Bad = 1e-7)],
    ['number-range', (r) => (catalog(r).Bad = 1e21)],
    ['acroform-shape', (r) => (catalog(r).AcroForm = [1, 2])],
    ['page-rewritten-twice', (r) => (catalog(r).AcroForm = { ref: [4, 0] })],
    ['annots-shape', (r) => (page(r).Annots = { name: 'NotAnArray' })],
  ];
  for (const [detail, mutate] of cases) {
    const lying = structuredClone(report);
    mutate(lying);
    assert.throws(() => composeFromReport(request, lying), reportInvalid(detail), detail);
  }
  // A reference the report does not resolve is a dangling form reference (422), never followed.
  for (const [what, mutate] of [
    ['acroform', (r) => (catalog(r).AcroForm = { ref: [6, 0] })],
    ['annots', (r) => (page(r).Annots = { ref: [6, 0] })],
    ['annots', (r) => (page(r).Annots = { ref: [1, 3] })],
  ]) {
    const lying = structuredClone(report);
    mutate(lying);
    assert.throws(
      () => composeFromReport(request, lying),
      (error) => error instanceof ComposeError && error.status === 422 && error.detail === 'dangling_form_reference' && error.details[0].field === what && error.retryable === false,
      what,
    );
  }
});

test('[CP-08] every refusal carries its contract code, its status and retryable, which is true only for 429 rate_limited and the parse service\'s 500s', async () => {
  const base = fixture('single-page.pdf');
  const rect = { x: 0.1, y: 0.7, width: 0.4, height: 0.06 };
  const statusOf = { invalid_request: 400, payload_too_large: 413, unsupported_characters: 422, unsupported_pdf: 422, rate_limited: 429, internal: 500 };
  const refusal = async (attempt) => {
    try {
      await attempt();
    } catch (error) {
      assert.ok(error instanceof ComposeError, 'a ComposeError');
      return error;
    }
    assert.fail('the request was not refused');
  };
  const report = await honestReport(base);
  const croppedReport = structuredClone(report);
  croppedReport.pages[0].crop_box = [0, 0, 600, 792];
  const observed = [
    await refusal(() => composeSealRevision({ ...simpleRequest(base), limits: {} })),
    await refusal(() => composeSealRevision(composeRequest(base, [field('sig_1', 1, rect)], [approval(RECIPIENT_1, [typed('sig_1', '中')])]))),
    await refusal(() => composeSealRevision(simpleRequest(fixture('pages-51.pdf')))),
    await refusal(() => composeSealRevision(simpleRequest(plainDocument({ page: '/Annots 98 0 R' })))),
    await refusal(() => composeFromReport(checkRequest(simpleRequest(base)), croppedReport)),
    await refusal(() => composeFromReport(checkRequest(simpleRequest(base)), { ...report, digest: '0'.repeat(64) })),
    await refusal(() => checkRequest({ ...simpleRequest(base), fieldManifest: { ...simpleRequest(base).fieldManifest, document_digest: 'a'.repeat(64) } })),
    await refusal(() => checkRequest(simpleRequest(base, 1, { certificateDer: Uint8Array.of(0x30, 0x00) }))),
  ];
  assert.deepEqual(
    observed.map((error) => [error.code, error.status, error.reason, error.retryable]),
    [
      ['invalid_request', 400, 'input-invalid', false],
      ['unsupported_characters', 422, 'unsupported-characters', false],
      ['unsupported_pdf', 422, 'page-limit', false],
      ['unsupported_pdf', 422, 'unsupported-feature', false],
      ['unsupported_pdf', 422, 'unsupported-feature', false],
      ['internal', 500, 'report-invalid', false],
      ['internal', 500, 'document-digest-mismatch', false],
      ['internal', 500, 'certificate-invalid', false],
    ],
  );
  // The parse service's refusals map by their own code: only 429 and its 500s are retryable.
  const mapped = [
    ['payload_too_large', 'size-limit', false],
    ['unsupported_pdf', 'malformed', false],
    ['rate_limited', 'parse-capacity', true],
    ['internal', 'service-failure', true],
    ['internal', 'sandbox-unavailable', true],
  ].map(([code, reason, retryable]) => {
    const error = fromParseOutcome({ code, reason, detail: 'synthetic' });
    return [error.code === code, error.status === statusOf[code], error.reason === reason, error.retryable === retryable];
  });
  for (const checks of mapped) assert.deepEqual(checks, [true, true, true, true]);
});

test('[CP-08] report values are data: a __proto__ key is written as a PDF name, and the caller\'s buffer is copied before parsing', async () => {
  const base = fixture('single-page.pdf');
  const report = await honestReport(base);
  const text = JSON.stringify(report);
  assert.ok(text.includes('"Type":{"name":"Catalog"}'));
  const odd = JSON.parse(text.replace('"Type":{"name":"Catalog"}', '"Type":{"name":"Catalog"},"__proto__":{"name":"Odd"}'));
  const revision = composeFromReport(checkRequest(simpleRequest(base)), odd);
  assert.match(sectionObjects(revision.bytes, lastSection(revision.bytes)).get(1), /\/__proto__ \/Odd\b/);
  assert.equal(Object.hasOwn(Object.prototype, 'name'), false, 'no prototype was touched');

  const document = new Uint8Array(base);
  const pending = composeSealRevision(simpleRequest(document));
  document.fill(0x20);
  const composed = await pending;
  assert.ok(Buffer.from(composed.bytes.subarray(0, base.length)).equals(Buffer.from(base)), 'the bytes parsed and composed are the bytes given');
});
