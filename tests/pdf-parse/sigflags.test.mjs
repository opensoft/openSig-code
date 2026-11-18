// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-27 (A-010, request #45): when the AcroForm's /SigFlags is an
// indirect reference to a non-negative integer object, the report carries that object, its
// integer value only, so the composer (T036) can combine the flags with 3. A dictionary,
// array, stream, negative, non-integer or dangling target is not reported, and its document
// still parses. The parent's object-count cap is 4 + 2 x pages. The report's top-level keys
// do not change, and no other object is reported. Synthetic documents, built at runtime.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import * as service from '../../src/pdf/service.ts';
import { classicPdf, streamObject, xrefStreamPdf } from './pdf-builder.mjs';

const REPORT_KEYS = ['bytes', 'digest', 'features', 'header_version', 'isolation', 'network_sandbox', 'objects', 'pages', 'schema', 'stats', 'trailer', 'xref'];

/**
 * An ordinary form: catalog 1 with an indirect AcroForm 4 whose /Fields holds one unsigned
 * text field 5 (also in page 3's inline /Annots). `sigFlags` is the AcroForm's /SigFlags
 * entry; `target`, when given, is object 6.
 */
function formBodies(sigFlags, target) {
  return [
    '<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
    '<< /Type /Page /Parent 2 0 R /Annots [5 0 R] >>',
    `<< /Fields [5 0 R] /DA (/Helv 0 Tf 0 g) /SigFlags ${sigFlags} >>`,
    '<< /Type /Annot /Subtype /Widget /FT /Tx /T (existing_text) /Rect [72 600 272 620] /P 3 0 R /F 4 >>',
    ...(target === undefined ? [] : [target]),
  ];
}

const parsed = async (bytes, what) => {
  const outcome = await service.parsePdf(bytes);
  assert.equal(outcome.ok, true, `${what} parses: ${outcome.ok ? '' : `${outcome.reason} ${outcome.detail}`}`);
  return outcome.report;
};
const objectKeys = (report) => Object.keys(report.objects).sort((a, b) => Number(a) - Number(b));

test('[PL-27] an indirect AcroForm /SigFlags is reported only as a non-negative integer target, and the object cap is 4 + 2 x pages', async () => {
  // The control: a direct /SigFlags. Catalog, page and AcroForm are reported; /Fields and /Annots are inline.
  const control = await parsed(classicPdf(formBodies('4')), 'the direct control');
  assert.deepEqual(objectKeys(control), ['1', '3', '4']);
  assert.deepEqual(Object.keys(control).sort(), REPORT_KEYS);

  // A non-negative integer target is reported as its value alone, plain or in an object stream.
  for (const value of [0, 4, 2_147_483_648, 4_294_967_295, 4_294_967_296]) {
    const report = await parsed(classicPdf(formBodies('6 0 R', String(value))), `indirect ${value}`);
    assert.deepEqual(report.objects['6'], { gen: 0, value }, `indirect ${value} is reported`);
    assert.deepEqual(objectKeys(report), ['1', '3', '4', '6'], 'and no other new object');
    assert.deepEqual(Object.keys(report).sort(), REPORT_KEYS, 'the top-level keys are unchanged');
    assert.deepEqual(report.features, control.features);
  }
  const packed = await parsed(xrefStreamPdf(formBodies('6 0 R', '4'), { packed: [[4, 6]] }), 'an integer in an object stream');
  assert.deepEqual(packed.objects['6'], { gen: 0, value: 4 });
  assert.deepEqual(objectKeys(packed), ['1', '3', '4', '6']);

  // Every other target is not reported, and its document still parses as before.
  const others = [
    ['a dictionary', '6 0 R', '<< /V 4 >>'],
    ['an array', '6 0 R', '[4]'],
    ['a stream', '6 0 R', streamObject('', '4').toString('latin1')],
    ['a negative integer', '6 0 R', '-4'],
    ['a real number', '6 0 R', '4.5'],
    ['a name', '6 0 R', '/Four'],
    ['another generation', '6 1 R', '4'],
    ['a dangling reference', '9 0 R', undefined],
  ];
  for (const [what, sigFlags, target] of others) {
    const report = await parsed(classicPdf(formBodies(sigFlags, target)), what);
    assert.deepEqual(objectKeys(report), ['1', '3', '4'], `${what} is not reported`);
    assert.deepEqual(Object.keys(report).sort(), REPORT_KEYS, what);
    assert.deepEqual(report.features, control.features, what);
  }

  // The parent's cap: catalog, AcroForm, /Fields and the /SigFlags integer, plus a page and its /Annots per page.
  const input = classicPdf(formBodies('6 0 R', '4'));
  const honest = structuredClone(await parsed(input, 'the cap document'));
  delete honest.digest;
  delete honest.network_sandbox;
  const withObjects = (count) => {
    const report = structuredClone(honest);
    report.xref.size = 40;
    for (let num = 20; objectKeys(report).length < count; num += 1) report.objects[String(num)] = { gen: 0, value: null };
    return service.validateChildResult({ ok: true, report }, input.length, 50);
  };
  assert.notEqual(withObjects(4), null, 'the honest report (four objects) is valid');
  assert.notEqual(withObjects(4 + 2 * 1), null, '4 + 2 x pages objects are allowed');
  assert.equal(withObjects(4 + 2 * 1 + 1), null, 'one more is refused');
});
