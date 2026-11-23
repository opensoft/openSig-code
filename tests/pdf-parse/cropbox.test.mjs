// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-14 (A-008 S2): an effective /CropBox that differs from the
// /MediaBox is rejected at upload with 422 unsupported_pdf, detail cropbox_differs. The
// effective crop box is the inherited /CropBox intersected with the media box, so a crop
// box covering the whole media box is accepted. All variants are generated at runtime.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parsePdf } from '../../src/pdf/service.ts';
import { basicObjects, classicPdf, xrefStreamPdf } from './pdf-builder.mjs';

function twoPages(secondPage) {
  return classicPdf([
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 612 792] >>',
    '<< /Type /Page /Parent 2 0 R >>',
    `<< /Type /Page /Parent 2 0 R ${secondPage} >>`,
  ]);
}

function nestedTree(intermediate, leaf = '') {
  return classicPdf([
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
    `<< /Type /Pages /Parent 2 0 R /Kids [4 0 R] /Count 1 ${intermediate} >>`,
    `<< /Type /Page /Parent 3 0 R ${leaf} >>`,
  ]);
}

test('[PL-14] an effective /CropBox that differs from the /MediaBox is rejected with 422 cropbox_differs', async () => {
  const cases = {
    'inherited from the page tree root': classicPdf(basicObjects({ pages: '/CropBox [36 36 576 756]' })),
    'inherited through an intermediate node': nestedTree('/CropBox [0 0 612 700]'),
    'on the page itself': classicPdf(basicObjects({ page: '/CropBox [0 0 612 700]' })),
    'beyond the media box on some edges only': classicPdf(basicObjects({ page: '/CropBox [-100 -100 300 900] /Rotate 180' })),
    'an indirect /CropBox array': classicPdf([...basicObjects({ page: '/CropBox 4 0 R' }), '[0 0 300 300]']),
    'the second of two pages': twoPages('/CropBox [10 10 602 782]'),
    'a page in an object stream': xrefStreamPdf(basicObjects({ page: '/CropBox [10 10 600 780]' }), { packed: [[1, 2, 3]] }),
    'a page media box that shrinks below an inherited crop box': classicPdf(basicObjects({ pages: '/CropBox [0 0 612 792]', page: '/MediaBox [0 0 595 842]' })),
  };
  const names = Object.keys(cases);
  const outcomes = await Promise.all(names.map((name) => parsePdf(cases[name])));
  names.forEach((name, index) => {
    const outcome = outcomes[index];
    assert.equal(outcome.ok, false, `${name} must be rejected`);
    assert.equal(outcome.status, 422, name);
    assert.equal(outcome.code, 'unsupported_pdf', name);
    assert.equal(outcome.reason, 'unsupported-feature', `${name}: ${outcome.reason} ${outcome.detail}`);
    assert.equal(outcome.detail, 'cropbox_differs', name);
  });
});

test('[PL-14] a crop box equal to, or covering, the media box is accepted and reported equal to it', async () => {
  const cases = {
    'no crop box': classicPdf(basicObjects()),
    'equal crop box': classicPdf(basicObjects({ page: '/CropBox [0 0 612 792]' })),
    'equal crop box with corners reversed': classicPdf(basicObjects({ pages: '/CropBox [612 792 0 0]' })),
    'crop box covering the media box on every edge': classicPdf(basicObjects({ page: '/CropBox [-10 -10 700 900]' })),
    'inherited equal crop box through an intermediate node': nestedTree('/CropBox [0 0 612 792]', '/Rotate 270'),
  };
  for (const [name, bytes] of Object.entries(cases)) {
    const outcome = await parsePdf(bytes);
    assert.equal(outcome.ok, true, `${name}: ${outcome.ok ? '' : `${outcome.reason} ${outcome.detail}`}`);
    for (const page of outcome.report.pages) assert.deepEqual(page.crop_box, page.media_box, name);
  }
  const rotated = await parsePdf(cases['inherited equal crop box through an intermediate node']);
  assert.deepEqual([rotated.report.pages[0].width, rotated.report.pages[0].height], [792, 612]);
});
