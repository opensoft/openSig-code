// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006), kind harness: in-test synthetic PDF cases.
//   EC-06 the builder is deterministic and its documents have the structure they claim
//   EC-07 exact-size documents hit the upload boundary byte counts
//   EC-08 the independent inspector rejects malformed input and finds each policy feature
// Documents are generated programmatically from structural descriptors; nothing
// is downloaded and no document file is committed.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildPdf, DEFAULT_MEDIA_BOX, inspectPdf, PDF_FEATURES } from './lib/pdf.mjs';

const FEATURE_FINDING = Object.freeze({
  encrypt: 'encrypt',
  signature: 'signature',
  'javascript-open-action': 'javascript',
  'launch-open-action': 'launch',
  'embedded-file': 'embedded-file',
  'rich-media': 'rich-media',
  xfa: 'xfa',
});

test('[EC-06] the builder is deterministic and its documents have the structure they claim', () => {
  const plain = buildPdf({});
  assert.ok(plain.equals(buildPdf({})), 'equal descriptors give equal bytes');
  const report = inspectPdf(plain);
  assert.equal(report.ok, true, report.problems.join('; '));
  assert.equal(report.version, '1.7');
  assert.equal(report.xrefKind, 'table');
  assert.equal(report.pageCount, 1);
  assert.deepEqual(report.pages[0], { mediaBox: [...DEFAULT_MEDIA_BOX], cropBox: [...DEFAULT_MEDIA_BOX], rotate: 0, displayed: { width: 612, height: 792 } });
  assert.deepEqual(report.features, []);

  const mixed = inspectPdf(buildPdf({ pages: 3, rotate: [0, 90, 180] }));
  assert.equal(mixed.ok, true);
  assert.deepEqual(
    mixed.pages.map((p) => [p.rotate, p.displayed.width, p.displayed.height]),
    [
      [0, 612, 792],
      [90, 792, 612],
      [180, 612, 792],
    ],
  );

  const inherited = inspectPdf(buildPdf({ inherit: { rotate: 270, mediaBox: [0, 0, 612, 792] } }));
  assert.equal(inherited.ok, true);
  assert.deepEqual([inherited.pages[0].rotate, inherited.pages[0].displayed], [270, { width: 792, height: 612 }]);
  const pagesNode = buildPdf({ inherit: { rotate: 270, mediaBox: [0, 0, 612, 792] } }).toString('latin1');
  assert.match(pagesNode, /\/Type \/Pages [^>]*\/MediaBox \[0 0 612 792\][^>]*\/Rotate 270/, 'inherited attributes live on the page tree node');
  assert.doesNotMatch(pagesNode, /\/Type \/Page \/Parent[^>]*\/MediaBox/, 'the page dictionary carries no MediaBox of its own');

  const stream = inspectPdf(buildPdf({ xref: 'stream' }));
  assert.equal(stream.ok, true, stream.problems.join('; '));
  assert.equal(stream.xrefKind, 'stream');
  assert.equal(stream.pageCount, 1);

  for (const pages of [50, 51]) {
    const many = inspectPdf(buildPdf({ pages }));
    assert.equal(many.ok, true);
    assert.equal(many.pageCount, pages);
    assert.equal(many.features.includes('pages-over-50'), pages > 50);
  }

  assert.deepEqual(inspectPdf(buildPdf({ cropBox: [0, 0, 612, 792] })).features, [], 'an equal crop box is not a defect');
  assert.deepEqual(inspectPdf(buildPdf({ cropBox: [36, 36, 576, 756] })).features, ['cropbox-differs']);
  assert.deepEqual(inspectPdf(buildPdf({ inherit: { cropBox: [36, 36, 576, 756] } })).features, ['cropbox-differs']);

  for (const feature of PDF_FEATURES) {
    for (const xref of ['table', 'stream']) {
      const r = inspectPdf(buildPdf({ features: [feature], xref }));
      assert.equal(r.ok, true, `${feature}/${xref}: ${r.problems.join('; ')}`);
      assert.deepEqual(r.features, [FEATURE_FINDING[feature]], `${feature}/${xref} must carry exactly its own feature`);
    }
  }

  // The existing-signature dictionary's /ByteRange covers the file except the /Contents placeholder.
  const signed = buildPdf({ features: ['signature'] });
  const text = signed.toString('latin1');
  const range = /\/ByteRange \[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(text).slice(1).map(Number);
  assert.equal(range[0], 0);
  assert.equal(text[range[1]], '<');
  assert.equal(text[range[2] - 1], '>');
  assert.equal(range[2] + range[3], signed.length);
  assert.match(text.slice(range[1] + 1, range[2] - 1), /^0+$/, 'the placeholder holds zero bytes only, no signature');

  assert.throws(() => buildPdf({ colour: 'red' }), /unknown key colour/);
  assert.throws(() => buildPdf({ rotate: 45 }), /not 0, 90, 180 or 270/);
  assert.throws(() => buildPdf({ features: ['javascript-open-action', 'launch-open-action'] }), /only one open action/);
});

test('[EC-07] exact-size documents hit the upload boundary byte counts', () => {
  const MiB10 = 10 * 1024 * 1024;
  for (const descriptor of [
    { targetBytes: MiB10 },
    { targetBytes: MiB10 + 1 },
    { pages: 50, targetBytes: MiB10 },
    { xref: 'stream', targetBytes: MiB10 },
    { targetBytes: 4096 },
  ]) {
    const bytes = buildPdf(descriptor);
    assert.equal(bytes.length, descriptor.targetBytes, JSON.stringify(descriptor));
    const report = inspectPdf(bytes);
    assert.equal(report.ok, true, `${JSON.stringify(descriptor)}: ${report.problems.join('; ')}`);
    assert.equal(report.pageCount, descriptor.pages ?? 1);
    assert.deepEqual(report.features, []);
  }
  assert.ok(buildPdf({ targetBytes: MiB10 }).equals(buildPdf({ targetBytes: MiB10 })), 'padding is deterministic');
  assert.throws(() => buildPdf({ targetBytes: 64 }), /smaller than the unpadded document/);
});

test('[EC-08] the independent inspector rejects malformed input and finds each policy feature', () => {
  const notPdf = inspectPdf(buildPdf({ variant: 'not-a-pdf' }));
  assert.equal(notPdf.ok, false);
  assert.deepEqual(notPdf.problems, ['no %PDF- header']);

  const truncated = inspectPdf(buildPdf({ variant: 'truncated' }));
  assert.equal(truncated.ok, false);
  assert.ok(truncated.problems.includes('no startxref'));
  const truncatedText = buildPdf({ variant: 'truncated' }).toString('latin1');
  assert.ok(truncatedText.startsWith('%PDF-1.7'));
  assert.ok(!truncatedText.includes('trailer') && !truncatedText.includes('%%EOF'));

  // Corrupt one cross-reference offset: the inspector must notice, not trust the table.
  const good = buildPdf({ pages: 2 });
  const text = good.toString('latin1');
  const xref = text.indexOf('xref\n');
  const firstEntry = text.indexOf(' 00000 n', xref) - 10;
  const corrupted = Buffer.from(good);
  corrupted.write('0000000001', firstEntry, 'latin1');
  const report = inspectPdf(corrupted);
  assert.equal(report.ok, false);
  assert.ok(report.problems.some((p) => /not at its cross-reference offset/.test(p)), report.problems.join('; '));

  // A page count that disagrees with /Kids is reported.
  const miscounted = Buffer.from(text.replace('/Count 2', '/Count 3'), 'latin1');
  assert.ok(inspectPdf(miscounted).problems.includes('/Count differs from the number of /Kids'));

  // A dangling startxref is reported.
  const dangling = Buffer.from(text.replace(/startxref\n\d+/, 'startxref\n99999999'), 'latin1');
  assert.ok(inspectPdf(dangling).problems.includes('startxref does not point into the file'));
});
