// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits: structure, geometry, page limit, encryption and malformed input,
// exercised through the isolated parse service (src/pdf/service.ts) with the T004
// synthetic fixtures and runtime-generated structural variants.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parsePdf } from '../../src/pdf/service.ts';
import { basicObjects, classicPdf, streamObject, xrefStreamPdf } from './pdf-builder.mjs';
import { fixtureBytes, fixtureRecord, geometry, manifest, sha256 } from './support.mjs';

const accepted = (outcome, label) => {
  assert.equal(outcome.ok, true, `${label}: ${outcome.ok ? '' : `${outcome.reason} ${outcome.detail}`}`);
  return outcome.report;
};

const rejected = (outcome, reason, label) => {
  assert.equal(outcome.ok, false, `${label} must be rejected`);
  assert.equal(outcome.reason, reason, `${label}: ${outcome.detail}`);
  assert.equal(outcome.status, reason === 'size-limit' ? 413 : 422);
  assert.equal(outcome.code, reason === 'size-limit' ? 'payload_too_large' : 'unsupported_pdf');
  return outcome;
};

/** Append an incremental update that redefines object `num` with `body`. */
function appendUpdate(base, num, body) {
  const text = base.toString('latin1');
  const prev = Number(/startxref\n(\d+)\n%%EOF\n$/.exec(text)[1]);
  const size = Number(/\/Size (\d+)/.exec(text)[1]);
  const object = `${num} 0 obj\n${body}\nendobj\n`;
  const xref = base.length + object.length;
  const update =
    `${object}xref\n0 1\n0000000000 65535 f \n${num} 1\n${String(base.length).padStart(10, '0')} 00000 n \n` +
    `trailer\n<< /Size ${size} /Root 1 0 R /Prev ${prev} >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.concat([base, Buffer.from(update, 'latin1')]);
}

/** A hybrid file: a classic table plus /XRefStm naming a compressed font object. */
function hybridDocument() {
  const head = Buffer.from('%PDF-1.7\n', 'latin1');
  const parts = [head];
  let length = head.length;
  const offsets = {};
  const add = (num, body) => {
    offsets[num] = length;
    const chunk = Buffer.concat([Buffer.from(`${num} 0 obj\n`, 'latin1'), Buffer.from(body, 'latin1'), Buffer.from('\nendobj\n', 'latin1')]);
    parts.push(chunk);
    length += chunk.length;
  };
  add(1, '<< /Type /Catalog /Pages 2 0 R >>');
  add(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>');
  add(3, '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> >>');
  const font = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
  add(5, streamObject(`/Type /ObjStm /N 1 /First 4`, `4 0\n${font}`).toString('latin1'));
  const rows = Buffer.alloc(7);
  rows[0] = 2;
  rows.writeUInt32BE(5, 1);
  rows.writeUInt16BE(0, 5);
  add(6, streamObject('/Type /XRef /Size 7 /W [1 4 2] /Index [4 1]', rows).toString('latin1'));
  const xref = length;
  const line = (num) => `${String(offsets[num]).padStart(10, '0')} 00000 n \n`;
  parts.push(
    Buffer.from(
      `xref\n0 7\n0000000000 65535 f \n${line(1)}${line(2)}${line(3)}0000000000 65535 f \n${line(5)}${line(6)}` +
        `trailer\n<< /Size 7 /Root 1 0 R /XRefStm ${offsets[6]} >>\nstartxref\n${xref}\n%%EOF\n`,
      'latin1',
    ),
  );
  return Buffer.concat(parts);
}

test('[PL-01] valid documents parse in the isolated service with the declared structure', async () => {
  const files = ['agreement-multipage.pdf', 'agreement-xref-stream.pdf', 'single-page.pdf', 'pages-50.pdf'];
  const outcomes = await Promise.all(files.map((file) => parsePdf(fixtureBytes(file))));
  files.forEach((file, index) => {
    const report = accepted(outcomes[index], file);
    const bytes = fixtureBytes(file);
    const record = fixtureRecord(file);
    assert.equal(report.schema, 'opensig.pdf.parse-report.v1');
    assert.equal(report.digest, sha256(bytes), `${file} digest covers the exact bytes`);
    assert.equal(report.bytes, bytes.length);
    assert.equal(report.header_version, '1.7');
    assert.deepEqual(geometry(report.pages), record.pages, `${file} geometry`);
    assert.equal(report.xref.kind, record.xref, `${file} cross-reference form`);
    assert.equal(report.xref.sections, 1);
    assert.equal(report.xref.startxref, Number(/startxref\n(\d+)\n%%EOF\n$/.exec(bytes.toString('latin1'))[1]));
    assert.ok(report.objects[String(report.trailer.root[0])], 'the catalog object is reported');
    for (const page of report.pages) assert.equal(report.objects[String(page.ref[0])].value.dict.Type.name, 'Page');
  });
  const streamed = outcomes[1].report;
  assert.ok(streamed.features.includes('object-streams') && streamed.features.includes('xref-stream'));
  assert.ok(streamed.stats.object_streams >= 1);

  // FlateDecode object streams and a PNG-predicted cross-reference stream.
  const packed = xrefStreamPdf(basicObjects(), { packed: [[1, 2, 3]] });
  const packedReport = accepted(await parsePdf(packed), 'flate object stream');
  assert.equal(packedReport.xref.kind, 'stream');
  assert.equal(packedReport.pages.length, 1);
  assert.ok(packedReport.stats.inflated_bytes > 0);

  // Incremental updates: the newest revision of a redefined page wins.
  const updated = appendUpdate(classicPdf(basicObjects()), 3, '<< /Type /Page /Parent 2 0 R /Rotate 90 >>');
  const updatedReport = accepted(await parsePdf(updated), 'incremental update');
  assert.equal(updatedReport.xref.sections, 2);
  assert.ok(updatedReport.features.includes('incremental-updates'));
  assert.deepEqual(geometry(updatedReport.pages), [{ number: 1, width: 792, height: 612, rotate: 90, media_box: [0, 0, 612, 792] }]);

  // Hybrid file: the /XRefStm entry supplies the object the table marks free.
  const hybrid = accepted(await parsePdf(hybridDocument()), 'hybrid file');
  assert.equal(hybrid.xref.hybrid, true);
  assert.equal(hybrid.stats.objects, 6);
});

test('[PL-02] rotated-page geometry follows inherited /Rotate, /MediaBox and /CropBox', async () => {
  const report = accepted(await parsePdf(fixtureBytes('rotated-pages.pdf')), 'rotated-pages.pdf');
  assert.deepEqual(geometry(report.pages), fixtureRecord('rotated-pages.pdf').pages);
  assert.deepEqual(report.pages.map((page) => page.rotate), [90, 270, 180, 0, 270]);
  assert.deepEqual(report.pages.map((page) => [page.width, page.height]), [
    [792, 612],
    [792, 612],
    [612, 792],
    [842, 595],
    [792, 612],
  ]);
  assert.deepEqual(report.pages[4].media_box, [36, 36, 648, 828], 'a non-zero media box origin is preserved');

  // An inherited /CropBox is the displayed box (clipped to the media box), then rotated.
  const cropped = classicPdf(basicObjects({ pages: '/CropBox [36 36 576 756] /Rotate 90', page: '/MediaBox [0 0 612 792]' }));
  const croppedReport = accepted(await parsePdf(cropped), 'inherited crop box');
  assert.deepEqual(croppedReport.pages[0].crop_box, [36, 36, 576, 756]);
  assert.deepEqual([croppedReport.pages[0].width, croppedReport.pages[0].height, croppedReport.pages[0].rotate], [720, 540, 90]);
  const clipped = classicPdf(basicObjects({ page: '/CropBox [-100 -100 300 900] /Rotate -180' }));
  const clippedReport = accepted(await parsePdf(clipped), 'clipped crop box');
  assert.deepEqual(clippedReport.pages[0].crop_box, [0, 0, 300, 792]);
  assert.deepEqual([clippedReport.pages[0].width, clippedReport.pages[0].height, clippedReport.pages[0].rotate], [300, 792, 180]);

  rejected(await parsePdf(classicPdf(basicObjects({ page: '/Rotate 45' }))), 'malformed', '/Rotate 45');
  rejected(await parsePdf(classicPdf(basicObjects({ page: '/MediaBox [0 0 0 792]' }))), 'malformed', 'zero-area media box');
});

test('[PL-03] a 51-page document is rejected and 50 pages are accepted', async () => {
  const [over, at] = await Promise.all([parsePdf(fixtureBytes('pages-51.pdf')), parsePdf(fixtureBytes('pages-50.pdf'))]);
  const outcome = rejected(over, 'page-limit', 'pages-51.pdf');
  assert.match(outcome.detail, /more than 50 pages/);
  assert.equal(accepted(at, 'pages-50.pdf').pages.length, 50);

  // An understated /Count does not hide the 51st page: leaves are counted, not trusted.
  const kids = [];
  const bodies = ['<< /Type /Catalog /Pages 2 0 R >>', null];
  for (let i = 0; i < 51; i += 1) {
    bodies.push('<< /Type /Page /Parent 2 0 R >>');
    kids.push(`${i + 3} 0 R`);
  }
  bodies[1] = `<< /Type /Pages /Kids [${kids.join(' ')}] /Count 50 /MediaBox [0 0 612 792] >>`;
  rejected(await parsePdf(classicPdf(bodies)), 'page-limit', 'understated /Count');

  // A lower configured page limit applies; the FR-002 ceiling cannot be raised.
  rejected(await parsePdf(fixtureBytes('agreement-multipage.pdf'), { limits: { maxPages: 2 } }), 'page-limit', 'maxPages 2');
  await assert.rejects(parsePdf(fixtureBytes('single-page.pdf'), { limits: { maxPages: 51 } }), TypeError);
  await assert.rejects(parsePdf(fixtureBytes('single-page.pdf'), { limits: { maxBytes: 10 * 1024 * 1024 + 1 } }), TypeError);
});

test('[PL-05] an /Encrypt dictionary in the trailer is rejected as encrypted', async () => {
  const outcome = rejected(await parsePdf(fixtureBytes('encrypted-flag.pdf')), 'encrypted', 'encrypted-flag.pdf');
  assert.deepEqual(outcome.detections, ['encryption']);
  // An /Encrypt entry in a cross-reference stream dictionary (the trailer of that form) is
  // detected the same way. The catalog is compressed, so the only /Root entry is in the
  // xref stream dictionary, which is the last object: the edit moves no offset.
  const streamed = xrefStreamPdf([...basicObjects(), '<< /Filter /Standard /V 1 /R 2 /P -4 /O <00> /U <00> >>'], {
    packed: [[1, 2, 3]],
  });
  const text = streamed.toString('latin1');
  assert.equal(text.split('/Root 1 0 R').length, 2, 'exactly one /Root entry');
  const withEncrypt = Buffer.from(text.replace('/Root 1 0 R', '/Root 1 0 R /Encrypt 4 0 R'), 'latin1');
  assert.deepEqual(rejected(await parsePdf(withEncrypt), 'encrypted', 'xref-stream /Encrypt').detections, ['encryption']);
});

test('[PL-08] every malformed fixture variant is rejected with a structural reason', async () => {
  const malformedDocs = manifest.documents.filter((doc) => doc.kind === 'malformed');
  assert.equal(malformedDocs.length, 8);
  const outcomes = await Promise.all(malformedDocs.map((doc) => parsePdf(fixtureBytes(doc.file))));
  const expectedDetail = {
    'missing-header': /header/,
    truncated: /startxref/,
    'startxref-out-of-range': /beyond the end of the file/,
    'xref-offset-mismatch': /does not point at its object/,
    'unterminated-dictionary': /dictionary key expected/,
    'stream-length-overrun': /does not end at endstream/,
    'xref-prev-cycle': /revisits a section/,
    'page-tree-cycle': /page tree revisits/,
  };
  malformedDocs.forEach((doc, index) => {
    const outcome = rejected(outcomes[index], 'malformed', doc.file);
    assert.match(outcome.detail, expectedDetail[doc.defect], `${doc.file} detail`);
  });

  const variants = {
    'duplicate dictionary key': classicPdf(basicObjects({ page: '/Rotate 0 /Rotate 90' })),
    'invalid name escape': classicPdf(basicObjects({ page: '/Foo /Ba#zz' })),
    'unterminated literal string': classicPdf(basicObjects({ page: '/T (open' })),
    'trailer without /Root': Buffer.from(classicPdf(basicObjects()).toString('latin1').replace('/Root 1 0 R', '/Rxxx 1 0 R'), 'latin1'),
    'root that is not a catalog': classicPdf(['<< /Type /Pages /Kids [] /Count 0 >>']),
    'page tree without pages': classicPdf(['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [] /Count 0 >>']),
    'object stream holding a stream': xrefStreamPdf([...basicObjects(), streamObject('', 'x').toString('latin1')], { packed: [[4]] }),
    'reference to a missing object': classicPdf(basicObjects({ page: '/MediaBox 9 0 R' })),
    'empty input': Buffer.alloc(0),
    'header only': Buffer.from('%PDF-1.7\n%%EOF\n', 'latin1'),
  };
  const names = Object.keys(variants);
  const variantOutcomes = await Promise.all(names.map((name) => parsePdf(variants[name])));
  names.forEach((name, index) => rejected(variantOutcomes[index], 'malformed', name));
});
