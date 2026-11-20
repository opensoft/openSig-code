// SPDX-License-Identifier: Apache-2.0
//
// T012 oracle unit cases for the independent DER reader, revision-chain
// parser, ByteRange check and /Contents extraction. Pure: no OpenSSL process.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { OID, readProfile } from './lib/cms-reader.mjs';
import { DerError, contentOf, decodeOid, encodeOid, readTlv, tlv } from './lib/der.mjs';
import { appendSignatureRevision, buildBaseRevision, embedCms, naturalByteRange, pngUpEncode, writeByteRange } from './lib/pdf-builder.mjs';
import { checkByteRange, extractCms, locateSignatures, parseRevisions } from './lib/pdf-checker.mjs';
import { pngUnfilter } from './lib/xref-stream.mjs';

const attr = (oid, ...values) => tlv(0x30, encodeOid(oid), tlv(0x31, ...values));

function syntheticSignedData(extra) {
  const attrs = [attr(OID.contentType, encodeOid(OID.data)), attr(OID.messageDigest, tlv(0x04, Buffer.alloc(32, 1))), ...extra];
  const signerInfo = tlv(0x30, tlv(0x02, Buffer.from([1])), tlv(0x30), tlv(0x30, encodeOid(OID.sha256)),
    tlv(0xa0, ...attrs), tlv(0x30, encodeOid('1.2.840.113549.1.1.1')), tlv(0x04, Buffer.alloc(4)));
  const sd = tlv(0x30, tlv(0x02, Buffer.from([1])), tlv(0x31), tlv(0x30, encodeOid(OID.data)), tlv(0x31, signerInfo));
  return tlv(0x30, encodeOid(OID.signedData), tlv(0xa0, sd));
}

function sealedLayout(defects, xref = 'table', baseDefects = {}) {
  const rev = appendSignatureRevision(buildBaseRevision({ seed: 'unit', xref, defects: baseDefects }), { defects });
  const bytes = writeByteRange(rev.bytes, rev.layout, naturalByteRange(rev.bytes, rev.layout));
  return { bytes, layout: rev.layout };
}

const codeOf = (fn) => {
  try {
    fn();
  } catch (error) {
    if (error instanceof DerError) return error.code;
    throw error;
  }
  return null;
};

test('[OC-09] the approval-evidence OID and a known CMS OID encode and decode losslessly', () => {
  const encoded = encodeOid(OID.approvalEvidenceDigest);
  const node = readTlv(encoded, 0);
  assert.equal(contentOf(encoded, node)[0], 0x69, 'arcs 2.25 encode as 0x69');
  assert.equal(decodeOid(contentOf(encoded, node)), OID.approvalEvidenceDigest);
  assert.equal(encodeOid(OID.messageDigest).toString('hex'), '06092a864886f70d010904');
});

test('[OC-07] the DER reader rejects truncated, indefinite and non-minimal lengths', () => {
  assert.equal(codeOf(() => readTlv(Buffer.from([0x30, 0x05, 0x02, 0x01, 0x01]), 0)), 'der-truncated');
  assert.equal(codeOf(() => readTlv(Buffer.from([0x30]), 0)), 'der-truncated');
  assert.equal(codeOf(() => readTlv(Buffer.from([0x30, 0x80, 0x00, 0x00]), 0)), 'der-indefinite');
  assert.equal(codeOf(() => readTlv(Buffer.from([0x04, 0x81, 0x05, 1, 2, 3, 4, 5]), 0)), 'der-non-minimal-length');
});

test('[OC-09] the approval-evidence reader classifies absent, present and malformed values', () => {
  const digest = Buffer.alloc(32, 0xab);
  const ev = (extra) => readProfile(syntheticSignedData(extra)).approvalEvidence;
  assert.deepEqual(ev([]), { status: 'absent' });
  assert.deepEqual(ev([attr(OID.approvalEvidenceDigest, tlv(0x04, digest))]), { status: 'present', digestHex: digest.toString('hex') });
  assert.equal(ev([attr(OID.approvalEvidenceDigest, tlv(0x04, digest.subarray(0, 31)))]).detail, 'not-32-byte-octet-string');
  assert.equal(ev([attr(OID.approvalEvidenceDigest, tlv(0x24, tlv(0x04, digest)))]).detail, 'not-32-byte-octet-string');
  assert.equal(ev([attr(OID.approvalEvidenceDigest, tlv(0x04, digest), tlv(0x04, digest))]).detail, 'value-count');
  const one = attr(OID.approvalEvidenceDigest, tlv(0x04, digest));
  assert.equal(ev([one, one]).detail, 'duplicate-attribute');
});

test('[OC-08] the revision parser follows the xref chain and rejects a /Prev that is not earlier', () => {
  const base = buildBaseRevision({ seed: 'unit' });
  assert.equal(parseRevisions(base.bytes.toString('latin1')).revisions.length, 1);
  const two = parseRevisions(sealedLayout({}).bytes.toString('latin1'));
  assert.equal(two.ok, true, JSON.stringify(two));
  assert.equal(two.revisions.length, 2);
  assert.equal(two.revisions[0].end, base.bytes.length, 'revision 0 ends at its %%EOF line');
  assert.deepEqual(parseRevisions(sealedLayout({ prevSelf: true }).bytes.toString('latin1')), { ok: false, detail: 'prev-not-earlier' });
});

test('[OC-06] the ByteRange check accepts only a range that excludes exactly /Contents up to a revision end', () => {
  const { bytes, layout } = sealedLayout({});
  const s = bytes.toString('latin1');
  const structure = parseRevisions(s);
  const located = locateSignatures(s);
  assert.equal(located.length, 1);
  const sig = located[0];
  assert.equal(sig.ok && sig.isSig, true, JSON.stringify(sig));
  assert.deepEqual(checkByteRange(bytes.length, sig, structure), { ok: true, signedRevision: 1 });
  const [o1, l1, o2, l2] = sig.byteRange;
  assert.equal(l1, layout.contentsStart);
  const verdict = (br) => checkByteRange(bytes.length, { ...sig, byteRange: br }, structure).detail;
  assert.equal(verdict([o1, l1, o2 + 4, l2 - 4]), 'gap-not-contents');
  assert.equal(verdict([o1, l1 - 1, o2, l2]), 'gap-not-contents');
  assert.equal(verdict([9, l1 - 9, o2, l2]), 'range1-not-at-zero');
  assert.equal(verdict([o1, l1, o2, l2 - 16]), 'not-revision-boundary');
  assert.equal(verdict([o1, l1, o2, l2 + 1]), 'beyond-eof');
});

test('[OC-04] /Contents extraction reads exactly one DER object and reports non-zero padding', () => {
  const { bytes, layout } = sealedLayout({});
  const der = tlv(0x30, tlv(0x02, Buffer.from([1])));
  const embedded = embedCms(bytes, layout, der);
  const first = extractCms(locateSignatures(embedded.toString('latin1'))[0]);
  assert.equal(first.ok, true);
  assert.equal(first.der.equals(der), true);
  assert.equal(first.paddingZero, true);
  const padded = Buffer.from(embedded);
  padded.write('1', layout.contentsEnd - 2, 'latin1');
  assert.equal(extractCms(locateSignatures(padded.toString('latin1'))[0]).paddingZero, false);
  const notHex = Buffer.from(embedded);
  notHex.write('G', layout.contentsStart + 1, 'latin1');
  assert.equal(locateSignatures(notHex.toString('latin1'))[0].detail, 'contents-not-hex');
});

test('[OC-01] cross-reference-stream bases (plain, and FlateDecode with PNG Up) parse, and the seal adds a stream section', () => {
  for (const xref of ['stream', 'stream-flate']) {
    const one = parseRevisions(buildBaseRevision({ seed: 'unit', xref }).bytes.toString('latin1'));
    assert.equal(one.ok, true, `${xref}: ${JSON.stringify(one)}`);
    assert.equal(one.revisions.length, 1);
    const { bytes } = sealedLayout({}, xref);
    const s = bytes.toString('latin1');
    const two = parseRevisions(s);
    assert.equal(two.ok, true, `${xref}: ${JSON.stringify(two)}`);
    assert.equal(two.revisions.length, 2);
    assert.equal(/\nxref\n/.test(s), false, `${xref}: no classic table is written`);
    assert.equal(s.includes('/FlateDecode'), xref === 'stream-flate');
    assert.deepEqual(checkByteRange(bytes.length, locateSignatures(s)[0], two), { ok: true, signedRevision: 1 });
  }
});

test('[OC-08] the PNG predictor decoder undoes each row filter and rejects an unknown filter byte', () => {
  const data = Buffer.from([1, 0, 0, 0, 16, 0, 0, 1, 0, 0, 0, 200, 0, 0]);
  assert.deepEqual(pngUnfilter(pngUpEncode(data, 7), 7), { ok: true, data });
  assert.deepEqual(pngUnfilter(Buffer.from([1, 3, 4]), 2).data, Buffer.from([3, 7]));
  assert.deepEqual(pngUnfilter(Buffer.from([3, 4, 6]), 2).data, Buffer.from([4, 8]));
  assert.deepEqual(pngUnfilter(Buffer.from([4, 1, 2]), 2).data, Buffer.from([1, 3]));
  assert.deepEqual(pngUnfilter(Buffer.from([5, 1, 2]), 2), { ok: false, detail: 'xref-predictor-invalid' });
  assert.deepEqual(pngUnfilter(Buffer.from([2, 1, 2, 3]), 2), { ok: false, detail: 'xref-predictor-row-length' });
});

test('[OC-08] cross-reference-stream entries are checked: type-1 headers and type-2 object streams', () => {
  const parse = (defects, baseDefects) => parseRevisions(sealedLayout(defects, 'stream-flate', baseDefects).bytes.toString('latin1'));
  assert.deepEqual(parse({ sigXrefDelta: 2 }, {}), { ok: false, detail: 'xref-entry-mismatch' });
  assert.deepEqual(parse({}, { type2StreamOverride: 4 }), { ok: false, detail: 'xref-type2-not-object-stream' });
  assert.deepEqual(parse({}, { type2StreamOverride: 99 }), { ok: false, detail: 'xref-type2-object-stream-unlocated' });
});

test('[OC-01] a hybrid base (table plus /XRefStm) parses, and the seal appends a classic table', () => {
  const one = parseRevisions(buildBaseRevision({ seed: 'unit', xref: 'hybrid' }).bytes.toString('latin1'));
  assert.equal(one.ok, true, JSON.stringify(one));
  assert.equal(one.revisions.length, 1);
  const { bytes } = sealedLayout({}, 'hybrid');
  const s = bytes.toString('latin1');
  const two = parseRevisions(s);
  assert.equal(two.ok, true, JSON.stringify(two));
  assert.equal(two.revisions.length, 2);
  assert.equal(s.slice(two.revisions[1].xrefOffset, two.revisions[1].xrefOffset + 4), 'xref', 'the update section is a table');
  assert.deepEqual(checkByteRange(bytes.length, locateSignatures(s)[0], two), { ok: true, signedRevision: 1 });
});

test('[OC-08] a hybrid /XRefStm is read and checked: a bad offset or a bad hidden entry fails', () => {
  const parse = (baseDefects) => parseRevisions(sealedLayout({}, 'hybrid', baseDefects).bytes.toString('latin1'));
  assert.deepEqual(parse({ xrefStmDelta: 3 }), { ok: false, detail: 'xrefstm-not-xref-stream' });
  assert.deepEqual(parse({ type2StreamOverride: 4 }), { ok: false, detail: 'xref-type2-not-object-stream' });
});
