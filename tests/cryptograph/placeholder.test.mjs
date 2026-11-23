// SPDX-License-Identifier: Apache-2.0
//
// WK-04: a CMS length that differs from the placeholder, in either direction,
// a placeholder that is not all zero digits at its offsets, a wrong written
// /ByteRange, malformed input and a document above MAX_SEALED_PDF_BYTES are
// each refused, non-retryably, with no partial artifact (plan.md § Case
// catalogs, WK; the T037 line; requests #39 Part F and #44). Checks run in-process on embed.ts, and the
// decisive cases also end to end through the real child.

import assert from 'node:assert/strict';
import test from 'node:test';

import { sealComposedPdf } from '../../src/cryptograph/worker/index.ts';
import { checkPlaceholder, embedSignedData, MAX_SEALED_PDF_BYTES } from '../../src/cryptograph/worker/testing.ts';
import { assertSealError, BYTE_RANGE_SLOT, byteRangeText, composeSynthetic, edited, EVIDENCE_DIGEST, keyPair, selfSignedCertificate, withSealKey } from './support.mjs';

const pair = keyPair('seal');
const certificateDer = selfSignedCertificate(pair);
const longerCertificateDer = selfSignedCertificate(pair, { commonName: 'opensig-seal-with-a-considerably-longer-common-name.example.test' });

const geometryOf = (composed) => ({ byteRange: composed.byteRange, contentsOffset: composed.contents.offset, contentsHexLength: composed.contents.hexLength });
const refusedAs = (reason) => (error) => error?.name === 'SealError' && error.reason === reason && error.retryable === false;

async function refusedEndToEnd(composed, reason, { certificate = certificateDer, keyMode = 0o600 } = {}) {
  const before = Buffer.from(composed.bytes);
  await withSealKey(
    pair,
    ({ fd, dir, pem }) =>
      assert.rejects(sealComposedPdf({ composed, certificateDer: certificate, approvalEvidenceDigest: EVIDENCE_DIGEST, keyFd: fd }), (error) =>
        assertSealError(error, { reason, retryable: false }, { pem, dir }),
      ),
    { mode: keyMode },
  );
  assert.deepEqual(Buffer.from(composed.bytes), before, "no partial artifact: the caller's bytes are unchanged");
}

test('[WK-04] a placeholder sized for another certificate is refused as length-mismatch, whether the CMS is shorter or longer', async () => {
  assert.notEqual(composeSynthetic(longerCertificateDer).contents.hexLength, composeSynthetic(certificateDer).contents.hexLength, 'premise: the lengths differ');
  await refusedEndToEnd(composeSynthetic(longerCertificateDer), 'length-mismatch', { certificate: certificateDer });
  await refusedEndToEnd(composeSynthetic(certificateDer), 'length-mismatch', { certificate: longerCertificateDer });
  const composed = composeSynthetic(certificateDer);
  const half = composed.contents.hexLength / 2;
  for (const length of [half - 2, half - 1, half + 1, half + 2]) {
    const before = Buffer.from(composed.bytes);
    assert.throws(() => embedSignedData(composed.bytes, geometryOf(composed), new Uint8Array(length).fill(0x30)), refusedAs('length-mismatch'), `a ${length}-byte CMS is refused`);
    assert.deepEqual(Buffer.from(composed.bytes), before, 'the input is not modified');
  }
});

test('[WK-04] anything but an unfilled placeholder at the stated offsets is refused, before the key is used', async () => {
  const composed = composeSynthetic(certificateDer);
  const { offset, hexLength } = composed.contents;
  const [, o1, o2, l2] = composed.byteRange;
  assert.doesNotThrow(() => checkPlaceholder(composed.bytes, geometryOf(composed)), 'premise: the clean placeholder passes');
  const digit = (at, value) => edited(composed, (b) => void b.write(value, at, 'latin1'));
  const cases = {
    'a 1 at the first digit': digit(offset, '1'),
    'a 1 in the middle': digit(offset + hexLength / 2, '1'),
    'an a at the last digit': digit(offset + hexLength - 1, 'a'),
    'no opening delimiter': digit(o1, '('),
    'no closing delimiter': digit(o2 - 1, ')'),
    'no /Contents key': edited(composed, (b) => void b.write('/Contentz', b.lastIndexOf('/Contents', o1), 'latin1')),
    'offset one late': { ...composed, contents: { offset: offset + 1, hexLength } },
    'length two short': { ...composed, contents: { offset, hexLength: hexLength - 2 } },
    'an odd length': { ...composed, contents: { offset, hexLength: hexLength - 1 } },
    'a first range not at 0': { ...composed, byteRange: [1, o1, o2, l2] },
    'a second range short of the end': { ...composed, byteRange: [0, o1, o2, l2 - 1] },
    'a second range past the end': { ...composed, byteRange: [0, o1, o2, l2 + 1] },
    'an empty gap': { ...composed, byteRange: [0, o1, o1 + 2, composed.bytes.length - o1 - 2] },
  };
  for (const [label, bad] of Object.entries(cases)) {
    assert.throws(() => checkPlaceholder(bad.bytes, geometryOf(bad)), refusedAs('placeholder-invalid'), label);
  }
  // End to end, with a key the adapter would refuse: the placeholder refusal comes first.
  await refusedEndToEnd(cases['a 1 in the middle'], 'placeholder-invalid', { keyMode: 0o640 });
});

test('[WK-04] the /ByteRange written in the signature dictionary must equal the stated byte range', async () => {
  for (const style of ['composer', 'zeros']) {
    const composed = composeSynthetic(certificateDer, { style });
    assert.doesNotThrow(() => checkPlaceholder(composed.bytes, geometryOf(composed)), `premise: the ${style} style passes`);
    const written = (values) => edited(composed, (b) => void b.write(byteRangeText(values, style), composed.slotAt, 'latin1'));
    const [, o1, o2, l2] = composed.byteRange;
    const cases = {
      'o1 + 1 written': written([0, o1 + 1, o2, l2]),
      'o2 - 1 written': written([0, o1, o2 - 1, l2]),
      'l2 + 1 written': written([0, o1, o2, l2 + 1]),
      'no /ByteRange key': edited(composed, (b) => void b.write('/ByteRangX', composed.slotAt - '/ByteRange '.length, 'latin1')),
      'a non-integer entry': edited(composed, (b) => void b.write('-', composed.slotAt + 3, 'latin1')),
      'a second /ByteRange in the object': edited(composed, (b) => void b.write('/ByteRange[0 0 0 0]', b.indexOf('/Reason', o2), 'latin1')),
    };
    for (const [label, bad] of Object.entries(cases)) {
      assert.throws(() => checkPlaceholder(bad.bytes, geometryOf(bad)), refusedAs('byte-range-mismatch'), `${style}: ${label}`);
    }
    assert.equal(BYTE_RANGE_SLOT, byteRangeText(composed.byteRange, style).length, 'premise: the slot width is fixed');
  }
  const composed = composeSynthetic(certificateDer);
  const [, o1, o2, l2] = composed.byteRange;
  await refusedEndToEnd(edited(composed, (b) => void b.write(byteRangeText([0, o1, o2, l2 - 1]), composed.slotAt, 'latin1')), 'byte-range-mismatch');
});

test('[WK-04] a document above MAX_SEALED_PDF_BYTES, a bad descriptor number or a malformed request is refused, non-retryably', async () => {
  assert.equal(MAX_SEALED_PDF_BYTES, 50_331_648, "the bound is T036's 48 MiB");
  const composed = composeSynthetic(certificateDer);
  const input = { composed, certificateDer, approvalEvidenceDigest: EVIDENCE_DIGEST, keyFd: 3 };
  const big = { ...composed, bytes: new Uint8Array(MAX_SEALED_PDF_BYTES + 1) };
  await assert.rejects(sealComposedPdf({ ...input, composed: big }), refusedAs('document-too-large'));
  for (const keyFd of [0, 1, 2, -1, 3.5, Number.NaN, '3']) {
    await assert.rejects(sealComposedPdf({ ...input, keyFd }), refusedAs('input-invalid'), `keyFd ${String(keyFd)}`);
  }
  await assert.rejects(sealComposedPdf({ ...input, approvalEvidenceDigest: new Uint8Array(31) }), refusedAs('input-invalid'));
  await assert.rejects(sealComposedPdf({ ...input, extra: true }), refusedAs('input-invalid'));
  await assert.rejects(sealComposedPdf({ ...input, composed: { ...composed, byteRange: [0, 1, 2] } }), refusedAs('input-invalid'));
  await assert.rejects(sealComposedPdf(input, { signal: 'not a signal' }), refusedAs('input-invalid'));
  await assert.rejects(sealComposedPdf({ ...input, certificateDer: 'not der' }), refusedAs('certificate-invalid'));
});
