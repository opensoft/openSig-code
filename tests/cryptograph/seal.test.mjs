// SPDX-License-Identifier: Apache-2.0
//
// WK-01 (embedding and report) and WK-05 (the approval-evidence digest passes
// unchanged; A-008 S1) for the isolated sealing worker (T037; plan.md § Case
// catalogs, WK). Every seal runs the real child through sealComposedPdf. The
// CMS is read back with this directory's own reader; the oracle (T012) and the
// verifier (T014) judge sealed output independently later, and are not used
// here.

import assert from 'node:assert/strict';
import test from 'node:test';

import { sealComposedPdf } from '../../src/cryptograph/worker/index.ts';
import {
  composeSynthetic,
  EVIDENCE_DIGEST,
  EVIDENCE_OID,
  extractCms,
  keyPair,
  octetAttribute,
  selfSignedCertificate,
  sha256,
  sha256hex,
  signatureVerifies,
  withSealKey,
} from './support.mjs';

const pair = keyPair('seal');
const certificateDer = selfSignedCertificate(pair);
const MESSAGE_DIGEST_OID = '1.2.840.113549.1.9.4';

const spans = (composed) => [composed.bytes.subarray(0, composed.byteRange[1]), composed.bytes.subarray(composed.byteRange[2])];

test('[WK-01] the CMS fills the placeholder exactly, as lowercase hex, changes no other byte, and verifies over both spans', async () => {
  for (const style of ['composer', 'zeros']) {
    const composed = composeSynthetic(certificateDer, { style });
    const before = Buffer.from(composed.bytes);
    const sealed = await withSealKey(pair, ({ fd }) => sealComposedPdf({ composed, certificateDer, approvalEvidenceDigest: EVIDENCE_DIGEST, keyFd: fd }));
    const { offset, hexLength } = composed.contents;
    assert.equal(sealed.bytes.length, composed.bytes.length, `${style}: nothing is appended`);
    assert.deepEqual(Buffer.from(sealed.bytes.subarray(0, offset)), before.subarray(0, offset), `${style}: bytes before the placeholder are unchanged`);
    assert.deepEqual(Buffer.from(sealed.bytes.subarray(offset + hexLength)), before.subarray(offset + hexLength), `${style}: bytes after the placeholder are unchanged`);
    const hex = Buffer.from(sealed.bytes.subarray(offset, offset + hexLength)).toString('latin1');
    assert.match(hex, /^[0-9a-f]+$/, `${style}: the placeholder holds lowercase hex only`);
    const cms = extractCms(sealed.bytes, composed.contents);
    assert.equal(cms.length * 2, hexLength, `${style}: the CMS fills the placeholder exactly, with no padding`);
    assert.equal(cms[0], 0x30, `${style}: the placeholder holds a DER SEQUENCE`);
    assert.deepEqual(Buffer.from(octetAttribute(cms, MESSAGE_DIGEST_OID)), sha256(Buffer.concat(spans(composed))), `${style}: messageDigest covers both spans`);
    assert.equal(signatureVerifies(cms, pair), true, `${style}: the signature verifies under the certificate key`);
    assert.deepEqual(Buffer.from(composed.bytes), before, `${style}: the caller's bytes are untouched`);
  }
});

test('[WK-01] the reported digests match a recomputation, and equal inputs seal to identical bytes', async () => {
  const composed = composeSynthetic(certificateDer);
  const [first, second] = await withSealKey(pair, async ({ fd }) => {
    const input = { composed, certificateDer, approvalEvidenceDigest: EVIDENCE_DIGEST, keyFd: fd };
    return [await sealComposedPdf(input), await sealComposedPdf(input)];
  });
  assert.deepEqual(Object.keys(first).sort(), ['bytes', 'finalPdfDigest', 'signerCertificateSha256'], 'only what the T037 line requires is reported');
  assert.equal(first.finalPdfDigest, sha256hex(first.bytes), 'finalPdfDigest is SHA-256 of the sealed bytes');
  assert.equal(first.signerCertificateSha256, sha256hex(certificateDer), 'signerCertificateSha256 is SHA-256 of the certificate');
  for (const name of ['finalPdfDigest', 'signerCertificateSha256']) assert.match(first[name], /^[0-9a-f]{64}$/, `${name} is lowercase hex SHA-256`);
  assert.deepEqual(Buffer.from(second.bytes), Buffer.from(first.bytes), 'a second seal of equal inputs gives identical bytes');
  assert.equal(second.finalPdfDigest, first.finalPdfDigest, 'and an identical digest');
});

test('[WK-05] the approval-evidence digest is read back from the signed attribute, byte for byte', async () => {
  const composed = composeSynthetic(certificateDer);
  const digests = [EVIDENCE_DIGEST, new Uint8Array(32), new Uint8Array(32).fill(0xff), Uint8Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff)];
  const cmsSeen = new Set();
  await withSealKey(pair, async ({ fd }) => {
    for (const digest of digests) {
      const copy = Uint8Array.from(digest);
      const sealed = await sealComposedPdf({ composed, certificateDer, approvalEvidenceDigest: digest, keyFd: fd });
      const cms = extractCms(sealed.bytes, composed.contents);
      assert.deepEqual(Buffer.from(octetAttribute(cms, EVIDENCE_OID)), Buffer.from(digest), 'the attribute holds the input digest');
      assert.deepEqual(digest, copy, "the caller's digest is not modified");
      assert.equal(signatureVerifies(cms, pair), true, 'the attribute is under the signature');
      cmsSeen.add(sha256hex(cms));
    }
  });
  assert.equal(cmsSeen.size, digests.length, 'each digest gives a different CMS');
});

test('[WK-05] a one-bit change in the evidence digest reaches the attribute and changes nothing outside the placeholder', async () => {
  const composed = composeSynthetic(certificateDer);
  const other = Uint8Array.from(EVIDENCE_DIGEST, (b, i) => (i === 31 ? b ^ 0x01 : b));
  const [a, b] = await withSealKey(pair, async ({ fd }) => [
    await sealComposedPdf({ composed, certificateDer, approvalEvidenceDigest: EVIDENCE_DIGEST, keyFd: fd }),
    await sealComposedPdf({ composed, certificateDer, approvalEvidenceDigest: other, keyFd: fd }),
  ]);
  const { offset, hexLength } = composed.contents;
  assert.deepEqual(Buffer.from(a.bytes.subarray(0, offset)), Buffer.from(b.bytes.subarray(0, offset)));
  assert.deepEqual(Buffer.from(a.bytes.subarray(offset + hexLength)), Buffer.from(b.bytes.subarray(offset + hexLength)));
  const cmsA = extractCms(a.bytes, composed.contents);
  const cmsB = extractCms(b.bytes, composed.contents);
  assert.deepEqual(Buffer.from(octetAttribute(cmsA, MESSAGE_DIGEST_OID)), Buffer.from(octetAttribute(cmsB, MESSAGE_DIGEST_OID)), 'the content digest does not depend on it');
  assert.deepEqual(Buffer.from(octetAttribute(cmsA, EVIDENCE_OID)), Buffer.from(EVIDENCE_DIGEST));
  assert.deepEqual(Buffer.from(octetAttribute(cmsB, EVIDENCE_OID)), Buffer.from(other));
});
