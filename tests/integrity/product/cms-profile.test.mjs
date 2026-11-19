// SPDX-License-Identifier: Apache-2.0
//
// VB-07, VB-09 and VB-10 on T014's own synthetic seals: the CMS profile the
// verifier accepts (request #39, Part F), each wrong binding or attribute, the
// strict DER reader, the ByteRange checks with the end-of-file fallback, the
// signingTime profile check, and the inputs reserved for `indeterminate`.
//
// Mutants killed here: the signature verified over the [0] tag instead of the
// SET; integrity from messageDigest alone; the ESS certHash or issuerSerial
// unchecked; the sid unmatched; unsorted signedAttrs accepted; NULL parameters
// unchecked; an attached CMS accepted; non-minimal DER accepted; the gap, range
// 1 or the revision boundary unchecked; the fallback accepting one byte short;
// signingTime changing a verdict; an out-of-profile algorithm read as valid.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { verifyPdf, VERIFIER_LIMITS } from '../../../src/verifier/index.ts';
import { DerFault, readTlv } from '../../../src/verifier/der.ts';
import { checkOf } from './helpers/agreement.mjs';
import { testPki } from './helpers/cert-build.mjs';
import { buildSignedData, sealSynthetic, sha256Hex } from './helpers/cms-build.mjs';
import { appendSignaturePlaceholder, appendUpdate, buildBase, docFromBytes, embedCms, signedContent } from './helpers/pdf-build.mjs';

const at = new Date();
const pki = testPki(at);
const anchors = [pki.ca.der];
const verify = (bytes, extra = {}) => verifyPdf(bytes, { anchors, validationTime: at, ...extra });

test('[VB-07] the product profile verifies on every base kind', () => {
  for (const xref of ['table', 'stream', 'stream-flate', 'hybrid']) {
    const { bytes } = sealSynthetic({ signer: pki.leaf, xref });
    const outcome = verify(bytes, { expectedArtifactDigest: sha256Hex(bytes) });
    assert.equal(outcome.integrity, 'valid', xref);
    assert.equal(outcome.trust, 'trusted', xref);
    assert.equal(outcome.revision_coverage, 'complete', xref);
    assert.equal(outcome.accepted_as_original, true, xref);
    assert.equal(checkOf(outcome, 'profile-signing-time').result, 'pass', xref);
    assert.equal(checkOf(outcome, 'profile-signing-certificate-v2').result, 'pass', xref);
    assert.equal(outcome.timestamp_status, 'absent', xref);
  }
});

test('[VB-07] the accepted OpenSSL variants verify: rsaEncryption, a subjectKeyIdentifier sid, ESSCertIDv2 with issuerSerial', () => {
  const variants = [
    { signatureAlgorithm: 'rsaEncryption' },
    { sid: 'ski' },
    { ess: 'issuer-serial' },
    { ess: 'explicit-sha256' },
    { ess: 'absent' },
    { sid: 'ski', ess: 'issuer-serial', signatureAlgorithm: 'rsaEncryption', signingTime: true },
  ];
  for (const variant of variants) {
    const outcome = verify(sealSynthetic({ signer: pki.leaf, variant }).bytes);
    assert.equal(outcome.integrity, 'valid', JSON.stringify(variant));
    assert.equal(outcome.trust, 'trusted', JSON.stringify(variant));
  }
  const withCa = verify(sealSynthetic({ signer: pki.leaf, chain: [pki.ca] }).bytes);
  assert.equal(withCa.integrity, 'valid');
});

test('[VB-07] a wrong binding, attribute or encoding makes integrity invalid', () => {
  const cases = [
    [{ ess: 'wrong-hash' }, 'signer-binding', 'ess-cert-hash-mismatch'],
    [{ ess: 'wrong-serial' }, 'signer-binding', 'ess-issuer-serial-mismatch'],
    [{ sid: 'other-serial' }, 'signer-binding', 'signer-certificate-not-found'],
    [{ omitSignerCertificate: true }, 'signer-binding', 'signer-certificate-not-found'],
    [{ contentType: 'other' }, 'cms-structure', 'content-type-attribute'],
    [{ contentType: 'absent' }, 'cms-structure', 'content-type-attribute'],
    [{ duplicateMessageDigest: true }, 'cms-structure', 'duplicate-signed-attribute'],
    [{ unsorted: true }, 'cms-structure', 'signed-attributes-not-der-sorted'],
    [{ attached: true }, 'cms-structure', 'not-detached'],
    [{ nonMinimalLength: true }, 'cms-structure', 'der-non-minimal-length'],
    [{ signatureAlgorithm: 'no-parameters' }, 'signature-value', 'signature-algorithm-parameters'],
    [{ messageDigest: Buffer.alloc(32, 7) }, 'message-digest', 'message-digest-mismatch'],
  ];
  for (const [variant, checkId, detail] of cases) {
    const outcome = verify(sealSynthetic({ signer: pki.leaf, variant }).bytes);
    assert.equal(outcome.integrity, 'invalid', JSON.stringify(variant));
    assert.equal(outcome.trust, 'indeterminate', JSON.stringify(variant));
    assert.equal(checkOf(outcome, checkId).result, 'fail', JSON.stringify(variant));
    assert.equal(checkOf(outcome, checkId).detail, detail, JSON.stringify(variant));
  }
});

test('[VB-07] the signature covers signedAttrs re-tagged as a SET; a valid messageDigest alone is never enough', () => {
  const retag = verify(sealSynthetic({ signer: pki.leaf, variant: { signOverContextTag: true } }).bytes);
  assert.equal(checkOf(retag, 'message-digest').result, 'pass');
  assert.equal(checkOf(retag, 'signature-value').detail, 'signature-invalid');
  assert.equal(retag.integrity, 'invalid');
  const sealed = sealSynthetic({ signer: pki.leaf });
  const hex = Buffer.from(sealed.der).toString('hex');
  const flipped = Buffer.from(sealed.bytes);
  const lastDigit = sealed.layout.contentsStart + hex.length;
  flipped[lastDigit] = flipped[lastDigit] === 0x30 ? 0x31 : 0x30;
  const outcome = verify(flipped);
  assert.equal(checkOf(outcome, 'message-digest').result, 'pass');
  assert.equal(checkOf(outcome, 'signature-value').result, 'fail');
  assert.equal(outcome.integrity, 'invalid');
});

test('[VB-07] the DER reader refuses indefinite, non-minimal and overlong lengths and high tag numbers', () => {
  const refuses = (bytes, code) => {
    assert.throws(() => readTlv(Uint8Array.from(bytes), 0, bytes.length), (e) => e instanceof DerFault && e.code === code);
  };
  refuses([0x30, 0x80, 0x00, 0x00], 'indefinite-length');
  refuses([0x04, 0x81, 0x05, 1, 2, 3, 4, 5], 'non-minimal-length');
  refuses([0x04, 0x82, 0x00, 0x90], 'non-minimal-length');
  refuses([0x04, 0x85, 1, 1, 1, 1, 1], 'length-too-large');
  refuses([0x04, 0x05, 1, 2], 'length-exceeds-parent');
  refuses([0x1f, 0x01, 0x00], 'high-tag-number');
});

test('[VB-07] the ByteRange: the gap is /Contents, range 1 starts at 0, range 2 ends at a revision boundary', () => {
  const gapPast = sealSynthetic({ signer: pki.leaf, byteRange: ({ l1, o2, length }) => [0, l1, o2 + 4, length - o2 - 4] });
  const gapOutcome = verify(gapPast.bytes);
  assert.equal(checkOf(gapOutcome, 'byte-range').detail, 'gap-not-contents');
  assert.equal(gapOutcome.integrity, 'invalid');
  assert.equal(gapOutcome.revision_coverage, 'indeterminate');
  const notZero = verify(sealSynthetic({ signer: pki.leaf, byteRange: ({ l1, o2, length }) => [9, l1 - 9, o2, length - o2] }).bytes);
  assert.equal(checkOf(notZero, 'byte-range').detail, 'range1-not-at-zero');
  assert.equal(checkOf(notZero, 'message-digest').result, 'pass', 'the signature over the stated ranges is valid');
  assert.equal(notZero.integrity, 'invalid');
  const short = verify(sealSynthetic({ signer: pki.leaf, byteRange: ({ l1, o2, length }) => [0, l1, o2, length - o2 - 16] }).bytes);
  assert.equal(checkOf(short, 'byte-range').detail, 'not-revision-boundary');
  assert.equal(short.integrity, 'invalid');
  const sealed = sealSynthetic({ signer: pki.leaf });
  const truncated = verify(sealed.bytes.subarray(0, sealed.bytes.length - 16));
  assert.equal(checkOf(truncated, 'byte-range').detail, 'beyond-eof');
  assert.equal(truncated.integrity, 'invalid');
});

test('[VB-07] with the structure check failed, range 2 must end exactly at the end of the file (OC-08 fallback)', () => {
  const seal = (byteRange) => {
    const layout = appendSignaturePlaceholder(buildBase(), { startxrefDelta: 7, byteRange });
    return embedCms(layout, buildSignedData({ content: signedContent(layout), signer: pki.leaf }));
  };
  const exact = verify(seal(undefined));
  assert.equal(checkOf(exact, 'revision-structure').detail, 'startxref-not-xref');
  assert.equal(checkOf(exact, 'byte-range').result, 'pass');
  assert.equal(exact.integrity, 'valid');
  assert.equal(exact.trust, 'trusted');
  assert.equal(exact.revision_coverage, 'indeterminate');
  const oneShort = verify(seal(({ l1, o2, length }) => [0, l1, o2, length - o2 - 1]));
  assert.equal(checkOf(oneShort, 'byte-range').detail, 'not-to-eof');
  assert.equal(oneShort.integrity, 'invalid');
});

test('[VB-07] an upper-case /Contents keeps integrity valid and changes the exact-artifact digest', () => {
  const sealed = sealSynthetic({ signer: pki.leaf, variant: {} });
  const recorded = sha256Hex(sealed.bytes);
  const upper = Buffer.from(sealed.bytes);
  const start = sealed.layout.contentsStart + 1;
  const digits = upper.subarray(start, start + Buffer.from(sealed.der).length * 2);
  digits.write(digits.toString('latin1').toUpperCase(), 0, 'latin1');
  const outcome = verify(upper, { expectedArtifactDigest: recorded });
  assert.equal(outcome.integrity, 'valid');
  assert.equal(outcome.artifact_match, false);
  assert.equal(outcome.accepted_as_original, false);
});

test('[VB-09] signingTime, a missing signingCertificateV2 or a time-stamp token changes no verdict', () => {
  const without = verify(sealSynthetic({ signer: pki.leaf }).bytes);
  const withTime = verify(sealSynthetic({ signer: pki.leaf, variant: { signingTime: true } }).bytes);
  const noEss = verify(sealSynthetic({ signer: pki.leaf, variant: { ess: 'absent' } }).bytes);
  const withToken = verify(sealSynthetic({ signer: pki.leaf, variant: { timestampToken: true } }).bytes);
  for (const outcome of [withTime, noEss, withToken]) {
    for (const field of ['integrity', 'trust', 'revision_coverage']) assert.equal(outcome[field], without[field], field);
  }
  assert.equal(without.integrity, 'valid');
  assert.equal(checkOf(without, 'profile-signing-time').result, 'pass');
  assert.equal(checkOf(without, 'profile-signing-certificate-v2').result, 'pass');
  assert.equal(without.timestamp_status, 'absent');
  assert.equal(checkOf(withTime, 'profile-signing-time').detail, 'signing-time-present');
  assert.equal(checkOf(noEss, 'profile-signing-certificate-v2').result, 'fail');
  assert.equal(checkOf(noEss, 'profile-signing-certificate-v2').detail, 'signing-certificate-v2-absent');
  assert.equal(checkOf(noEss, 'signer-binding').result, 'pass', 'the sid alone binds the signer');
  assert.equal(withToken.timestamp_status, 'indeterminate', 'an unevaluated token is never reported absent');
});

test('[VB-10] inputs outside what T014 evaluates are indeterminate, never valid', () => {
  const outOfProfile = [
    [{ digest: 'sha384' }, 'digest-algorithm-unsupported'],
    [{ signatureAlgorithm: 'rsassa-pss' }, 'signature-algorithm-unsupported'],
    [{ twoSigners: true }, 'multiple-signer-infos'],
  ];
  for (const [variant, detail] of outOfProfile) {
    const outcome = verify(sealSynthetic({ signer: pki.leaf, variant }).bytes);
    assert.equal(outcome.integrity, 'indeterminate', detail);
    assert.ok(outcome.checks.some((c) => c.detail === detail), detail);
  }
  const small = verify(sealSynthetic({ signer: pki.smallKey }).bytes);
  assert.equal(small.integrity, 'indeterminate');
  assert.equal(checkOf(small, 'signature-value').detail, 'signer-key-too-small');
  const ec = verify(sealSynthetic({ signer: pki.ecLeaf }).bytes);
  assert.equal(ec.integrity, 'indeterminate');
  assert.equal(checkOf(ec, 'signature-value').detail, 'signer-key-unsupported');
  const sealed = sealSynthetic({ signer: pki.leaf }).bytes;
  const doc = docFromBytes(sealed);
  const twoSeals = appendUpdate(doc, [{ num: doc.size, text: '<< /Type /Sig /ByteRange [0 1 2 3] /Contents <00> >>' }]).bytes;
  const multiple = verify(twoSeals);
  assert.equal(multiple.integrity, 'indeterminate');
  assert.equal(checkOf(multiple, 'signature-dictionary').detail, 'multiple-signatures');
  const huge = verify(Buffer.alloc(VERIFIER_LIMITS.maxInputBytes + 1));
  assert.equal(huge.integrity, 'indeterminate');
  assert.equal(checkOf(huge, 'input-size').detail, 'input-too-large');
  const unsigned = verify(buildBase().bytes);
  assert.equal(unsigned.integrity, 'invalid', 'a PDF with no seal is evaluated and fails');
  assert.equal(checkOf(unsigned, 'signature-dictionary').detail, 'no-byte-range');
});

// ---------------------------------------------------------------------------
// Request #58 (1), (2) and (4), builder-only (no capability).
//
// Mutants killed here: signatures counted by text; a second signature
// dictionary, a /DocMDP or /UR3 key, or a signature field's foreign /V ignored;
// unsigned bytes after the final %%EOF leaving coverage complete (the
// reviewer's R1); three SignerInfos or nine certificates read as invalid.
// ---------------------------------------------------------------------------

test('[VB-07] the one signature is found by dictionary: a string spelling /ByteRange and /Contents is no signature (request #58 (1))', () => {
  const sealed = sealSynthetic({
    signer: pki.leaf,
    extraObjects: (n) => [{ num: n + 1, text: '<< /Producer (/ByteRange [0 1 2 3] /Contents <00>) >>' }],
  });
  const outcome = verify(sealed.bytes);
  assert.equal(checkOf(outcome, 'signature-dictionary').result, 'pass');
  assert.equal(outcome.integrity, 'valid');
  assert.equal(outcome.revision_coverage, 'complete');
  for (const v of [(n) => `${n} 0 R`, () => 'null']) {
    const field = sealSynthetic({ signer: pki.leaf, extraObjects: (n) => [{ num: n + 1, text: `<< /FT /Sig /T (seal) /V ${v(n)} >>` }] });
    assert.equal(verify(field.bytes).integrity, 'valid', v(7));
  }
});

test('[VB-07] a second signature dictionary, a /DocMDP or /UR3 key, or a signature field whose /V is another value gives indeterminate (request #58 (1))', () => {
  const cases = [
    ['a second /Type /Sig', () => '<< /Type /Sig >>'],
    ['a /DocTimeStamp', () => '<< /Type /DocTimeStamp >>'],
    ['a second /ByteRange with /Contents', () => '<< /ByteRange [0 0 0 0] /Contents <00> >>'],
    ['a nested second signature', () => '<< /Annots [ << /Subtype /Widget /V << /Type /Sig >> >> ] >>'],
    ['a /DocMDP key', () => '<< /Perms << /DocMDP 2 0 R >> >>'],
    ['a /UR3 key', () => '<< /Perms << /UR3 2 0 R >> >>'],
    ['a field /V naming another object', () => '<< /FT /Sig /T (seal) /V 2 0 R >>'],
    ['a field /V that is a string', () => '<< /FT /Sig /T (seal) /V (text) >>'],
  ];
  for (const [label, text] of cases) {
    const sealed = sealSynthetic({ signer: pki.leaf, extraObjects: (n) => [{ num: n + 1, text: text(n) }] });
    const outcome = verify(sealed.bytes);
    assert.equal(outcome.integrity, 'indeterminate', label);
    assert.equal(checkOf(outcome, 'signature-dictionary').detail, 'multiple-signatures', label);
    assert.equal(outcome.accepted_as_original, false, label);
  }
});

test('[VB-07] unsigned bytes after the final %%EOF never leave coverage complete: indeterminate without a later revision, incomplete with one (R1, request #58 (2))', () => {
  const sealed = sealSynthetic({ signer: pki.leaf });
  const expectedArtifactDigest = sha256Hex(sealed.bytes);
  assert.equal(verify(sealed.bytes, { expectedArtifactDigest }).revision_coverage, 'complete');
  const trailing = Buffer.concat([sealed.bytes, Buffer.from('% an unsigned trailing note\n', 'latin1')]);
  const loose = verify(trailing, { expectedArtifactDigest });
  assert.equal(checkOf(loose, 'revision-structure').result, 'pass');
  assert.equal(loose.revision_coverage, 'indeterminate');
  assert.equal(loose.accepted_as_original, false);
  const later = verify(appendUpdate(docFromBytes(sealed.bytes), [{ num: 9, text: '<< /Producer (later) >>' }]).bytes, { expectedArtifactDigest });
  assert.equal(later.revision_coverage, 'incomplete');
  assert.equal(later.accepted_as_original, false);
});

test('[VB-10] three SignerInfos, or nine certificates, give integrity indeterminate, never invalid (request #58 (4))', () => {
  const three = verify(sealSynthetic({ signer: pki.leaf, variant: { signerCount: 3 } }).bytes);
  assert.equal(three.integrity, 'indeterminate');
  assert.equal(checkOf(three, 'cms-structure').detail, 'multiple-signer-infos');
  const nine = verify(sealSynthetic({ signer: pki.leaf, variant: { extraCertificates: 8 }, hexDigits: 65536 }).bytes);
  assert.equal(nine.integrity, 'indeterminate');
  assert.equal(checkOf(nine, 'cms-structure').detail, 'too-many-certificates');
  const eight = verify(sealSynthetic({ signer: pki.leaf, variant: { extraCertificates: 7 }, hexDigits: 65536 }).bytes);
  assert.equal(eight.integrity, 'valid');
});
