// SPDX-License-Identifier: Apache-2.0
//
// T013 detached CMS SignedData builder (plan.md § Case catalogs, CMS; A-010,
// request #39).
// CMS-S01..CMS-S06, the structure cases: `openssl cms -verify` acceptance and
//   trust behaviour, the SignedData and SignerInfo fields, the signed
//   attributes, the signature input, determinism and the exact length, and
//   input refusals (including exponent 65537 and the 16 KiB certificate cap).
// CMS-01 (A-008 S1; an extra case beyond the registry's KEY-01 and KEY-02):
//   OpenSSL reads the approval-evidence attribute (OID
//   2.25.254263291653419018820250361524609646248) back as the 32 digest bytes.
// Every check reads the output with OpenSSL or the test-local DER walker in
// support.mjs, never with the product's own reader.

import assert from 'node:assert/strict';
import { constants, verify, X509Certificate } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  buildDetachedSignedData,
  CertificateError,
  CmsBuildError,
  MAX_SIGNER_CERTIFICATE_BYTES,
  signedDataLength,
} from '../../src/cryptograph/cms/index.ts';
import { loadDevelopmentSealKey } from '../../src/cryptograph/keys/index.ts';
import {
  asn1parseLines,
  bodyOf,
  bytesOf,
  devFixture,
  EVIDENCE_DIGEST,
  EVIDENCE_OID_TEXT,
  hex,
  issuerAndSerial,
  kids,
  OID_HEX,
  openssl,
  sha256,
  syntheticContent,
  tlvAt,
  toHex,
  withScratch,
} from './support.mjs';

const RSA_PKCS1 = { padding: constants.RSA_PKCS1_PADDING };

/** Seal synthetic content in `dir`; the signature and content files are written for OpenSSL. */
function sealed(dir, options = {}) {
  const fixture = devFixture(dir, options);
  const signer = loadDevelopmentSealKey({ path: fixture.keyPath });
  const content = syntheticContent();
  const der = buildDetachedSignedData({
    contentDigest: sha256(content),
    approvalEvidenceDigest: EVIDENCE_DIGEST,
    certificateDer: fixture.certDer,
    signer,
  });
  const sigPath = join(dir, 'seal.der');
  const contentPath = join(dir, 'content.bin');
  writeFileSync(sigPath, der);
  writeFileSync(contentPath, content);
  return { ...fixture, signer, content, der: Buffer.from(der), sigPath, contentPath };
}

function verifyArgs(seal, dir, contentPath = seal.contentPath) {
  return ['cms', '-verify', '-binary', '-inform', 'DER', '-in', seal.sigPath, '-content', contentPath, '-out', join(dir, 'verified.bin')];
}

/** The SignerInfo's elements, by the test-local walker. */
function signerInfoOf(der) {
  const top = tlvAt(der, 0);
  const [, explicit] = kids(der, top);
  const [signedData] = kids(der, explicit);
  const fields = kids(der, signedData);
  const [signerInfo] = kids(der, fields[4]);
  return { top, explicit, signedData, fields, signerInfo, parts: kids(der, signerInfo) };
}

test('[CMS-01] OpenSSL reads the approval-evidence attribute back as the 32 digest bytes', async () => {
  await withScratch(async (dir) => {
    const seal = sealed(dir);
    const verified = openssl([...verifyArgs(seal, dir), '-CAfile', seal.certPath, '-no-CApath', '-no-CAstore', '-purpose', 'any']);
    assert.equal(verified.status, 0, 'openssl cms -verify accepts the seal, so the attribute is under the signature');

    const parsed = openssl(['asn1parse', '-inform', 'DER', '-in', seal.sigPath]);
    assert.equal(parsed.status, 0);
    const lines = asn1parseLines(parsed.stdout);
    const hits = lines.flatMap((line, index) => (line.type === 'OBJECT' && line.value === EVIDENCE_OID_TEXT ? [index] : []));
    assert.equal(hits.length, 1, 'the attribute type appears exactly once');
    const at = hits[0];
    const ancestor = (depth) => lines.slice(0, at).findLast((line) => line.depth === depth);
    assert.equal(lines[at].depth, 7, 'ContentInfo > [0] > SignedData > signerInfos > SignerInfo > [0] > Attribute > type');
    assert.equal(ancestor(6).type, 'SEQUENCE', 'inside an Attribute');
    assert.equal(ancestor(5).type, 'cont [ 0 ]', 'inside signedAttrs [0]');
    assert.equal(ancestor(4).type, 'SEQUENCE', 'inside a SignerInfo');
    assert.equal(ancestor(3).type, 'SET', 'inside signerInfos');
    assert.equal(lines[at + 1].type, 'SET');
    assert.equal(lines[at + 1].depth, 7);
    const value = lines[at + 2];
    assert.equal(value.depth, 8);
    assert.match(value.type, /^OCTET STRING\s+\[HEX DUMP\]$/);
    assert.equal(value.length, 32);
    assert.equal(value.value.toLowerCase(), toHex(EVIDENCE_DIGEST));
    assert.equal(lines.filter((line) => line.depth === 8 && line.value.toLowerCase() === toHex(EVIDENCE_DIGEST)).length, 1);

    const printed = openssl(['cms', '-cmsout', '-print', '-noout', '-inform', 'DER', '-in', seal.sigPath]);
    assert.equal(printed.status, 0);
    const signedAttrsAt = printed.stdout.indexOf('signedAttrs:');
    const oidAt = printed.stdout.indexOf(EVIDENCE_OID_TEXT);
    const signatureAlgorithmAt = printed.stdout.indexOf('signatureAlgorithm:', signedAttrsAt);
    assert.ok(signedAttrsAt >= 0 && oidAt > signedAttrsAt && signatureAlgorithmAt > oidAt, 'openssl prints the OID among the signed attributes');
  });
});

test('[CMS-S01] openssl cms -verify passes with the certificate as anchor (also under -cades) and with -noverify, gives untrusted without the anchor, and fails after a content change', async () => {
  await withScratch(async (dir) => {
    const seal = sealed(dir);
    const anchored = openssl([...verifyArgs(seal, dir), '-CAfile', seal.certPath, '-no-CApath', '-no-CAstore', '-purpose', 'any']);
    assert.equal(anchored.status, 0, 'integrity and trust against the supplied anchor');
    assert.ok(readFileSync(join(dir, 'verified.bin')).equals(seal.content), 'the detached content round-trips byte for byte');

    const cades = openssl([...verifyArgs(seal, dir), '-cades', '-CAfile', seal.certPath, '-no-CApath', '-no-CAstore', '-purpose', 'any']);
    assert.equal(cades.status, 0, 'with -cades OpenSSL requires signingCertificateV2 and matches its certHash to the signer certificate');

    const integrityOnly = openssl([...verifyArgs(seal, dir), '-noverify']);
    assert.equal(integrityOnly.status, 0, 'the signature verifies with certificate-chain checks off');

    const noAnchor = openssl([...verifyArgs(seal, dir), '-no-CAfile', '-no-CApath', '-no-CAstore', '-purpose', 'any']);
    assert.notEqual(noAnchor.status, 0, 'a self-signed development certificate is not trusted without an anchor');
    assert.match(noAnchor.stderr, /self.signed/i, 'the refusal is about trust, not integrity');

    const changed = Buffer.from(seal.content);
    changed[changed.length >> 1] ^= 0x01;
    const changedPath = join(dir, 'changed.bin');
    writeFileSync(changedPath, changed);
    const tampered = openssl([...verifyArgs(seal, dir, changedPath), '-CAfile', seal.certPath, '-no-CApath', '-no-CAstore', '-purpose', 'any']);
    assert.notEqual(tampered.status, 0, 'one changed content byte fails verification');
  });
});

test('[CMS-S02] SignedData and SignerInfo carry exactly the profile fields: version 1, SHA-256, detached id-data, only the signer certificate, an issuerAndSerialNumber sid, and sha256WithRSAEncryption with NULL parameters', async () => {
  await withScratch(async (dir) => {
    const seal = sealed(dir);
    const der = seal.der;
    const { top, explicit, signedData, fields, signerInfo, parts } = signerInfoOf(der);
    assert.equal(top.end, der.length, 'no trailing octets');
    assert.equal(top.tag, 0x30);
    const [contentType] = kids(der, top);
    assert.equal(toHex(bytesOf(der, contentType)), OID_HEX.signedData);
    assert.equal(explicit.tag, 0xa0);
    assert.equal(kids(der, explicit).length, 1);
    assert.equal(signedData.tag, 0x30);
    assert.equal(fields.length, 5, 'version, digestAlgorithms, encapContentInfo, certificates, signerInfos; no crls');
    assert.equal(toHex(bytesOf(der, fields[0])), '020101', 'SignedData version 1');
    assert.equal(toHex(bytesOf(der, fields[1])), `310d300b${OID_HEX.sha256}`, 'digestAlgorithms: SHA-256 with parameters absent');
    assert.equal(toHex(bytesOf(der, fields[2])), `300b${OID_HEX.data}`, 'encapContentInfo is id-data with no eContent');
    assert.equal(fields[3].tag, 0xa0, 'certificates [0] IMPLICIT');
    assert.ok(bodyOf(der, fields[3]).equals(Buffer.from(seal.certDer)), 'the certificate set holds exactly the signer certificate');
    assert.equal(fields[4].tag, 0x31);
    assert.equal(kids(der, fields[4]).length, 1, 'one SignerInfo');
    assert.equal(signerInfo.tag, 0x30);
    assert.equal(parts.length, 6, 'no unsignedAttrs');
    assert.equal(toHex(bytesOf(der, parts[0])), '020101', 'SignerInfo version 1');
    const sid = kids(der, parts[1]);
    const expected = issuerAndSerial(seal.certDer);
    assert.equal(parts[1].tag, 0x30);
    assert.equal(sid.length, 2);
    assert.ok(bytesOf(der, sid[0]).equals(expected.issuer), 'sid issuer is the certificate issuer, verbatim');
    assert.ok(bytesOf(der, sid[1]).equals(expected.serial), 'sid serial is the certificate serial, verbatim');
    assert.equal(toHex(bytesOf(der, parts[2])), `300b${OID_HEX.sha256}`, 'digestAlgorithm SHA-256, parameters absent');
    assert.equal(parts[3].tag, 0xa0, 'signedAttrs [0] IMPLICIT');
    assert.equal(toHex(bytesOf(der, parts[4])), `300d${OID_HEX.sha256WithRSAEncryption}0500`, 'sha256WithRSAEncryption with NULL parameters');
    assert.equal(parts[5].tag, 0x04);
    assert.equal(parts[5].end - parts[5].body, 384, 'an RSA-3072 signature');
  });
});

test('[CMS-S03] the signed attributes are exactly contentType, messageDigest, signingCertificateV2 (certHash only) and the approval-evidence digest, in DER order, with no signingTime', async () => {
  await withScratch(async (dir) => {
    const seal = sealed(dir);
    const der = seal.der;
    const { parts } = signerInfoOf(der);
    const attributes = kids(der, parts[3]);
    assert.equal(attributes.length, 4);
    for (let index = 1; index < attributes.length; index += 1) {
      assert.ok(Buffer.compare(bytesOf(der, attributes[index - 1]), bytesOf(der, attributes[index])) < 0, 'SET OF in ascending DER order');
    }
    const byType = new Map();
    for (const attribute of attributes) {
      const [type, values] = kids(der, attribute);
      assert.equal(values.tag, 0x31);
      const members = kids(der, values);
      assert.equal(members.length, 1, 'one value per attribute');
      byType.set(toHex(bytesOf(der, type)), toHex(bytesOf(der, members[0])));
    }
    assert.deepEqual(
      [...byType.keys()].sort(),
      [OID_HEX.contentType, OID_HEX.messageDigest, OID_HEX.signingCertificateV2, OID_HEX.approvalEvidenceDigest].sort(),
    );
    assert.equal(byType.has(OID_HEX.signingTime), false, 'no signingTime');
    assert.equal(byType.get(OID_HEX.contentType), OID_HEX.data);
    assert.equal(byType.get(OID_HEX.messageDigest), `0420${toHex(sha256(seal.content))}`);
    assert.equal(
      byType.get(OID_HEX.signingCertificateV2),
      `3026302430220420${toHex(sha256(seal.certDer))}`,
      'ESSCertIDv2 hashes the whole certificate DER; DEFAULT SHA-256 hashAlgorithm and issuerSerial omitted; no policies',
    );
    assert.equal(byType.get(OID_HEX.approvalEvidenceDigest), `0420${toHex(EVIDENCE_DIGEST)}`);
  });
});

test('[CMS-S04] the signature is over the signed attributes encoded as a SET (0x31)', async () => {
  await withScratch(async (dir) => {
    const seal = sealed(dir);
    const der = seal.der;
    const { parts } = signerInfoOf(der);
    const asField = bytesOf(der, parts[3]);
    const asSet = Buffer.from(asField);
    asSet[0] = 0x31;
    const signature = bodyOf(der, parts[5]);
    const publicKey = new X509Certificate(Buffer.from(seal.certDer)).publicKey;
    assert.ok(verify('sha256', asSet, { key: publicKey, ...RSA_PKCS1 }, signature));
    assert.equal(verify('sha256', asField, { key: publicKey, ...RSA_PKCS1 }, signature), false);
  });
});

test('[CMS-S05] equal inputs give equal bytes, and signedDataLength gives the exact output length', async () => {
  await withScratch(async (dir) => {
    const seal = sealed(dir);
    const input = { contentDigest: sha256(seal.content), approvalEvidenceDigest: EVIDENCE_DIGEST, certificateDer: seal.certDer, signer: seal.signer };
    const again = Buffer.from(buildDetachedSignedData(input));
    assert.ok(again.equals(seal.der), 'deterministic: PKCS#1 v1.5 and no signingTime');
    assert.equal(signedDataLength(seal.certDer), seal.der.length);
    const other = Buffer.from(buildDetachedSignedData({ ...input, approvalEvidenceDigest: sha256(Buffer.from('other manifest (synthetic)')) }));
    assert.equal(other.length, seal.der.length, 'the size does not depend on the digests');
    assert.equal(other.equals(seal.der), false);
  });
});

test('[CMS-S06] wrong digest sizes, a key that does not match the certificate, a certificate that is not RSA-3072 with exponent 65537 or exceeds 16 KiB, and a bad signer are refused', async () => {
  await withScratch(async (dir) => {
    const seal = sealed(dir);
    const base = { contentDigest: sha256(seal.content), approvalEvidenceDigest: EVIDENCE_DIGEST, certificateDer: seal.certDer, signer: seal.signer };
    const refused = (Kind, code) => (error) => error instanceof Kind && error.code === code;
    assert.throws(() => buildDetachedSignedData({ ...base, contentDigest: new Uint8Array(31) }), refused(CmsBuildError, 'digest-invalid'));
    assert.throws(() => buildDetachedSignedData({ ...base, approvalEvidenceDigest: new Uint8Array(33) }), refused(CmsBuildError, 'digest-invalid'));
    assert.throws(() => buildDetachedSignedData({ ...base, approvalEvidenceDigest: toHex(EVIDENCE_DIGEST) }), refused(CmsBuildError, 'digest-invalid'));

    const other = devFixture(dir, { name: 'other' });
    const otherSigner = loadDevelopmentSealKey({ path: other.keyPath });
    assert.throws(() => buildDetachedSignedData({ ...base, signer: otherSigner }), refused(CmsBuildError, 'key-certificate-mismatch'));

    const small = devFixture(dir, { name: 'small', modulusLength: 2048 });
    assert.throws(() => buildDetachedSignedData({ ...base, certificateDer: small.certDer }), refused(CertificateError, 'certificate-key-unsupported'));
    const exponent3 = devFixture(dir, { name: 'exponent3', publicExponent: 3 });
    assert.equal(new X509Certificate(Buffer.from(exponent3.certDer)).publicKey.asymmetricKeyDetails.publicExponent, 3n, 'premise: exponent 3');
    assert.throws(() => buildDetachedSignedData({ ...base, certificateDer: exponent3.certDer }), refused(CertificateError, 'certificate-key-unsupported'));
    assert.throws(() => buildDetachedSignedData({ ...base, certificateDer: hex('3000') }), refused(CertificateError, 'certificate-malformed'));

    assert.equal(MAX_SIGNER_CERTIFICATE_BYTES, 16 * 1024, 'the certificate cap is 16 KiB of DER');
    const large = devFixture(dir, { name: 'large', commentBytes: 17 * 1024 });
    assert.ok(large.certDer.length > 16 * 1024, 'premise: a real certificate over 16 KiB');
    assert.throws(() => buildDetachedSignedData({ ...base, certificateDer: large.certDer }), refused(CertificateError, 'certificate-too-large'));
    assert.throws(() => signedDataLength(large.certDer), refused(CertificateError, 'certificate-too-large'));
    assert.throws(() => buildDetachedSignedData({ ...base, certificateDer: new Uint8Array(16 * 1024 + 1) }), refused(CertificateError, 'certificate-too-large'));
    assert.throws(
      () => buildDetachedSignedData({ ...base, certificateDer: new Uint8Array(16 * 1024) }),
      refused(CertificateError, 'certificate-malformed'),
      'exactly 16 KiB is within the cap (refused here only as malformed)',
    );

    const short = { publicKey: seal.signer.publicKey, sign: () => new Uint8Array(383) };
    assert.throws(() => buildDetachedSignedData({ ...base, signer: short }), refused(CmsBuildError, 'signature-invalid'));
    const wrong = { publicKey: seal.signer.publicKey, sign: (data) => otherSigner.sign(data) };
    assert.throws(() => buildDetachedSignedData({ ...base, signer: wrong }), refused(CmsBuildError, 'signature-self-check-failed'));
  });
});
