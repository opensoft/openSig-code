// SPDX-License-Identifier: Apache-2.0
//
// VB-08: trust is judged against the configured anchors only, and a missing,
// null or malformed anchor configuration never yields `trusted` (row
// T012-ANCHORS, the product side; the T014 line). The anchors come from the
// caller: T038 reads OPENSIG_TRUST_ANCHORS_FILE and splits it with
// splitPemCertificates (request #44). trust_anchor_ref is the lowercase hex
// SHA-256 of the DER of the anchor the chain ends at, null unless trusted.
//
// Mutants killed here: null (or a string, an object, [1], ['']) anchors giving
// `trusted`; certificates embedded in the CMS used as anchors; validity periods
// ignored; trust judged when integrity is not valid; a default store consulted
// (the static denylist, below; behaviourally equivalent on a bench whose default
// stores lack the synthetic CA, as the oracle README notes for its own call).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { splitPemCertificates, verifyPdf, VerifierConfigError } from '../../../src/verifier/index.ts';
import { checkOf } from './helpers/agreement.mjs';
import { testPki } from './helpers/cert-build.mjs';
import { sealSynthetic, sha256Hex } from './helpers/cms-build.mjs';
import { listFiles, stripComments } from './helpers/import-scan.mjs';

const at = new Date();
const pki = testPki(at);
const leafSeal = sealSynthetic({ signer: pki.leaf }).bytes;
const selfSeal = sealSynthetic({ signer: pki.selfSigned }).bytes;
const pem = (der) => `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

test('[VB-08] trust_anchor_ref is the SHA-256 of the DER of the anchor the chain ends at, null unless trusted', () => {
  for (const anchor of [pki.ca.der, pem(pki.ca.der)]) {
    const outcome = verifyPdf(leafSeal, { anchors: [pki.selfSigned.der, anchor], validationTime: at });
    assert.equal(outcome.trust, 'trusted');
    assert.equal(outcome.trust_anchor_ref, sha256Hex(pki.ca.der));
    assert.equal(checkOf(outcome, 'trust-anchors').detail, 'anchor-chain');
  }
  const direct = verifyPdf(selfSeal, { anchors: [pki.selfSigned.der], validationTime: at });
  assert.equal(direct.trust, 'trusted', 'a configured self-signed certificate is a direct anchor');
  assert.equal(direct.trust_anchor_ref, sha256Hex(pki.selfSigned.der));
  const untrusted = verifyPdf(selfSeal, { anchors: [pki.ca.der], validationTime: at });
  assert.equal(untrusted.trust, 'untrusted');
  assert.equal(untrusted.trust_anchor_ref, null);
});

test('[VB-08] the OPENSIG_TRUST_ANCHORS_FILE text splits into anchors; a bad file is refused', () => {
  const file = `${pem(pki.selfSigned.der)}\n${pem(pki.ca.der)}`;
  const anchors = splitPemCertificates(file);
  assert.equal(anchors.length, 2);
  const outcome = verifyPdf(leafSeal, { anchors, validationTime: at });
  assert.equal(outcome.trust, 'trusted');
  assert.equal(outcome.trust_anchor_ref, sha256Hex(pki.ca.der));
  const refused = [
    '',
    '   \n',
    `${pem(pki.ca.der)}stray text\n`,
    `${pem(pki.ca.der)}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n`,
    '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n',
    null,
  ];
  for (const text of refused) {
    assert.throws(() => splitPemCertificates(text), (e) => e instanceof VerifierConfigError && e.code === 'anchors-invalid');
  }
});

test('[VB-08] omitted, undefined or empty anchors give untrusted, never trusted', () => {
  for (const options of [{}, { anchors: undefined }, { anchors: [] }]) {
    for (const bytes of [leafSeal, selfSeal]) {
      const outcome = verifyPdf(bytes, { ...options, validationTime: at });
      assert.equal(outcome.integrity, 'valid');
      assert.equal(outcome.trust, 'untrusted');
      assert.equal(outcome.trust_anchor_ref, null);
    }
  }
});

test('[VB-08] null, non-array and malformed anchor configurations are refused, so they never yield trusted', () => {
  const malformed = [
    null,
    'not a list',
    pem(pki.ca.der),
    { 0: pki.ca.der },
    [1],
    [''],
    [new Uint8Array(0)],
    [null],
    [Buffer.from('not a certificate')],
    ['-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'],
    [pem(pki.ca.der) + pem(pki.leaf.der)],
  ];
  for (const anchors of malformed) {
    assert.throws(
      () => verifyPdf(leafSeal, { anchors, validationTime: at }),
      (e) => e instanceof VerifierConfigError && e.code === 'anchors-invalid',
      `not refused: ${typeof anchors}`,
    );
  }
  assert.throws(() => verifyPdf(leafSeal, { anchors: [pki.ca.der], validationTime: at, anchor: [] }), VerifierConfigError);
  assert.throws(() => verifyPdf(leafSeal, { anchors: [pki.ca.der] }), VerifierConfigError, 'the validation time is required');
});

test('[VB-08] an unrelated anchor, or the CA only embedded in the CMS, gives untrusted', () => {
  const unrelated = verifyPdf(leafSeal, { anchors: [pki.selfSigned.der], validationTime: at });
  assert.equal(unrelated.trust, 'untrusted');
  const embeddedCa = sealSynthetic({ signer: pki.leaf, chain: [pki.ca] }).bytes;
  const embeddedOnly = verifyPdf(embeddedCa, { anchors: [pki.selfSigned.der], validationTime: at });
  assert.equal(embeddedOnly.integrity, 'valid');
  assert.equal(embeddedOnly.trust, 'untrusted', 'embedded certificates are never anchors');
  const viaAnchor = verifyPdf(embeddedCa, { anchors: [pki.ca.der], validationTime: at });
  assert.equal(viaAnchor.trust, 'trusted');
});

test('[VB-08] validity periods are judged at the supplied validation time', () => {
  const expiredSeal = sealSynthetic({ signer: pki.expired }).bytes;
  const expired = verifyPdf(expiredSeal, { anchors: [pki.ca.der], validationTime: at });
  assert.equal(expired.integrity, 'valid');
  assert.equal(expired.trust, 'untrusted');
  assert.equal(checkOf(expired, 'trust-anchors').detail, 'signer-outside-validity');
  const later = new Date(pki.notAfter.getTime() + 60_000);
  assert.equal(verifyPdf(leafSeal, { anchors: [pki.ca.der], validationTime: later }).trust, 'untrusted');
  const earlier = new Date(pki.notBefore.getTime() - 60_000);
  assert.equal(verifyPdf(leafSeal, { anchors: [pki.ca.der], validationTime: earlier }).trust, 'untrusted');
});

test('[VB-08] trust is indeterminate whenever integrity is not valid', () => {
  const tampered = Buffer.from(leafSeal);
  tampered[20] ^= 0x01;
  const outcome = verifyPdf(tampered, { anchors: [pki.ca.der], validationTime: at });
  assert.equal(outcome.integrity, 'invalid');
  assert.equal(outcome.trust, 'indeterminate');
  assert.equal(checkOf(outcome, 'trust-anchors').result, 'not-run');
});

test('[VB-08] the verifier names no default trust store, environment store or clock (static guard)', () => {
  const root = fileURLToPath(new URL('../../../src/verifier/', import.meta.url));
  for (const file of listFiles(root)) {
    const code = stripComments(readFileSync(file, 'utf8'));
    for (const text of ['rootCertificates', 'getCACertificates', 'node:tls', 'NODE_EXTRA_CA_CERTS', 'process.', 'Date.now', 'new Date(']) {
      assert.ok(!code.includes(text), `${file} names ${text}`);
    }
  }
});
