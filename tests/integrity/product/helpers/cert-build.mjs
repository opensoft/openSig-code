// SPDX-License-Identifier: Apache-2.0
//
// An in-memory synthetic PKI for T014's CMS-profile and trust tests. Keys are
// generated at test time and held only in memory: never written, exported or
// printed (request #43: in-memory test keys meet the key rules). Certificates
// are built with the test-local DER encoder and signed with crypto.sign.
// Names use the .test domain.

import { createHash, generateKeyPairSync, sign, X509Certificate } from 'node:crypto';
import { algorithm, bitString, bool, ctx, ctxPrimitive, integer, octets, oid, seq, set, utcTime, utf8 } from './der-build.mjs';

const SHA256_RSA = '1.2.840.113549.1.1.11';
const DAY = 24 * 60 * 60 * 1000;

export function rsaKeyPair(bits = 3072) {
  return generateKeyPairSync('rsa', { modulusLength: bits, publicExponent: 0x10001 });
}

export function name(commonName) {
  return seq(set(seq(oid('2.5.4.3'), utf8(commonName))));
}

/**
 * Build one certificate. issuer = { name (DER), privateKey, ski } or null for
 * self-signed. Returns { der, x509, issuerName, serial, ski, privateKey, publicKey }.
 */
export function buildCertificate({ commonName, keyPair, issuer = null, serial, ca = false, notBefore, notAfter, withSki = true }) {
  const subjectName = name(commonName);
  const spki = keyPair.publicKey.export({ type: 'spki', format: 'der' });
  const ski = createHash('sha1').update(spki).digest();
  const issuerName = issuer === null ? subjectName : issuer.name;
  const issuerKey = issuer === null ? keyPair.privateKey : issuer.privateKey;
  const issuerSki = issuer === null ? ski : issuer.ski;
  const extensions = [
    seq(oid('2.5.29.19'), bool(true), octets(ca ? seq(bool(true)) : seq())),
    ...(withSki ? [seq(oid('2.5.29.14'), octets(octets(ski)))] : []),
    seq(oid('2.5.29.35'), octets(seq(ctxPrimitive(0, issuerSki)))),
  ];
  const serialTlv = integer(serial);
  const tbs = seq(
    ctx(0, integer(2)),
    serialTlv,
    algorithm(SHA256_RSA),
    issuerName,
    seq(utcTime(notBefore), utcTime(notAfter)),
    subjectName,
    spki,
    ctx(3, seq(...extensions)),
  );
  const signature = sign('sha256', tbs, issuerKey);
  const der = seq(tbs, algorithm(SHA256_RSA), bitString(signature));
  return {
    der,
    x509: new X509Certificate(der),
    name: subjectName,
    issuerName,
    serialContent: serialTlv.subarray(2),
    ski: withSki ? ski : null,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

/**
 * A development CA, a leaf it issued, an unrelated self-signed signer, an
 * expired leaf, a small-key leaf and an EC-key leaf; all synthetic and in memory.
 */
export function testPki(now = new Date()) {
  const notBefore = new Date(now.getTime() - DAY);
  const notAfter = new Date(now.getTime() + 30 * DAY);
  const caKeys = rsaKeyPair();
  const ca = buildCertificate({ commonName: 'T014 Development CA (ca.example.test)', keyPair: caKeys, serial: 1, ca: true, notBefore, notAfter });
  const issuer = { name: ca.name, privateKey: ca.privateKey, ski: ca.ski };
  const leaf = buildCertificate({ commonName: 'T014 Seal (seal.example.test)', keyPair: rsaKeyPair(), issuer, serial: 0x1001, notBefore, notAfter });
  const selfSigned = buildCertificate({ commonName: 'T014 Self-signed (self.example.test)', keyPair: rsaKeyPair(), serial: 7, notBefore, notAfter });
  const expired = buildCertificate({
    commonName: 'T014 Expired (expired.example.test)',
    keyPair: rsaKeyPair(),
    issuer,
    serial: 0x1002,
    notBefore: new Date(now.getTime() - 10 * DAY),
    notAfter: new Date(now.getTime() - 5 * DAY),
  });
  const smallKey = buildCertificate({ commonName: 'T014 Small key (small.example.test)', keyPair: rsaKeyPair(1024), issuer, serial: 0x1003, notBefore, notAfter });
  const ecLeaf = buildCertificate({
    commonName: 'T014 EC key (ec.example.test)',
    keyPair: generateKeyPairSync('ec', { namedCurve: 'P-256' }),
    issuer,
    serial: 0x1004,
    notBefore,
    notAfter,
  });
  return { ca, leaf, selfSigned, expired, smallKey, ecLeaf, notBefore, notAfter };
}
