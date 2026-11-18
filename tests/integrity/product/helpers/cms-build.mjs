// SPDX-License-Identifier: Apache-2.0
//
// A test-local CMS SignedData builder for T014's CMS-profile and trust tests,
// written from RFC 5652 and RFC 5035 for these tests alone. It shares nothing
// with T013's builder or the oracle's splice code. It signs with crypto.sign
// using in-memory synthetic keys, and can produce each accepted variant
// (request #39, Part F) and each deliberately wrong one.

import { Buffer } from 'node:buffer';
import { constants, createHash, sign } from 'node:crypto';
import {
  algorithm,
  compareDer,
  contentOf,
  ctx,
  ctxPrimitive,
  integer,
  integerBytes,
  octets,
  oid,
  rawTlv,
  seq,
  set,
  setRaw,
  utcTime,
} from './der-build.mjs';
import { appendSignaturePlaceholder, buildBase, embedCms, signedContent } from './pdf-build.mjs';

export const OIDS = Object.freeze({
  signedData: '1.2.840.113549.1.7.2',
  data: '1.2.840.113549.1.7.1',
  digestedData: '1.2.840.113549.1.7.5',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRSAEncryption: '1.2.840.113549.1.1.11',
  rsassaPss: '1.2.840.113549.1.1.10',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  signatureTimeStampToken: '1.2.840.113549.1.9.16.2.14',
  approvalEvidenceDigest: '2.25.254263291653419018820250361524609646248',
});

const attribute = (oidText, ...values) => seq(oid(oidText), set(...values));

function essValue(signer, kind) {
  const hash = createHash('sha256').update(signer.der).digest();
  if (kind === 'wrong-hash') hash[0] ^= 0xff;
  const serial = kind === 'wrong-serial' ? Buffer.from([0x7e]) : signer.serialContent;
  const issuerSerial = seq(seq(ctx(4, signer.issuerName)), integerBytes(serial));
  let id;
  if (kind === 'explicit-sha256') id = seq(algorithm(OIDS.sha256, 'absent'), octets(hash));
  else if (kind === 'issuer-serial' || kind === 'wrong-serial') id = seq(octets(hash), issuerSerial);
  else id = seq(octets(hash));
  return seq(seq(id));
}

function evidenceAttribute(evidence) {
  if (evidence === 'two-values') return attribute(OIDS.approvalEvidenceDigest, octets(Buffer.alloc(32, 1)), octets(Buffer.alloc(32, 2)));
  if (evidence === 'integer') return attribute(OIDS.approvalEvidenceDigest, integer(5));
  return attribute(OIDS.approvalEvidenceDigest, octets(evidence));
}

function signatureAlgorithmOf(name = 'sha256WithRSAEncryption') {
  if (name === 'rsaEncryption') return algorithm(OIDS.rsaEncryption);
  if (name === 'rsassa-pss') return seq(oid(OIDS.rsassaPss), seq());
  if (name === 'no-parameters') return algorithm(OIDS.sha256WithRSAEncryption, 'absent');
  return algorithm(OIDS.sha256WithRSAEncryption);
}

/**
 * Build a detached SignedData over `content` (the stated ranges, concatenated).
 * signer: a cert-build certificate with its in-memory private key.
 * variant: see the profile tests; every field is optional and defaults to the
 * product profile (issuerAndSerialNumber, sha256WithRSAEncryption, ESS certHash
 * only, no signingTime).
 */
export function buildSignedData({ content, signer, chain = [], variant = {} }) {
  const digestName = variant.digest ?? 'sha256';
  const digestOid = digestName === 'sha384' ? OIDS.sha384 : OIDS.sha256;
  const messageDigest = variant.messageDigest ?? createHash(digestName).update(content).digest();
  const attrs = [];
  const contentType = variant.contentType ?? 'data';
  if (contentType !== 'absent') attrs.push(attribute(OIDS.contentType, oid(contentType === 'other' ? OIDS.digestedData : OIDS.data)));
  attrs.push(attribute(OIDS.messageDigest, octets(messageDigest)));
  if (variant.duplicateMessageDigest) attrs.push(attribute(OIDS.messageDigest, octets(Buffer.alloc(32, 9))));
  if (variant.signingTime) attrs.push(attribute(OIDS.signingTime, utcTime(variant.signingTimeValue ?? new Date(Date.UTC(2026, 10, 18)))));
  const ess = variant.ess ?? 'cert-hash';
  if (ess !== 'absent') attrs.push(attribute(OIDS.signingCertificateV2, essValue(signer, ess)));
  if (variant.evidence !== undefined && variant.evidence !== null) attrs.push(evidenceAttribute(variant.evidence));
  const sorted = [...attrs].sort(compareDer);
  const ordered = variant.unsorted ? [...sorted].reverse() : sorted;
  const asSet = setRaw(...ordered);
  const transmitted = Buffer.from(asSet);
  transmitted[0] = 0xa0;
  const signingKey =
    signer.privateKey.asymmetricKeyType === 'rsa' ? { key: signer.privateKey, padding: constants.RSA_PKCS1_PADDING } : signer.privateKey;
  const signature = sign(digestName, variant.signOverContextTag ? transmitted : asSet, signingKey);
  const sidKind = variant.sid ?? 'issuer-serial';
  const sid =
    sidKind === 'ski'
      ? ctxPrimitive(0, signer.ski)
      : seq(signer.issuerName, integerBytes(sidKind === 'other-serial' ? Buffer.from([0x7f]) : signer.serialContent));
  const version = sidKind === 'ski' ? 3 : 1;
  const unsigned = variant.timestampToken ? [ctx(1, attribute(OIDS.signatureTimeStampToken, seq()))] : [];
  const signerInfo = seq(
    integer(version),
    sid,
    algorithm(digestOid, 'absent'),
    transmitted,
    signatureAlgorithmOf(variant.signatureAlgorithm),
    octets(signature),
    ...unsigned,
  );
  const certificates = [...(variant.omitSignerCertificate ? [] : [signer.der]), ...chain.map((c) => c.der)];
  const encap = variant.attached ? seq(oid(OIDS.data), ctx(0, octets(content))) : seq(oid(OIDS.data));
  const signedData = seq(
    integer(version),
    set(algorithm(digestOid, 'absent')),
    encap,
    ctx(0, ...certificates),
    variant.twoSigners ? setRaw(signerInfo, signerInfo) : set(signerInfo),
  );
  const typeOid = oid(OIDS.signedData);
  const typeTlv = variant.nonMinimalLength ? rawTlv(0x06, [0x81, contentOf(typeOid).length], contentOf(typeOid)) : typeOid;
  return seq(typeTlv, ctx(0, signedData));
}

/**
 * A synthetic sealed PDF: T014's own base, a signature placeholder, and a
 * test-local CMS over the stated ranges. options.byteRange may state a wrong
 * range before signing, so the signature over the stated ranges stays valid.
 */
export function sealSynthetic({ signer, chain = [], variant = {}, xref = 'table', hexDigits = 16384, byteRange } = {}) {
  const layout = appendSignaturePlaceholder(buildBase({ xref }), { hexDigits, byteRange });
  const der = buildSignedData({ content: signedContent(layout), signer, chain, variant });
  return { bytes: embedCms(layout, der), der, layout };
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
