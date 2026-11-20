// SPDX-License-Identifier: Apache-2.0
//
// Independent reading of a detached CMS SignedData (RFC 5652) for the T012
// oracle: shape, signer certificates and the signed attributes the oracle
// needs. It decides nothing cryptographic; OpenSSL verifies signatures.

import { DerError, children, contentOf, decodeOid, rawOf, readTlv } from './der.mjs';

export const OID = Object.freeze({
  signedData: '1.2.840.113549.1.7.2',
  data: '1.2.840.113549.1.7.1',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  sha256: '2.16.840.1.101.3.4.2.1',
  // opensig-approval-evidence-digest (tasks.md T013, A-008 S1; contract
  // ApprovalManifest): value is an OCTET STRING of the 32 digest bytes.
  approvalEvidenceDigest: '2.25.254263291653419018820250361524609646248',
});

function expectTag(node, tag, code) {
  if (!node || node.tag !== tag) throw new DerError(code);
  return node;
}

function oidOf(der, node, code) {
  return decodeOid(contentOf(der, expectTag(node, 0x06, code)));
}

function parseAttribute(der, node) {
  expectTag(node, 0x30, 'cms-attribute-shape');
  const parts = children(der, node);
  if (parts.length !== 2) throw new DerError('cms-attribute-shape');
  const oid = oidOf(der, parts[0], 'cms-attribute-type');
  const values = children(der, expectTag(parts[1], 0x31, 'cms-attribute-values'));
  return { oid, values };
}

function parseSignerInfo(der, node) {
  const f = children(der, expectTag(node, 0x30, 'cms-signerinfo-shape'));
  let i = 0;
  expectTag(f[i++], 0x02, 'cms-signerinfo-version');
  const sid = f[i++];
  if (!sid) throw new DerError('cms-signerinfo-shape');
  const digestAlgorithm = expectTag(f[i++], 0x30, 'cms-signerinfo-digest-algorithm');
  const signedAttrs = f[i]?.tag === 0xa0 ? f[i++] : null;
  expectTag(f[i++], 0x30, 'cms-signerinfo-signature-algorithm');
  const signature = expectTag(f[i++], 0x04, 'cms-signerinfo-signature');
  if (f[i]?.tag === 0xa1) i += 1;
  if (i !== f.length) throw new DerError('cms-signerinfo-shape');
  const digestOid = oidOf(der, children(der, digestAlgorithm)[0], 'cms-digest-algorithm-oid');
  const attributes = signedAttrs ? children(der, signedAttrs).map((a) => parseAttribute(der, a)) : null;
  return { digestOid, attributes, signatureLength: signature.length };
}

/** Parse ContentInfo -> SignedData. Throws DerError on any shape problem. */
export function parseSignedData(der) {
  const top = readTlv(der, 0);
  if (top.end !== der.length) throw new DerError('cms-trailing-bytes');
  const info = children(der, expectTag(top, 0x30, 'cms-contentinfo-shape'));
  if (info.length !== 2) throw new DerError('cms-contentinfo-shape');
  if (oidOf(der, info[0], 'cms-content-type') !== OID.signedData) throw new DerError('cms-not-signed-data');
  const wrapped = children(der, expectTag(info[1], 0xa0, 'cms-contentinfo-shape'));
  if (wrapped.length !== 1) throw new DerError('cms-contentinfo-shape');
  const f = children(der, expectTag(wrapped[0], 0x30, 'cms-signeddata-shape'));
  let i = 0;
  expectTag(f[i++], 0x02, 'cms-signeddata-version');
  expectTag(f[i++], 0x31, 'cms-digest-algorithms');
  const encap = children(der, expectTag(f[i++], 0x30, 'cms-encapsulated-content'));
  const certificates = f[i]?.tag === 0xa0 ? f[i++] : null;
  if (f[i]?.tag === 0xa1) i += 1;
  const signerInfos = expectTag(f[i++], 0x31, 'cms-signer-infos');
  if (i !== f.length) throw new DerError('cms-signeddata-shape');
  if (encap.length < 1 || encap.length > 2) throw new DerError('cms-encapsulated-content');
  const certs = certificates ? children(der, certificates).filter((c) => c.tag === 0x30).map((c) => rawOf(der, c)) : [];
  return {
    eContentType: oidOf(der, encap[0], 'cms-econtent-type'),
    detached: encap.length === 1,
    certs,
    signers: children(der, signerInfos).map((s) => parseSignerInfo(der, s)),
  };
}

function single(attributes, oid) {
  const matches = attributes.filter((a) => a.oid === oid);
  if (matches.length === 0) return { present: false };
  if (matches.length > 1) return { present: true, malformed: 'duplicate-attribute' };
  if (matches[0].values.length !== 1) return { present: true, malformed: 'value-count' };
  return { present: true, value: matches[0].values[0] };
}

/**
 * Read the opensig-approval-evidence-digest attribute: absent, malformed
 * (not exactly one primitive OCTET STRING of 32 bytes), or present.
 */
export function readApprovalEvidence(der, attributes) {
  const got = single(attributes, OID.approvalEvidenceDigest);
  if (!got.present) return { status: 'absent' };
  if (got.malformed) return { status: 'malformed', detail: got.malformed };
  if (got.value.tag !== 0x04 || got.value.length !== 32) return { status: 'malformed', detail: 'not-32-byte-octet-string' };
  return { status: 'present', digestHex: Buffer.from(contentOf(der, got.value)).toString('hex') };
}

/** Facts about the single signer's signed attributes, read independently. */
export function readProfile(der) {
  const parsed = parseSignedData(der);
  if (parsed.signers.length !== 1) throw new DerError('cms-signer-count');
  const signer = parsed.signers[0];
  if (!signer.attributes) throw new DerError('cms-no-signed-attributes');
  const contentType = single(signer.attributes, OID.contentType);
  const digest = single(signer.attributes, OID.messageDigest);
  const contentTypeOid =
    contentType.value && contentType.value.tag === 0x06 ? decodeOid(contentOf(der, contentType.value)) : null;
  const messageDigest =
    digest.value && digest.value.tag === 0x04 ? Buffer.from(contentOf(der, digest.value)) : null;
  return {
    detached: parsed.detached,
    eContentType: parsed.eContentType,
    digestOid: signer.digestOid,
    contentTypeOid,
    messageDigest,
    signingTimePresent: single(signer.attributes, OID.signingTime).present,
    signingCertificateV2Present: single(signer.attributes, OID.signingCertificateV2).present,
    approvalEvidence: readApprovalEvidence(der, signer.attributes),
    certs: parsed.certs,
  };
}
