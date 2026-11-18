// SPDX-License-Identifier: Apache-2.0
//
// Detached CMS SignedData for the openSig organization seal (T013; RFC 5652;
// research.md § Engine decision; data-model.md FinalArtifact, A-008 S1).
//
// ContentInfo { id-signedData, [0] EXPLICIT SignedData {
//   version 1,
//   digestAlgorithms { sha256 (parameters absent, RFC 5754 § 2) },
//   encapContentInfo { id-data }               -- no eContent: detached
//   certificates [0] IMPLICIT { signer certificate, verbatim },
//   signerInfos { SignerInfo {
//     version 1,
//     sid issuerAndSerialNumber (the certificate's issuer and serial, verbatim),
//     digestAlgorithm sha256 (parameters absent),
//     signedAttrs [0] IMPLICIT SET OF, in DER order {
//       contentType id-data,
//       messageDigest OCTET STRING (32),
//       signingCertificateV2 { certs { ESSCertIDv2 { certHash } } },
//       opensig-approval-evidence-digest OCTET STRING (32) },
//     signatureAlgorithm sha256WithRSAEncryption (parameters NULL, RFC 4055 § 5),
//     signature OCTET STRING (384) } } } }
//
// No signingTime and no unsigned attributes. The versions follow RFC 5652
// § 5.1 and § 5.3 for an issuerAndSerialNumber sid, id-data content and no
// attribute certificates. ESSCertIDv2 holds its certHash only: hashAlgorithm
// is omitted because SHA-256 is its DEFAULT (X.690 § 11.5), and the OPTIONAL
// issuerSerial is omitted. `certificates` holds exactly the signer
// certificate (at most 16 KiB of DER). This profile is the one ratified in
// A-010, request #39 (Part F). The signature is computed over
// the DER of the signed attributes as a SET (tag 0x31), not over the [0]
// IMPLICIT field (RFC 5652 § 5.4); both carry the same content octets.
//
// PKCS#1 v1.5 is deterministic and nothing in the profile depends on time, so
// equal inputs give equal bytes, and the output length depends only on the
// certificate (signedDataLength).

import { createHash, verify, constants as cryptoConstants } from 'node:crypto';

import type { SealSigner } from '../keys/development-key.ts';
import { parseSignerCertificate, type SignerCertificate } from './certificate.ts';
import { derNull, integer, objectIdentifier, octetString, sequence, setOf, sortedSetContent, tlv } from './der.ts';
import { OID } from './oids.ts';

export const SHA256_BYTES = 32;
export const SEAL_SIGNATURE_BYTES = 384;

export class CmsBuildError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'CmsBuildError';
    this.code = code;
  }
}

export interface DetachedSignedDataInput {
  /** SHA-256 over the signed content (for a PDF seal, the ByteRange bytes in order). */
  readonly contentDigest: Uint8Array;
  /** SHA-256 of the pre-seal approval manifest (FinalArtifact.approval_evidence_digest as bytes). */
  readonly approvalEvidenceDigest: Uint8Array;
  /** The signer certificate, DER. */
  readonly certificateDer: Uint8Array;
  /** The key custodian; for development, loadDevelopmentSealKey. */
  readonly signer: SealSigner;
}

const SHA256_ALGORITHM = sequence(objectIdentifier(OID.sha256));
const SIGNATURE_ALGORITHM = sequence(objectIdentifier(OID.sha256WithRSAEncryption), derNull());

function sha256(data: Uint8Array): Uint8Array {
  return createHash('sha256').update(data).digest();
}

/** SHA-256 over the concatenation of `parts` (for example the two ByteRange spans). */
export function contentDigestOf(parts: Iterable<Uint8Array>): Uint8Array {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function attribute(type: string, value: Uint8Array): Uint8Array {
  return sequence(objectIdentifier(type), setOf([value]));
}

/** SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 } (policies absent). */
function signingCertificateV2(certificateDer: Uint8Array): Uint8Array {
  const essCertIdV2 = sequence(octetString(sha256(certificateDer)));
  return sequence(sequence(essCertIdV2));
}

/** The content octets shared by the signed SET (0x31) and the [0] IMPLICIT field (0xA0). */
function signedAttributesContent(contentDigest: Uint8Array, approvalEvidenceDigest: Uint8Array, certificateDer: Uint8Array): Uint8Array {
  return sortedSetContent([
    attribute(OID.contentType, objectIdentifier(OID.data)),
    attribute(OID.messageDigest, octetString(contentDigest)),
    attribute(OID.signingCertificateV2, signingCertificateV2(certificateDer)),
    attribute(OID.approvalEvidenceDigest, octetString(approvalEvidenceDigest)),
  ]);
}

function assemble(certificate: SignerCertificate, attributesContent: Uint8Array, signature: Uint8Array): Uint8Array {
  const signerInfo = sequence(
    integer(1),
    sequence(certificate.issuer, certificate.serialNumber),
    SHA256_ALGORITHM,
    tlv(0xa0, attributesContent),
    SIGNATURE_ALGORITHM,
    octetString(signature),
  );
  const signedData = sequence(
    integer(1),
    setOf([SHA256_ALGORITHM]),
    sequence(objectIdentifier(OID.data)),
    tlv(0xa0, sortedSetContent([certificate.der])),
    setOf([signerInfo]),
  );
  return sequence(objectIdentifier(OID.signedData), tlv(0xa0, signedData));
}

function digestInput(value: unknown, name: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== SHA256_BYTES) {
    throw new CmsBuildError('digest-invalid', `${name} must be ${SHA256_BYTES} bytes`);
  }
  return Uint8Array.from(value);
}

function checkSigner(signer: unknown, certificate: SignerCertificate): SealSigner {
  const candidate = signer as Partial<SealSigner> | null;
  if (typeof candidate !== 'object' || candidate === null || typeof candidate.sign !== 'function' || candidate.publicKey?.type !== 'public') {
    throw new CmsBuildError('signer-invalid', 'the signer must provide a public key and a sign function');
  }
  const signerKey = candidate.publicKey.export({ type: 'spki', format: 'der' });
  const certificateKey = certificate.publicKey.export({ type: 'spki', format: 'der' });
  if (!signerKey.equals(certificateKey)) {
    throw new CmsBuildError('key-certificate-mismatch', "the signer's key does not match the certificate's public key");
  }
  return candidate as SealSigner;
}

/** Build the DER ContentInfo of a detached SignedData sealing `contentDigest`. */
export function buildDetachedSignedData(input: DetachedSignedDataInput): Uint8Array {
  if (typeof input !== 'object' || input === null) throw new CmsBuildError('input-invalid', 'the seal input must be an object');
  const contentDigest = digestInput(input.contentDigest, 'the content digest');
  const approvalEvidenceDigest = digestInput(input.approvalEvidenceDigest, 'the approval-evidence digest');
  const certificate = parseSignerCertificate(input.certificateDer);
  const signer = checkSigner(input.signer, certificate);
  const attributesContent = signedAttributesContent(contentDigest, approvalEvidenceDigest, certificate.der);
  const toBeSigned = tlv(0x31, attributesContent);
  const signature = signer.sign(toBeSigned);
  if (!(signature instanceof Uint8Array) || signature.length !== SEAL_SIGNATURE_BYTES) {
    throw new CmsBuildError('signature-invalid', `the seal signature must be ${SEAL_SIGNATURE_BYTES} bytes`);
  }
  const verifies = verify('sha256', toBeSigned, { key: certificate.publicKey, padding: cryptoConstants.RSA_PKCS1_PADDING }, signature);
  if (!verifies) throw new CmsBuildError('signature-self-check-failed', 'the seal signature does not verify under the certificate key');
  return assemble(certificate, attributesContent, Uint8Array.from(signature));
}

/**
 * The exact DER length of buildDetachedSignedData's output for this
 * certificate. Every other field has a fixed size (two 32-byte digests and a
 * 384-byte signature). T036's /Contents placeholder holds exactly twice this
 * many hex digits, with no padding, and T037 refuses any other length
 * (request #39, Part F).
 */
export function signedDataLength(certificateDer: Uint8Array): number {
  const certificate = parseSignerCertificate(certificateDer);
  const zeros = new Uint8Array(SHA256_BYTES);
  return assemble(certificate, signedAttributesContent(zeros, zeros, certificate.der), new Uint8Array(SEAL_SIGNATURE_BYTES)).length;
}
