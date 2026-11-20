// SPDX-License-Identifier: Apache-2.0
//
// The CMS seal surface (T013) for the sealing worker (T037): the DER encoder,
// the strict reader used for the signer certificate, and the detached
// SignedData builder.

export {
  compareDer,
  concat,
  contextConstructed,
  DerError,
  derNull,
  encodeLength,
  integer,
  MAX_DER_LENGTH,
  objectIdentifier,
  octetString,
  sequence,
  setOf,
  sortedSetContent,
  tlv,
} from './der.ts';
export { children, contentOf, encodingOf, readElement, readWhole, type DerElement } from './der-reader.ts';
export {
  CertificateError,
  MAX_SIGNER_CERTIFICATE_BYTES,
  parseSignerCertificate,
  SIGNER_MODULUS_BITS,
  SIGNER_PUBLIC_EXPONENT,
  type SignerCertificate,
} from './certificate.ts';
export { OID } from './oids.ts';
export {
  buildDetachedSignedData,
  CmsBuildError,
  contentDigestOf,
  SEAL_SIGNATURE_BYTES,
  SHA256_BYTES,
  signedDataLength,
  type DetachedSignedDataInput,
} from './signed-data.ts';
