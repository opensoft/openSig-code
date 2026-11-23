// SPDX-License-Identifier: Apache-2.0
//
// The signer certificate as the seal builder needs it (T013): its exact DER,
// its issuer Name and serialNumber TLVs copied verbatim for the SignerInfo
// sid, and its public key, which must be RSA with a 3072-bit modulus and
// public exponent 65537. The certificate is at most 16 KiB of DER, refused
// before any parsing when larger (A-010, request #39). The
// structure walk is the minimum needed to find the issuer and serial
// (RFC 5280 § 4.1); crypto.X509Certificate parses the rest and supplies the
// public key. The certificate is not secret and its validity period is not
// judged here: trust and time belong to the verifier (T014).

import { X509Certificate, type KeyObject } from 'node:crypto';

import { DerError } from './der.ts';
import { children, encodingOf, readWhole, type DerElement } from './der-reader.ts';

export const SIGNER_MODULUS_BITS = 3072;
export const SIGNER_PUBLIC_EXPONENT = 65537n;
export const MAX_SIGNER_CERTIFICATE_BYTES = 16 * 1024;

export class CertificateError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'CertificateError';
    this.code = code;
  }
}

export interface SignerCertificate {
  /** The exact certificate encoding, as it goes into SignedData.certificates. */
  readonly der: Uint8Array;
  /** tbsCertificate.issuer, verbatim (a Name TLV). */
  readonly issuer: Uint8Array;
  /** tbsCertificate.serialNumber, verbatim (an INTEGER TLV). */
  readonly serialNumber: Uint8Array;
  /** The subject public key. */
  readonly publicKey: KeyObject;
}

function expectTag(element: DerElement | undefined, tag: number, what: string): DerElement {
  if (element === undefined || element.tag !== tag) {
    throw new CertificateError('certificate-malformed', `the signer certificate's ${what} is missing or malformed`);
  }
  return element;
}

export function parseSignerCertificate(certificateDer: Uint8Array): SignerCertificate {
  if (!(certificateDer instanceof Uint8Array) || certificateDer.length === 0) {
    throw new CertificateError('certificate-malformed', 'the signer certificate must be DER bytes');
  }
  if (certificateDer.length > MAX_SIGNER_CERTIFICATE_BYTES) {
    throw new CertificateError('certificate-too-large', `the signer certificate must be at most ${MAX_SIGNER_CERTIFICATE_BYTES} bytes of DER`);
  }
  const der = Uint8Array.from(certificateDer);
  let issuer: Uint8Array;
  let serialNumber: Uint8Array;
  try {
    const certificate = expectTag(readWhole(der), 0x30, 'Certificate');
    const parts = children(der, certificate);
    if (parts.length !== 3) throw new CertificateError('certificate-malformed', 'a Certificate has exactly three fields');
    const tbs = expectTag(parts[0], 0x30, 'tbsCertificate');
    const fields = children(der, tbs);
    let index = 0;
    if (fields[0]?.tag === 0xa0) index = 1; // [0] EXPLICIT version
    serialNumber = encodingOf(der, expectTag(fields[index], 0x02, 'serialNumber'));
    expectTag(fields[index + 1], 0x30, 'signature algorithm');
    issuer = encodingOf(der, expectTag(fields[index + 2], 0x30, 'issuer'));
  } catch (error) {
    if (error instanceof CertificateError) throw error;
    if (error instanceof DerError) throw new CertificateError('certificate-malformed', 'the signer certificate is not valid DER');
    throw error;
  }
  let x509: X509Certificate;
  try {
    x509 = new X509Certificate(Buffer.from(der));
  } catch {
    throw new CertificateError('certificate-malformed', 'the signer certificate cannot be parsed');
  }
  if (!Buffer.from(x509.raw).equals(Buffer.from(der))) {
    throw new CertificateError('certificate-malformed', 'the signer certificate has trailing or re-encoded content');
  }
  const publicKey = x509.publicKey;
  const details = publicKey.asymmetricKeyDetails;
  if (publicKey.asymmetricKeyType !== 'rsa' || details?.modulusLength !== SIGNER_MODULUS_BITS || details.publicExponent !== SIGNER_PUBLIC_EXPONENT) {
    throw new CertificateError(
      'certificate-key-unsupported',
      `the signer certificate must carry an RSA ${SIGNER_MODULUS_BITS}-bit public key with exponent ${SIGNER_PUBLIC_EXPONENT}`,
    );
  }
  return Object.freeze({ der, issuer, serialNumber, publicKey });
}
