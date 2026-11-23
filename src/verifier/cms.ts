// SPDX-License-Identifier: Apache-2.0
//
// The verifier's own CMS SignedData checks (T014), written from RFC 5652,
// RFC 5035 and the product profile stated in the T013 line. It shares no code
// with src/cryptograph/ (VB-01); certificates are parsed by crypto.X509Certificate.
//
// Accepted (request #39, Part F), because the oracle corpus is made by OpenSSL
// and the product profile is narrower:
// - signatureAlgorithm sha256WithRSAEncryption or rsaEncryption, each with NULL
//   parameters; the signature is RSA PKCS#1 v1.5 with SHA-256;
// - a sid that is issuerAndSerialNumber (SignerInfo version 1) or
//   subjectKeyIdentifier (version 3), matching an embedded certificate;
// - an ESSCertIDv2 with or without issuerSerial, its hashAlgorithm omitted
//   (SHA-256) or SHA-256. When signingCertificateV2 is present it must bind the
//   signer certificate; a foreign CMS without it is accepted and reported as
//   the profile check `signing-certificate-v2-absent` (request #44).
// Checked:
// - detached id-data, one SignerInfo, SHA-256 digest algorithm;
// - signedAttrs present, DER-sorted, with one contentType (id-data) and one
//   32-byte messageDigest; messageDigest equals SHA-256 over the stated ranges;
// - the signature verifies over signedAttrs re-tagged as a SET (0x31) with the
//   signer certificate's RSA key (crypto.verify), never over messageDigest alone.
// Reported, never changing integrity, trust or coverage:
// - signingTime (OpenSSL adds it by default): `signingTimePresent`;
// - signingCertificateV2 present or not: `signingCertificateV2Present`;
// - a signature time-stamp token in unsignedAttrs: `timestampTokenPresent`;
// - the opensig-approval-evidence-digest attribute (VB-03): `evidence`.
// Outside what T014 evaluates (integrity `indeterminate`, never `invalid`;
// VB-10, request #58 (4)): two or more SignerInfos, more than maxCertificates
// certificates, a non-certificate CertificateChoice, a digest other than
// SHA-256, another signature algorithm, a non-RSA or sub-2048-bit signer key.

import { Buffer } from 'node:buffer';
import { constants, createHash, verify as verifySignature, X509Certificate } from 'node:crypto';
import { VERIFIER_LIMITS } from './limits.ts';
import {
  algorithmIdentifier,
  bytesEqual,
  children,
  compareDerElements,
  DER_FAULTS,
  DerFault,
  encodingOf,
  expectTag,
  oidOf,
  readWhole,
  smallInteger,
  TAG,
  valueOf,
  type Tlv,
} from './der.ts';

export const OID = Object.freeze({
  signedData: '1.2.840.113549.1.7.2',
  data: '1.2.840.113549.1.7.1',
  sha256: '2.16.840.1.101.3.4.2.1',
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRSAEncryption: '1.2.840.113549.1.1.11',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  signatureTimeStampToken: '1.2.840.113549.1.9.16.2.14',
  approvalEvidenceDigest: '2.25.254263291653419018820250361524609646248',
  subjectKeyIdentifier: '2.5.29.14',
});

export const CMS_DETAILS = [
  ...DER_FAULTS.map((code) => `der-${code}` as const),
  'content-info-shape',
  'not-signed-data',
  'signed-data-shape',
  'signed-data-version',
  'digest-algorithms-missing-sha256',
  'econtent-type',
  'not-detached',
  'no-signer-info',
  'multiple-signer-infos',
  'too-many-certificates',
  'certificate-choice-unsupported',
  'certificate-too-large',
  'certificate-unparsable',
  'signer-info-shape',
  'sid-shape',
  'sid-version',
  'digest-algorithm-unsupported',
  'digest-algorithm-parameters',
  'signed-attributes-missing',
  'signed-attributes-not-der-sorted',
  'duplicate-signed-attribute',
  'content-type-attribute',
  'message-digest-attribute',
  'signer-certificate-not-found',
  'signing-certificate-v2-malformed',
  'ess-hash-unsupported',
  'ess-cert-hash-mismatch',
  'ess-issuer-serial-mismatch',
  'message-digest-mismatch',
  'signature-algorithm-unsupported',
  'signature-algorithm-parameters',
  'signer-key-unsupported',
  'signer-key-too-small',
  'signature-invalid',
] as const;

export type CmsDetail = (typeof CMS_DETAILS)[number];
export type Step = 'pass' | 'fail' | 'unsupported' | 'not-run';

export type EvidenceAttribute =
  | { readonly state: 'absent' }
  | { readonly state: 'present'; readonly hex: string }
  | { readonly state: 'malformed'; readonly hex: string | null };

export interface CmsEvaluation {
  readonly structure: Step;
  readonly structureDetail: CmsDetail | null;
  readonly binding: Step;
  readonly bindingDetail: CmsDetail | null;
  readonly messageDigest: Step;
  readonly signature: Step;
  readonly signatureDetail: CmsDetail | null;
  readonly signer: X509Certificate | null;
  readonly signerDer: Uint8Array | null;
  /** Every embedded certificate, the signer included, for path building. */
  readonly certificates: readonly X509Certificate[];
  readonly signingTimePresent: boolean | null;
  /** false for a foreign CMS without signingCertificateV2: a profile check, not an integrity failure. */
  readonly signingCertificateV2Present: boolean | null;
  readonly timestampTokenPresent: boolean;
  /** null when the signed attributes could not be read. */
  readonly evidence: EvidenceAttribute | null;
}

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

class CmsFault extends Error {
  readonly detail: CmsDetail;
  readonly unsupported: boolean;

  constructor(detail: CmsDetail, unsupported: boolean) {
    super(detail);
    this.detail = detail;
    this.unsupported = unsupported;
  }
}

function malformed(detail: CmsDetail): never {
  throw new CmsFault(detail, false);
}

function unsupported(detail: CmsDetail): never {
  throw new CmsFault(detail, true);
}

interface CertificateFields {
  readonly certificate: X509Certificate;
  readonly der: Uint8Array;
  readonly issuer: Uint8Array;
  readonly serial: Uint8Array;
  readonly subjectKeyIdentifier: Uint8Array | null;
}

type Attributes = Map<string, Tlv[][]>;

const SINGLE_INSTANCE = [
  OID.contentType,
  OID.messageDigest,
  OID.signingTime,
  OID.signingCertificateV2,
  OID.approvalEvidenceDigest,
];

/** Evaluate `der` (one SignedData ContentInfo) against `contentDigest` (SHA-256 over the stated ranges). */
export function evaluateCms(der: Uint8Array, contentDigest: Uint8Array): CmsEvaluation {
  const result: Mutable<CmsEvaluation> = {
    structure: 'not-run',
    structureDetail: null,
    binding: 'not-run',
    bindingDetail: null,
    messageDigest: 'not-run',
    signature: 'not-run',
    signatureDetail: null,
    signer: null,
    signerDer: null,
    certificates: [],
    signingTimePresent: null,
    signingCertificateV2Present: null,
    timestampTokenPresent: false,
    evidence: null,
  };
  try {
    evaluate(der, contentDigest, result);
  } catch (error) {
    if (error instanceof DerFault) {
      result.structure = 'fail';
      result.structureDetail = `der-${error.code}` as const;
    } else if (error instanceof CmsFault) {
      result.structure = error.unsupported ? 'unsupported' : 'fail';
      result.structureDetail = error.detail;
    } else {
      throw error;
    }
  }
  return result;
}

function evaluate(der: Uint8Array, contentDigest: Uint8Array, result: Mutable<CmsEvaluation>): void {
  // ContentInfo
  const contentInfo = expectTag(readWhole(der), TAG.SEQUENCE);
  const ciParts = children(der, contentInfo, 2);
  if (ciParts.length !== 2) malformed('content-info-shape');
  if (oidOf(der, expectTag(ciParts[0], TAG.OID)) !== OID.signedData) malformed('not-signed-data');
  const wrapped = children(der, expectTag(ciParts[1], TAG.CONTEXT_0), 1);
  const signedData = expectTag(wrapped[0], TAG.SEQUENCE);

  // SignedData
  const parts = children(der, signedData, 6);
  let i = 0;
  const sdVersion = smallInteger(der, parts[i++]);
  const digestAlgorithms = children(der, expectTag(parts[i++], TAG.SET), 16).map((t) => algorithmIdentifier(der, t));
  const encap = children(der, expectTag(parts[i++], TAG.SEQUENCE), 2);
  if (oidOf(der, expectTag(encap[0], TAG.OID)) !== OID.data) malformed('econtent-type');
  if (encap.length !== 1) malformed('not-detached');
  const certificatesTlv = parts[i]?.tag === TAG.CONTEXT_0 ? parts[i++] : undefined;
  if (parts[i]?.tag === TAG.CONTEXT_1) i += 1; // crls: revocation is not checked
  const infosTlv = expectTag(parts[i++], TAG.SET);
  if (i !== parts.length) malformed('signed-data-shape');
  // Every SignerInfo is counted (each takes at least two bytes of the bounded
  // CMS), so two or more is unsupported, never malformed (VB-10).
  const infos = children(der, infosTlv, VERIFIER_LIMITS.maxCmsBytes);
  if (infos.length === 0) malformed('no-signer-info');
  if (infos.length > 1) unsupported('multiple-signer-infos');

  // Certificates
  const certificates = certificatesTlv === undefined ? [] : readCertificates(der, certificatesTlv);
  result.certificates = certificates.map((c) => c.certificate);

  // SignerInfo
  const si = children(der, expectTag(infos[0], TAG.SEQUENCE), 7);
  let j = 0;
  const siVersion = smallInteger(der, si[j++]);
  const sid = si[j++];
  if (sid === undefined) malformed('signer-info-shape');
  const digestAlgorithm = algorithmIdentifier(der, si[j++]);
  const signedAttrsTlv = si[j]?.tag === TAG.CONTEXT_0 ? si[j++] : undefined;
  const signatureAlgorithm = algorithmIdentifier(der, si[j++]);
  const signatureValue = valueOf(der, expectTag(si[j++], TAG.OCTET_STRING));
  const unsignedAttrsTlv = si[j]?.tag === TAG.CONTEXT_1 ? si[j++] : undefined;
  if (j !== si.length) malformed('signer-info-shape');
  if (signedAttrsTlv === undefined) malformed('signed-attributes-missing');

  const sidKind: 'issuer-serial' | 'ski' =
    sid.tag === TAG.SEQUENCE ? 'issuer-serial' : sid.tag === TAG.CONTEXT_0_PRIMITIVE ? 'ski' : malformed('sid-shape');
  if (siVersion !== (sidKind === 'issuer-serial' ? 1 : 3)) malformed('sid-version');
  // Detached id-data: the SignedData version follows the SignerInfo's (RFC 5652, 5.1).
  if (sdVersion !== siVersion) malformed('signed-data-version');

  if (digestAlgorithm.oid !== OID.sha256) unsupported('digest-algorithm-unsupported');
  if (digestAlgorithm.parameters === 'other') malformed('digest-algorithm-parameters');
  if (!digestAlgorithms.some((a) => a.oid === OID.sha256)) malformed('digest-algorithms-missing-sha256');

  // Signed attributes
  const attributes = readAttributes(der, signedAttrsTlv, true);
  result.signingTimePresent = attributes.has(OID.signingTime);
  result.signingCertificateV2Present = attributes.has(OID.signingCertificateV2);
  result.evidence = evidenceOf(der, attributes);
  for (const oid of SINGLE_INSTANCE) {
    if ((attributes.get(oid)?.length ?? 0) > 1) malformed('duplicate-signed-attribute');
  }
  const contentType = singleValue(attributes, OID.contentType);
  if (contentType === undefined || oidOf(der, expectTag(contentType, TAG.OID)) !== OID.data) malformed('content-type-attribute');
  const digestTlv = singleValue(attributes, OID.messageDigest);
  if (digestTlv === undefined || digestTlv.tag !== TAG.OCTET_STRING) malformed('message-digest-attribute');
  const messageDigest = valueOf(der, digestTlv);
  if (messageDigest.length !== 32) malformed('message-digest-attribute');

  if (unsignedAttrsTlv !== undefined) {
    result.timestampTokenPresent = readAttributes(der, unsignedAttrsTlv, false).has(OID.signatureTimeStampToken);
  }
  result.structure = 'pass';

  // Signer binding: the sid names an embedded certificate; signingCertificateV2, when present, binds it.
  const signer = certificates.find((c) => matchesSid(der, sid, sidKind, c));
  result.messageDigest = bytesEqual(messageDigest, contentDigest) ? 'pass' : 'fail';
  if (signer === undefined) {
    result.binding = 'fail';
    result.bindingDetail = 'signer-certificate-not-found';
    return;
  }
  result.signer = signer.certificate;
  result.signerDer = signer.der;
  const essResult = checkSigningCertificateV2(der, attributes, signer);
  result.binding = essResult.step;
  result.bindingDetail = essResult.detail;

  // Signature over the signedAttrs SET.
  const signature = checkSignature(der, signedAttrsTlv, signatureAlgorithm, signatureValue, signer.certificate);
  result.signature = signature.step;
  result.signatureDetail = signature.detail;
}

function readCertificates(der: Uint8Array, tlv: Tlv): CertificateFields[] {
  const out: CertificateFields[] = [];
  // Every certificate is counted first (each takes at least two bytes of the
  // bounded CMS); more than maxCertificates is unsupported, never malformed (VB-10).
  const items = children(der, tlv, VERIFIER_LIMITS.maxCmsBytes);
  if (items.length > VERIFIER_LIMITS.maxCertificates) unsupported('too-many-certificates');
  for (const item of items) {
    if (item.tag !== TAG.SEQUENCE) unsupported('certificate-choice-unsupported');
    const encoding = encodingOf(der, item);
    if (encoding.length > VERIFIER_LIMITS.maxCertificateBytes) malformed('certificate-too-large');
    let certificate: X509Certificate;
    try {
      certificate = new X509Certificate(Buffer.from(encoding));
    } catch {
      return malformed('certificate-unparsable');
    }
    out.push({ certificate, der: Uint8Array.from(encoding), ...certificateFields(der, item) });
  }
  return out;
}

/** issuer Name encoding, serialNumber content bytes and subjectKeyIdentifier, read from the TBSCertificate. */
function certificateFields(der: Uint8Array, certificate: Tlv): Pick<CertificateFields, 'issuer' | 'serial' | 'subjectKeyIdentifier'> {
  const outer = children(der, certificate, 3);
  const tbs = children(der, expectTag(outer[0], TAG.SEQUENCE), 10);
  let k = tbs[0]?.tag === TAG.CONTEXT_0 ? 1 : 0;
  const serial = valueOf(der, expectTag(tbs[k++], TAG.INTEGER));
  k += 1; // signature algorithm
  const issuer = encodingOf(der, expectTag(tbs[k++], TAG.SEQUENCE));
  let subjectKeyIdentifier: Uint8Array | null = null;
  const extensions = tbs.find((t) => t.tag === TAG.CONTEXT_3);
  if (extensions !== undefined) {
    const list = children(der, expectTag(children(der, extensions, 1)[0], TAG.SEQUENCE), 64);
    for (const extension of list) {
      const fields = children(der, expectTag(extension, TAG.SEQUENCE), 3);
      if (oidOf(der, expectTag(fields[0], TAG.OID)) !== OID.subjectKeyIdentifier) continue;
      const wrapper = valueOf(der, expectTag(fields[fields.length - 1], TAG.OCTET_STRING));
      subjectKeyIdentifier = valueOf(wrapper, expectTag(readWhole(wrapper), TAG.OCTET_STRING));
    }
  }
  return { issuer, serial, subjectKeyIdentifier };
}

function readAttributes(der: Uint8Array, tlv: Tlv, requireDerOrder: boolean): Attributes {
  const elements = children(der, tlv, 32);
  if (requireDerOrder) {
    for (let k = 1; k < elements.length; k += 1) {
      const previous = elements[k - 1];
      const current = elements[k];
      if (previous !== undefined && current !== undefined && compareDerElements(encodingOf(der, previous), encodingOf(der, current)) > 0) {
        malformed('signed-attributes-not-der-sorted');
      }
    }
  }
  const attributes: Attributes = new Map();
  for (const element of elements) {
    const fields = children(der, expectTag(element, TAG.SEQUENCE), 2);
    if (fields.length !== 2) throw new DerFault('unexpected-tag');
    const oid = oidOf(der, expectTag(fields[0], TAG.OID));
    const values = children(der, expectTag(fields[1], TAG.SET), 16);
    if (values.length === 0) throw new DerFault('unexpected-tag');
    const list = attributes.get(oid) ?? [];
    list.push(values);
    attributes.set(oid, list);
  }
  return attributes;
}

function singleValue(attributes: Attributes, oid: string): Tlv | undefined {
  const instances = attributes.get(oid);
  if (instances === undefined || instances.length !== 1) return undefined;
  const values = instances[0];
  if (values === undefined || values.length !== 1) return undefined;
  return values[0];
}

function evidenceOf(der: Uint8Array, attributes: Attributes): EvidenceAttribute {
  const instances = attributes.get(OID.approvalEvidenceDigest);
  if (instances === undefined) return { state: 'absent' };
  const value = singleValue(attributes, OID.approvalEvidenceDigest);
  if (value === undefined || value.tag !== TAG.OCTET_STRING) return { state: 'malformed', hex: null };
  const bytes = valueOf(der, value);
  if (bytes.length === 32) return { state: 'present', hex: hex(bytes) };
  return { state: 'malformed', hex: bytes.length > 0 && bytes.length <= 64 ? hex(bytes) : null };
}

function matchesSid(der: Uint8Array, sid: Tlv, kind: 'issuer-serial' | 'ski', candidate: CertificateFields): boolean {
  if (kind === 'ski') {
    return candidate.subjectKeyIdentifier !== null && bytesEqual(valueOf(der, sid), candidate.subjectKeyIdentifier);
  }
  const fields = children(der, sid, 2);
  const name = fields[0];
  const serial = fields[1];
  if (name === undefined || serial === undefined || name.tag !== TAG.SEQUENCE || serial.tag !== TAG.INTEGER) return false;
  return bytesEqual(encodingOf(der, name), candidate.issuer) && bytesEqual(valueOf(der, serial), candidate.serial);
}

function checkSigningCertificateV2(
  der: Uint8Array,
  attributes: Attributes,
  signer: CertificateFields,
): { step: Step; detail: CmsDetail | null } {
  if (!attributes.has(OID.signingCertificateV2)) return { step: 'pass', detail: null };
  try {
    const value = singleValue(attributes, OID.signingCertificateV2);
    const top = children(der, expectTag(value, TAG.SEQUENCE), 2);
    const certs = children(der, expectTag(top[0], TAG.SEQUENCE), 16);
    const first = children(der, expectTag(certs[0], TAG.SEQUENCE), 3);
    let k = 0;
    if (first[0]?.tag === TAG.SEQUENCE) {
      if (algorithmIdentifier(der, first[0]).oid !== OID.sha256) return { step: 'unsupported', detail: 'ess-hash-unsupported' };
      k = 1;
    }
    const certHash = valueOf(der, expectTag(first[k], TAG.OCTET_STRING));
    const issuerSerial = first[k + 1];
    if (first.length > k + 2) return { step: 'fail', detail: 'signing-certificate-v2-malformed' };
    if (!bytesEqual(certHash, createHash('sha256').update(signer.der).digest())) {
      return { step: 'fail', detail: 'ess-cert-hash-mismatch' };
    }
    if (issuerSerial !== undefined) {
      const [names, serial] = children(der, expectTag(issuerSerial, TAG.SEQUENCE), 2);
      const generalNames = children(der, expectTag(names, TAG.SEQUENCE), 4);
      const directoryName = generalNames[0];
      if (generalNames.length !== 1 || directoryName === undefined || directoryName.tag !== TAG.CONTEXT_4) {
        return { step: 'fail', detail: 'ess-issuer-serial-mismatch' };
      }
      const name = expectTag(children(der, directoryName, 1)[0], TAG.SEQUENCE);
      const serialValue = valueOf(der, expectTag(serial, TAG.INTEGER));
      if (!bytesEqual(encodingOf(der, name), signer.issuer) || !bytesEqual(serialValue, signer.serial)) {
        return { step: 'fail', detail: 'ess-issuer-serial-mismatch' };
      }
    }
    return { step: 'pass', detail: null };
  } catch (error) {
    if (error instanceof DerFault) return { step: 'fail', detail: 'signing-certificate-v2-malformed' };
    throw error;
  }
}

function checkSignature(
  der: Uint8Array,
  signedAttrs: Tlv,
  algorithm: { oid: string; parameters: 'absent' | 'null' | 'other' },
  signatureValue: Uint8Array,
  signer: X509Certificate,
): { step: Step; detail: CmsDetail | null } {
  if (algorithm.oid !== OID.rsaEncryption && algorithm.oid !== OID.sha256WithRSAEncryption) {
    return { step: 'unsupported', detail: 'signature-algorithm-unsupported' };
  }
  if (algorithm.parameters !== 'null') return { step: 'fail', detail: 'signature-algorithm-parameters' };
  const key = signer.publicKey;
  if (key.asymmetricKeyType !== 'rsa') return { step: 'unsupported', detail: 'signer-key-unsupported' };
  if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) return { step: 'unsupported', detail: 'signer-key-too-small' };
  // RFC 5652, 5.4: the signature covers the DER of the attributes as a SET OF,
  // so the [0] IMPLICIT tag (0xA0) is replaced by the SET tag (0x31).
  const set = Uint8Array.from(encodingOf(der, signedAttrs));
  set[0] = TAG.SET;
  const ok = verifySignature('sha256', set, { key, padding: constants.RSA_PKCS1_PADDING }, signatureValue);
  return ok ? { step: 'pass', detail: null } : { step: 'fail', detail: 'signature-invalid' };
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('hex');
}
