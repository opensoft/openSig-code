// SPDX-License-Identifier: Apache-2.0
//
// Object identifiers of the openSig seal profile (T013). Sources: RFC 5652
// (CMS content types and the contentType and messageDigest attributes),
// RFC 5035 (signingCertificateV2), RFC 5754 (SHA-256), RFC 4055 (PKCS#1 v1.5
// with SHA-256) and tasks.md T013 / data-model.md FinalArtifact (A-008, S1)
// for the openSig approval-evidence attribute.

export const OID = Object.freeze({
  /** id-data (RFC 5652 § 4): the eContentType and the contentType attribute value. */
  data: '1.2.840.113549.1.7.1',
  /** id-signedData (RFC 5652 § 5.1). */
  signedData: '1.2.840.113549.1.7.2',
  /** id-contentType (RFC 5652 § 11.1). */
  contentType: '1.2.840.113549.1.9.3',
  /** id-messageDigest (RFC 5652 § 11.2). */
  messageDigest: '1.2.840.113549.1.9.4',
  /** id-signingTime (RFC 5652 § 11.3). The profile never emits it; named so tests can refuse it. */
  signingTime: '1.2.840.113549.1.9.5',
  /** id-aa-signingCertificateV2 (RFC 5035 § 3). */
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  /** opensig-approval-evidence-digest (A-008, S1): SHA-256 of the pre-seal approval manifest. */
  approvalEvidenceDigest: '2.25.254263291653419018820250361524609646248',
  /** id-sha256 (RFC 5754 § 2). */
  sha256: '2.16.840.1.101.3.4.2.1',
  /** sha256WithRSAEncryption (RFC 4055 § 5): RSASSA-PKCS1-v1_5 with SHA-256. */
  sha256WithRSAEncryption: '1.2.840.113549.1.1.11',
});
