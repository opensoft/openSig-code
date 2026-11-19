// SPDX-License-Identifier: Apache-2.0
//
// The shipped product verifier (T014): a separate module with its own ByteRange
// locator, revision-structure reader and DER decoder. It parses certificates
// with crypto.X509Certificate and evaluates trust against configured anchors
// only. It imports only node:* and src/verifier/** (VB-01); it shares no code
// with the signer (src/cryptograph/) or the parser (src/pdf/).
//
// Callers:
// - T038's finalization runner verifies the sealed bytes before completion:
//   verifyPdf(bytes, { anchors, expectedArtifactDigest, expectedApprovalEvidenceDigest,
//   validationTime }) and requires `accepted_as_original`. The anchors are the
//   PEM certificates of OPENSIG_TRUST_ANCHORS_FILE, which T038 reads and splits
//   with splitPemCertificates; without the setting it passes none.
// - T016 serves buildVerificationReport(outcome, { verifiedAt }) as
//   verification.json and GET /verification.
// - T017 labels its evidence with VERIFIER.name and VERIFIER.version.

export { verifyPdf, CHECK_IDS, DETAIL_CODES, EVIDENCE_STATES } from './verify.ts';
export type { CheckId, EvidenceState, VerificationOutcome, VerifierCheck, VerifyOptions } from './verify.ts';
export { buildVerificationReport, REPORT_LIMITS, REPORT_SCHEMA, VERIFIER } from './report.ts';
export type { ReportCheck, ReportResult, VerificationReport } from './report.ts';
export { VerifierConfigError, CONFIG_ERROR_CODES } from './errors.ts';
export type { ConfigErrorCode } from './errors.ts';
export { MAX_SEALED_PDF_BYTES, T033_PARSER_CEILINGS, VERIFIER_LIMITS } from './limits.ts';
export { splitPemCertificates } from './trust.ts';
export { readRevisionStructure, STRUCTURE_DETAILS } from './structure.ts';
export type { Revision, SignatureScan, StructureDetail, StructureResult } from './structure.ts';
