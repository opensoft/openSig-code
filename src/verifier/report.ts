// SPDX-License-Identifier: Apache-2.0
//
// The VerificationReport (contract 0.2.3, components.schemas.VerificationReport)
// built from a verification outcome (T014, VB-02).
//
// The report is emitted only when every field fits the contract: the enums, the
// 64-hex digests, trust_anchor_ref of at most 100 characters or null, the
// verifier name (80) and version (40), a date-time verified_at, and check ids
// and detail codes of at most 60 characters. When a field cannot be filled
// within the contract (for example a foreign CMS without the approval-evidence
// attribute, whose `approval_evidence_digest` the contract requires as 64 hex),
// no report is emitted and the caller gets a refusal naming the field. A report
// is never truncated, padded or invented to fit, and the contract is unchanged
// (request #44): product-sealed output always carries both digests, so a
// product report is always emitted, while agreement uses the internal outcome.
//
// timestamp_status is `absent` (or `indeterminate` when a foreign CMS carries a
// time-stamp token the verifier does not evaluate); revocation_status is
// `not-checked`. verified_at is the caller's time, labelled unsigned server
// time by the contract; the verifier reads no clock.

import type { VerificationOutcome } from './verify.ts';

export const REPORT_SCHEMA = 'opensig.verification/1';

export const VERIFIER = Object.freeze({ name: 'opensig-product-verifier', version: '0.1.0' });

export const REPORT_LIMITS = Object.freeze({
  trustAnchorRef: 100,
  verifierName: 80,
  verifierVersion: 40,
  checkId: 60,
  detailCode: 60,
});

export interface ReportCheck {
  readonly id: string;
  readonly result: 'pass' | 'fail' | 'not-run';
  readonly detail_code?: string;
}

export interface VerificationReport {
  readonly schema: typeof REPORT_SCHEMA;
  readonly artifact_digest: string;
  readonly integrity: 'valid' | 'invalid' | 'indeterminate';
  readonly trust: 'trusted' | 'untrusted' | 'indeterminate';
  readonly trust_anchor_ref: string | null;
  readonly revision_coverage: 'complete' | 'incomplete' | 'indeterminate';
  readonly seal_type: 'organization';
  readonly signer_certificate_sha256: string;
  readonly approval_evidence_digest: string;
  readonly timestamp_status: 'trusted' | 'absent' | 'invalid' | 'indeterminate';
  readonly revocation_status: 'good' | 'revoked' | 'unknown' | 'not-checked';
  readonly verifier: { readonly name: string; readonly version: string };
  readonly verified_at: string;
  readonly checks: readonly ReportCheck[];
}

export type ReportResult =
  | { readonly ok: true; readonly report: VerificationReport }
  | { readonly ok: false; readonly code: 'report-field-unavailable' | 'report-limit'; readonly field: string };

const HEX64 = /^[0-9a-f]{64}$/;

function refused(code: 'report-field-unavailable' | 'report-limit', field: string): ReportResult {
  return { ok: false, code, field };
}

export function buildVerificationReport(outcome: VerificationOutcome, options: { readonly verifiedAt: Date }): ReportResult {
  const verifiedAt = options.verifiedAt;
  if (!(verifiedAt instanceof Date) || !Number.isFinite(verifiedAt.getTime())) return refused('report-limit', 'verified_at');
  if (!HEX64.test(outcome.artifact_digest)) return refused('report-limit', 'artifact_digest');
  if (outcome.signer_certificate_sha256 === null) return refused('report-field-unavailable', 'signer_certificate_sha256');
  if (!HEX64.test(outcome.signer_certificate_sha256)) return refused('report-limit', 'signer_certificate_sha256');
  if (outcome.approval_evidence_digest === null || !HEX64.test(outcome.approval_evidence_digest)) {
    return refused('report-field-unavailable', 'approval_evidence_digest');
  }
  if (outcome.trust_anchor_ref !== null && outcome.trust_anchor_ref.length > REPORT_LIMITS.trustAnchorRef) {
    return refused('report-limit', 'trust_anchor_ref');
  }
  if (VERIFIER.name.length > REPORT_LIMITS.verifierName || VERIFIER.version.length > REPORT_LIMITS.verifierVersion) {
    return refused('report-limit', 'verifier');
  }
  const checks: ReportCheck[] = [];
  for (const check of outcome.checks) {
    if (check.id.length > REPORT_LIMITS.checkId) return refused('report-limit', 'checks');
    if (check.detail !== null && check.detail.length > REPORT_LIMITS.detailCode) return refused('report-limit', 'checks');
    checks.push(check.detail === null ? { id: check.id, result: check.result } : { id: check.id, result: check.result, detail_code: check.detail });
  }
  const report: VerificationReport = {
    schema: REPORT_SCHEMA,
    artifact_digest: outcome.artifact_digest,
    integrity: outcome.integrity,
    trust: outcome.trust,
    trust_anchor_ref: outcome.trust_anchor_ref,
    revision_coverage: outcome.revision_coverage,
    seal_type: 'organization',
    signer_certificate_sha256: outcome.signer_certificate_sha256,
    approval_evidence_digest: outcome.approval_evidence_digest,
    timestamp_status: outcome.timestamp_status,
    revocation_status: outcome.revocation_status,
    verifier: { name: VERIFIER.name, version: VERIFIER.version },
    verified_at: verifiedAt.toISOString(),
    checks,
  };
  return { ok: true, report };
}
