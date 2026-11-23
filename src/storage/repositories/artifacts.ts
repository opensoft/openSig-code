// SPDX-License-Identifier: Apache-2.0
//
// FinalArtifact and VerificationReport writes (T038; data-model.md § Entities,
// FinalArtifact and VerificationReport; migrations 0005, 0009 and 0019),
// through the tenant-scoped store only. Both inserts run only inside the
// publish transaction (src/domain/finalization/publish.ts), in the caller's
// Database.transaction (BEGIN IMMEDIATE).
//
// Row P13: 0005's columns are wider than the contract (verifier name 100 vs
// 80, version 50 vs 40, trust_anchor_ref 200 vs 100, a nullable signer
// digest), so every value is checked against the contract here, before the
// insert, and a refusal names the field, never its value. 0005 and 0019 back
// the rest: the blob refs are derived from the digests, one artifact per
// envelope, the fencing trigger, the required 64-hex approval_evidence_digest
// (0019, request #59 (2)) and the no-replace guards (0019, FEN-09).
//
// The package digest and package blob ref are written in the same insert
// (A-010, S4), never later through 0005's record-once update. The publish
// writes exactly one verification_reports row, whose report_bytes are the
// exact bytes of T014's report, and final_artifacts.verification_json holds
// the same report (request #59 (9)).

import { parseJson } from '../../domain/canonical/index.ts';
import { blobRef } from '../blobs/refs.ts';
import type { TenantStore } from '../db/index.ts';
import { StorageError, StorageUsageError } from '../db/index.ts';

/** Contract VerificationReport.verifier.name and .version maxLength, and trust_anchor_ref (row P13). */
export const MAX_VERIFIER_NAME = 80;
export const MAX_VERIFIER_VERSION = 40;
export const MAX_TRUST_ANCHOR_REF = 100;
/** 0005: CHECK (length(report_bytes) BETWEEN 2 AND 1048576). */
export const MAX_REPORT_BYTES = 1_048_576;
export const REPORT_SCHEMA = 'opensig.verification/1';

const ID = /^[A-Za-z0-9_-]{16,64}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SERVER_TIME = /^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d{3}Z$/;

/** A value outside the contract: refused before any write. The message names the field only. */
export class FinalArtifactInvalid extends StorageError {
  readonly field: string;

  constructor(field: string) {
    super('final_artifact_invalid', `final artifact ${field} is outside the contract limits`);
    this.field = field;
  }
}

export interface NewFinalArtifact {
  readonly artifactId: string;
  readonly envelopeId: string;
  /** SHA-256 of final.pdf; the PDF blob ref is derived from it. */
  readonly artifactDigest: string;
  /** SHA-256 of the package ZIP; the package blob ref is derived from it. */
  readonly packageDigest: string;
  readonly approvedCompositionDigest: string;
  /** SHA-256 of the stored evidence blob; the evidence blob ref is derived from it. */
  readonly evidenceDigest: string;
  /** SHA-256 of approval-manifest.json's RFC 8785 form without final_pdf_digest (FEN-07). */
  readonly approvalEvidenceDigest: string;
  readonly signerCertificateSha256: string;
  readonly developmentCertificate: boolean;
  readonly verifierName: string;
  readonly verifierVersion: string;
  /** T014's report, as the UTF-8 text of its exact bytes (a JSON object). */
  readonly verificationJson: string;
  /** The fencing token of the publishing attempt. */
  readonly fencingToken: number;
  readonly completedAt: string;
}

/** The shape of T029's CompletionCheckpoint, which T016's builder takes as `checkpoint`. */
export interface CompletionCheckpointRow {
  readonly seq: number;
  readonly digest: string;
  readonly created_at: string;
}

/** The contract VerificationReport fields the verification_reports row stores, read from the report bytes. */
export interface StoredReport {
  readonly artifactDigest: string;
  readonly integrity: 'valid' | 'invalid' | 'indeterminate';
  readonly trust: 'trusted' | 'untrusted' | 'indeterminate';
  readonly trustAnchorRef: string | null;
  readonly revisionCoverage: 'complete' | 'incomplete' | 'indeterminate';
  readonly signerCertificateSha256: string;
  readonly approvalEvidenceDigest: string;
  readonly timestampStatus: string;
  readonly revocationStatus: string;
  readonly verifierName: string;
  readonly verifierVersion: string;
  readonly verifiedAt: string;
  readonly checks: unknown[];
}

function checkText(value: unknown, field: string, min: number, max: number): void {
  if (typeof value !== 'string' || value.length < min || value.length > max) throw new FinalArtifactInvalid(field);
}

function checkPattern(value: unknown, field: string, pattern: RegExp): void {
  if (typeof value !== 'string' || !pattern.test(value)) throw new FinalArtifactInvalid(field);
}

function oneOf<T extends string>(value: unknown, field: string, allowed: readonly T[]): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) throw new FinalArtifactInvalid(field);
  return value as T;
}

/**
 * Read the contract fields out of T014's exact report bytes (FEN-06). The
 * bytes must be one JSON object of schema opensig.verification/1 within the
 * contract limits; anything else is refused naming the field.
 */
export function readReport(reportBytes: Uint8Array): StoredReport {
  if (!(reportBytes instanceof Uint8Array) || reportBytes.byteLength < 2 || reportBytes.byteLength > MAX_REPORT_BYTES) {
    throw new FinalArtifactInvalid('reportBytes');
  }
  let parsed: unknown;
  try {
    parsed = parseJson(Buffer.from(reportBytes).toString('utf8'));
  } catch {
    throw new FinalArtifactInvalid('reportBytes');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new FinalArtifactInvalid('reportBytes');
  const report = parsed as Record<string, unknown>;
  if (report['schema'] !== REPORT_SCHEMA) throw new FinalArtifactInvalid('report.schema');
  if (report['seal_type'] !== 'organization') throw new FinalArtifactInvalid('report.seal_type');
  checkPattern(report['artifact_digest'], 'report.artifact_digest', DIGEST);
  checkPattern(report['signer_certificate_sha256'], 'report.signer_certificate_sha256', DIGEST);
  checkPattern(report['approval_evidence_digest'], 'report.approval_evidence_digest', DIGEST);
  const anchor = report['trust_anchor_ref'];
  if (anchor !== null) checkText(anchor, 'report.trust_anchor_ref', 1, MAX_TRUST_ANCHOR_REF);
  const verifier = report['verifier'];
  if (typeof verifier !== 'object' || verifier === null || Array.isArray(verifier)) throw new FinalArtifactInvalid('report.verifier');
  const { name, version } = verifier as Record<string, unknown>;
  checkText(name, 'report.verifier.name', 1, MAX_VERIFIER_NAME);
  checkText(version, 'report.verifier.version', 1, MAX_VERIFIER_VERSION);
  checkPattern(report['verified_at'], 'report.verified_at', /^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d(\.\d{1,9})?Z$/);
  const checks = report['checks'];
  if (!Array.isArray(checks)) throw new FinalArtifactInvalid('report.checks');
  return {
    artifactDigest: report['artifact_digest'] as string,
    integrity: oneOf(report['integrity'], 'report.integrity', ['valid', 'invalid', 'indeterminate'] as const),
    trust: oneOf(report['trust'], 'report.trust', ['trusted', 'untrusted', 'indeterminate'] as const),
    trustAnchorRef: anchor as string | null,
    revisionCoverage: oneOf(report['revision_coverage'], 'report.revision_coverage', ['complete', 'incomplete', 'indeterminate'] as const),
    signerCertificateSha256: report['signer_certificate_sha256'] as string,
    approvalEvidenceDigest: report['approval_evidence_digest'] as string,
    timestampStatus: oneOf(report['timestamp_status'], 'report.timestamp_status', ['trusted', 'absent', 'invalid', 'indeterminate'] as const),
    revocationStatus: oneOf(report['revocation_status'], 'report.revocation_status', ['good', 'revoked', 'unknown', 'not-checked'] as const),
    verifierName: name as string,
    verifierVersion: version as string,
    verifiedAt: report['verified_at'] as string,
    checks,
  };
}

/** Check every value against the contract limits (row P13, FEN-06). Throws FinalArtifactInvalid. */
export function validateFinalArtifact(artifact: NewFinalArtifact): void {
  if (typeof artifact !== 'object' || artifact === null) throw new FinalArtifactInvalid('artifact');
  checkPattern(artifact.artifactId, 'artifactId', ID);
  checkPattern(artifact.envelopeId, 'envelopeId', ID);
  checkPattern(artifact.artifactDigest, 'artifactDigest', DIGEST);
  checkPattern(artifact.packageDigest, 'packageDigest', DIGEST);
  checkPattern(artifact.approvedCompositionDigest, 'approvedCompositionDigest', DIGEST);
  checkPattern(artifact.evidenceDigest, 'evidenceDigest', DIGEST);
  checkPattern(artifact.approvalEvidenceDigest, 'approvalEvidenceDigest', DIGEST);
  checkPattern(artifact.signerCertificateSha256, 'signerCertificateSha256', DIGEST);
  if (typeof artifact.developmentCertificate !== 'boolean') throw new FinalArtifactInvalid('developmentCertificate');
  checkText(artifact.verifierName, 'verifierName', 1, MAX_VERIFIER_NAME);
  checkText(artifact.verifierVersion, 'verifierVersion', 1, MAX_VERIFIER_VERSION);
  if (typeof artifact.verificationJson !== 'string') throw new FinalArtifactInvalid('verificationJson');
  readReport(Buffer.from(artifact.verificationJson, 'utf8'));
  if (!Number.isSafeInteger(artifact.fencingToken) || artifact.fencingToken < 1) throw new FinalArtifactInvalid('fencingToken');
  checkPattern(artifact.completedAt, 'completedAt', SERVER_TIME);
}

/** Insert the envelope's one FinalArtifact (inside the publish transaction only). */
export function insertFinalArtifact(store: TenantStore, artifact: NewFinalArtifact): void {
  validateFinalArtifact(artifact);
  const tenantId = store.tenantId;
  store.insert('final_artifacts', {
    artifact_id: artifact.artifactId,
    envelope_id: artifact.envelopeId,
    artifact_digest: artifact.artifactDigest,
    package_digest: artifact.packageDigest,
    approved_composition_digest: artifact.approvedCompositionDigest,
    pdf_blob_ref: blobRef(tenantId, artifact.artifactDigest),
    evidence_blob_ref: blobRef(tenantId, artifact.evidenceDigest),
    package_blob_ref: blobRef(tenantId, artifact.packageDigest),
    approval_evidence_digest: artifact.approvalEvidenceDigest,
    signer_certificate_sha256: artifact.signerCertificateSha256,
    development_certificate: artifact.developmentCertificate ? 1 : 0,
    verifier_name: artifact.verifierName,
    verifier_version: artifact.verifierVersion,
    verification_json: artifact.verificationJson,
    fencing_token: artifact.fencingToken,
    completed_at: artifact.completedAt,
  });
}

/** Insert the publish's one verification_reports row from T014's exact report bytes (inside the publish transaction only). */
export function insertVerificationReport(store: TenantStore, row: { readonly id: string; readonly envelopeId: string; readonly reportBytes: Uint8Array }): StoredReport {
  checkPattern(row.id, 'verificationReportId', ID);
  checkPattern(row.envelopeId, 'envelopeId', ID);
  const report = readReport(row.reportBytes);
  store.insert('verification_reports', {
    id: row.id,
    envelope_id: row.envelopeId,
    artifact_digest: report.artifactDigest,
    integrity: report.integrity,
    trust: report.trust,
    trust_anchor_ref: report.trustAnchorRef,
    revision_coverage: report.revisionCoverage,
    seal_type: 'organization',
    signer_certificate_sha256: report.signerCertificateSha256,
    timestamp_status: report.timestampStatus,
    revocation_status: report.revocationStatus,
    verifier_name: report.verifierName,
    verifier_version: report.verifierVersion,
    verified_at: new Date(report.verifiedAt).toISOString(),
    checks_json: JSON.stringify(report.checks),
    report_bytes: Buffer.from(row.reportBytes),
  });
  return report;
}

/**
 * The envelope's completion checkpoint (T029; written once at package
 * assembly and reused by a retry, A-010 S4 and request #59 (5)), or
 * undefined. Read through the tenant-scoped store; only the audit writer
 * inserts audit_checkpoints rows.
 */
export function getCompletionCheckpoint(store: TenantStore, envelopeId: string): CompletionCheckpointRow | undefined {
  const row = store.get('audit_checkpoints', { kind: 'completion', envelope_id: envelopeId });
  if (row === undefined) return undefined;
  const seq = typeof row['seq'] === 'bigint' ? Number(row['seq']) : row['seq'];
  const digest = row['event_digest'];
  const createdAt = row['created_at'];
  if (
    typeof seq !== 'number' ||
    !Number.isSafeInteger(seq) ||
    typeof digest !== 'string' ||
    !DIGEST.test(digest) ||
    typeof createdAt !== 'string' ||
    !SERVER_TIME.test(createdAt)
  ) {
    throw new StorageUsageError('audit_checkpoints holds an unexpected completion checkpoint');
  }
  return { seq, digest, created_at: createdAt };
}
