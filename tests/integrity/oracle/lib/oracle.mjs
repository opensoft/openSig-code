// SPDX-License-Identifier: Apache-2.0
//
// The T012 independent integrity oracle. checkPdf() combines the structure
// checker with OpenSSL's verdict over the exact ByteRange bytes. The verdict
// mapping is ratified by A-010 (request #39, Part E Q3; tasks.md T012/T014).
// Public (T014): checkPdf, ORACLE. Imports nothing from src/.

import { createHash } from 'node:crypto';
import { DerError } from './der.mjs';
import { OID, readProfile } from './cms-reader.mjs';
import { checkByteRange, extractCms, locateSignatures, parseRevisions, statedRangesWithin } from './pdf-checker.mjs';
import { rangesOf } from './pdf-builder.mjs';
import { cmsVerifyDetached } from './openssl.mjs';

export const ORACLE = Object.freeze({ name: 'opensig-integrity-oracle', version: '0.1.0' });

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
export const sha256Hex = (bytes) => sha256(bytes).toString('hex');

/**
 * options.anchors: trust-anchor certificate paths (omitted or [] = none; a non-array is refused).
 * options.expectedArtifactDigest: lowercase hex of the recorded original, or null.
 * options.expectedApprovalEvidenceDigest: lowercase hex, or null (not requested).
 */
export function checkPdf(work, bytes, { anchors = [], expectedArtifactDigest = null, expectedApprovalEvidenceDigest = null } = {}) {
  // Request #41 (T012-ANCHORS): anchors are a list of certificate paths. An
  // omitted value means none; anything that is not a list is refused, never trusted.
  if (!Array.isArray(anchors) || !anchors.every((p) => typeof p === 'string' && p.length > 0)) {
    throw new TypeError('anchors must be an array of certificate file paths');
  }
  for (const value of [expectedArtifactDigest, expectedApprovalEvidenceDigest]) {
    if (value !== null && !/^[0-9a-f]{64}$/.test(value)) throw new Error('expected digests are lowercase hex SHA-256');
  }
  const s = bytes.toString('latin1');
  const checks = [];
  const record = (id, result, detail) => checks.push(detail ? { id, result, detail_code: detail } : { id, result });

  const structure = parseRevisions(s);
  record('revision-structure', structure.ok ? 'pass' : 'fail', structure.ok ? null : structure.detail);

  const candidates = locateSignatures(s);
  let sig = null;
  if (candidates.length === 1 && candidates[0].ok && candidates[0].isSig) sig = candidates[0];
  const sigDetail = candidates.length === 0 ? 'no-signature' : candidates.length > 1 ? 'multiple-signatures'
    : !candidates[0].ok ? candidates[0].detail : candidates[0].isSig ? null : 'not-type-sig';
  record('signature-dictionary', sig ? 'pass' : 'fail', sigDetail);

  const byteRange = sig ? checkByteRange(bytes.length, sig, structure) : { ok: false, detail: 'not-run' };
  record('byte-range', sig ? (byteRange.ok ? 'pass' : 'fail') : 'not-run', sig && !byteRange.ok ? byteRange.detail : null);

  const cms = sig ? extractCms(sig) : null;
  record('cms-extraction', cms ? (cms.ok ? 'pass' : 'fail') : 'not-run', cms && !cms.ok ? cms.detail : null);
  record('contents-padding', cms?.ok ? (cms.paddingZero ? 'pass' : 'fail') : 'not-run', cms?.ok && !cms.paddingZero ? 'nonzero-padding' : null);

  let profile = null;
  let profileDetail = null;
  if (cms?.ok) {
    try {
      profile = readProfile(cms.der);
      if (!profile.detached) profileDetail = 'not-detached';
      else if (profile.eContentType !== OID.data || profile.contentTypeOid !== OID.data) profileDetail = 'content-type-not-data';
      else if (profile.digestOid !== OID.sha256) profileDetail = 'digest-not-sha256';
      else if (!profile.messageDigest || profile.messageDigest.length !== 32) profileDetail = 'message-digest-malformed';
    } catch (error) {
      if (!(error instanceof DerError)) throw error;
      profileDetail = error.code;
    }
  }
  const profileOk = profile !== null && profileDetail === null;
  record('cms-structure', cms?.ok ? (profileOk ? 'pass' : 'fail') : 'not-run', profileDetail);

  // OpenSSL decides the signature over the stated ranges; the oracle's own
  // messageDigest comparison is an independent cross-check.
  const within = sig ? statedRangesWithin(bytes.length, sig.byteRange) : false;
  const ranges = within ? rangesOf(bytes, sig.byteRange) : null;
  const mdOk = profileOk && ranges ? profile.messageDigest.equals(sha256(ranges)) : null;
  record('message-digest', mdOk === null ? 'not-run' : mdOk ? 'pass' : 'fail', mdOk === false ? 'mismatch' : null);
  const cryptoOk = cms?.ok && ranges ? cmsVerifyDetached(work, cms.der, ranges).ok : null;
  record('cms-verify-stated-ranges', cryptoOk === null ? 'not-run' : cryptoOk ? 'pass' : 'fail', null);

  const integrity = byteRange.ok && profileOk && mdOk === true && cryptoOk === true ? 'valid' : 'invalid';

  let trust = 'indeterminate';
  if (integrity === 'valid') trust = cmsVerifyDetached(work, cms.der, ranges, { anchors }).ok ? 'trusted' : 'untrusted';
  record('trust-anchors', integrity === 'valid' ? (trust === 'trusted' ? 'pass' : 'fail') : 'not-run', null);

  let revisionCoverage = 'indeterminate';
  if (structure.ok && byteRange.ok) {
    revisionCoverage = byteRange.signedRevision === structure.revisions.length - 1 ? 'complete' : 'incomplete';
  }
  record('revision-coverage', revisionCoverage === 'indeterminate' ? 'not-run' : revisionCoverage === 'complete' ? 'pass' : 'fail', null);

  const artifactDigest = sha256Hex(bytes);
  const artifactMatch = expectedArtifactDigest === null ? null : artifactDigest === expectedArtifactDigest;
  record('artifact-digest', artifactMatch === null ? 'not-run' : artifactMatch ? 'pass' : 'fail', null);

  const evidence = profile ? profile.approvalEvidence : null;
  let approvalEvidence = 'not-requested';
  if (expectedApprovalEvidenceDigest !== null) {
    if (!evidence) approvalEvidence = 'indeterminate';
    else if (evidence.status !== 'present') approvalEvidence = evidence.status; // absent | malformed
    else approvalEvidence = evidence.digestHex === expectedApprovalEvidenceDigest ? 'match' : 'mismatch';
  }
  record('approval-evidence-digest', approvalEvidence === 'not-requested' ? 'not-run' : approvalEvidence === 'match' ? 'pass' : 'fail',
    ['not-requested', 'match'].includes(approvalEvidence) ? null : approvalEvidence);

  return {
    oracle: ORACLE,
    artifact_digest: artifactDigest,
    integrity,
    trust,
    revision_coverage: revisionCoverage,
    artifact_match: artifactMatch,
    approval_evidence: approvalEvidence,
    approval_evidence_digest: evidence?.status === 'present' ? evidence.digestHex : null,
    // A-010 request #39 (Q3): acceptance needs a supplied, matching artifact digest; trust is ignored.
    accepted_as_original: integrity === 'valid' && revisionCoverage === 'complete' && artifactMatch === true
      && (approvalEvidence === 'match' || approvalEvidence === 'not-requested'),
    signed_revision: byteRange.ok ? byteRange.signedRevision : null,
    revision_count: structure.ok ? structure.revisions.length : null,
    signer_certificate_sha256: profile && profile.certs.length === 1 ? sha256Hex(profile.certs[0]) : null,
    cms_der_sha256: cms?.ok ? sha256Hex(cms.der) : null,
    profile: profile && {
      detached: profile.detached,
      digest_sha256: profile.digestOid === OID.sha256,
      content_type_data: profile.contentTypeOid === OID.data,
      signing_certificate_v2: profile.signingCertificateV2Present,
      signing_time: profile.signingTimePresent,
      certificate_count: profile.certs.length,
    },
    checks,
  };
}

/** OC-01 control: the same CMS must NOT verify over the whole file. */
export function verifiesOver(work, der, content) {
  return cmsVerifyDetached(work, der, content).ok;
}
