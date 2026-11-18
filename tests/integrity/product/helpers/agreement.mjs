// SPDX-License-Identifier: Apache-2.0
//
// Agreement between the T012 oracle and the shipped verifier (A-010, request
// #39 Part E; request #44): for every corpus case and every product-sealed
// output, T014's internal result (a value the input lacks is null) equals the
// oracle's on integrity, trust, revision_coverage, the exact-artifact digest and
// its match, and the approval-evidence check result. The evidence digest is
// compared only when that check result is `match` or `mismatch`; for a
// malformed attribute only the check result is compared. Check lists and detail
// codes may differ, and are not compared. The expected digests always come from
// the producer's record (a corpus entry's `originalDigest` and
// `expectedApprovalEvidenceDigest`, or the sealing step's reported digests),
// never re-derived from the bytes under test.

import { readFileSync } from 'node:fs';

export const AGREEMENT_FIELDS = Object.freeze([
  'integrity',
  'trust',
  'revision_coverage',
  'artifact_digest',
  'artifact_match',
  'approval_evidence',
]);

/** The check results under which the evidence digest itself is compared. */
export const DIGEST_COMPARED_WHEN = Object.freeze(['match', 'mismatch']);

export const HEX64 = /^[0-9a-f]{64}$/;

/** The fields on which the two results differ, with both values (verdicts and digests only). */
export function disagreements(oracleResult, productOutcome) {
  const out = AGREEMENT_FIELDS.filter((field) => oracleResult[field] !== productOutcome[field]).map((field) => ({
    field,
    oracle: oracleResult[field],
    product: productOutcome[field],
  }));
  const compareDigest =
    DIGEST_COMPARED_WHEN.includes(oracleResult.approval_evidence) || DIGEST_COMPARED_WHEN.includes(productOutcome.approval_evidence);
  if (compareDigest && oracleResult.approval_evidence_digest !== productOutcome.approval_evidence_digest) {
    out.push({
      field: 'approval_evidence_digest',
      oracle: oracleResult.approval_evidence_digest,
      product: productOutcome.approval_evidence_digest,
    });
  }
  return out;
}

/** The same anchor certificates the oracle is given as paths, as bytes for the verifier. */
export function anchorBytes(paths) {
  if (!Array.isArray(paths)) throw new TypeError('anchor paths must be an array');
  return paths.map((path) => readFileSync(path));
}

/** Run both checkers on the same bytes with the same expectations. */
export function runBoth({ work, checkPdf, verifyPdf, bytes, anchorPaths, expectedArtifactDigest, expectedApprovalEvidenceDigest, validationTime }) {
  const expectations = { expectedArtifactDigest, expectedApprovalEvidenceDigest };
  const oracle = checkPdf(work, bytes, { anchors: anchorPaths, ...expectations });
  const product = verifyPdf(bytes, { anchors: anchorBytes(anchorPaths), ...expectations, validationTime });
  return { oracle, product, diff: disagreements(oracle, product) };
}

export function checkOf(outcome, id) {
  const found = outcome.checks.find((check) => check.id === id);
  if (found === undefined) throw new Error(`no check ${id}`);
  return found;
}
