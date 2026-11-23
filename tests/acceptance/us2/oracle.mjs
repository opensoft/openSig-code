// SPDX-License-Identifier: Apache-2.0
//
// T017's only door to the T012 test oracle (the T017 line, A-010 request #78 (1), by the driver's
// word: "The allowed read-only agreement helper is a reasonable oracle interface"). It imports,
// read-only, T014's two helpers and nothing else:
// - tests/integrity/product/helpers/oracle.mjs, the adapter that re-exports the T012 oracle's seven
//   public exports (pinned by T014's import-boundary test);
// - tests/integrity/product/helpers/agreement.mjs: runBoth, disagreements, AGREEMENT_FIELDS and
//   checkOf. It imports only node:fs; the product's verifyPdf is passed in by the caller.
// The calling convention is read from those files and T014's call sites (corpus.test.mjs:45, :56
// and :72; product-sealed.test.mjs:73, :111-120 and :130; strand-*.test.mjs, each createWorkDir()
// in before() and removeWorkDir() in after()): createWorkDir() gives a work handle,
// synchronously; checkPdf(work, bytes, { anchors, expectedArtifactDigest,
// expectedApprovalEvidenceDigest }) takes anchors as certificate FILE PATHS; runBoth({ work,
// checkPdf, verifyPdf, bytes, anchorPaths, expectedArtifactDigest, expectedApprovalEvidenceDigest,
// validationTime }) gives the verifier the same files as bytes and returns { oracle, product, diff };
// removeWorkDir(work) removes the handle's directory. No T017 file names the oracle's own directory,
// no one working on T017 reads it or its fixtures, and no extract is taken (request #78).
// This file imports nothing from src/, so the product never stands in for the oracle; the caller
// injects verifyPdf exactly as T014's own tests do ([US2-STATIC] checks both rules).
// The expected digests always come from the producer's record, never from the bytes under test
// (agreement.mjs's rule): each flow passes the package index's final.pdf digest and the RFC 8785
// evidence digest of the packaged manifest (harness.mjs evidenceDigestOf).

import assert from 'node:assert/strict';

import { AGREEMENT_FIELDS, checkOf, disagreements, runBoth } from '../../integrity/product/helpers/agreement.mjs';
import { checkPdf, createWorkDir, ORACLE, removeWorkDir } from '../../integrity/product/helpers/oracle.mjs';

export { AGREEMENT_FIELDS, checkOf, disagreements };

/**
 * The evidence labels oracle_name and oracle_version: ORACLE's string members `name` and `version`,
 * read at run time (request #78 (1)). Neither the T012 line nor plan.md names them, so a missing one
 * FAILS with the members actually observed, never with a guessed value; that comes back for a ruling.
 */
export function oracleLabels() {
  const observed = ORACLE !== null && typeof ORACLE === 'object' ? Object.keys(ORACLE) : [];
  const ok = (member) => ORACLE !== null && typeof ORACLE === 'object' && typeof ORACLE[member] === 'string' && ORACLE[member].trim() !== '';
  assert.ok(ok('name') && ok('version'), `ORACLE must carry string members name and version for the labels oracle_name and oracle_version (request #78 (1)); observed ${typeof ORACLE} with members [${observed.join(', ')}]. This comes back to the architect for a ruling`);
  return { name: ORACLE.name, version: ORACLE.version };
}

/** A work handle for the oracle's runs (createWorkDir, as T014's call sites use it); close() removes it. */
export function openWork() {
  const work = createWorkDir();
  return { work, close: () => removeWorkDir(work) };
}

/**
 * Both checkers on the same bytes with the same expectations (T014's runBoth): { oracle, product,
 * diff }. `verifyPdf` is the caller's (src/verifier/), injected; `anchorPaths` are certificate files.
 */
export function checkBoth(handle, { verifyPdf, bytes, anchorPaths, expectedArtifactDigest, expectedApprovalEvidenceDigest }) {
  assert.equal(typeof verifyPdf, 'function', 'the caller injects the product verifier');
  assert.ok(Array.isArray(anchorPaths), 'the anchors are an array of certificate file paths');
  return runBoth({ work: handle.work, checkPdf, verifyPdf, bytes, anchorPaths, expectedArtifactDigest, expectedApprovalEvidenceDigest, validationTime: new Date() });
}

/** The oracle's values on AGREEMENT_FIELDS: the "oracle's result" a flows.json entry keeps. */
export function oracleResultOf(run) {
  return Object.fromEntries(AGREEMENT_FIELDS.map((field) => [field, run.oracle?.[field] ?? null]));
}
