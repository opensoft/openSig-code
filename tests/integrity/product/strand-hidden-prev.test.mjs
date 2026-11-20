// SPDX-License-Identifier: Apache-2.0
//
// VB-06 (request #64 (1); row T014-XREFSTART): CAND7, end to end. A hybrid
// base whose hidden /XRefStm stream carries a /Prev that T033 never reads:
// T033's readChain takes only that stream's entries and checks /Prev only on
// the section's own trailer. Each base is one T033 accepts: T036's
// composeSealRevision parses it through T033's parse service and composes it,
// T037's sealComposedPdf seals it with the T012 oracle's synthetic signer
// material (reached through its public exports), and T014 must then accept the
// sealed file as the original:
// - CAND7a: the hidden stream carries /Prev null;
// - CAND7b: the hidden stream carries /Prev -1.
// Needs T033's parse sandbox (undeclared by `verification`), OpenSSL (the
// oracle's material) and T037's worker: without the sandbox these cases FAIL,
// never CAPABILITY_ABSENT and never skipped (request #56 B5). Nothing here
// probes for the sandbox or catches its absence; the guard test in
// structure.test.mjs keeps it so. The key file stays in the oracle's
// owner-only work directory, removed after the file.
//
// Mutant killed here: the /Prev check restored on hidden streams.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readRevisionStructure, verifyPdf } from '../../../src/verifier/index.ts';
import { createWorkDir, prepareMaterial, removeWorkDir } from './helpers/oracle.mjs';
import { buildBase } from './helpers/pdf-build.mjs';
import { sealWithProduct, syntheticEvidenceDigest } from './helpers/product-seal.mjs';

const EVIDENCE = syntheticEvidenceDigest('T014 hidden stream prev');
const state = { work: null, material: null, validationTime: null };

before(() => {
  state.work = createWorkDir();
  state.material = prepareMaterial(state.work);
  state.validationTime = new Date();
});

after(() => {
  removeWorkDir(state.work);
});

/** The base passes T014's structure check; sealed by T036 and T037, it is accepted as the original. */
async function sealAndVerify(document) {
  const base = readRevisionStructure(document);
  assert.equal(base.ok, true, base.ok ? '' : `base structure failed: ${base.detail}`);
  const signer = state.material.signers['dev-ca-leaf'];
  const sealed = await sealWithProduct({ document, signer, approvalEvidenceDigest: EVIDENCE });
  const outcome = verifyPdf(sealed.bytes, {
    anchors: state.material.anchors['dev-ca'].map((path) => readFileSync(path)),
    expectedArtifactDigest: sealed.artifactDigest,
    expectedApprovalEvidenceDigest: EVIDENCE,
    validationTime: state.validationTime,
  });
  const failing = outcome.checks.filter((c) => c.result === 'fail').map((c) => `${c.id}:${c.detail}`);
  assert.equal(outcome.integrity, 'valid', failing.join(', '));
  assert.equal(outcome.trust, 'trusted');
  assert.equal(outcome.revision_coverage, 'complete');
  assert.equal(outcome.artifact_match, true);
  assert.equal(outcome.approval_evidence, 'match');
  assert.equal(outcome.accepted_as_original, true);
  return outcome;
}

test('[VB-06] CAND7a sealed: a hybrid whose hidden /XRefStm stream carries /Prev null is read for its entries only (request #64 (1))', async () => {
  const base = buildBase({ xref: 'hybrid', hiddenDictExtra: ' /Prev null' });
  assert.equal(base.bytes.toString('latin1').split('/Prev null').length - 1, 1, 'the hidden stream carries /Prev null');
  await sealAndVerify(base.bytes);
});

test('[VB-06] CAND7b sealed: a hybrid whose hidden /XRefStm stream carries /Prev -1 is read for its entries only (request #64 (1))', async () => {
  const base = buildBase({ xref: 'hybrid', hiddenDictExtra: ' /Prev -1' });
  assert.equal(base.bytes.toString('latin1').split('/Prev -1').length - 1, 1, 'the hidden stream carries /Prev -1');
  await sealAndVerify(base.bytes);
});
