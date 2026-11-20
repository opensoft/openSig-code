// SPDX-License-Identifier: Apache-2.0
//
// VB-06 (request #60 (1); row T014-XREFSTART): candidates 1 to 3 of the fix
// recheck at 6c17cd7, end to end. Each base is one T033 accepts: T036's
// composeSealRevision parses it through T033's parse service and composes it,
// T037's sealComposedPdf seals it with the T012 oracle's synthetic signer
// material (reached through its public exports), and T014 must then accept the
// sealed file as the original:
// - C1: a cross-reference stream whose /Index is null, which means [0 /Size]
//   as T033's default applies to a null;
// - C2: an object stream whose /Length is `7 1 R` while object 7's entry has
//   generation 0: the target is read with the entry's own generation, and the
//   reference's generation is never compared (T033's streamLength);
// - C3: two compressed objects, `12` and `true`, with no byte between them:
//   each is parsed only up to the next header offset (T033's readCompressed).
// Needs T033's parse sandbox (undeclared by `verification`), OpenSSL (the
// oracle's material) and T037's worker: without the sandbox these cases FAIL,
// never CAPABILITY_ABSENT and never skipped (request #56 B5). Nothing here
// probes for the sandbox or catches its absence; the guard test in
// structure.test.mjs keeps it so. The key file stays in the oracle's
// owner-only work directory, removed after the file.
//
// Mutants killed here: /Index null refused (C1); the reference's generation
// compared (C2); a compressed object parsed to the end of the decoded data (C3).

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readRevisionStructure, verifyPdf } from '../../../src/verifier/index.ts';
import { createWorkDir, prepareMaterial, removeWorkDir } from './helpers/oracle.mjs';
import { buildBase } from './helpers/pdf-build.mjs';
import { sealWithProduct, syntheticEvidenceDigest } from './helpers/product-seal.mjs';

const EVIDENCE = syntheticEvidenceDigest('T014 strand candidates');
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

test('[VB-06] C1 sealed: a cross-reference stream whose /Index is null reads as [0 /Size] (request #60 (1))', async () => {
  const base = buildBase({ xref: 'stream', xrefDictExtra: ' /Index null' });
  assert.equal(base.bytes.toString('latin1').split('/Index null').length - 1, 1, 'the base has one /Index null');
  await sealAndVerify(base.bytes);
});

test('[VB-06] C2 sealed: an object stream /Length of `7 1 R` is read with the entry\'s generation 0 (request #60 (1))', async () => {
  const base = buildBase({ xref: 'stream', objStmIndirectLength: true, objStmLengthRefGen: 1 });
  const text = base.bytes.toString('latin1');
  assert.equal(text.split('/Length 7 1 R').length - 1, 1, 'the reference names generation 1');
  assert.equal(text.split('\n7 0 obj\n').length - 1, 1, 'object 7 has generation 0');
  await sealAndVerify(base.bytes);
});

test('[VB-06] C3 sealed: compressed objects `12` and `true` with no byte between them each end at the next header offset (request #60 (1))', async () => {
  const base = buildBase({ xref: 'stream', objStmAdjacent: true });
  assert.equal(base.bytes.toString('latin1').split(' 12true\nendstream').length - 1, 1, 'the two objects touch');
  await sealAndVerify(base.bytes);
});
