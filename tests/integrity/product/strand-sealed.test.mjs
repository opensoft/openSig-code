// SPDX-License-Identifier: Apache-2.0
//
// VB-06 and VB-07 (request #58; row T014-XREFSTART): the five strand paths the
// recheck of 0c20abd observed, end to end. Each base is one T033 accepts: T036's
// composeSealRevision parses it through T033's parse service and composes it,
// T037's sealComposedPdf seals it with the T012 oracle's synthetic signer
// material (reached through its public exports), and T014 must then accept the
// sealed file as the original:
// - P1: trailer numbers of 16 digits and of 32 characters (T033's readValue);
// - P2: /Prev written as an integral real (`<n>.0`);
// - P3: a comment inside the reference `/Root 1 0 R`;
// - P4: one table section listing object 5 first as free, then in use: the
//   first entry wins (T033's addLocal);
// - P5: a trailer string that spells /ByteRange, which is no signature
//   dictionary (request #58 (1)).
// Needs T033's parse sandbox (undeclared by `verification`), OpenSSL (the
// oracle's material) and T037's worker: without the sandbox these cases FAIL,
// never CAPABILITY_ABSENT and never skipped (request #56 B5). Nothing here
// probes for the sandbox or catches its absence; the guard test in
// structure.test.mjs keeps it so. The key file stays in the oracle's
// owner-only work directory, removed after the file.
//
// Mutants killed here: number tokens capped at 15 digits (P1); integral reals
// refused where an integer is required (P2); comments refused inside a
// reference (P3); a table section's in-use entry preferred over its first entry
// (P4); signatures counted by text (P5).

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { readRevisionStructure, verifyPdf } from '../../../src/verifier/index.ts';
import { createWorkDir, prepareMaterial, removeWorkDir } from './helpers/oracle.mjs';
import { appendUpdate, buildBase } from './helpers/pdf-build.mjs';
import { sealWithProduct, syntheticEvidenceDigest } from './helpers/product-seal.mjs';

const EVIDENCE = syntheticEvidenceDigest('T014 strand paths');
const TRAILER = 'trailer\n<< /Size 5 /Root 1 0 R >>';
const state = { work: null, material: null, validationTime: null };

before(() => {
  state.work = createWorkDir();
  state.material = prepareMaterial(state.work);
  state.validationTime = new Date();
});

after(() => {
  removeWorkDir(state.work);
});

/** `text` with its one occurrence of `from` replaced. */
function edited(text, from, to) {
  const count = text.split(from).length - 1;
  assert.equal(count, 1, `the edit site occurs ${count} times`);
  return Buffer.from(text.replace(from, () => to), 'latin1');
}

const baseText = () => buildBase().bytes.toString('latin1');

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

test('[VB-06] P1 sealed: trailer numbers of 16 digits and of 32 characters are read as T033 reads them (request #58)', async () => {
  const real = `-${'1'.repeat(10)}.${'2'.repeat(20)}`;
  assert.equal(real.length, 32);
  await sealAndVerify(edited(baseText(), TRAILER, `trailer\n<< /Size 5 /Root 1 0 R /OpensigDigits 1234567890123456 /OpensigReal ${real} >>`));
});

test('[VB-06] P2 sealed: /Prev written as an integral real is read as an integer (request #58)', async () => {
  const base = buildBase();
  const updated = appendUpdate(base, [{ num: 5, text: '<< /Producer (strand path P2) >>' }]);
  await sealAndVerify(edited(updated.bytes.toString('latin1'), `/Prev ${base.startxref} >>`, `/Prev ${base.startxref}.0 >>`));
});

test('[VB-06] P3 sealed: a comment inside the reference /Root 1 0 R is skipped (request #58)', async () => {
  await sealAndVerify(edited(baseText(), TRAILER, 'trailer\n<< /Size 5 /Root 1 0 % a comment inside the reference\nR >>'));
});

test('[VB-06] P4 sealed: a table section listing object 5 free and then in use keeps its first entry (request #58)', async () => {
  const listing = '5 1\n0000000000 00000 f \n5 1\n0000099999 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R >>';
  await sealAndVerify(edited(baseText(), TRAILER, listing));
});

test('[VB-07] P5 sealed: a trailer string that spells /ByteRange is no second signature (request #58 (1))', async () => {
  const outcome = await sealAndVerify(edited(baseText(), TRAILER, 'trailer\n<< /Size 5 /Root 1 0 R /OpensigNote (/ByteRange) >>'));
  assert.equal(outcome.checks.find((c) => c.id === 'signature-dictionary')?.result, 'pass');
});
