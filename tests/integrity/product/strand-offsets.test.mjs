// SPDX-License-Identifier: Apache-2.0
//
// VB-06 (request #62 (1); row T014-XREFSTART): CAND6 and its class, end to
// end. A cross-reference stream section may start at any offset T033's section
// read admits. Each base is one T033 accepts: T036's composeSealRevision parses
// it through T033's parse service and composes it, T037's sealComposedPdf seals
// it with the T012 oracle's synthetic signer material (reached through its
// public exports), and T014 must then accept the sealed file as the original:
// - offset 7 on a %PDF-1.7 header: T033's readIndirect reads the minor version
//   digit, the next line's `0` and `obj` as the header `7 0 obj`;
// - offset 7 on a %PDF-2.0 header: the same, as object 0;
// - offset 0: readIndirect's skipWhitespace passes over the header line as a
//   comment and reads the object header on the next line.
// Needs T033's parse sandbox (undeclared by `verification`), OpenSSL (the
// oracle's material) and T037's worker: without the sandbox these cases FAIL,
// never CAPABILITY_ABSENT and never skipped (request #56 B5). Nothing here
// probes for the sandbox or catches its absence; the guard test in
// structure.test.mjs keeps it so. The key file stays in the oracle's
// owner-only work directory, removed after the file.
//
// Mutant killed here: the old lower bound restored, a section start of at
// least 8 bytes (both offset-7 cases).

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readRevisionStructure, verifyPdf } from '../../../src/verifier/index.ts';
import { createWorkDir, prepareMaterial, removeWorkDir } from './helpers/oracle.mjs';
import { buildEarlyStreamBase } from './helpers/pdf-build.mjs';
import { sealWithProduct, syntheticEvidenceDigest } from './helpers/product-seal.mjs';

const EVIDENCE = syntheticEvidenceDigest('T014 section offsets');
const state = { work: null, material: null, validationTime: null };

before(() => {
  state.work = createWorkDir();
  state.material = prepareMaterial(state.work);
  state.validationTime = new Date();
});

after(() => {
  removeWorkDir(state.work);
});

/** The base passes T014's structure check with its section at `start`; sealed by T036 and T037, it is accepted as the original. */
async function sealAndVerify(document, start) {
  const base = readRevisionStructure(document);
  assert.equal(base.ok, true, base.ok ? '' : `base structure failed: ${base.detail}`);
  assert.deepEqual(base.revisions.map((r) => r.start), [start], 'one section, at the expected start');
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

test('[VB-06] C6 sealed: a cross-reference stream at offset 7 on a %PDF-1.7 header, object 7 read from the version digit (request #62 (1))', async () => {
  const base = buildEarlyStreamBase({ version: '1.7', at: 7 });
  const text = base.bytes.toString('latin1');
  assert.equal(text.slice(0, 14), '%PDF-1.7\n0 obj', 'the header line ends in the object number');
  assert.ok(text.endsWith('startxref\n7\n%%EOF\n'));
  await sealAndVerify(base.bytes, 7);
});

test('[VB-06] C6 sealed: a cross-reference stream at offset 7 on a %PDF-2.0 header, object 0 read from the version digit (request #62 (1))', async () => {
  const base = buildEarlyStreamBase({ version: '2.0', at: 7 });
  const text = base.bytes.toString('latin1');
  assert.equal(text.slice(0, 14), '%PDF-2.0\n0 obj', 'the header line ends in the object number');
  assert.ok(text.endsWith('startxref\n7\n%%EOF\n'));
  await sealAndVerify(base.bytes, 7);
});

test('[VB-06] C6 sealed: a cross-reference stream at offset 0, the header line passed over as a comment (request #62 (1))', async () => {
  const base = buildEarlyStreamBase({ version: '1.7', at: 0 });
  const text = base.bytes.toString('latin1');
  assert.equal(text.slice(0, 16), '%PDF-1.7\n5 0 obj', 'the stream object opens the second line');
  assert.ok(text.endsWith('startxref\n0\n%%EOF\n'));
  await sealAndVerify(base.bytes, 9);
});
