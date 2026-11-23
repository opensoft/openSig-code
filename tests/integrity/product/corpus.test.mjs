// SPDX-License-Identifier: Apache-2.0
//
// The shipped verifier against the whole T012 oracle corpus (A-010, request #39
// Part E; request #41). The corpus is built ONCE, through the oracle's public
// exports only, and every case runs through both checkers with the same anchors
// and the entry's own expected digests (never re-derived).
//
// Case map (this file):
// - [VB-04] count: the entries equal `case_count`, one per descriptor, in order;
// - [VB-04] <case id>: one agreement test per corpus case on T014's internal
//   result (integrity, trust, revision_coverage, artifact_digest,
//   artifact_match and the approval-evidence check result; the evidence digest
//   only when that result is match or mismatch, request #44), plus the
//   descriptor's own expected report fields;
// - [VB-04] acceptance needs artifact_match exactly true;
// - [SC002-19] OC-02-a..f, [SC002-20] OC-03-a/b plus a T014-built revision,
//   [SC002-21] OC-04-a, [SC002-22] OC-05-a and OC-01-c;
// - [VB-03] OC-09-a..d; [VB-09] signingTime; [VB-10] no corpus case is
//   indeterminate.
//
// Mutants each test kills (Phase B):
// - the gap not checked against /Contents: OC-06-a;
// - range 1 not required at 0: OC-06-b; range 2 not required at a revision end:
//   OC-06-c; the end-of-file fallback accepting one byte short: OC-08-g;
// - coverage ignoring an appended revision: OC-03-a, OC-03-b, SC002-20;
// - integrity from messageDigest alone: OC-04-b;
// - padding folded into integrity: OC-04-a;
// - an evidence mismatch, absence or malformation accepted: OC-09-b..d;
// - signingTime changing a verdict: every valid case (VB-09);
// - acceptance with artifact_match !== false: the acceptance test;
// - structure checks skipped (startxref, /Prev, entries, type-2, /XRefStm):
//   OC-08-a..f; cross-reference streams or hybrids unread: OC-01-d..f.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyPdf } from '../../../src/verifier/index.ts';
import { anchorBytes, checkOf, disagreements, HEX64 } from './helpers/agreement.mjs';
import { buildCorpus, checkPdf, createWorkDir, loadCaseManifest, prepareMaterial, removeWorkDir } from './helpers/oracle.mjs';
import { appendInfoRevision } from './helpers/pdf-build.mjs';

const manifest = loadCaseManifest();
const state = { work: null, material: null, entries: [], results: new Map(), validationTime: null };

before(() => {
  state.work = createWorkDir();
  try {
    state.material = prepareMaterial(state.work);
    state.entries = buildCorpus(state.work, state.material, manifest);
    state.validationTime = new Date();
    for (const entry of state.entries) {
      const anchorPaths = state.material.anchors[entry.descriptor.anchors];
      const expectations = {
        expectedArtifactDigest: entry.originalDigest,
        expectedApprovalEvidenceDigest: entry.expectedApprovalEvidenceDigest,
      };
      const oracle = checkPdf(state.work, entry.bytes, { anchors: anchorPaths, ...expectations });
      const product = verifyPdf(entry.bytes, {
        anchors: anchorBytes(anchorPaths),
        ...expectations,
        validationTime: state.validationTime,
      });
      state.results.set(entry.descriptor.id, { entry, oracle, product, anchorPaths });
    }
  } catch (error) {
    removeWorkDir(state.work);
    state.work = null;
    throw error;
  }
});

after(() => {
  if (state.work !== null) removeWorkDir(state.work);
});

function result(id) {
  const found = state.results.get(id);
  assert.ok(found, `corpus entry ${id} was not built`);
  return found;
}

function idsOf(caseId) {
  return manifest.cases.filter((c) => c.case === caseId).map((c) => c.id);
}

const DIRECT_FIELDS = ['integrity', 'trust', 'revision_coverage', 'artifact_match', 'approval_evidence', 'accepted_as_original', 'signed_revision', 'revision_count'];

test('[VB-04] the corpus count equals case_count, with one entry per descriptor in descriptor order', () => {
  assert.equal(typeof manifest.case_count, 'number');
  assert.equal(manifest.cases.length, manifest.case_count);
  assert.equal(new Set(manifest.cases.map((c) => c.id)).size, manifest.case_count);
  assert.equal(state.entries.length, manifest.case_count);
  assert.deepEqual(state.entries.map((e) => e.descriptor.id), manifest.cases.map((c) => c.id));
  assert.equal(state.results.size, manifest.case_count);
});

for (const descriptor of manifest.cases) {
  test(`[VB-04] ${descriptor.id} agrees with the oracle: ${descriptor.title}`, () => {
    const { entry, oracle, product } = result(descriptor.id);
    assert.match(entry.originalDigest, HEX64, 'every corpus case supplies its recorded digest');
    assert.deepEqual(disagreements(oracle, product), []);
    for (const field of DIRECT_FIELDS) {
      if (Object.hasOwn(descriptor.expected, field)) assert.equal(product[field], descriptor.expected[field], field);
    }
    assert.notEqual(product.integrity, 'indeterminate');
    assert.equal(product.timestamp_status, 'absent');
    assert.equal(product.revocation_status, 'not-checked');
  });
}

test('[VB-04] acceptance needs artifact_match exactly true: each accepted case re-run without its digest is not accepted', () => {
  const accepted = [...state.results.values()].filter((r) => r.product.accepted_as_original);
  assert.ok(accepted.length > 0);
  for (const { entry, anchorPaths } of accepted) {
    const outcome = verifyPdf(entry.bytes, {
      anchors: anchorBytes(anchorPaths),
      expectedArtifactDigest: null,
      expectedApprovalEvidenceDigest: entry.expectedApprovalEvidenceDigest,
      validationTime: state.validationTime,
    });
    assert.equal(outcome.artifact_match, null, entry.descriptor.id);
    assert.equal(outcome.accepted_as_original, false, entry.descriptor.id);
  }
});

test('[SC002-19] a byte change inside either signed range makes integrity invalid (OC-02, all four range edges)', () => {
  const ids = idsOf('OC-02');
  assert.ok(ids.length >= 6, 'OC-02-a..f');
  for (const id of ids) {
    const { oracle, product } = result(id);
    assert.equal(product.integrity, 'invalid', id);
    assert.equal(product.trust, 'indeterminate', id);
    assert.equal(product.accepted_as_original, false, id);
    assert.equal(checkOf(product, 'message-digest').result, 'fail', id);
    assert.equal(oracle.integrity, 'invalid', id);
  }
});

test('[SC002-20] an appended revision leaves coverage incomplete and the artifact not accepted', () => {
  for (const id of idsOf('OC-03')) {
    const { product } = result(id);
    assert.equal(product.integrity, 'valid', id);
    assert.equal(product.revision_coverage, 'incomplete', id);
    assert.equal(product.accepted_as_original, false, id);
    assert.equal(checkOf(product, 'revision-coverage').detail, 'not-last-revision', id);
  }
  // T014's own appended revision on the clean seal of OC-01-a.
  const { entry, anchorPaths } = result('OC-01-a');
  const appended = appendInfoRevision(entry.bytes);
  const outcome = verifyPdf(appended, {
    anchors: anchorBytes(anchorPaths),
    expectedArtifactDigest: entry.originalDigest,
    validationTime: state.validationTime,
  });
  assert.equal(outcome.integrity, 'valid');
  assert.equal(outcome.revision_coverage, 'incomplete');
  assert.equal(outcome.revision_count, 3);
  assert.equal(outcome.signed_revision, 1);
  assert.equal(outcome.accepted_as_original, false);
});

test('[SC002-21] a /Contents padding change keeps integrity valid and fails the exact-artifact digest', () => {
  const { product } = result('OC-04-a');
  assert.equal(product.integrity, 'valid');
  assert.equal(product.artifact_match, false);
  assert.equal(product.accepted_as_original, false);
  assert.equal(checkOf(product, 'contents-padding').result, 'fail');
  assert.equal(checkOf(product, 'artifact-digest').detail, 'artifact-digest-mismatch');
});

test('[SC002-22] a self-signed certificate is integrity valid and trust untrusted', () => {
  for (const id of ['OC-05-a', 'OC-01-c']) {
    const { product } = result(id);
    assert.equal(product.integrity, 'valid', id);
    assert.equal(product.trust, 'untrusted', id);
    assert.equal(product.trust_anchor_ref, null, id);
  }
  assert.equal(result('OC-05-c').product.trust, 'untrusted', 'an unrelated anchor');
  assert.equal(result('OC-05-b').product.trust, 'trusted', 'the positive control');
});

test('[VB-03] the approval-evidence digest is reported and checked against the supplied digest (OC-09)', () => {
  const a = result('OC-09-a');
  assert.equal(a.product.approval_evidence, 'match');
  assert.equal(a.product.approval_evidence_digest, a.entry.expectedApprovalEvidenceDigest);
  assert.equal(checkOf(a.product, 'approval-evidence-digest').result, 'pass');
  const b = result('OC-09-b');
  assert.equal(b.product.approval_evidence, 'mismatch');
  assert.notEqual(b.product.approval_evidence_digest, b.entry.expectedApprovalEvidenceDigest);
  assert.equal(b.product.accepted_as_original, false);
  assert.equal(result('OC-09-c').product.approval_evidence, 'absent');
  assert.equal(result('OC-09-c').product.approval_evidence_digest, null);
  assert.equal(result('OC-09-d').product.approval_evidence, 'malformed');
  assert.equal(result('OC-09-d').product.approval_evidence_digest, null, 'a malformed attribute has no digest');
  assert.equal(checkOf(result('OC-09-d').product, 'approval-evidence-digest').detail, 'malformed');
  for (const { entry, product } of state.results.values()) {
    if (entry.expectedApprovalEvidenceDigest === null) assert.equal(product.approval_evidence, 'not-requested', entry.descriptor.id);
  }
  const unrequested = verifyPdf(a.entry.bytes, {
    anchors: anchorBytes(a.anchorPaths),
    expectedArtifactDigest: a.entry.originalDigest,
    validationTime: state.validationTime,
  });
  assert.equal(unrequested.approval_evidence, 'not-requested');
  assert.equal(unrequested.approval_evidence_digest, a.entry.expectedApprovalEvidenceDigest);
});

test('[VB-09] signingTime and a missing signingCertificateV2 in the corpus are profile checks and change no verdict', () => {
  const withTime = [...state.results.values()].filter((r) => checkOf(r.product, 'profile-signing-time').result === 'fail');
  assert.ok(withTime.length > 0, 'the OpenSSL-made corpus carries signingTime');
  for (const { entry, oracle, product } of withTime) {
    assert.equal(checkOf(product, 'profile-signing-time').detail, 'signing-time-present', entry.descriptor.id);
    assert.deepEqual(disagreements(oracle, product), [], entry.descriptor.id);
  }
  for (const { entry, oracle, product } of state.results.values()) {
    const ess = checkOf(product, 'profile-signing-certificate-v2');
    if (ess.result === 'fail') {
      assert.equal(ess.detail, 'signing-certificate-v2-absent', entry.descriptor.id);
      assert.deepEqual(disagreements(oracle, product), [], entry.descriptor.id);
    }
    assert.equal(product.timestamp_status, 'absent', entry.descriptor.id);
  }
  assert.equal(checkOf(result('OC-01-b').product, 'profile-signing-certificate-v2').result, 'pass', 'OC-01-b carries signingCertificateV2');
  const clean = result('OC-01-a').product;
  assert.equal(clean.integrity, 'valid');
  assert.equal(clean.trust, 'trusted');
  assert.equal(clean.revision_coverage, 'complete');
});

test('[VB-10] indeterminate integrity never occurs on a corpus case', () => {
  for (const { entry, oracle, product } of state.results.values()) {
    assert.notEqual(product.integrity, 'indeterminate', entry.descriptor.id);
    assert.notEqual(oracle.integrity, 'indeterminate', entry.descriptor.id);
  }
});
