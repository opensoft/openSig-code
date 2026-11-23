// SPDX-License-Identifier: Apache-2.0
//
// VB-05: the shipped verifier agrees with the T012 oracle on product-sealed
// output (A-010, request #39 Part E). Each output is sealed by the product's
// own path (helpers/product-seal.mjs: T036's landed composeSealRevision, then
// T037's sealComposedPdf, which builds the CMS with T013), signed with the
// oracle's runtime material, and checked by both checkers with the same anchors
// and the sealing step's reported digests (finalPdfDigest). Every base here is
// one the oracle reads (strict starts only; request #49); the loose starts of
// row T014-XREFSTART are in structure-composed.test.mjs, without agreement.
// Needs: T033's parse sandbox (undeclared by the mode), OpenSSL (the oracle and
// its runtime material), and T037's worker.
//
// Outputs: one seal on each base kind (a T004 classic-table fixture, the T004
// cross-reference-stream fixture, and T014-built FlateDecode-stream and hybrid
// bases), a self-signed seal, and derived variants: a flipped signed byte, an
// appended revision (table and stream), an upper-cased /Contents, an evidence
// mismatch, an unrequested evidence check, and an unrelated anchor. The run
// list is fixed, and a count check shows every planned run was compared.
//
// Also: [VB-03] on product output, [VB-02] product reports against the contract,
// and [VB-09] the product profile (no signingTime, signingCertificateV2 present,
// no time-stamp token), which only product-sealed output can show. Agreement
// compares T014's internal result (request #44). Without the parse sandbox
// VB-05 cannot compose, so this file FAILs there, never CAPABILITY_ABSENT.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { buildVerificationReport, MAX_SEALED_PDF_BYTES, verifyPdf } from '../../../src/verifier/index.ts';
import { MAX_SEALED_PDF_BYTES as T037_MAX_SEALED_PDF_BYTES } from '../../../src/cryptograph/worker/index.ts';
import { checkOf, HEX64, runBoth } from './helpers/agreement.mjs';
import { checkPdf, createWorkDir, prepareMaterial, removeWorkDir } from './helpers/oracle.mjs';
import { appendInfoRevision, buildBase } from './helpers/pdf-build.mjs';
import { sealWithProduct, syntheticEvidenceDigest } from './helpers/product-seal.mjs';
import { loadContractSchema, validate } from './helpers/schema.mjs';

const fixture = (name) => readFileSync(fileURLToPath(new URL(`../../../fixtures/synthetic/documents/${name}`, import.meta.url)));
const EVIDENCE = syntheticEvidenceDigest('A');
const OTHER_EVIDENCE = syntheticEvidenceDigest('B');

const PLANNED_RUNS = [
  'seal-table',
  'seal-stream',
  'seal-stream-flate',
  'seal-hybrid',
  'self-signed',
  'self-signed-no-anchor',
  'unrelated-anchor',
  'flipped-range1',
  'appended-table',
  'appended-stream',
  'upper-case-contents',
  'evidence-mismatch',
  'evidence-unrequested',
];

const state = { work: null, material: null, seals: new Map(), runs: new Map(), validationTime: null };

function upperCaseContents(bytes) {
  const text = Buffer.from(bytes).toString('latin1');
  const m = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(text);
  const lt = Number(m[2]);
  const gt = Number(m[3]) - 1;
  const out = Buffer.from(bytes);
  out.write(text.slice(lt + 1, gt).toUpperCase(), lt + 1, 'latin1');
  return out;
}

before(async () => {
  state.work = createWorkDir();
  try {
    state.material = prepareMaterial(state.work);
    state.validationTime = new Date();
    const leaf = state.material.signers['dev-ca-leaf'];
    const self = state.material.signers['self-signed'];
    const bases = {
      table: fixture('single-page.pdf'),
      stream: fixture('agreement-xref-stream.pdf'),
      'stream-flate': buildBase({ xref: 'stream-flate' }).bytes,
      hybrid: buildBase({ xref: 'hybrid' }).bytes,
    };
    for (const [kind, document] of Object.entries(bases)) {
      state.seals.set(kind, await sealWithProduct({ document, signer: leaf, approvalEvidenceDigest: EVIDENCE }));
    }
    state.seals.set('self-signed', await sealWithProduct({ document: bases.table, signer: self, approvalEvidenceDigest: EVIDENCE }));

    const table = state.seals.get('table');
    const stream = state.seals.get('stream');
    const selfSeal = state.seals.get('self-signed');
    const flipped = Buffer.from(table.bytes);
    flipped[24] ^= 0x01;
    const plan = {
      'seal-table': [table.bytes, 'dev-ca', table.artifactDigest, EVIDENCE],
      'seal-stream': [stream.bytes, 'dev-ca', stream.artifactDigest, EVIDENCE],
      'seal-stream-flate': [state.seals.get('stream-flate').bytes, 'dev-ca', state.seals.get('stream-flate').artifactDigest, EVIDENCE],
      'seal-hybrid': [state.seals.get('hybrid').bytes, 'dev-ca', state.seals.get('hybrid').artifactDigest, EVIDENCE],
      'self-signed': [selfSeal.bytes, 'dev-ca', selfSeal.artifactDigest, EVIDENCE],
      'self-signed-no-anchor': [selfSeal.bytes, 'none', selfSeal.artifactDigest, EVIDENCE],
      'unrelated-anchor': [table.bytes, 'self-signed-cert', table.artifactDigest, EVIDENCE],
      'flipped-range1': [flipped, 'dev-ca', table.artifactDigest, EVIDENCE],
      'appended-table': [appendInfoRevision(table.bytes), 'dev-ca', table.artifactDigest, EVIDENCE],
      'appended-stream': [appendInfoRevision(stream.bytes), 'dev-ca', stream.artifactDigest, EVIDENCE],
      'upper-case-contents': [upperCaseContents(table.bytes), 'dev-ca', table.artifactDigest, EVIDENCE],
      'evidence-mismatch': [table.bytes, 'dev-ca', table.artifactDigest, OTHER_EVIDENCE],
      'evidence-unrequested': [table.bytes, 'dev-ca', table.artifactDigest, null],
    };
    for (const [name, [bytes, anchors, expectedArtifactDigest, expectedApprovalEvidenceDigest]] of Object.entries(plan)) {
      state.runs.set(name, runBoth({
        work: state.work,
        checkPdf,
        verifyPdf,
        bytes,
        anchorPaths: state.material.anchors[anchors],
        expectedArtifactDigest,
        expectedApprovalEvidenceDigest,
        validationTime: state.validationTime,
      }));
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

function run(name) {
  const found = state.runs.get(name);
  assert.ok(found, `run ${name} was not made`);
  return found;
}

test('[VB-05] every planned product-sealed run was compared (count check)', () => {
  assert.deepEqual([...state.runs.keys()].sort(), [...PLANNED_RUNS].sort());
  for (const seal of state.seals.values()) assert.match(seal.artifactDigest, HEX64, 'the sealing step reports the artifact digest');
});

test('[VB-05] the sealing step and the verifier agree on the signer certificate digest and on the sealed-PDF bound', () => {
  const pairs = { 'seal-table': 'table', 'seal-stream': 'stream', 'seal-stream-flate': 'stream-flate', 'seal-hybrid': 'hybrid', 'self-signed': 'self-signed' };
  for (const [runName, sealName] of Object.entries(pairs)) {
    const reported = state.seals.get(sealName).signerCertificateSha256;
    assert.match(reported, HEX64, sealName);
    assert.equal(run(runName).product.signer_certificate_sha256, reported, sealName);
  }
  assert.equal(T037_MAX_SEALED_PDF_BYTES, MAX_SEALED_PDF_BYTES, 'T037 re-exports the same bound');
});

for (const name of PLANNED_RUNS) {
  test(`[VB-05] ${name}: the verifier and the oracle agree on product-sealed output`, () => {
    const { diff, product } = run(name);
    assert.deepEqual(diff, []);
    assert.notEqual(product.integrity, 'indeterminate');
  });
}

test('[VB-05] each clean product seal is valid, trusted, complete, matching and accepted on every base kind', () => {
  for (const name of ['seal-table', 'seal-stream', 'seal-stream-flate', 'seal-hybrid']) {
    const { product } = run(name);
    assert.equal(product.integrity, 'valid', name);
    assert.equal(product.trust, 'trusted', name);
    assert.equal(product.revision_coverage, 'complete', name);
    assert.equal(product.artifact_match, true, name);
    assert.equal(product.approval_evidence, 'match', name);
    assert.equal(product.accepted_as_original, true, name);
  }
});

test('[VB-05] the product-sealed variants give the expected verdicts on both sides', () => {
  const expect = {
    'self-signed': { integrity: 'valid', trust: 'untrusted' },
    'self-signed-no-anchor': { integrity: 'valid', trust: 'untrusted' },
    'unrelated-anchor': { integrity: 'valid', trust: 'untrusted' },
    'flipped-range1': { integrity: 'invalid', trust: 'indeterminate', artifact_match: false },
    'appended-table': { integrity: 'valid', revision_coverage: 'incomplete', accepted_as_original: false },
    'appended-stream': { integrity: 'valid', revision_coverage: 'incomplete', accepted_as_original: false },
    'upper-case-contents': { integrity: 'valid', artifact_match: false, accepted_as_original: false },
  };
  for (const [name, fields] of Object.entries(expect)) {
    const { oracle, product } = run(name);
    for (const [field, value] of Object.entries(fields)) {
      assert.equal(product[field], value, `${name} ${field}`);
      if (Object.hasOwn(oracle, field)) assert.equal(oracle[field], value, `${name} oracle ${field}`);
    }
  }
});

test('[VB-09] product-sealed output shows no signingTime, no missing signingCertificateV2 and no time-stamp token', () => {
  for (const name of ['seal-table', 'seal-stream', 'seal-stream-flate', 'seal-hybrid', 'self-signed']) {
    const { product } = run(name);
    assert.equal(checkOf(product, 'profile-signing-time').result, 'pass', name);
    assert.equal(checkOf(product, 'profile-signing-certificate-v2').result, 'pass', name);
    assert.equal(product.timestamp_status, 'absent', name);
    assert.equal(checkOf(product, 'signer-binding').result, 'pass', name);
    assert.equal(checkOf(product, 'contents-padding').result, 'pass', name);
  }
});

test('[VB-05] product-sealed output always carries both digests, so its contract report is always emitted', () => {
  for (const name of ['seal-table', 'seal-stream', 'seal-stream-flate', 'seal-hybrid', 'self-signed']) {
    const { product } = run(name);
    assert.match(product.signer_certificate_sha256, HEX64, name);
    assert.equal(product.approval_evidence_digest, EVIDENCE, name);
    assert.equal(buildVerificationReport(product, { verifiedAt: state.validationTime }).ok, true, name);
  }
});

test('[VB-03] on product output the evidence digest is the one passed to the seal; a different digest is a mismatch', () => {
  const sealed = run('seal-table').product;
  assert.equal(sealed.approval_evidence_digest, EVIDENCE);
  assert.equal(checkOf(sealed, 'approval-evidence-digest').result, 'pass');
  const mismatch = run('evidence-mismatch').product;
  assert.equal(mismatch.approval_evidence, 'mismatch');
  assert.equal(mismatch.accepted_as_original, false);
  assert.equal(checkOf(mismatch, 'approval-evidence-digest').detail, 'mismatch');
  const unrequested = run('evidence-unrequested').product;
  assert.equal(unrequested.approval_evidence, 'not-requested');
  assert.equal(unrequested.approval_evidence_digest, EVIDENCE);
});

test('[VB-02] reports from product-sealed outcomes validate against the vendored VerificationReport schema', () => {
  const { contract, schema } = loadContractSchema('VerificationReport');
  for (const name of ['seal-table', 'seal-hybrid', 'self-signed', 'flipped-range1', 'appended-table']) {
    const built = buildVerificationReport(run(name).product, { verifiedAt: state.validationTime });
    assert.equal(built.ok, true, `${name}: ${built.ok ? '' : built.field}`);
    assert.deepEqual(validate(schema, built.report, contract), [], name);
    assert.equal(built.report.timestamp_status, 'absent', name);
    assert.equal(built.report.revocation_status, 'not-checked', name);
  }
});
