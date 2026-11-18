// SPDX-License-Identifier: Apache-2.0
//
// T012 independent integrity oracle: corpus cases OC-01..OC-09 (plan.md
// § Case catalogs, OC). Imports nothing from src/. Signing and verification
// run only through the OpenSSL CLI; runtime material lives in an owner-only
// mkdtemp directory (0700, private keys 0600) that is removed in `finally`.
// The whole corpus is built before any case runs, so a failed build stops the
// run and no case is skipped.

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { test } from 'node:test';
import { buildCorpus, loadCaseManifest, prepareMaterial, syntheticDigest } from './lib/corpus.mjs';
import { createWorkDir, modeOf, removeWorkDir } from './lib/openssl.mjs';
import { checkPdf, sha256Hex, verifiesOver } from './lib/oracle.mjs';

const manifest = loadCaseManifest();
const CASE_IDS = ['OC-01', 'OC-02', 'OC-03', 'OC-04', 'OC-05', 'OC-06', 'OC-07', 'OC-08', 'OC-09'];
const REPORT_FIELDS = ['integrity', 'trust', 'revision_coverage', 'artifact_match', 'approval_evidence', 'accepted_as_original'];

function summary(report) {
  const { checks, ...fields } = report;
  return JSON.stringify({ ...fields, checks });
}

function runCase(work, material, entry) {
  const d = entry.descriptor;
  const anchors = material.anchors[d.anchors];
  assert.ok(anchors, `${d.id}: unknown anchor set ${d.anchors}`);
  const label = d.check?.expected_approval_evidence_label;
  const report = checkPdf(work, entry.bytes, {
    anchors,
    expectedArtifactDigest: entry.originalDigest,
    expectedApprovalEvidenceDigest: label === undefined ? null : syntheticDigest(label).toString('hex'),
  });
  const why = `${d.id}: ${summary(report)}`;
  for (const field of REPORT_FIELDS) assert.equal(report[field], d.expected[field], `${field} — ${why}`);
  for (const field of ['signed_revision', 'revision_count']) {
    if (d.expected[field] !== undefined) assert.equal(report[field], d.expected[field], `${field} — ${why}`);
  }
  for (const [id, result] of Object.entries(d.expected.checks ?? {})) {
    const check = report.checks.find((c) => c.id === id);
    assert.ok(check, `check ${id} missing — ${why}`);
    assert.equal(check.result, result, `check ${id} — ${why}`);
  }
  for (const [id, detail] of Object.entries(d.expected.check_details ?? {})) {
    assert.equal(report.checks.find((c) => c.id === id)?.detail_code, detail, `detail of ${id} — ${why}`);
  }
  if (d.expected.accepted_as_original === true) {
    // Request #39 Q3: acceptance needs a supplied, matching digest; without one it is never accepted.
    const bare = checkPdf(work, entry.bytes, {
      anchors,
      expectedApprovalEvidenceDigest: label === undefined ? null : syntheticDigest(label).toString('hex'),
    });
    assert.equal(bare.artifact_match, null, `${d.id}: no recorded digest supplied`);
    assert.equal(bare.accepted_as_original, false, `${d.id}: accepted without a recorded digest`);
  }
  if (d.signing?.approval_evidence) {
    assert.deepEqual(entry.controls, { splicedVerifies: true, oldSignatureRejected: true }, `${d.id}: splice controls`);
  }
  if (d.assert_profile) {
    assert.equal(report.cms_der_sha256, sha256Hex(entry.der), `extracted DER differs from the openssl output — ${why}`);
    assert.deepEqual(report.profile, {
      detached: true, digest_sha256: true, content_type_data: true, signing_certificate_v2: true,
      // OpenSSL 3.0 `cms -sign` adds signingTime; it never changes a verdict (request #39, Q4).
      signing_time: true, certificate_count: 1,
    }, why);
    assert.match(report.signer_certificate_sha256 ?? '', /^[0-9a-f]{64}$/, why);
  }
  if (d.control === 'verify-whole-file') {
    assert.equal(verifiesOver(work, entry.der, entry.ranges), true, `${d.id}: control must verify over the ranges`);
    assert.equal(verifiesOver(work, entry.der, entry.bytes), false, `${d.id}: the CMS must not verify over the whole file`);
  }
}

test('[OC-LIFECYCLE] runtime material is owner-only (0700 directory, 0600 keys) and removed in finally', async (t) => {
  const work = createWorkDir();
  try {
    assert.equal(modeOf(work.dir), 0o700, 'work directory mode');
    const material = prepareMaterial(work);
    for (const path of material.privateKeyPaths) assert.equal(modeOf(path), 0o600, 'private key file mode');
    const corpus = buildCorpus(work, material, manifest); // throws: run stopped, nothing skipped

    await t.test('[OC-01] the descriptor set is complete and counted', () => {
      assert.equal(manifest.schema, 'opensig.integrity-oracle.cases/1');
      assert.equal(manifest.cases.length, manifest.case_count, 'descriptor count check');
      assert.equal(corpus.length, manifest.case_count, 'built corpus count check');
      const ids = manifest.cases.map((d) => d.id);
      assert.equal(new Set(ids).size, ids.length, 'descriptor ids are unique');
      for (const d of manifest.cases) assert.ok(d.id.startsWith(`${d.case}-`), `${d.id} is filed under ${d.case}`);
      for (const id of CASE_IDS) assert.ok(manifest.cases.some((d) => d.case === id), `${id} has a descriptor`);
    });

    for (const entry of corpus) {
      const d = entry.descriptor;
      await t.test(`[${d.case}] ${d.id}: ${d.title}`, () => runCase(work, material, entry));
    }
  } finally {
    removeWorkDir(work);
  }
  assert.equal(existsSync(work.dir), false, 'work directory removed');
});
