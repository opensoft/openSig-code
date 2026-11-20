// SPDX-License-Identifier: Apache-2.0
//
// Contract limits on write (T038, row P13; FEN-06): 0005's verifier columns,
// trust_anchor_ref and nullable signer digest, and 0004's last_error_code are
// wider than the contract, so the repositories refuse a value the contract
// would not carry, before any write, naming the field and never echoing the
// value. Synthetic data in a migrated temporary database.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { canonicalBytes } from '../../src/domain/canonical/index.ts';
import { FinalArtifactInvalid, MAX_TRUST_ANCHOR_REF, MAX_VERIFIER_NAME, MAX_VERIFIER_VERSION } from '../../src/storage/repositories/artifacts.ts';
import { checkErrorCode, MAX_ERROR_CODE_LENGTH, recordAttemptFailure } from '../../src/storage/repositories/jobs.ts';
import { assertUnchanged, holderOf, lease, publish } from './support/steps.mjs';
import { assembleAttempt, makeWorld, seedFinalizing, snapshot } from './support/world.mjs';

function withReport(assembled, change) {
  const report = JSON.parse(Buffer.from(assembled.reportBytes).toString('utf8'));
  change(report);
  return { ...assembled, reportBytes: canonicalBytes(report) };
}

test('[FEN-06] artifact and report values outside the contract are refused before any write; values at the limits publish', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    const assembled = assembleAttempt(world, envelopeId);
    const before = snapshot(world, envelopeId);
    const outside = [
      ['packageDigest', { ...assembled, artifact: { ...assembled.artifact, packageDigest: 'A'.repeat(64) } }],
      // A digest that is not the report's is refused before its own format check.
      ['report.approval_evidence_digest', { ...assembled, artifact: { ...assembled.artifact, approvalEvidenceDigest: null } }],
      ['developmentCertificate', { ...assembled, artifact: { ...assembled.artifact, developmentCertificate: 1 } }],
      ['report.verifier.name', withReport(assembled, (report) => (report.verifier.name = 'v'.repeat(MAX_VERIFIER_NAME + 1)))],
      ['report.verifier.version', withReport(assembled, (report) => (report.verifier.version = '1'.repeat(MAX_VERIFIER_VERSION + 1)))],
      ['report.trust_anchor_ref', withReport(assembled, (report) => (report.trust_anchor_ref = 'r'.repeat(MAX_TRUST_ANCHOR_REF + 1)))],
      ['report.signer_certificate_sha256', withReport(assembled, (report) => (report.signer_certificate_sha256 = null))],
      ['report.artifact_digest', withReport(assembled, (report) => (report.artifact_digest = 'b'.repeat(64)))],
      ['reportBytes', { ...assembled, reportBytes: Buffer.from('[]') }],
    ];
    for (const [field, input] of outside) {
      assert.throws(
        () => publish(world, grant, input),
        (error) => error instanceof FinalArtifactInvalid && error.field === field,
        `${field}: refused naming the field`,
      );
      assertUnchanged(world, envelopeId, before, `${field}: nothing was written`);
    }
    publish(
      world,
      grant,
      withReport(assembled, (report) => {
        report.verifier.name = 'v'.repeat(MAX_VERIFIER_NAME);
        report.verifier.version = '1'.repeat(MAX_VERIFIER_VERSION);
      }),
    );
    const after = snapshot(world, envelopeId);
    assert.equal(after.artifacts.length, 1, `the boundary values publish (artifacts ${after.artifacts.length})`);
    assert.equal(after.artifacts[0].verifier_name.length, MAX_VERIFIER_NAME);
  } finally {
    world.close();
  }
});

test('[FEN-06] last_error_code longer than the contract’s 60 characters is refused and writes nothing', () => {
  assert.equal(checkErrorCode('e'.repeat(MAX_ERROR_CODE_LENGTH)), 'e'.repeat(MAX_ERROR_CODE_LENGTH));
  assert.throws(() => checkErrorCode('e'.repeat(MAX_ERROR_CODE_LENGTH + 1)), (error) => error?.code === 'storage_usage');
  assert.throws(() => checkErrorCode('Seal Failed'), (error) => error?.code === 'storage_usage');
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    const before = snapshot(world, envelopeId);
    assert.throws(
      () =>
        world.db.transaction(() =>
          recordAttemptFailure(world.store, holderOf(grant), { now: world.clock.now(), retryable: true, errorCode: 'e'.repeat(MAX_ERROR_CODE_LENGTH + 1) }),
        ),
      (error) => error?.code === 'storage_usage',
    );
    assertUnchanged(world, envelopeId, before, `a ${MAX_ERROR_CODE_LENGTH + 1}-character last_error_code wrote nothing`);
    assert.equal(before.job.status, 'running', `the job is ${before.job.status}`);
  } finally {
    world.close();
  }
});
