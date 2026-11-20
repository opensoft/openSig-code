// SPDX-License-Identifier: Apache-2.0
//
// The finalization runner (T038; A-008 S1; A-010 S4 and request #59 (3), (5)
// and (7); FEN-07 and FEN-08). The runner reads real seal records (T010's
// approvals, the frozen revision and field manifest) and drives every durable
// step for real: the seal anchor, the attempt records, the blob writes, the
// completion checkpoint and the publish. Only the CPU-bound components are
// fakes behind the runner's ports: T036's compose, T037's seal and T014's
// verify (their own suites cover them), and the package builder, which T016's
// suite covers. The key file is a synthetic placeholder opened by the real
// openSealKey. Synthetic data, injected clock, timers that never fire (the
// keeper never renews; its deadline still applies).

import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { canonicalBytes, canonicalDigest } from '../../src/domain/canonical/index.ts';
import { StepFailure } from '../../src/domain/finalization/index.ts';
import { FinalizationRunner } from '../../src/jobs/finalize.ts';
import { getCompletionCheckpoint } from '../../src/storage/repositories/artifacts.ts';
import { ATTEMPT_GRACE_MS, attemptCollectable, DEFAULT_LEASE_MS, listAttemptBlobs, retryDelayMs } from '../../src/storage/repositories/jobs.ts';
import { eventsOf } from './support/steps.mjs';
import { describe, makeWorld, reportBytesFor, RESERVED_VERSION, seedSealable, sha256, snapshot, syntheticBytes } from './support/world.mjs';

const NEVER = Object.freeze({ setTimeout: () => 0, clearTimeout: () => undefined });

/** The blob store behind the runner, delegating to the world's, with a hook before each put and an optional check. */
function hookedBlobs(world, beforePut, check) {
  const inner = world.blobs;
  const realCheck = (...args) => inner.check(...args);
  return {
    put: (tenantId, bytes, options) => {
      beforePut(bytes);
      return inner.put(tenantId, bytes, options);
    },
    putStream: (...args) => inner.putStream(...args),
    read: (...args) => inner.read(...args),
    readRef: (...args) => inner.readRef(...args),
    check: check === undefined ? realCheck : check(realCheck),
    list: (...args) => inner.list(...args),
    dispose: (...args) => inner.dispose(...args),
    sweepPartials: (...args) => inner.sweepPartials(...args),
  };
}

function makeRunner(world, { verify, buildPackage, beforePut = () => undefined, check } = {}) {
  const keyFile = join(world.dir, 'synthetic-seal-key');
  writeFileSync(keyFile, 'synthetic placeholder, never a key\n', { mode: 0o600 });
  const certificateDer = syntheticBytes('certificate-der', 64);
  const calls = { compose: [], seal: [], verify: [], packages: [] };
  const ports = {
    // Deterministic over the document and sealTime, as T036 is.
    compose: async (request) => {
      calls.compose.push(request);
      const bytes = Buffer.concat([Buffer.from(request.document), Buffer.from(`synthetic composition at ${request.sealTime}`)]);
      return { bytes, digest: sha256(bytes), documentDigest: sha256(request.document), documentLength: request.document.length, byteRange: [0, 1, 2, 3], contents: { offset: 1, hexLength: 2 }, signedDataLength: 1, xrefKind: 'table' };
    },
    // Deterministic over the composition and the evidence digest (the product CMS has no signingTime).
    sealPdf: async (input, options) => {
      calls.seal.push({ input, options });
      const bytes = Buffer.concat([Buffer.from(input.composed.bytes), Buffer.from(input.approvalEvidenceDigest)]);
      return { bytes, finalPdfDigest: sha256(bytes), signerCertificateSha256: sha256(input.certificateDer) };
    },
    verify: async (job, options) => {
      calls.verify.push(job);
      if (verify !== undefined) return verify(job, options, calls.verify.length);
      return reportBytesFor({ artifactDigest: job.expectedArtifactDigest, approvalEvidenceDigest: job.expectedApprovalEvidenceDigest, verifiedAt: job.validationTime });
    },
  };
  // Stands in for T016's buildPackage, whose own suite covers it: same input, the BuiltPackage fields the runner reads.
  const build = (inputs) => {
    calls.packages.push(inputs);
    const bytes =
      buildPackage !== undefined
        ? buildPackage(inputs, calls.packages.length)
        : canonicalBytes({ synthetic_package: true, checkpoint: inputs.checkpoint, events: inputs.events.length, pdf: sha256(inputs.finalPdf) });
    return { bytes, packageDigest: sha256(bytes), artifactDigest: sha256(inputs.finalPdf) };
  };
  const runner = new FinalizationRunner({
    db: world.db,
    audit: world.audit,
    blobs: hookedBlobs(world, beforePut, check),
    clock: world.clock.now,
    owner: 'runner-test',
    seal: { keyFile, certificateDer, developmentCertificate: true },
    anchors: [],
    buildPackage: build,
    ports,
    timers: NEVER,
  });
  return { runner, calls, certificateDer };
}

const roles = (world, envelopeId, token) => listAttemptBlobs(world.store, envelopeId).filter((record) => record.fencingToken === token).map((record) => record.role);
const hexOf = (bytes) => Buffer.from(bytes).toString('hex');

test('[FEN-07] the pre-seal manifest is built from the stored records; its RFC 8785 digest goes to the seal unchanged and is stored with the artifact', async () => {
  const world = makeWorld();
  try {
    const seeded = seedSealable(world);
    const { runner, calls, certificateDer } = makeRunner(world);
    const outcome = await runner.runAttempt(world.tenantId, seeded.envelopeId);
    assert.equal(outcome.kind, 'published', `outcome ${JSON.stringify(outcome)}`);
    const after = snapshot(world, seeded.envelopeId);
    const [artifact] = after.artifacts;
    const digest = artifact.approval_evidence_digest;
    const sealed = hexOf(calls.seal[0].input.approvalEvidenceDigest);
    assert.equal(sealed, digest, `the seal received ${sealed}; stored ${digest}`);
    assert.equal(calls.verify[0].expectedApprovalEvidenceDigest, digest, `T014 checked against ${calls.verify[0].expectedApprovalEvidenceDigest}; stored ${digest}`);

    // approval-manifest.json: the pre-seal manifest plus final_pdf_digest; the digest is over the manifest without it.
    const evidenceBytes = world.blobs.readRef(world.tenantId, artifact.evidence_blob_ref);
    const evidence = JSON.parse(evidenceBytes.toString('utf8'));
    const { final_pdf_digest: finalPdfDigest, ...preSeal } = evidence;
    assert.equal(finalPdfDigest, artifact.artifact_digest, `final_pdf_digest ${finalPdfDigest}, artifact ${artifact.artifact_digest}`);
    const recomputed = canonicalDigest(preSeal);
    assert.equal(recomputed, digest, `SHA-256 of the RFC 8785 pre-seal manifest is ${recomputed}; stored ${digest}`);
    assert.ok(Buffer.from(evidenceBytes).equals(canonicalBytes(evidence)), `the evidence blob (${evidenceBytes.length} bytes, sha256 ${sha256(evidenceBytes)}) is canonical`);
    assert.deepEqual(
      [preSeal.schema, preSeal.envelope_id, preSeal.envelope_version, preSeal.document.digest, preSeal.manifest_digest],
      ['opensig.approval-manifest/1', seeded.envelopeId, RESERVED_VERSION, seeded.documentDigest, seeded.manifestDigest],
      `manifest ${preSeal.schema} ${preSeal.envelope_id} v${preSeal.envelope_version} document ${preSeal.document.digest} manifest ${preSeal.manifest_digest}`,
    );
    const fieldManifestDigest = sha256(canonicalBytes(preSeal.field_manifest));
    assert.equal(fieldManifestDigest, seeded.manifestDigest, `the frozen field manifest hashes to ${fieldManifestDigest}, stored ${seeded.manifestDigest}`);
    const approval = world.store.get('approvals', { recipient_id: seeded.recipientId });
    assert.equal(preSeal.approvals.length, 1, `approvals ${preSeal.approvals.length}`);
    assert.equal(preSeal.approvals[0].approval_digest, approval.approval_digest, `approval digest ${preSeal.approvals[0].approval_digest}, stored ${approval.approval_digest}`);
    const { approval_digest: approvalDigest, ...record } = preSeal.approvals[0];
    const recordDigest = canonicalDigest(record);
    assert.equal(recordDigest, approvalDigest, `the ApprovalRecord hashes to ${recordDigest}, stored ${approvalDigest}`);
    assert.deepEqual(preSeal.consent_texts.map((consent) => consent.text_digest), [approval.consent_text_digest]);
    assert.equal(preSeal.approved_composition_digest, artifact.approved_composition_digest, `composition ${preSeal.approved_composition_digest}, artifact ${artifact.approved_composition_digest}`);
    assert.deepEqual(preSeal.seal, { type: 'organization', signer_certificate_sha256: sha256(certificateDer), development_certificate: true });
    const [anchor] = eventsOf(world, seeded.envelopeId, 'envelope.seal_started');
    assert.deepEqual(preSeal.seal_audit_anchor, { seq: anchor.seq, event_digest: anchor.event_digest });
    assert.equal(calls.compose[0].sealTime, anchor.server_time, `T036 composed at ${calls.compose[0].sealTime}; the anchor is ${anchor.server_time}`);
    const document = world.blobs.readRef(world.tenantId, `tenants/${world.tenantId}/sha256/${seeded.documentDigest}`);
    assert.ok(Buffer.from(calls.compose[0].document).equals(document), `T036 got ${calls.compose[0].document.length} bytes of the ${document.length}-byte frozen document`);
  } finally {
    world.close();
  }
});

test('[FEN-07] a retry reuses the seal anchor: one seal_started event, the same sealTime, the same evidence digest', async () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedSealable(world);
    const { runner, calls } = makeRunner(world, {
      verify: (job, _options, call) => {
        if (call === 1) throw new StepFailure('verification_timeout', 'cap', true);
        return reportBytesFor({ artifactDigest: job.expectedArtifactDigest, approvalEvidenceDigest: job.expectedApprovalEvidenceDigest, verifiedAt: job.validationTime });
      },
    });
    const first = await runner.runAttempt(world.tenantId, envelopeId);
    assert.deepEqual(first, { kind: 'retryable', errorCode: 'verification_timeout.cap' }, `attempt 1: ${JSON.stringify(first)}`);
    assert.deepEqual(roles(world, envelopeId, 1), ['composed'], `attempt 1 recorded ${JSON.stringify(roles(world, envelopeId, 1))}`);
    world.clock.advance(retryDelayMs(1));
    const second = await runner.runAttempt(world.tenantId, envelopeId);
    assert.equal(second.kind, 'published', `attempt 2: ${JSON.stringify(second)}`);
    const anchors = eventsOf(world, envelopeId, 'envelope.seal_started').length;
    assert.equal(anchors, 1, `the anchor is written once (got ${anchors})`);
    assert.equal(calls.compose[1].sealTime, calls.compose[0].sealTime, `sealTime ${calls.compose[0].sealTime} then ${calls.compose[1].sealTime}`);
    const [digestOne, digestTwo] = [hexOf(calls.seal[0].input.approvalEvidenceDigest), hexOf(calls.seal[1].input.approvalEvidenceDigest)];
    assert.equal(digestTwo, digestOne, `the evidence digest ${digestOne} then ${digestTwo}`);
    assert.deepEqual(roles(world, envelopeId, 2), ['composed', 'sealed', 'evidence', 'package'], `attempt 2 recorded ${JSON.stringify(roles(world, envelopeId, 2))}`);
    const published = snapshot(world, envelopeId).artifacts[0].fencing_token;
    assert.equal(published, 2, `the artifact carries attempt ${published}`);
  } finally {
    world.close();
  }
});

test('[FEN-08] every blob is recorded before it is stored; the checkpoint is written once and reused; the package gets the receipt up to it and the exact report', async () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedSealable(world);
    const puts = [];
    const { runner, calls } = makeRunner(world, {
      buildPackage: (inputs, call) => {
        if (call === 1) throw new Error('synthetic package failure');
        return canonicalBytes({ synthetic_package: true, pdf: sha256(inputs.finalPdf) });
      },
      beforePut: (bytes) => {
        const ref = `tenants/${world.tenantId}/sha256/${sha256(bytes)}`;
        const recorded = world.store.list('finalization_attempt_blobs', { blob_ref: ref });
        puts.push(recorded.length);
        assert.ok(recorded.length > 0, `${ref} is recorded before it is stored (records ${recorded.length})`);
      },
    });
    const first = await runner.runAttempt(world.tenantId, envelopeId);
    assert.deepEqual(first, { kind: 'retryable', errorCode: 'internal.package' }, `attempt 1: ${JSON.stringify(first)}`);
    const checkpoint = getCompletionCheckpoint(world.store, envelopeId);
    assert.ok(checkpoint, `the first attempt wrote the completion checkpoint (got ${JSON.stringify(checkpoint)})`);
    const once = world.store.count('audit_checkpoints', { kind: 'completion' });
    assert.equal(once, 1, `completion checkpoints ${once}`);
    world.clock.advance(retryDelayMs(1));
    const second = await runner.runAttempt(world.tenantId, envelopeId);
    assert.equal(second.kind, 'published', `attempt 2: ${JSON.stringify(second)}`);
    const reused = world.store.count('audit_checkpoints', { kind: 'completion' });
    assert.equal(reused, 1, `the retry reused it (checkpoints ${reused})`);
    assert.equal(puts.length, 3 + 4, `three puts in the failed attempt and four in the published one, each after its record (got ${puts.length}: ${JSON.stringify(puts)})`);

    const inputs = calls.packages[1];
    assert.deepEqual(inputs.checkpoint, checkpoint);
    assert.deepEqual(inputs.chainHead, { seq: checkpoint.seq, digest: checkpoint.digest });
    assert.deepEqual([inputs.tenantId, inputs.envelopeId], [world.tenantId, envelopeId]);
    const seqs = inputs.events.map(({ event }) => event.seq);
    assert.ok(
      inputs.events.length >= 1 && inputs.events.every(({ event }) => event.seq <= checkpoint.seq && event.envelopeId === envelopeId),
      `the receipt's events ${JSON.stringify(seqs)} run to the checkpoint seq ${checkpoint.seq}, all of ${envelopeId}`,
    );
    const types = inputs.events.map(({ event }) => event.type);
    assert.ok(types.includes('envelope.seal_started'), `the receipt holds the anchor (types ${JSON.stringify(types)})`);
    const after = snapshot(world, envelopeId);
    const [artifact] = after.artifacts;
    assert.equal(inputs.approvalManifest.final_pdf_digest, artifact.artifact_digest, `final_pdf_digest ${inputs.approvalManifest.final_pdf_digest}, artifact ${artifact.artifact_digest}`);
    assert.equal(sha256(inputs.finalPdf), artifact.artifact_digest, `the package's PDF hashes to ${sha256(inputs.finalPdf)}, artifact ${artifact.artifact_digest}`);
    assert.equal(inputs.artifactId, artifact.artifact_id, `the package names artifact ${inputs.artifactId}; published ${artifact.artifact_id}`);
    const [report] = world.store.list('verification_reports', { envelope_id: envelopeId });
    assert.ok(
      Buffer.from(inputs.verification).equals(Buffer.from(report.report_bytes)),
      `verification.json (sha256 ${sha256(inputs.verification)}) is the stored report (sha256 ${sha256(report.report_bytes)})`,
    );
    const expectedPackage = sha256(canonicalBytes({ synthetic_package: true, pdf: artifact.artifact_digest }));
    assert.equal(artifact.package_digest, expectedPackage, `package_digest ${artifact.package_digest}, built ${expectedPackage}`);
    assert.equal(world.blobs.check(world.tenantId, artifact.package_digest), 'ok');
  } finally {
    world.close();
  }
});

test('[FEN-08] an attempt that loses its lease after storing its package publishes nothing and records nothing more; its package stays collectable', async () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedSealable(world);
    let packageDigest;
    const { runner } = makeRunner(world, {
      buildPackage: (inputs) => {
        const bytes = canonicalBytes({ synthetic_package: true, pdf: sha256(inputs.finalPdf) });
        packageDigest = sha256(bytes);
        return bytes;
      },
      beforePut: (bytes) => {
        // The package is the last blob: the attempt stalls past its lease before publishing.
        if (sha256(bytes) === packageDigest) world.clock.advance(DEFAULT_LEASE_MS + 1_000);
      },
    });
    const outcome = await runner.runAttempt(world.tenantId, envelopeId);
    assert.deepEqual(outcome, { kind: 'lost' }, `outcome ${JSON.stringify(outcome)}`);
    const after = snapshot(world, envelopeId);
    assert.deepEqual([after.artifacts.length, after.reports, after.outbox.length], [0, 0, 0], `nothing published: ${describe(after)}`);
    assert.equal(after.job.status, 'running', `a lost attempt records no failure; the reclaim does (${describe(after)})`);
    const [last] = world.store.list('audit_events', {}, { orderBy: [['seq', 'desc']], limit: 1 });
    const head = getCompletionCheckpoint(world.store, envelopeId).seq;
    assert.equal(last.seq, head, `no event after the checkpoint: last seq ${last.seq}, checkpoint seq ${head}`);
    const failed = eventsOf(world, envelopeId, 'envelope.finalization_failed').length;
    assert.equal(failed, 0, `finalization_failed events ${failed}`);
    assert.deepEqual(roles(world, envelopeId, 1), ['composed', 'sealed', 'evidence', 'package'], `attempt 1 recorded ${JSON.stringify(roles(world, envelopeId, 1))}`);
    assert.equal(world.blobs.check(world.tenantId, packageDigest), 'ok', `package ${packageDigest} stored`);
    const within = attemptCollectable(world.store, envelopeId, 1, world.clock.now());
    assert.equal(within, false, `within the grace at ${world.clock.iso()}, collectable ${within}`);
    world.clock.advance(ATTEMPT_GRACE_MS);
    const later = attemptCollectable(world.store, envelopeId, 1, world.clock.now());
    assert.equal(later, true, `after lease end + 24 h, at ${world.clock.iso()}, collectable ${later}`);
  } finally {
    world.close();
  }
});

test('[FEN-08] a publish refused because a stored blob is missing is the retryable failure publish_refused.blob-missing, and publishes nothing', async () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedSealable(world);
    let packageDigest;
    const { runner } = makeRunner(world, {
      buildPackage: (inputs) => {
        const bytes = canonicalBytes({ synthetic_package: true, pdf: sha256(inputs.finalPdf) });
        packageDigest = sha256(bytes);
        return bytes;
      },
      // The publish's check finds the package missing (removed between its write and the publish).
      check: (real) => (tenantId, digest) => (digest === packageDigest ? 'missing' : real(tenantId, digest)),
    });
    const outcome = await runner.runAttempt(world.tenantId, envelopeId);
    assert.deepEqual(outcome, { kind: 'retryable', errorCode: 'publish_refused.blob-missing' }, `outcome ${JSON.stringify(outcome)}`);
    const after = snapshot(world, envelopeId);
    assert.deepEqual(
      [after.artifacts.length, after.reports, after.outbox.length, after.envelope.state],
      [0, 0, 0, 'finalizing'],
      `nothing published: ${describe(after)}`,
    );
    assert.deepEqual(
      [after.job.status, after.job.last_error_code, after.job.lease_owner],
      ['retryable', 'publish_refused.blob-missing', null],
      `the attempt's failure is recorded under its lease: ${describe(after)}`,
    );
    const failed = eventsOf(world, envelopeId, 'envelope.finalization_failed').length;
    assert.equal(failed, 0, `a retryable failure announces nothing (finalization_failed events ${failed})`);
  } finally {
    world.close();
  }
});
