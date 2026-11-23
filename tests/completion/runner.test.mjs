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
//
// The T038 correction (A-010 requests #80 (3) and #81 (7); FEN-01 extended):
// stop() aborts an attempt in flight through its lease keeper and resolves
// once it has unwound, with nothing written after the abort and no timer left
// (row RUNNER-STOP), and start()'s loop passes a rejected run to onError and
// carries on (row RUN-ERRORS). FEN-08 (extended) reaches publish step 3's
// refusal (finding F-3). The verify step there is the real runVerification
// with a worker that never answers; the database seam only replaces a read of
// the completion checkpoint and counts runs.
//
// The T038 correction FV-DIGEST (A-010 request #85 (1); FEN-07 extended):
// readSealRecords recomputes T010's fieldValuesDigest over each approval's
// stored values and its server-day dates, after the approval-digest
// comparison. Rows R0 (one and two recipients with a date field publish while
// the runner clock is on another UTC day than server_time), R1-R3 (a forged
// field_values_digest under a consistent approval_digest, at ordinal 1 of 1,
// 1 of 2 and 2 of 2, is refused before the seal anchor) and R4-R5 (the
// approval-digest refusal at ordinals 1 and 2) use support/sealable.mjs.

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { SealError } from '../../src/cryptograph/worker/index.ts';
import { fieldValuesDigest } from '../../src/domain/approval/index.ts';
import { canonicalBytes, canonicalDigest } from '../../src/domain/canonical/index.ts';
import { LeaseLost, reclaimLease, runVerification, StepFailure, VERIFY_WALL_CAP_MS } from '../../src/domain/finalization/index.ts';
import { FinalizationRunner } from '../../src/jobs/finalize.ts';
import { StorageUsageError } from '../../src/storage/db/index.ts';
import { getCompletionCheckpoint } from '../../src/storage/repositories/artifacts.ts';
import { ATTEMPT_GRACE_MS, attemptCollectable, DEFAULT_LEASE_MS, LEASE_EXPIRED_ERROR_CODE, listAttemptBlobs, retryDelayMs } from '../../src/storage/repositories/jobs.ts';
import { seedSealableWith } from './support/sealable.mjs';
import { assertUnchanged, eventsOf, lease, outboxOf, publish, refusedWith } from './support/steps.mjs';
import { assembleAttempt, describe, hex, makeWorld, reportBytesFor, RESERVED_VERSION, seedFinalizing, seedSealable, sha256, snapshot, syntheticBytes } from './support/world.mjs';

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

function makeRunner(world, { verify, sealPdf, buildPackage, beforePut = () => undefined, check, timers = NEVER, clock = world.clock.now, db = world.db, onError } = {}) {
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
      if (sealPdf !== undefined) return sealPdf(input, options, calls.seal.length);
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
    db,
    audit: world.audit,
    blobs: hookedBlobs(world, beforePut, check),
    clock,
    owner: 'runner-test',
    seal: { keyFile, certificateDer, developmentCertificate: true },
    anchors: [],
    buildPackage: build,
    ports,
    timers,
    onError,
  });
  return { runner, calls, certificateDer };
}

/** Lease timers that never fire and keep the live ones (the keeper's renewal), so a test sees what is left. */
function countingTimers() {
  const live = new Set();
  return {
    live,
    setTimeout: (callback, ms) => {
      const handle = { callback, ms };
      live.add(handle);
      return handle;
    },
    clearTimeout: (handle) => {
      live.delete(handle);
    },
  };
}

/** A verify worker that never answers and counts terminate() calls. */
function heldWorker() {
  const worker = new EventEmitter();
  worker.terminated = 0;
  worker.terminate = () => {
    worker.terminated += 1;
  };
  return worker;
}

/** 'settled' when `promise` settles within `ms`, otherwise a note of the bound; no timer is left behind. */
async function within(promise, ms) {
  let handle;
  const bound = new Promise((resolve) => {
    handle = setTimeout(() => resolve(`still pending after ${ms} ms`), ms);
  });
  try {
    return await Promise.race([promise.then(() => 'settled'), bound]);
  } finally {
    clearTimeout(handle);
  }
}

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const macrotask = () => new Promise((resolve) => setImmediate(resolve));
/** The process's active Timeout resources; the verify cap's timer is one while a verification runs. */
const activeTimeouts = () => process.getActiveResourcesInfo().filter((type) => type === 'Timeout').length;
/** The bound this file states for stop() with an attempt in flight, far under the 120 s verify cap. */
const STOP_BOUND_MS = 5_000;

/**
 * The runner's database: the world's, except that once `seam.checkpoint` is
 * set ('missing' or 'mismatch') a read of the completion checkpoint returns
 * none or one with another digest, and listTenantIds(), the first step of
 * every run, is counted in `seam.runs`.
 */
function seamDb(world, seam) {
  seam.runs = 0;
  const bound = (target, property) => {
    const value = Reflect.get(target, property, target);
    return typeof value === 'function' ? value.bind(target) : value;
  };
  const storeOf = (store) =>
    new Proxy(store, {
      get(target, property) {
        if (property !== 'get') return bound(target, property);
        return (table, where) => {
          const row = target.get(table, where);
          if (table !== 'audit_checkpoints' || where?.kind !== 'completion' || row === undefined || seam.checkpoint === undefined) return row;
          return seam.checkpoint === 'missing' ? undefined : { ...row, event_digest: hex('not-the-receipt-head') };
        };
      },
    });
  return new Proxy(world.db, {
    get(target, property) {
      if (property === 'forTenant') return (tenantId) => storeOf(target.forTenant(tenantId));
      if (property === 'listTenantIds') {
        return () => {
          seam.runs += 1;
          return target.listTenantIds();
        };
      }
      return bound(target, property);
    },
  });
}

const reportFor = (job) => reportBytesFor({ artifactDigest: job.expectedArtifactDigest, approvalEvidenceDigest: job.expectedApprovalEvidenceDigest, verifiedAt: job.validationTime });

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

// FV-DIGEST (request #85 (1)). One world per seed: consent_texts holds one version per tenant and locale.
const DAY_MS = 24 * 3_600_000;

/** Each seeded approval's stored and recomputed digests, for assertion messages (request #70 (6)). */
const digestsOf = (seeded) =>
  seeded.approvals
    .map((a) => `ordinal ${a.ordinal}: field_values_digest stored ${a.storedFieldValuesDigest}, of the values ${a.valuesDigest}; approval_digest stored ${a.storedApprovalDigest}, of the unforged record ${a.recordDigest}`)
    .join(' | ');

test('[FEN-07] FV-DIGEST R0: one and two recipients with a date field publish while the runner clock is a UTC day past server_time; each manifest approval carries T010’s field-values digest of its values and its server-day dates', async () => {
  for (const recipients of [1, 2]) {
    const world = makeWorld();
    try {
      const seeded = seedSealableWith(world, { recipients });
      world.clock.advance(DAY_MS);
      const runnerDay = world.clock.iso().slice(0, 10);
      assert.notEqual(runnerDay, seeded.serverDay, `R0 premise (${recipients} recipient(s)): runner day ${runnerDay}, server day ${seeded.serverDay}`);
      const { runner } = makeRunner(world);
      const outcome = await runner.runAttempt(world.tenantId, seeded.envelopeId);
      const after = snapshot(world, seeded.envelopeId);
      const at = `R0 (${recipients} recipient(s), server day ${seeded.serverDay}, runner day ${runnerDay}): ${digestsOf(seeded)}; ${describe(after)}`;
      assert.equal(outcome.kind, 'published', `${at}; outcome ${JSON.stringify(outcome)}`);
      const [artifact] = after.artifacts;
      const evidence = JSON.parse(world.blobs.readRef(world.tenantId, artifact.evidence_blob_ref).toString('utf8'));
      const ordinals = evidence.approvals.map((approval) => approval.recipient.ordinal);
      assert.deepEqual(ordinals, seeded.approvals.map((a) => a.ordinal), `${at}; manifest approval ordinals ${JSON.stringify(ordinals)}`);
      evidence.approvals.forEach((approval, index) => {
        const seed = seeded.approvals[index];
        const recomputed = fieldValuesDigest(approval.field_values, approval.date_values);
        assert.deepEqual(
          [approval.field_values_digest, recomputed],
          [seed.storedFieldValuesDigest, seed.storedFieldValuesDigest],
          `${at}; ordinal ${seed.ordinal}: manifest field_values_digest ${approval.field_values_digest}, recomputed ${recomputed}, stored ${seed.storedFieldValuesDigest}`,
        );
        assert.deepEqual(
          approval.date_values,
          [{ key: `date-${seed.ordinal}`, value: seeded.serverDay }],
          `${at}; ordinal ${seed.ordinal}: date_values ${JSON.stringify(approval.date_values)}`,
        );
      });
    } finally {
      world.close();
    }
  }
});

/**
 * One attempt on a seed with one forged digest is refused before the seal
 * anchor: failed after one attempt with manifest_invalid.<reason>, one
 * envelope.finalization_failed (audit and outbox), no seal_started, no compose
 * call, no attempt record, no later step, the envelope still finalizing.
 */
async function expectRefusedBeforeAnchor(label, recipients, forge, reason) {
  const world = makeWorld();
  try {
    const seeded = seedSealableWith(world, { recipients, forge });
    const ordinal = forge.fieldValuesDigestAt ?? forge.approvalDigestAt;
    const forged = seeded.approvals.find((a) => a.ordinal === ordinal);
    const premise = forge.fieldValuesDigestAt !== undefined ? forged.storedFieldValuesDigest !== forged.valuesDigest : forged.storedApprovalDigest !== forged.recordDigest && forged.storedFieldValuesDigest === forged.valuesDigest;
    assert.ok(premise, `${label} premise: ${digestsOf(seeded)}`);
    const { runner, calls } = makeRunner(world);
    const outcome = await runner.runAttempt(world.tenantId, seeded.envelopeId);
    const after = snapshot(world, seeded.envelopeId);
    const at = `${label} (${recipients} recipient(s), forged ${JSON.stringify(forge)}): ${digestsOf(seeded)}; ${describe(after)}`;
    const errorCode = `manifest_invalid.${reason}`;
    assert.deepEqual(outcome, { kind: 'failed', errorCode }, `${at}; outcome ${JSON.stringify(outcome)}`);
    const job = [after.job.status, after.job.attempt_count, after.job.last_error_code];
    assert.deepEqual(job, ['failed', 1, errorCode], `${at}; job ${JSON.stringify(job)}`);
    const announced = [eventsOf(world, seeded.envelopeId, 'envelope.finalization_failed').length, outboxOf(world, seeded.envelopeId, 'envelope.finalization_failed').length];
    assert.deepEqual(announced, [1, 1], `${at}; finalization_failed audit and outbox ${JSON.stringify(announced)}`);
    const beforeAnchor = [eventsOf(world, seeded.envelopeId, 'envelope.seal_started').length, calls.compose.length, after.attemptBlobs, after.envelope.state];
    assert.deepEqual(beforeAnchor, [0, 0, 0, 'finalizing'], `${at}; seal_started, compose calls, attempt records, envelope state ${JSON.stringify(beforeAnchor)}`);
    const later = [calls.seal.length, calls.verify.length, calls.packages.length, after.artifacts.length, after.reports];
    assert.deepEqual(later, [0, 0, 0, 0, 0], `${at}; seal, verify, package calls, artifacts, reports ${JSON.stringify(later)}`);
  } finally {
    world.close();
  }
}

test('[FEN-07] FV-DIGEST R1-R3: a forged field_values_digest under a consistent approval_digest, at ordinal 1 of 1, 1 of 2 and 2 of 2, fails the job as manifest_invalid.field-values-digest after one attempt, before the seal anchor and compose', async () => {
  for (const [label, recipients, ordinal] of [['R1', 1, 1], ['R2', 2, 1], ['R3', 2, 2]]) {
    await expectRefusedBeforeAnchor(label, recipients, { fieldValuesDigestAt: ordinal }, 'field-values-digest');
  }
});

test('[FEN-07] FV-DIGEST R4-R5: an approval_digest that is not the digest of its record, at ordinal 1 and 2 of 2, keeps its refusal manifest_invalid.approval-digest, before the seal anchor and compose', async () => {
  for (const [label, ordinal] of [['R4', 1], ['R5', 2]]) {
    await expectRefusedBeforeAnchor(label, 2, { approvalDigestAt: ordinal }, 'approval-digest');
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

test('[FEN-08] a receipt head that is not the envelope’s completion checkpoint refuses the publish (step 3): a mismatched digest, a mismatched seq and no checkpoint each write nothing; the runner takes the refusal as a lost attempt and records no failure', async () => {
  // The publish transaction, called as the runner calls it.
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    const assembled = assembleAttempt(world, envelopeId);
    const head = assembled.receiptHead;
    const before = snapshot(world, envelopeId);
    for (const receiptHead of [
      { seq: head.seq, digest: hex('another-head') },
      { seq: head.seq + 1, digest: head.digest },
    ]) {
      const shown = `a receipt ending at seq ${receiptHead.seq}, digest ${receiptHead.digest}, against the checkpoint at seq ${head.seq}, digest ${head.digest}`;
      assert.throws(() => publish(world, grant, assembled, { receiptHead }), refusedWith('checkpoint'), shown);
      assertUnchanged(world, envelopeId, before, `${shown} wrote nothing`);
    }
    const bare = seedFinalizing(world).envelopeId;
    const bareGrant = lease(world, bare, 'runner-b');
    const unchecked = assembleAttempt(world, bare, 'attempt', { checkpoint: false });
    const none = getCompletionCheckpoint(world.store, bare);
    assert.equal(none, undefined, `premise: ${bare} has no completion checkpoint (got ${JSON.stringify(none)})`);
    const bareBefore = snapshot(world, bare);
    assert.throws(() => publish(world, bareGrant, unchecked), refusedWith('checkpoint'), `a receipt ending at seq ${unchecked.receiptHead.seq} with no checkpoint for ${bare}`);
    assertUnchanged(world, bare, bareBefore, `a publish of ${bare} with no checkpoint wrote nothing`);
    // The positive control: the same attempt with the checkpoint's own head publishes.
    const published = publish(world, grant, assembled);
    assert.equal(published.envelopeVersion, RESERVED_VERSION + 1, `the true head publishes at v${published.envelopeVersion}`);
  } finally {
    world.close();
  }

  // Through the runner (finalize.ts: a PublishRefused other than 'blob' is a lost attempt, with no failure record).
  for (const mode of ['mismatch', 'missing']) {
    const runWorld = makeWorld();
    try {
      const { envelopeId } = seedSealable(runWorld);
      const seam = {};
      const { runner } = makeRunner(runWorld, {
        db: seamDb(runWorld, seam),
        // The package is built to the checkpoint just written; from here on the publish reads another one, or none.
        buildPackage: (inputs) => {
          seam.checkpoint = mode;
          return canonicalBytes({ synthetic_package: true, pdf: sha256(inputs.finalPdf) });
        },
      });
      const outcome = await runner.runAttempt(runWorld.tenantId, envelopeId);
      assert.deepEqual(outcome, { kind: 'lost' }, `(${mode}) outcome ${JSON.stringify(outcome)}`);
      const after = snapshot(runWorld, envelopeId);
      assert.deepEqual(
        [after.artifacts.length, after.reports, after.outbox.length, after.envelope.state, after.job.status, after.job.last_error_code],
        [0, 0, 0, 'finalizing', 'running', null],
        `(${mode}) nothing published and no failure recorded: ${describe(after)}`,
      );
      const [last] = runWorld.store.list('audit_events', {}, { orderBy: [['seq', 'desc']], limit: 1 });
      const checkpointSeq = getCompletionCheckpoint(runWorld.store, envelopeId).seq;
      assert.equal(last.seq, checkpointSeq, `(${mode}) no event after the checkpoint: last seq ${last.seq}, checkpoint seq ${checkpointSeq}`);
    } finally {
      runWorld.close();
    }
  }
});

test('[FEN-01] stop() during a held verify aborts the attempt through its lease keeper: the verify worker is terminated, stop() settles within 5 s (the verify cap is 120 s), nothing is written after it, no timer remains, a second stop() is harmless, and no attempt starts after it', async () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedSealable(world);
    const waiting = seedFinalizing(world).envelopeId;
    const timers = countingTimers();
    const worker = heldWorker();
    let entered;
    const inVerify = new Promise((resolve) => {
      entered = resolve;
    });
    const { runner } = makeRunner(world, {
      timers,
      // The real verify step with a worker that never answers. Its rejection on the abort reaches the
      // attempt one macrotask later, so a stop() that did not wait for the unwinding would be seen.
      verify: async (job, options) => {
        try {
          return await runVerification(job, {
            ...options,
            spawn: () => {
              entered();
              return worker;
            },
          });
        } catch (error) {
          await macrotask();
          throw error;
        }
      },
    });
    const baseline = activeTimeouts();
    let unwound = false;
    const attempt = runner.runAttempt(world.tenantId, envelopeId).then((outcome) => {
      unwound = true;
      return outcome;
    });
    await inVerify;
    const before = snapshot(world, envelopeId);
    const capRunning = activeTimeouts();
    assert.deepEqual(
      [before.job.status, timers.live.size, capRunning],
      ['running', 1, baseline + 1],
      `premise: the lease row is valid, the keeper holds ${timers.live.size} renewal(s), ${capRunning} timeout(s) run (${baseline} before the attempt): ${describe(before)}`,
    );

    const started = performance.now();
    const stopping = runner.stop();
    assert.ok(stopping instanceof Promise, `stop() returns ${Object.prototype.toString.call(stopping)}`);
    const settled = await within(stopping, STOP_BOUND_MS);
    const elapsed = Math.round(performance.now() - started);
    assert.equal(settled, 'settled', `stop() ${settled}: ${elapsed} ms, bound ${STOP_BOUND_MS} ms, verify cap ${VERIFY_WALL_CAP_MS} ms`);
    assert.equal(unwound, true, `stop() resolved after the attempt unwound (unwound ${unwound}, ${elapsed} ms)`);
    const outcome = await attempt;
    assert.deepEqual(outcome, { kind: 'lost' }, `the stopped attempt's outcome ${JSON.stringify(outcome)}`);
    assert.equal(worker.terminated, 1, `the verify worker was terminated ${worker.terminated} time(s)`);
    assertUnchanged(world, envelopeId, before, `stop() of attempt ${before.job.fencing_token} wrote nothing after the abort`);
    const timeouts = activeTimeouts();
    assert.ok(timers.live.size === 0 && timeouts <= baseline, `timers left: ${timers.live.size} renewal(s), ${timeouts} timeout(s), ${baseline} before the attempt`);

    const againStarted = performance.now();
    const again = await within(runner.stop(), STOP_BOUND_MS);
    const againMs = Math.round(performance.now() - againStarted);
    assert.ok(again === 'settled' && againMs < 1_000, `a second stop() ${again} in ${againMs} ms`);
    const late = await runner.runAttempt(world.tenantId, waiting);
    const waitingJob = snapshot(world, waiting).job;
    assert.deepEqual(
      [late.kind, waitingJob.status, waitingJob.attempt_count],
      ['not-claimed', 'pending', 0],
      `after stop() no attempt starts: ${late.kind}; ${waiting}'s job ${waitingJob.status} with ${waitingJob.attempt_count} attempt(s)`,
    );

    // Crash-equivalent: the stopped attempt counts, and its job is reclaimed at the lease expiry.
    world.clock.advance(DEFAULT_LEASE_MS);
    const reclaimed = reclaimLease(world.context(), envelopeId);
    const job = snapshot(world, envelopeId).job;
    assert.deepEqual(
      [reclaimed, job.attempt_count, job.last_error_code],
      ['retryable', 1, LEASE_EXPIRED_ERROR_CODE],
      `at the lease expiry ${world.clock.iso()} the job is ${reclaimed} after ${job.attempt_count} attempt(s), ${job.last_error_code}`,
    );

    // With nothing in flight stop() resolves at once, and a runner stopped before its first tick never runs.
    const seam = {};
    const { runner: idle } = makeRunner(world, { db: seamDb(world, seam) });
    idle.start(10);
    const idleStarted = performance.now();
    const idleSettled = await within(idle.stop(), STOP_BOUND_MS);
    const idleMs = Math.round(performance.now() - idleStarted);
    await pause(50);
    assert.ok(idleSettled === 'settled' && idleMs < 1_000 && seam.runs === 0, `an idle stop() ${idleSettled} in ${idleMs} ms; runs afterwards ${seam.runs} (interval 10 ms, 50 ms waited)`);
  } finally {
    world.close();
  }
});

test('[FEN-01] stop() during a held seal aborts it through the keeper’s signal, and a step that ignores the abort writes nothing after it: the held check refuses every later durable write, and no failure is recorded', async () => {
  // (a) The seal port gets the keeper's signal and rejects as T037 does on an abort (SealError 'aborted', retryable).
  const sealWorld = makeWorld();
  try {
    const { envelopeId } = seedSealable(sealWorld);
    let entered;
    const inSeal = new Promise((resolve) => {
      entered = resolve;
    });
    let signal;
    const { runner } = makeRunner(sealWorld, {
      timers: countingTimers(),
      sealPdf: (_input, options) =>
        new Promise((_resolve, reject) => {
          signal = options.signal;
          signal.addEventListener('abort', () => reject(new SealError('aborted')), { once: true });
          entered();
        }),
    });
    const attempt = runner.runAttempt(sealWorld.tenantId, envelopeId);
    await inSeal;
    const before = snapshot(sealWorld, envelopeId);
    const settled = await within(runner.stop(), STOP_BOUND_MS);
    const outcome = await attempt;
    assert.deepEqual([settled, outcome], ['settled', { kind: 'lost' }], `(seal) stop() ${settled}; outcome ${JSON.stringify(outcome)}`);
    assert.ok(
      signal?.aborted === true && signal.reason instanceof LeaseLost && signal.reason.lossCause === 'stopped',
      `(seal) the seal's signal: aborted ${signal?.aborted}, reason ${signal?.reason?.name} ${signal?.reason?.lossCause}`,
    );
    assertUnchanged(sealWorld, envelopeId, before, `(seal) the retryable SealError 'aborted' after stop() recorded no failure`);
  } finally {
    sealWorld.close();
  }

  // (b) A verify port that ignores the signal and answers after stop(): the keeper's held check refuses the store.
  const lateWorld = makeWorld();
  try {
    const { envelopeId } = seedSealable(lateWorld);
    let entered;
    const inVerify = new Promise((resolve) => {
      entered = resolve;
    });
    let release;
    const released = new Promise((resolve) => {
      release = resolve;
    });
    const { runner } = makeRunner(lateWorld, {
      timers: countingTimers(),
      verify: async (job) => {
        entered();
        await released;
        await macrotask();
        return reportFor(job);
      },
    });
    const attempt = runner.runAttempt(lateWorld.tenantId, envelopeId);
    await inVerify;
    const before = snapshot(lateWorld, envelopeId);
    const stopping = runner.stop();
    release();
    const settled = await within(stopping, STOP_BOUND_MS);
    const outcome = await attempt;
    assert.deepEqual([settled, outcome], ['settled', { kind: 'lost' }], `(late verify) stop() ${settled}; outcome ${JSON.stringify(outcome)}`);
    assertUnchanged(lateWorld, envelopeId, before, `(late verify) a report that arrived after stop() led to no record, checkpoint, failure or publication`);
  } finally {
    lateWorld.close();
  }
});

test('[FEN-01] start() passes a rejected run to onError exactly once and its loop runs the next tick; an onError that throws and a runner without onError keep the loop too; after stop() no tick follows', async () => {
  const unhandled = [];
  const onUnhandled = (reason) => unhandled.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    for (const variant of ['observed', 'throwing', 'absent']) {
      const world = makeWorld();
      try {
        const { envelopeId } = seedSealable(world);
        const seam = {};
        // The first clock read of the first run is not a date, so that run rejects (StorageUsageError, jobs repository).
        let poisoned = 1;
        const clock = () => {
          if (poisoned > 0) {
            poisoned -= 1;
            return new Date(Number.NaN);
          }
          return world.clock.now();
        };
        const seen = [];
        const onError =
          variant === 'absent'
            ? undefined
            : (error) => {
                seen.push(error);
                if (variant === 'throwing') throw new Error('synthetic onError failure');
              };
        let reach;
        const reached = new Promise((resolve) => {
          reach = resolve;
        });
        const { runner } = makeRunner(world, {
          db: seamDb(world, seam),
          clock,
          onError,
          timers: countingTimers(),
          // The next tick's attempt is held in verify until stop() aborts it, so stop() meets a run in flight.
          verify: (_job, options) =>
            new Promise((_resolve, reject) => {
              options.signal.addEventListener('abort', () => reject(options.signal.reason), { once: true });
              reach();
            }),
        });
        runner.start(5);
        const next = await within(reached, STOP_BOUND_MS);
        const runsBeforeStop = seam.runs;
        await runner.stop();
        const runsAtStop = seam.runs;
        await pause(50);
        const names = seen.map((error) => `${error?.name}: ${error?.message}`);
        assert.equal(next, 'settled', `(${variant}) the tick after the rejected run reached ${envelopeId}'s attempt: ${next}; runs ${runsBeforeStop}; onError saw ${JSON.stringify(names)}`);
        assert.ok(runsBeforeStop >= 2, `(${variant}) a rejected run and the next one: runs ${runsBeforeStop}`);
        if (variant !== 'absent') {
          assert.ok(seen.length === 1 && seen[0] instanceof StorageUsageError, `(${variant}) onError received ${seen.length} error(s): ${JSON.stringify(names)}`);
        }
        assert.equal(seam.runs, runsAtStop, `(${variant}) after stop() no tick followed: runs ${runsAtStop} at stop(), ${seam.runs} 50 ms later (interval 5 ms)`);
      } finally {
        world.close();
      }
    }
    await macrotask();
    const reasons = unhandled.map((reason) => `${reason?.name}: ${reason?.message}`);
    assert.deepEqual(reasons, [], `unhandled rejections: ${JSON.stringify(reasons)}`);
  } finally {
    process.off('unhandledRejection', onUnhandled);
  }
});
