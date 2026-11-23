// SPDX-License-Identifier: Apache-2.0
//
// Atomic publication (T038; data-model.md § Transitions and races, items 2
// and 4; § Entities, OutboxEvent, FinalArtifact). One BEGIN IMMEDIATE
// transaction holds the job completion, the envelope transition, the
// FinalArtifact insert, the `envelope.completed` audit event and the outbox
// event: all of them or none. Two runners racing in separate OS processes
// land exactly one publication, the current token's. Synthetic data only.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { ReferenceProtection } from '../../src/storage/retention/index.ts';
import { assertUnchanged, holderOf, lease, publish, takeOver } from './support/steps.mjs';
import { assembleAttempt, makeWorld, RESERVED_VERSION, seedFinalizing, sha256, snapshot } from './support/world.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..', '..');

function ref(world, digest) {
  return `tenants/${world.tenantId}/sha256/${digest}`;
}

test('[FEN-02] one publish transaction writes the artifact, the job completion, the envelope transition, the audit event and the outbox event', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    const assembled = assembleAttempt(world, envelopeId);
    const before = snapshot(world, envelopeId);
    const published = publish(world, grant, assembled);
    const after = snapshot(world, envelopeId);

    assert.equal(after.job.status, 'succeeded');
    assert.equal(after.job.lease_owner, null);
    assert.equal(after.job.lease_expires_at, null);
    assert.equal(after.job.attempt_count, 1);
    assert.equal(after.job.fencing_token, grant.fencingToken);
    assert.equal(after.envelope.state, 'completed');
    assert.equal(after.envelope.version, RESERVED_VERSION + 1);

    assert.equal(after.artifacts.length, 1);
    const [artifact] = after.artifacts;
    assert.equal(artifact.artifact_id, assembled.artifact.artifactId);
    assert.equal(artifact.fencing_token, grant.fencingToken);
    assert.equal(artifact.pdf_blob_ref, ref(world, assembled.artifact.artifactDigest));
    assert.equal(artifact.evidence_blob_ref, ref(world, assembled.artifact.evidenceDigest));
    assert.equal(artifact.package_digest, assembled.artifact.packageDigest, `package digest ${artifact.package_digest}, expected ${assembled.artifact.packageDigest}`);
    assert.equal(artifact.package_blob_ref, ref(world, assembled.artifact.packageDigest));
    assert.equal(
      artifact.approval_evidence_digest,
      assembled.artifact.approvalEvidenceDigest,
      `FEN-07: stored evidence digest ${artifact.approval_evidence_digest}, expected ${assembled.artifact.approvalEvidenceDigest}`,
    );
    const reportText = Buffer.from(assembled.reportBytes).toString('utf8');
    assert.equal(artifact.verification_json, reportText, `verification_json (${artifact.verification_json.length} chars) holds the report (${reportText.length} chars)`);
    const reports = world.store.list('verification_reports', { envelope_id: envelopeId });
    assert.equal(reports.length, 1, `exactly one verification_reports row (got ${reports.length})`);
    const stored = Buffer.from(reports[0].report_bytes);
    assert.ok(stored.equals(Buffer.from(assembled.reportBytes)), `report_bytes (${stored.length} bytes, sha256 ${sha256(stored)}) are the report's (${assembled.reportBytes.length} bytes, sha256 ${sha256(assembled.reportBytes)})`);
    assert.equal(reports[0].id, assembled.verificationReportId);

    assert.equal(after.outbox.length, 1);
    const [event] = after.outbox;
    assert.equal(event.event_id, published.outboxEventId);
    assert.equal(event.type, 'envelope.completed');
    assert.equal(event.envelope_version, RESERVED_VERSION + 1, `the event announces v${event.envelope_version}, the publish wrote v${RESERVED_VERSION + 1}`);
    const payload = JSON.parse(event.payload_json);
    assert.equal(payload.artifact_id, assembled.artifact.artifactId);
    assert.equal(payload.artifact_digest, assembled.artifact.artifactDigest);

    assert.equal(after.events, before.events + 1, `exactly one audit event (events ${before.events} → ${after.events})`);
    const completed = world.store.get('audit_events', { seq: published.completedEventSeq });
    assert.equal(completed.type, 'envelope.completed');
    assert.equal(completed.envelope_id, envelopeId);
    assert.equal(completed.subject_digest, assembled.artifact.artifactDigest);
    assert.ok(completed.seq > assembled.receiptHead.seq, `the completion event (seq ${completed.seq}) follows the receipt head (seq ${assembled.receiptHead.seq})`);
    assert.equal(after.checkpoints, before.checkpoints);
  } finally {
    world.close();
  }
});

test('[FEN-02] a failure at the last statement of the publish leaves no trace, and the attempt can still publish', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    const assembled = assembleAttempt(world, envelopeId);
    const before = snapshot(world, envelopeId);
    assert.throws(
      () => publish(world, grant, assembled, { options: { newEventId: () => 'malformed id' } }),
      (error) => error?.code === 'storage_usage' && /event id/.test(error.message),
    );
    assertUnchanged(world, envelopeId, before, 'no artifact, no transition, no job change, no event');
    assert.equal(before.job.status, 'running', `the job is ${before.job.status}`);

    publish(world, grant, assembled);
    const after = snapshot(world, envelopeId);
    assert.equal(after.artifacts.length, 1);
    assert.equal(after.outbox.length, 1);
    assert.equal(after.envelope.state, 'completed');
  } finally {
    world.close();
  }
});

function runChild(world, input, instant, startAt) {
  return new Promise((done, fail) => {
    const child = spawn(process.execPath, [join(HERE, 'support', 'publish-child.mjs'), world.dbPath, world.blobRoot, input, instant, String(startAt)], {
      cwd: REPO_ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.on('error', fail);
    child.on('close', (code) => done({ code, stdout, stderr }));
  });
}

test('[FEN-02] runners racing in separate processes land exactly one publication, the current token’s; the losers’ blobs stay collectable', async () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const stale = lease(world, envelopeId, 'runner-a');
    const current = takeOver(world, stale, 'runner-b');
    const impostor = { ...current, leaseOwner: 'runner-x' };
    const assemblies = {
      stale: assembleAttempt(world, envelopeId, 'a'),
      current: assembleAttempt(world, envelopeId, 'b'),
      impostor: assembleAttempt(world, envelopeId, 'x'),
    };
    const inputFor = (grant, assembled) =>
      JSON.stringify({
        tenantId: world.tenantId,
        holder: holderOf(grant),
        expectedEnvelopeVersion: grant.reservedVersion,
        receiptHead: assembled.receiptHead,
        verificationReportId: assembled.verificationReportId,
        reportBytesBase64: Buffer.from(assembled.reportBytes).toString('base64'),
        artifact: assembled.artifact,
      });
    const instant = world.clock.iso();
    const startAt = Date.now() + 1_500;
    const runs = await Promise.all([
      runChild(world, inputFor(stale, assemblies.stale), instant, startAt),
      runChild(world, inputFor(current, assemblies.current), instant, startAt),
      runChild(world, inputFor(impostor, assemblies.impostor), instant, startAt),
    ]);
    const [a, b, x] = runs.map((run) => {
      assert.equal(run.code, 0, run.stderr.slice(0, 400));
      return JSON.parse(run.stdout.trim().split('\n').at(-1));
    });
    assert.deepEqual(a, { outcome: 'refused', reason: 'fence' });
    assert.deepEqual(x, { outcome: 'refused', reason: 'fence' });
    assert.deepEqual(b, { outcome: 'published', artifactId: assemblies.current.artifact.artifactId, envelopeVersion: RESERVED_VERSION + 1 });

    const after = snapshot(world, envelopeId);
    assert.equal(after.artifacts.length, 1);
    assert.equal(after.artifacts[0].artifact_id, assemblies.current.artifact.artifactId);
    assert.equal(after.artifacts[0].fencing_token, current.fencingToken);
    assert.equal(after.outbox.length, 1);
    assert.equal(after.reports, 1, `one verification_reports row, the winner's (got ${after.reports})`);
    assert.equal(after.envelope.state, 'completed');
    assert.equal(after.job.status, 'succeeded');
    assert.equal(world.store.count('audit_events', { envelope_id: envelopeId, type: 'envelope.completed' }), 1);

    const protection = new ReferenceProtection(world.store, { envelopeId, kind: 'orphan-collection', scope: undefined });
    for (const loser of [assemblies.stale, assemblies.impostor]) {
      assert.equal(protection.referenced(ref(world, loser.artifact.artifactDigest)), false, `a loser's PDF ${loser.artifact.artifactDigest} is referenced by no final artifact`);
      assert.equal(protection.referenced(ref(world, loser.artifact.packageDigest)), false, `a loser's package ${loser.artifact.packageDigest} is referenced by no final artifact`);
    }
    assert.equal(
      protection.referenced(ref(world, assemblies.current.artifact.artifactDigest)),
      true,
      `the published PDF ${assemblies.current.artifact.artifactDigest} is protected`,
    );
  } finally {
    world.close();
  }
});
