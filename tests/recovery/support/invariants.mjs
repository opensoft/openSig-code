// SPDX-License-Identifier: Apache-2.0
//
// T015's invariants I1..I10 (plan.md § Case catalogs, SC-003: "the T015 preparation's I1–I10"),
// checked after every case once all of its children have ended, over the landed tables
// (0004 jobs, 0005 artifacts, 0006 audit, 0007 outbox, 0019 finalization_attempt_blobs) and the
// blob store. Each check returns 'pass' or throws; every message carries the discriminating
// values (request #70 (6)): ids, statuses, counts, tokens, never a capability value or bytes.
// - I1 at most one artifact; I2 one completion event if and only if completed; I3 never
//   completed beside voided, declined or expired; I4 bounded attempts;
// - I5 one envelope.finalization_failed (outbox and audit, the same type, request #61 (6)) per
//   move into failed;
// - I6 no referenced blob missing or torn, no stored blob untracked, and attempt records judged
//   by the landed rule: T029's ReferenceProtection with the attempt instant (7a11d08, unchanged at 00b260f) and
//   attemptCollectable (src/storage/repositories/jobs.ts), never a restatement;
// - I7 one seal anchor and one completion checkpoint, envelope.completed after the checkpoint;
// - I8 one verification_reports row per publish; I9 at most three finalization audit events per
//   attempt plus two; I10 the tenant chain verifies.

import assert from 'node:assert/strict';

import { verifyChain } from '../../../src/storage/audit/verify.ts';
import { blobRef, parseBlobRef } from '../../../src/storage/blobs/refs.ts';
import { attemptCollectable } from '../../../src/storage/repositories/jobs.ts';
import { ReferenceProtection } from '../../../src/storage/retention/index.ts';

const FAILED = 'envelope.finalization_failed';
const num = (value) => (value === null || value === undefined ? value : Number(value));
const ofType = (rows, type) => rows.filter((row) => row.type === type);

/** Everything the checks read for the case's envelope, in one pass (no child runs). */
export function readCase(world) {
  const { tenantId, envelopeId } = world.ctx;
  const key = [tenantId, envelopeId];
  const where = 'WHERE tenant_id = ? AND envelope_id = ?';
  const [envelope] = world.rows('envelopes', 'WHERE tenant_id = ? AND id = ?', key);
  assert.ok(envelope, `envelope ${envelopeId} exists`);
  return {
    envelope,
    job: world.rows('signing_jobs', where, key)[0],
    artifacts: world.rows('final_artifacts', where, key),
    reports: world.rows('verification_reports', where, key),
    outbox: world.rows('outbox_events', where, key),
    audit: world.rows('audit_events', where, key),
    checkpoints: world.rows('audit_checkpoints', `${where} AND kind = 'completion'`, key),
    revisions: world.rows('document_revisions', where, key),
    records: world.rows('finalization_attempt_blobs', where, key).map((row) => ({ fencingToken: num(row.fencing_token), ref: String(row.blob_ref), role: String(row.role) })),
  };
}

/** One line of discriminating values (request #70 (6)). */
export function summary(s) {
  const job = s.job ?? {};
  return [
    `envelope ${s.envelope.id} ${s.envelope.state} v${s.envelope.version}`,
    `job ${job.status} attempts ${job.attempt_count}/${job.max_attempts} attempt-no ${job.fencing_token} error ${job.last_error_code}`,
    `artifacts [${s.artifacts.map((row) => `${row.artifact_id} by attempt ${row.fencing_token}`)}]`,
    `reports ${s.reports.length}`,
    `outbox [${s.outbox.map((row) => `${row.type} v${row.envelope_version}`)}]`,
    `audit [${s.audit.map((row) => `${row.seq}:${row.type}`)}]`,
    `checkpoints [${s.checkpoints.map((row) => row.seq)}]`,
    `attempt records [${s.records.map((row) => `${row.fencingToken}:${row.role}`)}]`,
  ].join('; ');
}

/** I1. */
export function atMostOneArtifact(s) {
  assert.ok(s.artifacts.length <= 1, `I1 at most one FinalArtifact, found ${s.artifacts.length}: ${summary(s)}`);
  return 'pass';
}

/** I2. */
export function completionEventIffCompleted(s) {
  const events = ofType(s.outbox, 'envelope.completed');
  const audited = ofType(s.audit, 'envelope.completed');
  if (s.envelope.state !== 'completed') {
    assert.deepEqual([s.artifacts.length, events.length, audited.length], [0, 0, 0], `I2 not completed: no artifact, completion event or completion audit event: ${summary(s)}`);
    return 'pass';
  }
  assert.deepEqual([s.artifacts.length, events.length, audited.length], [1, 1, 1], `I2 completed: one artifact, one outbox and one audit envelope.completed: ${summary(s)}`);
  const [artifact] = s.artifacts;
  const payload = JSON.parse(String(events[0].payload_json));
  assert.deepEqual(
    { event_id: payload.event_id, artifact_id: payload.artifact_id, artifact_digest: payload.artifact_digest, version: num(events[0].envelope_version) },
    { event_id: events[0].event_id, artifact_id: artifact.artifact_id, artifact_digest: artifact.artifact_digest, version: num(s.envelope.version) },
    `I2 the one event names the one artifact and the completed version: ${summary(s)}`,
  );
  assert.deepEqual([s.job?.status, num(artifact.fencing_token)], ['succeeded', num(s.job?.fencing_token)], `I2 the job succeeded under the artifact's attempt: ${summary(s)}`);
  return 'pass';
}

/** I3. */
export function neverCompletedAndVoided(s) {
  const state = s.envelope.state;
  const completion = state === 'completed' || s.artifacts.length > 0 || ofType(s.outbox, 'envelope.completed').length > 0 || ofType(s.audit, 'envelope.completed').length > 0;
  const others = ['voided', 'declined', 'expired'].filter((terminal) => state === terminal || ofType(s.outbox, `envelope.${terminal}`).length > 0);
  assert.ok(!(completion && others.length > 0), `I3 never completed beside ${others.join(', ') || 'another terminal state'}: ${summary(s)}`);
  if (s.job !== undefined) assert.ok(['finalizing', 'completed'].includes(state), `I3 a reserved envelope stays finalizing or completes: ${summary(s)}`);
  return 'pass';
}

/** I4. */
export function attemptsBounded(s, expect = {}) {
  assert.ok(s.job, `I4 the job exists: ${summary(s)}`);
  const attempts = num(s.job.attempt_count);
  const max = num(s.job.max_attempts);
  const token = num(s.job.fencing_token);
  assert.ok(Number.isSafeInteger(attempts) && attempts >= 0 && attempts <= max && max >= 1 && max <= 100, `I4 0 <= attempt_count ${attempts} <= max_attempts ${max} <= 100: ${summary(s)}`);
  assert.ok(token === null || (token >= 1 && token <= attempts), `I4 attempt-no ${token} within 1..${attempts}: ${summary(s)}`);
  if (expect.attempts !== undefined) assert.equal(attempts, expect.attempts, `I4 attempt_count ${attempts}, expected ${expect.attempts}: ${summary(s)}`);
  if (expect.maxAttempts !== undefined) assert.equal(max, expect.maxAttempts, `I4 max_attempts ${max}, expected ${expect.maxAttempts}: ${summary(s)}`);
  if (expect.publisher !== undefined) assert.deepEqual(s.artifacts.map((row) => num(row.fencing_token)), [expect.publisher], `I4 attempt ${expect.publisher} published: ${summary(s)}`);
  return 'pass';
}

/** I5. */
export function finalizationFailedPerMove(s, expect = {}) {
  const moves = expect.failedMoves ?? 0;
  const outbox = ofType(s.outbox, FAILED);
  const audit = ofType(s.audit, FAILED);
  assert.deepEqual([outbox.length, audit.length], [moves, moves], `I5 ${FAILED} once per move into failed (${moves}) in the outbox and the audit chain: ${summary(s)}`);
  assert.equal(new Set(outbox.map((row) => row.event_id)).size, outbox.length, `I5 each failure event has its own event_id: ${summary(s)}`);
  for (const row of outbox) assert.equal(num(row.envelope_version), num(s.job.reserved_version), `I5 a failure leaves the envelope finalizing at v${s.job.reserved_version}: ${summary(s)}`);
  if (s.job.status === 'failed') assert.ok(outbox.length >= 1, `I5 a failed job has announced its failure: ${summary(s)}`);
  return 'pass';
}

/** I6. */
export function blobsAccountedFor(world, s, { nowMs }) {
  const { tenantId, envelopeId, seedBlobRefs } = world.ctx;
  const artifactRefs = s.artifacts.flatMap((row) => [row.pdf_blob_ref, row.evidence_blob_ref, row.package_blob_ref].filter((ref) => typeof ref === 'string'));
  const referenced = new Set([...s.revisions.map((row) => String(row.blob_ref)), ...artifactRefs]);
  for (const ref of referenced) {
    const status = world.blobs.check(tenantId, parseBlobRef(ref).digest);
    assert.equal(status, 'ok', `I6 referenced blob ${parseBlobRef(ref).digest.slice(0, 12)} is ${status}: ${summary(s)}`);
  }
  const known = new Set([...referenced, ...s.records.map((record) => record.ref), ...seedBlobRefs]);
  for (const digest of world.blobs.list(tenantId)) {
    assert.ok(known.has(blobRef(tenantId, digest)), `I6 stored blob ${digest.slice(0, 12)} is referenced, recorded before its write, or the seed's: ${summary(s)}`);
    assert.equal(world.blobs.check(tenantId, digest), 'ok', `I6 stored blob ${digest.slice(0, 12)} is intact: ${summary(s)}`);
  }
  const now = new Date(nowMs);
  const store = world.db.forTenant(tenantId);
  const protection = new ReferenceProtection(store, undefined, { attempts: { now } });
  const published = s.artifacts.length === 1 ? num(s.artifacts[0].fencing_token) : null;
  const tally = { referenced: 0, protected: 0, collectable: 0 };
  for (const record of s.records) {
    const isReferenced = artifactRefs.includes(record.ref);
    const kept = protection.referenced(record.ref);
    const collectable = attemptCollectable(store, envelopeId, record.fencingToken, now);
    const verdict = isReferenced ? 'referenced' : kept ? 'protected' : 'collectable';
    tally[verdict] += 1;
    if (record.fencingToken === published) {
      assert.deepEqual([kept, collectable], [true, false], `I6 the published attempt ${published}'s ${record.role} record is protected and not collectable: ${summary(s)}`);
      assert.equal(world.blobs.check(tenantId, parseBlobRef(record.ref).digest), 'ok', `I6 the published attempt's ${record.role} blob is present: ${summary(s)}`);
    }
    if (isReferenced) assert.equal(kept, true, `I6 a ref a final artifact references (${record.role}, attempt ${record.fencingToken}) is protected: ${summary(s)}`);
  }
  return { verdict: 'pass', attempt_records: tally };
}

/** I7. */
export function anchorAndCheckpointOnce(s) {
  const anchors = ofType(s.audit, 'envelope.seal_started');
  assert.ok(anchors.length <= 1 && s.checkpoints.length <= 1, `I7 at most one seal anchor (${anchors.length}) and one completion checkpoint (${s.checkpoints.length}): ${summary(s)}`);
  if (s.envelope.state === 'completed') {
    const [completed] = ofType(s.audit, 'envelope.completed');
    assert.ok(
      anchors.length === 1 && s.checkpoints.length === 1 && num(anchors[0].seq) <= num(s.checkpoints[0].seq) && num(completed.seq) > num(s.checkpoints[0].seq),
      `I7 completed: anchor <= checkpoint < envelope.completed in the chain: ${summary(s)}`,
    );
  }
  return 'pass';
}

/** I8. */
export function verificationRowIffCompleted(s) {
  const completed = s.envelope.state === 'completed';
  assert.equal(s.reports.length, completed ? 1 : 0, `I8 one verification_reports row exactly when published: ${summary(s)}`);
  if (completed) assert.equal(s.reports[0].artifact_digest, s.artifacts[0].artifact_digest, `I8 the report is of the published PDF: ${summary(s)}`);
  return 'pass';
}

/** I9. */
export function auditBudget(world, s) {
  const after = s.audit.filter((row) => num(row.seq) > world.ctx.seedAuditHeadSeq);
  const attempts = num(s.job.attempt_count);
  assert.ok(after.length <= 3 * attempts + 2, `I9 finalization audit events ${after.length} <= 3 x ${attempts} + 2: ${summary(s)}`);
  return 'pass';
}

/** I10. */
export function chainVerifies(world, s) {
  const report = verifyChain(world.db, world.ctx.tenantId);
  assert.deepEqual(
    { ok: report.ok, problems: report.problems.map((problem) => `${problem.kind} at ${problem.seq}`) },
    { ok: true, problems: [] },
    `I10 the tenant chain verifies (${report.events} events, ${report.checkpoints} checkpoints): ${summary(s)}`,
  );
  return 'pass';
}

/** I1..I10 in order, then the case's end state; returns the results and the state read. */
export function checkInvariants(world, expect, { nowMs }) {
  const s = readCase(world);
  const results = {
    I1: atMostOneArtifact(s),
    I2: completionEventIffCompleted(s),
    I3: neverCompletedAndVoided(s),
    I4: attemptsBounded(s, expect),
    I5: finalizationFailedPerMove(s, expect),
    I6: blobsAccountedFor(world, s, { nowMs }),
    I7: anchorAndCheckpointOnce(s),
    I8: verificationRowIffCompleted(s),
    I9: auditBudget(world, s),
    I10: chainVerifies(world, s),
  };
  assert.equal(s.envelope.state, expect.state, `the envelope ends ${expect.state}: ${summary(s)}`);
  return { results, state: s };
}
