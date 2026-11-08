// SPDX-License-Identifier: Apache-2.0
//
// Retention and disposal (T029): AC-05 DisposalRecord plus audit event under
// an injected clock, with completed evidence never mutated; RET-01 unset and
// invalid policies, scope "all", and resumption after a crash between the
// record's commit and the blob removal.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { canonicalDigest } from '../../src/domain/canonical/index.ts';
import { eventDigest, eventFromRow, verifyChain } from '../../src/storage/audit/index.ts';
import { DISPOSAL_RECORD_SCHEMA, RetentionPolicyError, RetentionService, parseRetentionPolicy } from '../../src/storage/retention/index.ts';
import { makeScratch } from '../storage/support/fixtures.mjs';
import { BASE_TIME, createTenant, environment, fixedClock, sid, steppingClock, terminalEnvelope } from './support/chain.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

const DAY = 86_400_000;
const RUN_AT = new Date(BASE_TIME + 31 * DAY).toISOString();

function setPolicy(db, tenant, policy) {
  db.transaction(() => db.forTenant(tenant).update('tenants', {}, { retention_json: policy === null ? null : JSON.stringify(policy) }));
}

function snapshot(db, tenant, table) {
  return db
    .forTenant(tenant)
    .list(table, {}, { orderBy: [[table === 'final_artifacts' ? 'artifact_id' : 'id', 'asc']] })
    .map((row) => ({ ...row }));
}

test('[AC-05] retention writes a DisposalRecord and an audit event, removes only unshared blobs, and never mutates evidence', () => {
  const { db, blobs, audit } = environment(scratch, steppingClock());
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    setPolicy(db, tenant, { policy_ref: 'synthetic-retention-30d', dispose_after_days: 30 });

    const oldCompleted = terminalEnvelope(db, blobs, tenant, { state: 'completed', updatedMinutes: 10 });
    const oldVoided = terminalEnvelope(db, blobs, tenant, { state: 'voided', updatedMinutes: 20 });
    const recentCompleted = terminalEnvelope(db, blobs, tenant, { state: 'completed', updatedMinutes: 40 * 24 * 60, documentSeed: 'shared-document' });
    const oldDeclinedShared = terminalEnvelope(db, blobs, tenant, { state: 'declined', updatedMinutes: 30, documentSeed: 'shared-document' });
    const oldNotTerminal = terminalEnvelope(db, blobs, tenant, { state: 'sent', updatedMinutes: 5 });
    db.transaction(() => audit.append(tenant, { type: 'envelope.completed', actor: { kind: 'system', ref: 'finalizer' }, envelopeId: oldCompleted.env }));

    const artifactsBefore = snapshot(db, tenant, 'final_artifacts');
    const envelopesBefore = snapshot(db, tenant, 'envelopes');
    const retention = new RetentionService({ db, blobs, audit, clock: fixedClock(RUN_AT) });
    const run = retention.run(tenant);

    assert.deepEqual(run.policy, { policyRef: 'synthetic-retention-30d', disposeAfterDays: 30, scope: 'documents' });
    const byEnvelope = new Map(run.disposals.map((disposal) => [disposal.envelopeId, disposal]));
    assert.deepEqual([...byEnvelope.keys()].sort(), [oldCompleted.env, oldVoided.env, oldDeclinedShared.env].sort());

    const completed = byEnvelope.get(oldCompleted.env);
    assert.deepEqual(completed.disposedBlobRefs, [oldCompleted.doc.ref]);
    assert.deepEqual(completed.retainedArtifactDigests, [oldCompleted.pdf.digest]);
    assert.deepEqual(byEnvelope.get(oldVoided.env).disposedBlobRefs, [oldVoided.doc.ref]);
    assert.deepEqual(byEnvelope.get(oldVoided.env).retainedArtifactDigests, []);
    assert.deepEqual(byEnvelope.get(oldDeclinedShared.env).disposedBlobRefs, [], 'a blob shared with a live envelope is kept');
    assert.deepEqual(run.keptSharedBlobRefs, [recentCompleted.doc.ref]);

    assert.equal(blobs.check(tenant, oldCompleted.doc.digest), 'missing');
    assert.equal(blobs.check(tenant, oldVoided.doc.digest), 'missing');
    assert.equal(blobs.check(tenant, oldCompleted.pdf.digest), 'ok', 'scope documents keeps the final PDF');
    assert.equal(blobs.check(tenant, oldCompleted.evidence.digest), 'ok');
    assert.equal(blobs.check(tenant, recentCompleted.doc.digest), 'ok');
    assert.equal(blobs.check(tenant, oldNotTerminal.doc.digest), 'ok', 'non-terminal envelopes are never disposed');

    const store = db.forTenant(tenant);
    for (const disposal of run.disposals) {
      const record = store.get('disposal_records', { id: disposal.disposalId });
      assert.equal(record.envelope_id, disposal.envelopeId);
      assert.equal(record.policy_ref, 'synthetic-retention-30d');
      assert.equal(record.server_time, RUN_AT, 'server_time comes from the injected clock');
      assert.deepEqual(JSON.parse(record.disposed_blob_refs_json), disposal.disposedBlobRefs);
      assert.deepEqual(JSON.parse(record.retained_artifact_digests_json), disposal.retainedArtifactDigests);
      const recordDigest = canonicalDigest({
        schema: DISPOSAL_RECORD_SCHEMA,
        tenant_id: tenant,
        id: record.id,
        envelope_id: record.envelope_id,
        retained_artifact_digests: JSON.parse(record.retained_artifact_digests_json),
        disposed_blob_refs: JSON.parse(record.disposed_blob_refs_json),
        policy_ref: record.policy_ref,
        server_time: record.server_time,
      });
      assert.equal(disposal.recordDigest, recordDigest);
      const event = store.get('audit_events', { type: 'retention.disposed', envelope_id: disposal.envelopeId });
      assert.equal(event.subject_digest, recordDigest, 'the audit event names the record by its RFC 8785 digest');
      assert.deepEqual([event.actor_kind, event.actor_ref], ['system', 'retention']);
      assert.deepEqual(JSON.parse(event.metadata_json), {
        disposal_id: disposal.disposalId,
        disposed_blob_count: disposal.disposedBlobRefs.length,
        policy_ref: 'synthetic-retention-30d',
        retained_artifact_count: disposal.retainedArtifactDigests.length,
      });
      assert.equal(eventDigest(eventFromRow(event)), event.event_digest);
    }
    assert.equal(verifyChain(db, tenant).ok, true);
    assert.deepEqual(snapshot(db, tenant, 'final_artifacts'), artifactsBefore, 'completed evidence rows are unchanged');
    assert.deepEqual(snapshot(db, tenant, 'envelopes'), envelopesBefore, 'envelope rows are unchanged');

    const second = retention.run(tenant);
    assert.deepEqual(second.disposals, [], 'each envelope is disposed once');
    assert.deepEqual(second.resumedBlobRefs, []);
  } finally {
    db.close();
  }
});

test('[RET-01] unset retention disposes nothing, an invalid policy fails closed, scope "all" removes evidence blobs, and an interrupted disposal resumes', () => {
  const { db, blobs, audit } = environment(scratch, steppingClock());
  try {
    const unset = sid('tenant');
    createTenant(db, unset);
    const kept = terminalEnvelope(db, blobs, unset, { state: 'completed', updatedMinutes: 1 });
    const retention = new RetentionService({ db, blobs, audit, clock: fixedClock(new Date(BASE_TIME + 10_000 * DAY).toISOString()) });
    const none = retention.run(unset);
    assert.equal(none.policy, null);
    assert.deepEqual(none.disposals, []);
    for (const blob of [kept.doc, kept.pdf, kept.evidence]) assert.equal(blobs.check(unset, blob.digest), 'ok');
    assert.equal(db.forTenant(unset).count('disposal_records'), 0);

    for (const bad of [
      '{"policy_ref":"x"}',
      '{"policy_ref":"x","dispose_after_days":0}',
      '{"policy_ref":"x","dispose_after_days":1.5}',
      '{"policy_ref":"","dispose_after_days":3}',
      '{"policy_ref":"x","dispose_after_days":3,"scope":"everything"}',
      '{"policy_ref":"x","dispose_after_days":3,"archive":true}',
      '{"policy_ref":"x","dispose_after_days":3,"dispose_after_days":4}',
      '[1]',
      'not json',
    ]) {
      assert.throws(() => parseRetentionPolicy(bad), RetentionPolicyError, bad);
    }
    db.transaction(() => db.forTenant(unset).update('tenants', {}, { retention_json: '{"policy_ref":"x","dispose_after_days":3,"scope":"everything"}' }));
    assert.throws(() => retention.run(unset), RetentionPolicyError);
    assert.equal(blobs.check(unset, kept.doc.digest), 'ok', 'an invalid policy disposes nothing');

    const all = sid('tenant');
    createTenant(db, all);
    setPolicy(db, all, { policy_ref: 'synthetic-retention-all', dispose_after_days: 7, scope: 'all' });
    const envelope = terminalEnvelope(db, blobs, all, { state: 'completed', updatedMinutes: 1 });
    const runAll = new RetentionService({ db, blobs, audit, clock: fixedClock(new Date(BASE_TIME + 8 * DAY).toISOString()) }).run(all);
    assert.equal(runAll.disposals.length, 1);
    assert.deepEqual(runAll.disposals[0].disposedBlobRefs, [envelope.doc.ref, envelope.evidence.ref, envelope.pdf.ref].sort());
    assert.deepEqual(runAll.disposals[0].retainedArtifactDigests, [envelope.pdf.digest], 'the artifact digest stays recorded');
    for (const blob of [envelope.doc, envelope.pdf, envelope.evidence]) assert.equal(blobs.check(all, blob.digest), 'missing');
    assert.equal(db.forTenant(all).get('final_artifacts', { envelope_id: envelope.env }).artifact_digest, envelope.pdf.digest);

    // A crash after the record commits but before the blob is removed.
    const crash = sid('tenant');
    createTenant(db, crash);
    setPolicy(db, crash, { policy_ref: 'synthetic-retention-crash', dispose_after_days: 1 });
    const victim = terminalEnvelope(db, blobs, crash, { state: 'expired', updatedMinutes: 1 });
    const failing = {
      ...Object.fromEntries(['put', 'putStream', 'read', 'readRef', 'check', 'list', 'sweepPartials'].map((name) => [name, blobs[name].bind(blobs)])),
      dispose() {
        throw new Error('synthetic crash before blob removal');
      },
    };
    const clock = fixedClock(new Date(BASE_TIME + 2 * DAY).toISOString());
    assert.throws(() => new RetentionService({ db, blobs: failing, audit, clock }).run(crash), /synthetic crash/);
    assert.equal(db.forTenant(crash).count('disposal_records'), 1, 'the record committed');
    assert.equal(blobs.check(crash, victim.doc.digest), 'ok', 'the blob survived the crash');
    const resumed = new RetentionService({ db, blobs, audit, clock }).run(crash);
    assert.deepEqual(resumed.disposals, []);
    assert.deepEqual(resumed.resumedBlobRefs, [victim.doc.ref]);
    assert.equal(blobs.check(crash, victim.doc.digest), 'missing');

    // If a live envelope references the same content before resumption, the
    // blob is kept.
    const crash2 = sid('tenant');
    createTenant(db, crash2);
    setPolicy(db, crash2, { policy_ref: 'synthetic-retention-crash', dispose_after_days: 1 });
    const disposedEnvelope = terminalEnvelope(db, blobs, crash2, { state: 'expired', updatedMinutes: 1, documentSeed: 'reused-content' });
    assert.throws(() => new RetentionService({ db, blobs: failing, audit, clock }).run(crash2), /synthetic crash/);
    const live = terminalEnvelope(db, blobs, crash2, { state: 'sent', updatedMinutes: 1, documentSeed: 'reused-content' });
    assert.equal(live.doc.ref, disposedEnvelope.doc.ref);
    assert.equal(live.doc.created, false);
    const resumed2 = new RetentionService({ db, blobs, audit, clock }).run(crash2);
    assert.deepEqual(resumed2.resumedBlobRefs, []);
    assert.deepEqual(resumed2.disposals, []);
    assert.equal(blobs.check(crash2, live.doc.digest), 'ok', 'content referenced by a live envelope survives resumption');
    assert.throws(() => new RetentionService({ db, blobs, audit }), /injected clock/);
  } finally {
    db.close();
  }
});
