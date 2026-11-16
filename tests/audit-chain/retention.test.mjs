// SPDX-License-Identifier: Apache-2.0
//
// Retention and disposal (T029): AC-05 DisposalRecord plus audit event under
// an injected clock, with completed evidence never mutated; RET-01 unset and
// invalid policies, scope "all", and resumption after a crash between the
// record's commit and the blob removal; RET-02 the exported disposal path and
// its in-transaction re-check; RET-03 only retention records end retention;
// RET-04 retained final artifacts keep protecting their blobs; RET-05 more
// than 10,000 eligible envelopes; RET-06 every shared reference is seen;
// RET-07 the exported reference-protection predicate is the disposer's rule.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalDigest } from '../../src/domain/canonical/index.ts';
import { eventDigest, eventFromRow, verifyChain } from '../../src/storage/audit/index.ts';
import { MAX_LIST_LIMIT, StorageConstraintError, StorageUsageError } from '../../src/storage/db/index.ts';
import {
  BLOB_REFERENCE_COLUMNS,
  BlobDisposer,
  DISPOSAL_RECORD_SCHEMA,
  ReferenceProtection,
  RETENTION_BATCH_SIZE,
  RetentionPolicyError,
  RetentionService,
  parseRetentionPolicy,
} from '../../src/storage/retention/index.ts';
import { makeScratch } from '../storage/support/fixtures.mjs';
import {
  BASE_TIME,
  createTenant,
  envelopeRow,
  environment,
  fixedClock,
  sid,
  steppingClock,
  syntheticBytes,
  terminalEnvelope,
  ts,
} from './support/chain.mjs';

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
      assert.equal(record.kind, 'retention');
      assert.equal(disposal.kind, 'retention');
      assert.equal(record.policy_ref, 'synthetic-retention-30d');
      assert.equal(record.server_time, RUN_AT, 'server_time comes from the injected clock');
      assert.deepEqual(JSON.parse(record.disposed_blob_refs_json), disposal.disposedBlobRefs);
      assert.deepEqual(JSON.parse(record.retained_artifact_digests_json), disposal.retainedArtifactDigests);
      const recordDigest = canonicalDigest({
        schema: DISPOSAL_RECORD_SCHEMA,
        tenant_id: tenant,
        id: record.id,
        envelope_id: record.envelope_id,
        kind: 'retention',
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
        kept_blob_count: disposal.keptBlobRefs.length,
        kind: 'retention',
        policy_ref: 'synthetic-retention-30d',
        retained_artifact_count: disposal.retainedArtifactDigests.length,
        scope: 'documents',
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

/** An envelope in `state` whose single document revision is the existing blob `blob`. */
function envelopeWithDocument(db, tenant, blob, { state = 'declined', updatedMinutes = 10, revisions = 1 } = {}) {
  const store = db.forTenant(tenant);
  const env = sid('env');
  db.transaction(() => {
    store.insert('envelopes', envelopeRow(env, { state, updated_at: ts(updatedMinutes) }));
    for (let i = 0; i < revisions; i += 1) {
      store.insert('document_revisions', {
        id: sid('rev'),
        envelope_id: env,
        content_digest: blob.digest,
        blob_ref: blob.ref,
        bytes: 1,
        pages: 1,
        page_geometry_json: '[]',
        parse_report_json: '{}',
        created_at: ts(2),
      });
    }
  });
  return env;
}

function disposalRecord(id, envelopeId, kind) {
  return {
    id,
    envelope_id: envelopeId,
    kind,
    retained_artifact_digests_json: '[]',
    disposed_blob_refs_json: '[]',
    policy_ref: 'synthetic-policy',
    server_time: ts(30),
  };
}

test('[RET-02] BlobDisposer is the exported disposal path: it re-checks every candidate in its own transaction and records the kind', () => {
  const { db, blobs, audit } = environment(scratch, steppingClock());
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const store = db.forTenant(tenant);
    const disposer = new BlobDisposer({ db, blobs, audit, clock: fixedClock(RUN_AT) });
    const owner = terminalEnvelope(db, blobs, tenant, { state: 'voided', updatedMinutes: 1 });
    const completed = terminalEnvelope(db, blobs, tenant, { state: 'completed', updatedMinutes: 1 });
    const live = terminalEnvelope(db, blobs, tenant, { state: 'sent', updatedMinutes: 1 });

    // Candidates an orphan collector computed earlier: two unreferenced attempt
    // blobs, the published PDF of another envelope, and a live document.
    const orphanA = blobs.put(tenant, syntheticBytes('attempt-a', 300));
    const orphanB = blobs.put(tenant, syntheticBytes('attempt-b', 300));
    const candidates = [orphanA.ref, orphanB.ref, completed.pdf.ref, live.doc.ref];
    // After the candidates were computed, a live envelope starts using orphanB.
    envelopeWithDocument(db, tenant, orphanB, { state: 'draft' });

    const before = store.count('disposal_records');
    const request = { envelopeId: owner.env, kind: 'orphan-collection', policyRef: 'orphan-collection', refs: candidates, retainedArtifactDigests: [] };
    assert.throws(() => db.transaction(() => disposer.dispose(tenant, request)), (error) => error instanceof StorageUsageError && /own transaction/.test(error.message));
    for (const bad of [
      { ...request, kind: 'archive' },
      { ...request, kind: 'retention' },
      { ...request, scope: 'all' },
      { ...request, refs: [blobs.put(sid('tenant'), syntheticBytes('foreign', 10)).ref] },
      { ...request, policyRef: '' },
    ]) {
      assert.throws(() => disposer.dispose(tenant, bad), StorageUsageError, JSON.stringify(bad.kind));
    }
    assert.equal(store.count('disposal_records'), before, 'refused requests write nothing');

    const outcome = disposer.dispose(tenant, request);
    assert.equal(outcome.kind, 'orphan-collection');
    assert.deepEqual(outcome.disposedBlobRefs, [orphanA.ref]);
    assert.deepEqual(outcome.keptBlobRefs, [orphanB.ref, completed.pdf.ref, live.doc.ref].sort(), 'referenced refs are kept, re-checked at disposal time');
    assert.equal(blobs.check(tenant, orphanA.digest), 'missing');
    for (const kept of [orphanB, completed.pdf, live.doc]) assert.equal(blobs.check(tenant, kept.digest), 'ok');

    const record = store.get('disposal_records', { id: outcome.disposalId });
    assert.equal(record.kind, 'orphan-collection');
    const recordDigest = canonicalDigest({
      schema: DISPOSAL_RECORD_SCHEMA,
      tenant_id: tenant,
      id: record.id,
      envelope_id: owner.env,
      kind: 'orphan-collection',
      retained_artifact_digests: [],
      disposed_blob_refs: [orphanA.ref],
      policy_ref: 'orphan-collection',
      server_time: RUN_AT,
    });
    assert.equal(outcome.recordDigest, recordDigest);
    const event = store.get('audit_events', { subject_digest: recordDigest });
    assert.deepEqual([event.type, event.actor_kind, event.actor_ref, event.envelope_id], ['retention.orphans_collected', 'system', 'orphan-collector', owner.env]);
    assert.deepEqual(JSON.parse(event.metadata_json), {
      disposal_id: record.id,
      disposed_blob_count: 1,
      kept_blob_count: 3,
      kind: 'orphan-collection',
      policy_ref: 'orphan-collection',
      retained_artifact_count: 0,
    });
    assert.equal(disposer.hasRetentionDisposal(tenant, owner.env), false, 'an orphan collection is not a retention disposal');

    // A batch is decided in order: A keeps the shared document while B is
    // live; B, decided after A gave it up, disposes it.
    const shared = blobs.put(tenant, syntheticBytes('shared-batch', 400));
    const envA = envelopeWithDocument(db, tenant, shared);
    const envB = envelopeWithDocument(db, tenant, shared);
    const retention = (envelopeId) => ({ envelopeId, kind: 'retention', scope: 'documents', policyRef: 'synthetic-policy', refs: [shared.ref], retainedArtifactDigests: [] });
    const [first, second] = disposer.disposeBatch(tenant, [retention(envA), retention(envB)]);
    assert.deepEqual([first.keptBlobRefs, first.disposedBlobRefs], [[shared.ref], []]);
    assert.deepEqual([second.keptBlobRefs, second.disposedBlobRefs], [[], [shared.ref]]);
    assert.equal(blobs.check(tenant, shared.digest), 'missing');
    assert.equal(disposer.hasRetentionDisposal(tenant, envA), true);
    const records = store.count('disposal_records');
    assert.throws(() => disposer.dispose(tenant, retention(envA)), /already has a retention disposal/, 'checked inside the transaction');
    assert.equal(store.count('disposal_records'), records, 'a refused batch writes nothing');
    assert.equal(verifyChain(db, tenant).ok, true);
  } finally {
    db.close();
  }
});

test('[RET-03] an orphan-collection DisposalRecord does not block retention; only a retention record ends it', () => {
  const { db, blobs, audit } = environment(scratch, steppingClock());
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    setPolicy(db, tenant, { policy_ref: 'tenant-retention', dispose_after_days: 1 });
    const store = db.forTenant(tenant);
    const orphaned = terminalEnvelope(db, blobs, tenant, { state: 'voided', updatedMinutes: 1 });
    const control = terminalEnvelope(db, blobs, tenant, { state: 'voided', updatedMinutes: 1 });
    const retained = terminalEnvelope(db, blobs, tenant, { state: 'voided', updatedMinutes: 1 });
    db.transaction(() => {
      store.insert('disposal_records', disposalRecord(sid('disp'), orphaned.env, 'orphan-collection'));
      store.insert('disposal_records', disposalRecord(sid('disp'), retained.env, 'retention'));
    });
    // A record without a kind (as an untyped writer would insert it) is refused.
    const { kind: _omitted, ...untyped } = disposalRecord(sid('disp'), control.env, 'retention');
    assert.throws(
      () => db.transaction(() => store.insert('disposal_records', untyped)),
      (error) => error instanceof StorageConstraintError && /kind is required/.test(error.message),
    );

    const clock = fixedClock(new Date(BASE_TIME + 3 * DAY).toISOString());
    const run = new RetentionService({ db, blobs, audit, clock }).run(tenant);
    assert.deepEqual(run.disposals.map((disposal) => disposal.envelopeId).sort(), [orphaned.env, control.env].sort());
    assert.equal(blobs.check(tenant, orphaned.doc.digest), 'missing', 'the envelope with only an orphan-collection record was disposed');
    assert.equal(blobs.check(tenant, control.doc.digest), 'missing');
    assert.equal(blobs.check(tenant, retained.doc.digest), 'ok', 'an envelope with a retention record is skipped');
    assert.equal(store.count('disposal_records', { envelope_id: orphaned.env, kind: 'retention' }), 1);
    assert.deepEqual(new RetentionService({ db, blobs, audit, clock }).run(tenant).disposals, [], 'retention records end it');
  } finally {
    db.close();
  }
});

test('[RET-04] a final artifact kept by scope "documents" keeps protecting its blob; scope "all" gives it up', () => {
  const { db, blobs, audit } = environment(scratch, steppingClock());
  try {
    for (const scope of ['documents', 'all']) {
      const tenant = sid('tenant');
      createTenant(db, tenant);
      setPolicy(db, tenant, { policy_ref: `synthetic-${scope}`, dispose_after_days: 30, scope });
      const disposed = terminalEnvelope(db, blobs, tenant, { state: 'completed', updatedMinutes: 10 });
      // A later envelope reuses the final PDF's bytes as its document; it is
      // not yet eligible at the first run.
      const reuser = envelopeWithDocument(db, tenant, disposed.pdf, { state: 'declined', updatedMinutes: 40 * 24 * 60 });

      const first = new RetentionService({ db, blobs, audit, clock: fixedClock(RUN_AT) }).run(tenant);
      assert.deepEqual(first.disposals.map((disposal) => disposal.envelopeId), [disposed.env]);
      assert.equal(blobs.check(tenant, disposed.pdf.digest), 'ok', `${scope}: the PDF survives the first run (kept or still shared)`);

      const later = fixedClock(new Date(BASE_TIME + 80 * DAY).toISOString());
      const second = new RetentionService({ db, blobs, audit, clock: later }).run(tenant);
      assert.deepEqual(second.disposals.map((disposal) => disposal.envelopeId), [reuser]);
      if (scope === 'documents') {
        assert.equal(blobs.check(tenant, disposed.pdf.digest), 'ok', 'scope documents never removes a retained final artifact');
        assert.deepEqual(second.disposals[0].keptBlobRefs, [disposed.pdf.ref], 'the retained final artifact still references the blob');
        assert.equal(db.forTenant(tenant).get('final_artifacts', { envelope_id: disposed.env }).pdf_blob_ref, disposed.pdf.ref);
      } else {
        assert.equal(blobs.check(tenant, disposed.pdf.digest), 'missing', 'scope all gave the artifact up, so the last user disposes it');
        assert.deepEqual(second.disposals[0].disposedBlobRefs, [disposed.pdf.ref]);
      }
      assert.equal(verifyChain(db, tenant).ok, true);
    }
  } finally {
    db.close();
  }
});

test('[RET-05] one run disposes every eligible envelope, beyond 10,000, in batched transactions', () => {
  const { db, blobs, audit } = environment(scratch, steppingClock());
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    setPolicy(db, tenant, { policy_ref: 'synthetic-bulk', dispose_after_days: 1 });
    const store = db.forTenant(tenant);
    const count = MAX_LIST_LIMIT + 1;
    db.transaction(() => {
      for (let i = 0; i < count; i += 1) store.insert('envelopes', envelopeRow(`env_${String(i).padStart(16, '0')}`, { state: 'voided', updated_at: ts(5) }));
    });
    // Two more whose ids sort after all of those, with real document blobs.
    const tail = ['zz_tail_000000000001', 'zz_tail_000000000002'].map((id, index) => {
      const doc = blobs.put(tenant, syntheticBytes(`tail-${index}`, 256));
      db.transaction(() => {
        store.insert('envelopes', envelopeRow(id, { state: 'expired', updated_at: ts(5) }));
        store.insert('document_revisions', {
          id: sid('rev'),
          envelope_id: id,
          content_digest: doc.digest,
          blob_ref: doc.ref,
          bytes: 256,
          pages: 1,
          page_geometry_json: '[]',
          parse_report_json: '{}',
          created_at: ts(2),
        });
      });
      return { id, doc };
    });
    const clock = fixedClock(new Date(BASE_TIME + 2 * DAY).toISOString());
    const run = new RetentionService({ db, blobs, audit, clock }).run(tenant);
    assert.equal(run.disposals.length, count + 2, 'every eligible envelope in one run');
    assert.equal(new Set(run.disposals.map((disposal) => disposal.envelopeId)).size, count + 2);
    for (const { id, doc } of tail) {
      assert.ok(run.disposals.some((disposal) => disposal.envelopeId === id && disposal.disposedBlobRefs[0] === doc.ref));
      assert.equal(blobs.check(tenant, doc.digest), 'missing');
    }
    assert.equal(store.count('disposal_records', { kind: 'retention' }), count + 2);
    assert.ok(RETENTION_BATCH_SIZE < count, 'the run spans several batches');
    const report = verifyChain(db, tenant);
    assert.deepEqual([report.ok, report.events], [true, count + 2]);
    assert.deepEqual(new RetentionService({ db, blobs, audit, clock }).run(tenant).disposals, []);
  } finally {
    db.close();
  }
});

test('[RET-06] the shared-reference check reads every reference, so a live user past 10,000 rows keeps the blob', () => {
  const { db, blobs, audit } = environment(scratch, steppingClock());
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    setPolicy(db, tenant, { policy_ref: 'synthetic-shared', dispose_after_days: 1 });
    const shared = blobs.put(tenant, syntheticBytes('shared-many', 512));
    // The eligible envelope holds the first 10,000 references; the live
    // draft's reference comes after them.
    const eligible = envelopeWithDocument(db, tenant, shared, { state: 'declined', updatedMinutes: 5, revisions: MAX_LIST_LIMIT });
    const live = envelopeWithDocument(db, tenant, shared, { state: 'draft', updatedMinutes: 5 });
    assert.equal(db.forTenant(tenant).count('document_revisions', { blob_ref: shared.ref }), MAX_LIST_LIMIT + 1);

    const clock = fixedClock(new Date(BASE_TIME + 2 * DAY).toISOString());
    const run = new RetentionService({ db, blobs, audit, clock }).run(tenant);
    assert.deepEqual(run.disposals.map((disposal) => disposal.envelopeId), [eligible]);
    assert.deepEqual(run.disposals[0].disposedBlobRefs, []);
    assert.deepEqual(run.keptSharedBlobRefs, [shared.ref]);
    assert.equal(blobs.check(tenant, shared.digest), 'ok', `the live envelope ${live} keeps its document`);
  } finally {
    db.close();
  }
});

test('[RET-07] the exported ReferenceProtection predicate is the one rule the disposer applies (A-009 T30R-4)', () => {
  const { db, blobs, audit } = environment(scratch, steppingClock());
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const store = db.forTenant(tenant);
    const disposer = new BlobDisposer({ db, blobs, audit, clock: fixedClock(RUN_AT) });
    assert.deepEqual(
      BLOB_REFERENCE_COLUMNS.map(({ table, column, kind }) => `${table}.${column}:${kind}`),
      ['document_revisions.blob_ref:document', 'final_artifacts.pdf_blob_ref:artifact', 'final_artifacts.evidence_blob_ref:artifact', 'final_artifacts.package_blob_ref:artifact'],
    );

    // Four envelopes, one per case of the rule.
    const keptArtifacts = terminalEnvelope(db, blobs, tenant, { state: 'completed', updatedMinutes: 1 });
    const gaveUpAll = terminalEnvelope(db, blobs, tenant, { state: 'completed', updatedMinutes: 1 });
    const orphaned = terminalEnvelope(db, blobs, tenant, { state: 'completed', updatedMinutes: 1 });
    const live = terminalEnvelope(db, blobs, tenant, { state: 'sent', updatedMinutes: 1 });
    const retention = (envelope, scope) => ({ envelopeId: envelope.env, kind: 'retention', scope, policyRef: 'synthetic-policy', refs: [], retainedArtifactDigests: [] });
    disposer.dispose(tenant, retention(keptArtifacts, 'documents'));
    disposer.dispose(tenant, retention(gaveUpAll, 'all'));
    disposer.dispose(tenant, { envelopeId: orphaned.env, kind: 'orphan-collection', policyRef: 'orphan-collection', refs: [], retainedArtifactDigests: [] });

    const plain = new ReferenceProtection(store);
    const decisions = (protection) =>
      [keptArtifacts, gaveUpAll, orphaned, live].map((envelope) => [protection.protects(envelope.env, 'document'), protection.protects(envelope.env, 'artifact')]);
    assert.deepEqual(decisions(plain), [
      [false, true], // retention, scope documents: documents given up, artifacts kept
      [false, false], // retention, scope all: both given up
      [true, true], // an orphan-collection record gives nothing up
      [true, true], // live
    ]);
    const asRetentionAll = new ReferenceProtection(store, { envelopeId: live.env, kind: 'retention', scope: 'all' });
    assert.deepEqual(decisions(asRetentionAll)[3], [false, false], 'the envelope being disposed counts as giving up what the disposal gives up');
    assert.deepEqual(decisions(asRetentionAll).slice(0, 3), decisions(plain).slice(0, 3));
    const asOrphan = new ReferenceProtection(store, { envelopeId: live.env, kind: 'orphan-collection', scope: undefined });
    assert.deepEqual(decisions(asOrphan)[1], [false, true], 'an orphan collection never overrides a final artifact');

    // Parity: for both kinds of disposal, the disposer keeps exactly the refs
    // the exported predicate calls referenced.
    const unreferenced = blobs.put(tenant, syntheticBytes('ret-07-unreferenced', 200));
    const refsOf = (envelope) => [envelope.doc.ref, envelope.pdf?.ref, envelope.evidence?.ref].filter(Boolean);
    const pool = [...new Set([...refsOf(keptArtifacts), ...refsOf(gaveUpAll), ...refsOf(orphaned), ...refsOf(live), unreferenced.ref])].sort();
    for (const request of [
      { envelopeId: orphaned.env, kind: 'orphan-collection', policyRef: 'orphan-collection', refs: pool, retainedArtifactDigests: [] },
      { envelopeId: live.env, kind: 'retention', scope: 'documents', policyRef: 'synthetic-policy', refs: pool, retainedArtifactDigests: [] },
    ]) {
      const context = { envelopeId: request.envelopeId, kind: request.kind, scope: request.scope };
      const predicted = pool.filter((ref) => new ReferenceProtection(store, context).referenced(ref));
      const outcome = disposer.dispose(tenant, request);
      assert.deepEqual(outcome.keptBlobRefs, predicted, `${request.kind}: kept refs equal the predicate`);
      assert.deepEqual(outcome.disposedBlobRefs, pool.filter((ref) => !predicted.includes(ref)));
    }
    assert.equal(blobs.check(tenant, keptArtifacts.pdf.digest), 'ok', 'a retained final artifact survived both disposals');

    // The disposer has no private copy of the rule: it delegates to the class.
    const source = readFileSync(join(resolve(dirname(fileURLToPath(import.meta.url)), '..', '..'), 'src', 'storage', 'retention', 'service.ts'), 'utf8');
    assert.equal([...source.matchAll(/new ReferenceProtection\(/g)].length, 1, 'one construction site, in BlobDisposer');
    assert.equal([...source.matchAll(/iterate\('final_artifacts'/g)].length, 0, 'no second scan of artifact references');
  } finally {
    db.close();
  }
});
