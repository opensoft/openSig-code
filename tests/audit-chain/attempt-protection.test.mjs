// SPDX-License-Identifier: Apache-2.0
//
// RET-09 (T029 commit in the T038 slot; A-010 requests #59 (7) and #75 (2),
// (4); row ATTEMPT-ALL): the single reference-protection predicate gains
// FinalizationAttemptBlob records, and every blob removal, after a disposal's
// commit and in resume(), re-checks protection and removes the blob inside one
// BEGIN IMMEDIATE transaction. A live finalization attempt that rewrites a
// content-addressed ref an older disposal is removing keeps its blob. A
// published attempt's records protect exactly as its final artifact does:
// always against an orphan collection, still under retention scope
// `documents`, and not after scope `all`, which also proposes every ref the
// published attempt recorded. The finalizing envelopes, leases and attempt
// records come from T038's completion support and domain steps. Synthetic
// data, injected clock.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { recordBlob } from '../../src/domain/finalization/index.ts';
import { ATTEMPT_GRACE_MS, DEFAULT_LEASE_MS } from '../../src/storage/repositories/jobs.ts';
import { OrphanCollector } from '../../src/storage/retention/orphans.ts';
import { BlobDisposer, ReferenceProtection, RetentionService } from '../../src/storage/retention/index.ts';
import { holderOf, lease, publish } from '../completion/support/steps.mjs';
import { assembleAttempt, makeWorld, seedFinalizing, sha256, syntheticBytes } from '../completion/support/world.mjs';

/** The world's blob store, noting whether each removal ran inside a transaction; `crashes` removals throw first. */
function watchedBlobs(world, crashes = 0) {
  const inner = world.blobs;
  const removals = [];
  let left = crashes;
  const blobs = Object.fromEntries(['put', 'putStream', 'read', 'readRef', 'check', 'list', 'sweepPartials'].map((name) => [name, inner[name].bind(inner)]));
  blobs.dispose = (tenantId, digest) => {
    removals.push({ digest, inTransaction: world.db.inTransaction });
    if (left > 0) {
      left -= 1;
      throw new Error('synthetic crash before blob removal');
    }
    return inner.dispose(tenantId, digest);
  };
  return { blobs, removals };
}

function recordAndStore(world, grant, label, role = 'composed') {
  const bytes = syntheticBytes(label);
  const digest = sha256(bytes);
  const ref = `tenants/${world.tenantId}/sha256/${digest}`;
  assert.equal(recordBlob(world.context(), holderOf(grant), ref, role), true, `${label} (${ref}) is recorded under attempt ${grant.fencingToken}`);
  const stored = world.blobs.put(world.tenantId, bytes, { expectedDigest: digest });
  return { ref, digest, bytes, created: stored.created };
}

const inTransaction = (removals) => `removals ${JSON.stringify(removals)}`;
const shown = (disposals) => JSON.stringify(disposals.map((disposal) => [disposal.envelopeId, disposal.disposedBlobRefs, disposal.keptBlobRefs]));

/** A published envelope whose attempt recorded its composed PDF and its artifact's three refs. */
function publishedEnvelope(world) {
  const { envelopeId } = seedFinalizing(world);
  const grant = lease(world, envelopeId, 'runner-a');
  const composed = recordAndStore(world, grant, `ret09-composed-${envelopeId}`, 'composed');
  const assembled = assembleAttempt(world, envelopeId);
  const refOf = (digest) => `tenants/${world.tenantId}/sha256/${digest}`;
  const blobs = {
    composed,
    pdf: { ref: refOf(assembled.artifact.artifactDigest), digest: assembled.artifact.artifactDigest },
    evidence: { ref: refOf(assembled.artifact.evidenceDigest), digest: assembled.artifact.evidenceDigest },
    pack: { ref: refOf(assembled.artifact.packageDigest), digest: assembled.artifact.packageDigest },
  };
  for (const [name, role] of [['pdf', 'sealed'], ['evidence', 'evidence'], ['pack', 'package']]) {
    assert.equal(recordBlob(world.context(), holderOf(grant), blobs[name].ref, role), true, `${name} ${blobs[name].ref} is recorded under attempt ${grant.fencingToken}`);
  }
  publish(world, grant, assembled);
  return { envelopeId, blobs };
}

function setPolicy(world, scope) {
  world.db.transaction(() => world.store.update('tenants', {}, { retention_json: JSON.stringify({ policy_ref: `synthetic-ret09-${scope}`, dispose_after_days: 1, scope }) }));
}

test('[RET-09] a live attempt that records a ref after the disposal committed keeps its blob: the removal re-checks inside its own transaction', () => {
  const world = makeWorld();
  try {
    const abandoned = seedFinalizing(world).envelopeId;
    const shared = recordAndStore(world, lease(world, abandoned, 'runner-a'), 'ret09-shared');
    world.clock.advance(DEFAULT_LEASE_MS + ATTEMPT_GRACE_MS);
    const live = lease(world, seedFinalizing(world).envelopeId, 'runner-b');
    const { blobs, removals } = watchedBlobs(world);
    const collector = new OrphanCollector({ db: world.db, blobs, audit: world.audit, clock: world.clock.now });

    // Between the disposal's commit and its removal, the live attempt records the same content-addressed ref and rewrites it.
    const transaction = world.db.transaction.bind(world.db);
    let armed = true;
    world.db.transaction = (fn) => {
      const result = transaction(fn);
      if (armed) {
        armed = false;
        assert.equal(recordBlob(world.context(), holderOf(live), shared.ref, 'composed'), true, `the live attempt ${live.fencingToken} records ${shared.ref}`);
        const rewrite = world.blobs.put(world.tenantId, shared.bytes, { expectedDigest: shared.digest });
        assert.equal(rewrite.created, false, `the blob ${shared.digest} was still there (created ${rewrite.created})`);
      }
      return result;
    };
    let run;
    try {
      run = collector.run(world.tenantId);
    } finally {
      delete world.db.transaction;
    }
    assert.deepEqual(
      run.disposals.map((disposal) => disposal.disposedBlobRefs),
      [[shared.ref]],
      `the record committed before the live attempt recorded the ref (disposals ${shown(run.disposals)})`,
    );
    const status = world.blobs.check(world.tenantId, shared.digest);
    assert.equal(status, 'ok', `the live attempt's blob ${shared.digest} survives (status ${status})`);
    assert.deepEqual(removals, [], `the re-check kept it: no removal was attempted (${inTransaction(removals)})`);
    const withAttempts = new ReferenceProtection(world.store, undefined, { attempts: { now: world.clock.now() } }).referenced(shared.ref);
    assert.equal(withAttempts, true, `with attempts, ${shared.ref} is referenced (got ${withAttempts})`);
    const without = new ReferenceProtection(world.store).referenced(shared.ref);
    assert.equal(without, false, `without attempts the predicate reads no attempt record, as protects() and backup do not (got ${without})`);
  } finally {
    world.close();
  }
});

test('[RET-09] resume() re-checks every interrupted removal inside a transaction: a ref a live attempt recorded is kept until that attempt is collectable', () => {
  const world = makeWorld();
  try {
    const abandoned = seedFinalizing(world).envelopeId;
    const blob = recordAndStore(world, lease(world, abandoned, 'runner-a'), 'ret09-resume');
    world.clock.advance(DEFAULT_LEASE_MS + ATTEMPT_GRACE_MS);
    const crashing = watchedBlobs(world, 1);
    assert.throws(() => new OrphanCollector({ db: world.db, blobs: crashing.blobs, audit: world.audit, clock: world.clock.now }).run(world.tenantId), /synthetic crash/);
    const records = world.store.count('disposal_records', { kind: 'orphan-collection' });
    assert.equal(records, 1, `the record committed (records ${records})`);
    const afterCrash = world.blobs.check(world.tenantId, blob.digest);
    assert.equal(afterCrash, 'ok', `the blob ${blob.digest} survived the crash (status ${afterCrash})`);
    assert.deepEqual(crashing.removals.map((removal) => removal.inTransaction), [true], `the removal ran inside a transaction (${inTransaction(crashing.removals)})`);

    const liveEnvelope = seedFinalizing(world).envelopeId;
    const liveGrant = lease(world, liveEnvelope, 'runner-b');
    const rewritten = recordAndStore(world, liveGrant, 'ret09-resume');
    assert.equal(rewritten.created, false, `the live attempt rewrote the existing ${blob.digest} (created ${rewritten.created})`);
    const watched = watchedBlobs(world);
    const disposer = new BlobDisposer({ db: world.db, blobs: watched.blobs, audit: world.audit, clock: world.clock.now });
    const kept = disposer.resume(world.tenantId);
    assert.deepEqual(kept, [], `a live attempt's record protects the ref (resumed ${JSON.stringify(kept)})`);
    const whileLive = world.blobs.check(world.tenantId, blob.digest);
    assert.equal(whileLive, 'ok', `the blob stays while ${liveEnvelope}'s attempt is live (status ${whileLive})`);

    world.clock.advance(DEFAULT_LEASE_MS + ATTEMPT_GRACE_MS);
    const resumed = disposer.resume(world.tenantId);
    assert.deepEqual(resumed, [blob.ref], `once every record of the ref is collectable, resume removes it (resumed ${JSON.stringify(resumed)})`);
    const finally_ = world.blobs.check(world.tenantId, blob.digest);
    assert.equal(finally_, 'missing', `the blob ${blob.digest} is removed (status ${finally_})`);
    assert.ok(watched.removals.length >= 1 && watched.removals.every((removal) => removal.inTransaction), `every removal inside a transaction (${inTransaction(watched.removals)})`);
  } finally {
    world.close();
  }
});

test('[RET-09] a published attempt’s records protect as its final artifact does: orphan collection keeps them; scope "all" proposes and removes every ref the attempt recorded, the composed PDF included; a live attempt’s record keeps the shared blob it re-wrote', () => {
  const world = makeWorld();
  try {
    const { envelopeId, blobs } = publishedEnvelope(world);

    world.clock.advance(2 * 86_400_000);
    const live = lease(world, seedFinalizing(world).envelopeId, 'runner-b');
    assert.equal(recordBlob(world.context(), holderOf(live), blobs.evidence.ref, 'evidence'), true, `a live attempt elsewhere records the evidence ref ${blobs.evidence.ref}`);
    // Record, then write: the live attempt re-writes the same content-addressed evidence blob (assembleAttempt's bytes).
    const rewrite = world.blobs.put(world.tenantId, syntheticBytes(`evidence-${envelopeId}-attempt`), { expectedDigest: blobs.evidence.digest });
    assert.equal(rewrite.created, false, `the live attempt ${live.fencingToken} re-wrote the existing ${blobs.evidence.digest} (created ${rewrite.created})`);
    const watched = watchedBlobs(world);
    const options = { db: world.db, blobs: watched.blobs, audit: world.audit, clock: world.clock.now };
    const orphans = new OrphanCollector(options).run(world.tenantId).disposals;
    assert.deepEqual(orphans, [], `the published attempt is never an orphan (disposals ${shown(orphans)})`);

    setPolicy(world, 'all');
    const run = new RetentionService(options).run(world.tenantId);
    assert.equal(run.disposals.length, 1, `retention disposals ${shown(run.disposals)}`);
    const [disposal] = run.disposals;
    assert.equal(disposal.envelopeId, envelopeId, `disposed ${disposal.envelopeId}, expected ${envelopeId}`);
    for (const name of ['composed', 'pdf', 'pack']) {
      assert.ok(disposal.disposedBlobRefs.includes(blobs[name].ref), `scope "all" lists the published attempt's ${name} ${blobs[name].ref} (disposals ${shown(run.disposals)})`);
    }
    assert.deepEqual(disposal.keptBlobRefs, [blobs.evidence.ref], `the live attempt's record keeps the shared ref (disposals ${shown(run.disposals)})`);
    const record = world.store.get('disposal_records', { id: disposal.disposalId });
    const listed = JSON.parse(record.disposed_blob_refs_json);
    assert.ok(listed.includes(blobs.composed.ref), `the DisposalRecord lists the composed ${blobs.composed.ref} (listed ${JSON.stringify(listed)})`);
    const statuses = Object.fromEntries(Object.entries(blobs).map(([name, blob]) => [name, world.blobs.check(world.tenantId, blob.digest)]));
    assert.deepEqual(statuses, { composed: 'missing', pdf: 'missing', evidence: 'ok', pack: 'missing' }, `blob statuses ${JSON.stringify(statuses)}`);
    assert.ok(watched.removals.length >= 3 && watched.removals.every((removal) => removal.inTransaction), `every removal inside a transaction (${inTransaction(watched.removals)})`);
  } finally {
    world.close();
  }
});

test('[RET-09] under retention scope "documents" the published attempt’s records keep protecting: its composed PDF and artifact blobs stay', () => {
  const world = makeWorld();
  try {
    const { envelopeId, blobs } = publishedEnvelope(world);
    world.clock.advance(2 * 86_400_000);
    setPolicy(world, 'documents');
    const watched = watchedBlobs(world);
    const run = new RetentionService({ db: world.db, blobs: watched.blobs, audit: world.audit, clock: world.clock.now }).run(world.tenantId);
    assert.deepEqual(run.disposals.map((disposal) => disposal.envelopeId), [envelopeId], `retention disposals ${shown(run.disposals)}`);
    const [disposal] = run.disposals;
    for (const name of ['composed', 'pdf', 'evidence', 'pack']) {
      assert.ok(!disposal.disposedBlobRefs.includes(blobs[name].ref), `scope "documents" does not dispose the ${name} ${blobs[name].ref} (disposals ${shown(run.disposals)})`);
    }
    const statuses = Object.fromEntries(Object.entries(blobs).map(([name, blob]) => [name, world.blobs.check(world.tenantId, blob.digest)]));
    assert.deepEqual(statuses, { composed: 'ok', pdf: 'ok', evidence: 'ok', pack: 'ok' }, `blob statuses ${JSON.stringify(statuses)}`);
    // The published attempt's records still protect the composed ref under a documents-scope context.
    const protection = new ReferenceProtection(world.store, { envelopeId, kind: 'retention', scope: 'documents' }, { attempts: { now: world.clock.now() } });
    const composedProtected = protection.referenced(blobs.composed.ref);
    assert.equal(composedProtected, true, `the composed ${blobs.composed.ref} is protected under scope documents (got ${composedProtected})`);
  } finally {
    world.close();
  }
});
