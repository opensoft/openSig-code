// SPDX-License-Identifier: Apache-2.0
//
// Orphan collection (T038; data-model.md § Entities, FinalizationAttemptBlob;
// § Transitions and races, item 2; FEN-04; A-010 request #59 (7) and (9)).
// An abandoned attempt's recorded blobs are removed through T029's one
// disposal path once its lease ended and 24 hours passed, exactly once; the
// published attempt's blobs, a ref any live or published attempt also
// recorded, and a live attempt's refs are kept. Synthetic data in a migrated
// temporary database and blob store, with an injected clock.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { recordBlob } from '../../src/domain/finalization/index.ts';
import { ATTEMPT_GRACE_MS, attemptCollectable, DEFAULT_LEASE_MS } from '../../src/storage/repositories/jobs.ts';
import { OrphanCollector } from '../../src/storage/retention/orphans.ts';
import { holderOf, lease, publish, takeOver } from './support/steps.mjs';
import { assembleAttempt, makeWorld, seedFinalizing, sha256, syntheticBytes } from './support/world.mjs';

const ORPHAN_EVENT = 'retention.orphans_collected';

function refOf(world, digest) {
  return `tenants/${world.tenantId}/sha256/${digest}`;
}

/** Record `label`'s synthetic bytes under `grant`, then store them (the runner's order). */
function storeRecorded(world, grant, role, label) {
  const bytes = syntheticBytes(label);
  const digest = sha256(bytes);
  const ref = refOf(world, digest);
  assert.equal(recordBlob(world.context(), holderOf(grant), ref, role), true, `${label} is recorded under the held lease`);
  world.blobs.put(world.tenantId, bytes, { expectedDigest: digest });
  return { ref, digest };
}

function collector(world, envelopesPerRun) {
  return new OrphanCollector({ db: world.db, blobs: world.blobs, audit: world.audit, clock: world.clock.now, envelopesPerRun });
}

const orphanEvents = (world) => world.store.count('audit_events', { type: ORPHAN_EVENT });
const status = (world, blob) => world.blobs.check(world.tenantId, blob.digest);
/** The disposals of a run as envelope ids and disposed refs, for assertion messages. */
const shown = (disposals) => JSON.stringify(disposals.map((disposal) => [disposal.envelopeId, disposal.disposedBlobRefs]));

test('[FEN-04] an abandoned attempt’s blobs are collected once, only after its lease ended and 24 hours passed', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    const composed = storeRecorded(world, grant, 'composed', 'fen04-composed');
    const sealed = storeRecorded(world, grant, 'sealed', 'fen04-sealed');
    const orphans = collector(world);

    const live = orphans.run(world.tenantId).disposals;
    assert.deepEqual(live, [], `a live lease (to ${grant.leaseExpiresAt}) keeps its blobs (disposals ${shown(live)})`);
    world.clock.advance(DEFAULT_LEASE_MS + 1_000);
    const expired = orphans.run(world.tenantId).disposals;
    assert.deepEqual(expired, [], `an expired, unreclaimed lease keeps its blobs within the grace at ${world.clock.iso()} (disposals ${shown(expired)})`);
    world.clock.advance(ATTEMPT_GRACE_MS - 2_000);
    const early = attemptCollectable(world.store, envelopeId, grant.fencingToken, world.clock.now());
    assert.equal(early, false, `at ${world.clock.iso()}, one second before lease end ${grant.leaseExpiresAt} + 24 h, collectable ${early}`);
    assert.deepEqual(orphans.run(world.tenantId).disposals, []);
    assert.equal(world.store.count('disposal_records'), 0);
    assert.equal(orphanEvents(world), 0);

    world.clock.advance(1_000);
    const run = orphans.run(world.tenantId);
    assert.equal(run.disposals.length, 1);
    const [disposal] = run.disposals;
    assert.equal(disposal.kind, 'orphan-collection');
    assert.deepEqual(disposal.disposedBlobRefs, [composed.ref, sealed.ref].sort());
    assert.deepEqual(disposal.keptBlobRefs, []);
    assert.deepEqual([status(world, composed), status(world, sealed)], ['missing', 'missing']);
    const records = world.store.list('disposal_records', { envelope_id: envelopeId });
    assert.equal(records.length, 1);
    assert.equal(records[0].kind, 'orphan-collection');
    assert.equal(orphanEvents(world), 1, `one orphan audit event for the attempt (got ${orphanEvents(world)})`);
    const kept = world.store.count('finalization_attempt_blobs', { envelope_id: envelopeId });
    assert.equal(kept, 2, `the records stay, immutable (got ${kept})`);

    world.clock.advance(ATTEMPT_GRACE_MS);
    const repeat = orphans.run(world.tenantId).disposals;
    assert.deepEqual(repeat, [], `a collected attempt is never collected again (disposals ${shown(repeat)})`);
    assert.equal(orphanEvents(world), 1);
    assert.equal(world.store.count('disposal_records'), 1);
  } finally {
    world.close();
  }
});

test('[FEN-04] the published attempt’s blobs, a ref a published or live attempt also recorded, and a live attempt’s blobs are kept', () => {
  const world = makeWorld();
  try {
    const published = seedFinalizing(world).envelopeId;
    const stale = lease(world, published, 'runner-a');
    const assembled = assembleAttempt(world, published, 'winner');
    const pdf = { ref: refOf(world, assembled.artifact.artifactDigest), digest: assembled.artifact.artifactDigest };
    const evidence = { ref: refOf(world, assembled.artifact.evidenceDigest), digest: assembled.artifact.evidenceDigest };
    const pack = { ref: refOf(world, assembled.artifact.packageDigest), digest: assembled.artifact.packageDigest };
    // The stale attempt recorded the same content-addressed PDF (a deterministic seal), one blob of its own, and one a live attempt elsewhere records too.
    assert.equal(recordBlob(world.context(), holderOf(stale), pdf.ref, 'sealed'), true);
    const own = storeRecorded(world, stale, 'composed', 'fen04-stale-only');
    const sharedLive = storeRecorded(world, stale, 'evidence', 'fen04-shared-with-live');
    const current = takeOver(world, stale, 'runner-b');
    for (const [blob, role] of [[pdf, 'sealed'], [evidence, 'evidence'], [pack, 'package']]) {
      assert.equal(recordBlob(world.context(), holderOf(current), blob.ref, role), true);
    }
    publish(world, current, assembled);

    world.clock.advance(DEFAULT_LEASE_MS + ATTEMPT_GRACE_MS + 60_000);
    const live = seedFinalizing(world).envelopeId;
    const liveGrant = lease(world, live, 'runner-c');
    const liveOwn = storeRecorded(world, liveGrant, 'composed', 'fen04-live-only');
    storeRecorded(world, liveGrant, 'evidence', 'fen04-shared-with-live');

    const run = collector(world).run(world.tenantId);
    assert.equal(run.next, null);
    assert.deepEqual(
      run.disposals.map((disposal) => [disposal.envelopeId, disposal.disposedBlobRefs]),
      [[published, [own.ref]]],
      `only the stale attempt's own blob ${own.ref} is collected and ${live} gets no disposal (disposals ${shown(run.disposals)})`,
    );
    assert.equal(status(world, own), 'missing');
    for (const blob of [pdf, evidence, pack, sharedLive, liveOwn]) assert.equal(status(world, blob), 'ok', `${blob.ref} is kept`);
    assert.equal(
      attemptCollectable(world.store, published, current.fencingToken, world.clock.now()),
      false,
      `the published attempt ${current.fencingToken} of ${published} is never collectable, at ${world.clock.iso()}`,
    );
    assert.equal(attemptCollectable(world.store, published, stale.fencingToken, world.clock.now()), true);
    assert.equal(orphanEvents(world), 1);
  } finally {
    world.close();
  }
});

test('[FEN-04] a run with nothing to collect writes nothing; a bounded run hands back a cursor and the next run reaches the rest', () => {
  const world = makeWorld();
  try {
    const envelopes = [];
    for (let index = 0; index < 3; index += 1) {
      const { envelopeId } = seedFinalizing(world);
      storeRecorded(world, lease(world, envelopeId, `runner-${index}`), 'composed', `fen04-bounded-${index}`);
      envelopes.push(envelopeId);
    }
    envelopes.sort();
    const orphans = collector(world, 2);
    const events = world.store.count('audit_events');
    const early = orphans.run(world.tenantId);
    assert.deepEqual(early.disposals, []);
    assert.equal(early.next, envelopes[1], `stopped after two envelopes at ${early.next}, expected ${envelopes[1]}`);
    const eventsNow = world.store.count('audit_events');
    assert.equal(eventsNow, events, `no disposal, no audit event (events ${events} → ${eventsNow})`);
    assert.equal(world.store.count('disposal_records'), 0);

    world.clock.advance(DEFAULT_LEASE_MS + ATTEMPT_GRACE_MS);
    const first = orphans.run(world.tenantId);
    assert.deepEqual(first.disposals.map((disposal) => disposal.envelopeId), envelopes.slice(0, 2));
    assert.equal(first.next, envelopes[1]);
    const second = orphans.run(world.tenantId, first.next);
    assert.deepEqual(second.disposals.map((disposal) => disposal.envelopeId), [envelopes[2]]);
    assert.equal(second.next, null);
    const again = orphans.run(world.tenantId);
    assert.deepEqual(again.disposals, [], `nothing is collected twice (disposals ${shown(again.disposals)})`);
    assert.equal(orphanEvents(world), 3, `one orphan event per abandoned attempt (got ${orphanEvents(world)} for 3)`);
  } finally {
    world.close();
  }
});
