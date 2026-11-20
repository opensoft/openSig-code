// SPDX-License-Identifier: Apache-2.0
//
// The publish compare-and-set (T038; data-model.md § Envelope states,
// completed; § Transitions and races, item 2; A-008 P04). Each refused
// publish is checked for its exact reason and for writing nothing at all: the
// job, the envelope, final_artifacts, outbox_events and the audit chain are
// equal before and after. Data is synthetic, in a migrated temporary database.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { DEFAULT_LEASE_MS, reclaimExpiredLease } from '../../src/storage/repositories/jobs.ts';
import { assertUnchanged, lease, publish, refusedWith, takeOver } from './support/steps.mjs';
import { assembleAttempt, makeWorld, RESERVED_VERSION, seedFinalizing, snapshot } from './support/world.mjs';

test('[FEN-01] a stale fencing token publishes nothing after another attempt took over; the current token publishes', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const stale = lease(world, envelopeId, 'runner-a');
    const current = takeOver(world, stale, 'runner-b');
    const assembled = assembleAttempt(world, envelopeId);
    const before = snapshot(world, envelopeId);
    assert.throws(() => publish(world, stale, assembled), refusedWith('fence'));
    assertUnchanged(world, envelopeId, before, `the stale attempt ${stale.fencingToken} wrote nothing`);

    const published = publish(world, current, assembled);
    assert.equal(published.envelopeVersion, RESERVED_VERSION + 1, `published at version ${published.envelopeVersion}, expected ${RESERVED_VERSION + 1}`);
    const after = snapshot(world, envelopeId);
    assert.equal(after.artifacts.length, 1, `artifacts ${after.artifacts.length}`);
    assert.equal(
      after.artifacts[0].fencing_token,
      current.fencingToken,
      `the artifact carries attempt ${after.artifacts[0].fencing_token}, the publisher's is ${current.fencingToken}`,
    );
    assert.throws(() => publish(world, stale, { ...assembled, artifact: { ...assembled.artifact, artifactId: `${assembled.artifact.artifactId}x` } }), refusedWith('fence'));
    assertUnchanged(world, envelopeId, after, `a late publish by attempt ${stale.fencingToken} still writes nothing`);
  } finally {
    world.close();
  }
});

test('[FEN-01] a stale envelope version publishes nothing, even under a valid lease', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    const assembled = assembleAttempt(world, envelopeId);
    // Test-only premise: move the version by one while the envelope stays finalizing (0010 allows a +1 step alone).
    world.db.transaction(() =>
      assert.equal(world.store.compareAndSet('envelopes', { id: envelopeId }, RESERVED_VERSION, { updated_at: world.clock.iso() }), true, `premise: ${envelopeId} moved past v${RESERVED_VERSION}`),
    );
    const state = world.store.get('envelopes', { id: envelopeId }).state;
    assert.equal(state, 'finalizing', `premise: ${envelopeId} is ${state}`);
    const before = snapshot(world, envelopeId);
    assert.throws(() => publish(world, grant, assembled), refusedWith('version'));
    assertUnchanged(world, envelopeId, before, `a publish expecting v${RESERVED_VERSION} at v${before.envelope.version} wrote nothing`);
    assert.equal(before.job.status, 'running', `the job is ${before.job.status} under attempt ${grant.fencingToken}`);
  } finally {
    world.close();
  }
});

test('[FEN-01] an envelope that is not finalizing publishes nothing, even at its current version', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    const assembled = assembleAttempt(world, envelopeId);
    // Test-only premise: the envelope is completed (version 5) while the job still runs.
    world.db.transaction(() =>
      assert.equal(
        world.store.compareAndSet('envelopes', { id: envelopeId }, RESERVED_VERSION, { state: 'completed', updated_at: world.clock.iso() }),
        true,
        `premise: ${envelopeId} moved to completed`,
      ),
    );
    const before = snapshot(world, envelopeId);
    assert.throws(() => publish(world, grant, assembled, { expectedEnvelopeVersion: RESERVED_VERSION + 1 }), refusedWith('state'));
    assertUnchanged(world, envelopeId, before, `a publish on a ${before.envelope.state} envelope wrote nothing`);
    assert.equal(before.artifacts.length, 0, `artifacts ${before.artifacts.length}`);
  } finally {
    world.close();
  }
});

test('[FEN-05] publication requires a running job under the attempt’s unexpired lease', () => {
  const world = makeWorld();
  try {
    // (a) The lease expired and nobody reclaimed it: the token is still current, the lease is not. At
    // exactly lease_expires_at the lease no longer holds (request #59 (11): the fence is strict).
    const first = seedFinalizing(world);
    const expired = lease(world, first.envelopeId, 'runner-a');
    const assembledFirst = assembleAttempt(world, first.envelopeId);
    world.clock.advance(DEFAULT_LEASE_MS);
    assert.equal(world.clock.iso(), expired.leaseExpiresAt, `premise: now ${world.clock.iso()} is the expiry ${expired.leaseExpiresAt}`);
    const beforeFirst = snapshot(world, first.envelopeId);
    assert.equal(
      beforeFirst.job.fencing_token,
      expired.fencingToken,
      `premise: the job's current attempt is ${beforeFirst.job.fencing_token}, the holder's ${expired.fencingToken}`,
    );
    assert.throws(() => publish(world, expired, assembledFirst), refusedWith('fence'));
    assertUnchanged(world, first.envelopeId, beforeFirst, `the holder whose lease expired at ${expired.leaseExpiresAt} wrote nothing`);

    // (b) The lease was reclaimed: the job is retryable with the same token, which 0005's trigger alone would accept.
    const second = seedFinalizing(world);
    const reclaimedHolder = lease(world, second.envelopeId, 'runner-c');
    const assembledSecond = assembleAttempt(world, second.envelopeId);
    world.clock.advance(DEFAULT_LEASE_MS + 1_000);
    const reclaimed = world.db.transaction(() => reclaimExpiredLease(world.store, second.envelopeId, world.clock.now()));
    assert.equal(reclaimed, 'retryable', `reclaim of ${second.envelopeId}: ${reclaimed}`);
    const beforeSecond = snapshot(world, second.envelopeId);
    assert.equal(beforeSecond.job.status, 'retryable', `the reclaimed job is ${beforeSecond.job.status}`);
    assert.equal(
      beforeSecond.job.fencing_token,
      reclaimedHolder.fencingToken,
      `premise: the reclaimed job keeps attempt ${reclaimedHolder.fencingToken} (got ${beforeSecond.job.fencing_token})`,
    );
    assert.throws(() => publish(world, reclaimedHolder, assembledSecond), refusedWith('fence'));
    assertUnchanged(world, second.envelopeId, beforeSecond, `the lease loser, attempt ${reclaimedHolder.fencingToken}, wrote nothing`);
  } finally {
    world.close();
  }
});
