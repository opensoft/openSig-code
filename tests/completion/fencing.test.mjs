// SPDX-License-Identifier: Apache-2.0
//
// The publish compare-and-set (T038; data-model.md § Envelope states,
// completed; § Transitions and races, item 2; A-008 P04). Each refused
// publish is checked for its exact reason and for writing nothing at all: the
// job, the envelope, final_artifacts, outbox_events and the audit chain are
// equal before and after. Data is synthetic, in a migrated temporary database.
//
// Row LEASE-TOKEN-TEST (A-010 request #86; FEN-05 extended): the guarded
// writes behind leaseHeld (recordAttemptBlob, writeSealAnchor and
// writeCompletionCheckpoint) refuse a stale attempt whose owner holds the new
// lease under the next fencing token, so the token comparison is what refuses.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { writeCompletionCheckpoint, writeSealAnchor } from '../../src/domain/finalization/index.ts';
import { getCompletionCheckpoint } from '../../src/storage/repositories/artifacts.ts';
import { DEFAULT_LEASE_MS, LEASE_EXPIRED_ERROR_CODE, leaseHeld, listAttemptBlobs, listExpiredLeases, reclaimExpiredLease, recordAttemptBlob, retryDelayMs } from '../../src/storage/repositories/jobs.ts';
import { assertUnchanged, eventsOf, holderOf, lease, publish, refusedWith, takeOver } from './support/steps.mjs';
import { assembleAttempt, hex, makeWorld, RESERVED_VERSION, seedFinalizing, snapshot } from './support/world.mjs';

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

test('[FEN-05] a reclaim needs lease_expires_at at or before now: 1 ms before the expiry it reclaims nothing and the lease still holds; at exactly the expiry the lease no longer holds and the reclaim succeeds (request #59 (11))', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    const tx = (fn) => world.db.transaction(fn);

    world.clock.advance(DEFAULT_LEASE_MS - 1);
    const justBefore = world.clock.iso();
    const before = snapshot(world, envelopeId);
    const early = tx(() => reclaimExpiredLease(world.store, envelopeId, world.clock.now()));
    assert.equal(early, 'not-expired', `at ${justBefore}, 1 ms before the expiry ${grant.leaseExpiresAt}, the reclaim answered ${early}`);
    assertUnchanged(world, envelopeId, before, `the reclaim at ${justBefore} wrote nothing`);
    const heldEarly = leaseHeld(world.store, holderOf(grant), world.clock.now());
    const listedEarly = listExpiredLeases(world.store, world.clock.now(), 10).includes(envelopeId);
    assert.deepEqual([heldEarly, listedEarly], [true, false], `at ${justBefore}: the lease holds ${heldEarly}, listed as expired ${listedEarly}`);

    world.clock.advance(1);
    assert.equal(world.clock.iso(), grant.leaseExpiresAt, `premise: now ${world.clock.iso()} is the expiry ${grant.leaseExpiresAt}`);
    const heldAt = leaseHeld(world.store, holderOf(grant), world.clock.now());
    const listedAt = listExpiredLeases(world.store, world.clock.now(), 10).includes(envelopeId);
    assert.deepEqual([heldAt, listedAt], [false, true], `at the expiry ${grant.leaseExpiresAt}: the lease holds ${heldAt}, listed as expired ${listedAt}`);
    // #59 (11): a lease holds only while lease_expires_at is later than now, and a reclaim needs it at or
    // before now. With attempt 1 of 5 used, the reclaimed job is retryable, its token kept.
    const reclaimed = tx(() => reclaimExpiredLease(world.store, envelopeId, world.clock.now()));
    assert.equal(reclaimed, 'retryable', `at exactly the expiry ${grant.leaseExpiresAt} the reclaim answered ${reclaimed}; #59 (11) and the code define retryable (attempt 1 of 5)`);
    const job = snapshot(world, envelopeId).job;
    const retryAt = new Date(world.clock.now().getTime() + retryDelayMs(1)).toISOString();
    assert.deepEqual(
      [job.status, job.fencing_token, job.lease_owner, job.last_error_code, job.retry_at],
      ['retryable', grant.fencingToken, null, LEASE_EXPIRED_ERROR_CODE, retryAt],
      `reclaimed job ${job.status}, attempt ${job.fencing_token}, owner ${job.lease_owner}, ${job.last_error_code}, retry_at ${job.retry_at} (expected ${retryAt})`,
    );
  } finally {
    world.close();
  }
});

test('[FEN-05] a reclaimed lease lets the old attempt write nothing, also when the same owner holds the new lease: the stale recordAttemptBlob is false, writeSealAnchor and writeCompletionCheckpoint are null, and the job, the audit chain, the attempt records and the checkpoints are unchanged (row LEASE-TOKEN-TEST, request #86)', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const owner = 'runner-a';
    const stale = lease(world, envelopeId, owner);
    const current = takeOver(world, stale, owner);
    const staleHolder = holderOf(stale);
    const currentHolder = holderOf(current);
    const renewed = [current.leaseOwner, current.fencingToken];
    assert.deepEqual(renewed, [owner, stale.fencingToken + 1], `premise: the new lease is ${current.leaseOwner} attempt ${current.fencingToken}; the stale one ${stale.leaseOwner} attempt ${stale.fencingToken}`);
    const held = leaseHeld(world.store, currentHolder, world.clock.now());
    assert.equal(held, true, `premise: at ${world.clock.iso()} ${owner} holds attempt ${current.fencingToken} until ${current.leaseExpiresAt} (held ${held})`);
    const head = () => {
      const [last] = world.store.list('audit_events', {}, { orderBy: [['seq', 'desc']], limit: 1 });
      return last === undefined ? null : [last.seq, last.event_digest];
    };
    const before = snapshot(world, envelopeId);
    const headBefore = head();
    const empty = [eventsOf(world, envelopeId, 'envelope.seal_started').length, getCompletionCheckpoint(world.store, envelopeId) ?? null, before.attemptBlobs];
    assert.deepEqual(empty, [0, null, 0], `premise: no anchor, no checkpoint and no attempt record yet (anchors, checkpoint, records ${JSON.stringify(empty)})`);

    const context = world.context();
    const blobRef = `tenants/${world.tenantId}/sha256/${hex(`stale-composed-${envelopeId}`)}`;
    const recorded = world.db.transaction(() => recordAttemptBlob(world.store, staleHolder, { blobRef, role: 'composed', now: world.clock.now() }));
    const anchor = writeSealAnchor(context, staleHolder);
    const checkpoint = writeCompletionCheckpoint(context, staleHolder);
    assert.deepEqual(
      [recorded, anchor, checkpoint],
      [false, null, null],
      `${owner} attempt ${stale.fencingToken}, while ${owner} holds attempt ${current.fencingToken}: recordAttemptBlob ${recorded}, writeSealAnchor ${JSON.stringify(anchor)}, writeCompletionCheckpoint ${JSON.stringify(checkpoint)}`,
    );
    assertUnchanged(world, envelopeId, before, `the stale holder ${owner} attempt ${stale.fencingToken} wrote nothing`);
    const headAfter = head();
    assert.deepEqual(headAfter, headBefore, `the audit head (seq, digest) ${JSON.stringify(headBefore)} then ${JSON.stringify(headAfter)}`);

    // The refusal is the token's: the same owner's current attempt records and anchors.
    const currentRecorded = world.db.transaction(() => recordAttemptBlob(world.store, currentHolder, { blobRef, role: 'composed', now: world.clock.now() }));
    const currentAnchor = writeSealAnchor(context, currentHolder);
    const tokens = listAttemptBlobs(world.store, envelopeId).map((record) => record.fencingToken);
    assert.deepEqual(
      [currentRecorded, currentAnchor !== null, tokens],
      [true, true, [current.fencingToken]],
      `${owner} attempt ${current.fencingToken}: recordAttemptBlob ${currentRecorded}, writeSealAnchor ${JSON.stringify(currentAnchor)}, attempt records of attempts ${JSON.stringify(tokens)}`,
    );
  } finally {
    world.close();
  }
});
