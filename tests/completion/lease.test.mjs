// SPDX-License-Identifier: Apache-2.0
//
// The finalization lease (T038; data-model.md § Entities, SigningJob, and
// § Transitions and races, item 2; migration 0004). A grant takes
// attempt_count + 1 as the fencing token; renewal and failure recording run
// under the lease predicate; an expired lease is reclaimed with its token
// kept, after which the old holder can write nothing; the keeper aborts its
// signal on loss. Synthetic data and an injected clock only.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { LeaseKeeper, LeaseLost } from '../../src/domain/finalization/index.ts';
import {
  DEFAULT_LEASE_MS,
  grantLease,
  LEASE_EXPIRED_ERROR_CODE,
  reclaimExpiredLease,
  recordAttemptFailure,
  renewLease,
  retryDelayMs,
} from '../../src/storage/repositories/jobs.ts';
import { assertUnchanged, holderOf, lease } from './support/steps.mjs';
import { makeClock, makeWorld, seedFinalizing, snapshot } from './support/world.mjs';

test('[FEN-01] a lease is granted once, renewed only under its fence, and after expiry and reclaim its holder writes nothing', () => {
  const world = makeWorld();
  const tx = (fn) => world.db.transaction(fn);
  try {
    const { envelopeId } = seedFinalizing(world, { maxAttempts: 3 });
    const grant = lease(world, envelopeId, 'runner-a');
    assert.equal(grant.fencingToken, 1, `the first grant's attempt number is attempt_count at the grant (got ${grant.fencingToken})`);
    assert.equal(grant.attemptCount, 1, `attempt_count ${grant.attemptCount}`);
    const expectedExpiry = new Date(world.clock.now().getTime() + DEFAULT_LEASE_MS).toISOString();
    assert.equal(grant.leaseExpiresAt, expectedExpiry, `lease_expires_at ${grant.leaseExpiresAt}, expected ${expectedExpiry}`);
    const second = tx(() => grantLease(world.store, envelopeId, { owner: 'runner-b', now: world.clock.now() }));
    assert.equal(second, null, `a running job is not claimable (got ${JSON.stringify(second)})`);

    world.clock.advance(60_000);
    const renewed = tx(() => renewLease(world.store, holderOf(grant), { now: world.clock.now() }));
    const renewedExpected = new Date(world.clock.now().getTime() + DEFAULT_LEASE_MS).toISOString();
    assert.equal(renewed, renewedExpected, `renewed to ${renewed}, expected ${renewedExpected}`);
    const held = snapshot(world, envelopeId);
    assert.equal(held.job.lease_expires_at, renewed, `stored ${held.job.lease_expires_at}, renewal ${renewed}`);
    const wrongOwner = tx(() => renewLease(world.store, { ...holderOf(grant), leaseOwner: 'runner-x' }, { now: world.clock.now() }));
    assert.equal(wrongOwner, null, `owner runner-x renewed to ${wrongOwner}`);
    const wrongAttempt = tx(() => renewLease(world.store, { ...holderOf(grant), fencingToken: 2 }, { now: world.clock.now() }));
    assert.equal(wrongAttempt, null, `attempt 2 renewed to ${wrongAttempt}`);
    assertUnchanged(world, envelopeId, held, 'a renewal outside the fence writes nothing');

    world.clock.advance(DEFAULT_LEASE_MS + 1);
    const expired = snapshot(world, envelopeId);
    const lateRenewal = tx(() => renewLease(world.store, holderOf(grant), { now: world.clock.now() }));
    assert.equal(lateRenewal, null, `an expired lease (${expired.job.lease_expires_at} at ${world.clock.iso()}) is not renewed (got ${lateRenewal})`);
    const lateFailure = tx(() => recordAttemptFailure(world.store, holderOf(grant), { now: world.clock.now(), retryable: true, errorCode: 'seal_failed.aborted' }));
    assert.equal(lateFailure, 'lease-lost', `the expired holder's failure: ${lateFailure}`);
    assertUnchanged(world, envelopeId, expired, 'the expired holder recorded nothing');

    const reclaimOutcome = tx(() => reclaimExpiredLease(world.store, envelopeId, world.clock.now()));
    assert.equal(reclaimOutcome, 'retryable', `reclaim: ${reclaimOutcome}`);
    const reclaimed = snapshot(world, envelopeId).job;
    const retryAt = new Date(world.clock.now().getTime() + retryDelayMs(1)).toISOString();
    assert.deepEqual(
      [reclaimed.status, reclaimed.fencing_token, reclaimed.attempt_count, reclaimed.lease_owner, reclaimed.last_error_code, reclaimed.retry_at],
      ['retryable', 1, 1, null, LEASE_EXPIRED_ERROR_CODE, retryAt],
      `reclaimed job: ${reclaimed.status}, attempt ${reclaimed.fencing_token} kept, attempt_count ${reclaimed.attempt_count}, owner ${reclaimed.lease_owner}, ${reclaimed.last_error_code}, retry_at ${reclaimed.retry_at} (expected ${retryAt})`,
    );

    const lost = snapshot(world, envelopeId);
    const lostRenewal = tx(() => renewLease(world.store, holderOf(grant), { now: world.clock.now() }));
    assert.equal(lostRenewal, null, `the reclaimed holder renewed to ${lostRenewal}`);
    const lostFailure = tx(() => recordAttemptFailure(world.store, holderOf(grant), { now: world.clock.now(), retryable: false, errorCode: 'seal_failed.aborted' }));
    assert.equal(lostFailure, 'lease-lost', `the reclaimed holder's failure: ${lostFailure}`);
    assertUnchanged(world, envelopeId, lost, 'the reclaimed holder writes nothing');

    const early = tx(() => grantLease(world.store, envelopeId, { owner: 'runner-b', now: world.clock.now() }));
    assert.equal(early, null, `not due before retry_at ${reclaimed.retry_at} (now ${world.clock.iso()}; got ${JSON.stringify(early)})`);
    world.clock.advance(retryDelayMs(1));
    const next = lease(world, envelopeId, 'runner-b');
    assert.equal(next.fencingToken, 2, `the next grant's attempt number is ${next.fencingToken}`);
  } finally {
    world.close();
  }
});

function fakeTimers() {
  const scheduled = [];
  return {
    setTimeout(callback, ms) {
      const entry = { callback, ms, done: false };
      scheduled.push(entry);
      return entry;
    },
    clearTimeout(entry) {
      entry.done = true;
    },
    last: () => scheduled.at(-1),
    live: () => scheduled.filter((entry) => !entry.done).length,
    fire() {
      const entry = scheduled.at(-1);
      assert.ok(entry !== undefined && !entry.done, `a renewal is scheduled (${scheduled.length} scheduled, last done ${entry?.done})`);
      entry.done = true;
      entry.callback();
    },
  };
}

test('[FEN-01] the lease keeper renews, survives a busy renewal before its deadline, and aborts its signal on loss', () => {
  const leaseMs = 120_000;
  const clock = makeClock();
  const inFuture = (ms) => new Date(clock.now().getTime() + ms).toISOString();

  // Deadline: no successful renewal before expiry minus the margin.
  let renew = () => inFuture(leaseMs);
  const timers = fakeTimers();
  const keeper = new LeaseKeeper({ renew: () => renew(), leaseExpiresAt: inFuture(leaseMs), leaseMs, clock: clock.now, timers });
  keeper.start();
  assert.equal(timers.last().ms, leaseMs / 3, `renewal interval ${timers.last().ms} ms`);
  clock.advance(leaseMs / 3);
  timers.fire();
  keeper.checkHeld();
  assert.equal(keeper.signal.aborted, false, `aborted ${keeper.signal.aborted} after a good renewal`);
  renew = () => {
    throw new Error('synthetic busy');
  };
  clock.advance(leaseMs / 3);
  timers.fire();
  keeper.checkHeld();
  assert.equal(keeper.signal.aborted, false, `a renewal that throws is not a loss before the deadline (aborted ${keeper.signal.aborted})`);
  clock.advance(leaseMs - leaseMs / 3 + 1);
  timers.fire();
  assert.equal(keeper.signal.aborted, true, `aborted ${keeper.signal.aborted} past the deadline`);
  assert.ok(keeper.signal.reason instanceof LeaseLost, `the abort reason is ${keeper.signal.reason?.name}`);
  assert.equal(keeper.lossCause, 'deadline', `loss cause ${keeper.lossCause}`);
  assert.throws(() => keeper.checkHeld(), (error) => error instanceof LeaseLost && error.lossCause === 'deadline');
  assert.equal(timers.live(), 0, `${timers.live()} renewals scheduled after the loss`);

  // Fenced: the renewal matched no row.
  const fencedTimers = fakeTimers();
  const fenced = new LeaseKeeper({ renew: () => null, leaseExpiresAt: inFuture(leaseMs), leaseMs, clock: clock.now, timers: fencedTimers });
  fenced.start();
  clock.advance(leaseMs / 3);
  fencedTimers.fire();
  assert.equal(fenced.signal.aborted, true, `aborted ${fenced.signal.aborted} when fenced`);
  assert.equal(fenced.lossCause, 'fenced', `loss cause ${fenced.lossCause}`);
  assert.throws(() => fenced.checkHeld(), (error) => error instanceof LeaseLost && error.lossCause === 'fenced');
  assert.equal(fencedTimers.live(), 0, `${fencedTimers.live()} renewals scheduled after the loss`);
});
