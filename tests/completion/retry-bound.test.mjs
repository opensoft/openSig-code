// SPDX-License-Identifier: Apache-2.0
//
// The bound on operator retries (the T038 correction; A-010 request #80 (1),
// row RETRY-BOUND; FEN-03, extended). An operator retry writes the job and its
// `envelope.finalization_retried` event only on an actual transition: from
// `failed`, at the attempt limit (the raise), or from `retryable` with a later
// retry_at (brought forward to now). A retry that finds the job already
// `retryable` and due is an accepted no-op: 202 with the envelope as it
// stands, its Idempotency-Key recording that answer for replay, no job write
// and no audit event. So each attempt is followed by at most one retried
// event, and finalization writes at most three events per attempt plus two.
// The three sequences are the bounded probe's (T9 at 7a11d08, where three
// fresh keys wrote 1, 2 and 3 retried events); the clock moves 1 s before each
// step, as it did there.
//
// The retry's instant (C2; request #82): the retry reads its clock inside its
// BEGIN IMMEDIATE transaction, and its instant is max(clock, job.updated_at),
// so a retry whose clock is behind the job's last write (a clock stepped back,
// a stale reading, another process's skew) finds a transitioned job already
// due and writes nothing, and no job instant moves backwards. A retry exactly
// at retry_at is a no-op (N2). The two-connection case uses three real
// connections to the same database file; its one barrier is the write lock,
// bounded by the third connection's busy timeout. Every clock call records
// whether its connection was inside a transaction. Synthetic data, injected
// clocks.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { FINALIZATION_RETRIED, retryFinalization } from '../../src/domain/finalization/index.ts';
import { AuditWriter } from '../../src/storage/audit/index.ts';
import { openDatabase, StorageBusyError } from '../../src/storage/db/index.ts';
import { retryDelayMs } from '../../src/storage/repositories/jobs.ts';
import { eventsOf, fail, lease, retry } from './support/steps.mjs';
import { makeWorld, RESERVED_VERSION, seedFinalizing, sha256 } from './support/world.mjs';

const STEP_MS = 1_000;
/** The third connection's busy timeout: the bound on the lock barrier. */
const BARRIER_MS = 100;
/** The bound this file states for that barrier, busy timeout and scheduling included. */
const BARRIER_BOUND_MS = 5_000;

/**
 * An operator retry through the domain operation on `db` (the world's connection by default), with its own
 * clock. Each clock call first records the connection and whether it was inside a transaction.
 */
function retryOn(world, { db = world.db, audit = world.audit, connection = 1, envelopeId, key, clock, calls }) {
  return retryFinalization(
    db,
    audit,
    { tenantId: world.tenantId, envelopeId, actor: { kind: 'human-operator', ref: 'admin-1' }, idempotency: { key, request: { expected_version: RESERVED_VERSION } } },
    {
      clock: () => {
        calls.push({ connection, inTransaction: db.inTransaction });
        return clock();
      },
    },
  );
}

/** A job row's two instants, for the no-backwards checks. */
const instants = (state) => `updated_at ${state.job.updated_at}, retry_at ${state.job.retry_at}`;

/** The job row and the tenant's whole audit chain, as stored. */
function stored(world, envelopeId) {
  return {
    job: world.store.get('signing_jobs', { envelope_id: envelopeId }),
    chain: world.store.list('audit_events', {}, { orderBy: [['seq', 'asc']] }),
  };
}

/** The compared values in one line, for assertion messages (request #70 (6)). */
function shown({ job, chain }) {
  return `job ${job.status} ${job.attempt_count}/${job.max_attempts} retry_at ${job.retry_at} v${job.version}; chain ${chain.length} event(s), last seq ${chain.at(-1)?.seq}`;
}

const retriedCount = (world, envelopeId) => eventsOf(world, envelopeId, FINALIZATION_RETRIED).length;
const keyFor = (label, envelopeId) => `fen03-bound-${label}-${envelopeId}`.slice(0, 128);
const bytesShown = (result) => `${result.bytes.length} bytes, sha256 ${sha256(result.bytes)}`;

const SEQUENCES = [
  { name: 'a: a non-retryable failure', maxAttempts: 5, retryable: false, errorCode: 'verification_refused.integrity', ended: 'failed', raisedTo: 5 },
  { name: 'b: a retryable failure, retry_at 30 s ahead', maxAttempts: 5, retryable: true, errorCode: 'verification_timeout.cap', ended: 'retryable', raisedTo: 5 },
  { name: 'c: a failure at the attempt limit', maxAttempts: 1, retryable: true, errorCode: 'verification_timeout.cap', ended: 'failed', raisedTo: 2 },
];

test('[FEN-03] each of the probe’s three sequences writes exactly one retried event: the first fresh key transitions; the second and third answer 202 with the envelope as it stands and leave the job row and the audit chain byte-identical; a replay of a no-op key answers the same 202 and writes nothing', () => {
  for (const sequence of SEQUENCES) {
    const world = makeWorld();
    try {
      const { envelopeId } = seedFinalizing(world, { maxAttempts: sequence.maxAttempts });
      const grant = lease(world, envelopeId, 'runner-a');
      world.clock.advance(STEP_MS);
      const ended = fail(world, grant, sequence.retryable, sequence.errorCode);
      assert.equal(ended, sequence.ended, `(${sequence.name}) attempt 1 ended ${ended}`);
      if (sequence.ended === 'retryable') {
        const later = new Date(world.clock.now().getTime() + retryDelayMs(1)).toISOString();
        const retryAt = stored(world, envelopeId).job.retry_at;
        assert.equal(retryAt, later, `(${sequence.name}) premise: retry_at ${retryAt} is ${retryDelayMs(1)} ms ahead (${later})`);
      }

      world.clock.advance(STEP_MS);
      const first = retry(world, envelopeId, RESERVED_VERSION, keyFor('k1', envelopeId));
      assert.deepEqual([first.status, first.replayed], [202, false], `(${sequence.name}) k1 answered ${first.status}, replayed ${first.replayed}`);
      const afterFirst = stored(world, envelopeId);
      assert.deepEqual(
        [afterFirst.job.status, afterFirst.job.retry_at, afterFirst.job.attempt_count, afterFirst.job.max_attempts],
        ['retryable', world.clock.iso(), 1, sequence.raisedTo],
        `(${sequence.name}) k1 made the transition: ${shown(afterFirst)}`,
      );
      const afterK1 = retriedCount(world, envelopeId);
      assert.equal(afterK1, 1, `(${sequence.name}) retried events after k1: ${afterK1}`);

      const noOps = [];
      for (const label of ['k2', 'k3']) {
        world.clock.advance(STEP_MS);
        const result = retry(world, envelopeId, RESERVED_VERSION, keyFor(label, envelopeId));
        noOps.push(result);
        assert.deepEqual([result.status, result.replayed], [202, false], `(${sequence.name}) ${label} answered ${result.status}, replayed ${result.replayed}`);
        assert.ok(result.bytes.equals(first.bytes), `(${sequence.name}) ${label} answers the envelope as it stands: ${bytesShown(result)}; after k1 ${bytesShown(first)}`);
        const now = stored(world, envelopeId);
        assert.deepEqual(now, afterFirst, `(${sequence.name}) ${label} wrote no job change and no audit event: after k1 [${shown(afterFirst)}], after ${label} [${shown(now)}]`);
      }
      const events = retriedCount(world, envelopeId);
      assert.equal(events, 1, `(${sequence.name}) three fresh keys wrote ${events} retried event(s); at 7a11d08 the probe saw 3`);

      world.clock.advance(STEP_MS);
      const records = world.store.count('idempotency_records');
      const replay = retry(world, envelopeId, RESERVED_VERSION, keyFor('k2', envelopeId));
      assert.deepEqual([replay.status, replay.replayed], [202, true], `(${sequence.name}) the replay of k2 answered ${replay.status}, replayed ${replay.replayed}`);
      assert.ok(replay.bytes.equals(noOps[0].bytes), `(${sequence.name}) the replay is k2's answer: ${bytesShown(replay)}; recorded ${bytesShown(noOps[0])}`);
      const afterReplay = stored(world, envelopeId);
      assert.deepEqual(afterReplay, afterFirst, `(${sequence.name}) the replay wrote nothing: [${shown(afterReplay)}]`);
      const recordsAfter = world.store.count('idempotency_records');
      assert.deepEqual([records, recordsAfter], [3, 3], `(${sequence.name}) each fresh key recorded its answer and the replay none: ${records}, then ${recordsAfter} record(s)`);

      // The no-ops left the job due: the next attempt is granted at once.
      const next = lease(world, envelopeId, 'runner-b');
      assert.equal(next.fencingToken, 2, `(${sequence.name}) the next attempt holds attempt ${next.fencingToken}`);
    } finally {
      world.close();
    }
  }
});

test('[FEN-03] N = 3 attempts, each failed so that its first retry transitions (from failed, brought forward, raised at the limit) and followed by M = 3 more fresh-key retries, write exactly N retried events and at most 3N + 2 finalization events', () => {
  const N = 3;
  const M = 3;
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world, { maxAttempts: N });
    const baseline = world.store.list('audit_events', { envelope_id: envelopeId }).length;
    const attempts = [
      { retryable: false, errorCode: 'verification_refused.integrity', ended: 'failed', transition: 'from failed' },
      { retryable: true, errorCode: 'verification_timeout.cap', ended: 'retryable', transition: 'brought forward' },
      { retryable: true, errorCode: 'verification_timeout.cap', ended: 'failed', transition: 'raised at the limit' },
    ];
    const statuses = [];
    let keys = 0;
    attempts.forEach((attempt, index) => {
      const grant = lease(world, envelopeId, `runner-${index + 1}`);
      assert.equal(grant.fencingToken, index + 1, `attempt ${index + 1} holds attempt ${grant.fencingToken}`);
      world.clock.advance(STEP_MS);
      const ended = fail(world, grant, attempt.retryable, attempt.errorCode);
      assert.equal(ended, attempt.ended, `attempt ${index + 1} ended ${ended}`);
      for (let retries = 0; retries <= M; retries += 1) {
        world.clock.advance(STEP_MS);
        keys += 1;
        statuses.push(retry(world, envelopeId, RESERVED_VERSION, keyFor(`n${keys}`, envelopeId)).status);
      }
      const count = retriedCount(world, envelopeId);
      assert.equal(count, index + 1, `after attempt ${index + 1} (${attempt.transition}) and ${M + 1} fresh-key retries: ${count} retried event(s)`);
    });
    const distinct = [...new Set(statuses)];
    assert.deepEqual(distinct, [202], `all ${statuses.length} retries answered 202 (statuses ${JSON.stringify(statuses)})`);
    const job = world.store.get('signing_jobs', { envelope_id: envelopeId });
    assert.deepEqual([job.status, job.attempt_count, job.max_attempts], ['retryable', N, N + 1], `job ${job.status} ${job.attempt_count}/${job.max_attempts}`);
    const retried = retriedCount(world, envelopeId);
    assert.equal(retried, N, `${N} attempts and ${statuses.length} retries wrote ${retried} retried event(s)`);
    const finalization = world.store.list('audit_events', { envelope_id: envelopeId }).length - baseline;
    assert.ok(finalization <= 3 * N + 2, `${N} attempts wrote ${finalization} finalization event(s); the bound 3N + 2 is ${3 * N + 2}`);
  } finally {
    world.close();
  }
});

test('[FEN-03] a retry whose clock is behind the job’s last write cannot transition again: from failed (then at t1 − 1 ms and t1 − 1 s) and from retryable (brought forward, then 1 s earlier) one retried event each, the earlier retries byte-identical; a first retry behind the last write writes retry_at = updated_at = that write; no job instant moves backwards', () => {
  const sequences = [
    { name: 'from failed', retryable: false, errorCode: 'verification_refused.integrity', earlier: [-1, -1_000] },
    { name: 'from retryable', retryable: true, errorCode: 'verification_timeout.cap', earlier: [-1_000] },
  ];
  for (const sequence of sequences) {
    const world = makeWorld();
    try {
      const { envelopeId } = seedFinalizing(world);
      const grant = lease(world, envelopeId, 'runner-a');
      world.clock.advance(STEP_MS);
      const ended = fail(world, grant, sequence.retryable, sequence.errorCode);
      assert.equal(ended, sequence.retryable ? 'retryable' : 'failed', `(${sequence.name}) attempt 1 ended ${ended}`);
      world.clock.advance(STEP_MS);
      const t1 = world.clock.iso();
      const calls = [];
      const first = retryOn(world, { envelopeId, key: keyFor('t1', envelopeId), clock: () => new Date(t1), calls });
      const afterFirst = stored(world, envelopeId);
      assert.deepEqual(
        [first.status, afterFirst.job.status, afterFirst.job.retry_at, afterFirst.job.updated_at],
        [202, 'retryable', t1, t1],
        `(${sequence.name}) the retry at ${t1} transitioned: ${first.status}, ${shown(afterFirst)}`,
      );
      for (const step of sequence.earlier) {
        const instant = new Date(Date.parse(t1) + step).toISOString();
        const result = retryOn(world, { envelopeId, key: keyFor(`t1${step}`, envelopeId), clock: () => new Date(instant), calls });
        assert.deepEqual([result.status, result.replayed], [202, false], `(${sequence.name}) the retry at ${instant} answered ${result.status}, replayed ${result.replayed}`);
        const now = stored(world, envelopeId);
        assert.deepEqual(now, afterFirst, `(${sequence.name}) a retry at ${instant}, ${-step} ms before ${t1}, wrote nothing: after ${t1} [${shown(afterFirst)}], after ${instant} [${shown(now)}]`);
      }
      const events = retriedCount(world, envelopeId);
      assert.equal(events, 1, `(${sequence.name}) ${1 + sequence.earlier.length} retries, ${sequence.earlier.length} of them behind ${t1}, wrote ${events} retried event(s)`);
      const outside = calls.filter((call) => !call.inTransaction);
      assert.equal(outside.length, 0, `(${sequence.name}) every clock call inside the transaction: ${JSON.stringify(calls)}`);
    } finally {
      world.close();
    }
  }

  // The first retry is itself behind the job's last write: its instant is that write, never earlier.
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    world.clock.advance(STEP_MS);
    fail(world, grant, false, 'verification_refused.integrity');
    const before = stored(world, envelopeId);
    const lastWrite = before.job.updated_at;
    const behind = new Date(Date.parse(lastWrite) - 1_000).toISOString();
    const result = retryOn(world, { envelopeId, key: keyFor('behind', envelopeId), clock: () => new Date(behind), calls: [] });
    const after = stored(world, envelopeId);
    assert.deepEqual(
      [result.status, after.job.status, after.job.retry_at, after.job.updated_at],
      [202, 'retryable', lastWrite, lastWrite],
      `a retry with the clock at ${behind}, 1 s behind the last write ${lastWrite}, writes the last write's instant: ${instants(after)}`,
    );
    assert.ok(after.job.updated_at >= before.job.updated_at && after.job.retry_at >= before.job.updated_at, `no job instant moved backwards: before ${instants(before)}, after ${instants(after)}`);
    const events = retriedCount(world, envelopeId);
    assert.equal(events, 1, `retried events ${events}`);
    // No transition is lost: the job is due at the last write's instant.
    const next = lease(world, envelopeId, 'runner-b');
    assert.equal(next.fencingToken, 2, `the next attempt holds attempt ${next.fencingToken} at ${world.clock.iso()}`);
  } finally {
    world.close();
  }
});

test('[FEN-03] a retry exactly at the stored retry_at is a no-op (N2): 202, no job write, no retried event; 1 ms earlier it brings retry_at forward', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-a');
    world.clock.advance(STEP_MS);
    fail(world, grant, true, 'verification_timeout.cap');
    const before = stored(world, envelopeId);
    const retryAt = before.job.retry_at;
    const equal = retryOn(world, { envelopeId, key: keyFor('equal', envelopeId), clock: () => new Date(retryAt), calls: [] });
    const afterEqual = stored(world, envelopeId);
    assert.equal(equal.status, 202, `the retry at exactly ${retryAt} answered ${equal.status}`);
    assert.deepEqual(afterEqual, before, `a retry at exactly retry_at ${retryAt} wrote nothing: before [${shown(before)}], after [${shown(afterEqual)}]`);
    const none = retriedCount(world, envelopeId);
    assert.equal(none, 0, `retried events after the equal-instant retry: ${none}`);

    const earlier = new Date(Date.parse(retryAt) - 1).toISOString();
    const control = retryOn(world, { envelopeId, key: keyFor('earlier', envelopeId), clock: () => new Date(earlier), calls: [] });
    const afterControl = stored(world, envelopeId);
    assert.deepEqual(
      [control.status, afterControl.job.retry_at, afterControl.job.updated_at, retriedCount(world, envelopeId)],
      [202, earlier, earlier, 1],
      `1 ms earlier, at ${earlier}, the retry brings retry_at forward: ${shown(afterControl)}`,
    );
  } finally {
    world.close();
  }
});

test('[FEN-03] two connections: a retry committed at tB on one connection and then a retry on another whose clock reads earlier write one retried event in all; every clock call happens inside its transaction, where no other connection can commit (a lock barrier bounded by a 100 ms busy timeout)', () => {
  const world = makeWorld();
  const second = openDatabase({ path: world.dbPath, busyTimeoutMs: 5_000 });
  const third = openDatabase({ path: world.dbPath, busyTimeoutMs: BARRIER_MS });
  try {
    const secondAudit = new AuditWriter(second, { clock: world.clock.now });
    const thirdAudit = new AuditWriter(third, { clock: world.clock.now });

    // (1) Connection 1 commits a transition at tB; connection 2 then retries with a reading 1 s earlier.
    for (const sequence of [
      { name: 'from failed', retryable: false, errorCode: 'verification_refused.integrity' },
      { name: 'from retryable', retryable: true, errorCode: 'verification_timeout.cap' },
    ]) {
      const { envelopeId } = seedFinalizing(world);
      const grant = lease(world, envelopeId, `runner-${sequence.retryable ? 'b' : 'a'}`);
      world.clock.advance(STEP_MS);
      fail(world, grant, sequence.retryable, sequence.errorCode);
      world.clock.advance(STEP_MS);
      const tB = world.clock.iso();
      const tA = new Date(Date.parse(tB) - 1_000).toISOString();
      const calls = [];
      const committed = retryOn(world, { connection: 1, envelopeId, key: keyFor('conn1', envelopeId), clock: () => new Date(tB), calls });
      const afterB = stored(world, envelopeId);
      assert.deepEqual(
        [committed.status, afterB.job.retry_at, afterB.job.updated_at],
        [202, tB, tB],
        `(${sequence.name}) connection 1 transitioned at ${tB}: ${committed.status}, ${instants(afterB)}`,
      );
      const late = retryOn(world, { db: second, audit: secondAudit, connection: 2, envelopeId, key: keyFor('conn2', envelopeId), clock: () => new Date(tA), calls });
      assert.equal(late.status, 202, `(${sequence.name}) connection 2, reading ${tA}, answered ${late.status}`);
      assert.ok(late.bytes.equals(committed.bytes), `(${sequence.name}) connection 2 answers the envelope as it stands: ${bytesShown(late)}; connection 1 ${bytesShown(committed)}`);
      const afterA = stored(world, envelopeId);
      assert.deepEqual(afterA, afterB, `(${sequence.name}) connection 2's retry at ${tA}, behind tB ${tB}, wrote nothing: [${shown(afterA)}]`);
      const events = retriedCount(world, envelopeId);
      assert.equal(events, 1, `(${sequence.name}) two connections wrote ${events} retried event(s)`);
      assert.deepEqual(
        calls.map((call) => [call.connection, call.inTransaction]),
        [
          [1, true],
          [2, true],
        ],
        `(${sequence.name}) clock calls: ${JSON.stringify(calls)}`,
      );
    }

    // (2) While connection 2 reads its clock inside its transaction, connection 3 cannot commit: its BEGIN IMMEDIATE
    // waits its 100 ms busy timeout and is refused, so no commit falls between the reading and the job read.
    const { envelopeId } = seedFinalizing(world);
    const grant = lease(world, envelopeId, 'runner-c');
    world.clock.advance(STEP_MS);
    fail(world, grant, false, 'verification_refused.integrity');
    const tA = world.clock.iso();
    const tB = new Date(Date.parse(tA) + 1_000).toISOString();
    const calls = [];
    const barrier = [];
    const held = retryOn(world, {
      db: second,
      audit: secondAudit,
      connection: 2,
      envelopeId,
      key: keyFor('held', envelopeId),
      calls,
      clock: () => {
        const started = performance.now();
        try {
          retryOn(world, { db: third, audit: thirdAudit, connection: 3, envelopeId, key: keyFor('barred', envelopeId), clock: () => new Date(tB), calls });
          barrier.push({ outcome: 'committed', ms: Math.round(performance.now() - started) });
        } catch (error) {
          barrier.push({ outcome: error instanceof StorageBusyError ? 'busy' : `${error?.name}`, ms: Math.round(performance.now() - started) });
        }
        return new Date(tA);
      },
    });
    const after = stored(world, envelopeId);
    assert.deepEqual(
      [barrier.length, barrier[0]?.outcome, barrier[0]?.ms < BARRIER_BOUND_MS],
      [1, 'busy', true],
      `connection 3 during connection 2's clock reading: ${JSON.stringify(barrier)} (busy timeout ${BARRIER_MS} ms, bound ${BARRIER_BOUND_MS} ms)`,
    );
    assert.deepEqual(
      [held.status, after.job.status, after.job.retry_at, retriedCount(world, envelopeId)],
      [202, 'retryable', tA, 1],
      `connection 2 transitioned at ${tA}: ${held.status}, ${shown(after)}`,
    );
    assert.deepEqual(
      calls.map((call) => [call.connection, call.inTransaction]),
      [[2, true]],
      `clock calls: ${JSON.stringify(calls)} (connection 3 never reached its clock)`,
    );
  } finally {
    third.close();
    second.close();
    world.close();
  }
});
