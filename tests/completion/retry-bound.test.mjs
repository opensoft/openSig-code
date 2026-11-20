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
// step, as it did there. Synthetic data, injected clock.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { FINALIZATION_RETRIED } from '../../src/domain/finalization/index.ts';
import { retryDelayMs } from '../../src/storage/repositories/jobs.ts';
import { eventsOf, fail, lease, retry } from './support/steps.mjs';
import { makeWorld, RESERVED_VERSION, seedFinalizing, sha256 } from './support/world.mjs';

const STEP_MS = 1_000;

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
