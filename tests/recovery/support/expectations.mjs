// SPDX-License-Identifier: Apache-2.0
//
// T015's stable expectations under request #59's lease and fence rules, bound to T038's code at
// 00b260f, as reusable assertions over before/after snapshots (world.snapshot: a row count and a
// content digest per table). Messages carry both sides (request #70 (6)).
// - Strict expiry: a runner one millisecond before lease_expires_at finds no expired lease
//   (listExpiredLeases, src/storage/repositories/jobs.ts:425-431; reclaimExpiredLease :337-356
//   needs lease_expires_at <= now) and nothing claimable, so it writes nothing.
// - A stale holder writes nothing once released: each of its writes is fenced on its lease
//   (leaseFence :225-233; writeSealAnchor, recordBlob and the checkpoint check leaseHeld,
//   transitions.ts:78-113; publish's completeJob, publish.ts:136), and a lost attempt records no
//   failure (finalize.ts:210-211).
// - void, decline and expiry against a running finalization are refused and write nothing
//   (data-model.md § Transitions and races, item 1); the void and the decline with 409
//   state_conflict (request #79 (5)).
// - An operator retry while running is 409 finalization_not_retryable with no ceiling detail and
//   writes nothing (retryJob :386-413; retryFinalization, retry.ts:131-137).
// - From failed at the limit a retry raises max_attempts by exactly one, never writes
//   attempt_count, and is audited once with envelope_version, attempt_count and max_attempts
//   (transition 'raised'; retry.ts:138-147; request #61 (6)).
// - A retry that finds the job already retryable and due answers 202 and writes neither the job
//   nor an audit event; only its answer is recorded under its key (retryJob 'unchanged',
//   jobs.ts:403; its instant is max(clock, updated_at), request #82; request #80 (1), row RETRY-BOUND).

import assert from 'node:assert/strict';

const differences = (before, after) =>
  Object.keys({ ...before, ...after })
    .filter((table) => before[table] !== after[table])
    .map((table) => `${table}: ${before[table]} -> ${after[table]}`)
    .join('; ') || 'none';

/** Nothing written between two snapshots. */
export function expectUnchanged(before, after, label) {
  assert.deepEqual(after, before, `${label}: writes nothing (changed: ${differences(before, after)})`);
}

/** A stale holder writes nothing at all after its release: no table changes, attempt records included. */
export function expectStaleHolderWroteNothing(before, after, staleToken) {
  expectUnchanged(before, after, `the stale holder (attempt ${staleToken}) once released`);
}

/** A refused racer (T010's race child result, or a retry FinalizationError) and nothing written by it. */
export function expectRacerRefused(result, expected, before, after, label) {
  const seen = { status: result.status, code: result.code ?? null, expired: result.expired ?? null };
  if (expected.code !== undefined) assert.deepEqual([seen.status, seen.code], [expected.status, expected.code], `${label}: refused ${expected.status} ${expected.code} (got ${JSON.stringify(seen)})`);
  else assert.equal(seen.status, expected.status, `${label}: answers ${expected.status} (got ${JSON.stringify(seen)})`);
  if (expected.expired !== undefined) assert.equal(seen.expired, expected.expired, `${label}: expires ${expected.expired} envelopes (got ${JSON.stringify(seen)})`);
  expectUnchanged(before, after, label);
}

/** The retry refusal while running: status, code, no ceiling detail. */
export function expectRetryRefusedWhileRunning(error, before, after) {
  const seen = { name: error?.name, status: error?.status, code: error?.code, details: error?.details ?? null };
  assert.deepEqual([seen.name, seen.status, seen.code], ['FinalizationError', 409, 'finalization_not_retryable'], `an operator retry while running is 409 finalization_not_retryable (got ${JSON.stringify(seen)})`);
  assert.ok(!(seen.details ?? []).some((detail) => detail.code === 'attempt_ceiling'), `a wrong state is told apart from the ceiling (details ${JSON.stringify(seen.details)})`);
  expectUnchanged(before, after, 'the refused operator retry');
}

/** From failed at the limit: +1, attempt_count unwritten, one audited retry with the three metadata keys. */
export function expectRetryRaisesByOne(result, jobBefore, jobAfter, retried) {
  const job = (row) => `${row.status} ${row.attempt_count}/${row.max_attempts} retry ${row.retry_at}`;
  assert.deepEqual([result.status, result.replayed], [202, false], `the retry from failed is scheduled (got ${result.status}, replayed ${result.replayed})`);
  assert.deepEqual(
    { from: jobBefore.status, attempts: Number(jobAfter.attempt_count), max: Number(jobAfter.max_attempts), status: jobAfter.status },
    { from: 'failed', attempts: Number(jobBefore.attempt_count), max: Number(jobBefore.attempt_count) + 1, status: 'retryable' },
    `max_attempts rises by exactly one and attempt_count is never written (before ${job(jobBefore)}; after ${job(jobAfter)})`,
  );
  assert.equal(retried.length, 1, `one envelope.finalization_retried audit event (found ${retried.length})`);
  const [event] = retried;
  const metadata = JSON.parse(String(event.metadata_json));
  assert.deepEqual(
    { actor: event.actor_kind, keys: Object.keys(metadata).sort(), attempt_count: metadata.attempt_count, max_attempts: metadata.max_attempts },
    { actor: 'human-operator', keys: ['attempt_count', 'envelope_version', 'max_attempts'], attempt_count: Number(jobAfter.attempt_count), max_attempts: Number(jobAfter.max_attempts) },
    `the retry is audited with the operator as actor and request #61 (6)'s keys (got ${event.actor_kind} ${JSON.stringify(metadata)})`,
  );
}

/** RETRY-BOUND: a retry on a job already retryable and due is an accepted no-op (202), recorded only under its key. */
export function expectRetryNoOp(result, before, after, retried) {
  assert.deepEqual([result.status, result.replayed], [202, false], `a retry on a job already retryable and due answers 202 afresh (got ${result.status}, replayed ${result.replayed})`);
  const rows = (entry) => Number.parseInt(String(entry), 10);
  const { idempotency_records: keyBefore, ...restBefore } = before;
  const { idempotency_records: keyAfter, ...restAfter } = after;
  expectUnchanged(restBefore, restAfter, 'the no-op retry (job, audit chain and every other table)');
  assert.equal(rows(keyAfter), rows(keyBefore) + 1, `only its answer is recorded under its key (idempotency_records: ${keyBefore} -> ${keyAfter})`);
  assert.equal(retried.length, 1, `still exactly one envelope.finalization_retried event (found ${retried.length})`);
}
