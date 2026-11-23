// SPDX-License-Identifier: Apache-2.0
//
// T015 (SC-003): the case catalog of `recovery`, as ratified in plan.md § Case catalogs (SC-003)
// and the T015 line (A-010, request #61, adopting the preparation's proposal P1).
// - SC003-01..SC003-08: a SIGKILL at each phase, in order. A fresh runner reclaims at the strict
//   lease expiry and the job is finalized exactly once; 01..07 take one more attempt (07 rolls
//   back an uncommitted publish and reuses the anchor and the checkpoint); 08 takes none.
// - SC003-09..SC003-16: a barrier at each phase, in order: the stale-lease races. A probe 1 ms
//   before the expiry reclaims nothing; a second runner reclaims at the expiry. In 09..14 the
//   released holder writes nothing; in 15 the holder keeps the publish write lock, its commit
//   stands, and the second runner queues and writes nothing; in 16 the second runner finds the
//   job succeeded.
// - SC003-17..SC003-20: void at compose, decline at seal, expiry at store PDF and an operator
//   retry at store evidence, each against a running finalization: refused, nothing written. The
//   void and the decline carry the envelope's current version on a live session and assert 409
//   with code state_conflict (request #79 (5)).
// - Extra case IDs, never required: REC-01 (the hook inert without the flag) and REC-02 (the
//   attempt limit; with request #80 (1), a second retry before the next attempt is a no-op).
// Recovery is two runner children (request #79 (1)): B reclaims at the strict expiry, C takes the
// one further attempt at the retry_at B wrote; where B finds the job succeeded, no C runs.
// The hook positions are request #61 (2)'s; the flag spells each phase as FAULT_PHASES does.

import { FAULT_PHASES } from '../../../src/domain/finalization/fault-hook.ts';

/** The eight phases in order: the spec's words (titles, receipts) and the flag's spelling. */
export const PHASES = Object.freeze(
  ['reserve', 'compose', 'seal', 'verify', 'store PDF', 'store evidence', 'publish', 'outbox'].map((label, index) => Object.freeze({ label, flag: FAULT_PHASES[index] })),
);

export function phaseOf(label) {
  const phase = PHASES.find((entry) => entry.label === label);
  if (phase === undefined) throw new Error(`no phase ${label}`);
  return phase;
}

const id = (n) => `SC003-${String(n).padStart(2, '0')}`;

const sigkill = (n, label, expect) =>
  Object.freeze({
    id: id(n),
    group: 'sigkill',
    phase: phaseOf(label),
    title: `SIGKILL at ${label}: a fresh runner reclaims at the strict lease expiry and the envelope is completed exactly once`,
    expect: Object.freeze({ state: 'completed', failedMoves: 0, ...expect }),
  });

const stale = (n, label, expect) =>
  Object.freeze({
    id: id(n),
    group: 'stale-lease',
    phase: phaseOf(label),
    title: `barrier at ${label} while the lease expires: a probe 1 ms before the expiry reclaims nothing, a second runner reclaims at the expiry, and exactly one attempt publishes`,
    expect: Object.freeze({ state: 'completed', failedMoves: 0, ...expect }),
  });

const race = (n, label, name, racer) =>
  Object.freeze({
    id: id(n),
    group: 'race',
    phase: phaseOf(label),
    race: name,
    title: `${name} against a running finalization held at ${label}: refused with nothing written, and the finalization completes once`,
    expect: Object.freeze({ state: 'completed', attempts: 1, publisher: 1, failedMoves: 0, racer: Object.freeze(racer) }),
  });

/**
 * `expect`: state (the envelope's end state), attempts (attempt_count), maxAttempts, publisher (the
 * artifact's fencing token), failedMoves (moves into failed), reuse (SC003-07: the anchor and the
 * checkpoint the crashed attempt wrote are the ones published), racer (the refusal).
 */
export const CASES = Object.freeze([
  sigkill(1, 'reserve', { attempts: 2, publisher: 2 }),
  sigkill(2, 'compose', { attempts: 2, publisher: 2 }),
  sigkill(3, 'seal', { attempts: 2, publisher: 2 }),
  sigkill(4, 'verify', { attempts: 2, publisher: 2 }),
  sigkill(5, 'store PDF', { attempts: 2, publisher: 2 }),
  sigkill(6, 'store evidence', { attempts: 2, publisher: 2 }),
  sigkill(7, 'publish', { attempts: 2, publisher: 2, reuse: true }),
  sigkill(8, 'outbox', { attempts: 1, publisher: 1 }),
  stale(9, 'reserve', { attempts: 2, publisher: 2 }),
  stale(10, 'compose', { attempts: 2, publisher: 2 }),
  stale(11, 'seal', { attempts: 2, publisher: 2 }),
  stale(12, 'verify', { attempts: 2, publisher: 2 }),
  stale(13, 'store PDF', { attempts: 2, publisher: 2 }),
  stale(14, 'store evidence', { attempts: 2, publisher: 2 }),
  stale(15, 'publish', { attempts: 1, publisher: 1 }),
  stale(16, 'outbox', { attempts: 1, publisher: 1 }),
  race(17, 'compose', 'void', { status: 409, code: 'state_conflict' }),
  race(18, 'seal', 'decline', { status: 409, code: 'state_conflict' }),
  race(19, 'store PDF', 'expiry', { status: 200, expired: 0 }),
  race(20, 'store evidence', 'operator retry', { status: 409, code: 'finalization_not_retryable' }),
]);

/** Extra case IDs, never required (plan.md SC-003; request #61 (7)). */
export const EXTRA = Object.freeze({
  'REC-01': Object.freeze({
    id: 'REC-01',
    group: 'hook',
    phase: null,
    title: 'without the harness flag every compiled-in hook point is inert: the run completes exactly as an unhooked run, and the hook reads only that flag',
    expect: Object.freeze({ state: 'completed', attempts: 1, publisher: 1, failedMoves: 0 }),
  }),
  'REC-02': Object.freeze({
    id: 'REC-02',
    group: 'limit',
    phase: phaseOf('compose'),
    title: 'a crash at the last allowed attempt is reclaimed into failed once; an operator retry raises max_attempts by exactly one, a second retry before the next attempt changes nothing, and the next attempt completes',
    seed: Object.freeze({ maxAttempts: 2 }),
    expect: Object.freeze({ state: 'completed', attempts: 3, maxAttempts: 3, publisher: 3, failedMoves: 1, retried: 1 }),
  }),
});

export function entryById(caseId) {
  const entry = CASES.find((candidate) => candidate.id === caseId) ?? EXTRA[caseId];
  if (entry === undefined) throw new Error(`no catalog case ${caseId}`);
  return entry;
}

// Static self-check: SC003-01..SC003-20 in order, each phase once per kind, the flag order bound.
{
  const ids = CASES.map((entry) => entry.id).join(',');
  const expected = Array.from({ length: 20 }, (_, index) => id(index + 1)).join(',');
  if (ids !== expected) throw new Error(`the catalog lists ${ids}, not SC003-01..SC003-20`);
  for (const group of ['sigkill', 'stale-lease']) {
    const labels = CASES.filter((entry) => entry.group === group).map((entry) => entry.phase.label).join(',');
    if (labels !== PHASES.map((phase) => phase.label).join(',')) throw new Error(`the ${group} group covers ${labels}`);
  }
  if (FAULT_PHASES.length !== PHASES.length || PHASES.some((phase) => typeof phase.flag !== 'string')) throw new Error('the hook spells every phase');
}
