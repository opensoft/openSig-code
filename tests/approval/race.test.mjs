// SPDX-License-Identifier: Apache-2.0
//
// T010 races in separate OS processes (data-model.md § Transitions and races). Each racer is
// its own Node process with its own SQLite connection to the world's database file
// (support/race-child.mjs); a racer can be paused just before or just after the commit of its
// nth transaction, or gated before its action, until this process answers. Nothing else is
// simulated: the write lock (BEGIN IMMEDIATE), the compare-and-set and every statement are real.
//
// AP-12, one pairing per round, each deterministic:
// A. the final approval holds the write lock (paused before its commit) while a void waits:
//    the void cannot finish while the lock is held; the approval commits finalizing with its
//    reservation; the void is then refused (409 state_conflict).
// B. the approval has committed (paused after its commit) when a void runs to the end: the
//    void is refused, so the reservation and the approval are the only outcome. (An approval
//    whose reservation committed apart from its compare-and-set would let this void win and
//    leave a reservation on a voided envelope.)
// C. a decline of the same recipient has committed when an approval authenticated before it
//    runs: the approval is 401 (its session was revoked) and records nothing. envelope.declined
//    is already in the outbox at the decline's commit: it was written in that transaction.
// C2. the approval holds the lock when a decline authenticated before it runs: the decline
//    waits, then is refused (409 state_conflict); the reservation stands.
// D. the sweeper has committed an expiry when an approval authenticated before it (with a
//    clock before the deadline) runs: 401, nothing recorded. envelope.expired is already in the
//    outbox at the expiry's commit.
// D2. the sweeper listed an envelope as due, then an approval (before the deadline) commits
//    before the sweeper's own transaction: the sweeper re-reads it and leaves it finalizing.
// AP-14: all at once. A holder process keeps the write lock while two identical approvals, a
// changed approval, a decline, a void and a sweep (each from its own process; the sweep's clock
// past the deadline, the others before it) queue for it; then the lock is released and they
// race in whatever order SQLite grants it. Three times. Whoever wins, exactly one outcome
// commits: the state, the version (exactly + 1), the approval, its receipt and its reservation
// agree with it; identical approvals get byte-identical receipts; a changed one is 409; every
// loser is 401 or 409; and the audit chain and the outbox hold exactly the winner's events.
// Everything is synthetic (see support.mjs).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { RACE_BUSY_TIMEOUT_MS, bytesOf, startRacer, stopAll } from './support/race.mjs';
import { BASE_TIME, MINUTE, approvalBody, auditEvents, createWorld, envelopeRow, openSession, outboxOf, sentEnvelope } from './support.mjs';

/** How long a racer queued for the write lock is watched to show that it cannot finish. */
const BLOCKED_WATCH_MS = 1_000;

function outcomeOf(world, envelopeId) {
  const row = envelopeRow(world, envelopeId);
  return {
    state: row.state,
    version: row.version,
    approvals: world.rows('approvals', 'WHERE envelope_id = ?', [envelopeId]).length,
    receipts: world.rows('approval_receipts', 'WHERE envelope_id = ?', [envelopeId]).length,
    jobs: world.rows('signing_jobs', 'WHERE envelope_id = ?', [envelopeId]).map((job) => job.reserved_version),
  };
}

test('[AP-12] races between approval, void, decline and the sweeper in separate OS processes: each pairing commits exactly one outcome through the shared compare-and-set', { timeout: 540_000 }, async () => {
  const world = await createWorld({ busyTimeoutMs: RACE_BUSY_TIMEOUT_MS });
  const racers = [];
  const dir = world.scratch.dir('opensig-race-');
  const start = (job) => {
    const racer = startRacer(world, dir, { tenantId: world.tenantId('alpha'), clockMs: BASE_TIME, ...job });
    racers.push(racer);
    return racer;
  };
  try {
    const opened = async (options = {}) => {
      const sent = await sentEnvelope(world, options);
      const session = await openSession(world, sent.token);
      return { envelope: sent.envelope, session, v: session.state.envelope_version };
    };

    // A. Final approval paused before its commit; a void queues for the lock.
    {
      const { envelope, session, v } = await opened();
      const approval = start({ action: 'approve', cookie: session.cookie, body: approvalBody(session.state), pause: { phase: 'before-commit', nth: 1 } });
      await approval.waitFor('paused');
      const voiding = start({ action: 'void', envelopeId: envelope.id, body: { expected_version: v, reason_code: 'sender-cancelled' } });
      await voiding.waitFor('attempting');
      assert.equal(await voiding.absentFor('result', BLOCKED_WATCH_MS), true, 'A: the void cannot finish while the approval holds the write lock');
      approval.answer();
      const approved = await approval.result();
      assert.equal(approved.status, 200, `A: the approval commits (${approved.code ?? ''})`);
      assert.equal(JSON.parse(bytesOf(approved).toString('utf8')).envelope_state, 'finalizing');
      const voided = await voiding.result();
      assert.deepEqual({ status: voided.status, code: voided.code }, { status: 409, code: 'state_conflict' }, 'A: the void is refused');
      assert.deepEqual(outcomeOf(world, envelope.id), { state: 'finalizing', version: v + 1, approvals: 1, receipts: 1, jobs: [v + 1] }, 'A: one outcome, reserved at the finalizing version');
    }

    // B. The approval has committed (paused after its commit) when a void runs to the end.
    {
      const { envelope, session, v } = await opened();
      const approval = start({ action: 'approve', cookie: session.cookie, body: approvalBody(session.state), pause: { phase: 'after-commit', nth: 1 } });
      await approval.waitFor('paused');
      const voiding = start({ action: 'void', envelopeId: envelope.id, body: { expected_version: v, reason_code: 'sender-cancelled' } });
      const voided = await voiding.result();
      assert.deepEqual({ status: voided.status, code: voided.code }, { status: 409, code: 'state_conflict' }, 'B: the void finds the envelope reserved and is refused');
      approval.answer();
      const approved = await approval.result();
      assert.equal(approved.status, 200, `B: the approval returns its receipt (${approved.code ?? ''})`);
      assert.deepEqual(outcomeOf(world, envelope.id), { state: 'finalizing', version: v + 1, approvals: 1, receipts: 1, jobs: [v + 1] }, 'B: the approval and its reservation are the only outcome');
    }

    // C. A decline has committed when an approval of the same recipient, authenticated before it, runs.
    {
      const { envelope, session, v } = await opened();
      const approval = start({ action: 'approve', cookie: session.cookie, body: approvalBody(session.state), gate: true });
      assert.equal((await approval.waitFor('authenticated')).ok, true, 'C: premise: the approval authenticated first');
      await approval.waitFor('gated');
      const declining = start({ action: 'decline', cookie: session.cookie, body: { expected_version: v }, pause: { phase: 'after-commit', nth: 1 } });
      await declining.waitFor('paused');
      assert.deepEqual(
        outboxOf(world, envelope.id, 'envelope.declined').map((event) => event.envelope_version),
        [v + 1],
        'C: at the decline’s commit, envelope.declined is already in the outbox, once',
      );
      approval.answer();
      const refused = await approval.result();
      assert.deepEqual({ status: refused.status, code: refused.code }, { status: 401, code: 'unauthenticated' }, 'C: the approval finds its session revoked');
      declining.answer();
      const declined = await declining.result();
      assert.equal(declined.status, 200, `C: the decline commits (${declined.code ?? ''})`);
      assert.deepEqual(outcomeOf(world, envelope.id), { state: 'declined', version: v + 1, approvals: 0, receipts: 0, jobs: [] }, 'C: declined, nothing approved or reserved');
      assert.equal(outboxOf(world, envelope.id, 'envelope.declined').length, 1, 'C: still exactly one envelope.declined');
    }

    // C2. The approval holds the lock when a decline, authenticated before it, runs.
    {
      const { envelope, session, v } = await opened();
      const declining = start({ action: 'decline', cookie: session.cookie, body: { expected_version: v }, gate: true });
      assert.equal((await declining.waitFor('authenticated')).ok, true, 'C2: premise: the decline authenticated first');
      await declining.waitFor('gated');
      const approval = start({ action: 'approve', cookie: session.cookie, body: approvalBody(session.state), pause: { phase: 'before-commit', nth: 1 } });
      await approval.waitFor('paused');
      declining.answer();
      await declining.waitFor('attempting');
      assert.equal(await declining.absentFor('result', BLOCKED_WATCH_MS), true, 'C2: the decline cannot finish while the approval holds the write lock');
      approval.answer();
      assert.equal((await approval.result()).status, 200, 'C2: the approval commits');
      const refused = await declining.result();
      assert.deepEqual({ status: refused.status, code: refused.code }, { status: 409, code: 'state_conflict' }, 'C2: the decline finds the envelope reserved');
      assert.deepEqual(outcomeOf(world, envelope.id), { state: 'finalizing', version: v + 1, approvals: 1, receipts: 1, jobs: [v + 1] }, 'C2: one outcome');
    }

    // D. The sweeper has committed an expiry when an approval authenticated before it runs.
    {
      const deadline = BASE_TIME + 10 * MINUTE;
      const { envelope, session, v } = await opened({ expiresAt: new Date(deadline).toISOString() });
      const approval = start({ action: 'approve', cookie: session.cookie, body: approvalBody(session.state), gate: true, clockMs: deadline - 1 });
      assert.equal((await approval.waitFor('authenticated')).ok, true, 'D: premise: the approval authenticated before the deadline');
      await approval.waitFor('gated');
      // The sweep's first transaction lists the due envelopes; its second expires this one.
      const sweeping = start({ action: 'sweep', clockMs: deadline, pause: { phase: 'after-commit', nth: 2 } });
      await sweeping.waitFor('paused');
      assert.equal(envelopeRow(world, envelope.id).state, 'expired', 'D: premise: the expiry has committed');
      assert.deepEqual(outboxOf(world, envelope.id, 'envelope.expired').map((event) => event.envelope_version), [v + 1], 'D: at the expiry’s commit, envelope.expired is already in the outbox, once');
      approval.answer();
      const refused = await approval.result();
      assert.deepEqual({ status: refused.status, code: refused.code }, { status: 401, code: 'unauthenticated' }, 'D: the approval finds its session revoked by the expiry');
      sweeping.answer();
      const swept = await sweeping.result();
      assert.equal(swept.expired, 1, 'D: the sweep expired it');
      assert.deepEqual(outcomeOf(world, envelope.id), { state: 'expired', version: v + 1, approvals: 0, receipts: 0, jobs: [] }, 'D: expired, nothing approved or reserved');
    }

    // D2. The sweeper listed the envelope as due; an approval before the deadline commits first.
    {
      const deadline = BASE_TIME + 20 * MINUTE;
      const { envelope, session, v } = await opened({ expiresAt: new Date(deadline).toISOString() });
      const sweeping = start({ action: 'sweep', clockMs: deadline, pause: { phase: 'after-commit', nth: 1 } });
      await sweeping.waitFor('paused');
      const approval = start({ action: 'approve', cookie: session.cookie, body: approvalBody(session.state), clockMs: deadline - 1 });
      const approved = await approval.result();
      assert.equal(approved.status, 200, `D2: the approval before the deadline commits (${approved.code ?? ''})`);
      sweeping.answer();
      const swept = await sweeping.result();
      assert.equal(swept.status, 200, `D2: the sweep completes (${swept.code ?? ''})`);
      assert.equal(swept.expired, 0, 'D2: the sweep re-reads the envelope and leaves it alone');
      assert.deepEqual(outcomeOf(world, envelope.id), { state: 'finalizing', version: v + 1, approvals: 1, receipts: 1, jobs: [v + 1] }, 'D2: the approval is the only outcome');
      assert.equal(outboxOf(world, envelope.id, 'envelope.expired').length, 0, 'D2: nothing announces an expiry');
    }
  } finally {
    await stopAll(racers);
    await world.close();
  }
});

test('[AP-14] two identical approvals, a changed approval, a decline, a void and a sweep released together from separate OS processes: exactly one outcome commits, three times over', { timeout: 540_000 }, async () => {
  const world = await createWorld({ busyTimeoutMs: RACE_BUSY_TIMEOUT_MS });
  const racers = [];
  const dir = world.scratch.dir('opensig-race-');
  const start = (job) => {
    const racer = startRacer(world, dir, { tenantId: world.tenantId('alpha'), clockMs: BASE_TIME, ...job });
    racers.push(racer);
    return racer;
  };
  try {
    const winners = [];
    for (let round = 1; round <= 3; round += 1) {
      const deadline = BASE_TIME + 20 * MINUTE;
      const before = deadline - 1;
      const sent = await sentEnvelope(world, { expiresAt: new Date(deadline).toISOString() });
      const session = await openSession(world, sent.token);
      const v = session.state.envelope_version;
      const body = approvalBody(session.state, { text: 'Synthetic Racer' });
      const changed = approvalBody(session.state, { text: 'Synthetic Changed Racer' });
      const audit = { approved: auditEvents(world, 'recipient.approved').length, declined: auditEvents(world, 'recipient.declined').length };

      const contenders = {
        a1: start({ action: 'approve', cookie: session.cookie, body, gate: true, clockMs: before }),
        a2: start({ action: 'approve', cookie: session.cookie, body, gate: true, clockMs: before }),
        a3: start({ action: 'approve', cookie: session.cookie, body: changed, gate: true, clockMs: before }),
        decline: start({ action: 'decline', cookie: session.cookie, body: { expected_version: v, reason_code: 'disagree' }, gate: true, clockMs: before }),
        void: start({ action: 'void', envelopeId: sent.envelope.id, body: { expected_version: v, reason_code: 'superseded' }, gate: true, clockMs: before }),
        sweep: start({ action: 'sweep', gate: true, clockMs: deadline }),
      };
      for (const [name, racer] of Object.entries(contenders)) {
        await racer.waitFor('gated');
        if (name.startsWith('a') || name === 'decline') assert.equal(racer.events.find((event) => event.event === 'authenticated')?.ok, true, `round ${round}: ${name} authenticated`);
      }
      const holder = start({ action: 'hold', pause: { phase: 'before-commit', nth: 1 } });
      await holder.waitFor('paused');
      for (const racer of Object.values(contenders)) racer.answer();
      for (const [name, racer] of Object.entries(contenders)) {
        await racer.waitFor('attempting');
        assert.equal(await racer.absentFor('result', 50), true, `round ${round}: ${name} queues behind the holder`);
      }
      holder.answer();
      assert.equal((await holder.result()).status, 200);
      const results = {};
      for (const [name, racer] of Object.entries(contenders)) results[name] = await racer.result();

      // Exactly one outcome.
      const outcome = outcomeOf(world, sent.envelope.id);
      const won = {
        approval: outcome.approvals === 1,
        decline: results.decline.status === 200,
        void: results.void.status === 200,
        sweep: results.sweep.status === 200 && results.sweep.expired === 1,
      };
      const kinds = Object.entries(won).filter(([, value]) => value).map(([kind]) => kind);
      assert.equal(kinds.length, 1, `round ${round}: exactly one outcome commits (${kinds.join(', ') || 'none'}; statuses ${Object.entries(results).map(([name, result]) => `${name}=${result.status}${result.code ? `:${result.code}` : ''}`).join(' ')})`);
      const [kind] = kinds;
      winners.push(kind);
      assert.equal(outcome.state, { approval: 'finalizing', decline: 'declined', void: 'voided', sweep: 'expired' }[kind], `round ${round}: the state is the winner's`);
      assert.equal(outcome.version, v + 1, `round ${round}: the version moved by exactly one`);
      assert.equal(outcome.receipts, kind === 'approval' ? 1 : 0, `round ${round}: a receipt exists exactly when the approval won`);
      assert.deepEqual(outcome.jobs, kind === 'approval' ? [v + 1] : [], `round ${round}: a reservation exists exactly when the approval won, at its version`);
      assert.equal(results.sweep.status, 200, `round ${round}: the sweep itself never fails (${results.sweep.code ?? ''})`);

      // Approvals: identical requests get identical bytes; a changed one is 409.
      const approvals = ['a1', 'a2', 'a3'];
      const accepted = approvals.filter((name) => results[name].status === 200);
      if (kind === 'approval') {
        const [stored] = world.rows('approval_receipts', 'WHERE envelope_id = ?', [sent.envelope.id]);
        const storedBytes = Buffer.from(stored.receipt_body);
        for (const name of accepted) assert.ok(bytesOf(results[name]).equals(storedBytes), `round ${round}: ${name} returns the stored receipt bytes`);
        const changedWon = JSON.parse(world.rows('approvals', 'WHERE envelope_id = ?', [sent.envelope.id])[0].field_values_json).some((value) => value.text === 'Synthetic Changed Racer');
        assert.deepEqual(accepted, changedWon ? ['a3'] : ['a1', 'a2'], `round ${round}: exactly the requests identical to the winner's are 200`);
        for (const name of approvals.filter((entry) => !accepted.includes(entry))) {
          assert.deepEqual({ status: results[name].status, code: results[name].code }, { status: 409, code: 'state_conflict' }, `round ${round}: ${name}, a changed retry, is 409`);
        }
      } else {
        assert.deepEqual(accepted, [], `round ${round}: no approval is accepted when ${kind} won`);
      }
      // Every loser is 401 or 409; nothing is a 500 or a busy timeout.
      for (const [name, result] of Object.entries(results)) {
        if (name === 'sweep') continue;
        assert.ok([200, 401, 409].includes(result.status), `round ${round}: ${name} answered ${result.status} ${result.code ?? ''}`);
      }
      // The audit chain holds exactly the winner's event.
      assert.equal(auditEvents(world, 'recipient.approved').length - audit.approved, kind === 'approval' ? 1 : 0, `round ${round}: recipient.approved events`);
      assert.equal(auditEvents(world, 'recipient.declined').length - audit.declined, kind === 'decline' ? 1 : 0, `round ${round}: recipient.declined events`);
      assert.equal(outboxOf(world, sent.envelope.id, 'envelope.declined').length, kind === 'decline' ? 1 : 0, `round ${round}: envelope.declined events`);
      assert.equal(outboxOf(world, sent.envelope.id, 'envelope.expired').length, kind === 'sweep' ? 1 : 0, `round ${round}: envelope.expired events`);
    }
    assert.equal(winners.length, 3);
  } finally {
    await stopAll(racers);
    await world.close();
  }
});
