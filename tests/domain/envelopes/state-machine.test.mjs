// SPDX-License-Identifier: Apache-2.0
//
// The envelope state machine (T007): the transition graph of data-model.md
// § Envelope states (A-010) and the "fully approved" mapping, including the
// one-recipient case sent -> finalizing.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import {
  APPROVING_STATES,
  canTransition,
  ENVELOPE_STATES,
  FULLY_APPROVED_STATES,
  isFullyApproved,
  isTerminal,
  PRE_RESERVATION_STATES,
  stateAfterApproval,
  TERMINAL_STATES,
  TRANSITIONS,
} from '../../../src/domain/envelopes/index.ts';
import { advanceOnly, approve, contractErrors, RULED_GRAPH, HUMAN, insertConsent, makeScratch, rejectsWith, req, sentEnvelope, setup } from './support.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

test('[ST-01] the domain transition table is exactly the ruled graph; terminal states have no exits and a same-state update is not a transition', () => {
  assert.deepEqual([...ENVELOPE_STATES].sort(), Object.keys(RULED_GRAPH).sort(), 'the nine data-model states');
  for (const from of ENVELOPE_STATES) {
    assert.deepEqual([...TRANSITIONS[from]].sort(), [...RULED_GRAPH[from]].sort(), `exits of ${from}`);
    for (const to of ENVELOPE_STATES) {
      assert.equal(canTransition(from, to), RULED_GRAPH[from].includes(to), `${from} -> ${to}`);
    }
    assert.equal(canTransition(from, from), false, `${from} -> ${from} is not a transition`);
  }
  assert.deepEqual([...TERMINAL_STATES].sort(), ['completed', 'declined', 'expired', 'voided']);
  for (const state of ENVELOPE_STATES) assert.equal(isTerminal(state), RULED_GRAPH[state].length === 0, `${state} terminal`);
  assert.deepEqual([...PRE_RESERVATION_STATES].sort(), ['draft', 'in-progress', 'prepared', 'sent'], 'void, decline and expiry win only before reservation');
  for (const state of PRE_RESERVATION_STATES) assert.ok(canTransition(state, 'voided') && canTransition(state, 'expired'), `${state} can be voided or expire`);
  assert.equal(canTransition('finalizing', 'voided'), false, 'after reservation, void is refused');
  assert.deepEqual([...APPROVING_STATES].sort(), ['in-progress', 'sent']);

  // "Fully approved" = approvals_complete = true = finalizing or completed; it is not completed.
  assert.deepEqual([...FULLY_APPROVED_STATES].sort(), ['completed', 'finalizing']);
  assert.equal(isFullyApproved('finalizing'), true);
  assert.equal(isFullyApproved('in-progress'), false);
  assert.equal(stateAfterApproval(1, 1), 'finalizing', 'one recipient: sent -> finalizing directly');
  assert.equal(stateAfterApproval(2, 1), 'in-progress', 'two recipients: the first approval -> in-progress');
  assert.equal(stateAfterApproval(2, 2), 'finalizing', 'two recipients: the last approval -> finalizing');
  for (const [count, ordinal] of [[0, 1], [3, 1], [1, 2], [2, 0], [1.5, 1]]) {
    assert.throws(() => stateAfterApproval(count, ordinal), RangeError, `${count}/${ordinal}`);
  }
});

test('[ST-02] one recipient: the single approval moves sent -> finalizing directly with approvals_complete = true, never in-progress, and is not completed', () => {
  const ctx = setup(scratch);
  try {
    const consent = insertConsent(ctx.db, ctx.tenant);
    const sent = sentEnvelope(ctx, { recipients: 1 });
    assert.equal(sent.state, 'sent');
    assert.deepEqual(sent.recipients.map((r) => r.status), ['invited']);
    const { approval, outcome } = approve(ctx, sent, sent.recipients[0], consent);
    assert.deepEqual(outcome, { state: 'finalizing', version: sent.version + 1, fullyApproved: true });

    const view = ctx.service.read(req(ctx.tenant), sent.id);
    assert.equal(view.state, 'finalizing');
    assert.equal(view.approvals_complete, true, 'fully approved');
    assert.notEqual(view.state, 'completed', 'fully approved is visibly distinct from completed');
    assert.equal(view.artifact, null, 'no sealed artifact is claimed');
    assert.equal(view.version, sent.version + 1);
    assert.equal(view.recipients[0].status, 'approved');
    assert.equal(view.recipients[0].approval_digest, approval.digest);
    assert.deepEqual(contractErrors('Envelope', view), [], 'the fully approved view conforms to the contract');

    const approvalChanges = ctx.changes.filter((change) => change.operation === 'approval');
    assert.deepEqual(approvalChanges.map((change) => [change.from, change.to]), [['sent', 'finalizing']], 'never through in-progress');
    assert.equal(ctx.changes.some((change) => change.to === 'in-progress'), false);

    rejectsWith(() => advanceOnly(ctx, view, view.recipients[0]), 'state_conflict', 409);
    assert.equal(ctx.service.read(req(ctx.tenant), sent.id).version, view.version, 'a refused approval leaves the version');
  } finally {
    ctx.db.close();
  }
});

test('[ST-02] two recipients: only the recipient whose turn it is advances; sent -> in-progress -> finalizing; a stale version is refused', () => {
  const ctx = setup(scratch);
  try {
    const consent = insertConsent(ctx.db, ctx.tenant);
    const sent = sentEnvelope(ctx, { recipients: 2 });
    const [first, second] = sent.recipients;
    assert.deepEqual([first.status, second.status], ['invited', 'pending']);

    rejectsWith(() => advanceOnly(ctx, sent, second), 'order_conflict', 409);
    const unchanged = ctx.service.read(req(ctx.tenant), sent.id);
    assert.equal(unchanged.version, sent.version, 'an out-of-turn approval changes nothing');
    assert.deepEqual(unchanged.recipients.map((r) => r.approval_digest), [null, null], 'and leaves no approval');

    rejectsWith(() => approve(ctx, { ...sent, version: sent.version + 1 }, first, consent), 'version_conflict', 409);

    const one = approve(ctx, sent, first, consent);
    assert.deepEqual(one.outcome, { state: 'in-progress', version: sent.version + 1, fullyApproved: false });
    const progressing = ctx.service.read(req(ctx.tenant), sent.id);
    assert.equal(progressing.state, 'in-progress');
    assert.equal(progressing.approvals_complete, false);
    assert.deepEqual(progressing.recipients.map((r) => r.status), ['approved', 'invited'], 'recipient 2 is invited after the first approval');

    rejectsWith(() => advanceOnly(ctx, progressing, progressing.recipients[0]), 'order_conflict', 409);

    const two = approve(ctx, progressing, progressing.recipients[1], consent, one.approval.digest);
    assert.deepEqual(two.outcome, { state: 'finalizing', version: sent.version + 2, fullyApproved: true });
    const done = ctx.service.read(req(ctx.tenant, HUMAN), sent.id);
    assert.equal(done.state, 'finalizing');
    assert.equal(done.approvals_complete, true);
    assert.deepEqual(done.recipients.map((r) => r.status), ['approved', 'approved']);
    assert.deepEqual(contractErrors('Envelope', done), []);
    assert.deepEqual(
      ctx.changes.filter((change) => change.operation === 'approval').map((change) => [change.from, change.to]),
      [['sent', 'in-progress'], ['in-progress', 'finalizing']],
    );
  } finally {
    ctx.db.close();
  }
});
