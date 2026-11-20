// SPDX-License-Identifier: Apache-2.0
//
// T010, SC002-02: a recipient session of envelope A used on envelope B. approveAsHuman and
// declineAsRecipient carry no envelope in their path: the session cookie alone names the
// tenant, the envelope and the recipient, so "used on B" can only mean A's session presenting
// B's inputs (version, document and manifest digests, consent). B is tried in the same tenant
// and in another tenant. The approval is decided on A's binding alone:
// - B is never touched, in either tenant; nothing at all is recorded;
// - the refusal does not depend on B: it is the same refusal, member for member except the
//   correlation id, as for inputs that name nothing, so it is no oracle for B's existence or
//   its tenant;
// - A, B and the other tenant's envelope each still take their own recipient's approval.
// The contract declares no 404 for these two operations (contracts/http-api.json), so the
// refusal is the contract's 409 digest_mismatch for A; see the T010 report (PLAN AMENDMENT on
// the SC002-02 catalog text). Everything is synthetic (see support.mjs).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  GUARD_TOUCH,
  approvalBody,
  assertError,
  createWorld,
  envelopeRow,
  errorShape,
  openSession,
  postApproval,
  sentEnvelope,
  sha256,
} from './support.mjs';

test('[SC002-02] a recipient session of envelope A used on envelope B, in the same tenant or another, approves nothing: B is untouched and the refusal is the one for inputs that name nothing', async () => {
  const world = await createWorld();
  try {
    const a = await sentEnvelope(world, { tenant: 'alpha' });
    const b = await sentEnvelope(world, { tenant: 'alpha' });
    const c = await sentEnvelope(world, { tenant: 'beta' });
    const sessionA = await openSession(world, a.token);
    const sessionB = await openSession(world, b.token);
    const sessionC = await openSession(world, c.token);
    const stateA = sessionA.state;
    assert.equal(sessionB.state.envelope_version, stateA.envelope_version, 'premise: A and B are at the same version, so the version alone does not tell them apart');
    assert.equal(sessionC.state.envelope_version, stateA.envelope_version, 'premise: so is the other tenant’s envelope');
    assert.notEqual(sessionB.state.manifest_digest, stateA.manifest_digest, 'premise: different manifests');

    const before = world.snapshot(GUARD_TOUCH);
    const nothing = (label) => sha256(Buffer.from(`names nothing: ${label}`, 'utf8'));
    const inputsOf = (state) => ({
      expected_version: state.envelope_version,
      document_digest: state.document.digest,
      manifest_digest: state.manifest_digest,
      prior_approval_digest: state.prior_approval_digest,
      consent_version: state.consent.version,
      consent_text_digest: state.consent.text_digest,
    });
    const baseline = await postApproval(world, sessionA, approvalBody(stateA, { overrides: { ...inputsOf(stateA), document_digest: nothing('document'), manifest_digest: nothing('manifest') } }));
    assertError(baseline, 409, 'digest_mismatch', 'inputs that name nothing');

    for (const [label, state] of [
      ['B in the same tenant', sessionB.state],
      ['B in another tenant', sessionC.state],
    ]) {
      // B's inputs with A's fields (A's session must present A's field keys), then B's own field keys too.
      for (const [variant, body] of [
        ['B’s inputs', approvalBody(stateA, { overrides: inputsOf(state) })],
        ['B’s inputs and field keys', approvalBody(state)],
      ]) {
        const response = await postApproval(world, sessionA, body);
        assertError(response, 409, 'digest_mismatch', `${label}: ${variant}`);
        assert.deepEqual(errorShape(response), errorShape(baseline), `${label}: ${variant}: the same refusal as for inputs that name nothing`);
        assert.deepEqual(Object.keys(response.headers).sort(), Object.keys(baseline.headers).sort(), `${label}: ${variant}: the same response headers`);
      }
    }
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded in either tenant');
    assert.equal(world.rows('approvals').length, 0, 'no approval exists');
    for (const [label, sent] of [
      ['A', a],
      ['B', b],
      ['the other tenant’s envelope', c],
    ]) {
      const row = envelopeRow(world, sent.envelope.id);
      assert.deepEqual({ state: row.state, version: row.version }, { state: 'sent', version: sent.envelope.version }, `${label} is untouched`);
    }

    // Each envelope still takes its own recipient's approval.
    for (const [label, session, envelopeId] of [
      ['A', sessionA, a.envelope.id],
      ['B', sessionB, b.envelope.id],
      ['the other tenant’s envelope', sessionC, c.envelope.id],
    ]) {
      const response = await postApproval(world, session, approvalBody(session.state));
      assert.equal(response.status, 200, `${label} approves through its own session`);
      assert.equal(envelopeRow(world, envelopeId).state, 'finalizing');
    }
    assert.equal(world.rows('approvals', 'WHERE tenant_id = ?', [world.tenantId('beta')]).length, 1, 'the other tenant holds exactly its own approval');
  } finally {
    await world.close();
  }
});
