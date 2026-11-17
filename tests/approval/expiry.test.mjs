// SPDX-License-Identifier: Apache-2.0
//
// T010 expiry (data-model.md § Envelope states, expired; A-010 rows IDEMP-B3 / N2 and
// T008-F5), with the sweeper run directly at instants of the injected clock:
// - AP-02: every sweep also purges, for every tenant, exactly the idempotency records T007's
//   replay-expiry predicate (isIdempotencyRecordExpired) treats as expired, oldest first, in
//   bounded batches (A-010, request #24, ruling (9)). At the exact 24-hour instant the record
//   is expired by that predicate and purged; one millisecond earlier it is still a replay and
//   kept. A run that reaches its batch bound says so and the next run continues; the purge
//   writes no audit event. The interval scheduler runs the same sweep.
// - AP-04 (row T008-F5): past expires_at and before any sweep, a session stays readable and
//   shows the turn as closed; the sweep expires every due envelope before the reservation in
//   every tenant through the shared compare-and-set (version + 1), closes open recipients,
//   revokes invitations and sessions (now 401) with an audit record, announces each expiry
//   as envelope.expired in the outbox exactly once, in the expiry's transaction (ruling (6)),
//   leaves finalizing, declined and not-yet-due envelopes alone, and a second sweep changes
//   nothing.
// - AP-11: an approval or decline at or past expires_at is 409 state_conflict, records no
//   approval, and the request commits the expiry itself, announced exactly once; one
//   millisecond before is accepted.
// Everything is synthetic (see support.mjs).

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';

import { ExpirySweeper, runExpirySweep } from '../../src/jobs/expiry.ts';
import { DEFAULT_PURGE_BATCH, findIdempotencyRecord, insertIdempotencyRecord, isIdempotencyRecordExpired } from '../../src/storage/repositories/idempotency.ts';
import {
  BASE_TIME,
  DAY,
  MINUTE,
  approvalBody,
  assertError,
  auditEvents,
  contractErrors,
  createWorld,
  envelopeRow,
  openSession,
  outboxOf,
  postApproval,
  postDecline,
  readSession,
  secondToken,
  sentEnvelope,
  sha256,
  stateOf,
  testClock,
} from './support.mjs';

/** One synthetic idempotency record for `tenant`, created `ageMs` before `now`. */
function seedRecord(world, tenant, now, ageMs, label) {
  const key = `purge-${label}-${randomBytes(9).toString('base64url')}`;
  world.db.transaction(() =>
    insertIdempotencyRecord(world.store(tenant), {
      route: 'createEnvelope',
      principal: { kind: 'human-operator', ref: 'operator-purge-tests' },
      key,
      requestDigest: sha256(Buffer.from(key, 'utf8')),
      responseStatus: 201,
      response: { kind: 'body', body: { synthetic: label } },
      resourceId: null,
      createdAt: new Date(now - ageMs).toISOString(),
    }),
  );
  return key;
}

const keysOf = (world, tenant) => world.rows('idempotency_records', 'WHERE tenant_id = ?', [world.tenantId(tenant)]).map((row) => row.key).sort();

test('[AP-02] every sweep purges, for every tenant, the idempotency records whose 24 hours have passed, oldest first in bounded batches, by the injected clock, writing no audit event', async () => {
  const world = await createWorld();
  try {
    const now = BASE_TIME + 3 * DAY;
    const expired = { alpha: [], beta: [] };
    const kept = { alpha: [], beta: [] };
    for (const tenant of ['alpha', 'beta']) {
      expired[tenant].push(seedRecord(world, tenant, now, DAY, 'exactly-24h'));
      for (let index = 0; index < (tenant === 'alpha' ? 6 : 4); index += 1) expired[tenant].push(seedRecord(world, tenant, now, DAY + (index + 1) * MINUTE, `older-${index}`));
      kept[tenant].push(seedRecord(world, tenant, now, DAY - 1, 'one-ms-younger'));
      kept[tenant].push(seedRecord(world, tenant, now, 0, 'fresh'));
      kept[tenant].push(seedRecord(world, tenant, now, 23 * 60 * MINUTE, 'twenty-three-hours'));
    }
    const auditBefore = world.rows('audit_events').length;
    const disposalsBefore = world.rows('disposal_records').length;

    // A sweep one millisecond earlier: the record of exactly 24 hours is still a replay window, so kept.
    // The boundary is T007's own predicate: the record of exactly 24 hours is expired at `now`, not before.
    const boundary = findIdempotencyRecord(world.store('alpha'), 'createEnvelope', 'operator-purge-tests', expired.alpha[0]);
    assert.deepEqual([isIdempotencyRecordExpired(boundary, new Date(now - 1)), isIdempotencyRecordExpired(boundary, new Date(now))], [false, true], 'premise: T007’s predicate turns at exactly 24 hours');
    const early = testClock(now - 1);
    const earlyReport = runExpirySweep({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: early.clock, purgeBatch: 2 });
    assert.equal(earlyReport.purged, 6 + 4, 'only the records older than 24 hours at that instant');
    assert.ok(keysOf(world, 'alpha').includes(expired.alpha[0]) && keysOf(world, 'beta').includes(expired.beta[0]), 'the record of exactly 24 hours is kept one millisecond before');

    // The bounded run: one batch of two per tenant, reported incomplete; the next run continues.
    const boundedKeys = { alpha: [], beta: [] };
    for (const tenant of ['alpha', 'beta']) {
      for (let index = 0; index < 3; index += 1) boundedKeys[tenant].push(seedRecord(world, tenant, now, 2 * DAY + index, `bounded-${index}`));
    }
    const clock = testClock(now);
    const bounded = runExpirySweep({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: clock.clock, purgeBatch: 2, maxBatches: 1 });
    assert.deepEqual({ purged: bounded.purged, complete: bounded.complete, tenants: bounded.tenants, at: bounded.at }, { purged: 4, complete: false, tenants: 2, at: new Date(now).toISOString() }, 'two per tenant, then it stops and says so');
    for (const tenant of ['alpha', 'beta']) {
      // Oldest first: bounded-2 and bounded-1 (the oldest) are gone; bounded-0 and the 24-hour record wait for the next run.
      const left = keysOf(world, tenant);
      assert.ok(!left.includes(boundedKeys[tenant][2]) && !left.includes(boundedKeys[tenant][1]), `${tenant}: the oldest records go first`);
      assert.ok(left.includes(boundedKeys[tenant][0]) && left.includes(expired[tenant][0]), `${tenant}: the younger expired records wait for the next run`);
    }
    const report = runExpirySweep({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: clock.clock, purgeBatch: 2 });
    assert.equal(report.complete, true, 'the next run finishes');
    assert.equal(bounded.purged + report.purged, 1 + 3 + 1 + 3, 'the rest: the boundary records and the remaining old ones');
    for (const tenant of ['alpha', 'beta']) {
      assert.deepEqual(keysOf(world, tenant), [...kept[tenant]].sort(), `${tenant}: exactly the records younger than 24 hours remain`);
    }
    assert.equal(world.rows('audit_events').length, auditBefore, 'the purge writes no audit event');
    assert.equal(world.rows('disposal_records').length, disposalsBefore, 'the purge writes no disposal record');
    assert.equal(runExpirySweep({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: clock.clock }).purged, 0, 'a second run purges nothing');
    assert.equal(DEFAULT_PURGE_BATCH, 500, 'premise: the default batch');

    // Bad options are refused before anything runs.
    for (const options of [{ purgeBatch: 0 }, { purgeBatch: 1001 }, { expiryBatch: 0 }, { maxBatches: 0 }, { purgeBatch: 1.5 }]) {
      assert.throws(() => runExpirySweep({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: clock.clock, ...options }), TypeError, JSON.stringify(options));
    }
    assert.throws(() => runExpirySweep({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange }), TypeError, 'a clock is required');

    // The scheduler runs the same sweep on its interval (one second at least, never two at once).
    const refused = new ExpirySweeper({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: clock.clock });
    assert.throws(() => refused.start(999), TypeError, 'an interval under one second is refused');
    assert.equal(refused.runOnce().complete, true, 'runOnce is one sweep');
    const late = seedRecord(world, 'beta', now, 2 * DAY, 'scheduled');
    let timer;
    let reporting;
    try {
      const scheduled = await new Promise((resolveReport, rejectReport) => {
        timer = setTimeout(() => rejectReport(new Error('the scheduled sweep did not report within 10 s')), 10_000);
        reporting = new ExpirySweeper({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: clock.clock, onReport: resolveReport, onError: rejectReport });
        reporting.start(1000);
      });
      assert.equal(scheduled.purged, 1, 'the scheduled run purged the old record');
    } finally {
      clearTimeout(timer);
      reporting?.stop();
    }
    assert.ok(!keysOf(world, 'beta').includes(late));
  } finally {
    await world.close();
  }
});

test('[AP-04] past expires_at a session stays readable showing closed until the sweep, which expires every due envelope before the reservation in every tenant and revokes its capabilities (row T008-F5)', async () => {
  const world = await createWorld();
  try {
    const due = new Date(BASE_TIME + 10 * MINUTE).toISOString();
    const later = new Date(BASE_TIME + 20 * MINUTE).toISOString();
    const sent = await sentEnvelope(world, { expiresAt: due });
    const sentSession = await openSession(world, sent.token);
    const progress = await sentEnvelope(world, { recipients: 2, expiresAt: due });
    const firstSession = await openSession(world, progress.token);
    assert.equal((await postApproval(world, firstSession, approvalBody(firstSession.state))).status, 200, 'recipient 1 approves');
    const secondSession = await openSession(world, secondToken(world), 'signer.two@example.test');
    const finalizing = await sentEnvelope(world, { expiresAt: due });
    const finalizingSession = await openSession(world, finalizing.token);
    assert.equal((await postApproval(world, finalizingSession, approvalBody(finalizingSession.state))).json.envelope_state, 'finalizing');
    const declined = await sentEnvelope(world, { expiresAt: due });
    const declinedSession = await openSession(world, declined.token);
    assert.equal((await postDecline(world, declinedSession, { expected_version: declinedSession.state.envelope_version })).status, 200);
    const notDue = await sentEnvelope(world, { expiresAt: later });
    const beta = await sentEnvelope(world, { tenant: 'beta', expiresAt: due });
    const betaSession = await openSession(world, beta.token);
    const draft = world.envelopes.create(world.req('alpha'), { source: { app: 'manual', record: 'synthetic-draft-0001', version: 'v1' }, recipients: [{ email: 'signer.one@example.test', role: 'approver', ordinal: 1 }], expires_at: due }).body;

    const versions = Object.fromEntries(
      [
        ['sent', sent],
        ['progress', progress],
        ['finalizing', finalizing],
        ['declined', declined],
        ['notDue', notDue],
        ['beta', beta],
      ].map(([name, entry]) => [name, envelopeRow(world, entry.envelope.id).version]),
    );
    versions.draft = envelopeRow(world, draft.id).version;

    // Past the deadline, before any sweep: the sessions are still readable and show closed.
    world.time.set(BASE_TIME + 11 * MINUTE);
    for (const [label, session, state] of [
      ['sent', sentSession, 'sent'],
      ['in-progress', secondSession, 'in-progress'],
      ['other tenant', betaSession, 'sent'],
    ]) {
      const view = await stateOf(world, session);
      assert.deepEqual({ state: view.envelope_state, turn: view.turn }, { state, turn: 'closed' }, `${label}: readable, turn closed, before the sweep`);
    }
    const beforeSweep = world.snapshot();

    // The sweep.
    const report = runExpirySweep({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: world.time.clock, expiryBatch: 1 });
    assert.deepEqual({ expired: report.expired, tenants: report.tenants, complete: report.complete }, { expired: 4, tenants: 2, complete: true }, 'sent, in-progress, the draft and the other tenant’s sent envelope expire');
    for (const [label, id, version] of [
      ['sent', sent.envelope.id, versions.sent],
      ['in-progress', progress.envelope.id, versions.progress],
      ['other tenant', beta.envelope.id, versions.beta],
      ['draft', draft.id, versions.draft],
    ]) {
      const row = envelopeRow(world, id);
      assert.deepEqual({ state: row.state, version: row.version }, { state: 'expired', version: version + 1 }, `${label}: expired at version + 1`);
    }
    for (const [label, id, state] of [
      ['finalizing', finalizing.envelope.id, 'finalizing'],
      ['declined', declined.envelope.id, 'declined'],
      ['not yet due', notDue.envelope.id, 'sent'],
    ]) {
      const row = envelopeRow(world, id);
      assert.equal(row.state, state, `${label}: left alone`);
    }
    assert.equal(envelopeRow(world, finalizing.envelope.id).version, versions.finalizing, 'the reserved envelope keeps its version');
    assert.equal(world.rows('signing_jobs', 'WHERE envelope_id = ?', [finalizing.envelope.id]).length, 1, 'its reservation stands');

    // Recipients, capabilities and the audit record.
    const progressRecipients = world.rows('recipients', 'WHERE envelope_id = ?', [progress.envelope.id]).sort((x, y) => x.ordinal - y.ordinal);
    assert.deepEqual(progressRecipients.map((entry) => entry.status), ['approved', 'expired'], 'the approved recipient stays approved; the invited one is expired');
    assert.deepEqual(world.rows('recipients', 'WHERE envelope_id = ?', [sent.envelope.id]).map((entry) => entry.status), ['expired']);
    for (const [label, id] of [
      ['sent', sent.envelope.id],
      ['in-progress', progress.envelope.id],
      ['other tenant', beta.envelope.id],
    ]) {
      assert.ok(world.rows('recipient_sessions', 'WHERE envelope_id = ?', [id]).every((entry) => entry.revoked_at !== null), `${label}: every session is revoked`);
      assert.ok(world.rows('invitations', 'WHERE envelope_id = ?', [id]).every((entry) => entry.revoked_at !== null), `${label}: every invitation is revoked`);
      assert.equal(auditEvents(world, 'recipient.capabilities_revoked').filter((event) => event.envelope_id === id).length, 1, `${label}: the revocation is in the audit chain`);
    }
    for (const [label, session] of [
      ['sent', sentSession],
      ['in-progress', secondSession],
      ['other tenant', betaSession],
      ['in-progress, recipient 1', firstSession],
    ]) {
      assert.equal((await readSession(world, session)).status, 401, `${label}: the session is closed`);
    }
    assert.notDeepEqual(world.snapshot(), beforeSweep, 'premise: the sweep changed something');

    // Each expiry is announced exactly once, at its expired version; nothing else is.
    for (const [label, id, version] of [
      ['sent', sent.envelope.id, versions.sent],
      ['in-progress', progress.envelope.id, versions.progress],
      ['other tenant', beta.envelope.id, versions.beta],
      ['draft', draft.id, versions.draft],
    ]) {
      const announced = outboxOf(world, id, 'envelope.expired');
      assert.equal(announced.length, 1, `${label}: exactly one envelope.expired event`);
      assert.equal(announced[0].envelope_version, version + 1, `${label}: at the expired version`);
      assert.deepEqual(contractErrors('WebhookEvent', announced[0].payload), [], `${label}: a contract WebhookEvent`);
      assert.equal(announced[0].payload.occurred_at, new Date(BASE_TIME + 11 * MINUTE).toISOString(), `${label}: at the sweep's instant`);
    }
    for (const [label, id] of [
      ['finalizing', finalizing.envelope.id],
      ['declined', declined.envelope.id],
      ['not yet due', notDue.envelope.id],
    ]) {
      assert.equal(outboxOf(world, id, 'envelope.expired').length, 0, `${label}: no envelope.expired event`);
    }

    // A second sweep at the same instant changes nothing; a later one expires the next due envelope.
    const settled = world.snapshot();
    const again = runExpirySweep({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: world.time.clock });
    assert.equal(again.expired, 0, 'a second sweep expires nothing');
    assert.deepEqual(world.snapshot(), settled, 'a second sweep changes nothing');
    world.time.set(BASE_TIME + 20 * MINUTE);
    assert.equal(runExpirySweep({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: world.time.clock }).expired, 1, 'the envelope due later expires on a later sweep');
    assert.equal(envelopeRow(world, notDue.envelope.id).state, 'expired');
    assert.equal(outboxOf(world, notDue.envelope.id, 'envelope.expired').length, 1, 'and is announced once');
    assert.equal(outboxOf(world, sent.envelope.id, 'envelope.expired').length, 1, 'earlier expiries are not announced again');
  } finally {
    await world.close();
  }
});

test('[AP-11] an approval or decline at or past expires_at is 409 state_conflict, records no approval, and commits the expiry itself; one millisecond earlier is accepted', async () => {
  const world = await createWorld();
  try {
    const due = BASE_TIME + 10 * MINUTE;
    const iso = new Date(due).toISOString();
    const edge = await sentEnvelope(world, { expiresAt: iso });
    const edgeSession = await openSession(world, edge.token);
    const late = await sentEnvelope(world, { recipients: 2, expiresAt: iso });
    const lateSession = await openSession(world, late.token);
    const declining = await sentEnvelope(world, { expiresAt: iso });
    const decliningSession = await openSession(world, declining.token);

    world.time.set(due - 1);
    const accepted = await postApproval(world, edgeSession, approvalBody(edgeSession.state));
    assert.equal(accepted.status, 200, 'one millisecond before expires_at the approval is accepted');
    assert.equal(envelopeRow(world, edge.envelope.id).state, 'finalizing');

    world.time.set(due);
    const lateVersion = envelopeRow(world, late.envelope.id).version;
    const refused = await postApproval(world, lateSession, approvalBody(lateSession.state));
    assertError(refused, 409, 'state_conflict', 'an approval at expires_at');
    const lateRow = envelopeRow(world, late.envelope.id);
    assert.deepEqual({ state: lateRow.state, version: lateRow.version }, { state: 'expired', version: lateVersion + 1 }, 'the request committed the expiry through the compare-and-set');
    assert.equal(world.rows('approvals', 'WHERE envelope_id = ?', [late.envelope.id]).length, 0, 'no approval');
    assert.equal(world.rows('approval_receipts', 'WHERE envelope_id = ?', [late.envelope.id]).length, 0, 'no receipt');
    assert.equal(world.rows('signing_jobs', 'WHERE envelope_id = ?', [late.envelope.id]).length, 0, 'no reservation');
    assert.deepEqual(world.rows('recipients', 'WHERE envelope_id = ?', [late.envelope.id]).map((entry) => entry.status).sort(), ['expired', 'expired'], 'both recipients are closed');
    assert.equal(auditEvents(world, 'recipient.capabilities_revoked').filter((event) => event.envelope_id === late.envelope.id).length, 1, 'the revocation is recorded');
    const lateAnnounced = outboxOf(world, late.envelope.id, 'envelope.expired');
    assert.equal(lateAnnounced.length, 1, 'the expiry the request committed is announced once');
    assert.equal(lateAnnounced[0].envelope_version, lateVersion + 1);
    assert.equal((await readSession(world, lateSession)).status, 401, 'the session is closed');
    assertError(await postApproval(world, lateSession, approvalBody(lateSession.state)), 401, 'unauthenticated', 'a retry finds no live session');

    world.time.set(due + MINUTE);
    const decliningVersion = envelopeRow(world, declining.envelope.id).version;
    assertError(await postDecline(world, decliningSession, { expected_version: decliningSession.state.envelope_version }), 409, 'state_conflict', 'a decline past expires_at');
    const decliningRow = envelopeRow(world, declining.envelope.id);
    assert.deepEqual({ state: decliningRow.state, version: decliningRow.version }, { state: 'expired', version: decliningVersion + 1 }, 'the decline request committed the expiry, not a decline');
    assert.equal(auditEvents(world, 'recipient.declined').filter((event) => event.envelope_id === declining.envelope.id).length, 0, 'no decline is recorded');
    assert.equal(outboxOf(world, declining.envelope.id, 'envelope.declined').length, 0, 'no decline is announced');
    assert.equal(outboxOf(world, declining.envelope.id, 'envelope.expired').length, 1, 'the expiry is announced once');
    assert.equal(outboxOf(world, edge.envelope.id, 'envelope.expired').length, 0, 'the approved envelope is not announced as expired');

    // The sweep finds nothing left to do for these envelopes.
    assert.equal(runExpirySweep({ db: world.db, onEnvelopeChange: world.ceremony.onEnvelopeChange, clock: world.time.clock }).expired, 0, 'nothing left for the sweeper');
  } finally {
    await world.close();
  }
});
