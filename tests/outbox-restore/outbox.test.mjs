// SPDX-License-Identifier: Apache-2.0
//
// Transactional outbox (T030): OR-01 the event commits exactly with the state
// change it announces; OR-02 every delivery attempt, including a redelivery
// after a crash before acknowledgement, carries the same event_id and bytes;
// OR-05 retries are bounded (backoff cap, attempts, horizon, non-retryable);
// OR-14 reclaiming an expired claim is held to the same bounds; OR-25 a late
// settle after an abandon on reclaim changes nothing.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { canonicalize } from '../../src/domain/canonical/index.ts';
import { StorageConstraintError, StorageUsageError } from '../../src/storage/db/index.ts';
import { ATTEMPTS_EXHAUSTED, enqueueOutboxEvent, OutboxDispatcher, RETRY_HORIZON_MS, RETRY_HORIZON_PASSED } from '../../src/storage/outbox/index.ts';
import { makeScratch } from '../storage/support/fixtures.mjs';
import { addEnvelope, BASE_TIME, createTenant, environment, sid, terminalEnvelope, ts } from '../audit-chain/support/chain.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

function controllableClock(start = BASE_TIME) {
  const state = { now: start };
  return { state, clock: () => new Date(state.now) };
}

function voidEnvelope(db, tenant, envelopeId, clock, { fail = false } = {}) {
  return db.transaction(() => {
    const store = db.forTenant(tenant);
    assert.equal(store.compareAndSet('envelopes', { id: envelopeId }, 1, { state: 'voided', updated_at: ts(30) }), true);
    const event = enqueueOutboxEvent(db, tenant, { type: 'envelope.voided', envelopeId, envelopeVersion: 2 }, { clock });
    if (fail) throw new Error('synthetic failure after the state change');
    return event;
  });
}

test('[OR-01] an outbox event is inserted in the transaction of the state change it announces, with a fixed event_id', () => {
  const { db, blobs } = environment(scratch);
  try {
    const tenant = sid('tenant');
    const other = sid('tenant');
    createTenant(db, tenant);
    createTenant(db, other);
    const { clock } = controllableClock();
    const store = db.forTenant(tenant);

    const rolledBack = addEnvelope(db, tenant);
    assert.throws(() => voidEnvelope(db, tenant, rolledBack, clock, { fail: true }), /synthetic failure/);
    assert.equal(store.count('outbox_events'), 0, 'no event without the state change');
    assert.equal(store.get('envelopes', { id: rolledBack }).state, 'draft');

    const envelope = addEnvelope(db, tenant);
    const event = voidEnvelope(db, tenant, envelope, clock);
    const rows = store.list('outbox_events');
    assert.equal(rows.length, 1);
    const row = rows[0];
    assert.equal(row.event_id, event.eventId);
    assert.deepEqual(event.payload, {
      event_id: event.eventId,
      schema_version: '1',
      type: 'envelope.voided',
      envelope_id: envelope,
      envelope_version: 2,
      artifact_id: null,
      artifact_digest: null,
      occurred_at: new Date(BASE_TIME).toISOString(),
    });
    assert.equal(row.payload_json, canonicalize(event.payload), 'the stored payload is canonical and carries the event_id');
    assert.deepEqual(event.body, Buffer.from(row.payload_json, 'utf8'));
    assert.deepEqual([row.attempts, row.acknowledged_at, row.next_attempt_at], [0, null, null]);

    const completed = terminalEnvelope(db, blobs, tenant, { state: 'completed' });
    const artifact = store.get('final_artifacts', { envelope_id: completed.env });
    const completion = { type: 'envelope.completed', envelopeId: completed.env, envelopeVersion: 2, artifactId: artifact.artifact_id, artifactDigest: artifact.artifact_digest };
    db.transaction(() => enqueueOutboxEvent(db, tenant, completion, { clock }));
    assert.throws(
      () => db.transaction(() => enqueueOutboxEvent(db, tenant, completion, { clock })),
      (error) => error instanceof StorageConstraintError && error.constraint === 'unique',
      'one completion event per envelope',
    );

    const usage = (input, pattern, tenantId = tenant) =>
      assert.throws(() => db.transaction(() => enqueueOutboxEvent(db, tenantId, input, { clock })), (error) => error instanceof StorageUsageError && pattern.test(error.message));
    usage({ type: 'envelope.voided', envelopeId: envelope, envelopeVersion: 1 }, /envelope version written in this transaction/);
    usage({ type: 'envelope.approved', envelopeId: envelope, envelopeVersion: 2 }, /not a webhook event type/);
    usage({ type: 'envelope.completed', envelopeId: envelope, envelopeVersion: 2 }, /needs the artifact/);
    usage({ type: 'envelope.voided', envelopeId: envelope, envelopeVersion: 2, artifactId: artifact.artifact_id }, /carries no artifact/);
    usage({ type: 'envelope.voided', envelopeId: envelope, envelopeVersion: 2 }, /does not exist in this tenant/, other);
    assert.throws(() => enqueueOutboxEvent(db, tenant, { type: 'envelope.voided', envelopeId: envelope, envelopeVersion: 2 }, { clock }), /inside the transaction/);
    assert.equal(store.count('outbox_events'), 2);
  } finally {
    db.close();
  }
});

test('[OR-02] retries and a redelivery after a crash before acknowledgement keep the same event_id and bytes', async () => {
  const { db } = environment(scratch);
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const { state, clock } = controllableClock();
    const event = voidEnvelope(db, tenant, addEnvelope(db, tenant), clock);

    const attempts = [];
    const outcomes = [{ ok: false, errorCode: 'http_503' }, { ok: false, errorCode: 'timeout' }, { ok: true }];
    const dispatcher = new OutboxDispatcher({
      db,
      clock,
      deliver: async (attempt) => {
        attempts.push(attempt);
        return outcomes[attempts.length - 1];
      },
    });

    assert.deepEqual((await dispatcher.dispatch(tenant)).retrying, [event.eventId]);
    const row = () => db.forTenant(tenant).get('outbox_events', { event_id: event.eventId });
    assert.equal(row().next_attempt_at, new Date(state.now + 30_000).toISOString(), 'first retry after 30 s');
    assert.equal(row().last_error_code, 'http_503');
    state.now += 10_000;
    assert.deepEqual(await dispatcher.dispatch(tenant), { delivered: [], retrying: [], abandoned: [] }, 'not due yet');
    state.now += 21_000;
    await dispatcher.dispatch(tenant);
    assert.equal(row().next_attempt_at, new Date(state.now + 60_000).toISOString(), 'the delay doubles');
    state.now += 60_000;
    assert.deepEqual((await dispatcher.dispatch(tenant)).delivered, [event.eventId]);
    assert.equal(row().acknowledged_at, new Date(state.now).toISOString());
    assert.deepEqual([row().attempts, row().next_attempt_at, row().last_error_code], [3, null, null]);
    state.now += 3_600_000;
    assert.deepEqual(await dispatcher.dispatch(tenant), { delivered: [], retrying: [], abandoned: [] }, 'acknowledged events are not redelivered');

    assert.deepEqual(attempts.map((attempt) => attempt.attempt), [1, 2, 3]);
    for (const attempt of attempts) {
      assert.equal(attempt.eventId, event.eventId);
      assert.deepEqual(attempt.body, event.body, 'identical bytes on every attempt');
      assert.equal(JSON.parse(attempt.body.toString('utf8')).event_id, event.eventId);
    }

    // Crash after the claim, with the delivery in flight and no acknowledgement.
    const second = voidEnvelope(db, tenant, addEnvelope(db, tenant), clock);
    const received = [];
    const consumer = new Set();
    const crashed = new OutboxDispatcher({ db, clock, deliver: (attempt) => (received.push(attempt), new Promise(() => {})) });
    void crashed.dispatch(tenant);
    await new Promise((settle) => setImmediate(settle));
    assert.equal(received.length, 1);
    consumer.add(received[0].eventId);
    const restarted = new OutboxDispatcher({ db, clock, deliver: async (attempt) => (received.push(attempt), consumer.add(attempt.eventId), { ok: true }) });
    assert.deepEqual(await restarted.dispatch(tenant), { delivered: [], retrying: [], abandoned: [] }, 'the claim window holds the event');
    state.now += 60_001;
    assert.deepEqual((await restarted.dispatch(tenant)).delivered, [second.eventId]);
    assert.deepEqual(received.map((attempt) => [attempt.eventId, attempt.attempt]), [
      [second.eventId, 1],
      [second.eventId, 2],
    ]);
    assert.deepEqual(received[0].body, received[1].body);
    assert.equal(consumer.size, 1, 'a consumer deduplicating on event_id sees one event');
  } finally {
    db.close();
  }
});

test('[OR-05] retries are bounded: capped backoff, maximum attempts, the 72-hour horizon and non-retryable failures', async () => {
  const { db } = environment(scratch);
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const { state, clock } = controllableClock();
    const failures = new Map();
    const make = (options) =>
      new OutboxDispatcher({
        db,
        clock,
        deliver: async (attempt) => failures.get(attempt.eventId) ?? { ok: false, errorCode: 'http_500' },
        ...options,
      });

    const nonRetryable = voidEnvelope(db, tenant, addEnvelope(db, tenant), clock);
    failures.set(nonRetryable.eventId, { ok: false, errorCode: 'http_410', retryable: false });
    const invalidCode = voidEnvelope(db, tenant, addEnvelope(db, tenant), clock);
    failures.set(invalidCode.eventId, { ok: false, errorCode: 'Not A Code!' });
    let summary = await make({}).dispatch(tenant);
    assert.deepEqual(summary.abandoned, [nonRetryable.eventId]);
    assert.deepEqual(summary.retrying, [invalidCode.eventId]);
    const store = db.forTenant(tenant);
    assert.equal(store.get('outbox_events', { event_id: invalidCode.eventId }).last_error_code, 'delivery_failed');
    const dispatcher = make({});
    assert.deepEqual(dispatcher.abandoned(tenant).map((row) => row.event_id), [nonRetryable.eventId]);

    // maxAttempts: the third failure abandons.
    const capped = make({ maxAttempts: 3, baseDelayMs: 1_000 });
    const abandoned = [];
    for (let i = 0; i < 3; i += 1) {
      state.now += 40_000;
      abandoned.push(...(await capped.dispatch(tenant)).abandoned);
    }
    assert.deepEqual(abandoned, [invalidCode.eventId]);
    assert.equal(store.get('outbox_events', { event_id: invalidCode.eventId }).attempts, 3);

    // Backoff cap and the retry horizon.
    const horizonEvent = voidEnvelope(db, tenant, addEnvelope(db, tenant), clock);
    const createdAt = state.now;
    const slow = make({ baseDelayMs: 1_000, maxDelayMs: 4_000, horizonMs: 20_000, maxAttempts: 100 });
    const delays = [];
    for (let i = 0; i < 10; i += 1) {
      summary = await slow.dispatch(tenant);
      const next = store.get('outbox_events', { event_id: horizonEvent.eventId }).next_attempt_at;
      if (next === null) break;
      delays.push(Date.parse(next) - state.now);
      state.now = Date.parse(next);
    }
    assert.deepEqual(delays.slice(0, 4), [1_000, 2_000, 4_000, 4_000], 'exponential, capped at maxDelayMs');
    const final = store.get('outbox_events', { event_id: horizonEvent.eventId });
    assert.equal(final.next_attempt_at, null, 'no retry is scheduled past the horizon');
    assert.ok(state.now - createdAt <= 20_000);
    assert.equal(RETRY_HORIZON_MS, 72 * 3600 * 1000);

    assert.throws(() => new OutboxDispatcher({ db, clock }), /deliver function/);
    assert.throws(() => new OutboxDispatcher({ db, clock, deliver: async () => ({ ok: true }), baseDelayMs: 0 }), /positive integer/);
  } finally {
    db.close();
  }
});

test('[OR-14] reclaiming an expired claim enforces maxAttempts and the retry horizon: the event is abandoned without another delivery', async () => {
  const { db } = environment(scratch);
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const { state, clock } = controllableClock();
    const store = db.forTenant(tenant);
    const row = (eventId) => store.get('outbox_events', { event_id: eventId });
    const settle = () => new Promise((resolve) => setImmediate(resolve));

    // maxAttempts 1: the only attempt is claimed, then the dispatcher dies
    // with the delivery in flight.
    const single = voidEnvelope(db, tenant, addEnvelope(db, tenant), clock);
    const inFlight = [];
    let release;
    const crashed = new OutboxDispatcher({
      db,
      clock,
      maxAttempts: 1,
      deliver: (attempt) => (inFlight.push(attempt), new Promise((resolve) => (release = resolve))),
    });
    const pending = crashed.dispatch(tenant);
    await settle();
    assert.deepEqual(inFlight.map((attempt) => attempt.attempt), [1]);
    assert.equal(row(single.eventId).attempts, 1);

    state.now += 60_001; // the claim window has passed
    const redelivered = [];
    const restarted = new OutboxDispatcher({ db, clock, maxAttempts: 1, deliver: async (attempt) => (redelivered.push(attempt), { ok: true }) });
    assert.deepEqual(await restarted.dispatch(tenant), { delivered: [], retrying: [], abandoned: [single.eventId] });
    assert.deepEqual(redelivered, [], 'deliver() is not called past maxAttempts');
    assert.deepEqual(
      [row(single.eventId).attempts, row(single.eventId).next_attempt_at, row(single.eventId).last_error_code],
      [1, null, ATTEMPTS_EXHAUSTED],
    );
    assert.deepEqual(restarted.abandoned(tenant).map((event) => event.event_id), [single.eventId]);
    state.now += 3_600_000;
    assert.deepEqual(await restarted.dispatch(tenant), { delivered: [], retrying: [], abandoned: [] }, 'an abandoned event stays abandoned');
    // The original attempt finishing late changes nothing (OR-25).
    release({ ok: true });
    assert.deepEqual((await pending).abandoned, [single.eventId]);
    assert.deepEqual([row(single.eventId).attempts, row(single.eventId).acknowledged_at, row(single.eventId).last_error_code], [1, null, ATTEMPTS_EXHAUSTED]);

    // The horizon: a retry is claimed just inside it, the dispatcher dies, and
    // the claim expires after the horizon has passed.
    const late = voidEnvelope(db, tenant, addEnvelope(db, tenant), clock);
    const createdAt = Date.parse(row(late.eventId).created_at);
    const options = { db, clock, horizonMs: 120_000, baseDelayMs: 100_000, maxAttempts: 50 };
    const failing = new OutboxDispatcher({ ...options, deliver: async () => ({ ok: false, errorCode: 'http_503' }) });
    assert.deepEqual((await failing.dispatch(tenant)).retrying, [late.eventId]);
    state.now = Date.parse(row(late.eventId).next_attempt_at);
    const hung = [];
    const stalled = new OutboxDispatcher({ ...options, deliver: (attempt) => (hung.push(attempt), new Promise(() => {})) });
    void stalled.dispatch(tenant);
    await settle();
    assert.deepEqual(hung.map((attempt) => attempt.attempt), [2]);
    state.now += 60_001;
    assert.ok(state.now > createdAt + 120_000, 'the claim expired after the horizon');
    const afterHorizon = [];
    const recovering = new OutboxDispatcher({ ...options, deliver: async (attempt) => (afterHorizon.push(attempt), { ok: true }) });
    assert.deepEqual(await recovering.dispatch(tenant), { delivered: [], retrying: [], abandoned: [late.eventId] });
    assert.deepEqual(afterHorizon, [], 'deliver() is not called past the horizon');
    assert.deepEqual([row(late.eventId).attempts, row(late.eventId).next_attempt_at, row(late.eventId).last_error_code], [2, null, RETRY_HORIZON_PASSED]);

    // Within both bounds an expired claim is still redelivered (OR-02).
    const ok = voidEnvelope(db, tenant, addEnvelope(db, tenant), clock);
    const firstTry = new OutboxDispatcher({ db, clock, maxAttempts: 3, deliver: () => new Promise(() => {}) });
    void firstTry.dispatch(tenant);
    await settle();
    state.now += 60_001;
    const retried = [];
    const second = new OutboxDispatcher({ db, clock, maxAttempts: 3, deliver: async (attempt) => (retried.push(attempt.attempt), { ok: true }) });
    assert.deepEqual((await second.dispatch(tenant)).delivered, [ok.eventId]);
    assert.deepEqual(retried, [2]);
  } finally {
    db.close();
  }
});

test('[OR-25] a late settle after an abandon on reclaim changes nothing: attempts_exhausted and retry_horizon_passed stay recorded, nothing is acknowledged or rescheduled', async () => {
  const { db } = environment(scratch);
  try {
    const { state, clock } = controllableClock();
    const settle = () => new Promise((resolve) => setImmediate(resolve));
    const setup = () => {
      const tenant = sid('tenant');
      createTenant(db, tenant);
      const store = db.forTenant(tenant);
      const { eventId } = voidEnvelope(db, tenant, addEnvelope(db, tenant), clock);
      return { tenant, eventId, row: () => ({ ...store.get('outbox_events', { event_id: eventId }) }) };
    };
    /** Crash-reclaim cycles: every dispatcher dies with its delivery in flight. */
    async function crashCycles(tenant, cycles, options) {
      const inFlight = [];
      for (let cycle = 0; cycle < cycles; cycle += 1) {
        const dispatcher = new OutboxDispatcher({ db, clock, ...options, deliver: (attempt) => new Promise((resolve) => inFlight.push({ attempt: attempt.attempt, resolve })) });
        const pending = dispatcher.dispatch(tenant);
        await settle();
        if (inFlight.length > 0 && inFlight.at(-1).pending === undefined) inFlight.at(-1).pending = pending;
        state.now += 60_001;
      }
      return inFlight;
    }
    const noDelivery = (options) => new OutboxDispatcher({ db, clock, ...options, deliver: async () => assert.fail('deliver() after the event was abandoned') });

    // maxAttempts 3: three attempts hang, the reclaim abandons the event.
    const failing = setup();
    const failingHung = await crashCycles(failing.tenant, 3, { maxAttempts: 3 });
    assert.deepEqual(failingHung.map((hung) => hung.attempt), [1, 2, 3]);
    assert.deepEqual(await noDelivery({ maxAttempts: 3 }).dispatch(failing.tenant), { delivered: [], retrying: [], abandoned: [failing.eventId] });
    const exhausted = failing.row();
    assert.deepEqual([exhausted.attempts, exhausted.next_attempt_at, exhausted.acknowledged_at, exhausted.last_error_code], [3, null, null, ATTEMPTS_EXHAUSTED]);
    // Every hung attempt now fails late, retryably.
    for (const hung of failingHung) hung.resolve({ ok: false, errorCode: 'http_503', retryable: true });
    const failingSummaries = await Promise.all(failingHung.map((hung) => hung.pending));
    assert.deepEqual(failing.row(), exhausted, 'a late failure neither reschedules nor relabels the abandoned event');
    assert.deepEqual(failingSummaries.at(-1), { delivered: [], retrying: [], abandoned: [failing.eventId] });

    // The same, finishing late with a success: not acknowledged.
    const succeeding = setup();
    const succeedingHung = await crashCycles(succeeding.tenant, 3, { maxAttempts: 3 });
    await noDelivery({ maxAttempts: 3 }).dispatch(succeeding.tenant);
    const abandoned = succeeding.row();
    assert.equal(abandoned.last_error_code, ATTEMPTS_EXHAUSTED);
    for (const hung of succeedingHung) hung.resolve({ ok: true });
    const succeedingSummaries = await Promise.all(succeedingHung.map((hung) => hung.pending));
    assert.deepEqual(succeeding.row(), abandoned, 'a late success does not acknowledge the abandoned event');
    assert.deepEqual(succeedingSummaries.at(-1).abandoned, [succeeding.eventId]);

    // The horizon: the third cycle abandons on reclaim; the second attempt then fails late, non-retryably.
    const horizon = setup();
    const horizonOptions = { maxAttempts: 50, horizonMs: 120_000 };
    const horizonHung = await crashCycles(horizon.tenant, 3, horizonOptions);
    assert.deepEqual(horizonHung.map((hung) => hung.attempt), [1, 2]);
    const passed = horizon.row();
    assert.deepEqual([passed.attempts, passed.next_attempt_at, passed.last_error_code], [2, null, RETRY_HORIZON_PASSED]);
    for (const hung of horizonHung) hung.resolve({ ok: false, errorCode: 'http_400', retryable: false });
    await Promise.all(horizonHung.map((hung) => hung.pending));
    assert.deepEqual(horizon.row(), passed, 'retry_horizon_passed stays recorded');

    // Hours later, none of them is delivered again.
    state.now += 7_200_000;
    for (const { tenant } of [failing, succeeding]) assert.deepEqual(await noDelivery({ maxAttempts: 3 }).dispatch(tenant), { delivered: [], retrying: [], abandoned: [] });
    assert.deepEqual(await noDelivery(horizonOptions).dispatch(horizon.tenant), { delivered: [], retrying: [], abandoned: [] });
  } finally {
    db.close();
  }
});
