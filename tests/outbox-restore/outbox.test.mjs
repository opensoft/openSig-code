// SPDX-License-Identifier: Apache-2.0
//
// Transactional outbox (T030): OR-01 the event commits exactly with the state
// change it announces; OR-02 every delivery attempt, including a redelivery
// after a crash before acknowledgement, carries the same event_id and bytes;
// OR-05 retries are bounded (backoff cap, attempts, horizon, non-retryable).

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { canonicalize } from '../../src/domain/canonical/index.ts';
import { StorageConstraintError, StorageUsageError } from '../../src/storage/db/index.ts';
import { enqueueOutboxEvent, OutboxDispatcher, RETRY_HORIZON_MS } from '../../src/storage/outbox/index.ts';
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
