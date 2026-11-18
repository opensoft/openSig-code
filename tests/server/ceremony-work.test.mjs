// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-15 (A-010 row T008FU-D5) and SEC-16 (row T008FU-D9), on the composed server
// (src/server/main.ts startServer, row WIRE-US1) with its production defaults: the ceremony's
// default work scheduler and the real T032 notifier, whose SMTP transport talks to a loopback
// relay of the test's own. While that relay withholds its greeting the notifier is blocked.
//
// SEC-15: the generic 202 of requestChallenge is written to the socket before any background
// ceremony step starts. The order is an event sequence recorded inside this process, never a
// time: the 202's ServerResponse 'finish' (its last bytes handed to the operating system) and
// end(), against the composed database's first transaction and invitation lookup, seen
// through a spy on the Database prototype that records only calls on the composition's own
// database while armed. The spy observes; it changes nothing the server does.
//
// SEC-16: shutdown waits for that background work. With a job held in the blocked notifier,
// close() closes the listeners and then does not settle while the job is pending; once the
// relay is released the job's mail is delivered, and only then does close() settle, logging
// `closed` with no pending work. Extended (A-010 request #30):
// - SHUTDOWN-INFLIGHT and SWEEP-SCHED: the order is the listeners, then every dispatched
//   handler settles (a send held in the blocked notifier), then the ceremony drain, then the
//   sweeper stops, then the database closes, then `closed`; recorded as an event sequence
//   through spies that only observe;
// - PARSE-COUNTS: the parse service's counts are read at least once a minute; a rise logs
//   `parse_counts_rose`, and `closed` carries both totals (the real T033 totals by default).
// The only timers are hang guards, bounded barrier polls and, for "no warning without a rise",
// a few check intervals.

import assert from 'node:assert/strict';
import { ServerResponse } from 'node:http';
import { connect } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { after, test } from 'node:test';

import { RecipientCeremony } from '../../src/api/recipients/ceremony.ts';
import { ExpirySweeper } from '../../src/jobs/expiry.ts';
import { parseOrphans, parseStopsPastCap } from '../../src/pdf/service.ts';
// A namespace import, so a head without the parse-count interval fails the assertion, not the module load.
import * as serverMain from '../../src/server/main.ts';

const { PARSE_COUNT_INTERVAL_MS, startServer } = serverMain;
import { Database } from '../../src/storage/db/index.ts';
import { call, FIELDS, guarded, ORIGIN, smtpRelay, testSide, turn } from './composed-support.mjs';
import { authFile, bearer, cleanup, composedEnv, seedConsent } from './support.mjs';

after(cleanup);

const GENERIC_BODY = '{"status":"accepted"}';
const CHALLENGES = '/v1/recipient-session/challenges';

/** A composed environment whose notifier sends through the test's SMTP relay on `port`. */
function smtpEnv(port, overrides = {}) {
  const env = composedEnv({ OPENSIG_ALLOWED_ORIGINS: ORIGIN, OPENSIG_PUBLIC_ORIGIN: ORIGIN, OPENSIG_MAIL_TRANSPORT: 'smtp', OPENSIG_SMTP_HOST: '127.0.0.1', OPENSIG_SMTP_PORT: String(port), OPENSIG_SPOOL_DIR: undefined, ...overrides });
  seedConsent(env.OPENSIG_DATABASE);
  return env;
}

const postChallenge = (port, invitation) => call(port, { method: 'POST', path: CHALLENGES, headers: { origin: ORIGIN }, body: { invitation } });

test('[SEC-15] on the composed server with a blocked notifier, the generic 202 is written to the socket before any background ceremony step starts', async () => {
  const relay = await smtpRelay({ held: true });
  const lines = [];
  const env = smtpEnv(relay.port);
  const running = await guarded(startServer(env, { logSink: (line) => lines.push(line) }), 'startServer');
  const side = testSide(env);
  const observed = { armed: false, events: [] };
  const original = { transaction: Database.prototype.transaction, resolveCapability: Database.prototype.resolveCapability };
  const endWasOwn = Object.hasOwn(ServerResponse.prototype, 'end');
  const end = ServerResponse.prototype.end;
  const composed = (db) => observed.armed && db === running.composition?.db;
  Database.prototype.transaction = function spiedTransaction(...args) {
    if (composed(this)) observed.events.push('transaction');
    return original.transaction.apply(this, args);
  };
  Database.prototype.resolveCapability = function spiedResolve(...args) {
    if (composed(this) && args[0] === 'invitations') observed.events.push('invitation lookup');
    return original.resolveCapability.apply(this, args);
  };
  ServerResponse.prototype.end = function observedEnd(...args) {
    const challenge = observed.armed && this.req?.method === 'POST' && this.req?.url === CHALLENGES && this.statusCode === 202;
    if (challenge) this.once('finish', () => observed.events.push('202 written'));
    const result = end.apply(this, args);
    if (challenge) observed.events.push(this.writableEnded ? '202 ended' : '202 end() returned without ending');
    return result;
  };
  try {
    const { token } = await side.sentEnvelope();
    observed.armed = true;
    const response = await guarded(postChallenge(running.port, token), 'the 202 while the notifier is blocked');
    // The mail step has started (the relay holds its connection), so every earlier step ran.
    await guarded(relay.until((state) => state.connections === 1), 'the composed notifier reached the relay');
    observed.armed = false;
    const sequence = observed.events.join(' > ');
    assert.equal(response.status, 202);
    assert.equal(response.bytes.toString('utf8'), GENERIC_BODY, 'the complete generic body');
    assert.equal(relay.state.delivered, 0, 'the 202 arrived while the mail was blocked');
    assert.equal(running.composition.ceremony.challengeWorkStats().pending, 1, 'the request\'s work is pending in the blocked notifier');
    const written = observed.events.indexOf('202 written');
    assert.ok(written >= 0 && observed.events.includes('202 ended'), `the 202 was ended and written (observed: ${sequence})`);
    for (const step of ['transaction', 'invitation lookup']) {
      const index = observed.events.indexOf(step);
      assert.ok(index >= 0, `the background ${step} ran and was observed (observed: ${sequence})`);
      assert.ok(written < index, `the 202 was written to the socket before the first ${step} (observed: ${sequence})`);
    }
    relay.release();
    await guarded(running.composition.ceremony.drain(), 'the released work settles');
    assert.equal(relay.state.delivered, 1, 'once released, the code was mailed');
    assert.deepEqual({ ...running.composition.ceremony.challengeWorkStats() }, { pending: 0, completed: 1, failed: 0 });
  } finally {
    observed.armed = false;
    Database.prototype.transaction = original.transaction;
    Database.prototype.resolveCapability = original.resolveCapability;
    if (endWasOwn) ServerResponse.prototype.end = end;
    else delete ServerResponse.prototype.end;
    relay.release();
    side.close();
    await running.close();
    await relay.close();
  }
});

test('[SEC-16] shutdown closes the listeners, then waits for pending background ceremony jobs, so none is dropped', async () => {
  const relay = await smtpRelay({ held: true });
  const lines = [];
  const env = smtpEnv(relay.port);
  const running = await guarded(startServer(env, { logSink: (line) => lines.push(line) }), 'startServer');
  const side = testSide(env);
  const records = () => lines.map((line) => JSON.parse(line));
  let closing = null;
  try {
    const { token } = await side.sentEnvelope();
    const response = await postChallenge(running.port, token);
    assert.equal(response.status, 202);
    await guarded(relay.until((state) => state.connections === 1), 'the job reached the blocked notifier');
    assert.equal(running.composition.ceremony.challengeWorkStats().pending, 1, 'premise: one job pending');

    let settled = false;
    closing = running.close();
    closing.then(() => {
      settled = true;
    });
    // Barrier: shutdown reached its drain (or settled without one), then two macrotask turns.
    const started = Date.now();
    while (!settled && !records().some((record) => record.event === 'draining')) {
      if (Date.now() - started > 5_000) assert.fail('shutdown neither reached its drain nor settled (hang guard 5000 ms)');
      await sleep(5);
    }
    await turn();
    await turn();
    assert.equal(settled, false, 'close() does not settle while a background job is pending');
    assert.equal(running.composition.ceremony.challengeWorkStats().pending, 1, 'the job is still pending, not dropped');
    assert.equal(records().find((record) => record.event === 'draining')?.challenge_work_pending, 1, 'the drain names the pending job');
    const refused = await new Promise((resolveConnect) => {
      const socket = connect({ host: '127.0.0.1', port: running.port });
      socket.on('connect', () => {
        socket.destroy();
        resolveConnect(false);
      });
      socket.on('error', () => resolveConnect(true));
    });
    assert.equal(refused, true, 'the listeners are closed while the drain waits: no new work can start');

    relay.release();
    await guarded(closing, 'close() settles once the job is done');
    assert.equal(relay.state.delivered, 1, 'the pending job ran to its end: the code was mailed');
    const events = records().map((record) => record.event);
    const closed = records().find((record) => record.event === 'closed');
    assert.deepEqual({ ...closed?.challenge_work }, { pending: 0, completed: 1, failed: 0 }, 'closed is logged with no pending work');
    assert.ok(events.lastIndexOf('notification_accepted') < events.indexOf('closed'), 'the mail was accepted before the server closed');
  } finally {
    relay.release();
    if (closing !== null) await guarded(closing, 'final close');
    side.close();
    await running.close();
    await relay.close();
  }
});

/** Barrier: poll `check` with a bounded sleep until it holds, failing with `label` at the guard. */
async function until(check, label, ms = 5_000) {
  const started = Date.now();
  while (!check()) {
    if (Date.now() - started > ms) assert.fail(`${label} (hang guard ${ms} ms)`);
    await sleep(5);
  }
}

test('[SEC-16] shutdown order: listeners, then dispatched handlers settle, then the ceremony drain, then the sweeper stops, then the database closes', async () => {
  const relay = await smtpRelay({ held: true });
  const order = [];
  const lines = [];
  // Operator authentication too: the in-flight handler is an operator send.
  const env = smtpEnv(relay.port, { OPENSIG_OPERATOR_AUTH_FILE: authFile() });
  const sink = (line) => {
    lines.push(line);
    if (line.includes('"event":"request"') && line.includes('"operation":"sendEnvelope"')) order.push('handler settled');
    if (line.includes('"event":"closed"')) order.push('closed');
  };
  const running = await guarded(startServer(env, { logSink: sink }), 'startServer');
  const side = testSide(env);
  const records = () => lines.map((line) => JSON.parse(line));
  const original = { drain: RecipientCeremony.prototype.drain, stop: ExpirySweeper.prototype.stop, close: Database.prototype.close };
  RecipientCeremony.prototype.drain = function spiedDrain(...args) {
    if (this !== running.composition.ceremony) return original.drain.apply(this, args);
    order.push('drain called');
    return original.drain.apply(this, args).then(() => {
      order.push('drain settled');
    });
  };
  ExpirySweeper.prototype.stop = function spiedStop(...args) {
    if (this === running.composition.sweeper) order.push('sweeper stopped');
    return original.stop.apply(this, args);
  };
  Database.prototype.close = function spiedClose(...args) {
    if (this === running.composition.db) order.push('database closed');
    return original.close.apply(this, args);
  };
  let closing = null;
  try {
    // A prepared envelope to send through the HTTP API, and a live invitation for a challenge.
    const { envelope: uploaded } = side.recordDocument(side.draft());
    const prepared = side.service.prepare(side.req(), uploaded.id, { expected_version: uploaded.version, fields: FIELDS }).body;
    const { token } = await side.sentEnvelope();
    // 1. An in-flight handler: the send commits, then waits in the blocked notifier for its invitation mail.
    const sending = call(running.port, { method: 'POST', path: `/v1/envelopes/${prepared.id}/send`, headers: { authorization: `Bearer ${bearer('sender')}`, 'idempotency-key': `ik-${'s'.repeat(24)}` }, body: { expected_version: prepared.version } }).catch(() => null);
    // The send must still be in flight when the relay sees its mail; an early answer fails here with its status.
    const early = sending.then((response) => {
      throw new Error(`the send answered before its mail reached the relay: ${response?.status} ${response?.json?.code ?? ''}`);
    });
    early.catch(() => {});
    await guarded(Promise.race([relay.until((state) => state.connections === 1), early]), 'the send handler reached the blocked notifier');
    // 2. Background work: a challenge job, also held in the notifier.
    assert.equal((await postChallenge(running.port, token)).status, 202);
    await guarded(relay.until((state) => state.connections === 2), 'the challenge job reached the blocked notifier');
    assert.deepEqual(order, [], 'premise: nothing has settled or closed');

    let settled = false;
    closing = running.close();
    closing.then(() => {
      settled = true;
    });
    await until(() => settled || records().some((record) => record.event === 'shutdown'), 'shutdown started');
    await turn();
    await turn();
    assert.equal(records().find((record) => record.event === 'shutdown')?.handlers_in_flight, 1, 'shutdown names the handler in flight');
    assert.deepEqual(order, [], 'while a dispatched handler runs, no drain starts and the database stays open');
    assert.equal(settled, false);

    // 3. The handler's mail goes out: the handler settles, and only then does the drain start.
    relay.releaseOne();
    await until(() => order.includes('drain called'), 'the drain started after the handler settled');
    await turn();
    await turn();
    assert.deepEqual(order, ['handler settled', 'drain called'], 'the handler settled before the drain; the job is still pending');
    assert.equal(settled, false, 'close() waits for the drain');

    // 4. The job's mail goes out: the drain settles, then the sweeper stops, then the database closes.
    relay.releaseOne();
    await guarded(closing, 'close() settles');
    assert.deepEqual(order, ['handler settled', 'drain called', 'drain settled', 'sweeper stopped', 'database closed', 'closed'], 'the shutdown order (SHUTDOWN-INFLIGHT, SWEEP-SCHED)');
    assert.equal(relay.state.delivered, 2, 'both mails were delivered: nothing was dropped');
    const closed = records().find((record) => record.event === 'closed');
    assert.deepEqual({ ...closed.challenge_work }, { pending: 0, completed: 1, failed: 0 });
    // PARSE-COUNTS: the closed line carries the parse service's process-wide totals.
    assert.deepEqual([closed.parse_orphans_ended, closed.parse_stops_past_cap], [parseOrphans().orphans_ended, parseStopsPastCap().stops_past_cap]);
    await sending;
  } finally {
    RecipientCeremony.prototype.drain = original.drain;
    ExpirySweeper.prototype.stop = original.stop;
    Database.prototype.close = original.close;
    relay.release();
    if (closing !== null) await guarded(closing, 'final close');
    side.close();
    await running.close();
    await relay.close();
  }
});

test('[SEC-16] the parse service counts are read at least once a minute: a rise logs a warning, and closed carries the totals', async () => {
  assert.ok(PARSE_COUNT_INTERVAL_MS <= 60_000, 'the production check runs at least once a minute');
  const INTERVAL_MS = 20;
  const counts = { orphans_ended: 0, stops_past_cap: 0 };
  const lines = [];
  const warnings = () => lines.map((line) => JSON.parse(line)).filter((record) => record.event === 'parse_counts_rose');
  const running = await guarded(startServer(composedEnv(), { logSink: (line) => lines.push(line), parseCounts: () => ({ ...counts }), parseCountIntervalMs: INTERVAL_MS }), 'startServer');
  try {
    await sleep(5 * INTERVAL_MS);
    assert.deepEqual(warnings(), [], 'no warning while the counts stay put');
    counts.orphans_ended = 1;
    await until(() => warnings().length === 1, 'a rise of orphans_ended is warned at the next check');
    assert.deepEqual((({ orphans_ended, stops_past_cap, orphans_ended_before, stops_past_cap_before }) => ({ orphans_ended, stops_past_cap, orphans_ended_before, stops_past_cap_before }))(warnings()[0]), { orphans_ended: 1, stops_past_cap: 0, orphans_ended_before: 0, stops_past_cap_before: 0 });
    counts.stops_past_cap = 2;
    await until(() => warnings().length === 2, 'a rise of stops_past_cap is warned at the next check');
    assert.deepEqual([warnings()[1].stops_past_cap, warnings()[1].stops_past_cap_before], [2, 0]);
    await sleep(5 * INTERVAL_MS);
    assert.equal(warnings().length, 2, 'each rise is warned once');
  } finally {
    counts.orphans_ended = 3;
    await running.close();
  }
  // The last read at shutdown warns a rise the interval had not seen yet, and closed carries the totals.
  assert.equal(warnings().length, 3, 'the shutdown read warned the last rise');
  const closed = lines.map((line) => JSON.parse(line)).find((record) => record.event === 'closed');
  assert.deepEqual([closed.parse_orphans_ended, closed.parse_stops_past_cap], [3, 2]);

  // By default the counts are T033's own process-wide totals.
  const defaults = [];
  const real = await guarded(startServer(composedEnv(), { logSink: (line) => defaults.push(line) }), 'startServer (default reader)');
  await real.close();
  const realClosed = defaults.map((line) => JSON.parse(line)).find((record) => record.event === 'closed');
  assert.deepEqual([realClosed.parse_orphans_ended, realClosed.parse_stops_past_cap], [parseOrphans().orphans_ended, parseStopsPastCap().stops_past_cap]);
});
