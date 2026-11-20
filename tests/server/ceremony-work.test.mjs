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
// `closed` with no pending work. Amended without weakening (A-010 row SEC16-PROBE, requests #47
// and #48): that the listeners are closed while the drain waits, and that no new work can start,
// is read from the product itself, not from the host's port table. Both product listeners (TCP and
// the relay socket) are started, and each one's read-only state (ListenerView `listening` and
// `acceptedConnections`) is first checked against connections of the test's own, each premise
// with its own message. While the drain waits, a fresh connection attempt to the product's former
// TCP port follows, and the case fails on product facts only:
// - a listener reports `listening: true`;
// - a listener's accepted-connection count rises (checked again after close() settles);
// - a request or refusal line (`request`, `request_refused_at_shutdown`,
//   `pipelined_request_refused`) is logged after `draining` (checked again after close() settles);
// - the ceremony's work statistics change;
// - the owned-port snapshot shows a LISTEN socket on the former port whose inode is one of this
//   process's own file descriptors, whatever the attempt's outcome and whatever in the process
//   holds it: the product runs here, so it is an untracked product listener or a test helper on
//   the product's port, and either is a fault.
// Where the attempt went is recorded as a diagnostic, never as a pass or a fail: refused, or
// connected to another process's listener, with its endpoints and whether it was a self-connect
// (local endpoint equal to the remote one). The owned-port snapshot is the /proc/net/tcp and tcp6
// rows on that port only, each marked owned only by matching its inode against this process's own
// /proc/self/fd. The attempt writes no byte, and nothing outside this process is inspected or
// touched. The record (no secret, no path) goes to $OPENSIG_VERIFY_OUT/sec16-probe.json, ignored
// output that is never committed and never evidence of a pass, and to a test diagnostic.
// Strengthened (A-010 row SEC16-TESTS, request #54): N1, each view counts exactly its own
// connections (the relay request raises only the relay view's count, the TCP request only the TCP
// view's); N2, the record is read back as written and fails the case if it holds a host-absolute
// path (the working directory, the repository root, the home directory, or any absolute path).
// Extended (A-010 request #30):
// - SHUTDOWN-INFLIGHT and SWEEP-SCHED: the order is the listeners, then every dispatched
//   handler settles (a send held in the blocked notifier), then the ceremony drain, then the
//   sweeper stops, then the database closes, then `closed`; recorded as an event sequence
//   through spies that only observe;
// - PARSE-COUNTS: the parse service's counts are read at least once a minute; a rise logs
//   `parse_counts_rose`, and `closed` carries both totals (the real T033 totals by default).
// The only timers are hang guards, bounded barrier polls and, for "no warning without a rise",
// a few check intervals.

import assert from 'node:assert/strict';
import { mkdirSync, readdirSync, readFileSync, readlinkSync, writeFileSync } from 'node:fs';
import { ServerResponse } from 'node:http';
import { connect } from 'node:net';
import { endianness, homedir } from 'node:os';
import { join } from 'node:path';
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
import { authFile, bearer, cleanup, composedEnv, ENVELOPE_ID, REPO, seedConsent, tempDir } from './support.mjs';

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

// SEC16-PROBE (A-010 request #47): the fresh connection attempt to the product's former port, and
// its diagnostic record. Nothing here is a verdict; the case judges product facts only.

/** App log events that mean a request reached the product's app: dispatched, or refused there. */
const REACHED_APP = new Set(['request', 'request_refused_at_shutdown', 'pipelined_request_refused']);

/** Linux TCP state numbers as /proc/net/tcp prints them (hex), by name. */
const TCP_STATES = Object.freeze({ '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV', '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT', '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK', '0A': 'LISTEN', '0B': 'CLOSING', '0C': 'NEW_SYN_RECV' });

/** One /proc/net/tcp{,6} endpoint, "ADDRESS:PORT" in hex, as text. The address is in host byte order per 32-bit word; the port is exact. */
function endpoint(field) {
  const [hexAddress = '', hexPort = '0'] = field.split(':');
  const bytes = Buffer.from(hexAddress, 'hex');
  if (endianness() === 'LE') for (let at = 0; at + 4 <= bytes.length; at += 4) bytes.subarray(at, at + 4).reverse();
  const port = Number.parseInt(hexPort, 16);
  if (bytes.length === 4) return `${[...bytes].join('.')}:${port}`;
  const groups = [];
  for (let at = 0; at + 2 <= bytes.length; at += 2) groups.push(bytes.readUInt16BE(at).toString(16));
  return `[${groups.join(':')}]:${port}`;
}

/**
 * The owned-port snapshot: the rows of /proc/net/tcp and /proc/net/tcp6 whose local or remote
 * port is `port`, and no other row. A row is `owned` when its socket inode is one of this test
 * process's own file descriptors (/proc/self/fd); no other process's descriptors are read. A read
 * that fails is recorded by source name and error code (no path), never thrown.
 */
function ownedPortSnapshot(port) {
  const snapshot = { port, rows: [], errors: [] };
  const own = new Set();
  try {
    for (const fd of readdirSync('/proc/self/fd')) {
      try {
        const inode = /^socket:\[(\d+)\]$/.exec(readlinkSync(join('/proc/self/fd', fd)))?.[1];
        if (inode !== undefined) own.add(inode);
      } catch {
        // that descriptor closed meanwhile
      }
    }
  } catch (error) {
    snapshot.errors.push({ source: 'own-fds', code: error?.code ?? 'unreadable' });
  }
  for (const family of ['tcp', 'tcp6']) {
    let table;
    try {
      table = readFileSync(join('/proc/net', family), 'latin1');
    } catch (error) {
      snapshot.errors.push({ source: family, code: error?.code ?? 'unreadable' });
      continue;
    }
    for (const line of table.split('\n').slice(1)) {
      const field = line.trim().split(/\s+/);
      if (field.length < 10) continue;
      const [, local, remote, state] = field;
      if (Number.parseInt(local.split(':')[1], 16) !== port && Number.parseInt(remote.split(':')[1], 16) !== port) continue;
      snapshot.rows.push({ family, local: endpoint(local), remote: endpoint(remote), state: TCP_STATES[state] ?? state, uid: Number(field[7]), owned: field[9] !== '0' && own.has(field[9]) });
    }
  }
  return snapshot;
}

/**
 * One fresh connection attempt to 127.0.0.1:`port`, the product's former port. It resolves with
 * where the attempt went, and the owned-port snapshot in either case: not connected (refused, or
 * any other error; the snapshot is taken then), or connected, with its endpoints and whether it is
 * a self-connect, all taken while the socket is still open. The socket is then destroyed; no byte
 * is ever written to it.
 */
function probeFormerPort(port) {
  return new Promise((resolveProbe) => {
    let settled = false;
    const socket = connect({ host: '127.0.0.1', port });
    socket.on('error', (error) => {
      if (settled) return;
      settled = true;
      resolveProbe({ outcome: 'not-connected', code: error?.code ?? 'error', snapshot: ownedPortSnapshot(port) });
    });
    socket.once('connect', () => {
      settled = true;
      const local = { address: socket.localAddress, port: socket.localPort };
      const remote = { address: socket.remoteAddress, port: socket.remotePort };
      const probe = { outcome: 'connected', local, remote, self_connect: local.port === remote.port && local.address === remote.address, snapshot: ownedPortSnapshot(port) };
      socket.destroy();
      resolveProbe(probe);
    });
  });
}

/**
 * The own-listener rule (A-010 request #48, A2): the snapshot's LISTEN sockets on `port` whose inode
 * is one of this process's own descriptors, whatever the probe's outcome and whatever in the
 * process holds them. The product runs in this process, so any is an untracked product listener or
 * a test helper on the product's port; either is a fault.
 */
function ownListeners(probe, port) {
  return probe.snapshot.rows.filter((row) => row.owned && row.state === 'LISTEN' && row.local.endsWith(`:${port}`));
}

/** One line on where the attempt went, for assertion messages (the full record is sec16-probe.json). */
function describeProbe(probe) {
  const rows = `${probe.snapshot.rows.length} row(s) on the port`;
  if (probe.outcome !== 'connected') return `the probe did not connect: ${probe.code}; ${rows}`;
  return `the probe connected ${probe.local.address}:${probe.local.port} to ${probe.remote.address}:${probe.remote.port}, self-connect ${probe.self_connect}; ${rows}`;
}

/**
 * Record the diagnostic whatever the verdict: as a test diagnostic, and as sec16-probe.json in the
 * runner's output directory (OPENSIG_VERIFY_OUT; outside the runner, the gitignored
 * .verify-out/server/). Returns the file written, or null when the write failed, which is
 * ignored: the record is never evidence of a pass. Only N2 reads it back, for host paths.
 */
function recordProbe(t, record) {
  t.diagnostic(`SEC16-PROBE ${JSON.stringify(record)}`);
  try {
    const dir = process.env.OPENSIG_VERIFY_OUT ?? join(REPO, '.verify-out', 'server');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'sec16-probe.json'), `${JSON.stringify(record, null, 2)}\n`);
    return join(dir, 'sec16-probe.json');
  } catch {
    // evidence only
    return null;
  }
}

/**
 * N2 (row SEC16-TESTS, request #54; request #48 C1): every place where the record names a
 * host-absolute path, as its JSON path and the rule it breaks, never the value itself. No string,
 * key or value, may contain the working directory, the repository root or the home directory, or
 * hold an absolute path anywhere (`/…`, `~/…`, `C:\…` or a `file:` URL), as a stack frame with a
 * full path would; stack frames must be repo-relative.
 */
function hostPaths(text) {
  const named = [
    ['working directory', process.cwd()],
    ['repository root', REPO],
    ['home directory', homedir()],
  ].filter(([, value]) => typeof value === 'string' && value.length > 1);
  const found = [];
  const visit = (value, at) => {
    if (typeof value === 'string') {
      for (const [rule, prefix] of named) if (value.includes(prefix)) found.push(`${at}: ${rule}`);
      if (/(?:^|[\s("'=,])(?:\/|~\/|[A-Za-z]:\\)/.test(value) || value.includes('file:')) found.push(`${at}: absolute path`);
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${at}[${index}]`));
    } else if (value !== null && typeof value === 'object') {
      for (const [key, item] of Object.entries(value)) {
        visit(key, `${at} key`);
        visit(item, `${at}.${key}`);
      }
    }
  };
  visit(JSON.parse(text), '$');
  return found;
}

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

test('[SEC-16] shutdown closes the listeners, then waits for pending background ceremony jobs, so none is dropped', async (t) => {
  const relay = await smtpRelay({ held: true });
  const lines = [];
  // Both product listeners (SEC16-PROBE): the TCP listener and the relay socket's.
  const relaySocket = join(tempDir('relay'), 'opensig.sock');
  const env = smtpEnv(relay.port, { OPENSIG_RELAY_SOCKET: relaySocket });
  const running = await guarded(startServer(env, { logSink: (line) => lines.push(line) }), 'startServer');
  const side = testSide(env);
  const records = () => lines.map((line) => JSON.parse(line));
  // Request or refusal lines the product logged after its `draining` line (A-010 request #48, A3).
  const reachedSinceDrain = () => {
    const all = records();
    return all.slice(all.findIndex((record) => record.event === 'draining') + 1).filter((record) => REACHED_APP.has(record.event)).length;
  };
  let closing = null;
  try {
    // The listener state, first against the test's own connections: each listener listens once
    // started and counts a connection made to it. Every premise has its own message (request #48, A5).
    assert.deepEqual(running.listeners.map((listener) => listener.name), ['tcp', 'relay'], 'premise: both product listeners are started');
    for (const listener of running.listeners) assert.equal(listener.listening, true, `premise: the ${listener.name} listener reports listening once started`);
    // N1 (row SEC16-TESTS, request #54): each view counts exactly its own connections, so a view
    // wired to the other listener's server fails here.
    const [tcpView, relayView] = running.listeners;
    const beforeRelay = { tcp: tcpView.acceptedConnections, relay: relayView.acceptedConnections };
    const viaRelay = await call(0, { socketPath: relaySocket, path: `/v1/envelopes/${ENVELOPE_ID}` });
    assert.equal(viaRelay.status, 401, 'premise: the relay listener serves (an operator route, no operator authentication configured)');
    assert.equal(relayView.acceptedConnections - beforeRelay.relay, 1, `premise: the relay request raised the relay listener's count by exactly one (${relayView.acceptedConnections - beforeRelay.relay})`);
    assert.equal(tcpView.acceptedConnections - beforeRelay.tcp, 0, `premise: the relay request left the tcp listener's count unchanged (${tcpView.acceptedConnections - beforeRelay.tcp})`);
    const { token } = await side.sentEnvelope();
    const beforeTcp = { tcp: tcpView.acceptedConnections, relay: relayView.acceptedConnections };
    const response = await postChallenge(running.port, token);
    assert.equal(response.status, 202, `premise: the challenge request over TCP got the generic 202 (${response.status})`);
    assert.equal(tcpView.acceptedConnections - beforeTcp.tcp, 1, `premise: the challenge request over TCP raised the tcp listener's count by exactly one (${tcpView.acceptedConnections - beforeTcp.tcp})`);
    assert.equal(relayView.acceptedConnections - beforeTcp.relay, 0, `premise: the challenge request over TCP left the relay listener's count unchanged (${relayView.acceptedConnections - beforeTcp.relay})`);
    for (const listener of running.listeners) assert.ok(listener.acceptedConnections >= 1, `premise: the ${listener.name} listener counted the test's own connection (${listener.acceptedConnections})`);
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

    // SEC16-PROBE: the product's own state, then a fresh connection attempt to its former port,
    // then two macrotask turns (an accept the attempt caused has been delivered by then), then
    // the record, and only then the verdict, from product facts alone. Where the attempt went
    // decides nothing.
    const before = { accepted: running.listeners.map((listener) => listener.acceptedConnections), work: { ...running.composition.ceremony.challengeWorkStats() } };
    const probe = await probeFormerPort(running.port);
    await turn();
    await turn();
    const record = {
      case: 'SEC-16',
      port: running.port,
      probe,
      product: {
        listeners: running.listeners.map((listener, index) => ({ name: listener.name, listening: listener.listening, accepted_before: before.accepted[index], accepted_after: listener.acceptedConnections })),
        reached_app_since_drain: reachedSinceDrain(),
        work_before: before.work,
        work_after: { ...running.composition.ceremony.challengeWorkStats() },
        own_listeners_on_port: ownListeners(probe, running.port).length,
      },
    };
    const recordPath = recordProbe(t, record);
    // N2 (row SEC16-TESTS, request #54): the record, as written to disk, holds no host-absolute path.
    const recordText = recordPath === null ? JSON.stringify(record) : readFileSync(recordPath, 'utf8');
    assert.deepEqual(hostPaths(recordText), [], 'the SEC16-PROBE record holds no host-absolute path');
    // Each message names its own fact and never repeats the pre-amendment probe's message.
    const where = describeProbe(probe);
    for (const listener of running.listeners) assert.equal(listener.listening, false, `during the drain the ${listener.name} listener still reports listening (${where})`);
    running.listeners.forEach((listener, index) => assert.equal(listener.acceptedConnections, before.accepted[index], `the probe reached the product: the ${listener.name} listener's accepted-connection count rose during the drain (${where})`));
    assert.equal(reachedSinceDrain(), 0, `the probe reached the product: a request or refusal line was logged during the drain (${where})`);
    assert.deepEqual({ ...running.composition.ceremony.challengeWorkStats() }, before.work, `the probe reached the product: the work statistics changed during the drain (${where})`);
    assert.deepEqual(ownListeners(probe, running.port), [], `a LISTEN socket of this test process holds the product's former port during the drain (${where})`);

    relay.release();
    await guarded(closing, 'close() settles once the job is done');
    assert.equal(relay.state.delivered, 1, 'the pending job ran to its end: the code was mailed');
    const events = records().map((record) => record.event);
    const closed = records().find((record) => record.event === 'closed');
    assert.deepEqual({ ...closed?.challenge_work }, { pending: 0, completed: 1, failed: 0 }, 'closed is logged with no pending work');
    assert.ok(events.lastIndexOf('notification_accepted') < events.indexOf('closed'), 'the mail was accepted before the server closed');
    // SEC16-PROBE, once close() settled: no listener accepted anything after its close, and no
    // request reached the app after the drain began.
    running.listeners.forEach((listener, index) => assert.equal(listener.acceptedConnections, before.accepted[index], `after close() settled, the ${listener.name} listener's accepted-connection count had risen since the drain began (${where})`));
    assert.equal(reachedSinceDrain(), 0, `after close() settled, a request or refusal line had been logged since the drain began (${where})`);
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
