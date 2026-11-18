// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-08 (A-009 LBR-2) and SEC-10 (A-010 LBR4-1), over raw loopback sockets.
//
// SEC-08: once a response with `Connection: close` is decided, no later pipelined request on
// that connection is parsed or dispatched: its handler never runs, it gets no response and
// no `request` log line. That holds for a request that arrives later, for one already
// buffered in the same packet, and after a request that itself asked for close (there Node's
// parser refuses any byte after the close request; since SEC-11 the close request still gets
// its own response, see pipelining.test.mjs); ordinary keep-alive pipelining still works.
// SEC-10: a request body that goes idle for 10 s, or arrives below the minimum rate once the
// 10 s grace has passed, is answered with 408 and a connection close by a per-request timer
// (not Node's 30 s check interval); a body that pauses for less than that is accepted.
// SEC-10 (A-010 row REQ-TIMEOUT): that timer is the body bound, so Node's request timeout on
// the entrypoint's listeners is only the outer backstop: never shorter than the longest request
// SEC-10 admits (headers, the PDF limit at the minimum rate, and the one wait before a body read,
// a pre-body transaction's busy timeout; the parse plan is settled at startup, A-010 request #32).

import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { after, before, test } from 'node:test';

import * as serverConfig from '../../src/server/config.ts';
// A namespace import, so a head without the derived timeouts fails the assertions, not the module load.
import * as serverMain from '../../src/server/main.ts';
import { DEFAULT_BUSY_TIMEOUT_MS } from '../../src/storage/db/index.ts';
import { bearer, cleanup, composedEnv, ENVELOPE_ID, serveApp, tempDir } from './support.mjs';

let served;
const invoked = [];

before(async () => {
  served = await serveApp({
    handlers: {
      readEnvelope: async (ctx) => {
        invoked.push(`read ${ctx.correlationId}`);
        return { status: 200, json: { read: true } };
      },
      uploadDocument: async (ctx) => {
        let bytes = 0;
        for await (const chunk of ctx.pdf()) bytes += chunk.length;
        invoked.push('upload');
        return { status: 200, json: { bytes } };
      },
      createEnvelope: async (ctx) => {
        await ctx.json();
        invoked.push('create');
        return { status: 201, json: {} };
      },
    },
  });
});

after(async () => {
  await served.close();
  cleanup();
});

const records = () => served.lines.map((line) => JSON.parse(line));
const requestLines = () => records().filter((record) => record.event === 'request');

/**
 * Open a raw connection, perform `writes` ({at, data}) on schedule, half-close at `endAt`,
 * and collect everything until the connection closes (or `limitMs` passes). `endedMs` is when
 * the server half-closed; with `endOnServerEnd` the client then closes its side too, otherwise
 * it keeps writing on schedule (as a pipelining client would).
 */
function exchange(writes, { endAt = null, limitMs = 5000, endOnServerEnd = false } = {}) {
  return new Promise((resolveExchange) => {
    const started = performance.now();
    const socket = connect({ host: '127.0.0.1', port: served.port, allowHalfOpen: true });
    let text = '';
    let firstResponseMs = null;
    let endedMs = null;
    socket.on('data', (chunk) => {
      if (firstResponseMs === null) firstResponseMs = performance.now() - started;
      text += chunk.toString('latin1');
    });
    socket.on('error', () => {});
    socket.on('end', () => {
      endedMs = performance.now() - started;
      if (endOnServerEnd) socket.end();
    });
    const timers = [];
    socket.on('connect', () => {
      for (const { at, data } of writes) timers.push(setTimeout(() => !socket.destroyed && socket.write(data), at));
      if (endAt !== null) timers.push(setTimeout(() => !socket.destroyed && socket.end(), endAt));
    });
    const limit = setTimeout(() => socket.destroy(), limitMs);
    socket.on('close', () => {
      clearTimeout(limit);
      for (const timer of timers) clearTimeout(timer);
      resolveExchange({
        text,
        // Status lines anywhere: a pipelined response follows the previous body directly.
        statuses: [...text.matchAll(/HTTP\/1\.1 (\d{3}) /g)].map((match) => Number(match[1])),
        firstResponseMs,
        endedMs,
        closedMs: performance.now() - started,
      });
    });
  });
}

const read = (extra = '') => `GET /v1/envelopes/${ENVELOPE_ID} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${bearer('sender')}\r\n${extra}\r\n`;
// No Authorization: a 401 decided before the 2-byte body is read, so the connection closes.
const unauthorized = 'POST /v1/envelopes HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}';

test('[SEC-08] after a Connection: close response is decided, no later pipelined request is parsed or dispatched', async () => {
  // 1. The LBR-2 shape: the authorized request arrives 400 ms after the closing 401.
  invoked.length = 0;
  let before = requestLines().length;
  const later = await exchange([{ at: 0, data: unauthorized }, { at: 400, data: read() }], { endAt: 900 });
  assert.deepEqual(later.statuses, [401], 'one response only');
  assert.ok(later.endedMs !== null && later.closedMs > 400, 'the later request was sent on the half-closed connection');
  assert.match(later.text, /\r\nconnection: close\r\n/i);
  assert.deepEqual(invoked, [], 'the later request was never dispatched to its handler');
  assert.equal(requestLines().length - before, 1, 'only the closing request was handled and logged');
  assert.equal(records().filter((record) => record.event === 'pipelined_request_refused').length, 0, 'the later request was not even parsed');

  // 2. The authorized request in the same packet as the closing 401.
  invoked.length = 0;
  before = requestLines().length;
  let refusedBefore = records().filter((record) => record.event === 'pipelined_request_refused').length;
  const packed = await exchange([{ at: 0, data: unauthorized + read() }], { endAt: 600 });
  assert.deepEqual(packed.statuses, [401]);
  assert.deepEqual(invoked, [], 'a request already parsed from the same packet is never dispatched');
  assert.equal(requestLines().length - before, 1);
  assert.equal(records().filter((record) => record.event === 'pipelined_request_refused').length - refusedBefore, 1);

  // 3. A request that asks for close ends the connection after its own response: a later
  //    request is never dispatched, whether it arrives later or in the same packet.
  invoked.length = 0;
  const create = `POST /v1/envelopes HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer ${bearer('sender')}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}`;
  const askedLater = await exchange([{ at: 0, data: read('Connection: close\r\n') }, { at: 400, data: create }], { endAt: 900 });
  assert.deepEqual(askedLater.statuses, [200], 'the close request is answered; nothing after it');
  const askedPacked = await exchange([{ at: 0, data: read('Connection: close\r\n') + create }], { endAt: 600 });
  assert.equal(askedPacked.statuses.length, 1, `one response only (${askedPacked.statuses})`);
  assert.equal(invoked.includes('create'), false, 'the request after the close request was never dispatched');

  // Control: keep-alive pipelining is served in order.
  invoked.length = 0;
  const kept = await exchange([{ at: 0, data: read() + read() + read('Connection: close\r\n') }], { endAt: 1500 });
  assert.deepEqual(kept.statuses, [200, 200, 200]);
  assert.equal(invoked.length, 3);
});

test('[SEC-10] an idle or below-minimum-rate body gets 408 and a connection close from a per-request timer', async (t) => {
  const auth = `Authorization: Bearer ${bearer('sender')}\r\n`;
  const upload = (length) => `PUT /v1/envelopes/${ENVELOPE_ID}/document HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth}Content-Type: application/pdf\r\nContent-Length: ${length}\r\n\r\n`;
  const create = (length) => `POST /v1/envelopes HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth}Content-Type: application/json\r\nContent-Length: ${length}\r\n\r\n`;
  const limitMs = 16_000;

  // Idle: ten bytes, then silence.
  const idle = exchange([{ at: 0, data: upload(1000) + '%PDF-1.7\n%' }], { limitMs, endOnServerEnd: true });
  // Below the minimum rate but never idle: one byte every 900 ms.
  const trickle = Array.from({ length: 17 }, (_, i) => ({ at: i * 900, data: i === 0 ? `${create(1000)}{` : 'a' }));
  const slow = exchange(trickle, { limitMs, endOnServerEnd: true });
  // Control: half the body, a 6 s pause (under both limits), then the rest.
  const half = 'x'.repeat(1000);
  const paused = exchange([{ at: 0, data: upload(2000) + half }, { at: 6000, data: half }], { endAt: 8000, limitMs });

  const [idleResult, slowResult, pausedResult] = await Promise.all([idle, slow, paused]);
  t.diagnostic(`idle body: ${idleResult.statuses} after ${idleResult.firstResponseMs?.toFixed(0)} ms; below-rate body: ${slowResult.statuses} after ${slowResult.firstResponseMs?.toFixed(0)} ms; paused body: ${pausedResult.statuses}`);
  for (const [label, result] of [['idle', idleResult], ['below-rate', slowResult]]) {
    assert.deepEqual(result.statuses, [408], `${label}: 408 within ${limitMs} ms`);
    assert.match(result.text, /\r\nconnection: close\r\n/i, `${label}: the connection is closed`);
    assert.match(result.text, /"code":"invalid_request"/, `${label}: a contract Error body`);
    assert.ok(result.firstResponseMs >= 9_500 && result.firstResponseMs <= 11_500, `${label}: 408 after ${result.firstResponseMs.toFixed(0)} ms (10 s timer, not a 30 s sweep)`);
    assert.ok(result.endedMs !== null && result.endedMs - result.firstResponseMs < 3_000, `${label}: the server closes the connection after the 408`);
  }
  assert.deepEqual(pausedResult.statuses, [200], 'a body that pauses under the limits is accepted');
  const { BODY_IDLE_TIMEOUT_MS, BODY_RATE_GRACE_MS, BODY_MIN_BYTES_PER_SECOND } = serverConfig;
  assert.ok(BODY_IDLE_TIMEOUT_MS <= 10_000 && BODY_RATE_GRACE_MS <= 10_000 && BODY_MIN_BYTES_PER_SECOND >= 1024, 'the documented limits');
  const timedOut = requestLines().filter((record) => record.status === 408);
  assert.ok(timedOut.length >= 2 && timedOut.every((record) => record.error_code === 'invalid_request'));
});

test('[SEC-10] Node\'s request timeout on both listeners is never shorter than the longest request SEC-10 admits', async () => {
  const { PDF_BODY_LIMIT, JSON_BODY_LIMIT, BODY_MIN_BYTES_PER_SECOND } = serverConfig;
  const { HEADERS_TIMEOUT_MS, PRE_BODY_WAIT_MS, REQUEST_TIMEOUT_MS, startServer } = serverMain;
  const longestPdf = Math.ceil(PDF_BODY_LIMIT / BODY_MIN_BYTES_PER_SECOND) * 1000;
  const longestJson = Math.ceil(JSON_BODY_LIMIT / BODY_MIN_BYTES_PER_SECOND) * 1000;
  assert.equal(longestPdf, 640_000, 'premise: a 10 MiB body at the 16 KiB/s minimum rate is admitted for 640 s');
  assert.equal(PRE_BODY_WAIT_MS, DEFAULT_BUSY_TIMEOUT_MS, 'the one wait before a body read is a pre-body transaction\'s busy timeout (the parse plan is settled at startup)');
  assert.ok(REQUEST_TIMEOUT_MS >= HEADERS_TIMEOUT_MS + longestPdf + DEFAULT_BUSY_TIMEOUT_MS, `the backstop ${REQUEST_TIMEOUT_MS} ms covers headers + ${longestPdf} ms + the busy timeout`);
  assert.ok(REQUEST_TIMEOUT_MS >= HEADERS_TIMEOUT_MS + longestJson + PRE_BODY_WAIT_MS, 'and so the longest JSON request too');
  const running = await startServer(composedEnv({ OPENSIG_RELAY_SOCKET: join(tempDir('relay'), 'opensig.sock') }), { logSink: () => {} });
  try {
    assert.deepEqual(running.listeners.map((listener) => listener.name), ['tcp', 'relay']);
    for (const listener of running.listeners) {
      assert.equal(listener.timeouts.headers, HEADERS_TIMEOUT_MS, `${listener.name}: header timeout`);
      assert.ok(listener.timeouts.request >= listener.timeouts.headers + longestPdf + DEFAULT_BUSY_TIMEOUT_MS, `${listener.name}: request timeout ${listener.timeouts.request} ms is at least ${listener.timeouts.headers + longestPdf + DEFAULT_BUSY_TIMEOUT_MS} ms`);
    }
  } finally {
    await running.close();
  }
});
