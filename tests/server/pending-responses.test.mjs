// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-13 (A-010 rows SEC11-D5 and SEC11-Q) and SEC-14 (row SEC11-D6), over raw
// loopback sockets against the real application built by createAppServer (support.mjs
// serveApp), as SEC-11 is.
//
// SEC-13 (a): a stalled partial request behind a pending response (Node's own request timeout,
// ERR_HTTP_REQUEST_TIMEOUT, on its unfinished headers) never displaces that response: the
// pending response goes first, then the connection closes; Node's 408 never replaces it. The
// test server shortens Node's header timeout and check interval (createAppServer options) so
// the timeout fires in well under a second; production keeps its own values (main.ts).
// SEC-13 (c): a malformed chunk that arrives after a pipelined upload's handler was entered,
// while the response before it is still being sent, ends that upload's body read at once: the
// upload is answered with the uniform 400 invalid_request right after the pending response,
// never after the 10 s body idle timer, and the T033 body-read permit its parse holds is
// released at once. The upload handler streams its body into the real parsePdf(), so the
// permit is T033's own; this case needs the T033 sandbox launcher that parsePdf requires.
// The close after that decision waits for every pending response, however slowly the client
// reads: B's error response does not start the lingering close itself (src/server/app.ts fail()).
// SEC-13 (b) (a half-close while a response is pending) is a documented T024 limitation (A-010
// request #30 (6), row SEC11-D5): Node keeps a half-closed socket only through its undocumented
// httpAllowHalfOpen, which is not used, so (b) is not asserted here.
// SEC-14: the SEC-11 replay (src/server/app.ts clientError) reads the Node internal
// socket._httpMessage._headerSent. The guard fails loudly if it is missing or not a boolean, or
// when the runtime is not the pinned Node, so a Node bump re-verifies the replay.
// Barriers wait on observable state; timers are hang guards only, and (c)'s guard is half the
// idle timer, so a read that waited for that timer fails here.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { after, test } from 'node:test';

import { bodyReadCapacity, parsePdf } from '../../src/pdf/service.ts';
// A namespace import, so a head without the exported constant still runs (and fails) these cases.
import * as serverApp from '../../src/server/app.ts';
import { BODY_IDLE_TIMEOUT_MS } from '../../src/server/config.ts';
import { bearer, cleanup, ENVELOPE_ID, REPO, serveApp } from './support.mjs';

after(cleanup);

const SEC11_EVENT = 'parse_error_while_response_pending';
/** app.ts's lingering-close wait (2 s at heads that predate its export). */
const LINGER_MS = serverApp.LINGER_MS ?? 2_000;
const NODE_408 = 'HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n';
const auth = () => `Authorization: Bearer ${bearer('sender')}\r\n`;
const statusesOf = (text) => [...text.matchAll(/HTTP\/1\.1 (\d{3}) /g)].map((match) => Number(match[1]));

/** Barrier: poll `check` with a bounded sleep until it holds; false at the guard. */
async function until(check, ms) {
  const started = Date.now();
  while (!check()) {
    if (Date.now() - started > ms) return false;
    await sleep(5);
  }
  return true;
}

/** A raw connection that collects everything until it closes; `paused` defers reading until resume(). */
function rawConnection(port, { paused = false } = {}) {
  const socket = connect({ host: '127.0.0.1', port, allowHalfOpen: true });
  const chunks = [];
  let serverEnded = false;
  if (paused) socket.pause();
  socket.on('data', (chunk) => chunks.push(chunk));
  socket.on('end', () => {
    serverEnded = true;
    socket.end();
  });
  socket.on('error', () => {});
  const closed = new Promise((resolveClose) => socket.on('close', resolveClose));
  return {
    socket,
    closed,
    text: () => Buffer.concat(chunks).toString('latin1'),
    serverEnded: () => serverEnded,
  };
}

test('[SEC-13] (a) a stalled partial request behind a pending response never displaces it: the pending response first, then the close', async () => {
  let entered = 0;
  const served = await serveApp({
    serverOptions: { connectionsCheckingInterval: 50, headersTimeout: 300, requestTimeout: 600 },
    handlers: {
      readEnvelope: async (ctx) => {
        entered += 1;
        // Held until Node's request timeout has fired on the partial request behind it (the
        // server's decision is logged), or the socket is gone; hang guard 5 s.
        await until(() => ctx.request.socket.destroyed || served.lines.some((line) => line.includes(SEC11_EVENT)), 5_000);
        return { status: 200, json: { read: true } };
      },
    },
  });
  try {
    const connection = rawConnection(served.port);
    // A complete keep-alive request, then a request whose headers never finish.
    connection.socket.write(`GET /v1/envelopes/${ENVELOPE_ID} HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}\r\nGET /v1/envelopes/${ENVELOPE_ID} HTTP/1.1\r\nHost: 127.0.0.1\r\n`);
    const guard = setTimeout(() => connection.socket.destroy(), 8_000);
    await connection.closed;
    clearTimeout(guard);
    const text = connection.text();
    assert.ok(!text.startsWith(NODE_408), 'Node\'s 408 never replaces the pending response');
    assert.deepEqual(statusesOf(text), [200], `the pending response only (got ${statusesOf(text)})`);
    assert.match(text, /"read":true/, 'the pending request\'s own response');
    assert.match(text, /\r\nconnection: close\r\n/i, 'it closes the connection');
    assert.equal(connection.serverEnded(), true, 'then the server closes the connection');
    assert.equal(entered, 1, 'the partial request never reached a handler');
    const records = served.lines.map((line) => JSON.parse(line));
    const decision = records.filter((record) => record.event === SEC11_EVENT);
    assert.equal(decision.length, 1, 'the server decided once');
    assert.equal(decision[0].parser_error, 'ERR_HTTP_REQUEST_TIMEOUT');
    assert.deepEqual(records.filter((record) => record.event === 'request').map((record) => `${record.operation}:${record.status}`), ['readEnvelope:200']);
  } finally {
    await served.close();
  }
});

/**
 * Accept B's headers before A queues its large response. If A has already backpressured
 * the socket when Node sees B's headers, Node also pauses input, so B's later chunk
 * cannot reach the parser until the client resumes reading A.
 */
function uploadSocketAfterHeaders(server) {
  return new Promise((resolve) => {
    const onRequest = (req) => {
      if (req.method !== 'PUT') return;
      server.off('request', onRequest);
      resolve(req.socket);
    };
    server.on('request', onRequest);
  });
}

test('[SEC-13] (c) a malformed chunk after a pipelined upload handler was entered gets 400 right after the pending response, and its body-read permit is released at once', async () => {
  const LARGE = 32 * 1024 * 1024; // more than loopback buffers hold while the client is not reading
  const entered = [];
  let uploadSocket;
  const served = await serveApp({
    handlers: {
      readEnvelope: async () => {
        entered.push('A');
        await uploadSocket;
        return { status: 200, json: { pad: 'x'.repeat(LARGE) } };
      },
      uploadDocument: async (ctx) => {
        entered.push('B');
        // The real T033 parse service: it reads the streamed body under one of its body-read permits.
        const outcome = await parsePdf(ctx.pdf());
        return { status: outcome.ok ? 200 : outcome.status, json: { ok: outcome.ok } };
      },
    },
  });
  uploadSocket = uploadSocketAfterHeaders(served.server);
  try {
    assert.equal(bodyReadCapacity().held, 0, 'premise: no body-read permit held');
    const connection = rawConnection(served.port, { paused: true });
    const upload = `PUT /v1/envelopes/${ENVELOPE_ID}/document HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}Content-Type: application/pdf\r\nIf-Match: "1"\r\nIdempotency-Key: idem_synthetic_000000000013\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n%PDF-1.7\r\n`;
    connection.socket.write(`GET /v1/envelopes/${ENVELOPE_ID} HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}\r\n`);
    assert.ok(await until(() => entered.includes('A'), 5_000), 'premise: A is waiting for the upload headers');
    connection.socket.write(upload);
    // B's handler is entered while A's large response is still being sent, and its parse holds a permit.
    const reading = await until(() => entered.includes('B') && bodyReadCapacity().held === 1, 5_000);
    assert.ok(reading, `premise: the upload's handler was entered and its parse holds a body-read permit (entered ${entered}; held ${bodyReadCapacity().held}); this case needs the T033 sandbox launcher`);
    assert.ok((await uploadSocket).writableNeedDrain, 'premise: A is backpressured before the malformed chunk arrives');
    connection.socket.write('zz\r\n');
    const released = await until(() => bodyReadCapacity().held === 0, BODY_IDLE_TIMEOUT_MS / 2);
    assert.ok(released, `the body-read permit is released at once, never after the ${BODY_IDLE_TIMEOUT_MS} ms idle timer`);
    connection.socket.resume();
    const guard = setTimeout(() => connection.socket.destroy(), 15_000);
    await connection.closed;
    clearTimeout(guard);
    const text = connection.text();
    assert.deepEqual(statusesOf(text), [200, 400], `A's response, then B's 400 (got ${statusesOf(text)})`);
    assert.doesNotMatch(text, /HTTP\/1\.1 408 /, 'never the idle timer\'s 408');
    const second = text.slice(text.lastIndexOf('HTTP/1.1 400 '));
    assert.match(second, /\r\nconnection: close\r\n/i, 'B\'s answer closes the connection');
    assert.match(second, /"code":"invalid_request"/, 'B\'s answer is the uniform Error');
    const secondBody = JSON.parse(second.slice(second.indexOf('\r\n\r\n') + 4));
    assert.match(secondBody.correlation_id, /^[A-Za-z0-9_-]{8,64}$/, 'with its correlation ID');
    assert.match(second, new RegExp(`\\r\\nx-correlation-id: ${secondBody.correlation_id}\\r\\n`, 'i'), 'the same correlation ID in the header');
    assert.equal(connection.serverEnded(), true);
    const records = served.lines.map((line) => JSON.parse(line));
    assert.equal(records.filter((record) => record.event === SEC11_EVENT && record.parser_error === 'HPE_INVALID_CHUNK_SIZE').length, 1, 'the SEC-11 decision was taken on the malformed chunk');
    assert.deepEqual(records.filter((record) => record.event === 'request').map((record) => `${record.operation}:${record.status}`), ['readEnvelope:200', 'uploadDocument:400']);
  } finally {
    await served.close();
  }
});

test('[SEC-13] (c) the close after the decision waits for every pending response, however slowly the client reads', async () => {
  const LARGE = 32 * 1024 * 1024;
  const entered = [];
  let uploadSocket;
  const served = await serveApp({
    handlers: {
      readEnvelope: async () => {
        entered.push('A');
        await uploadSocket;
        return { status: 200, json: { pad: 'x'.repeat(LARGE) } };
      },
      uploadDocument: async (ctx) => {
        entered.push('B');
        let bytes = 0;
        for await (const chunk of ctx.pdf()) bytes += chunk.length;
        return { status: 200, json: { bytes } };
      },
    },
  });
  uploadSocket = uploadSocketAfterHeaders(served.server);
  try {
    const connection = rawConnection(served.port, { paused: true });
    const upload = `PUT /v1/envelopes/${ENVELOPE_ID}/document HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}Content-Type: application/pdf\r\nIf-Match: "1"\r\nIdempotency-Key: idem_synthetic_000000000014\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n%PDF-1.7\r\n`;
    connection.socket.write(`GET /v1/envelopes/${ENVELOPE_ID} HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}\r\n`);
    assert.ok(await until(() => entered.includes('A'), 5_000), 'premise: A is waiting for the upload headers');
    connection.socket.write(upload);
    assert.ok(await until(() => entered.includes('B'), 5_000), 'premise: the upload\'s handler was entered while A\'s response was pending');
    assert.ok((await uploadSocket).writableNeedDrain, 'premise: A is backpressured before the malformed chunk arrives');
    connection.socket.write('zz\r\n');
    // B's 400 is decided (its request line is logged) while A's response is still unsent ...
    const decided = await until(() => served.lines.some((line) => line.includes('"event":"request"') && line.includes('"operation":"uploadDocument"')), BODY_IDLE_TIMEOUT_MS / 2);
    assert.ok(decided, 'B was answered at once');
    // ... and the client keeps not reading for longer than the lingering close would wait.
    await sleep(LINGER_MS + 1_000);
    connection.socket.resume();
    const guard = setTimeout(() => connection.socket.destroy(), 15_000);
    await connection.closed;
    clearTimeout(guard);
    const text = connection.text();
    assert.deepEqual(statusesOf(text), [200, 400], `A's whole response, then B's 400, after a slow reader (got ${statusesOf(text)})`);
    const head = text.slice(0, text.indexOf('\r\n\r\n'));
    const length = Number(/\r\ncontent-length: (\d+)/i.exec(head)?.[1]);
    assert.ok(text.indexOf('HTTP/1.1 400 ') >= head.length + 4 + length, 'A\'s body arrived in full before B\'s answer');
    assert.equal(connection.serverEnded(), true, 'then the server closed the connection');
  } finally {
    await served.close();
  }
});

test('[SEC-14] the Node internal socket._httpMessage._headerSent that the SEC-11 replay reads exists and is a boolean on the pinned Node', async () => {
  const pinned = readFileSync(join(REPO, '.node-version'), 'utf8').trim();
  assert.equal(process.version, `v${pinned}`, `SEC-14 is pinned to Node ${pinned}: on any other runtime, re-verify src/server/app.ts clientError's read of socket._httpMessage._headerSent, then update this guard`);
  const probes = [];
  const served = await serveApp({
    handlers: {
      readEnvelope: async (ctx) => {
        const socket = ctx.request.socket;
        const message = socket._httpMessage;
        probes.push({ socket, message, hasField: '_httpMessage' in socket, own: message !== null && typeof message === 'object' && Object.hasOwn(message, '_headerSent'), before: message?._headerSent });
        return { status: 200, json: { read: true } };
      },
    },
  });
  try {
    const connection = rawConnection(served.port);
    connection.socket.write(`GET /v1/envelopes/${ENVELOPE_ID} HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}Connection: close\r\n\r\n`);
    await connection.closed;
    assert.deepEqual(statusesOf(connection.text()), [200]);
    assert.equal(probes.length, 1);
    const [probe] = probes;
    assert.equal(probe.hasField, true, 'the socket carries _httpMessage (Node internal; read by the SEC-11 replay)');
    assert.ok(probe.message !== null && typeof probe.message === 'object', 'while a response is pending, _httpMessage is the response object');
    assert.equal(probe.own, true, '_headerSent is an own property of that response (Node internal)');
    assert.equal(typeof probe.before, 'boolean', '_headerSent is a boolean');
    assert.equal(probe.before, false, '_headerSent is false before the response is written');
    assert.equal(typeof probe.message._headerSent, 'boolean', '_headerSent stays a boolean');
    assert.equal(probe.message._headerSent, true, '_headerSent is true once the response was written');
  } finally {
    await served.close();
  }
});
