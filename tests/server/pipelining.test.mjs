// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-11 (A-010 LBR5-1), over raw loopback sockets.
//
// While a response is pending on a connection that will close, bytes the HTTP parser cannot
// accept are never answered with Node's parser 400 in place of that response:
// - pipelined bytes after a mutating `Connection: close` request, in the same packet or in a
//   later one that arrives while the handler is still working, get the handler's own response
//   and then the connection closes; the pipelined request is never parsed or dispatched, so
//   SEC-08 still holds;
// - extra bytes after a complete upload body get the upload's own response, now with
//   `Connection: close`, and then the connection closes;
// - a complete request already queued behind the pending one is refused, as SEC-08 refuses
//   any request after a decided close.
// Control: a malformed request with no response pending (the first bytes of a connection, or
// bytes after a finished response) still gets Node's 400 exactly as before, and so does a
// malformed body inside the request being handled, which is not extra bytes. Node's other
// canned responses (431 for oversized headers) are unchanged too.
// The real entrypoint (src/server/main.ts) behaves the same way.
//
// Choreography: each handler holds its response until the parser has run over every byte the
// client sends on that connection, or until the server has destroyed the connection. So the
// parser has always seen the extra bytes while the response is pending, however the packets
// were split. socket.bytesRead counts bytes as they are read, just before the parser runs over
// them in the same synchronous call; handlers can run between parser callbacks, so the hold
// always waits at least one macrotask, which runs only after that call has returned. A later
// packet is written only once the handler has its request (or, for the finished-response
// control, once the client has the whole response). Nothing depends on host timing; the limits
// below only stop a broken run from hanging.

import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { after, before, test } from 'node:test';

import { startServer } from '../../src/server/main.ts';
import { bearer, cleanup, ENVELOPE_ID, serveApp } from './support.mjs';

const HOLD_LIMIT_MS = 3_000;
const EXCHANGE_LIMIT_MS = 6_000;
const SEC11_EVENT = 'parse_error_while_response_pending';
// Node's own parser error response, byte for byte (node:_http_server badRequestResponse).
const NODE_400 = 'HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n';

let served;
const calls = [];
let expectedBytes = 0;
let onDispatch = () => {};

const pause = (ms) =>
  new Promise((resolvePause) => {
    setTimeout(resolvePause, ms);
  });

/**
 * Hold the response until the parser has run over `expectedBytes` on this connection, or the
 * server destroyed it: the count is checked only from a timer, never inside the parser's call.
 */
async function hold(ctx) {
  const socket = ctx.request.socket;
  onDispatch();
  let waited = 0;
  do {
    await pause(5);
    waited += 5;
  } while (!socket.destroyed && socket.bytesRead < expectedBytes && waited < HOLD_LIMIT_MS);
}

before(async () => {
  served = await serveApp({
    handlers: {
      createEnvelope: async (ctx) => {
        const body = await ctx.json();
        calls.push(`create:${body.n}`);
        await hold(ctx);
        return { status: 201, json: { created: body.n } };
      },
      uploadDocument: async (ctx) => {
        let bytes = 0;
        for await (const chunk of ctx.pdf()) bytes += chunk.length;
        calls.push(`upload:${bytes}`);
        await hold(ctx);
        return { status: 200, json: { bytes } };
      },
      readEnvelope: async (ctx) => {
        calls.push('read');
        await hold(ctx);
        return { status: 200, json: { read: true } };
      },
    },
  });
});

after(async () => {
  await served.close();
  cleanup();
});

const records = () => served.lines.map((line) => JSON.parse(line));
const requestStatuses = () => records().filter((record) => record.event === 'request').map((record) => record.status);
const events = (name) => records().filter((record) => record.event === name);

const auth = () => `Authorization: Bearer ${bearer('sender')}\r\n`;
const create = (n, extra = '') => {
  const body = JSON.stringify({ n });
  return `POST /v1/envelopes HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}Content-Type: application/json\r\nContent-Length: ${body.length}\r\n${extra}\r\n${body}`;
};
const read = (extra = '') => `GET /v1/envelopes/${ENVELOPE_ID} HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}${extra}\r\n`;
const UPLOAD_BYTES = 4096;
const upload = () =>
  `PUT /v1/envelopes/${ENVELOPE_ID}/document HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}Content-Type: application/pdf\r\nIf-Match: "1"\r\n` +
  `Idempotency-Key: idem_synthetic_000000000011\r\nContent-Length: ${UPLOAD_BYTES}\r\n\r\n%PDF-1.7\n${'x'.repeat(UPLOAD_BYTES - 9)}`;
// Bytes no HTTP parser accepts as a request: what an over-sending client leaves after its body.
const EXTRA = '%'.repeat(512);

/** Whether `text` holds one complete response (headers and a Content-Length body). */
function responseComplete(text) {
  const end = text.indexOf('\r\n\r\n');
  if (end < 0) return false;
  const length = /\r\ncontent-length: (\d+)\r\n/i.exec(text.slice(0, end + 2));
  return length !== null && text.length >= end + 4 + Number(length[1]);
}

/**
 * One raw loopback connection. Writes `first`; when `second` is given, writes it once the
 * handler has its request (`after: 'dispatch'`) or once the client has the whole first
 * response (`after: 'response'`). Reads until the connection closes; when the server
 * half-closes, the client closes its side too.
 */
function exchange(port, first, { second = null, after: trigger = 'dispatch' } = {}) {
  expectedBytes = Buffer.byteLength(first) + (second !== null && trigger === 'dispatch' ? Buffer.byteLength(second) : 0);
  let dispatched = false;
  let writeSecond = () => {};
  onDispatch = () => {
    dispatched = true;
    if (trigger === 'dispatch') writeSecond();
  };
  return new Promise((resolveExchange) => {
    const socket = connect({ host: '127.0.0.1', port, allowHalfOpen: true });
    let text = '';
    let serverEnded = false;
    let closedByLimit = false;
    let secondWritten = false;
    writeSecond = () => {
      if (second === null || secondWritten || socket.destroyed) return;
      secondWritten = true;
      socket.write(second);
    };
    socket.on('data', (chunk) => {
      text += chunk.toString('latin1');
      if (trigger === 'response' && responseComplete(text)) writeSecond();
    });
    socket.on('end', () => {
      serverEnded = true;
      socket.end();
    });
    socket.on('error', () => {});
    socket.on('connect', () => {
      socket.write(first);
      if (trigger === 'dispatch' && dispatched) writeSecond();
    });
    // A request that never reaches its handler would otherwise wait for the limit below.
    const fallback = second !== null && trigger === 'dispatch' ? setTimeout(writeSecond, HOLD_LIMIT_MS) : null;
    const limit = setTimeout(() => {
      closedByLimit = true;
      socket.destroy();
    }, EXCHANGE_LIMIT_MS);
    socket.on('close', () => {
      clearTimeout(limit);
      if (fallback !== null) clearTimeout(fallback);
      onDispatch = () => {};
      resolveExchange({
        text,
        // Status lines anywhere: a later response follows the previous body directly.
        statuses: [...text.matchAll(/HTTP\/1\.1 (\d{3}) /g)].map((match) => Number(match[1])),
        serverEnded,
        closedByLimit,
      });
    });
  });
}

test('[SEC-11] pipelined bytes after a mutating Connection: close request get the pending response, then the connection closes', async () => {
  const cases = [
    { label: 'same packet', n: 1, first: create(1, 'Connection: close\r\n') + create(2), second: null },
    { label: 'later packet, while the handler works', n: 3, first: create(3, 'Connection: close\r\n'), second: create(4) },
  ];
  for (const { label, n, first, second } of cases) {
    calls.length = 0;
    const requestsBefore = requestStatuses().length;
    const refusedBefore = events('pipelined_request_refused').length;
    const deferredBefore = events(SEC11_EVENT).length;
    const result = await exchange(served.port, first, { second });
    assert.deepEqual(result.statuses, [201], `${label}: the handler's own response, never the parser's 400 (got ${result.statuses})`);
    assert.doesNotMatch(result.text, /HTTP\/1\.1 400 /, `${label}: no parser 400`);
    assert.match(result.text, new RegExp(`"created":${n}}`), `${label}: the response of the close request`);
    assert.match(result.text, /\r\nconnection: close\r\n/i, `${label}: the response closes the connection`);
    assert.equal(result.serverEnded, true, `${label}: then the server closes the connection`);
    assert.equal(result.closedByLimit, false, `${label}: the connection closed by itself`);
    assert.deepEqual(calls, [`create:${n}`], `${label}: the pipelined mutating request was never dispatched`);
    assert.deepEqual(requestStatuses().slice(requestsBefore), [201], `${label}: only the close request was handled and logged`);
    assert.equal(events('pipelined_request_refused').length - refusedBefore, 0, `${label}: the pipelined request was not even parsed (SEC-08)`);
    const deferred = events(SEC11_EVENT).slice(deferredBefore);
    assert.equal(deferred.length, 1, `${label}: the server logged its decision once`);
    assert.equal(deferred[0].parser_error, 'HPE_CLOSED_CONNECTION');
  }
});

test('[SEC-11] extra bytes after a complete upload body get the pending response, then the connection closes', async () => {
  const cases = [
    { label: 'later packet, while the handler works', first: upload(), second: EXTRA },
    { label: 'same packet', first: upload() + EXTRA, second: null },
  ];
  for (const { label, first, second } of cases) {
    calls.length = 0;
    const requestsBefore = requestStatuses().length;
    const deferredBefore = events(SEC11_EVENT).length;
    const result = await exchange(served.port, first, { second });
    assert.deepEqual(result.statuses, [200], `${label}: the upload's own response, never the parser's 400 (got ${result.statuses})`);
    assert.doesNotMatch(result.text, /HTTP\/1\.1 400 /, `${label}: no parser 400`);
    assert.match(result.text, new RegExp(`"bytes":${UPLOAD_BYTES}}`), `${label}: the handler read exactly the declared body`);
    assert.match(result.text, /\r\nconnection: close\r\n/i, `${label}: the pending response closes the keep-alive connection`);
    assert.equal(result.serverEnded, true, `${label}: then the server closes the connection`);
    assert.equal(result.closedByLimit, false, `${label}: the connection closed by itself`);
    assert.deepEqual(calls, [`upload:${UPLOAD_BYTES}`], `${label}: one upload handled`);
    assert.deepEqual(requestStatuses().slice(requestsBefore), [200], `${label}: one request handled and logged`);
    const deferred = events(SEC11_EVENT).slice(deferredBefore);
    assert.equal(deferred.length, 1, `${label}: the server logged its decision once`);
    assert.equal(deferred[0].parser_error, 'HPE_INVALID_METHOD');
    assert.equal(deferred[0].pending_responses, 1);
  }
});

test('[SEC-11] a complete request queued behind the pending response is refused, as after any decided close', async () => {
  calls.length = 0;
  const requestsBefore = requestStatuses().length;
  const refusedBefore = events('pipelined_request_refused').length;
  const result = await exchange(served.port, read() + create(5) + EXTRA);
  assert.deepEqual(result.statuses, [200], `the pending response only (got ${result.statuses})`);
  assert.doesNotMatch(result.text, /HTTP\/1\.1 400 /);
  assert.match(result.text, /\r\nconnection: close\r\n/i);
  assert.equal(result.serverEnded, true);
  assert.equal(result.closedByLimit, false);
  assert.deepEqual(calls, ['read'], 'the queued mutating request was never dispatched');
  assert.deepEqual(requestStatuses().slice(requestsBefore), [200]);
  assert.equal(events('pipelined_request_refused').length - refusedBefore, 1, 'the queued request is refused (SEC-08)');
  assert.equal(events(SEC11_EVENT).at(-1)?.pending_responses, 2, 'both requests were pending when the parser failed');
});

test('[SEC-11] control: a malformed request with no response pending still gets the parser 400', async () => {
  // A server of its own, so nothing left over from another test can reach its log.
  const reads = [];
  const control = await serveApp({
    handlers: {
      readEnvelope: async (ctx) => {
        reads.push('read');
        await hold(ctx);
        return { status: 200, json: { read: true } };
      },
    },
  });
  const logged = () => control.lines.map((line) => JSON.parse(line));
  const handled = () => logged().filter((record) => record.event === 'request').map((record) => record.status);
  try {
    // The first bytes of a connection: nothing was dispatched.
    const fresh = await exchange(control.port, 'GARBAGE /\r\n\r\n');
    assert.equal(fresh.text, NODE_400, 'exactly Node\'s 400');
    assert.equal(fresh.closedByLimit, false, 'and the connection closes');
    // Node's other canned responses are unchanged too: header overflow (default 16 KiB) is 431.
    const overflow = await exchange(control.port, `GET /v1/envelopes/${ENVELOPE_ID} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: ${'a'.repeat(17_000)}\r\n\r\n`);
    assert.equal(overflow.text, 'HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n', 'exactly Node\'s 431');
    assert.equal(overflow.closedByLimit, false);
    assert.deepEqual(handled(), [], 'nothing was handled');

    // Bytes after a finished response on a keep-alive connection.
    const finished = await exchange(control.port, read(), { second: EXTRA, after: 'response' });
    assert.deepEqual(finished.statuses, [200, 400], `the finished response, then Node's 400 (got ${finished.statuses})`);
    assert.ok(finished.text.endsWith(NODE_400), 'the second response is exactly Node\'s 400');
    assert.doesNotMatch(finished.text.slice(0, finished.text.indexOf(NODE_400)), /\r\nconnection: close\r\n/i, 'the first response kept the connection');
    assert.equal(finished.closedByLimit, false);
    assert.deepEqual(reads, ['read']);
    assert.deepEqual(handled(), [200]);

    // A malformed body inside the request being handled is that request's own error, not
    // extra bytes after it: Node's 400 still answers it, even with its handler dispatched.
    const chunked = await exchange(control.port, `GET /v1/envelopes/${ENVELOPE_ID} HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}Transfer-Encoding: chunked\r\n\r\nzz\r\n`);
    assert.equal(chunked.text, NODE_400, 'exactly Node\'s 400');
    assert.equal(chunked.closedByLimit, false);

    assert.equal(logged().filter((record) => record.event === SEC11_EVENT).length, 0, 'parser errors are not suppressed globally');
  } finally {
    await control.close();
  }
});

test('[SEC-11] the real entrypoint sends the pending response, not the parser 400', async () => {
  const lines = [];
  const running = await startServer({ OPENSIG_PORT: '0' }, { logSink: (line) => lines.push(line) });
  try {
    // No operator authentication is configured, so the GET is decided as a 401.
    const result = await exchange(running.port, read('Connection: close\r\n') + create(6));
    assert.deepEqual(result.statuses, [401], `the decided response, not the parser's 400 (got ${result.statuses})`);
    assert.match(result.text, /\r\nconnection: close\r\n/i);
    assert.equal(result.serverEnded, true);
    assert.equal(result.closedByLimit, false);
    const logged = lines.map((line) => JSON.parse(line));
    assert.deepEqual(logged.filter((record) => record.event === 'request').map((record) => record.status), [401], 'the pipelined request was never handled');
    assert.equal(logged.filter((record) => record.event === SEC11_EVENT).length, 1);
  } finally {
    await running.close();
  }
});
