// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-11 (A-010 LBR5-1), over raw loopback sockets.
//
// While a response is pending on a connection that will close, bytes the HTTP parser cannot
// accept are never answered with Node's canned response in place of that response:
// - pipelined bytes after a mutating `Connection: close` request, in the same packet or in a
//   later one that arrives while the handler is still working, get the handler's own response
//   and then the connection closes; the pipelined request is never parsed or dispatched, so
//   SEC-08 still holds;
// - extra bytes after a complete upload body get the upload's own response, now with
//   `Connection: close`, and then the connection closes;
// - a malformed request parsed behind a pending upload (an invalid chunk size, or a chunk
//   extension over Node's limit), in the same write or once the upload's handler is held, never
//   replaces the upload's response with Node's 400 or 413, and its handler is never entered;
// - a complete request already queued behind the pending one is refused, as SEC-08 refuses any
//   request after a decided close (its turn is fixed after the decision by the barrier below);
// - after the pending response the server half-closes, lingers, and then closes the connection
//   itself, even for a client that never closes its side (F2).
// Control: a malformed request with no response pending (the first bytes of a connection, a
// malformed first request, or bytes after a finished response) still gets Node's canned 400,
// 413 or 431 exactly as before, and so does a malformed body inside the request being handled.
// The real entrypoint (src/server/main.ts) behaves the same way.
//
// Choreography: each handler holds its response until the parser has run over every byte the
// client sends on that connection, or until the server has destroyed the connection. So the
// parser has always seen the malformed bytes while the response is pending, however the
// packets were split. socket.bytesRead counts bytes as they are read, just before the parser
// runs over them in the same synchronous call; handlers can run between parser callbacks, so a
// barrier always waits at least one macrotask, which runs only after that call has returned.
// A later packet is written only once the handler has its request, or once the client has a
// whole response. Before its baselines each test waits until no handler of an earlier test is
// still running, so nothing left over can reach its log. Ordering never depends on host timing:
// the limits below are hang guards only, and every test asserts that no barrier ever opened on
// its guard instead of its condition.

import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { after, before, test } from 'node:test';

import { startServer } from '../../src/server/main.ts';
import { bearer, cleanup, ENVELOPE_ID, serveApp } from './support.mjs';

const HOLD_LIMIT_MS = 3_000;
const EXCHANGE_LIMIT_MS = 6_000;
const LINGER_GUARD_MS = 15_000;
const SEC11_EVENT = 'parse_error_while_response_pending';
// Node's own parser error responses, byte for byte (node:_http_server).
const NODE_400 = 'HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n';
const NODE_413 = 'HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n';
const NODE_431 = 'HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n';

let served;
const calls = []; // handler effects
const entered = []; // handler entries, by X-Test-Label
let guardHits = 0;
let expectedBytes = 0;
let onDispatch = () => {};
let onUploadSocket = () => {};

const pause = (ms) =>
  new Promise((resolvePause) => {
    setTimeout(resolvePause, ms);
  });

/**
 * Barrier: resolves once the server's parser has run over `count` bytes on `socket`, or the
 * server destroyed it. The count is checked only from a timer, never inside the parser's call.
 */
async function parsed(socket, count) {
  let waited = 0;
  do {
    await pause(5);
    waited += 5;
  } while (!socket.destroyed && socket.bytesRead < count && waited < HOLD_LIMIT_MS);
  if (!socket.destroyed && socket.bytesRead < count) guardHits += 1;
}

/** Hold the response until the parser has run over everything the client sends. */
async function hold(ctx) {
  onDispatch();
  await parsed(ctx.request.socket, expectedBytes);
}

let inFlight = 0;
/** A handler counted while it runs, so a test can wait for an earlier test's handlers to end. */
const counted = (handler) => async (ctx) => {
  inFlight += 1;
  try {
    return await handler(ctx);
  } finally {
    inFlight -= 1;
  }
};

/** Barrier: no handler is running, so nothing left over from an earlier exchange can log. */
async function quiesce() {
  let waited = 0;
  while (inFlight > 0 && waited < HOLD_LIMIT_MS) {
    await pause(5);
    waited += 5;
  }
  if (inFlight > 0) guardHits += 1;
  await pause(0);
}

const labelOf = (ctx) => String(ctx.request.headers['x-test-label'] ?? '-');

before(async () => {
  served = await serveApp({
    handlers: {
      createEnvelope: counted(async (ctx) => {
        entered.push(labelOf(ctx));
        const body = await ctx.json();
        calls.push(`create:${body.n}`);
        await hold(ctx);
        return { status: 201, json: { created: body.n } };
      }),
      uploadDocument: counted(async (ctx) => {
        const label = labelOf(ctx);
        entered.push(label);
        onUploadSocket(ctx.request.socket);
        let bytes = 0;
        for await (const chunk of ctx.pdf()) bytes += chunk.length;
        calls.push(`upload:${label}:${bytes}`);
        await hold(ctx);
        return { status: 200, json: { label, bytes } };
      }),
      readEnvelope: counted(async (ctx) => {
        entered.push(labelOf(ctx));
        calls.push('read');
        await hold(ctx);
        return { status: 200, json: { read: true } };
      }),
    },
  });
});

after(async () => {
  await served.close();
  cleanup();
});

const records = () => served.lines.map((line) => JSON.parse(line));
const requestStatuses = () => records().filter((record) => record.event === 'request').map((record) => record.status);
/** The requests handled and logged since `count` request lines, as operation:status. */
const requestsSince = (count) =>
  records()
    .filter((record) => record.event === 'request')
    .slice(count)
    .map((record) => `${record.operation}:${record.status}`);
const events = (name) => records().filter((record) => record.event === name);

const auth = () => `Authorization: Bearer ${bearer('sender')}\r\n`;
const create = (n, extra = '') => {
  const body = JSON.stringify({ n });
  return `POST /v1/envelopes HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}Content-Type: application/json\r\nContent-Length: ${body.length}\r\n${extra}\r\n${body}`;
};
const read = (extra = '') => `GET /v1/envelopes/${ENVELOPE_ID} HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}${extra}\r\n`;
const UPLOAD_BYTES = 4096;
// A complete keep-alive upload (no Connection: close).
const upload = (label = 'A') =>
  `PUT /v1/envelopes/${ENVELOPE_ID}/document HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}X-Test-Label: ${label}\r\nContent-Type: application/pdf\r\nIf-Match: "1"\r\n` +
  `Idempotency-Key: idem_synthetic_000000000011\r\nContent-Length: ${UPLOAD_BYTES}\r\n\r\n%PDF-1.7\n${'x'.repeat(UPLOAD_BYTES - 9)}`;
// Valid upload headers with a chunked body that follows separately.
const chunkedHead = (label) =>
  `PUT /v1/envelopes/${ENVELOPE_ID}/document HTTP/1.1\r\nHost: 127.0.0.1\r\n${auth()}X-Test-Label: ${label}\r\nContent-Type: application/pdf\r\nIf-Match: "1"\r\n` +
  'Idempotency-Key: idem_synthetic_000000000012\r\nTransfer-Encoding: chunked\r\n\r\n';
// A chunk-size line that is not hexadecimal (HPE_INVALID_CHUNK_SIZE).
const BAD_CHUNK = 'zz\r\n';
// A chunk extension over Node's 16 KiB limit (HPE_CHUNK_EXTENSIONS_OVERFLOW, Node's 413).
const LONG_EXTENSION = `8;${'e'.repeat(20_000)}\r\n`;
// Bytes no HTTP parser accepts as a request: what an over-sending client leaves after its body.
const EXTRA = '%'.repeat(512);
const statusesOf = (text) => [...text.matchAll(/HTTP\/1\.1 (\d{3}) /g)].map((match) => Number(match[1]));

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
      // Status lines anywhere: a later response follows the previous body directly.
      resolveExchange({ text, statuses: statusesOf(text), serverEnded, closedByLimit });
    });
  });
}

/**
 * One connection whose client never ends or destroys its side. Resolves once the server's side
 * of the connection closes (the oracle), or at the hang guard; only then is the client closed.
 */
function exchangeNeverClosing(port, packet) {
  expectedBytes = Buffer.byteLength(packet);
  return new Promise((resolveExchange) => {
    const socket = connect({ host: '127.0.0.1', port, allowHalfOpen: true });
    let text = '';
    let serverEnded = false;
    let settled = false;
    const finish = (serverClosed) => {
      if (settled) return;
      settled = true;
      clearTimeout(guard);
      onUploadSocket = () => {};
      const clientStillOpen = !socket.destroyed && socket.writable;
      socket.destroy();
      resolveExchange({ text, statuses: statusesOf(text), serverEnded, serverClosed, clientStillOpen });
    };
    onUploadSocket = (serverSocket) => {
      serverSocket.once('close', () => finish(true));
    };
    socket.on('data', (chunk) => {
      text += chunk.toString('latin1');
    });
    socket.on('end', () => {
      serverEnded = true; // the client keeps its own side open
    });
    socket.on('error', () => {});
    socket.on('connect', () => socket.write(packet));
    const guard = setTimeout(() => finish(false), LINGER_GUARD_MS);
  });
}

/**
 * A complete keep-alive upload A is pending when the parser fails on B, a request after it:
 * A's own response comes first, with Connection: close, then the connection closes; A ran
 * once; B's handler is never entered and nothing of B is dispatched.
 */
async function assertUploadResponseKept(label, first, second, parserError) {
  await quiesce();
  calls.length = 0;
  entered.length = 0;
  const requestsBefore = requestStatuses().length;
  const refusedBefore = events('pipelined_request_refused').length;
  const deferredBefore = events(SEC11_EVENT).length;
  const guardBefore = guardHits;
  const result = await exchange(served.port, first, { second });
  assert.ok(result.text.startsWith('HTTP/1.1 200 OK\r\n'), `${label}: the first response on the wire is A's own (got ${JSON.stringify(result.text.split('\r\n')[0])})`);
  assert.deepEqual(result.statuses, [200], `${label}: A's response only, never Node's canned response (got ${result.statuses})`);
  assert.match(result.text, new RegExp(`"label":"A","bytes":${UPLOAD_BYTES}}`), `${label}: A's handler read its whole body`);
  assert.match(result.text, /\r\nconnection: close\r\n/i, `${label}: A's response closes the connection`);
  assert.deepEqual(calls, [`upload:A:${UPLOAD_BYTES}`], `${label}: A's handler ran exactly once and its effect persisted`);
  assert.deepEqual(entered, ['A'], `${label}: B's handler was never entered`);
  assert.deepEqual(requestsSince(requestsBefore), ['uploadDocument:200'], `${label}: only A was handled and logged`);
  assert.equal(events('pipelined_request_refused').length - refusedBefore, 1, `${label}: B was refused, never dispatched (as SEC-08)`);
  const deferred = events(SEC11_EVENT).slice(deferredBefore);
  assert.equal(deferred.length, 1, `${label}: the server logged its decision once`);
  assert.equal(deferred[0].parser_error, parserError);
  assert.equal(deferred[0].pending_responses, 2, `${label}: A and B were pending when the parser failed`);
  assert.equal(result.serverEnded, true, `${label}: then the server closes the connection`);
  assert.equal(result.closedByLimit, false, `${label}: the connection closed by itself`);
  assert.equal(guardHits, guardBefore, `${label}: every barrier opened on its condition`);
}

test('[SEC-11] pipelined bytes after a mutating Connection: close request get the pending response, then the connection closes', async () => {
  const cases = [
    { label: 'same packet', n: 1, first: create(1, 'Connection: close\r\n') + create(2), second: null },
    { label: 'later packet, while the handler works', n: 3, first: create(3, 'Connection: close\r\n'), second: create(4) },
  ];
  for (const { label, n, first, second } of cases) {
    await quiesce();
    calls.length = 0;
    const requestsBefore = requestStatuses().length;
    const refusedBefore = events('pipelined_request_refused').length;
    const deferredBefore = events(SEC11_EVENT).length;
    const guardBefore = guardHits;
    const result = await exchange(served.port, first, { second });
    assert.deepEqual(result.statuses, [201], `${label}: the handler's own response, never the parser's 400 (got ${result.statuses})`);
    assert.doesNotMatch(result.text, /HTTP\/1\.1 400 /, `${label}: no parser 400`);
    assert.match(result.text, new RegExp(`"created":${n}}`), `${label}: the response of the close request`);
    assert.match(result.text, /\r\nconnection: close\r\n/i, `${label}: the response closes the connection`);
    assert.equal(result.serverEnded, true, `${label}: then the server closes the connection`);
    assert.equal(result.closedByLimit, false, `${label}: the connection closed by itself`);
    assert.deepEqual(calls, [`create:${n}`], `${label}: the pipelined mutating request was never dispatched`);
    assert.deepEqual(requestsSince(requestsBefore), ['createEnvelope:201'], `${label}: only the close request was handled and logged`);
    assert.equal(events('pipelined_request_refused').length - refusedBefore, 0, `${label}: the pipelined request was not even parsed (SEC-08)`);
    const deferred = events(SEC11_EVENT).slice(deferredBefore);
    assert.equal(deferred.length, 1, `${label}: the server logged its decision once`);
    assert.equal(deferred[0].parser_error, 'HPE_CLOSED_CONNECTION');
    assert.equal(guardHits, guardBefore, `${label}: every barrier opened on its condition`);
  }
});

test('[SEC-11] extra bytes after a complete upload body get the pending response, then the connection closes', async () => {
  const cases = [
    { label: 'later packet, while the handler works', first: upload(), second: EXTRA },
    { label: 'same packet', first: upload() + EXTRA, second: null },
  ];
  for (const { label, first, second } of cases) {
    await quiesce();
    calls.length = 0;
    const requestsBefore = requestStatuses().length;
    const deferredBefore = events(SEC11_EVENT).length;
    const guardBefore = guardHits;
    const result = await exchange(served.port, first, { second });
    assert.deepEqual(result.statuses, [200], `${label}: the upload's own response, never the parser's 400 (got ${result.statuses})`);
    assert.doesNotMatch(result.text, /HTTP\/1\.1 400 /, `${label}: no parser 400`);
    assert.match(result.text, new RegExp(`"bytes":${UPLOAD_BYTES}}`), `${label}: the handler read exactly the declared body`);
    assert.match(result.text, /\r\nconnection: close\r\n/i, `${label}: the pending response closes the keep-alive connection`);
    assert.equal(result.serverEnded, true, `${label}: then the server closes the connection`);
    assert.equal(result.closedByLimit, false, `${label}: the connection closed by itself`);
    assert.deepEqual(calls, [`upload:A:${UPLOAD_BYTES}`], `${label}: one upload handled`);
    assert.deepEqual(requestsSince(requestsBefore), ['uploadDocument:200'], `${label}: one request handled and logged`);
    const deferred = events(SEC11_EVENT).slice(deferredBefore);
    assert.equal(deferred.length, 1, `${label}: the server logged its decision once`);
    assert.equal(deferred[0].parser_error, 'HPE_INVALID_METHOD');
    assert.equal(deferred[0].pending_responses, 1);
    assert.equal(guardHits, guardBefore, `${label}: every barrier opened on its condition`);
  }
});

test('[SEC-11] a malformed request behind a pending upload in the same write is refused and never replaces the upload response', async () => {
  await assertUploadResponseKept('single write', upload('A') + chunkedHead('B') + BAD_CHUNK, null, 'HPE_INVALID_CHUNK_SIZE');
});

test('[SEC-11] a malformed request sent while the upload handler is held is refused and never replaces its response', async () => {
  await assertUploadResponseKept('separate writes', upload('A'), chunkedHead('B') + BAD_CHUNK, 'HPE_INVALID_CHUNK_SIZE');
});

test('[SEC-11] a chunk-extension overflow behind a pending upload never replaces its response with Node 413', async () => {
  await assertUploadResponseKept('chunk-extension overflow', upload('A') + chunkedHead('B') + LONG_EXTENSION, null, 'HPE_CHUNK_EXTENSIONS_OVERFLOW');
});

test('[SEC-11] a complete request queued behind the pending response is refused, as after any decided close', async () => {
  await quiesce();
  calls.length = 0;
  entered.length = 0;
  const requestsBefore = requestStatuses().length;
  const linesBefore = served.lines.length;
  const guardBefore = guardHits;
  // R (keep-alive), then C, a complete mutating request, then junk, in one write. R's handler is
  // held until the parser has run over every byte, so the SEC-11 decision (taken on the junk)
  // always comes before R's response; C is dispatched by Node before that decision, but its turn
  // comes only after R's, so it always finds the connection closing.
  const result = await exchange(served.port, read('X-Test-Label: R\r\n') + create(5, 'X-Test-Label: C\r\n') + EXTRA);
  assert.deepEqual(result.statuses, [200], `R's response only (got ${result.statuses})`);
  assert.doesNotMatch(result.text, /HTTP\/1\.1 400 /);
  assert.match(result.text, /\r\nconnection: close\r\n/i);
  assert.equal(result.serverEnded, true);
  assert.equal(result.closedByLimit, false);
  assert.deepEqual(entered, ['R'], 'C\'s handler was never entered');
  assert.deepEqual(calls, ['read'], 'the queued mutating request had no effect');
  assert.deepEqual(requestsSince(requestsBefore), ['readEnvelope:200'], 'only R was handled and logged');
  const order = served.lines
    .slice(linesBefore)
    .map((line) => JSON.parse(line))
    .filter((record) => [SEC11_EVENT, 'request', 'pipelined_request_refused'].includes(record.event))
    .map((record) => (record.event === SEC11_EVENT ? `decision:${record.pending_responses}` : record.event === 'request' ? `served:${record.operation}` : `refused:${record.method} ${record.path}`));
  assert.deepEqual(order, ['decision:2', 'served:readEnvelope', 'refused:POST /v1/envelopes'], 'the decision with R and C pending, then R served, then C refused (SEC-08)');
  assert.equal(guardHits, guardBefore, 'every barrier opened on its condition');
});

test('[SEC-11] after the pending response the server half-closes, lingers and then closes the connection itself', async () => {
  await quiesce();
  calls.length = 0;
  const guardBefore = guardHits;
  // The ruled case (extra bytes after a complete upload body), with a client that reads the
  // response and the server's FIN but never closes or destroys its own side.
  const result = await exchangeNeverClosing(served.port, upload('A') + EXTRA);
  assert.deepEqual(result.statuses, [200], `the upload's response (got ${result.statuses})`);
  assert.match(result.text, /\r\nconnection: close\r\n/i);
  assert.equal(result.serverEnded, true, 'the server half-closed after the response');
  assert.equal(result.serverClosed, true, `the server closed the connection itself (hang guard ${LINGER_GUARD_MS} ms)`);
  assert.equal(result.clientStillOpen, true, 'the client had not closed its side: the close was the server\'s');
  assert.deepEqual(calls, [`upload:A:${UPLOAD_BYTES}`]);
  assert.equal(guardHits, guardBefore, 'every barrier opened on its condition');
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
    assert.equal(overflow.text, NODE_431, 'exactly Node\'s 431');
    assert.equal(overflow.closedByLimit, false);
    assert.deepEqual(handled(), [], 'nothing was handled');

    // A malformed first request alone (an invalid chunk size, or an over-long chunk extension):
    // its own error, with nothing before it, gets Node's 400 or 413.
    const malformedFirst = await exchange(control.port, chunkedHead('B') + BAD_CHUNK);
    assert.equal(malformedFirst.text, NODE_400, 'exactly Node\'s 400');
    assert.equal(malformedFirst.closedByLimit, false);
    const extensionFirst = await exchange(control.port, chunkedHead('B') + LONG_EXTENSION);
    assert.equal(extensionFirst.text, NODE_413, 'exactly Node\'s 413');
    assert.equal(extensionFirst.closedByLimit, false);

    // Bytes after a finished response on a keep-alive connection.
    const before = handled().length;
    const finished = await exchange(control.port, read(), { second: EXTRA, after: 'response' });
    assert.deepEqual(finished.statuses, [200, 400], `the finished response, then Node's 400 (got ${finished.statuses})`);
    assert.ok(finished.text.endsWith(NODE_400), 'the second response is exactly Node\'s 400');
    assert.doesNotMatch(finished.text.slice(0, finished.text.indexOf(NODE_400)), /\r\nconnection: close\r\n/i, 'the first response kept the connection');
    assert.equal(finished.closedByLimit, false);
    assert.deepEqual(reads, ['read']);
    assert.deepEqual(handled().slice(before), [200]);

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
