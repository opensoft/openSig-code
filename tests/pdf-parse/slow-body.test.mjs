// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-25 (A-010 LBR4-1): slow upload bodies never hold parse slots.
//
// A real HTTP server on 127.0.0.1 hands each request stream straight to parsePdf(), and
// slow senders are real sockets that send one body byte per second. With two such uploads in
// flight, an honest HTTP upload and a composition (an in-memory parse) each complete within
// LATENCY_BOUND_MS. With every body-read permit held by slow senders, a further upload is
// refused at once with 429 rate_limited (reason body-read-capacity) without its body being
// read, while a composition still completes; a freed permit admits the next upload. A client
// abort mid-body leaves no body-read permit and no parse slot held.

import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { connect } from 'node:net';
import { performance } from 'node:perf_hooks';
import { after, before, test } from 'node:test';

import * as service from '../../src/pdf/service.ts';
import { basicObjects, classicPdf } from './pdf-builder.mjs';

const LATENCY_BOUND_MS = 3000;
const pdf = classicPdf(basicObjects());
const sleep = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
let server;
let port;
const handled = { aborted: 0 };
const slowSockets = new Set();

before(async () => {
  server = createServer(async (req, res) => {
    try {
      const outcome = await service.parsePdf(req);
      res.writeHead(outcome.status, { 'content-type': 'application/json', connection: 'close' });
      res.end(JSON.stringify({ status: outcome.status, reason: outcome.reason ?? null }));
    } catch {
      handled.aborted += 1;
      if (!res.headersSent && !res.destroyed) res.writeHead(400, { connection: 'close' }).end();
    }
  });
  server.requestTimeout = 0;
  await new Promise((resolveListen) => server.listen({ host: '127.0.0.1', port: 0 }, resolveListen));
  port = server.address().port;
  const warm = await service.parsePdf(pdf);
  assert.equal(warm.status, 200, warm.ok ? '' : `${warm.reason} ${warm.detail}`);
});

after(async () => {
  for (const socket of slowSockets) socket.destroy();
  await new Promise((resolveClose) => {
    server.close(resolveClose);
    server.closeAllConnections();
  });
});

/** A real upload that declares 4000 bytes and sends one byte per second. */
function slowUpload() {
  const socket = connect({ host: '127.0.0.1', port });
  slowSockets.add(socket);
  socket.on('error', () => {});
  socket.write('PUT /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/pdf\r\nContent-Length: 4000\r\n\r\n%');
  const timer = setInterval(() => {
    if (!socket.destroyed) socket.write('%');
  }, 1000);
  socket.on('close', () => {
    clearInterval(timer);
    slowSockets.delete(socket);
  });
  return socket;
}

/** An honest upload of `body`, sent at once; resolves with the status and the latency. */
function upload(body) {
  return new Promise((resolveUpload, reject) => {
    const started = performance.now();
    const req = request(
      { host: '127.0.0.1', port, method: 'PUT', path: '/upload', agent: false, headers: { 'content-type': 'application/pdf', 'content-length': body.length } },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (text += chunk));
        res.on('end', () => resolveUpload({ status: res.statusCode, json: text ? JSON.parse(text) : null, ms: performance.now() - started }));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

/** A composition: an in-memory parse; resolves with the outcome and the latency. */
async function compose() {
  const started = performance.now();
  const outcome = await service.parsePdf(pdf);
  return { status: outcome.status, reason: outcome.reason ?? null, ms: performance.now() - started };
}

const within = (promise, ms) => Promise.race([promise, sleep(ms).then(() => ({ status: 'timeout', ms }))]);

async function until(check, ms, label) {
  const deadline = Date.now() + ms;
  while (!check()) {
    if (Date.now() > deadline) assert.fail(`${label} within ${ms} ms`);
    await sleep(20);
  }
}

const idle = () => {
  const parse = service.parseCapacity();
  return parse.running === 0 && parse.waiting === 0 && service.bodyReadCapacity().held === 0;
};

test('[PL-25] with slow uploads in flight, an honest upload and a composition complete within the bound; a full body-read cap refuses at once', async (t) => {
  // Two uploads at one byte per second (the LBR4-1 shape).
  const slow = [slowUpload(), slowUpload()];
  await sleep(1500);
  const [honest, composition] = await Promise.all([within(upload(pdf), LATENCY_BOUND_MS), within(compose(), LATENCY_BOUND_MS)]);
  t.diagnostic(`2 slow uploads: honest upload ${honest.status} in ${honest.ms.toFixed(0)} ms, composition ${composition.status} in ${composition.ms.toFixed(0)} ms`);
  assert.equal(honest.status, 200, `an honest upload completes within ${LATENCY_BOUND_MS} ms while two slow uploads are in flight`);
  assert.equal(composition.status, 200, `a composition completes within ${LATENCY_BOUND_MS} ms while two slow uploads are in flight`);
  assert.equal(service.parseCapacity().running, 0, 'the slow uploads hold no parse slot');
  assert.equal(service.bodyReadCapacity().held, 2, 'each slow upload holds one body-read permit');

  // Every body-read permit held by slow senders: a further upload is refused at once, its
  // body unread; a composition is unaffected.
  const max = service.MAX_CONCURRENT_BODY_READS;
  assert.equal(max, 4);
  for (let i = slow.length; i < max; i += 1) slow.push(slowUpload());
  await until(() => service.bodyReadCapacity().held === max, 3000, 'all body-read permits held');
  const [refused, composed] = await Promise.all([within(upload(pdf), LATENCY_BOUND_MS), within(compose(), LATENCY_BOUND_MS)]);
  t.diagnostic(`${max} slow uploads: upload ${refused.status} ${refused.json?.reason} in ${refused.ms.toFixed(0)} ms, composition ${composed.status} in ${composed.ms.toFixed(0)} ms`);
  assert.deepEqual([refused.status, refused.json?.reason], [429, 'body-read-capacity']);
  assert.ok(refused.ms < 1000, `refused at once (${refused.ms.toFixed(0)} ms)`);
  assert.equal(composed.status, 200, 'a composition completes while every body-read permit is held');
  let pulled = 0;
  const stream = (async function* body() {
    pulled += 1;
    yield pdf;
  })();
  const direct = await service.parsePdf(stream);
  assert.deepEqual([direct.status, direct.code, direct.reason], [429, 'rate_limited', 'body-read-capacity']);
  assert.equal(pulled, 0, 'a refused upload is never read');

  // A freed permit (here a client abort) admits the next upload.
  slow.pop().destroy();
  await until(() => service.bodyReadCapacity().held === max - 1, 3000, 'the aborted upload releases its permit');
  const admitted = await within(upload(pdf), LATENCY_BOUND_MS);
  assert.equal(admitted.status, 200, 'the next upload is admitted once a permit is free');

  for (const socket of slow) socket.destroy();
  await until(idle, 3000, 'every permit and slot is released');
});

test('[PL-25] a client abort mid-body leaves no body-read permit and no parse slot held', async () => {
  const before = handled.aborted;
  const socket = connect({ host: '127.0.0.1', port });
  socket.on('error', () => {});
  socket.write(`PUT /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/pdf\r\nContent-Length: ${pdf.length}\r\n\r\n`);
  socket.write(pdf.subarray(0, Math.floor(pdf.length / 2)));
  await sleep(300);
  assert.equal(service.parseCapacity().running, 0, 'a body still arriving holds no parse slot');
  await until(() => service.bodyReadCapacity().held === 1, 3000, 'the upload holds a body-read permit');
  socket.destroy();
  await until(idle, 2000, 'the abort releases the permit, and no slot was taken');
  await until(() => handled.aborted === before + 1, 2000, 'parsePdf() rethrows the abort to its caller');

  // The same for an in-memory stream whose producer fails mid-body.
  const failing = (async function* body() {
    yield pdf.subarray(0, 100);
    throw new Error('synthetic abort');
  })();
  await assert.rejects(service.parsePdf(failing), /synthetic abort/);
  assert.ok(idle(), 'nothing is held after a failing stream');
});
