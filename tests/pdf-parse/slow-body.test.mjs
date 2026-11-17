// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-25 (A-010 LBR4-1; oracle amended by A-010 PL25-ORC): slow upload
// bodies never hold parse slots.
//
// A real HTTP server on 127.0.0.1 hands each request stream straight to parsePdf(), and slow
// senders are real sockets that send one body byte per second. Every pass criterion is state
// the service itself reports (parseCapacity(), parseAdmissions(), bodyReadCapacity()), reached
// through barriers. No fixed sleep orders the test, and no wall-clock bound is a pass criterion.
//
// - Two slow uploads hold two body-read permits (barrier: 2 held). While they are in flight no
//   parse runs or waits, and no arrival ticket is drawn (parseAdmissions().next_ticket does not
//   move): a parse slot is taken only after the buffered body.
// - An honest upload and a composition (an in-memory parse) both enter the parse gate, are
//   admitted with nothing waiting, and complete with 200.
// - With every body-read permit held (barrier: 4 held), a further upload that sends its headers
//   only is refused with 429 rate_limited, reason body-read-capacity, before any body byte is
//   sent. A refused in-memory stream is never read (pulled === 0). Refusals draw no ticket, and
//   a composition still completes. A freed permit (a client abort) admits the next upload.
// - A client abort mid-body leaves no body-read permit and no parse slot held, and parsePdf()
//   rethrows the abort to its caller.
//
// Latency is a diagnostic only: it is logged (t.diagnostic), never asserted. Every wait is
// bounded by one generous hang guard, HANG_GUARD_MS, three times the parse child's own
// wall-time limit. A guard that fires fails under its own message, which names what it waited
// for and the service's state at that moment.
//
// AFTER A-010 PL25-ORC, ANY FIRING OF THE HANG GUARD IS REAL. The slow phase behind the natural
// failure at the 58f88da acceptance (the old 3000 ms LATENCY_BOUND_MS) was never observed, and
// its cause was inferred, not established. This oracle has no wall-clock pass bound, so a stall
// long enough to fire the guard is a defect or a host fault: stop and report it, with the
// guard's message verbatim. Never rerun it until it goes green.
//
// Isolation: each test's cleanup is unconditional (t.after). It destroys every socket the test
// opened, awaits every promise it issued and drains the service to idle. Each test starts by
// asserting idle (0 parse slots running, 0 waiting, 0 body-read permits held) and names any
// leftover, so one test's failure never surfaces as a misleading assertion in the next.

import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { connect } from 'node:net';
import { performance } from 'node:perf_hooks';
import { after, before, test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';

import { DEFAULT_SERVICE_LIMITS } from '../../src/pdf/limits.ts';
import * as service from '../../src/pdf/service.ts';
import { basicObjects, classicPdf } from './pdf-builder.mjs';

/** The one bound on every wait: three times the parse child's own wall-time limit (60 s). */
const HANG_GUARD_MS = 3 * DEFAULT_SERVICE_LIMITS.wallMs;
const POLL_MS = 5;
const pdf = classicPdf(basicObjects());
let server;
let port;
const handled = { aborted: 0 };
/** Every client socket any test opened and has not yet seen close; the after hook destroys them. */
const clients = new Set();
/** Server-side sockets by the client's local port, to see how many bytes reached the server. */
const serverSockets = new Map();

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
  server.on('connection', (socket) => {
    const key = socket.remotePort;
    serverSockets.set(key, socket);
    socket.on('close', () => {
      if (serverSockets.get(key) === socket) serverSockets.delete(key);
    });
  });
  await new Promise((resolveListen) => server.listen({ host: '127.0.0.1', port: 0 }, resolveListen));
  port = server.address().port;
  const warm = await service.parsePdf(pdf);
  assert.equal(warm.status, 200, warm.ok ? '' : `${warm.reason} ${warm.detail}`);
});

after(async () => {
  for (const socket of clients) socket.destroy();
  await new Promise((resolveClose) => {
    server.close(resolveClose);
    server.closeAllConnections();
  });
});

// --- service state, idle and the hang guard ---------------------------------------------------

function state() {
  const parse = service.parseCapacity();
  return { running: parse.running, waiting: parse.waiting, held: service.bodyReadCapacity().held, next_ticket: service.parseAdmissions().next_ticket };
}

const show = (s = state()) => `running=${s.running} waiting=${s.waiting} held=${s.held} next_ticket=${s.next_ticket}`;
const isIdle = () => {
  const s = state();
  return s.running === 0 && s.waiting === 0 && s.held === 0;
};

/** A test starts idle; the message names every leftover. */
function assertIdle(which) {
  const s = state();
  const leftovers = [];
  if (s.running !== 0) leftovers.push(`${s.running} parse slot(s) running`);
  if (s.waiting !== 0) leftovers.push(`${s.waiting} parse(s) waiting for a slot`);
  if (s.held !== 0) leftovers.push(`${s.held} body-read permit(s) held`);
  assert.deepEqual(leftovers, [], `${which} must start idle (0 parse slots running, 0 waiting, 0 body-read permits held); left over from an earlier test: ${leftovers.join(', ')}`);
}

/** The hang guard's own failure. After A-010 PL25-ORC a firing is REAL (see the file header). */
function hangGuard(what, started) {
  const label = typeof what === 'function' ? what() : what;
  assert.fail(
    `PL-25 hang guard fired after ${Math.round(performance.now() - started)} ms (bound ${HANG_GUARD_MS} ms): ${label}. ` +
      `Service state: ${show()}. After A-010 PL25-ORC this is REAL, not a flake: report it verbatim and do not rerun to settle it.`,
  );
}

/** Barrier: poll `check` until it holds, under the hang guard. Resolves with the wait in ms. */
async function until(check, what) {
  const started = performance.now();
  while (!check()) {
    if (performance.now() - started > HANG_GUARD_MS) hangGuard(what, started);
    await sleep(POLL_MS);
  }
  return performance.now() - started;
}

/** Await `promise` under the hang guard; the guard's timer never outlives the wait. */
async function settle(promise, what) {
  const started = performance.now();
  let timer;
  const guard = new Promise((_, rejectGuard) => {
    timer = setTimeout(() => {
      try {
        hangGuard(what, started);
      } catch (error) {
        rejectGuard(error);
      }
    }, HANG_GUARD_MS);
  });
  try {
    return await Promise.race([promise, guard]);
  } finally {
    clearTimeout(timer);
  }
}

/** With uploads in flight: no parse runs or waits, and no arrival ticket was drawn. */
function assertNoParse(ticket, when) {
  const s = state();
  assert.deepEqual(
    { running: s.running, waiting: s.waiting, next_ticket: s.next_ticket },
    { running: 0, waiting: 0, next_ticket: ticket },
    `${when}: no parse runs or waits and no arrival ticket is drawn (next_ticket stays ${ticket}), because a parse slot is taken only after the buffered body (${show(s)})`,
  );
}

/** Bytes of `client`'s connection that have reached the server. */
const serverBytes = (client) => serverSockets.get(client.localPort)?.bytesRead ?? 0;

const uploadHead = (length) => `PUT /upload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/pdf\r\nContent-Length: ${length}\r\n\r\n`;

/** Status and JSON body of a complete HTTP/1.1 response (Content-Length or chunked framing). */
function parseResponse(raw) {
  const text = raw.toString('latin1');
  const end = text.indexOf('\r\n\r\n');
  if (end < 0) throw new Error(`no complete response head: ${JSON.stringify(text.slice(0, 80))}`);
  const head = text.slice(0, end).split('\r\n');
  const status = Number(/^HTTP\/1\.1 (\d{3}) /.exec(head[0] ?? '')?.[1]);
  let body = text.slice(end + 4);
  if (head.some((line) => /^transfer-encoding:\s*chunked$/i.test(line))) {
    let rest = body;
    body = '';
    for (;;) {
      const lineEnd = rest.indexOf('\r\n');
      const size = lineEnd < 0 ? 0 : Number.parseInt(rest.slice(0, lineEnd), 16);
      if (!(size > 0)) break;
      body += rest.slice(lineEnd + 2, lineEnd + 2 + size);
      rest = rest.slice(lineEnd + 2 + size + 2);
    }
  }
  return { status, json: body ? JSON.parse(body) : null };
}

// --- what a test has in flight ----------------------------------------------------------------

/**
 * One test's sockets and promises. cleanup() is the unconditional teardown: destroy every
 * socket, await every issued promise, drain the service to idle (each wait under the guard).
 * A sampler records the most parses ever seen waiting for a slot while the test runs.
 */
function flight() {
  const own = new Set();
  const issued = [];
  const seen = { waiting: 0 };
  const sampler = setInterval(() => {
    seen.waiting = Math.max(seen.waiting, service.parseCapacity().waiting);
  }, POLL_MS);

  const track = (socket) => {
    own.add(socket);
    clients.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => {
      own.delete(socket);
      clients.delete(socket);
    });
    return socket;
  };
  const issue = (label, promise) => {
    // Handled from the start, so a rejection while a barrier waits is never an unhandled
    // rejection; whoever awaits the promise still sees it.
    promise.catch(() => {});
    issued.push({ label, promise });
    return promise;
  };

  return {
    maxWaiting: () => Math.max(seen.waiting, service.parseCapacity().waiting),

    /** A real upload that declares 4000 bytes and sends one byte per second. */
    slowUpload() {
      const socket = track(connect({ host: '127.0.0.1', port }));
      socket.write(`${uploadHead(4000)}%`);
      const timer = setInterval(() => {
        if (!socket.destroyed) socket.write('%');
      }, 1000);
      socket.on('close', () => clearInterval(timer));
      return socket;
    },

    /** An honest upload of `body`, sent at once; resolves with the status and the latency. */
    upload(label, body) {
      return issue(
        label,
        new Promise((resolveUpload, rejectUpload) => {
          const started = performance.now();
          const req = request(
            { host: '127.0.0.1', port, method: 'PUT', path: '/upload', agent: false, headers: { 'content-type': 'application/pdf', 'content-length': body.length } },
            (res) => {
              let text = '';
              res.setEncoding('utf8');
              res.on('data', (chunk) => (text += chunk));
              res.on('end', () => {
                try {
                  resolveUpload({ status: res.statusCode, json: text ? JSON.parse(text) : null, ms: performance.now() - started });
                } catch (error) {
                  rejectUpload(error);
                }
              });
            },
          );
          req.on('socket', track);
          req.on('error', rejectUpload);
          req.on('close', () => {
            if (req.res?.complete !== true) rejectUpload(new Error(`${label}: the connection closed before a complete response`));
          });
          req.end(body);
        }),
      );
    },

    /**
     * An upload that sends its headers only: it declares the document's length and never sends
     * a body byte, so a response can only come from a refusal that does not read the body.
     */
    headersOnly(label) {
      const socket = track(connect({ host: '127.0.0.1', port }));
      const head = uploadHead(pdf.length);
      const started = performance.now();
      socket.write(head);
      const outcome = { settled: false };
      outcome.promise = issue(
        label,
        new Promise((resolveResponse, rejectResponse) => {
          const chunks = [];
          socket.on('data', (chunk) => chunks.push(chunk));
          socket.on('end', () => {
            try {
              const response = parseResponse(Buffer.concat(chunks));
              resolveResponse({ ...response, bodyBytesSent: socket.bytesWritten - Buffer.byteLength(head), ms: performance.now() - started });
            } catch (error) {
              rejectResponse(error);
            }
          });
          socket.on('close', () => rejectResponse(new Error(`${label}: the connection closed before a complete response`)));
        }).finally(() => {
          outcome.settled = true;
        }),
      );
      return outcome;
    },

    /** A raw upload whose bytes the caller writes. */
    rawUpload() {
      return track(connect({ host: '127.0.0.1', port }));
    },

    /** A composition: an in-memory parse; resolves with the outcome and the latency. */
    compose(label) {
      const started = performance.now();
      return issue(
        label,
        service.parsePdf(pdf).then((outcome) => ({ status: outcome.status, reason: outcome.reason ?? null, ms: performance.now() - started })),
      );
    },

    async cleanup(which) {
      clearInterval(sampler);
      for (const socket of own) socket.destroy();
      await settle(Promise.allSettled(issued.map(({ promise }) => promise)), `${which} cleanup: every issued request and parse settles (${issued.map(({ label }) => label).join(', ') || 'none'})`);
      await until(isIdle, () => `${which} cleanup: the service drains to idle`);
    },
  };
}

const ms = (value) => `${value.toFixed(0)} ms`;

// --- tests ------------------------------------------------------------------------------------

test('[PL-25] slow uploads hold body-read permits, never parse slots: an honest upload and a composition are admitted with nothing waiting and complete; a full body-read cap refuses before any body byte', async (t) => {
  assertIdle('PL-25 test 1 (slow uploads)');
  const run = flight();
  t.after(() => run.cleanup('PL-25 test 1'));
  const max = service.MAX_CONCURRENT_BODY_READS;
  assert.equal(max, 4);
  assert.equal(service.MAX_CONCURRENT_PARSES, 2);
  const base = service.parseAdmissions().next_ticket;

  // Two uploads at one byte per second (the LBR4-1 shape). Barrier: both hold a body-read
  // permit and their first body byte has reached the server.
  const slow = [run.slowUpload(), run.slowUpload()];
  await until(() => service.bodyReadCapacity().held === 2, 'two slow uploads each take a body-read permit');
  await until(() => slow.every((socket) => serverBytes(socket) > uploadHead(4000).length), 'the first body byte of each slow upload reaches the server');
  assertNoParse(base, 'with two slow uploads in flight');

  // The honest upload and the composition both enter the parse gate and are admitted with
  // nothing waiting; their 200s are awaited under the hang guard only.
  const honestPending = run.upload('the honest upload', pdf);
  const compositionPending = run.compose('the composition');
  await until(() => service.parseAdmissions().next_ticket >= base + 2, 'the honest upload and the composition both enter the parse gate');
  const entered = service.parseAdmissions();
  assert.equal(entered.next_ticket, base + 2, `exactly two parses entered the gate, the honest upload and the composition, and no slow upload (${show()})`);
  assert.ok(
    entered.admitted.includes(base) && entered.admitted.includes(base + 1),
    `both were admitted to a parse slot: tickets ${base} and ${base + 1} in the admission record [${entered.admitted.join(',')}] (${show()})`,
  );
  assert.equal(run.maxWaiting(), 0, `nothing waited for a parse slot while they entered (${show()})`);
  const [honest, composition] = await Promise.all([
    settle(honestPending, 'the honest upload, with two slow uploads in flight, returns its response'),
    settle(compositionPending, 'the composition, with two slow uploads in flight, completes'),
  ]);
  t.diagnostic(`2 slow uploads: honest upload ${honest.status} in ${ms(honest.ms)}, composition ${composition.status} in ${ms(composition.ms)} (latency is a diagnostic only)`);
  assert.equal(honest.status, 200, `an honest upload completes while two slow uploads are in flight (${honest.json?.reason ?? 'no reason'})`);
  assert.equal(composition.status, 200, `a composition completes while two slow uploads are in flight (${composition.reason ?? 'no reason'})`);
  assert.equal(service.parseCapacity().running, 0, 'the slow uploads hold no parse slot');
  assert.equal(service.bodyReadCapacity().held, 2, 'each slow upload holds one body-read permit');
  assert.equal(service.parseAdmissions().next_ticket, base + 2, 'the slow uploads drew no arrival ticket while the others parsed');
  assert.equal(run.maxWaiting(), 0, 'no parse waited for a slot behind the slow uploads');

  // Every body-read permit held by slow senders (barrier: 4 held). A further upload that sends
  // its headers only is refused with 429 before any body byte; a composition is unaffected.
  for (let i = slow.length; i < max; i += 1) slow.push(run.slowUpload());
  await until(() => service.bodyReadCapacity().held === max, 'all body-read permits held');
  assertNoParse(base + 2, `with ${max} slow uploads in flight`);
  const refusal = run.headersOnly('the refused upload');
  const composedPending = run.compose('the composition with every body-read permit held');
  await until(() => refusal.settled || service.bodyReadCapacity().held > max, 'the further upload is answered');
  assert.ok(service.bodyReadCapacity().held <= max, `the body-read cap of ${max} must refuse a further upload, but it took a permit (${show()})`);
  const [refused, composed] = await Promise.all([
    settle(refusal.promise, 'the headers-only upload, with every body-read permit held, is answered'),
    settle(composedPending, 'the composition, with every body-read permit held, completes'),
  ]);
  t.diagnostic(`${max} slow uploads: upload ${refused.status} ${refused.json?.reason} in ${ms(refused.ms)}, composition ${composed.status} in ${ms(composed.ms)} (latency is a diagnostic only)`);
  assert.deepEqual([refused.status, refused.json?.reason], [429, 'body-read-capacity']);
  assert.equal(refused.bodyBytesSent, 0, 'the 429 arrived before any body byte was sent: the refusal never reads the body');
  assert.equal(composed.status, 200, `a composition completes while every body-read permit is held (${composed.reason ?? 'no reason'})`);
  let pulled = 0;
  const stream = (async function* body() {
    pulled += 1;
    yield pdf;
  })();
  const direct = await settle(service.parsePdf(stream), 'the refused in-memory stream is answered');
  assert.deepEqual([direct.status, direct.code, direct.reason], [429, 'rate_limited', 'body-read-capacity']);
  assert.equal(pulled, 0, 'a refused upload is never read');
  assert.equal(service.parseAdmissions().next_ticket, base + 3, `the composition drew one arrival ticket and the two refusals none (${show()})`);

  // A freed permit (here a client abort) admits the next upload. The release precedes the
  // rethrow, so once parsePdf() has rethrown the abort to the handler the permit is free.
  const abortsBefore = handled.aborted;
  slow.pop().destroy();
  await until(() => handled.aborted === abortsBefore + 1, 'parsePdf() rethrows the client abort to its caller');
  assert.equal(service.bodyReadCapacity().held, max - 1, `the aborted upload releases its permit (${show()})`);
  const admitted = await settle(run.upload('the next upload', pdf), 'the next upload, once a permit is free, returns its response');
  t.diagnostic(`a freed permit: next upload ${admitted.status} in ${ms(admitted.ms)} (latency is a diagnostic only)`);
  assert.equal(admitted.status, 200, `the next upload is admitted once a permit is free (${admitted.json?.reason ?? 'no reason'})`);
  assert.equal(service.parseAdmissions().next_ticket, base + 4, `only the admitted upload drew a ticket; the remaining slow uploads drew none (${show()})`);
  assert.equal(run.maxWaiting(), 0, 'no parse waited for a slot at any point');
  // t.after: destroy the remaining slow uploads, await every issued promise, drain to idle.
});

test('[PL-25] a client abort mid-body leaves no body-read permit and no parse slot held', async (t) => {
  assertIdle('PL-25 test 2 (client abort)');
  const run = flight();
  t.after(() => run.cleanup('PL-25 test 2'));
  const base = service.parseAdmissions().next_ticket;
  const abortsBefore = handled.aborted;

  const socket = run.rawUpload();
  const head = uploadHead(pdf.length);
  const half = pdf.subarray(0, Math.floor(pdf.length / 2));
  socket.write(head);
  socket.write(half);
  await until(() => service.bodyReadCapacity().held === 1, 'the upload takes a body-read permit');
  await until(() => serverBytes(socket) >= Buffer.byteLength(head) + half.length, 'the first half of the body reaches the server');
  assertNoParse(base, 'with half of a body arrived');
  socket.destroy();
  await until(() => handled.aborted === abortsBefore + 1, 'parsePdf() rethrows the abort to its caller');
  assert.ok(isIdle(), `the abort releases the permit, and no slot was taken (${show()})`);
  assert.equal(service.parseAdmissions().next_ticket, base, 'the aborted upload never entered the parse gate');

  // The same for an in-memory stream whose producer fails mid-body.
  const failing = (async function* body() {
    yield pdf.subarray(0, 100);
    throw new Error('synthetic abort');
  })();
  await assert.rejects(settle(service.parsePdf(failing), 'the failing stream rejects'), /synthetic abort/);
  assert.ok(isIdle(), `nothing is held after a failing stream (${show()})`);
  assert.equal(service.parseAdmissions().next_ticket, base, 'the failing stream never entered the parse gate');
});
