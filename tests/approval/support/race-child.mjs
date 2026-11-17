// SPDX-License-Identifier: Apache-2.0
//
// One racer of the T010 race tests (AP-12, AP-14), in its own OS process. It opens the shared
// database file with its own connection and builds the same production modules the server
// composes: the T008 recipient ceremony (real blob store, real spool notifier, the 0600
// challenge-key file), the T010 ApprovalApi, and a T007 EnvelopeService whose onChange is the
// ceremony's (for void and the sweeper). It then runs exactly one action:
// - approve / decline: authenticate the session cookie (as the T008 guard does, without the
//   refresh write), then ApprovalApi.approve or ApprovalApi.decline: the calls the handlers
//   make after the guard;
// - void: EnvelopeService.void inside the ceremony's capture (T034's voidEnvelope);
// - sweep: one runExpirySweep (src/jobs/expiry.ts), reporting to the ceremony's listener;
// - hold: one empty write transaction (only useful paused before its commit: it holds the
//   write lock while the other racers queue for it).
// The clock is fixed at the job's instant. Nothing in production is replaced: the only test
// device is a proxy over this process's Database whose transaction() can pause, before or
// after the commit of the nth transaction once armed (armed right before the action), until
// the parent writes a line on stdin. The database connection, the SQLite write lock (BEGIN
// IMMEDIATE) and every statement are real.
//
// Protocol: the job is a JSON file (argv[2], 0600, in the test's mkdtemp directory). Events are
// JSON lines on stdout: ready, authenticated, gated, attempting, paused, result, error. The
// parent answers gated and paused with a line on stdin. Every wait is bounded; a closed stdin
// ends the process. Results carry status, error code and the response bytes (a receipt or a
// decline outcome: no capability value); nothing is logged.

import { readFileSync, readSync, writeSync } from 'node:fs';

import { ApprovalApi } from '../../../src/api/recipients/approval.ts';
import { RecipientCeremony, loadChallengeKey } from '../../../src/api/recipients/index.ts';
import { EnvelopeService } from '../../../src/domain/envelopes/service.ts';
import { runExpirySweep } from '../../../src/jobs/expiry.ts';
import { createNotifier, createSpoolTransport } from '../../../src/notifications/index.ts';
import { createLogger } from '../../../src/server/redact.ts';
import { openBlobStore } from '../../../src/storage/blobs/index.ts';
import { openDatabase } from '../../../src/storage/db/index.ts';

/** The longest the child waits for a line from its parent. */
const WAIT_LIMIT_MS = 120_000;
const SLEEP = new Int32Array(new SharedArrayBuffer(4));

function emit(event) {
  writeSync(1, `${JSON.stringify(event)}\n`);
}

/** Block until the parent writes a line on stdin (bounded; a closed stdin is an error). */
function waitForParent(label) {
  const byte = Buffer.alloc(1);
  const deadline = Date.now() + WAIT_LIMIT_MS;
  for (;;) {
    let n;
    try {
      n = readSync(0, byte, 0, 1, null);
    } catch (error) {
      if (error?.code === 'EAGAIN') {
        if (Date.now() > deadline) throw new Error(`no ${label} line from the parent within ${WAIT_LIMIT_MS} ms`);
        Atomics.wait(SLEEP, 0, 0, 10);
        continue;
      }
      throw error;
    }
    if (n === 0) throw new Error(`the parent closed stdin before the ${label} line`);
    if (byte[0] === 0x0a) return;
  }
}

function errorOf(error) {
  return { status: typeof error?.status === 'number' ? error.status : null, code: typeof error?.code === 'string' ? error.code : 'unexpected', message: String(error?.message ?? error).slice(0, 200) };
}

const job = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const real = openDatabase({ path: job.dbPath, busyTimeoutMs: job.busyTimeoutMs });
let armed = null;

/** Database.transaction with the optional pause (the only test device). */
function transaction(fn) {
  if (armed === null) return real.transaction(fn);
  armed.count += 1;
  const mine = armed.pause !== null && armed.count === armed.pause.nth;
  if (mine && armed.pause.phase === 'before-commit') {
    return real.transaction(() => {
      const value = fn();
      emit({ event: 'paused', phase: 'before-commit', nth: armed.pause.nth });
      waitForParent('release');
      return value;
    });
  }
  const value = real.transaction(fn);
  if (mine && armed.pause.phase === 'after-commit') {
    emit({ event: 'paused', phase: 'after-commit', nth: armed.pause.nth });
    waitForParent('release');
  }
  return value;
}

const db = new Proxy(real, {
  get(target, property) {
    if (property === 'transaction') return transaction;
    const value = Reflect.get(target, property, target);
    return typeof value === 'function' ? value.bind(target) : value;
  },
});

const clock = () => new Date(job.clockMs);
const logger = createLogger(() => {});
const notifier = createNotifier({
  transport: createSpoolTransport({ dir: job.spoolDir }),
  from: 'no-reply@opensig.test',
  publicOrigin: 'https://sign.alpha.test',
  rateLimit: { limit: 10_000, windowMs: 600_000 },
  logger,
  now: () => job.clockMs,
});
const ceremony = new RecipientCeremony({ db, blobs: openBlobStore({ root: job.blobRoot }), notifier, challengeKey: loadChallengeKey({ path: job.keyPath }), clock, logger });
const envelopes = new EnvelopeService({ db, clock, onChange: ceremony.onEnvelopeChange });
const api = new ApprovalApi({ db, ceremony, clock });

async function run() {
  let session = null;
  if (job.action === 'approve' || job.action === 'decline') {
    session = ceremony.authenticate({ headers: { cookie: `__Host-opensig_rs=${job.cookie}` } }, { refresh: false });
    emit({ event: 'authenticated', ok: session !== null });
  }
  emit({ event: 'ready' });
  if (job.gate) {
    emit({ event: 'gated' });
    waitForParent('go');
  }
  armed = { pause: job.pause ?? null, count: 0 };
  emit({ event: 'attempting' });
  try {
    switch (job.action) {
      case 'approve':
      case 'decline': {
        if (session === null) return { status: 401, code: 'unauthenticated' };
        const result = job.action === 'approve' ? await api.approve(session, job.body) : await api.decline(session, job.body);
        return { status: result.status, bytes: Buffer.from(result.body).toString('base64') };
      }
      case 'void': {
        const { value } = ceremony.capture(() => envelopes.void({ tenantId: job.tenantId, actor: { kind: 'human-operator', ref: 'operator-race-tests' } }, job.envelopeId, job.body));
        return { status: value.status };
      }
      case 'sweep': {
        const report = runExpirySweep({ db, onEnvelopeChange: ceremony.onEnvelopeChange, clock });
        return { status: 200, expired: report.expired, purged: report.purged, complete: report.complete };
      }
      case 'hold':
        db.transaction(() => null);
        return { status: 200 };
      default:
        throw new Error(`unknown action ${String(job.action)}`);
    }
  } catch (error) {
    return errorOf(error);
  }
}

try {
  const result = await run();
  emit({ event: 'result', ...result });
  real.close();
  process.exit(0);
} catch (error) {
  emit({ event: 'error', message: String(error?.message ?? error).slice(0, 300) });
  real.close();
  process.exit(1);
}
