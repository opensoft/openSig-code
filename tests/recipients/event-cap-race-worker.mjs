// SPDX-License-Identifier: Apache-2.0
//
// CH-10's second connection (T008; A-010 row EVENT-CAP, request #46). A worker
// thread with its own connection to the world's database file and its own
// RecipientCeremony: real blob store, real spool notifier into the world's
// spool, and the 0600 challenge-key file. It runs one challenge request for the
// presented invitation once the main thread's first connection holds its write
// transaction open, then reports the ceremony's work counts.
//
// The only test device is a proxy over this thread's Database. Its
// transaction() sets the ENTERING flag before it calls the real
// transaction(), which then waits in BEGIN IMMEDIATE for the main thread's
// commit. A count made inside the transaction therefore runs after that
// commit, and a count made before transaction() would run before it.
//
// Shared flags (an Int32Array over workerData.flags): [0] GO is set by the main
// thread from inside its transaction; [1] ENTERING is set here. Every wait is
// bounded by workerData.waitMs. Messages: { ready: true } once the connection
// and the ceremony exist, then { stats } or { error }. No capability value is
// ever posted or logged.

import { parentPort, workerData } from 'node:worker_threads';

import { RecipientCeremony, loadChallengeKey } from '../../src/api/recipients/index.ts';
import { createNotifier, createSpoolTransport } from '../../src/notifications/index.ts';
import { createLogger } from '../../src/server/redact.ts';
import { openBlobStore } from '../../src/storage/blobs/index.ts';
import { openDatabase } from '../../src/storage/db/index.ts';

const GO = 0;
const ENTERING = 1;
const flags = new Int32Array(workerData.flags);
const db = openDatabase({ path: workerData.dbPath, busyTimeoutMs: workerData.busyTimeoutMs });
try {
  const watched = new Proxy(db, {
    get(target, property) {
      if (property === 'transaction') {
        return (fn) => {
          Atomics.store(flags, ENTERING, 1);
          Atomics.notify(flags, ENTERING);
          return target.transaction(fn);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  const logger = createLogger(() => {});
  const ceremony = new RecipientCeremony({
    db: watched,
    blobs: openBlobStore({ root: workerData.blobRoot }),
    notifier: createNotifier({
      transport: createSpoolTransport({ dir: workerData.spoolDir }),
      from: 'no-reply@opensig.test',
      publicOrigin: workerData.origin,
      rateLimit: { limit: 1000, windowMs: 600_000 },
      logger,
      now: () => workerData.nowMs,
    }),
    challengeKey: loadChallengeKey({ path: workerData.keyPath }),
    clock: () => new Date(workerData.nowMs),
    logger,
  });
  parentPort.postMessage({ ready: true });
  if (Atomics.wait(flags, GO, 0, workerData.waitMs) === 'timed-out') {
    parentPort.postMessage({ error: 'the first connection never held its transaction open' });
  } else {
    ceremony.requestChallenge({ invitation: workerData.invitation }, '192.0.2.20', 'cap-race-worker');
    await ceremony.drain();
    parentPort.postMessage({ stats: { ...ceremony.challengeWorkStats() } });
  }
} finally {
  db.close();
}
