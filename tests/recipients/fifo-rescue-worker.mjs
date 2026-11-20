// SPDX-License-Identifier: Apache-2.0
//
// CH-01's FIFO rescuer (T008; A-010 row KEY-FIFO, request #30). A worker
// thread that, when the test's main thread has not come back from
// loadChallengeKey within `afterMs`, opens the FIFO's other end, so a
// blocking open(2) of the FIFO returns. A regression (the loader opening
// without O_NONBLOCK) therefore fails CH-01 after one bounded wait instead of
// hanging the test runner: a synchronous open blocks the main thread, where
// no test timeout can reach it, but this thread has its own event loop.
//
// Shared flags (an Int32Array over workerData.flags): [0] is set by the main
// thread once the load returned; [1] is set here when the other end had to be
// opened. On Linux, opening a FIFO O_RDWR never blocks and counts as a writer,
// which wakes a reader blocked in open(2). The interval tries again until the
// main thread has returned; the test terminates this worker in `finally`.

import { closeSync, constants, openSync } from 'node:fs';
import { parentPort, workerData } from 'node:worker_threads';

const flags = new Int32Array(workerData.flags);

setInterval(() => {
  if (Atomics.load(flags, 0) !== 0) return;
  Atomics.store(flags, 1, 1);
  try {
    closeSync(openSync(workerData.path, constants.O_RDWR | constants.O_NONBLOCK));
  } catch {
    // The next interval tries again; the main thread's own bound still applies.
  }
}, workerData.afterMs);

parentPort.postMessage('armed');
