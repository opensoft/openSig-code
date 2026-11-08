// SPDX-License-Identifier: Apache-2.0
//
// Child process for the blob store tests.
//
//   put <root> <tenant> <seed> <size> <start-at-ms>
//     Waits until <start-at-ms>, then stores the deterministic synthetic bytes
//     for <seed>/<size> and prints {"created": bool, "digest": hex}.
//   slow <root> <tenant>
//     Streams synthetic chunks forever with short pauses, printing "writing"
//     once data has reached the temp file. The parent kills it with SIGKILL.

import { setTimeout as delay } from 'node:timers/promises';

import { openBlobStore } from '../../../src/storage/blobs/index.ts';
import { syntheticBytes } from './synthetic.mjs';

const [mode, root, tenant, ...rest] = process.argv.slice(2);
const store = openBlobStore({ root });

if (mode === 'put') {
  const [seed, size, startAt] = rest;
  while (Date.now() < Number(startAt)) await delay(1);
  const result = store.put(tenant, syntheticBytes(seed, Number(size)));
  process.stdout.write(JSON.stringify({ created: result.created, digest: result.digest }));
} else if (mode === 'slow') {
  async function* chunks() {
    for (let i = 0; ; i += 1) {
      yield syntheticBytes(`slow-${i}`, 4096);
      // The previous chunk has been written to the temp file once the loop
      // asks for the next one.
      if (i === 2) process.stdout.write('writing\n');
      await delay(20);
    }
  }
  await store.putStream(tenant, chunks());
} else {
  process.stderr.write(`unknown mode ${mode}\n`);
  process.exitCode = 2;
}
