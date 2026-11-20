// SPDX-License-Identifier: Apache-2.0
//
// Child process for the two-runner publish race (FEN-02). It opens the shared
// database and blob store, waits (a bounded timer, never a spin) until the
// shared start instant, and runs the real publish transaction once with the
// attempt it was given. The parent's injected clock instant is passed in, so
// lease expiry is judged at the same instant in every process.
//
// Arguments: <database path> <blob root> <JSON publish input> <clock instant ISO> <start epoch ms>
// Stdout: one JSON line, { outcome: 'published' | 'refused' | 'error', ... }.

import { setTimeout as delay } from 'node:timers/promises';

import { PublishRefused, publishFinalization } from '../../../src/domain/finalization/index.ts';
import { AuditWriter } from '../../../src/storage/audit/index.ts';
import { openBlobStore } from '../../../src/storage/blobs/index.ts';
import { openDatabase } from '../../../src/storage/db/index.ts';

const [path, blobRoot, inputJson, instant, startArg] = process.argv.slice(2);
const { reportBytesBase64, ...rest } = JSON.parse(inputJson);
const input = { ...rest, reportBytes: Buffer.from(reportBytesBase64, 'base64') };
const clock = () => new Date(instant);
const db = openDatabase({ path, busyTimeoutMs: 30_000 });
let result;
try {
  const wait = Math.min(Math.max(0, Number(startArg) - Date.now()), 10_000);
  await delay(wait);
  const audit = new AuditWriter(db, { clock });
  const blobs = openBlobStore({ root: blobRoot });
  try {
    const published = publishFinalization(db, input, { clock, audit, blobs });
    result = { outcome: 'published', artifactId: published.artifactId, envelopeVersion: published.envelopeVersion };
  } catch (error) {
    result = error instanceof PublishRefused ? { outcome: 'refused', reason: error.reason } : { outcome: 'error', name: error?.name, code: error?.code };
  }
} finally {
  db.close();
}
process.stdout.write(`${JSON.stringify(result)}\n`);
