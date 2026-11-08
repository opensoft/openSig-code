// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-04: the 10 MiB streaming cap. Input beyond the cap ends the read
// at the first chunk that would exceed it (413 payload_too_large) without reading the body
// in full and without starting a parse child; exactly 10 MiB is accepted.

import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { test } from 'node:test';

import { MAX_DOCUMENT_BYTES } from '../../src/pdf/limits.ts';
import { parsePdf } from '../../src/pdf/service.ts';
import { fixtureBytes, sha256 } from './support.mjs';

const CHUNK = 64 * 1024;

/** An async iterable over `buffer` in CHUNK pieces that records how much was pulled. */
function meteredChunks(buffer) {
  const meter = { pulled: 0, closed: false, completed: false };
  async function* chunks() {
    try {
      for (let at = 0; at < buffer.length; at += CHUNK) {
        const piece = buffer.subarray(at, Math.min(buffer.length, at + CHUNK));
        meter.pulled += piece.length;
        yield piece;
      }
      meter.completed = true;
    } finally {
      meter.closed = true;
    }
  }
  return { meter, iterable: chunks() };
}

test('[PL-04] input over 10 MiB is refused at the first chunk past the cap, before a full read', async () => {
  assert.equal(MAX_DOCUMENT_BYTES, 10 * 1024 * 1024);
  const oversized = fixtureBytes('oversized.pdf');
  assert.equal(oversized.length, MAX_DOCUMENT_BYTES + 1);

  const padded = Buffer.concat([oversized, Buffer.alloc(4 * 1024 * 1024, 0x20)]);
  const { meter, iterable } = meteredChunks(padded);
  const outcome = await parsePdf(iterable);
  assert.equal(outcome.ok, false);
  assert.equal(outcome.status, 413);
  assert.equal(outcome.code, 'payload_too_large');
  assert.equal(outcome.reason, 'size-limit');
  assert.ok(meter.pulled <= MAX_DOCUMENT_BYTES + CHUNK, `read stopped at ${meter.pulled} bytes`);
  assert.ok(meter.pulled < padded.length, 'the body was not read in full');
  assert.equal(meter.completed, false);
  assert.equal(meter.closed, true, 'the input iterator is closed');

  // A byte array over the cap is refused without parsing.
  const direct = await parsePdf(oversized);
  assert.equal(direct.status, 413);
});

test('[PL-04] an endless request stream terminates with 413 and is destroyed', async () => {
  let produced = 0;
  const endless = new Readable({
    read() {
      produced += CHUNK;
      this.push(Buffer.alloc(CHUNK, 0x25));
    },
  });
  const outcome = await parsePdf(endless);
  assert.equal(outcome.status, 413);
  assert.ok(produced <= MAX_DOCUMENT_BYTES + 4 * CHUNK, `stream produced ${produced} bytes`);
  assert.equal(endless.destroyed, true, 'the request stream is destroyed when the cap is hit');
});

test('[PL-04] exactly 10 MiB streamed in chunks is accepted with a digest of the exact bytes', async () => {
  const atLimit = fixtureBytes('size-at-limit.pdf');
  assert.equal(atLimit.length, MAX_DOCUMENT_BYTES);
  const { meter, iterable } = meteredChunks(atLimit);
  const outcome = await parsePdf(iterable);
  assert.equal(outcome.ok, true, outcome.ok ? '' : `${outcome.reason} ${outcome.detail}`);
  assert.equal(meter.completed, true);
  assert.equal(outcome.report.bytes, MAX_DOCUMENT_BYTES);
  assert.equal(outcome.report.digest, sha256(atLimit));
  assert.equal(outcome.report.pages.length, 1);

  // A lower configured cap applies to the same input.
  const lowered = await parsePdf(Readable.from([atLimit]), { limits: { maxBytes: 1024 * 1024 } });
  assert.equal(lowered.status, 413);
});
