// SPDX-License-Identifier: Apache-2.0
//
// VB-06 (request #63; the T014 line; row T014-XREFSTART): the shared inflate
// budget refuses a stream only when that stream's output is larger than the
// bytes still allowed, the comparison T033's inflate makes. A budget used up
// exactly never refuses an empty output, for cross-reference and object
// streams alike. No ratio limit is applied.
//
// These unit boundary cases use a small budget through decodeWithInflateBudget,
// a test-only seam that decodes one structural stream exactly as the reader
// does (the same decodeStream, with the cross-reference or object-stream
// details). It is kept out of product reach as readRevisionStructureCounted is:
// structure.ts alone exports it, index.ts does not, and the last case fails if
// any other module under src/ names it. The 512 MiB budget itself is never
// reached here; that would take about 22 million entries.
//
// Mutants killed here: the refusal before inflating once nothing is left,
// restored for cross-reference streams, or for object streams; `>` read as
// `>=`; the seam reachable from another src/ module.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';
import * as verifier from '../../../src/verifier/index.ts';
import { parseValue } from '../../../src/verifier/pdf-syntax.ts';
import { decodeWithInflateBudget } from '../../../src/verifier/structure.ts';
import { listFiles, stripComments } from './helpers/import-scan.mjs';

const FLATE_TEXT = '<< /Filter /FlateDecode >>';
const FLATE = parseValue(Buffer.from(FLATE_TEXT, 'latin1'), 0, FLATE_TEXT.length).value;
const BUDGET = 64;

/** A FlateDecode body whose output is `n` bytes. */
const deflated = (n) => deflateSync(Buffer.alloc(n, 0x20));

/** Decode a stream of `n` output bytes against `budget`; returns the seam's result. */
const decode = (kind, n, budget) => decodeWithInflateBudget(kind, FLATE, deflated(n), budget);

test('[VB-06] a cross-reference stream: an output using the budget exactly passes, then an empty one, and a one-byte one is refused (request #63)', () => {
  const budget = { inflated: BUDGET };
  const exact = decode('xref-stream', BUDGET, budget);
  assert.equal(exact.ok, true, exact.ok ? '' : `exact use refused: ${exact.detail}`);
  assert.equal(exact.data.length, BUDGET);
  assert.equal(budget.inflated, 0, 'the budget is used up exactly');
  const empty = decode('xref-stream', 0, budget);
  assert.equal(empty.ok, true, empty.ok ? '' : `empty output refused: ${empty.detail}`);
  assert.equal(empty.data.length, 0);
  assert.equal(budget.inflated, 0);
  assert.deepEqual(decode('xref-stream', 1, budget), { ok: false, detail: 'xref-stream-too-large' });
  // One byte over a budget that is not spent is refused the same way.
  assert.deepEqual(decode('xref-stream', BUDGET + 1, { inflated: BUDGET }), { ok: false, detail: 'xref-stream-too-large' });
});

test('[VB-06] an object stream: on the same spent budget an empty output passes and a one-byte one is refused with too-much-work (request #63)', () => {
  const budget = { inflated: BUDGET };
  const exact = decode('xref-stream', BUDGET, budget);
  assert.equal(exact.ok, true, exact.ok ? '' : `exact use refused: ${exact.detail}`);
  assert.equal(budget.inflated, 0, 'the budget is used up exactly');
  const empty = decode('object-stream', 0, budget);
  assert.equal(empty.ok, true, empty.ok ? '' : `empty output refused: ${empty.detail}`);
  assert.equal(empty.data.length, 0);
  assert.equal(budget.inflated, 0);
  assert.deepEqual(decode('object-stream', 1, budget), { ok: false, detail: 'too-much-work' });
  const whole = { inflated: BUDGET };
  const objectExact = decode('object-stream', BUDGET, whole);
  assert.equal(objectExact.ok, true, objectExact.ok ? '' : `exact use refused: ${objectExact.detail}`);
  assert.equal(whole.inflated, 0);
});

test('[VB-06] the inflate-budget seam is test-only: index.ts does not export it and no other module under src/ names it (request #63)', () => {
  assert.equal('decodeWithInflateBudget' in verifier, false, 'not on the public surface');
  assert.equal(typeof decodeWithInflateBudget, 'function');
  const srcRoot = fileURLToPath(new URL('../../../src/', import.meta.url));
  const own = join(srcRoot, 'verifier', 'structure.ts');
  const files = listFiles(srcRoot);
  assert.ok(files.includes(own), 'the scan reaches structure.ts');
  const naming = files.filter((file) => file !== own && stripComments(readFileSync(file, 'utf8')).includes('decodeWithInflateBudget'));
  assert.deepEqual(naming.map((file) => relative(srcRoot, file)), []);
});
