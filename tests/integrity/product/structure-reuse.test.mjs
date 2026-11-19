// SPDX-License-Identifier: Apache-2.0
//
// VB-06, row T014-TESTS (request #62 (3)): deterministic reuse tests. Request
// #60 (2) reuses a region already read: an indirect read by its start offset,
// a compressed object by its object stream, start and end. These cases count
// the reads one structure read asks for and the reads it makes afresh, through
// readRevisionStructureCounted.
//
// The count is test-only and unreachable from product callers:
// - readRevisionStructureCounted is exported by structure.ts alone; index.ts,
//   the verifier's public surface, does not export it, and no other module
//   under src/ names it (the last case checks both);
// - its counts object is created inside that function for one call and carried
//   in that call's own budget; readRevisionStructure passes none, and the
//   reader only adds to the counts, never reads them, so no verdict can depend
//   on them. There is no global counter.
//
// Mutants killed here: indirect-read reuse disabled; compressed-object reuse
// disabled; the compressed key ignoring its object stream; the compressed key
// ignoring its end.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as verifier from '../../../src/verifier/index.ts';
import { readRevisionStructureCounted } from '../../../src/verifier/structure.ts';
import { listFiles, stripComments } from './helpers/import-scan.mjs';
import { appendXrefStreamSection, buildBase } from './helpers/pdf-build.mjs';

/** The counts of one structure read, which must pass. */
function counted(bytes) {
  const { result, counts } = readRevisionStructureCounted(bytes);
  assert.equal(result.ok, true, result.ok ? '' : `structure failed: ${result.detail}`);
  return counts;
}

/** An object stream's text: `pairs` ([num, offset] ...) form the header, `body` follows /First. */
function objectStream(pairs, body) {
  const header = `${pairs.map(([num, offset]) => `${num} ${offset}`).join(' ')} `;
  const data = header + body;
  return `<< /Type /ObjStm /N ${pairs.length} /First ${header.length} /Length ${data.length} >>\nstream\n${data}\nendstream`;
}

test('[VB-06] reuse: an offset reached in several roles is read once (row T014-TESTS)', () => {
  // Seven requests reach four offsets: the stream section (object 6), then
  // object stream 5 and its /Length object 7 (through the first compressed
  // entry), then the entries of objects 4, 5, 6 and 7, three of them again.
  const counts = counted(buildBase({ xref: 'stream', objStmIndirectLength: true }).bytes);
  assert.equal(counts.indirectRequests, 7);
  assert.equal(counts.indirectReads, 4);
  assert.equal(counts.objectStreamDecodes, 1);
  assert.equal(counts.xrefStreamRequests, 1);
  assert.equal(counts.xrefStreamDecodes, 1);
});

test('[VB-06] reuse: a compressed object named twice is parsed once, and keys that differ only in their end are parsed apart (row T014-TESTS)', () => {
  // Header pairs 10 at 0, 11 at 4, 12 at 0, 13 at 0: object 10 ends at the next
  // offset (4), object 12 at the end of the data, so 10 and 12 share a start
  // but not an end; 12 and 13 share start and end, so 13 reuses 12's parse.
  const doc = appendXrefStreamSection(buildBase(), {
    objects: [{ num: 8, text: objectStream([[10, 0], [11, 4], [12, 0], [13, 0]], '12  true') }],
    widths: [1, 4, 2],
    rowsFor: (offsets, xrefAt) => [
      { first: 8, rows: [[1, offsets.get(8), 0]] },
      { first: 10, rows: [[2, 8, 0], [2, 8, 1], [2, 8, 2], [2, 8, 3]] },
      { first: 14, rows: [[1, xrefAt, 0]] },
    ],
    xnum: 14,
  });
  const counts = counted(doc.bytes);
  assert.equal(counts.compressedRequests, 4);
  assert.equal(counts.compressedParses, 3);
  assert.equal(counts.objectStreamDecodes, 1);
});

test('[VB-06] reuse: compressed keys that differ only in their object stream are parsed apart (row T014-TESTS)', () => {
  // Objects 20 and 21 sit at the same start and end in two object streams.
  const doc = appendXrefStreamSection(buildBase(), {
    objects: [
      { num: 9, text: objectStream([[20, 0]], 'true') },
      { num: 15, text: objectStream([[21, 0]], 'null') },
    ],
    widths: [1, 4, 2],
    rowsFor: (offsets, xrefAt) => [
      { first: 9, rows: [[1, offsets.get(9), 0]] },
      { first: 15, rows: [[1, offsets.get(15), 0]] },
      { first: 20, rows: [[2, 9, 0], [2, 15, 0]] },
      { first: 22, rows: [[1, xrefAt, 0]] },
    ],
    xnum: 22,
  });
  const counts = counted(doc.bytes);
  assert.equal(counts.compressedRequests, 2);
  assert.equal(counts.compressedParses, 2);
  assert.equal(counts.objectStreamDecodes, 2);
});

test('[VB-06] the read counts are test-only: index.ts does not export them and no other module under src/ names them (request #62 (3))', () => {
  assert.equal('readRevisionStructureCounted' in verifier, false, 'not on the public surface');
  assert.equal(typeof readRevisionStructureCounted, 'function');
  const srcRoot = fileURLToPath(new URL('../../../src/', import.meta.url));
  const own = join(srcRoot, 'verifier', 'structure.ts');
  const files = listFiles(srcRoot);
  assert.ok(files.includes(own), 'the scan reaches structure.ts');
  const naming = files.filter((file) => file !== own && stripComments(readFileSync(file, 'utf8')).includes('readRevisionStructureCounted'));
  assert.deepEqual(naming.map((file) => relative(srcRoot, file)), []);
});
