// SPDX-License-Identifier: Apache-2.0
//
// VB-06: the verifier's own revision-structure reader, on T014's own builds.
// Classic tables, cross-reference streams (uncompressed, and FlateDecode with
// every PNG filter), hybrids, the /Prev walk, revision ends, and every bound.
//
// Mutants killed here: xref streams unread; the PNG predictor not applied or its
// filter byte unchecked; type-1 or type-2 entries unchecked (in the stream and
// in a hybrid's hidden stream); /XRefStm ignored or its offset unchecked; /Prev
// allowed to loop; the revision bound or the inflate bound dropped; the tail
// window ignored; for row T014-XREFSTART, the four loose-start mutants listed
// above the E1 test; and, for request #56 Part B, the four listed above the
// forward /Prev test (the fifth, a skip bound below the input bound, is killed
// in bounds.test.mjs).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { readRevisionStructure, VERIFIER_LIMITS } from '../../../src/verifier/index.ts';
import { appendUpdate, buildBase } from './helpers/pdf-build.mjs';

function ok(bytes) {
  const result = readRevisionStructure(bytes);
  assert.equal(result.ok, true, result.ok ? '' : `structure failed: ${result.detail}`);
  return result.revisions;
}

function failsWith(bytes, detail) {
  const result = readRevisionStructure(bytes);
  assert.equal(result.ok, false, 'structure unexpectedly passed');
  assert.equal(result.detail, detail);
}

const info = (doc, text = 'info') => appendUpdate(doc, [{ num: doc.size, text: `<< /Producer (${text}) >>` }]);

test('[VB-06] a classic table, then a classic update: two revisions, the last ending at the file length', () => {
  const base = buildBase();
  const [only] = ok(base.bytes);
  assert.equal(only.kind, 'table');
  assert.equal(only.end, base.bytes.length);
  const updated = info(base);
  const revisions = ok(updated.bytes);
  assert.equal(revisions.length, 2);
  assert.equal(revisions[0].end, base.bytes.length, 'the first revision ends after its %%EOF line');
  assert.equal(revisions[1].end, updated.bytes.length);
});

test('[VB-06] cross-reference streams with an object stream, uncompressed and FlateDecode with every PNG filter', () => {
  ok(buildBase({ xref: 'stream' }).bytes);
  ok(buildBase({ xref: 'stream-flate' }).bytes);
  ok(buildBase({ xref: 'stream-flate', pngRowFilters: [0, 1, 2, 3, 4, 2, 1] }).bytes);
  const updated = info(buildBase({ xref: 'stream-flate' }));
  const revisions = ok(updated.bytes);
  assert.deepEqual(revisions.map((r) => r.kind), ['stream', 'stream']);
});

test('[VB-06] an unknown PNG filter byte fails the structure', () => {
  failsWith(buildBase({ xref: 'stream-flate', pngRowFilters: [2, 2, 5] }).bytes, 'png-filter-unknown');
});

test('[VB-06] a hybrid base: the hidden stream is read, merged and checked', () => {
  const base = buildBase({ xref: 'hybrid' });
  const [only] = ok(base.bytes);
  assert.equal(only.kind, 'table');
  assert.notEqual(only.hiddenStreamOffset, null);
  failsWith(buildBase({ xref: 'hybrid', hiddenType2StreamOverride: 4 }).bytes, 'xref-type2-not-object-stream');
  failsWith(buildBase({ xref: 'hybrid', xrefStmDelta: 3 }).bytes, 'xrefstm-not-xref-stream');
  const updated = info(base);
  assert.deepEqual(ok(updated.bytes).map((r) => r.kind), ['table', 'table']);
});

test('[VB-06] bad startxref, /Prev, entry offsets and type-2 entries each fail with their detail', () => {
  failsWith(buildBase({ startxrefDelta: 7 }).bytes, 'startxref-not-xref');
  failsWith(buildBase({ xref: 'stream', startxrefDelta: 3 }).bytes, 'startxref-not-xref');
  failsWith(appendUpdate(buildBase(), [{ num: 5, text: '<< >>' }], { prevDelta: 3 }).bytes, 'prev-not-xref');
  failsWith(buildBase({ entryDelta: { num: 3, delta: 2 } }).bytes, 'xref-entry-mismatch');
  failsWith(buildBase({ entryDelta: { num: 3, delta: 1 } }).bytes, 'xref-entry-mismatch');
  failsWith(buildBase({ xref: 'stream-flate', entryDelta: { num: 4, delta: 2 } }).bytes, 'xref-entry-mismatch');
  failsWith(buildBase({ xref: 'stream', type2StreamOverride: 4 }).bytes, 'xref-type2-not-object-stream');
});

test('[VB-06] more revisions than maxRevisions fail the structure', () => {
  let doc = buildBase();
  for (let i = 0; i < VERIFIER_LIMITS.maxRevisions; i += 1) doc = info(doc, `r${i}`);
  failsWith(doc.bytes, 'too-many-revisions');
});

test('[VB-06] an inflate output past maxXrefInflatedBytes fails without decoding it', () => {
  const huge = deflateSync(Buffer.alloc(VERIFIER_LIMITS.maxXrefInflatedBytes + 7));
  const head = buildBase().bytes.toString('latin1').split('xref\n')[0];
  const offset = Buffer.byteLength(head, 'latin1');
  const object = `9 0 obj\n<< /Type /XRef /Size 10 /W [1 4 2] /Length ${huge.length} /Filter /FlateDecode >>\nstream\n`;
  const bytes = Buffer.concat([
    Buffer.from(head + object, 'latin1'),
    huge,
    Buffer.from(`\nendstream\nendobj\nstartxref\n${offset}\n%%EOF\n`, 'latin1'),
  ]);
  failsWith(bytes, 'xref-stream-too-large');
});

test('[VB-06] the header and the final %%EOF window are required; bytes after %%EOF stay in the last revision', () => {
  const base = buildBase();
  const noHeader = Buffer.from(base.bytes);
  noHeader[0] ^= 0x01;
  failsWith(noHeader, 'no-header');
  failsWith(base.bytes.subarray(0, base.bytes.length - 16), 'no-final-startxref-eof');
  failsWith(buildBase({ trailingBytes: 'x'.repeat(VERIFIER_LIMITS.tailWindowBytes + 1) }).bytes, 'no-final-startxref-eof');
  const flipped = Buffer.from(base.bytes);
  flipped[flipped.length - 1] ^= 0x01;
  const [only] = ok(flipped);
  assert.equal(only.end, flipped.length, 'the last revision ends at the file length');
});

test('[VB-06] an earlier revision\'s own startxref value is not read, as T033 never reads it', () => {
  const base = buildBase();
  const text = base.bytes.toString('latin1');
  const wrong = text.replace(`startxref\n${base.startxref}\n`, `startxref\n${String(base.startxref + 1)}\n`);
  const forgedBase = { ...base, bytes: Buffer.from(wrong, 'latin1') };
  const revisions = ok(info(forgedBase).bytes);
  assert.equal(revisions.length, 2);
  assert.equal(revisions[0].end, forgedBase.bytes.length, 'the earlier revision still ends after its %%EOF line');
});

// ---------------------------------------------------------------------------
// Row T014-XREFSTART (request #49): every section start and object header T033
// accepts. These cases use T014's own builds and need no capability; the same
// shapes composed through T033's parser and T036's composer are in
// structure-composed.test.mjs.
//
// Mutants killed here: a comment after `xref` refused (the E1 and token tests);
// tables read as fixed 20-byte records (the token test); white-space before an
// object header refused (the E2, entry and /XRefStm tests); leading zeros
// refused (the token test).
// ---------------------------------------------------------------------------

test('[VB-06] E1: a table whose `xref` is directly followed by a comment', () => {
  const base = buildBase({ tableStyle: 'tokens' });
  assert.ok(base.bytes.toString('latin1').includes('xref% '), 'the E1 shape is present');
  ok(base.bytes);
  assert.equal(ok(info(base).bytes).length, 2);
});

test('[VB-06] table entries as tokens: comments and mixed white-space between them, 15-digit leading-zero offsets', () => {
  const base = buildBase({ tableStyle: 'tokens' });
  const text = base.bytes.toString('latin1');
  assert.match(text, /0{15} 65535 f\n/, 'leading zeros to 15 digits');
  assert.match(text, /\d{15} {2}00000\tn % entry 1\r\n/, 'tokens, not 20-byte records');
  const [only] = ok(base.bytes);
  assert.equal(only.kind, 'table');
  failsWith(buildBase({ tableStyle: 'tokens', entryDelta: { num: 2, delta: 3 } }).bytes, 'xref-entry-mismatch');
  const sixteen = Buffer.from(text.replace(/0{15} 65535 f/, `${'0'.repeat(16)} 65535 f`), 'latin1');
  failsWith(sixteen, 'xref-table-malformed');
  const bigGen = Buffer.from(text.replace('0'.repeat(15) + ' 65535 f', '0'.repeat(15) + ' 65536 f'), 'latin1');
  failsWith(bigGen, 'xref-table-malformed');
});

test('[VB-06] E2: startxref naming the end-of-line byte before a cross-reference stream header', () => {
  const e2 = buildBase({ xref: 'stream', startxrefDelta: -1 });
  const text = e2.bytes.toString('latin1');
  const named = Number(/startxref\n(\d+)\n%%EOF/.exec(text)[1]);
  assert.equal(e2.bytes[named], 0x0a, 'startxref names the end-of-line byte');
  assert.deepEqual(ok(e2.bytes).map((r) => r.kind), ['stream']);
  const updated = appendUpdate(e2, [{ num: e2.size, text: '<< /Producer (e2) >>' }], { prevDelta: -1 });
  assert.deepEqual(ok(updated.bytes).map((r) => r.kind), ['stream', 'stream'], '/Prev names the same end-of-line byte');
  ok(buildBase({ xref: 'stream-flate', startxrefDelta: -1 }).bytes);
});

test('[VB-06] a type-1 entry naming white-space or a comment before its header', () => {
  ok(buildBase({ entryDelta: { num: 3, delta: -1 } }).bytes);
  ok(buildBase({ xref: 'stream', entryDelta: { num: 4, delta: -1 } }).bytes);
  ok(buildBase({ commentBeforeObjects: true, pointAtComment: true }).bytes);
  ok(buildBase({ tableStyle: 'tokens', commentBeforeObjects: true, pointAtComment: true }).bytes);
  ok(buildBase({ xref: 'hybrid', xrefStmDelta: -1 }).bytes);
});

test('[VB-06] white-space before `xref` is accepted (the T014 line; a superset of T033)', () => {
  const base = buildBase({ startxrefDelta: -1 });
  const named = Number(/startxref\n(\d+)\n%%EOF/.exec(base.bytes.toString('latin1'))[1]);
  assert.equal(base.bytes[named], 0x0a);
  ok(base.bytes);
  ok(appendUpdate(buildBase(), [{ num: 5, text: '<< >>' }], { prevDelta: -1 }).bytes);
});

// ---------------------------------------------------------------------------
// Request #56 Part B: base-structure checks mirror T033 (B1 to B3), and the
// composed cases cannot skip (B5).
//
// Mutants killed here: the type-2 /N check dropped (the /N test); superseded
// entries checked (the effective-entry test); a forward /Prev refused (the
// forward test); a composed VB-06 case skipped instead of failing without the
// sandbox (the guard test, over structure-composed.test.mjs and its helper);
// and, for request #57 item 4, the object-stream header-number check dropped
// (the header-number test).
// ---------------------------------------------------------------------------

const PAGES = '<< /Type /Pages /Kids [3 0 R] /Count 1 >>';
const PAGE = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>';

/**
 * Three table sections where the final startxref names A, the middle one by
 * position, and A's /Prev points FORWARD to B, the last by position. B's /Prev
 * is `bPrev(base, a)`. A /Prev or startxref is written after its own section,
 * so changing it moves nothing before it; pass 1 learns where B lands, and pass
 * 2 keeps it there when A's /Prev keeps its digit count (asserted).
 */
function forwardChain(bPrev) {
  const base = buildBase();
  const objectsA = [{ num: 5, text: '<< /Producer (section a) >>' }];
  const objectsB = [{ num: 6, text: '<< /Producer (section b) >>' }];
  const draftA = appendUpdate(base, objectsA);
  const draftB = appendUpdate(draftA, objectsB, { prevDelta: bPrev(base, draftA) - draftA.startxref });
  const atB = draftB.startxref;
  assert.equal(String(atB).length, String(base.startxref).length, 'the forward /Prev keeps its digit count');
  const a = appendUpdate(base, objectsA, { prevDelta: atB - base.startxref });
  assert.equal(a.startxref, draftA.startxref, 'section A did not move');
  const b = appendUpdate(a, objectsB, { prevDelta: bPrev(base, a) - a.startxref, startxrefDelta: a.startxref - atB });
  assert.equal(b.startxref, atB, 'section B did not move');
  const text = b.bytes.toString('latin1');
  assert.equal(Number(/startxref\n(\d+)\n%%EOF\n$/.exec(text)[1]), a.startxref, 'the final startxref names A');
  return { base, a, b, atB };
}

test('[VB-06] /Prev may point forward, as T033 follows it; revisions are listed in file order (B3)', () => {
  const { base, a, b, atB } = forwardChain((doc) => doc.startxref);
  const revisions = ok(b.bytes);
  assert.deepEqual(revisions.map((r) => r.start), [base.startxref, a.startxref, atB], 'file order, not chain order');
  assert.deepEqual(revisions.map((r) => r.end), [base.bytes.length, a.bytes.length, b.bytes.length]);
  assert.equal(revisions[2].eofEnd, b.bytes.length, 'the last by position ends at the file length');
});

test('[VB-06] no section is visited twice: a self-loop, a /Prev naming white-space before its own section, a cycle (B3)', () => {
  const base = buildBase();
  const objects = [{ num: 5, text: '<< >>' }];
  // The update's xref offset does not depend on its /Prev, so a second build
  // with the same objects can name its own section.
  const own = appendUpdate(base, objects).startxref;
  failsWith(appendUpdate(base, objects, { prevDelta: own - base.startxref }).bytes, 'prev-revisited');
  const beforeOwn = appendUpdate(base, objects, { prevDelta: own - 1 - base.startxref });
  assert.equal(beforeOwn.bytes[own - 1], 0x0a, '/Prev names the end-of-line byte before its own `xref`');
  failsWith(beforeOwn.bytes, 'prev-revisited');
  // A, then forward to B, whose /Prev names A again.
  const { b } = forwardChain((_base, a) => a.startxref);
  failsWith(b.bytes, 'prev-revisited');
});

test('[VB-06] an effective type-2 index at or past its object stream /N fails (B1 (d), restored)', () => {
  ok(buildBase({ xref: 'stream', type2IndexOverride: { num: 3, index: 2 } }).bytes);
  failsWith(buildBase({ xref: 'stream', type2IndexOverride: { num: 3, index: 3 } }).bytes, 'xref-type2-not-object-stream');
  failsWith(buildBase({ xref: 'stream-flate', type2IndexOverride: { num: 1, index: 65535 } }).bytes, 'xref-type2-not-object-stream');
  // /N 2 below a header that still holds three pairs: only the /N check refuses object 3 (index 2).
  failsWith(buildBase({ xref: 'stream', objStmCount: 2 }).bytes, 'xref-type2-not-object-stream');
  // In the hybrid, the table's free entries for 1..3 yield to the hidden stream's (B1 (c)), so these are effective.
  failsWith(buildBase({ xref: 'hybrid', type2IndexOverride: { num: 2, index: 3 } }).bytes, 'xref-type2-not-object-stream');
});

test('[VB-06] only effective entries are checked: a superseded entry is never read (B2)', () => {
  const badOffset = buildBase({ entryDelta: { num: 2, delta: 3 } });
  failsWith(badOffset.bytes, 'xref-entry-mismatch');
  assert.equal(ok(appendUpdate(badOffset, [{ num: 2, text: PAGES }]).bytes).length, 2, 'object 2 rewritten');
  failsWith(appendUpdate(badOffset, [{ num: 5, text: '<< >>' }]).bytes, 'xref-entry-mismatch');
  const badIndex = buildBase({ xref: 'stream', type2IndexOverride: { num: 3, index: 3 } });
  ok(appendUpdate(badIndex, [{ num: 3, text: PAGE }]).bytes);
  const badStream = buildBase({ xref: 'stream', type2StreamOverride: 4 });
  failsWith(appendUpdate(badStream, [{ num: 1, text: '<< /Type /Catalog /Pages 2 0 R >>' }]).bytes, 'xref-type2-not-object-stream');
  ok(
    appendUpdate(badStream, [
      { num: 1, text: '<< /Type /Catalog /Pages 2 0 R >>' },
      { num: 2, text: PAGES },
      { num: 3, text: PAGE },
    ]).bytes,
  );
});

/** A source file's code lines: line comments are dropped, so the headers may describe what the code must not do. */
function codeOf(relative) {
  return readFileSync(new URL(relative, import.meta.url), 'latin1')
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//'))
    .join('\n');
}

test('[VB-06] the composed cases cannot skip: no skip, todo, catch or capability probe (B5)', () => {
  const composed = codeOf('./structure-composed.test.mjs');
  const helper = codeOf('./helpers/product-compose.mjs');
  const forbidden = [
    /\bskip\b/,
    /\btodo\b/,
    /\btry\b/,
    /\bcatch\b/,
    /CAPABILITY_ABSENT/,
    /\bprocess\b/,
    /\bimport\s*\(/,
    /\bbwrap\b|\bbubblewrap\b|\bunshare\b/,
    /\bexistsSync\b|\baccessSync\b|\bspawn|\bexec/,
  ];
  for (const [name, code] of [['structure-composed.test.mjs', composed], ['helpers/product-compose.mjs', helper]]) {
    for (const pattern of forbidden) assert.doesNotMatch(code, pattern, `${name} must not contain ${pattern}`);
  }
  assert.equal(composed.match(/^test\(/gm)?.length, 4, 'the four composed cases');
  assert.ok((composed.match(/await composeAndRead\(t, /g)?.length ?? 0) >= 4, 'every case composes and reads');
  assert.match(composed, /^import \{ composeWithProduct \} from '\.\/helpers\/product-compose\.mjs';$/m, 'a static import');
  assert.match(helper, /^import \{ composeSealRevision \} from /m, 'a static import');
  assert.match(helper, /return composeSealRevision\(/, 'the helper composes unconditionally');
});

test('[VB-06] an effective type-2 entry whose object-stream header names another object fails (request #57 item 4)', () => {
  ok(buildBase({ xref: 'stream', objStmFlate: true }).bytes);
  ok(buildBase({ xref: 'stream', objStmIndirectLength: true }).bytes);
  ok(buildBase({ xref: 'stream-flate', objStmFlate: true, objStmIndirectLength: true }).bytes);
  ok(buildBase({ xref: 'hybrid', objStmFlate: true }).bytes);
  failsWith(buildBase({ xref: 'stream', objStmHeaderOverride: { index: 1, num: 9 } }).bytes, 'xref-entry-mismatch');
  failsWith(buildBase({ xref: 'stream', objStmFlate: true, objStmHeaderOverride: { index: 2, num: 1 } }).bytes, 'xref-entry-mismatch');
  failsWith(buildBase({ xref: 'hybrid', objStmHeaderOverride: { index: 0, num: 2 } }).bytes, 'xref-entry-mismatch');
  // Only effective entries: once an update rewrites object 2, its compressed entry is never read.
  ok(appendUpdate(buildBase({ xref: 'stream', objStmHeaderOverride: { index: 1, num: 9 } }), [{ num: 2, text: PAGES }]).bytes);
});
