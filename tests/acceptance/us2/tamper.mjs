// SPDX-License-Identifier: Apache-2.0
//
// The probes of the extra-ID case [US2-TAMPER] (the T017 line; quickstart.md golden flow step 9).
// Each takes a COPY of a completed flow's final.pdf and returns new bytes; the retained original is
// never edited. Every probe is built at run time from a structural description (no third-party
// sample or proof-of-concept file).
// - byteChangeInRange: one byte inside a signed range is replaced by a byte the PDF syntax treats
//   alike (a space becomes a line feed), so the file still parses as before and only the signed
//   bytes differ. Expected: integrity `invalid` (plan.md SC002-19, OC-02), from the product
//   verifier and from the oracle alike.
//   - first range: the first space inside the BASE document's first content stream, which lies in
//     signed range 1 because final.pdf begins with the base's exact bytes (CP-01);
//   - second range: the first space at or after the offset just past /Contents (range 2 starts
//     there and runs to the end of the sealed file).
// - appendRevision: a classic incremental update after the final %%EOF that adds one Info
//   dictionary object (OC-03 "Info only"), with its own table, trailer (/Prev = the old startxref,
//   /Root kept) and startxref. The signed bytes are untouched. Expected: integrity `valid`,
//   revision_coverage `incomplete` and not accepted as the original (SC002-20), from both.
//   It needs a table-based source (the last section a classic table), which [US2-TAMPER] uses.

import assert from 'node:assert/strict';

const SPACE = 0x20;
const LINE_FEED = 0x0a;

const latin1 = (bytes) => Buffer.from(bytes).toString('latin1');

/** The two signed ranges of a product-sealed PDF: { first: [0, o1], second: [o2, end] }. */
export function signedRanges(pdf) {
  const text = latin1(pdf);
  const at = text.lastIndexOf('/ByteRange');
  assert.ok(at >= 0, 'the sealed PDF carries a /ByteRange');
  const match = /^\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(text.slice(at, at + 160));
  assert.ok(match, 'its /ByteRange is four integers');
  const [start, length1, offset2, length2] = match.slice(1).map(Number);
  assert.equal(start, 0, `the first signed range starts at 0, not ${start}`);
  assert.ok(length1 < offset2, `the ranges leave the /Contents gap (${length1} < ${offset2})`);
  assert.equal(offset2 + length2, pdf.length, `the second signed range ends at the end of the sealed file (${offset2 + length2} of ${pdf.length})`);
  return { first: [0, length1], second: [offset2, offset2 + length2] };
}

/** A copy of `pdf` with one space inside signed range `range` ('first' or 'second') turned into a line feed. */
export function byteChangeInRange(pdf, base, range) {
  const ranges = signedRanges(pdf);
  const original = Buffer.from(pdf);
  let offset = -1;
  if (range === 'first') {
    const baseText = latin1(base);
    const keyword = /stream\r?\n/.exec(baseText);
    assert.ok(keyword, 'the base document has a stream');
    const dataStart = keyword.index + keyword[0].length;
    const dataEnd = baseText.indexOf('endstream', dataStart);
    assert.ok(dataEnd > dataStart, 'the base stream has an end');
    const at = original.indexOf(SPACE, dataStart);
    offset = at >= 0 && at < dataEnd ? at : -1;
    assert.ok(offset >= 0 && offset < base.length && original.subarray(0, base.length).equals(Buffer.from(base)), 'final.pdf begins with the base bytes, and the base stream holds a space');
  } else {
    assert.equal(range, 'second', `a range is 'first' or 'second', not ${range}`);
    offset = original.indexOf(SPACE, ranges.second[0]);
  }
  const [from, to] = ranges[range];
  assert.ok(offset >= from && offset < to, `the changed byte ${offset} lies inside signed range ${range} [${from}, ${to})`);
  const copy = Buffer.from(original);
  copy[offset] = LINE_FEED;
  return { bytes: copy, offset, range: [from, to] };
}

/** A copy of `pdf` with one classic incremental update appended after its final %%EOF. */
export function appendRevision(pdf) {
  const head = Buffer.from(pdf);
  const text = latin1(head);
  const tail = /startxref\s+(\d+)\s+%%EOF\s*$/.exec(text.slice(-256));
  assert.ok(tail, 'the sealed PDF ends with startxref and %%EOF');
  const previous = Number(tail[1]);
  assert.equal(text.slice(previous, previous + 4), 'xref', `the last cross-reference section, at ${previous}, is a classic table (the tamper source must be a table-based flow)`);
  const trailerAt = text.lastIndexOf('trailer');
  const startxrefAt = text.lastIndexOf('startxref');
  assert.ok(trailerAt > previous && startxrefAt > trailerAt, 'the last section has its own trailer');
  const trailer = text.slice(trailerAt, startxrefAt);
  const size = Number(/\/Size\s+(\d+)/.exec(trailer)?.[1]);
  const root = /\/Root\s+(\d+\s+\d+\s+R)/.exec(trailer)?.[1];
  assert.ok(Number.isSafeInteger(size) && size > 0, `the last trailer names /Size (${size})`);
  assert.ok(root, 'the last trailer names /Root');
  const lead = head[head.length - 1] === LINE_FEED ? '' : '\n';
  const objectOffset = head.length + lead.length;
  const object = `${lead}${size} 0 obj\n<< /Producer (openSig US2 tamper probe, synthetic) >>\nendobj\n`;
  const sectionOffset = head.length + Buffer.byteLength(object, 'latin1');
  const entry = `${String(objectOffset).padStart(10, '0')} 00000 n \n`;
  assert.equal(entry.length, 20, 'a classic cross-reference entry is 20 bytes');
  const section = `xref\n${size} 1\n${entry}trailer\n<< /Size ${size + 1} /Root ${root} /Info ${size} 0 R /Prev ${previous} >>\nstartxref\n${sectionOffset}\n%%EOF\n`;
  return Buffer.concat([head, Buffer.from(object + section, 'latin1')]);
}
