// SPDX-License-Identifier: Apache-2.0
//
// The appended cross-reference section (T036; A-010, request #39, Part E). It is
// of the same kind as the base's last section: a classic table after a table
// (including a hybrid base, whose last section is a table carrying /XRefStm), and
// a cross-reference stream after a stream. It lists only the objects this
// revision writes, every one in use (type 1), in ascending order, grouped into
// runs of consecutive numbers; object 0 and the base's entries stay in the base's
// sections, reached through /Prev.
//
// - Table: `xref`, then for each run `start count` and 20-byte entries
//   `oooooooooo ggggg n` CR LF, then `trailer`, the trailer dictionary,
//   `startxref`, the section's offset and `%%EOF`.
// - Stream: one uncompressed /Type /XRef stream object, numbered last, with
//   /W [1 4 2] (type, a four-byte offset, a two-byte generation) and /Index
//   naming the runs; it lists itself. Its dictionary carries the trailer entries.
//   No filter is applied, so the bytes do not depend on a compressor.
//
// Trailer entries, in this fixed order: /Size (the base's /Size plus the objects
// appended), /Root (unchanged), /Info (copied when the base has one), /ID and
// /Prev (the base's startxref).

import { pdfHexString, pdfRef, type Ref } from './syntax.ts';

export interface XrefEntry {
  readonly num: number;
  readonly gen: number;
  readonly offset: number;
}

export interface TrailerFields {
  readonly size: number;
  readonly root: Ref;
  readonly info: Ref | null;
  readonly id: readonly [string, string];
  readonly prev: number;
}

/** The largest offset a four-byte stream field can hold. */
const MAX_STREAM_OFFSET = 0xffff_ffff;

function sortedEntries(entries: readonly XrefEntry[]): XrefEntry[] {
  const sorted = [...entries].sort((a, b) => a.num - b.num);
  for (let index = 1; index < sorted.length; index += 1) {
    if (sorted[index]?.num === sorted[index - 1]?.num) throw new RangeError('an object appears twice in one cross-reference section');
  }
  for (const entry of sorted) {
    if (!Number.isSafeInteger(entry.num) || entry.num < 1 || !Number.isSafeInteger(entry.gen) || entry.gen < 0 || entry.gen > 65535) {
      throw new RangeError('a cross-reference entry has an invalid number or generation');
    }
    if (!Number.isSafeInteger(entry.offset) || entry.offset < 0 || entry.offset > MAX_STREAM_OFFSET) throw new RangeError('a cross-reference offset is out of range');
  }
  return sorted;
}

/** Runs of consecutive object numbers: each run's first number and its entries. */
function runsOf(sorted: readonly XrefEntry[]): Array<{ start: number; entries: XrefEntry[] }> {
  const runs: Array<{ start: number; entries: XrefEntry[] }> = [];
  for (const entry of sorted) {
    const last = runs[runs.length - 1];
    if (last !== undefined && last.start + last.entries.length === entry.num) last.entries.push(entry);
    else runs.push({ start: entry.num, entries: [entry] });
  }
  return runs;
}

/** The trailer entries after /Size: /Root, /Info when present, /ID and /Prev. */
function trailerTail(fields: TrailerFields): string {
  const parts = [`/Root ${pdfRef(fields.root)}`];
  if (fields.info !== null) parts.push(`/Info ${pdfRef(fields.info)}`);
  parts.push(`/ID [${pdfHexString(fields.id[0])} ${pdfHexString(fields.id[1])}]`);
  parts.push(`/Prev ${fields.prev}`);
  return parts.join(' ');
}

/** The trailer entries, without the enclosing << >>. */
export function trailerEntries(fields: TrailerFields): string {
  return `/Size ${fields.size} ${trailerTail(fields)}`;
}

/** A classic cross-reference section starting at absolute offset `at`, through `%%EOF`. */
export function classicSection(entries: readonly XrefEntry[], fields: TrailerFields, at: number): Uint8Array {
  const lines = ['xref\n'];
  for (const run of runsOf(sortedEntries(entries))) {
    lines.push(`${run.start} ${run.entries.length}\n`);
    for (const entry of run.entries) lines.push(`${String(entry.offset).padStart(10, '0')} ${String(entry.gen).padStart(5, '0')} n\r\n`);
  }
  lines.push(`trailer\n<< ${trailerEntries(fields)} >>\nstartxref\n${at}\n%%EOF\n`);
  return Buffer.from(lines.join(''), 'latin1');
}

/**
 * A cross-reference stream object numbered `self`, starting at absolute offset `at`
 * and listing itself, followed by `startxref` and `%%EOF`.
 */
export function streamSection(entries: readonly XrefEntry[], self: number, fields: TrailerFields, at: number): Uint8Array {
  const sorted = sortedEntries([...entries, { num: self, gen: 0, offset: at }]);
  const data = Buffer.alloc(sorted.length * 7);
  sorted.forEach((entry, index) => {
    const base = index * 7;
    data[base] = 1;
    data.writeUInt32BE(entry.offset, base + 1);
    data.writeUInt16BE(entry.gen, base + 5);
  });
  const index = runsOf(sorted)
    .map((run) => `${run.start} ${run.entries.length}`)
    .join(' ');
  const dict = `<< /Type /XRef /Size ${fields.size} /W [1 4 2] /Index [${index}] ${trailerTail(fields)} /Length ${data.length} >>`;
  return Buffer.concat([
    Buffer.from(`${self} 0 obj\n${dict}\nstream\n`, 'latin1'),
    data,
    Buffer.from(`\nendstream\nendobj\nstartxref\n${at}\n%%EOF\n`, 'latin1'),
  ]);
}
