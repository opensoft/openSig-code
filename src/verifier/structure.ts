// SPDX-License-Identifier: Apache-2.0
//
// The verifier's own revision-structure reader (T014). It walks the
// cross-reference chain of an incrementally updated PDF and reports where each
// revision ends, so the ByteRange check can find the signed revision and the
// coverage verdict can tell whether that revision is the last.
//
// It accepts at least every cross-reference section start and object header
// that T033's parser accepts (request #49, row T014-XREFSTART; VB-06), so a base
// T033 accepted and T036 composed never fails here on its layout alone:
// - a section start (the final startxref, each /Prev, each /XRefStm) may name
//   white-space or comments before `xref` or before the stream object's header.
//   T033 skips them only before an object header, not before `xref`; the T014
//   line accepts both, a harmless superset;
// - a table is read as tokens: white-space and comments may come anywhere
//   between and around them, including directly after `xref`; numbers have 1 to
//   15 digits with leading zeros allowed; a generation is at most 65535; each
//   entry ends with exactly the keyword `n` or `f`;
// - an object header read at an offset (each section object and each type-1
//   entry check) may be preceded by white-space and comments, and its tokens
//   may be separated by white-space and comments;
// - the final `startxref` is the last one in the final tailWindowBytes, then
//   white-space or comments, 1 to 15 digits, white-space, `%%EOF`. Bytes after
//   that %%EOF belong to the last revision, which ends at the end of the file
//   (T033 allows only white-space there; tolerating more keeps OC-02-f, whose
//   flipped final byte the oracle reads, and is again a superset);
// - stream data is /Length bytes, then white-space and comments, then
//   `endstream`.
//
// What it reads (request #39, Parts E and F): classic tables, cross-reference
// streams (uncompressed, or FlateDecode with the PNG predictors; filter bytes
// 0..4, any other fails) and hybrids (a table trailer's /XRefStm names a hidden
// stream whose entries belong to the same section and are checked too).
//
// What it checks (request #56 B1: base-structure checks mirror T033; the
// security checks in byte-range.ts and verify.ts stay strict and read only the
// final chain's signature, its ByteRange and /Contents, and the bytes outside
// the signed ranges, so none depends on a relaxed check here):
// - the header at offset 0;
// - the final startxref, every /Prev and every /XRefStm reach a section of the
//   right kind. /Prev is followed as T033 follows it (B3): a non-negative offset
//   within the file, in either direction, no section revisited, and at most
//   maxRevisions sections (at least T033's limit);
// - only EFFECTIVE entries are checked (B2): the newest entry for each object
//   number, newest section first, as T033's addEntry keeps them; inside a
//   hybrid section the precedence is an in-use table entry, then the /XRefStm
//   entry, then a free table entry (B1 (c)). An effective in-use entry reaches
//   a header with its own number and generation (its offset bounded only by
//   the file, B1 (b)); an effective type-2 entry names an object stream
//   (/Type /ObjStm) whose effective entry is in use, its index is below that
//   stream's /N (B1 (d) restored), and the stream's header pair at that index
//   names the entry's own object number, as T033's readCompressed checks
//   (request #57 item 4). Object streams are decoded (no filter, or
//   FlateDecode with or without a PNG predictor) under the same inflate budget
//   as cross-reference streams. Superseded entries are never read.
// It does not read an earlier revision's own startxref value (B1 (a)). Revision
// ends are found in file order: each revision ends after the first %%EOF past
// its section and at most one end-of-line, before the next section by
// position; one without a %%EOF has an unmarked end, at which no signature can
// end; the last by position ends at the file length. Coverage then depends only
// on whether the signed range reaches the file length, never on the chain's
// direction.
//
// Every loop and size is bounded (VERIFIER_LIMITS). A failure names one detail.

import { inflateSync } from 'node:zlib';
import { VERIFIER_LIMITS } from './limits.ts';
import {
  atKeyword,
  byteAt,
  dictEntry,
  eolLength,
  indexOfAscii,
  intValue,
  isDigit,
  isRegular,
  isWhitespace,
  lastIndexOfAscii,
  matchAscii,
  nameValue,
  parseValue,
  readIndirectObject,
  readObjectHeader,
  readUnsignedInt,
  skipWhitespaceAndComments,
  SyntaxFault,
  type IndirectObject,
  type PdfValue,
} from './pdf-syntax.ts';

export const STRUCTURE_DETAILS = [
  'input-too-large',
  'no-header',
  'no-final-startxref-eof',
  'startxref-not-xref',
  'prev-not-xref',
  'prev-revisited',
  'too-many-revisions',
  'too-many-xref-entries',
  'too-much-work',
  'xref-table-malformed',
  'trailer-malformed',
  'xref-stream-malformed',
  'xref-stream-too-large',
  'xref-stream-filter-unsupported',
  'xref-stream-predictor-unsupported',
  'png-filter-unknown',
  'xrefstm-not-xref-stream',
  'xref-entry-mismatch',
  'xref-type2-not-object-stream',
  'revision-order',
] as const;

export type StructureDetail = (typeof STRUCTURE_DETAILS)[number];

/** One revision, listed in FILE order (by its section's position), not chain order. */
export interface Revision {
  /** The section offset as named (by startxref or /Prev). */
  readonly xrefOffset: number;
  /** The first byte of the section itself (`xref`, or the stream object's number). */
  readonly start: number;
  readonly kind: 'table' | 'stream';
  /** Offset of the hidden cross-reference stream of a hybrid section, else null. */
  readonly hiddenStreamOffset: number | null;
  /** Offset just past this revision: after %%EOF and one end-of-line; the file length for the last. */
  readonly end: number;
  /** Offset just after this revision's %%EOF (the file length for the last), or null when unmarked. */
  readonly eofEnd: number | null;
}

export type StructureResult =
  | { readonly ok: true; readonly revisions: readonly Revision[] }
  | { readonly ok: false; readonly detail: StructureDetail };

class StructureFault extends Error {
  readonly detail: StructureDetail;

  constructor(detail: StructureDetail) {
    super(detail);
    this.detail = detail;
  }
}

function fault(detail: StructureDetail): never {
  throw new StructureFault(detail);
}

interface Entry {
  readonly num: number;
  /** 0 free, 1 in use at an offset, 2 compressed in an object stream. */
  readonly type: 0 | 1 | 2;
  /** Type 1: byte offset. Type 2: object stream number. */
  readonly field2: number;
  /** Type 1: generation. Type 2: index in the object stream. */
  readonly field3: number;
}

interface Section {
  readonly offset: number;
  readonly start: number;
  readonly kind: 'table' | 'stream';
  readonly prev: number | null;
  readonly hiddenStreamOffset: number | null;
  /** The table's or the stream's own entries, in their order. */
  readonly entries: readonly Entry[];
  /** A hybrid table's hidden-stream entries (empty otherwise). */
  readonly hidden: readonly Entry[];
}

interface Budget {
  entries: number;
  /** Inflated bytes still allowed across all decoded cross-reference and object streams. */
  inflated: number;
  /** White-space and comment bytes skipped so far around object headers. */
  skipped: number;
}

const HEADER_LENGTH = 8; // `%PDF-x.y`
const MAX_GENERATION = 65535;

/** Read the revision structure of `bytes`. Never throws on malformed input. */
export function readRevisionStructure(bytes: Uint8Array): StructureResult {
  try {
    return { ok: true, revisions: walk(bytes) };
  } catch (error) {
    if (error instanceof StructureFault) return { ok: false, detail: error.detail };
    throw error;
  }
}

function walk(bytes: Uint8Array): Revision[] {
  if (bytes.length > VERIFIER_LIMITS.maxInputBytes) fault('input-too-large');
  checkHeader(bytes);
  const budget: Budget = { entries: 0, inflated: VERIFIER_LIMITS.maxXrefInflatedBytes, skipped: 0 };
  const newestFirst: Section[] = [];
  // B3: /Prev in either direction, as T033 follows it; no section is visited
  // twice, whether named by the same offset or reached at the same position.
  const seenOffsets = new Set<number>();
  const seenStarts = new Set<number>();
  let offset = finalStartxref(bytes);
  let origin: 'startxref' | 'prev' = 'startxref';
  for (;;) {
    if (newestFirst.length >= VERIFIER_LIMITS.maxRevisions) fault('too-many-revisions');
    if (seenOffsets.has(offset)) fault('prev-revisited');
    seenOffsets.add(offset);
    const section = readSection(bytes, offset, origin, budget);
    if (seenStarts.has(section.start)) fault('prev-revisited');
    seenStarts.add(section.start);
    newestFirst.push(section);
    if (section.prev === null) break;
    offset = section.prev;
    origin = 'prev';
  }
  const revisions = locateRevisions(bytes, newestFirst);
  checkEffectiveEntries(bytes, newestFirst, budget);
  return revisions;
}

function spend(budget: Budget, skipped: number): void {
  budget.skipped += skipped;
  if (budget.skipped > VERIFIER_LIMITS.maxHeaderSkipBytes) fault('too-much-work');
}

function checkHeader(bytes: Uint8Array): void {
  if (
    !matchAscii(bytes, 0, '%PDF-') ||
    !isDigit(byteAt(bytes, 5)) ||
    byteAt(bytes, 6) !== 0x2e ||
    !isDigit(byteAt(bytes, 7))
  ) {
    fault('no-header');
  }
}

/**
 * `startxref`, white-space or comments, 1 to 15 digits, white-space, `%%EOF`.
 * Comments cannot sit between the number and %%EOF, which is itself a comment.
 */
function parseStartxrefAt(bytes: Uint8Array, kw: number): { value: number; eofStart: number } | null {
  const end = bytes.length;
  if (!atKeyword(bytes, kw, 'startxref')) return null;
  const numberAt = skipWhitespaceAndComments(bytes, kw + 9, end);
  const n = readUnsignedInt(bytes, numberAt, end);
  if (n === null) return null;
  let eofStart = n.next;
  while (eofStart < end && isWhitespace(byteAt(bytes, eofStart))) eofStart += 1;
  if (!matchAscii(bytes, eofStart, '%%EOF')) return null;
  return { value: n.value, eofStart };
}

/** The value of the LAST `startxref` in the final tailWindowBytes, as T033 reads it. */
function finalStartxref(bytes: Uint8Array): number {
  const length = bytes.length;
  const kw = lastIndexOfAscii(bytes, 'startxref', length - 9, length - VERIFIER_LIMITS.tailWindowBytes);
  if (kw < 0) fault('no-final-startxref-eof');
  const line = parseStartxrefAt(bytes, kw);
  if (line === null) fault('no-final-startxref-eof');
  return line.value;
}

function readSection(bytes: Uint8Array, offset: number, origin: 'startxref' | 'prev', budget: Budget): Section {
  const notXref: StructureDetail = origin === 'startxref' ? 'startxref-not-xref' : 'prev-not-xref';
  if (offset < 0 || offset >= bytes.length) fault(notXref);
  // The T014 line accepts white-space and comments before `xref` (a superset of T033).
  const start = skipWhitespaceAndComments(bytes, offset, bytes.length);
  if (atKeyword(bytes, start, 'xref')) {
    spend(budget, start - offset);
    return readTableSection(bytes, offset, start, budget);
  }
  const stream = readXrefStream(bytes, offset, budget);
  if (stream === null) fault(notXref);
  return {
    offset,
    start: stream.start,
    kind: 'stream',
    prev: stream.prev,
    hiddenStreamOffset: null,
    entries: stream.entries,
    hidden: [],
  };
}

// ---------------------------------------------------------------------------
// Classic tables, read as tokens
// ---------------------------------------------------------------------------

function readTableSection(bytes: Uint8Array, offset: number, start: number, budget: Budget): Section {
  const end = bytes.length;
  const entries: Entry[] = [];
  let p = start + 4;
  for (;;) {
    p = skipWhitespaceAndComments(bytes, p, end);
    if (p >= end) fault('xref-table-malformed');
    if (atKeyword(bytes, p, 'trailer')) break;
    const first = readUnsignedInt(bytes, p, end);
    if (first === null) fault('xref-table-malformed');
    const count = readUnsignedInt(bytes, skipWhitespaceAndComments(bytes, first.next, end), end);
    if (count === null) fault('xref-table-malformed');
    budget.entries += count.value;
    if (budget.entries > VERIFIER_LIMITS.maxXrefEntries) fault('too-many-xref-entries');
    p = count.next;
    for (let i = 0; i < count.value; i += 1) {
      const read = readTableEntry(bytes, p, first.value + i);
      entries.push(read.entry);
      p = read.next;
    }
  }
  let trailer: PdfValue;
  try {
    trailer = parseValue(bytes, p + 7, end).value;
  } catch (error) {
    if (error instanceof SyntaxFault) fault('trailer-malformed');
    throw error;
  }
  if (trailer.kind !== 'dict') fault('trailer-malformed');
  const prev = optionalOffset(trailer, 'Prev', 'trailer-malformed');
  const hiddenStreamOffset = optionalOffset(trailer, 'XRefStm', 'trailer-malformed');
  let hidden: readonly Entry[] = [];
  if (hiddenStreamOffset !== null) {
    // B1 (c): bounded only by the file; its entries are kept apart so that the
    // hybrid precedence in effectiveEntries can apply.
    if (hiddenStreamOffset >= end) fault('xrefstm-not-xref-stream');
    const stream = readXrefStream(bytes, hiddenStreamOffset, budget);
    if (stream === null) fault('xrefstm-not-xref-stream');
    hidden = stream.entries;
  }
  return { offset, start, kind: 'table', prev, hiddenStreamOffset, entries, hidden };
}

/** One entry as three tokens: offset, generation (at most 65535), and exactly `n` or `f`. */
function readTableEntry(bytes: Uint8Array, from: number, num: number): { entry: Entry; next: number } {
  const end = bytes.length;
  const offset = readUnsignedInt(bytes, skipWhitespaceAndComments(bytes, from, end), end);
  if (offset === null) fault('xref-table-malformed');
  const gen = readUnsignedInt(bytes, skipWhitespaceAndComments(bytes, offset.next, end), end);
  if (gen === null || gen.value > MAX_GENERATION) fault('xref-table-malformed');
  const at = skipWhitespaceAndComments(bytes, gen.next, end);
  const kind = byteAt(bytes, at);
  if ((kind !== 0x6e && kind !== 0x66) || isRegular(byteAt(bytes, at + 1))) fault('xref-table-malformed');
  const entry: Entry = { num, type: kind === 0x6e ? 1 : 0, field2: offset.value, field3: gen.value };
  return { entry, next: at + 1 };
}

function optionalOffset(dict: PdfValue, key: string, detail: StructureDetail): number | null {
  const value = dictEntry(dict, key);
  if (value === undefined) return null;
  const n = intValue(value);
  if (n === null || n < 0) fault(detail);
  return n;
}

// ---------------------------------------------------------------------------
// Cross-reference streams
// ---------------------------------------------------------------------------

/** The cross-reference stream reached at `offset`, or null when no /Type /XRef object is there. */
function readXrefStream(
  bytes: Uint8Array,
  offset: number,
  budget: Budget,
): { start: number; prev: number | null; entries: Entry[] } | null {
  let object: IndirectObject | null;
  try {
    object = readIndirectObject(bytes, offset);
  } catch (error) {
    if (error instanceof SyntaxFault) return null;
    throw error;
  }
  if (object === null) return null;
  spend(budget, object.header.skipped);
  if (nameValue(dictEntry(object.value, 'Type')) !== 'XRef') return null;
  if (object.streamStart === null) fault('xref-stream-malformed');
  // /Length is always direct in a cross-reference stream (ISO 32000, 7.5.8.2).
  const length = intValue(dictEntry(object.value, 'Length'));
  if (length === null) fault('xref-stream-malformed');
  const raw = streamBody(bytes, object.streamStart, length, budget, XREF_STREAM_FAULTS);
  const decoded = decodeStream(object.value, raw, budget, XREF_STREAM_FAULTS, () => rowWidth(object.value));
  const entries = xrefStreamEntries(object.value, decoded, budget);
  return { start: object.header.start, prev: optionalOffset(object.value, 'Prev', 'xref-stream-malformed'), entries };
}

/** The details one stream decode reports: a cross-reference stream's own, or those of an object stream a type-2 entry names. */
interface DecodeFaults {
  readonly malformed: StructureDetail;
  readonly filter: StructureDetail;
  readonly predictor: StructureDetail;
  readonly tooLarge: StructureDetail;
  readonly pngFilter: StructureDetail;
}

const XREF_STREAM_FAULTS: DecodeFaults = {
  malformed: 'xref-stream-malformed',
  filter: 'xref-stream-filter-unsupported',
  predictor: 'xref-stream-predictor-unsupported',
  tooLarge: 'xref-stream-too-large',
  pngFilter: 'png-filter-unknown',
};

const OBJECT_STREAM_FAULTS: DecodeFaults = {
  malformed: 'xref-type2-not-object-stream',
  filter: 'xref-type2-not-object-stream',
  predictor: 'xref-type2-not-object-stream',
  tooLarge: 'too-much-work',
  pngFilter: 'xref-type2-not-object-stream',
};

/** `length` bytes from `start`, then white-space and comments, then `endstream`. */
function streamBody(bytes: Uint8Array, start: number, length: number, budget: Budget, faults: DecodeFaults): Uint8Array {
  if (length < 0) fault(faults.malformed);
  if (length > VERIFIER_LIMITS.maxXrefStreamBytes) fault(faults.tooLarge);
  const end = start + length;
  if (end > bytes.length) fault(faults.malformed);
  const kw = skipWhitespaceAndComments(bytes, end, bytes.length);
  spend(budget, kw - end);
  if (!atKeyword(bytes, kw, 'endstream')) fault(faults.malformed);
  return bytes.subarray(start, end);
}

/**
 * No filter, or FlateDecode with no predictor or a PNG predictor (one byte per
 * pixel). Inflated bytes count against one total budget over every decoded
 * stream, as T033's maxInflatedBytes does. `columns`, when given, yields the
 * only /Columns accepted (a cross-reference stream's row width), read only
 * when a predictor is present.
 */
function decodeStream(
  dict: PdfValue,
  raw: Uint8Array,
  budget: Budget,
  faults: DecodeFaults,
  columns: (() => number) | null,
): Uint8Array {
  const filter = dictEntry(dict, 'Filter');
  let filterName: string | null = null;
  if (filter !== undefined) {
    if (filter.kind === 'name') filterName = filter.value;
    else if (filter.kind === 'array' && filter.items.length === 1) filterName = nameValue(filter.items[0]);
    if (filterName !== 'FlateDecode') fault(faults.filter);
  }
  let parms = dictEntry(dict, 'DecodeParms');
  if (parms !== undefined && parms.kind === 'array') {
    if (parms.items.length !== 1) fault(faults.malformed);
    parms = parms.items[0];
  }
  if (parms !== undefined && parms.kind !== 'dict' && parms.kind !== 'null') fault(faults.malformed);
  if (filterName === null) {
    if (parms !== undefined && parms.kind === 'dict') fault(faults.malformed);
    return raw;
  }
  let decoded: Uint8Array;
  try {
    if (budget.inflated < 1) fault(faults.tooLarge);
    decoded = inflateSync(raw, { maxOutputLength: budget.inflated });
  } catch (error) {
    if (error instanceof StructureFault) throw error;
    if (error instanceof RangeError) fault(faults.tooLarge);
    return fault(faults.malformed);
  }
  budget.inflated -= decoded.length;
  if (parms === undefined || parms.kind !== 'dict') return decoded;
  const predictor = intValue(dictEntry(parms, 'Predictor')) ?? 1;
  if (predictor === 1) return decoded;
  if (predictor < 10 || predictor > 15) fault(faults.predictor);
  const stated = intValue(dictEntry(parms, 'Columns')) ?? 1;
  const colors = intValue(dictEntry(parms, 'Colors')) ?? 1;
  const bits = intValue(dictEntry(parms, 'BitsPerComponent')) ?? 8;
  if (colors !== 1 || bits !== 8) fault(faults.predictor);
  if (columns !== null && stated !== columns()) fault(faults.malformed);
  return undoPngPredictor(decoded, stated, faults);
}

/** PNG row filters 0 None, 1 Sub, 2 Up, 3 Average, 4 Paeth; one byte per pixel. */
function undoPngPredictor(data: Uint8Array, columns: number, faults: DecodeFaults): Uint8Array {
  const rowLength = columns + 1;
  if (columns < 1 || data.length % rowLength !== 0) fault(faults.malformed);
  const rows = data.length / rowLength;
  const out = new Uint8Array(rows * columns);
  for (let r = 0; r < rows; r += 1) {
    const filter = byteAt(data, r * rowLength);
    for (let i = 0; i < columns; i += 1) {
      const x = byteAt(data, r * rowLength + 1 + i);
      const left = i > 0 ? byteAt(out, r * columns + i - 1) : 0;
      const up = r > 0 ? byteAt(out, (r - 1) * columns + i) : 0;
      const upLeft = i > 0 && r > 0 ? byteAt(out, (r - 1) * columns + i - 1) : 0;
      let v: number;
      if (filter === 0) v = x;
      else if (filter === 1) v = x + left;
      else if (filter === 2) v = x + up;
      else if (filter === 3) v = x + ((left + up) >> 1);
      else if (filter === 4) v = x + paeth(left, up, upLeft);
      else return fault(faults.pngFilter);
      out[r * columns + i] = v & 0xff;
    }
  }
  return out;
}

function paeth(a: number, b: number, c: number): number {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

function widths(dict: PdfValue): [number, number, number] {
  const w = dictEntry(dict, 'W');
  if (w === undefined || w.kind !== 'array' || w.items.length !== 3) fault('xref-stream-malformed');
  const [a, b, c] = w.items.map((item) => intValue(item));
  if (a === null || b === null || c === null || a === undefined || b === undefined || c === undefined) {
    return fault('xref-stream-malformed');
  }
  for (const width of [a, b, c]) {
    if (width < 0 || width > VERIFIER_LIMITS.maxXrefFieldWidth) fault('xref-stream-malformed');
  }
  if (b === 0) fault('xref-stream-malformed');
  return [a, b, c];
}

function rowWidth(dict: PdfValue): number {
  const [a, b, c] = widths(dict);
  return a + b + c;
}

function xrefStreamEntries(dict: PdfValue, data: Uint8Array, budget: Budget): Entry[] {
  const [w1, w2, w3] = widths(dict);
  const row = w1 + w2 + w3;
  const size = intValue(dictEntry(dict, 'Size'));
  if (size === null || size < 0) fault('xref-stream-malformed');
  const index = dictEntry(dict, 'Index');
  const pairs: Array<[number, number]> = [];
  if (index === undefined) {
    pairs.push([0, size]);
  } else {
    if (index.kind !== 'array' || index.items.length % 2 !== 0) fault('xref-stream-malformed');
    for (let i = 0; i < index.items.length; i += 2) {
      const first = intValue(index.items[i]);
      const count = intValue(index.items[i + 1]);
      if (first === null || count === null || first < 0 || count < 0) fault('xref-stream-malformed');
      pairs.push([first, count]);
    }
  }
  let total = 0;
  for (const [, count] of pairs) total += count;
  budget.entries += total;
  if (budget.entries > VERIFIER_LIMITS.maxXrefEntries) fault('too-many-xref-entries');
  if (data.length !== total * row) fault('xref-stream-malformed');
  const entries: Entry[] = [];
  let p = 0;
  for (const [first, count] of pairs) {
    for (let i = 0; i < count; i += 1) {
      const type = w1 === 0 ? 1 : readField(data, p, w1);
      const field2 = readField(data, p + w1, w2);
      const field3 = w3 === 0 ? 0 : readField(data, p + w1 + w2, w3);
      p += row;
      // Types above 2 are references to the null object (ISO 32000, 7.5.8.3).
      if (type === 0 || type === 1 || type === 2) entries.push({ num: first + i, type, field2, field3 });
    }
  }
  return entries;
}

/**
 * A big-endian field. Widths up to 8 bytes are read; a value past 2^53 loses
 * precision but is far beyond any offset or object number the bounds allow, so
 * the entry checks still fail it.
 */
function readField(data: Uint8Array, at: number, width: number): number {
  let value = 0;
  for (let i = 0; i < width; i += 1) value = value * 256 + byteAt(data, at + i);
  return value;
}

// ---------------------------------------------------------------------------
// Revision ends and entry checks
// ---------------------------------------------------------------------------

/**
 * Revision ends, in FILE order. B3 lets /Prev point either way, so a
 * revision's region runs from its section to the next section by position,
 * not to the next in the chain. Duplicate starts were refused by walk.
 */
function locateRevisions(bytes: Uint8Array, newestFirst: readonly Section[]): Revision[] {
  const sections = [...newestFirst].sort((a, b) => a.start - b.start);
  const revisions: Revision[] = [];
  for (let k = 0; k < sections.length; k += 1) {
    const section = sections[k];
    if (section === undefined) return fault('revision-order');
    const next = sections[k + 1];
    const regionEnd = next === undefined ? bytes.length : next.start;
    if (section.start < HEADER_LENGTH || section.start >= regionEnd) fault('revision-order');
    let end = bytes.length;
    let eofEnd: number | null = bytes.length;
    if (next !== undefined) {
      const eof = indexOfAscii(bytes, '%%EOF', section.start, regionEnd);
      if (eof < 0) {
        end = regionEnd;
        eofEnd = null;
      } else {
        eofEnd = eof + 5;
        end = Math.min(regionEnd, eofEnd + eolLength(bytes, eofEnd));
      }
    }
    revisions.push({
      xrefOffset: section.offset,
      start: section.start,
      kind: section.kind,
      hiddenStreamOffset: section.hiddenStreamOffset,
      end,
      eofEnd,
    });
  }
  return revisions;
}

/**
 * B2: the effective entry for each object number is the first one met, newest
 * section first, as T033's addEntry keeps it. Inside a hybrid section the
 * order is the table's in-use entries, then the /XRefStm entries, then the
 * table's free entries (B1 (c)). Superseded entries are never read.
 */
function effectiveEntries(newestFirst: readonly Section[]): Map<number, Entry> {
  const effective = new Map<number, Entry>();
  const keep = (entry: Entry): void => {
    if (!effective.has(entry.num)) effective.set(entry.num, entry);
  };
  for (const section of newestFirst) {
    if (section.kind === 'table') {
      for (const entry of section.entries) if (entry.type === 1) keep(entry);
      for (const entry of section.hidden) keep(entry);
      for (const entry of section.entries) if (entry.type === 0) keep(entry);
    } else {
      for (const entry of section.entries) keep(entry);
    }
  }
  return effective;
}

/**
 * An object stream already read: its object number, its /N, its decoded data,
 * and the object numbers of the header pairs parsed so far (read on demand, up
 * to the highest index an entry names).
 */
interface ObjectStream {
  readonly num: number;
  readonly count: number;
  readonly data: Uint8Array;
  readonly numbers: number[];
  pos: number;
}

function checkEffectiveEntries(bytes: Uint8Array, newestFirst: readonly Section[], budget: Budget): void {
  const effective = effectiveEntries(newestFirst);
  const objectStreams = new Map<number, ObjectStream>(); // keyed by the stream's offset
  for (const entry of effective.values()) {
    if (entry.type === 1) checkInUseEntry(bytes, entry, budget);
    else if (entry.type === 2) checkCompressedEntry(bytes, entry, effective, objectStreams, budget);
  }
}

/** B1 (b): the offset is bounded only by the file; the header there carries the entry's number and generation. */
function checkInUseEntry(bytes: Uint8Array, entry: Entry, budget: Budget): void {
  const header = readObjectHeader(bytes, entry.field2);
  if (header === null) fault('xref-entry-mismatch');
  spend(budget, header.skipped);
  if (header.num !== entry.num || header.gen !== entry.field3) fault('xref-entry-mismatch');
}

/**
 * An effective type-2 entry names an object stream whose own effective entry is
 * in use and reaches a /Type /ObjStm stream object with that number; its index
 * is below that stream's /N (B1 (d), restored); and the header pair at that
 * index names the entry's own object number, as T033's readCompressed requires
 * (request #57 item 4, under #56 B1). Each stream object is read and decoded
 * once, cached by offset together with its number.
 */
function checkCompressedEntry(
  bytes: Uint8Array,
  entry: Entry,
  effective: ReadonlyMap<number, Entry>,
  objectStreams: Map<number, ObjectStream>,
  budget: Budget,
): void {
  const stream = effective.get(entry.field2);
  if (stream === undefined || stream.type !== 1) fault('xref-type2-not-object-stream');
  let read = objectStreams.get(stream.field2);
  if (read === undefined) {
    read = readObjectStream(bytes, stream.field2, effective, budget);
    objectStreams.set(stream.field2, read);
  }
  if (read.num !== entry.field2) fault('xref-type2-not-object-stream');
  if (entry.field3 >= read.count) fault('xref-type2-not-object-stream');
  if (headerNumber(read, entry.field3) !== entry.num) fault('xref-entry-mismatch');
}

function readObjectStream(
  bytes: Uint8Array,
  offset: number,
  effective: ReadonlyMap<number, Entry>,
  budget: Budget,
): ObjectStream {
  let object: IndirectObject | null = null;
  try {
    object = readIndirectObject(bytes, offset);
  } catch (error) {
    if (!(error instanceof SyntaxFault)) throw error;
  }
  if (object === null || object.streamStart === null) fault('xref-type2-not-object-stream');
  spend(budget, object.header.skipped);
  if (nameValue(dictEntry(object.value, 'Type')) !== 'ObjStm') fault('xref-type2-not-object-stream');
  const count = intValue(dictEntry(object.value, 'N'));
  if (count === null || count < 0) fault('xref-type2-not-object-stream');
  const length = streamLength(bytes, dictEntry(object.value, 'Length'), effective, budget);
  const raw = streamBody(bytes, object.streamStart, length, budget, OBJECT_STREAM_FAULTS);
  const data = decodeStream(object.value, raw, budget, OBJECT_STREAM_FAULTS, null);
  return { num: object.num, count, data, numbers: [], pos: 0 };
}

/**
 * An object stream's /Length: a direct integer, or a reference to an integer
 * object reached through its effective in-use entry.
 */
function streamLength(
  bytes: Uint8Array,
  value: PdfValue | undefined,
  effective: ReadonlyMap<number, Entry>,
  budget: Budget,
): number {
  if (value === undefined) return fault('xref-type2-not-object-stream');
  if (value.kind !== 'ref') {
    const direct = intValue(value);
    if (direct === null) fault('xref-type2-not-object-stream');
    return direct;
  }
  const target = effective.get(value.num);
  if (target === undefined || target.type !== 1) fault('xref-type2-not-object-stream');
  let object: IndirectObject | null = null;
  try {
    object = readIndirectObject(bytes, target.field2);
  } catch (error) {
    if (!(error instanceof SyntaxFault)) throw error;
  }
  if (object === null || object.num !== value.num || object.gen !== value.gen) fault('xref-type2-not-object-stream');
  spend(budget, object.header.skipped);
  const length = intValue(object.value);
  if (length === null) fault('xref-type2-not-object-stream');
  return length;
}

/**
 * The object number of header pair `index` (pairs of unsigned integers,
 * separated by white-space and comments, from the start of the decoded data).
 * Pairs are parsed once, in order, and only as far as an entry needs; each
 * consumes at least one byte, so the work is bounded by the data's length.
 */
function headerNumber(stream: ObjectStream, index: number): number {
  const data = stream.data;
  while (stream.numbers.length <= index) {
    const num = readUnsignedInt(data, skipWhitespaceAndComments(data, stream.pos, data.length), data.length);
    if (num === null) fault('xref-type2-not-object-stream');
    const offset = readUnsignedInt(data, skipWhitespaceAndComments(data, num.next, data.length), data.length);
    if (offset === null) fault('xref-type2-not-object-stream');
    stream.numbers.push(num.value);
    stream.pos = offset.next;
  }
  const number = stream.numbers[index];
  if (number === undefined) return fault('xref-type2-not-object-stream');
  return number;
}
