// SPDX-License-Identifier: Apache-2.0
//
// The verifier's own revision-structure reader (T014). It walks the
// cross-reference chain of an incrementally updated PDF, reports where each
// revision ends (so the ByteRange check can find the signed revision and the
// coverage verdict can tell whether that revision is the last), and finds the
// signature dictionaries among the effective objects (request #58 (1)).
//
// It accepts at least every base T033's parser accepts (requests #49, #55, #56,
// #57 and #58; row T014-XREFSTART; VB-06), so a base T033 accepted and T036
// composed never fails here on its layout alone:
// - a section start (the final startxref, each /Prev, each /XRefStm) may name
//   white-space or comments before `xref` or before the stream object's header
//   (T033 skips them only before an object header; the T014 line also accepts
//   them before `xref`, a harmless superset);
// - a table is read as tokens: white-space and comments may come anywhere
//   between and around them, including directly after `xref`; numbers have 1 to
//   15 digits with leading zeros allowed; a generation is at most 65535; each
//   entry ends with exactly the keyword `n` or `f`. Within one section the FIRST
//   entry for an object number wins, a free one included (T033's addLocal);
// - an object header read at an offset may be preceded by white-space and
//   comments, and its tokens may be separated by them;
// - dictionary values follow T033's readValue (pdf-syntax.ts): numbers of up to
//   32 characters, integral reals wherever an integer is required, comments
//   inside `n g R`, and no item cap below the input bound;
// - the final `startxref` is the last one in the final tailWindowBytes, then
//   white-space or comments, 1 to 15 digits, white-space, `%%EOF`. Bytes after
//   that %%EOF belong to the last revision, which ends at the end of the file
//   (T033 allows only white-space there; tolerating more keeps OC-02-f, and
//   unsigned bytes there never leave coverage complete, request #58 (2));
// - stream data is /Length bytes, then white-space and comments, then
//   `endstream`.
//
// Cross-reference streams (T033's readXrefStream): /W is three non-negative
// integers, not all zero; /W[0] = 0 makes the type 1, and /W[1] = 0 is allowed;
// types other than 1 and 2 are free entries. Structural streams (cross-reference
// streams and object streams, T033's decodeStructuralStream) have no filter
// when /Filter is absent, null or [], with /DecodeParms then ignored; otherwise
// exactly one FlateDecode with no predictor or a PNG predictor (/BitsPerComponent
// 8, /Colors 1 to 4, any /Columns of at least 1). Inflated bytes count against
// one total budget, at least T033's ceiling. Hybrids: a table trailer's
// /XRefStm names a hidden stream whose entries belong to the same section.
//
// What it checks (request #56 B1: base-structure checks mirror T033; the
// security checks in byte-range.ts and verify.ts stay strict and read only the
// final chain's signature, its ByteRange and /Contents, and the bytes outside
// the signed ranges, so none depends on a relaxed check here):
// - the header at offset 0;
// - the final startxref, every /Prev and every /XRefStm reach a section of the
//   right kind. /Prev is followed as T033 follows it (B3): a non-negative offset
//   within the file, in either direction, no section revisited, and at most
//   maxRevisions sections;
// - only EFFECTIVE entries are checked (B2): the first entry for each object
//   number, newest section first (T033's addEntry). Inside a hybrid section the
//   precedence is the section's in-use table entry, then its /XRefStm entry,
//   then its free table entry (B1 (c)). Entries are counted as T033 counts
//   them: the distinct effective entries, and separately each section's own,
//   never the sum (request #58 (3)).
// - every effective in-use entry reaches a header with its own number and
//   generation (its offset bounded only by the file, B1 (b)), and its object
//   parses; every effective type-2 entry names an object stream (/Type /ObjStm)
//   whose own effective entry is in use, its index is below /N (B1 (d)), the
//   header pair at that index (the header ends at /First) names the entry's
//   own object number (request #57 item 4), and its object parses.
// - signatures by DICTIONARY over every effective object, nested dictionaries
//   and stream dictionaries included, never by text (request #58 (1)).
// It does not read an earlier revision's own startxref value (B1 (a)). Revision
// ends are found in file order: each revision ends after the first %%EOF past
// its section and at most one end-of-line, before the next section by
// position; one without a %%EOF has an unmarked end, at which no signature can
// end; the last by position ends at the file length. A stream section may start
// at any offset T033's section read admits (request #62 (1)): at 7, where
// readIndirect reads the header's minor version digit as the object number,
// and at 0, where its skipWhitespace passes over the header line as a comment.
// No revision check assumes that a section starts after the header.
//
// Work (request #60 (2)): a region already read is reused, never read again: an
// indirect read or a header skip by its start offset, a cross-reference stream
// by its offset, a compressed object by its object stream, start and end. No
// byte total refuses a file: each loop is bounded by its own run, which never
// passes the input or the decoded data, and by the counts capped at or above
// T033's ceilings (entries, sections, depth and inflated bytes).
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
  type ByteRangeKey,
  type IndirectObject,
  type ObjectHeader,
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
  'object-malformed',
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

/**
 * The signature dictionaries among the effective objects (request #58 (1)).
 * `one` carries the file offsets of the one dictionary's /ByteRange key and
 * value, or null when it has no /ByteRange.
 */
export type SignatureScan =
  | { readonly state: 'none' }
  | { readonly state: 'one'; readonly byteRange: ByteRangeKey | null }
  | { readonly state: 'unsupported'; readonly detail: 'multiple-signatures' | 'signature-compressed' };

export type StructureResult =
  | { readonly ok: true; readonly revisions: readonly Revision[]; readonly signature: SignatureScan }
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

/** A section's own entries: the first for each object number (T033's addLocal). */
type LocalEntries = Map<number, Entry>;

interface SectionInfo {
  readonly offset: number;
  readonly start: number;
  readonly kind: 'table' | 'stream';
  readonly prev: number | null;
  readonly hiddenStreamOffset: number | null;
}

interface Section extends SectionInfo {
  readonly local: LocalEntries;
  /** A hybrid table's hidden-stream entries, or null. */
  readonly hidden: LocalEntries | null;
}

/** What one structure read has spent, and the regions it has read and reuses (request #60 (2)). */
interface Budget {
  /** Inflated bytes still allowed across all decoded cross-reference and object streams. */
  inflated: number;
  /** Indirect objects read at an offset: the header, and the object, or null when its body is malformed. */
  readonly indirect: Map<number, { readonly header: ObjectHeader; readonly object: IndirectObject | null } | null>;
  /** Cross-reference streams read at an offset (sections and /XRefStm). */
  readonly xrefStreams: Map<number, XrefStreamRead | null>;
  /** Compressed objects parsed, keyed by object stream offset, start and end. */
  readonly compressed: Map<string, PdfValue>;
  /** Test-only read counts (readRevisionStructureCounted), or null; the reader never reads them. */
  readonly counts: StructureReadCounts | null;
}

/**
 * TEST ONLY (request #62 (3); row T014-TESTS): how many reads one structure
 * read asked for, and how many it made afresh rather than reusing.
 */
export interface StructureReadCounts {
  /** Indirect objects asked for at an offset, and read afresh (indirectAt). */
  indirectRequests: number;
  indirectReads: number;
  /** Cross-reference streams asked for at an offset, and decoded afresh. */
  xrefStreamRequests: number;
  xrefStreamDecodes: number;
  /** Object streams read and decoded (once per stream object). */
  objectStreamDecodes: number;
  /** Compressed objects asked for, and parsed afresh (by object stream, start and end). */
  compressedRequests: number;
  compressedParses: number;
}

const MAX_GENERATION = 65535;

/** Read the revision structure of `bytes`. Never throws on malformed input. */
export function readRevisionStructure(bytes: Uint8Array): StructureResult {
  return readStructure(bytes, null);
}

/**
 * TEST ONLY (request #62 (3); row T014-TESTS): readRevisionStructure, with the
 * reads it made counted in a fresh object created here for this one call.
 * index.ts does not export it, so no product caller reaches it, and the reader
 * only adds to the counts, never reads them; product calls carry none.
 */
export function readRevisionStructureCounted(bytes: Uint8Array): { result: StructureResult; counts: StructureReadCounts } {
  const counts: StructureReadCounts = {
    indirectRequests: 0,
    indirectReads: 0,
    xrefStreamRequests: 0,
    xrefStreamDecodes: 0,
    objectStreamDecodes: 0,
    compressedRequests: 0,
    compressedParses: 0,
  };
  return { result: readStructure(bytes, counts), counts };
}

function readStructure(bytes: Uint8Array, counts: StructureReadCounts | null): StructureResult {
  try {
    const { revisions, signature } = walk(bytes, counts);
    return { ok: true, revisions, signature };
  } catch (error) {
    if (error instanceof StructureFault) return { ok: false, detail: error.detail };
    throw error;
  }
}

function walk(bytes: Uint8Array, counts: StructureReadCounts | null): { revisions: Revision[]; signature: SignatureScan } {
  if (bytes.length > VERIFIER_LIMITS.maxInputBytes) fault('input-too-large');
  checkHeader(bytes);
  const budget: Budget = {
    inflated: VERIFIER_LIMITS.maxXrefInflatedBytes,
    indirect: new Map(),
    xrefStreams: new Map(),
    compressed: new Map(),
    counts,
  };
  const sections: SectionInfo[] = [];
  const effective = new Map<number, Entry>();
  // B3: /Prev in either direction, as T033 follows it; no section is visited
  // twice, whether named by the same offset or reached at the same position.
  const seenOffsets = new Set<number>();
  const seenStarts = new Set<number>();
  let offset = finalStartxref(bytes);
  let origin: 'startxref' | 'prev' = 'startxref';
  for (;;) {
    if (sections.length >= VERIFIER_LIMITS.maxRevisions) fault('too-many-revisions');
    if (seenOffsets.has(offset)) fault('prev-revisited');
    seenOffsets.add(offset);
    const section = readSection(bytes, offset, origin, budget);
    if (seenStarts.has(section.start)) fault('prev-revisited');
    seenStarts.add(section.start);
    mergeSection(effective, section);
    sections.push({
      offset: section.offset,
      start: section.start,
      kind: section.kind,
      prev: section.prev,
      hiddenStreamOffset: section.hiddenStreamOffset,
    });
    if (section.prev === null) break;
    offset = section.prev;
    origin = 'prev';
  }
  const revisions = locateRevisions(bytes, sections);
  const signature = checkEffectiveObjects(bytes, effective, budget);
  return { revisions, signature };
}

/**
 * The indirect object at `offset`, read once and reused (request #60 (2)): null
 * when no header is there; `object` is null when the body is malformed.
 */
function indirectAt(
  bytes: Uint8Array,
  offset: number,
  budget: Budget,
): { readonly header: ObjectHeader; readonly object: IndirectObject | null } | null {
  if (budget.counts !== null) budget.counts.indirectRequests += 1;
  const known = budget.indirect.get(offset);
  if (known !== undefined) return known;
  if (budget.counts !== null) budget.counts.indirectReads += 1;
  const header = readObjectHeader(bytes, offset);
  let read: { readonly header: ObjectHeader; readonly object: IndirectObject | null } | null = null;
  if (header !== null) {
    let object: IndirectObject | null = null;
    try {
      object = readIndirectObject(bytes, offset);
    } catch (error) {
      if (!(error instanceof SyntaxFault)) throw error;
    }
    read = { header, object };
  }
  budget.indirect.set(offset, read);
  return read;
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
    return readTableSection(bytes, offset, start, budget);
  }
  const stream = readXrefStream(bytes, offset, budget);
  if (stream === null) fault(notXref);
  return { offset, start: stream.start, kind: 'stream', prev: stream.prev, hiddenStreamOffset: null, local: stream.local, hidden: null };
}

/** T033's addLocal: the first entry for an object number in a section wins; a section's own count is bounded. */
function addLocal(local: LocalEntries, entry: Entry): void {
  if (local.has(entry.num)) return;
  local.set(entry.num, entry);
  if (local.size > VERIFIER_LIMITS.maxXrefEntries) fault('too-many-xref-entries');
}

/**
 * T033's addEntry, newest section first: the first entry for an object number
 * wins. In a hybrid section, the in-use table entry comes before the /XRefStm
 * entry, and the /XRefStm entry before a free table entry (B1 (c)). The
 * distinct effective entries are bounded.
 */
function mergeSection(effective: Map<number, Entry>, section: Section): void {
  const keep = (entry: Entry): void => {
    if (effective.has(entry.num)) return;
    effective.set(entry.num, entry);
    if (effective.size > VERIFIER_LIMITS.maxXrefEntries) fault('too-many-xref-entries');
  };
  if (section.hidden === null) {
    for (const entry of section.local.values()) keep(entry);
    return;
  }
  for (const entry of section.local.values()) if (entry.type === 1) keep(entry);
  for (const entry of section.hidden.values()) keep(entry);
  for (const entry of section.local.values()) if (entry.type === 0) keep(entry);
}

// ---------------------------------------------------------------------------
// Classic tables, read as tokens
// ---------------------------------------------------------------------------

function readTableSection(bytes: Uint8Array, offset: number, start: number, budget: Budget): Section {
  const end = bytes.length;
  const local: LocalEntries = new Map();
  let p = start + 4;
  for (;;) {
    p = skipWhitespaceAndComments(bytes, p, end);
    if (p >= end) fault('xref-table-malformed');
    if (atKeyword(bytes, p, 'trailer')) break;
    const first = readUnsignedInt(bytes, p, end);
    if (first === null) fault('xref-table-malformed');
    const count = readUnsignedInt(bytes, skipWhitespaceAndComments(bytes, first.next, end), end);
    if (count === null) fault('xref-table-malformed');
    p = count.next;
    // Each entry takes at least five bytes, so the input bounds this loop.
    for (let i = 0; i < count.value; i += 1) {
      const read = readTableEntry(bytes, p, first.value + i);
      addLocal(local, read.entry);
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
  let hidden: LocalEntries | null = null;
  if (hiddenStreamOffset !== null) {
    // B1 (c): bounded only by the file; its entries are kept apart so that the
    // hybrid precedence in mergeSection can apply.
    if (hiddenStreamOffset >= end) fault('xrefstm-not-xref-stream');
    const stream = readXrefStream(bytes, hiddenStreamOffset, budget);
    if (stream === null) fault('xrefstm-not-xref-stream');
    hidden = stream.local;
  }
  return { offset, start, kind: 'table', prev, hiddenStreamOffset, local, hidden };
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

interface XrefStreamRead {
  readonly start: number;
  readonly prev: number | null;
  readonly local: LocalEntries;
}

/**
 * The cross-reference stream reached at `offset`, or null when no /Type /XRef
 * object is there. Each offset is read and decoded once, and reused when more
 * sections name it (request #60 (2)).
 */
function readXrefStream(bytes: Uint8Array, offset: number, budget: Budget): XrefStreamRead | null {
  if (budget.counts !== null) budget.counts.xrefStreamRequests += 1;
  const known = budget.xrefStreams.get(offset);
  if (known !== undefined) return known;
  if (budget.counts !== null) budget.counts.xrefStreamDecodes += 1;
  const read = decodeXrefStreamAt(bytes, offset, budget);
  budget.xrefStreams.set(offset, read);
  return read;
}

function decodeXrefStreamAt(bytes: Uint8Array, offset: number, budget: Budget): XrefStreamRead | null {
  const read = indirectAt(bytes, offset, budget);
  if (read === null || read.object === null) return null;
  const object = read.object;
  if (nameValue(dictEntry(object.value, 'Type')) !== 'XRef') return null;
  if (object.streamStart === null) fault('xref-stream-malformed');
  // /Length is always direct in a cross-reference stream (ISO 32000, 7.5.8.2).
  const length = intValue(dictEntry(object.value, 'Length'));
  if (length === null) fault('xref-stream-malformed');
  const raw = streamBody(bytes, object.streamStart, length, XREF_STREAM_FAULTS);
  const decoded = decodeStream(object.value, raw, budget, XREF_STREAM_FAULTS);
  const local = xrefStreamEntries(object.value, decoded);
  return { start: object.header.start, prev: optionalOffset(object.value, 'Prev', 'xref-stream-malformed'), local };
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
function streamBody(bytes: Uint8Array, start: number, length: number, faults: DecodeFaults): Uint8Array {
  if (length < 0) fault(faults.malformed);
  if (length > VERIFIER_LIMITS.maxXrefStreamBytes) fault(faults.tooLarge);
  const end = start + length;
  if (end > bytes.length) fault(faults.malformed);
  const kw = skipWhitespaceAndComments(bytes, end, bytes.length);
  if (!atKeyword(bytes, kw, 'endstream')) fault(faults.malformed);
  return bytes.subarray(start, end);
}

/**
 * T033's decodeStructuralStream: no filter when /Filter is absent, null or an
 * empty array, and /DecodeParms is then ignored; otherwise exactly one
 * FlateDecode (a name or a one-element array) with /Predictor 1 or a PNG
 * predictor 10 to 15 (/BitsPerComponent 8, /Colors 1 to 4, /Columns at least
 * 1; each row is Colors x Columns bytes plus its tag byte). Inflated bytes
 * count against one total budget over every decoded stream.
 */
function decodeStream(dict: PdfValue, raw: Uint8Array, budget: Budget, faults: DecodeFaults): Uint8Array {
  const filter = dictEntry(dict, 'Filter');
  if (filter === undefined || filter.kind === 'null' || (filter.kind === 'array' && filter.items.length === 0)) return raw;
  let filterName: string | null = null;
  if (filter.kind === 'name') filterName = filter.value;
  else if (filter.kind === 'array' && filter.items.length === 1) filterName = nameValue(filter.items[0]);
  if (filterName !== 'FlateDecode') fault(faults.filter);
  let parms = dictEntry(dict, 'DecodeParms');
  if (parms !== undefined && parms.kind === 'array') {
    if (parms.items.length !== 1) fault(faults.malformed);
    parms = parms.items[0];
  }
  if (parms !== undefined && parms.kind !== 'dict' && parms.kind !== 'null') fault(faults.malformed);
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
  const bits = intValue(dictEntry(parms, 'BitsPerComponent')) ?? 8;
  const colors = intValue(dictEntry(parms, 'Colors')) ?? 1;
  const columns = intValue(dictEntry(parms, 'Columns')) ?? 1;
  if (bits !== 8 || colors < 1 || colors > 4 || columns < 1) fault(faults.predictor);
  return undoPngPredictor(decoded, colors * columns, colors, faults);
}

/** PNG row filters 0 None, 1 Sub, 2 Up, 3 Average, 4 Paeth; `bpp` bytes per pixel. */
function undoPngPredictor(data: Uint8Array, rowBytes: number, bpp: number, faults: DecodeFaults): Uint8Array {
  const rowLength = rowBytes + 1;
  if (data.length % rowLength !== 0) fault(faults.malformed);
  const rows = data.length / rowLength;
  const out = new Uint8Array(rows * rowBytes);
  for (let r = 0; r < rows; r += 1) {
    const filter = byteAt(data, r * rowLength);
    for (let i = 0; i < rowBytes; i += 1) {
      const x = byteAt(data, r * rowLength + 1 + i);
      const left = i >= bpp ? byteAt(out, r * rowBytes + i - bpp) : 0;
      const up = r > 0 ? byteAt(out, (r - 1) * rowBytes + i) : 0;
      const upLeft = i >= bpp && r > 0 ? byteAt(out, (r - 1) * rowBytes + i - bpp) : 0;
      let v: number;
      if (filter === 0) v = x;
      else if (filter === 1) v = x + left;
      else if (filter === 2) v = x + up;
      else if (filter === 3) v = x + ((left + up) >> 1);
      else if (filter === 4) v = x + paeth(left, up, upLeft);
      else return fault(faults.pngFilter);
      out[r * rowBytes + i] = v & 0xff;
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

/** /W: three non-negative integers, each at most maxXrefFieldWidth, not all zero (T033's readXrefStream). */
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
  if (a + b + c === 0) fault('xref-stream-malformed');
  return [a, b, c];
}

function xrefStreamEntries(dict: PdfValue, data: Uint8Array): LocalEntries {
  const [w1, w2, w3] = widths(dict);
  const row = w1 + w2 + w3;
  const size = intValue(dictEntry(dict, 'Size'));
  if (size === null || size < 0) fault('xref-stream-malformed');
  const index = dictEntry(dict, 'Index');
  const pairs: Array<[number, number]> = [];
  // /Index absent or null means [0 /Size]: T033's default applies to a null too (request #60 (1)).
  if (index === undefined || index.kind === 'null') {
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
  // The rows must fill the decoded data exactly, so its length bounds the loop.
  if (data.length !== total * row) fault('xref-stream-malformed');
  const local: LocalEntries = new Map();
  let p = 0;
  for (const [first, count] of pairs) {
    for (let i = 0; i < count; i += 1) {
      const type = w1 === 0 ? 1 : readField(data, p, w1);
      const field2 = w2 === 0 ? 0 : readField(data, p + w1, w2);
      const field3 = w3 === 0 ? 0 : readField(data, p + w1 + w2, w3);
      p += row;
      // Types other than 1 and 2 (0, and 3 or above) are free (T033).
      const kind: 0 | 1 | 2 = type === 1 ? 1 : type === 2 ? 2 : 0;
      addLocal(local, { num: first + i, type: kind, field2, field3 });
    }
  }
  return local;
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
// Revision ends
// ---------------------------------------------------------------------------

/**
 * Revision ends, in FILE order. B3 lets /Prev point either way, so a
 * revision's region runs from its section to the next section by position,
 * not to the next in the chain. Duplicate starts were refused by walk.
 */
function locateRevisions(bytes: Uint8Array, newestFirst: readonly SectionInfo[]): Revision[] {
  const sections = [...newestFirst].sort((a, b) => a.start - b.start);
  const revisions: Revision[] = [];
  for (let k = 0; k < sections.length; k += 1) {
    const section = sections[k];
    if (section === undefined) return fault('revision-order');
    const next = sections[k + 1];
    const regionEnd = next === undefined ? bytes.length : next.start;
    // Any start T033's section read admits, 0 and 7 included (request #62 (1)).
    if (section.start >= regionEnd) fault('revision-order');
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

// ---------------------------------------------------------------------------
// Effective objects: entry checks and the signature scan
// ---------------------------------------------------------------------------

/**
 * An object stream already read: its object number, /N, /First, decoded data,
 * and the header pairs parsed so far (read on demand, in order, up to the
 * highest index an entry names).
 */
interface ObjectStream {
  readonly num: number;
  readonly count: number;
  readonly first: number;
  readonly data: Uint8Array;
  readonly pairs: Array<readonly [number, number]>;
  pos: number;
}

/**
 * Every effective entry, as T033's parseObjects reads it: an in-use entry's
 * header and object, and a compressed entry's object stream, header pair and
 * object. Each object, with every dictionary nested in it, goes to the
 * signature scan.
 */
function checkEffectiveObjects(bytes: Uint8Array, effective: ReadonlyMap<number, Entry>, budget: Budget): SignatureScan {
  const scan = new SignatureCollector();
  const objectStreams = new Map<number, ObjectStream>(); // keyed by the stream's offset
  for (const entry of effective.values()) {
    if (entry.type === 1) {
      const object = readInUseObject(bytes, entry, budget);
      scan.object(entry.num, object.gen, object.value, false);
    } else if (entry.type === 2) {
      scan.object(entry.num, 0, readCompressedObject(bytes, entry, effective, objectStreams, budget), true);
    }
  }
  return scan.result();
}

/** B1 (b): the offset is bounded only by the file; the header there carries the entry's number and generation, and the object parses. */
function readInUseObject(bytes: Uint8Array, entry: Entry, budget: Budget): { gen: number; value: PdfValue } {
  const read = indirectAt(bytes, entry.field2, budget);
  if (read === null) fault('xref-entry-mismatch');
  if (read.header.num !== entry.num || read.header.gen !== entry.field3) fault('xref-entry-mismatch');
  if (read.object === null) fault('object-malformed');
  return { gen: read.header.gen, value: read.object.value };
}

/**
 * An effective type-2 entry names an object stream whose own effective entry is
 * in use and reaches a /Type /ObjStm stream object with that number; its index
 * is below /N (B1 (d)); the header pair at that index names the entry's own
 * object number (request #57 item 4); and the object at /First plus the pair's
 * offset parses. Each stream object is read and decoded once, cached by offset
 * together with its number.
 */
function readCompressedObject(
  bytes: Uint8Array,
  entry: Entry,
  effective: ReadonlyMap<number, Entry>,
  objectStreams: Map<number, ObjectStream>,
  budget: Budget,
): PdfValue {
  const stream = effective.get(entry.field2);
  if (stream === undefined || stream.type !== 1) fault('xref-type2-not-object-stream');
  let read = objectStreams.get(stream.field2);
  if (read === undefined) {
    read = readObjectStream(bytes, stream.field2, effective, budget);
    objectStreams.set(stream.field2, read);
  }
  if (read.num !== entry.field2) fault('xref-type2-not-object-stream');
  if (entry.field3 >= read.count) fault('xref-type2-not-object-stream');
  const [number, offset] = headerPair(read, entry.field3);
  if (number !== entry.num) fault('xref-entry-mismatch');
  const at = read.first + offset;
  if (at >= read.data.length) fault('xref-type2-not-object-stream');
  // The object ends at the next header offset, or at the end of the decoded
  // data when that offset is not greater than its own (T033's readCompressed;
  // request #60 (1)).
  let end = read.data.length;
  if (entry.field3 + 1 < read.count) {
    const [, nextOffset] = headerPair(read, entry.field3 + 1);
    if (nextOffset > offset) end = Math.min(read.data.length, read.first + nextOffset);
  }
  const key = `${stream.field2}:${at}:${end}`;
  if (budget.counts !== null) budget.counts.compressedRequests += 1;
  const known = budget.compressed.get(key);
  if (known !== undefined) return known;
  if (budget.counts !== null) budget.counts.compressedParses += 1;
  let parsed: { value: PdfValue; next: number };
  try {
    parsed = parseValue(read.data, at, end);
  } catch (error) {
    if (error instanceof SyntaxFault) fault('object-malformed');
    throw error;
  }
  budget.compressed.set(key, parsed.value);
  return parsed.value;
}

function readObjectStream(
  bytes: Uint8Array,
  offset: number,
  effective: ReadonlyMap<number, Entry>,
  budget: Budget,
): ObjectStream {
  if (budget.counts !== null) budget.counts.objectStreamDecodes += 1;
  const read = indirectAt(bytes, offset, budget);
  const object = read === null ? null : read.object;
  if (object === null || object.streamStart === null) fault('xref-type2-not-object-stream');
  if (nameValue(dictEntry(object.value, 'Type')) !== 'ObjStm') fault('xref-type2-not-object-stream');
  const count = intValue(dictEntry(object.value, 'N'));
  if (count === null || count < 0) fault('xref-type2-not-object-stream');
  const first = intValue(dictEntry(object.value, 'First'));
  if (first === null || first < 0) fault('xref-type2-not-object-stream');
  const length = streamLength(bytes, dictEntry(object.value, 'Length'), effective, budget);
  const raw = streamBody(bytes, object.streamStart, length, OBJECT_STREAM_FAULTS);
  const data = decodeStream(object.value, raw, budget, OBJECT_STREAM_FAULTS);
  if (first > data.length) fault('xref-type2-not-object-stream');
  return { num: object.num, count, first, data, pairs: [], pos: 0 };
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
  // Read with the ENTRY's own generation; the reference's generation is never
  // compared, as in T033's streamLength (request #60 (1)).
  const read = indirectAt(bytes, target.field2, budget);
  const object = read === null ? null : read.object;
  if (object === null || object.num !== value.num || object.gen !== target.field3) fault('xref-type2-not-object-stream');
  const length = intValue(object.value);
  if (length === null) fault('xref-type2-not-object-stream');
  return length;
}

/**
 * Header pair `index`: two unsigned integers (object number, then offset),
 * separated by white-space and comments, read from the start of the decoded
 * data in a region that ends at /First, so the last number may run right up
 * to /First (T033's loadObjectStream). Pairs are parsed once, in order, and
 * only as far as an entry needs; each consumes at least one byte, so /First
 * bounds the work.
 */
function headerPair(stream: ObjectStream, index: number): readonly [number, number] {
  const data = stream.data;
  const end = stream.first;
  while (stream.pairs.length <= index) {
    const num = readUnsignedInt(data, skipWhitespaceAndComments(data, stream.pos, end), end);
    if (num === null) fault('xref-type2-not-object-stream');
    const offset = readUnsignedInt(data, skipWhitespaceAndComments(data, num.next, end), end);
    if (offset === null) fault('xref-type2-not-object-stream');
    stream.pairs.push([num.value, offset.value]);
    stream.pos = offset.next;
  }
  const pair = stream.pairs[index];
  if (pair === undefined) return fault('xref-type2-not-object-stream');
  return pair;
}

interface FoundSignature {
  readonly dict: PdfValue & { readonly kind: 'dict' };
  /** The object's number when the dictionary is the object's own value, else null. */
  readonly num: number | null;
  readonly gen: number;
  readonly compressed: boolean;
}

/** What one parsed value holds for the signature scan, found once and reused for every object sharing it (request #60 (2)). */
interface ValueSummary {
  /** At most two signature dictionaries (`more` marks others), each with whether it is the value itself. */
  readonly signatures: ReadonlyArray<{ readonly dict: PdfValue & { readonly kind: 'dict' }; readonly top: boolean }>;
  readonly more: boolean;
  readonly permissions: boolean;
  readonly fieldValues: readonly PdfValue[];
}

/**
 * Signatures by DICTIONARY, as T033's classifyValue finds them (request #58
 * (1)): every dictionary in every effective object is examined, nested ones
 * and stream dictionaries included; string contents are never scanned. A
 * dictionary is a signature when /Type is /Sig or /DocTimeStamp, or when it has
 * both /ByteRange and /Contents. More than one, any /DocMDP or /UR3 key, or a
 * /FT /Sig field whose non-null /V is not the one signature dictionary, is
 * `multiple-signatures`. A value shared by several objects (a reused
 * compressed object) is walked once, and its signatures count once per object,
 * as T033 counts each object it parses.
 */
class SignatureCollector {
  private readonly found: FoundSignature[] = [];
  private more = false;
  private permissions = false;
  private readonly fieldValues: PdfValue[] = [];
  private readonly summaries = new Map<PdfValue, ValueSummary>();

  object(num: number, gen: number, value: PdfValue, compressed: boolean): void {
    let summary = this.summaries.get(value);
    const firstUse = summary === undefined;
    if (summary === undefined) {
      summary = summarize(value);
      this.summaries.set(value, summary);
    }
    for (const signature of summary.signatures) {
      if (this.found.length < 2) this.found.push({ dict: signature.dict, num: signature.top ? num : null, gen, compressed });
      else this.more = true;
    }
    if (summary.more) this.more = true;
    if (summary.permissions) this.permissions = true;
    // A shared value's field values are the same values, so they are compared once.
    if (firstUse) for (const v of summary.fieldValues) this.fieldValues.push(v);
  }

  result(): SignatureScan {
    const [one, second] = this.found;
    if (second !== undefined || this.more || this.permissions) return { state: 'unsupported', detail: 'multiple-signatures' };
    for (const v of this.fieldValues) {
      if (one === undefined) return { state: 'unsupported', detail: 'multiple-signatures' };
      const same = v.kind === 'ref' ? one.num !== null && v.num === one.num && v.gen === one.gen : v === one.dict;
      if (!same) return { state: 'unsupported', detail: 'multiple-signatures' };
    }
    if (one === undefined) return { state: 'none' };
    // Request #60 (4): its /Contents would sit in compressed bytes no ByteRange can address.
    if (one.compressed) return { state: 'unsupported', detail: 'signature-compressed' };
    return { state: 'one', byteRange: one.dict.byteRangeKey };
  }
}

/** One walk of a parsed value: its signature dictionaries, permission keys and signature-field values. */
function summarize(value: PdfValue): ValueSummary {
  const signatures: Array<{ readonly dict: PdfValue & { readonly kind: 'dict' }; readonly top: boolean }> = [];
  const fieldValues: PdfValue[] = [];
  let more = false;
  let permissions = false;
  const visit = (v: PdfValue, top: boolean): void => {
    if (v.kind === 'array') {
      for (const item of v.items) visit(item, false);
      return;
    }
    if (v.kind !== 'dict') return;
    const type = nameValue(v.entries.get('Type'));
    if (type === 'Sig' || type === 'DocTimeStamp' || (v.entries.has('ByteRange') && v.entries.has('Contents'))) {
      if (signatures.length < 2) signatures.push({ dict: v, top });
      else more = true;
    }
    if (v.entries.has('DocMDP') || v.entries.has('UR3')) permissions = true;
    if (nameValue(v.entries.get('FT')) === 'Sig') {
      const field = v.entries.get('V');
      if (field !== undefined && field.kind !== 'null') fieldValues.push(field);
    }
    for (const item of v.entries.values()) visit(item, false);
  };
  visit(value, true);
  return { signatures, more, permissions, fieldValues };
}
