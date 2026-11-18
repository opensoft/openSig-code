// SPDX-License-Identifier: Apache-2.0
//
// Bounded hostile-input PDF parser (T033). It runs only inside the isolated parse child
// (src/pdf/worker.ts, started by src/pdf/service.ts); nothing here touches the file
// system or the network.
//
// Supported subset (anything else is rejected):
// - a %PDF-1.0..1.7 or %PDF-2.0 header at byte 0, and startxref plus %%EOF at the end;
// - classic cross-reference tables, cross-reference streams and hybrid files, with /Prev
//   chains (cycle-checked and bounded);
// - object streams (/Type /ObjStm), decoded under the inflation budget;
// - every in-use object is parsed, so a broken offset, stream /Length or dictionary is a
//   rejection, never a silent repair;
// - the page tree with inherited /MediaBox, /CropBox and /Rotate, cycle- and
//   depth-checked, at most maxPages leaves.
//
// Rejections, in precedence order after structural validity: encryption (trailer
// /Encrypt), an existing digital signature, active content (the policy in policy.ts:
// JavaScript, Launch, embedded files, RichMedia, XFA, 3D, Screen, Rendition, SubmitForm,
// ImportData, GoToR, GoToE, Movie, Sound, and any /OpenAction or /AA action other than
// same-document navigation), then, page by page, an effective /CropBox that differs from the
// /MediaBox (unsupported-feature `cropbox_differs`, A-008 S2: field rectangles are
// normalized to the displayed page, so a cropped page would mis-map them) and more than
// maxPages pages. The effective crop box is the inherited /CropBox intersected with the
// /MediaBox (ISO 32000-1 14.11.2); a crop box that covers the whole media box is accepted.
// Names are compared after #xx decoding, so an escaped name cannot hide a detection. JBIG2
// and JPX image filters are reported as features; they are not decoded here.

import { Buffer } from 'node:buffer';

import { limitExceeded, malformed, ParseFailure, type RejectReason } from './errors.ts';
import { createBudget, decodeStructuralStream, streamFilterNames, type InflateBudget } from './filters.ts';
import {
  isDict,
  isNonNegativeInteger,
  isRef,
  isString,
  latin1,
  Lexer,
  nameOf,
  type PdfDict,
  type PdfRef,
  type PdfValue,
} from './lexer.ts';
import { reportBudget, type ParserLimits } from './limits.ts';
import { classifyValue, createFindings } from './policy.ts';

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export interface PageReport {
  number: number;
  /** Displayed width and height in points, after /Rotate (contract PageGeometry). */
  width: number;
  height: number;
  rotate: 0 | 90 | 180 | 270;
  /** Effective /MediaBox, normalized to [llx, lly, urx, ury]. */
  media_box: number[];
  /** Displayed box: the effective /CropBox clipped to the media box. Always equal to media_box (S2). */
  crop_box: number[];
  /** Indirect reference of the page object. */
  ref: [number, number];
}

/**
 * The child's report (A-010 LBR3-1: only what a named reader uses). Upload validation (T034)
 * reads the page count and geometry; the composer (T036) reads the page references and boxes,
 * `xref` (where and how to append the incremental update), `trailer` and `objects` (the
 * dictionaries and arrays it rewrites); the parent (service.ts) checks `schema`, `bytes` and
 * the child's isolation claims; `features` carries the detections reported rather than
 * rejected (JBIG2, JPX, unsigned signature fields) and `stats` the evidence that the parser
 * limits held, both fixed in size. Only `objects` and the trailer /ID vary with the document:
 * both count against the report's byte budget, and `objects` against its node budget too
 * (limits.ts reportBudget).
 */
export interface ParseReport {
  schema: 'opensig.pdf.parse-report.v1';
  header_version: string;
  bytes: number;
  pages: PageReport[];
  xref: { kind: 'table' | 'stream'; sections: number; startxref: number; size: number; hybrid: boolean };
  trailer: { root: [number, number]; info: [number, number] | null; id: [string, string] | null };
  /**
   * Only the objects the composer rewrites: the catalog, the pages, and the AcroForm, its /Fields
   * and page /Annots when indirect; plus, when the AcroForm's /SigFlags is indirect and names a
   * non-negative integer object, that object (its integer value only), which the composer reads
   * to combine the flags with 3 (request #44, T036-FIXES). No other object is reported.
   */
  objects: Record<string, { gen: number; value: JsonValue }>;
  features: string[];
  stats: { objects: number; object_streams: number; max_depth: number; inflated_bytes: number };
}

export type ParseResult =
  | { ok: true; report: ParseReport }
  | { ok: false; reason: RejectReason; detail: string; detections: string[] };

type XrefEntry = { type: 0 } | { type: 1; offset: number; gen: number } | { type: 2; stream: number; index: number };

interface ParsedObject {
  num: number;
  gen: number;
  value: PdfValue;
  stream: { start: number; length: number } | null;
}

interface ObjectStream {
  data: Uint8Array;
  first: number;
  nums: number[];
  offsets: number[];
}

/**
 * A PDF value as plain JSON: names {name}, strings {hex}, references {ref}, dictionaries {dict}.
 * Every value converted (each scalar, name, string, reference, array and dictionary) takes one
 * node from `budget`; past it, the document is refused (limit-exceeded `report-nodes`). The
 * parent counts the same way (service.ts fromJson).
 */
export function toJson(value: PdfValue, budget: { nodes: number } = { nodes: Number.POSITIVE_INFINITY }): JsonValue {
  budget.nodes -= 1;
  if (budget.nodes < 0) throw limitExceeded('report-nodes');
  if (value === null || typeof value === 'boolean' || typeof value === 'number') return value;
  if (Array.isArray(value)) return value.map((item) => toJson(item, budget));
  if (value.t === 'name') return { name: value.v };
  if (value.t === 'str') return { hex: Buffer.from(value.v).toString('hex') };
  if (value.t === 'ref') return { ref: [value.num, value.gen] };
  const dict: { [key: string]: JsonValue } = {};
  for (const [key, inner] of value.map) Object.defineProperty(dict, key, { value: toJson(inner, budget), enumerable: true, writable: true, configurable: true });
  return { dict };
}

const EOF_TAIL = /^startxref[\x00\t\n\f\r ]+(\d{1,15})[\x00\t\n\f\r ]+%%EOF[\x00\t\n\f\r ]*$/;

class DocumentParser {
  readonly bytes: Uint8Array;
  readonly limits: ParserLimits;
  readonly budget: InflateBudget;
  readonly entries = new Map<number, XrefEntry>();
  readonly objects = new Map<number, ParsedObject>();
  readonly objectStreams = new Map<number, ObjectStream>();
  readonly features = new Set<string>();
  readonly active = new Set<string>();
  signatures = 0;
  deepest = 0;
  sections = 0;
  hybrid = false;
  kind: 'table' | 'stream' = 'table';
  trailer: PdfDict | null = null;
  startxref = 0;

  constructor(bytes: Uint8Array, limits: ParserLimits) {
    this.bytes = bytes;
    this.limits = limits;
    this.budget = createBudget(limits.maxRatio, limits.maxInflatedBytes);
  }

  lexer(pos: number, bytes: Uint8Array = this.bytes, end: number = bytes.length): Lexer {
    return new Lexer(bytes, pos, end, this.limits.maxDepth);
  }

  track(lx: Lexer): void {
    if (lx.deepest > this.deepest) this.deepest = lx.deepest;
  }

  run(): ParseReport {
    const version = this.header();
    this.startxref = this.findStartxref();
    this.readChain();
    const trailer = this.trailer;
    if (trailer === null) throw malformed('no trailer');
    if (trailer.map.has('Encrypt')) throw new ParseFailure('encrypted', 'trailer names an /Encrypt dictionary', ['encryption']);
    const size = trailer.map.get('Size');
    if (!isNonNegativeInteger(size)) throw malformed('trailer has no valid /Size');
    for (const num of this.entries.keys()) if (num >= size) throw malformed('trailer /Size does not cover every cross-reference entry');
    const rootRef = trailer.map.get('Root');
    if (!isRef(rootRef)) throw malformed('trailer has no /Root reference');

    this.parseObjects();
    const findings = createFindings();
    const policyResolve = (value: PdfValue | undefined): PdfValue | undefined => {
      if (!isRef(value)) return value;
      const target = this.objects.get(value.num);
      return target !== undefined && target.gen === value.gen ? target.value : undefined;
    };
    for (const obj of this.objects.values()) {
      classifyValue(obj.value, policyResolve, findings);
      if (obj.stream !== null && isDict(obj.value)) this.scanFilters(obj.value);
    }
    this.signatures = findings.signatures;
    for (const kind of findings.active) this.active.add(kind);
    for (const feature of findings.features) this.features.add(feature);
    if (this.signatures > 0) {
      throw new ParseFailure('already-signed', 'existing digital signature or signature permissions', ['signature']);
    }
    if (this.active.size > 0) {
      const found = [...this.active].sort();
      throw new ParseFailure('active-content', found.join(','), found);
    }

    const catalog = this.dictObject(rootRef);
    if (nameOf(catalog, 'Type') !== 'Catalog') throw malformed('/Root is not a /Type /Catalog dictionary');
    const pages = this.walkPages(catalog);

    const objects: ParseReport['objects'] = {};
    const nodes = { nodes: reportBudget(this.limits).nodes };
    const include = (ref: PdfRef): void => {
      const obj = this.objects.get(ref.num);
      if (obj !== undefined && obj.stream === null && !Object.hasOwn(objects, String(ref.num))) {
        Object.defineProperty(objects, String(ref.num), {
          value: { gen: obj.gen, value: toJson(obj.value, nodes) },
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
    };
    include(rootRef);
    for (const page of pages) {
      const ref: PdfRef = { t: 'ref', num: page.ref[0], gen: page.ref[1] };
      include(ref);
      const annots = this.dictObject(ref).map.get('Annots');
      if (isRef(annots)) include(annots);
    }
    const acroform = catalog.map.get('AcroForm');
    if (acroform !== undefined && acroform !== null) {
      this.features.add('acroform');
      if (isRef(acroform)) include(acroform);
      const form = isRef(acroform) ? this.resolve(acroform) : acroform;
      if (isDict(form)) {
        const fields = form.map.get('Fields');
        if (isRef(fields)) include(fields);
        // An indirect /SigFlags: report its target only when it is a non-negative integer
        // object (one node, a few bytes), never a dictionary, array, stream or dangling
        // reference, so no document that parsed before is refused now.
        const sigFlags = form.map.get('SigFlags');
        if (isRef(sigFlags)) {
          const target = this.objects.get(sigFlags.num);
          if (target !== undefined && target.gen === sigFlags.gen && target.stream === null && isNonNegativeInteger(target.value)) include(sigFlags);
        }
      }
    }
    if (this.sections > 1) this.features.add('incremental-updates');
    if (this.hybrid) this.features.add('hybrid-xref');
    if (this.objectStreams.size > 0) this.features.add('object-streams');

    const info = trailer.map.get('Info');
    const id = trailer.map.get('ID');
    let idHex: [string, string] | null = null;
    if (Array.isArray(id) && id.length === 2 && isString(id[0]) && isString(id[1])) {
      idHex = [Buffer.from(id[0].v).toString('hex'), Buffer.from(id[1].v).toString('hex')];
    }
    let inUse = 0;
    for (const entry of this.entries.values()) if (entry.type !== 0) inUse += 1;

    return {
      schema: 'opensig.pdf.parse-report.v1',
      header_version: version,
      bytes: this.bytes.length,
      pages,
      xref: { kind: this.kind, sections: this.sections, startxref: this.startxref, size, hybrid: this.hybrid },
      trailer: { root: [rootRef.num, rootRef.gen], info: isRef(info) ? [info.num, info.gen] : null, id: idHex },
      objects,
      features: [...this.features].sort(),
      stats: {
        objects: inUse,
        object_streams: this.objectStreams.size,
        max_depth: this.deepest,
        inflated_bytes: this.budget.inflated,
      },
    };
  }

  // --- file framing ---------------------------------------------------------------------

  header(): string {
    const head = latin1(this.bytes, 0, Math.min(16, this.bytes.length));
    const match = /^%PDF-(1\.[0-7]|2\.0)(?![0-9])/.exec(head);
    if (!match || match[1] === undefined) throw malformed('missing %PDF-1.x or %PDF-2.0 header at byte 0');
    return match[1];
  }

  findStartxref(): number {
    const tailStart = Math.max(0, this.bytes.length - 1024);
    const tail = latin1(this.bytes, tailStart, this.bytes.length);
    const at = tail.lastIndexOf('startxref');
    if (at < 0) throw malformed('no startxref in the last 1024 bytes');
    const match = EOF_TAIL.exec(tail.slice(at));
    if (!match || match[1] === undefined) throw malformed('startxref is not followed by an offset and %%EOF at the end of the file');
    return Number(match[1]);
  }

  // --- cross-reference data ---------------------------------------------------------------

  /** Merge one section's entry; newer sections are read first, so the first entry wins. */
  addEntry(num: number, entry: XrefEntry): void {
    if (this.entries.has(num)) return;
    if (this.entries.size >= this.limits.maxObjects) throw limitExceeded('object-count');
    this.entries.set(num, entry);
  }

  /** Record an entry within one section (the first occurrence in the section wins). */
  addLocal(section: Map<number, XrefEntry>, num: number, entry: XrefEntry): void {
    if (section.has(num)) return;
    if (section.size >= this.limits.maxObjects) throw limitExceeded('object-count');
    section.set(num, entry);
  }

  readChain(): void {
    let offset: number | null = this.startxref;
    const seen = new Set<number>();
    while (offset !== null) {
      if (seen.has(offset)) throw malformed('cross-reference /Prev chain revisits a section');
      if (seen.size >= this.limits.maxXrefSections) throw limitExceeded('xref-sections');
      seen.add(offset);
      if (offset >= this.bytes.length) throw malformed(`cross-reference offset ${offset} is beyond the end of the file`);
      const isTable = this.lexer(offset).atKeyword('xref');
      let trailer: PdfDict;
      let section: Map<number, XrefEntry>;
      if (isTable) {
        ({ trailer, section } = this.readXrefTable(offset));
        const stm = trailer.map.get('XRefStm');
        if (stm !== undefined) {
          // Hybrid file: within this section an in-use table entry wins, then the
          // /XRefStm entry, then a free table entry (compressed objects are free there).
          if (!isNonNegativeInteger(stm) || stm >= this.bytes.length) throw malformed('/XRefStm is not an offset in the file');
          this.hybrid = true;
          for (const [num, entry] of this.readXrefStream(stm).section) {
            const own = section.get(num);
            if (own === undefined || own.type === 0) section.set(num, entry);
          }
        }
      } else {
        ({ trailer, section } = this.readXrefStream(offset));
        this.features.add('xref-stream');
      }
      for (const [num, entry] of section) this.addEntry(num, entry);
      this.sections += 1;
      if (this.trailer === null) {
        this.trailer = trailer;
        this.kind = isTable ? 'table' : 'stream';
      }
      const prev = trailer.map.get('Prev');
      if (prev === undefined) offset = null;
      else if (isNonNegativeInteger(prev)) offset = prev;
      else throw malformed('/Prev is not an offset');
    }
  }

  readXrefTable(offset: number): { trailer: PdfDict; section: Map<number, XrefEntry> } {
    const section = new Map<number, XrefEntry>();
    const lx = this.lexer(offset + 'xref'.length);
    for (;;) {
      lx.skipWhitespace();
      if (lx.atKeyword('trailer')) break;
      const start = lx.readUnsigned();
      lx.skipWhitespace();
      const count = lx.readUnsigned();
      if (start === null || count === null) throw malformed(`invalid cross-reference subsection header at byte ${lx.pos}`);
      for (let i = 0; i < count; i += 1) {
        lx.skipWhitespace();
        const entryOffset = lx.readUnsigned();
        lx.skipWhitespace();
        const gen = lx.readUnsigned();
        lx.skipWhitespace();
        const kind = lx.readKeyword();
        if (entryOffset === null || gen === null || gen > 65535 || (kind !== 'n' && kind !== 'f')) {
          throw malformed(`invalid cross-reference entry at byte ${lx.pos}`);
        }
        this.addLocal(section, start + i, kind === 'n' ? { type: 1, offset: entryOffset, gen } : { type: 0 });
      }
    }
    lx.pos += 'trailer'.length;
    const trailer = lx.readValue(0);
    this.track(lx);
    if (!isDict(trailer)) throw malformed('trailer is not a dictionary');
    return { trailer, section };
  }

  readXrefStream(offset: number): { trailer: PdfDict; section: Map<number, XrefEntry> } {
    const section = new Map<number, XrefEntry>();
    const obj = this.readIndirect(offset, null, true);
    if (obj.stream === null || !isDict(obj.value) || nameOf(obj.value, 'Type') !== 'XRef') {
      throw malformed(`offset ${offset} does not hold a cross-reference table or stream`);
    }
    const dict = obj.value;
    const data = decodeStructuralStream(dict, this.bytes.subarray(obj.stream.start, obj.stream.start + obj.stream.length), this.budget);
    const widths = dict.map.get('W');
    if (!Array.isArray(widths) || widths.length !== 3 || !widths.every((w) => isNonNegativeInteger(w) && w <= 6)) {
      throw malformed('cross-reference stream /W is not three widths of at most 6 bytes');
    }
    const [w0, w1, w2] = widths as [number, number, number];
    const rowLength = w0 + w1 + w2;
    if (rowLength === 0) throw malformed('cross-reference stream /W is all zero');
    const size = dict.map.get('Size');
    if (!isNonNegativeInteger(size)) throw malformed('cross-reference stream has no valid /Size');
    const index = dict.map.get('Index') ?? [0, size];
    if (!Array.isArray(index) || index.length % 2 !== 0 || !index.every((v) => isNonNegativeInteger(v))) {
      throw malformed('cross-reference stream /Index is not pairs of integers');
    }
    let rows = 0;
    for (let i = 1; i < index.length; i += 2) rows += index[i] as number;
    if (rows * rowLength !== data.length) throw malformed('cross-reference stream data length does not match /W and /Index');
    const field = (at: number, width: number): number => {
      let value = 0;
      for (let i = 0; i < width; i += 1) value = value * 256 + (data[at + i] ?? 0);
      return value;
    };
    let row = 0;
    for (let i = 0; i < index.length; i += 2) {
      const first = index[i] as number;
      const count = index[i + 1] as number;
      for (let k = 0; k < count; k += 1, row += 1) {
        const at = row * rowLength;
        const type = w0 === 0 ? 1 : field(at, w0);
        const f1 = field(at + w0, w1);
        const f2 = field(at + w0 + w1, w2);
        if (type === 1) {
          // Generation numbers are at most 65535 (as in classic tables); the parent relies on it.
          if (f2 > 65535) throw malformed(`cross-reference stream entry for object ${first + k} has a generation above 65535`);
          this.addLocal(section, first + k, { type: 1, offset: f1, gen: f2 });
        } else if (type === 2) {
          this.addLocal(section, first + k, { type: 2, stream: f1, index: f2 });
        } else {
          this.addLocal(section, first + k, { type: 0 });
        }
      }
    }
    return { trailer: dict, section };
  }

  // --- objects ----------------------------------------------------------------------------

  readIndirect(offset: number, expected: { num: number; gen: number } | null, directLengthOnly = false): ParsedObject {
    const lx = this.lexer(offset);
    lx.skipWhitespace();
    const num = lx.readUnsigned();
    lx.skipWhitespace();
    const gen = lx.readUnsigned();
    lx.skipWhitespace();
    if (num === null || gen === null || !lx.atKeyword('obj')) {
      throw malformed(expected ? `cross-reference entry for object ${expected.num} does not point at its object` : `no indirect object at byte ${offset}`);
    }
    if (expected && (num !== expected.num || gen !== expected.gen)) {
      throw malformed(`cross-reference entry for object ${expected.num} points at a different object`);
    }
    lx.pos += 3;
    const value = lx.readValue(0);
    lx.skipWhitespace();
    let stream: ParsedObject['stream'] = null;
    if (lx.atKeyword('stream')) {
      if (!isDict(value)) throw malformed(`stream keyword after a non-dictionary in object ${num}`);
      lx.pos += 'stream'.length;
      if (lx.byteAt(lx.pos) === 0x0d && lx.byteAt(lx.pos + 1) === 0x0a) lx.pos += 2;
      else if (lx.byteAt(lx.pos) === 0x0a) lx.pos += 1;
      else throw malformed(`stream keyword of object ${num} is not followed by an end-of-line`);
      const length = this.streamLength(value, num, directLengthOnly);
      const start = lx.pos;
      if (start + length > this.bytes.length) throw malformed(`stream of object ${num} runs past the end of the file`);
      lx.pos = start + length;
      lx.skipWhitespace();
      if (!lx.atKeyword('endstream')) throw malformed(`stream /Length of object ${num} does not end at endstream`);
      lx.pos += 'endstream'.length;
      lx.skipWhitespace();
      stream = { start, length };
    }
    if (!lx.atKeyword('endobj')) throw malformed(`object ${num} is not terminated by endobj`);
    this.track(lx);
    return { num, gen, value, stream };
  }

  streamLength(dict: PdfDict, num: number, directOnly: boolean): number {
    const length = dict.map.get('Length');
    if (isNonNegativeInteger(length)) return length;
    if (isRef(length) && !directOnly) {
      const entry = this.entries.get(length.num);
      if (entry === undefined || entry.type !== 1 || length.num === num) {
        throw malformed(`indirect /Length of object ${num} does not name an uncompressed object`);
      }
      const target = this.readIndirect(entry.offset, { num: length.num, gen: entry.gen }, true);
      if (target.stream !== null || !isNonNegativeInteger(target.value)) throw malformed(`indirect /Length of object ${num} is not an integer`);
      return target.value;
    }
    throw malformed(`stream of object ${num} has no valid /Length`);
  }

  parseObjects(): void {
    for (const [num, entry] of this.entries) {
      if (entry.type !== 1) continue;
      if (num === 0) throw malformed('object 0 is marked in use');
      this.objects.set(num, this.readIndirect(entry.offset, { num, gen: entry.gen }));
    }
    for (const [num, entry] of this.entries) {
      if (entry.type !== 2) continue;
      this.objects.set(num, { num, gen: 0, value: this.readCompressed(num, entry), stream: null });
    }
  }

  loadObjectStream(streamNum: number): ObjectStream {
    const cached = this.objectStreams.get(streamNum);
    if (cached !== undefined) return cached;
    const container = this.objects.get(streamNum);
    if (container === undefined || container.stream === null || !isDict(container.value)) {
      throw malformed(`object stream ${streamNum} is not an uncompressed stream object`);
    }
    const dict = container.value;
    if (nameOf(dict, 'Type') !== 'ObjStm') throw malformed(`object ${streamNum} is not a /Type /ObjStm stream`);
    const n = dict.map.get('N');
    const first = dict.map.get('First');
    if (!isNonNegativeInteger(n) || !isNonNegativeInteger(first) || n > this.limits.maxObjects) {
      throw malformed(`object stream ${streamNum} has no valid /N and /First`);
    }
    const raw = this.bytes.subarray(container.stream.start, container.stream.start + container.stream.length);
    const data = decodeStructuralStream(dict, raw, this.budget);
    if (first > data.length) throw malformed(`object stream ${streamNum} /First is beyond its data`);
    const lx = this.lexer(0, data, first);
    const nums: number[] = [];
    const offsets: number[] = [];
    for (let i = 0; i < n; i += 1) {
      lx.skipWhitespace();
      const num = lx.readUnsigned();
      lx.skipWhitespace();
      const offset = lx.readUnsigned();
      if (num === null || offset === null || first + offset >= data.length) throw malformed(`invalid header in object stream ${streamNum}`);
      nums.push(num);
      offsets.push(offset);
    }
    const stream = { data, first, nums, offsets };
    this.objectStreams.set(streamNum, stream);
    return stream;
  }

  readCompressed(num: number, entry: { stream: number; index: number }): PdfValue {
    if (this.entries.get(entry.stream)?.type !== 1) throw malformed(`object ${num} names object stream ${entry.stream}, which is not uncompressed`);
    const stream = this.loadObjectStream(entry.stream);
    if (entry.index >= stream.nums.length || stream.nums[entry.index] !== num) {
      throw malformed(`object stream ${entry.stream} does not hold object ${num} at index ${entry.index}`);
    }
    const start = stream.first + (stream.offsets[entry.index] ?? 0);
    const nextOffset = stream.offsets[entry.index + 1];
    const next = nextOffset === undefined ? stream.data.length : stream.first + nextOffset;
    const lx = this.lexer(start, stream.data, next > start ? next : stream.data.length);
    const value = lx.readValue(0);
    this.track(lx);
    lx.skipWhitespace();
    if (lx.atKeyword('stream')) throw malformed(`object stream ${entry.stream} holds a stream object`);
    return value;
  }

  resolve(value: PdfValue | undefined): PdfValue | undefined {
    if (!isRef(value)) return value;
    const obj = this.objects.get(value.num);
    if (obj === undefined || obj.gen !== value.gen) throw malformed(`reference to missing object ${value.num}`);
    if (obj.stream !== null) throw malformed(`object ${value.num} is a stream where a direct value is required`);
    return obj.value;
  }

  dictObject(ref: PdfRef): PdfDict {
    const value = this.resolve(ref);
    if (!isDict(value)) throw malformed(`object ${ref.num} is not a dictionary`);
    return value;
  }

  // --- detections -------------------------------------------------------------------------

  scanFilters(dict: PdfDict): void {
    for (const filter of streamFilterNames(dict)) {
      if (filter === 'JBIG2Decode') this.features.add('jbig2');
      if (filter === 'JPXDecode') this.features.add('jpx');
    }
  }

  // --- page tree --------------------------------------------------------------------------

  box(dict: PdfDict, key: string): number[] | null {
    const value = this.resolve(dict.map.get(key));
    if (value === undefined) return null;
    if (!Array.isArray(value) || value.length !== 4 || !value.every((n) => typeof n === 'number')) {
      throw malformed(`/${key} is not an array of four numbers`);
    }
    const [a, b, c, d] = value as [number, number, number, number];
    const box = [Math.min(a, c), Math.min(b, d), Math.max(a, c), Math.max(b, d)] as [number, number, number, number];
    if (box[2] - box[0] <= 0 || box[3] - box[1] <= 0) throw malformed(`/${key} has no area`);
    return box;
  }

  rotate(dict: PdfDict): number | null {
    const value = this.resolve(dict.map.get('Rotate'));
    if (value === undefined) return null;
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value % 90 !== 0) throw malformed('/Rotate is not a multiple of 90');
    return ((value % 360) + 360) % 360;
  }

  walkPages(catalog: PdfDict): PageReport[] {
    const root = catalog.map.get('Pages');
    if (!isRef(root)) throw malformed('catalog has no /Pages reference');
    const pages: PageReport[] = [];
    const visited = new Set<number>();
    interface Inherited {
      mediaBox: number[] | null;
      cropBox: number[] | null;
      rotate: number;
    }
    const visit = (ref: PdfValue | undefined, inherited: Inherited, depth: number, expectRoot: boolean): void => {
      if (depth > this.limits.maxDepth) throw limitExceeded('page-tree-depth');
      if (!isRef(ref)) throw malformed('page tree node is not an indirect reference');
      if (visited.has(ref.num)) throw malformed(`page tree revisits object ${ref.num}`);
      visited.add(ref.num);
      const dict = this.dictObject(ref);
      const type = nameOf(dict, 'Type');
      const effective: Inherited = {
        mediaBox: this.box(dict, 'MediaBox') ?? inherited.mediaBox,
        cropBox: this.box(dict, 'CropBox') ?? inherited.cropBox,
        rotate: this.rotate(dict) ?? inherited.rotate,
      };
      if (type === 'Pages') {
        const kids = this.resolve(dict.map.get('Kids'));
        if (!Array.isArray(kids)) throw malformed(`page tree node ${ref.num} has no /Kids array`);
        const before = pages.length;
        for (const kid of kids) visit(kid, effective, depth + 1, false);
        const count = this.resolve(dict.map.get('Count'));
        if (!isNonNegativeInteger(count) || count !== pages.length - before) {
          throw malformed(`page tree node ${ref.num} /Count does not match its leaves`);
        }
        return;
      }
      if (type !== 'Page' || expectRoot) throw malformed(`page tree object ${ref.num} has no valid /Type`);
      const media = effective.mediaBox;
      if (media === null) throw malformed(`page object ${ref.num} has no effective /MediaBox`);
      let crop = media;
      if (effective.cropBox !== null) {
        const c = effective.cropBox;
        crop = [Math.max(c[0] ?? 0, media[0] ?? 0), Math.max(c[1] ?? 0, media[1] ?? 0), Math.min(c[2] ?? 0, media[2] ?? 0), Math.min(c[3] ?? 0, media[3] ?? 0)];
        if ((crop[2] ?? 0) - (crop[0] ?? 0) <= 0 || (crop[3] ?? 0) - (crop[1] ?? 0) <= 0) throw malformed(`page object ${ref.num} /CropBox lies outside its /MediaBox`);
        if (!crop.every((value, index) => value === media[index])) throw new ParseFailure('unsupported-feature', 'cropbox_differs');
      }
      const width = (crop[2] ?? 0) - (crop[0] ?? 0);
      const height = (crop[3] ?? 0) - (crop[1] ?? 0);
      const rotate = effective.rotate as 0 | 90 | 180 | 270;
      pages.push({
        number: pages.length + 1,
        width: rotate % 180 === 0 ? width : height,
        height: rotate % 180 === 0 ? height : width,
        rotate,
        media_box: [...media],
        crop_box: [...crop],
        ref: [ref.num, ref.gen],
      });
      if (pages.length > this.limits.maxPages) throw new ParseFailure('page-limit', `more than ${this.limits.maxPages} pages`);
    };
    visit(root, { mediaBox: null, cropBox: null, rotate: 0 }, 0, true);
    if (pages.length === 0) throw malformed('the page tree has no pages');
    return pages;
  }
}

/** Parse `bytes` under `limits`. Never throws for document content. */
export function parseDocument(bytes: Uint8Array, limits: ParserLimits): ParseResult {
  if (bytes.length > limits.maxBytes) {
    return { ok: false, reason: 'size-limit', detail: `more than ${limits.maxBytes} bytes`, detections: [] };
  }
  try {
    return { ok: true, report: new DocumentParser(bytes, limits).run() };
  } catch (error) {
    if (error instanceof ParseFailure) return { ok: false, reason: error.reason, detail: error.detail, detections: [...error.detections] };
    return { ok: false, reason: 'malformed', detail: 'unexpected structure (parser exception)', detections: [] };
  }
}

