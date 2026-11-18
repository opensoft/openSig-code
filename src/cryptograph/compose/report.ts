// SPDX-License-Identifier: Apache-2.0
//
// The composer's own checks of the parse report (T036; A-009 LBR-4, CP-08; A-008
// S2, CP-07). The parse service's parent already validates the child's report
// (src/pdf/service.ts validateChildResult), but the composer still treats the
// report, and above all its `objects`, `trailer` and page references, as
// untrusted input: it re-checks every member it uses, against the document bytes
// wherever the bytes can answer.
//
// - `bytes` equals the document length and `digest` equals its SHA-256;
// - the document's own tail names `startxref`, and the bytes at that offset begin
//   a section of the reported kind (`xref` for a table, `n g obj` for a stream);
// - `size` leaves room for the appended objects below the PDF object-number limit;
// - the root, every page reference and every reported object number lie below
//   `size`, with matching generations, and the catalog and pages are dictionaries
//   of the right /Type;
// - page geometry is consistent with its rotation, and an effective CropBox that
//   differs from the MediaBox is refused with 422 cropbox_differs (CP-07);
// - every reported value is shape-checked within the parser's depth limit and the
//   report node budget (syntax.ts serializeValue).
//
// A failure is 500 report-invalid (or 422 cropbox_differs), never a repaired guess.

import { createHash } from 'node:crypto';

import { DEFAULT_PARSER_LIMITS, MAX_DOCUMENT_BYTES, MAX_DOCUMENT_PAGES, reportBudget } from '../../pdf/limits.ts';
import { cropboxDiffers, reportInvalid } from './errors.ts';
import { dictEntries, entryOf, isRefPair, nameValue, serializeValue, type Ref, type ValueBudget } from './syntax.ts';

/** The largest indirect object number (ISO 32000-1:2008, Annex C, Table C.1). */
export const MAX_OBJECT_NUMBER = 8_388_607;
/** The largest coordinate magnitude accepted in a page box, in points. */
export const MAX_BOX_COORDINATE = 1_000_000;

export interface CheckedPage {
  readonly number: number;
  readonly rotate: 0 | 90 | 180 | 270;
  /** The MediaBox in centipoints (1/100 point), [llx, lly, urx, ury]. */
  readonly box: readonly [number, number, number, number];
  readonly ref: Ref;
}

export interface CheckedObject {
  readonly gen: number;
  readonly value: unknown;
}

export interface CheckedReport {
  readonly kind: 'table' | 'stream';
  readonly hybrid: boolean;
  readonly startxref: number;
  readonly size: number;
  readonly root: Ref;
  readonly info: Ref | null;
  readonly id: readonly [string, string] | null;
  readonly pages: readonly CheckedPage[];
  readonly objects: ReadonlyMap<number, CheckedObject>;
  /** The node budget left after checking every reported value, shared with the rewrites. */
  readonly budget: ValueBudget;
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const isCount = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const isRotate = (value: unknown): value is 0 | 90 | 180 | 270 => value === 0 || value === 90 || value === 180 || value === 270;
const isKind = (value: unknown): value is 'table' | 'stream' => value === 'table' || value === 'stream';
const isHexPart = (value: unknown): value is string => typeof value === 'string' && value.length % 2 === 0 && /^[0-9a-f]*$/.test(value);

const TAIL = /^startxref[\x00\t\n\f\r ]+(\d{1,15})[\x00\t\n\f\r ]+%%EOF[\x00\t\n\f\r ]*$/;

/** The offset the document's own tail names after its last `startxref`, or null. */
export function tailStartxref(document: Uint8Array): number | null {
  const from = Math.max(0, document.length - 1024);
  const tail = Buffer.from(document.buffer, document.byteOffset + from, document.length - from).toString('latin1');
  const at = tail.lastIndexOf('startxref');
  if (at < 0) return null;
  const match = TAIL.exec(tail.slice(at));
  return match === null || match[1] === undefined ? null : Number(match[1]);
}

/** True when the bytes at `offset` begin a section of `kind`. */
export function sectionStartsAt(document: Uint8Array, offset: number, kind: 'table' | 'stream'): boolean {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= document.length) return false;
  const head = Buffer.from(document.buffer, document.byteOffset + offset, Math.min(64, document.length - offset)).toString('latin1');
  if (kind === 'table') return /^xref[\x00\t\n\f\r ]/.test(head);
  return /^[1-9]\d{0,9}[\x00\t\n\f\r ]+\d{1,5}[\x00\t\n\f\r ]+obj[\x00\t\n\f\r <]/.test(head);
}

function checkBox(value: unknown): [number, number, number, number] | null {
  if (!Array.isArray(value) || value.length !== 4) return null;
  const numbers: number[] = [];
  for (const item of value) {
    if (typeof item !== 'number' || !Number.isFinite(item) || Math.abs(item) > MAX_BOX_COORDINATE) return null;
    numbers.push(item);
  }
  const [llx, lly, urx, ury] = numbers as [number, number, number, number];
  return urx > llx && ury > lly ? [llx, lly, urx, ury] : null;
}

const centi = (value: number): number => Math.round(value * 100);

function checkPage(value: unknown, index: number, size: number): CheckedPage {
  if (!isRecord(value)) throw reportInvalid('page-shape');
  const { number, width, height, rotate, media_box: mediaValue, crop_box: cropValue, ref } = value;
  if (number !== index + 1) throw reportInvalid('page-number');
  if (!isRotate(rotate)) throw reportInvalid('page-rotate');
  const media = checkBox(mediaValue);
  const crop = checkBox(cropValue);
  if (media === null || crop === null) throw reportInvalid('page-box');
  // CP-07 (A-008 S2): field rectangles are normalized to the displayed page, so a
  // cropped page would mis-map them. T033 refuses it at upload; refuse it here too.
  if (!media.every((coordinate, at) => coordinate === crop[at])) throw cropboxDiffers(index + 1);
  const boxWidth = media[2] - media[0];
  const boxHeight = media[3] - media[1];
  const [shownWidth, shownHeight] = rotate % 180 === 0 ? [boxWidth, boxHeight] : [boxHeight, boxWidth];
  if (width !== shownWidth || height !== shownHeight) throw reportInvalid('page-geometry');
  if (!isRefPair(ref) || ref[0] >= size) throw reportInvalid('page-ref');
  const box: [number, number, number, number] = [centi(media[0]), centi(media[1]), centi(media[2]), centi(media[3])];
  if (box[2] - box[0] < 1 || box[3] - box[1] < 1) throw reportInvalid('page-box');
  return Object.freeze({ number: index + 1, rotate, box: Object.freeze(box), ref: Object.freeze([ref[0], ref[1]] as const) });
}

/** The dictionary entries of reported object `ref` if it has /Type `type`, else a refusal. */
export function typedDict(objects: ReadonlyMap<number, CheckedObject>, ref: Ref, type: string, what: string): Array<[string, unknown]> {
  const found = objects.get(ref[0]);
  if (found === undefined || found.gen !== ref[1]) throw reportInvalid(`${what}-missing`);
  const entries = dictEntries(found.value);
  if (entries === null || nameValue(entryOf(entries, 'Type')) !== type) throw reportInvalid(`${what}-type`);
  return entries;
}

/**
 * Check `report` (a ServiceReport from parsePdf) against `document`, whose SHA-256 is
 * `documentDigest`, and return the members the composer uses.
 */
export function checkReport(document: Uint8Array, documentDigest: string, report: unknown): CheckedReport {
  if (!isRecord(report) || report['schema'] !== 'opensig.pdf.parse-report.v1') throw reportInvalid('schema');
  if (document.length > MAX_DOCUMENT_BYTES || report['bytes'] !== document.length) throw reportInvalid('bytes');
  if (report['digest'] !== documentDigest || documentDigest !== createHash('sha256').update(document).digest('hex')) throw reportInvalid('digest');

  const xref = report['xref'];
  if (!isRecord(xref)) throw reportInvalid('xref-shape');
  const { kind, sections, startxref, size, hybrid } = xref;
  if (!isKind(kind) || !isCount(sections) || sections < 1 || typeof hybrid !== 'boolean') throw reportInvalid('xref-shape');
  if (!isCount(size) || size < 2 || size > MAX_OBJECT_NUMBER + 1) throw reportInvalid('xref-size');
  if (!isCount(startxref) || startxref >= document.length) throw reportInvalid('xref-startxref');
  // The bytes, not the report, say where the last section is and what kind it is.
  if (tailStartxref(document) !== startxref) throw reportInvalid('xref-startxref');
  if (!sectionStartsAt(document, startxref, kind)) throw reportInvalid('xref-kind');

  const trailer = report['trailer'];
  if (!isRecord(trailer)) throw reportInvalid('trailer-shape');
  const { root, info, id } = trailer;
  if (!isRefPair(root) || root[0] >= size) throw reportInvalid('trailer-root');
  let checkedInfo: Ref | null = null;
  if (info !== null) {
    // Any object number: a reference outside the file is legal and means null. It is copied as is.
    if (!isRefPair(info)) throw reportInvalid('trailer-info');
    checkedInfo = Object.freeze([info[0], info[1]] as const);
  }
  let checkedId: readonly [string, string] | null = null;
  if (id !== null) {
    if (!Array.isArray(id) || id.length !== 2) throw reportInvalid('trailer-id');
    const first: unknown = id[0];
    const second: unknown = id[1];
    if (!isHexPart(first) || !isHexPart(second)) throw reportInvalid('trailer-id');
    checkedId = Object.freeze([first, second] as const);
  }

  const pagesValue = report['pages'];
  if (!Array.isArray(pagesValue) || pagesValue.length < 1 || pagesValue.length > MAX_DOCUMENT_PAGES) throw reportInvalid('pages');
  const pages = pagesValue.map((page: unknown, index: number) => checkPage(page, index, size));
  if (new Set(pages.map((page) => page.ref[0])).size !== pages.length) throw reportInvalid('page-ref-duplicate');

  const objectsValue = report['objects'];
  if (!isRecord(objectsValue)) throw reportInvalid('objects-shape');
  const keys = Object.keys(objectsValue);
  if (keys.length > 3 + 2 * pages.length) throw reportInvalid('objects-count');
  const budget: ValueBudget = { nodes: reportBudget(DEFAULT_PARSER_LIMITS).nodes, maxDepth: DEFAULT_PARSER_LIMITS.maxDepth };
  const objects = new Map<number, CheckedObject>();
  for (const key of keys) {
    if (!/^[1-9]\d{0,9}$/.test(key) || Number(key) >= size) throw reportInvalid('object-number');
    const entry = objectsValue[key];
    if (!isRecord(entry) || Object.keys(entry).length !== 2 || !Object.hasOwn(entry, 'gen') || !Object.hasOwn(entry, 'value')) throw reportInvalid('object-shape');
    const gen = entry['gen'];
    if (!isCount(gen) || gen > 65535) throw reportInvalid('object-shape');
    const value: unknown = entry['value'];
    // Shape, depth and node budget of the whole value, before anything reads it.
    serializeValue(value, budget);
    objects.set(Number(key), Object.freeze({ gen, value }));
  }

  typedDict(objects, root, 'Catalog', 'catalog');
  for (const page of pages) typedDict(objects, page.ref, 'Page', 'page');

  return Object.freeze({
    kind,
    hybrid,
    startxref,
    size,
    root: Object.freeze([root[0], root[1]] as const),
    info: checkedInfo,
    id: checkedId,
    pages: Object.freeze(pages),
    objects,
    budget,
  });
}
