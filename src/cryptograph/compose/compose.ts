// SPDX-License-Identifier: Apache-2.0
//
// The incremental-update composer (T036). It appends one revision to the frozen
// document: an appearance stream and a widget annotation for every approved field
// value, one AcroForm signature field whose widgets they are, and the /Sig
// dictionary with fixed-size /ByteRange and /Contents placeholders. The base
// bytes are never changed: the output is the base followed by the update.
//
// Layout of the update, in this order of object numbers from the base's /Size:
//   the shared Helvetica font (only when a typed or date value exists); then, for
//   every field in field-manifest order, its appearance stream and its widget;
//   then the signature field, the /Sig dictionary, a new AcroForm (only when the
//   base has none) and, after a stream base, the cross-reference stream itself.
// Rewritten base objects keep their number and generation: the catalog (when it
// gains /AcroForm or holds the AcroForm inline), the AcroForm (when indirect;
// /Fields gains the seal field, /SigFlags is combined with 3, SignaturesExist and
// AppendOnly), and every page that receives a widget (/Annots gains it). An
// indirect /Fields or /Annots array is copied inline into the rewritten
// dictionary, so an array shared elsewhere is never changed. Existing fields,
// unsigned signature fields and /NeedAppearances are left as they are. A form
// reference that resolves to nothing is refused (422 dangling_form_reference); a
// page /Annots that is not an array (422 annots_shape); an AcroForm that is not a
// dictionary, whose /Fields is not an array, or that is a page receiving a widget
// (422 acroform_shape). Objects are written in ascending number.
//
// The seal field (request #43): /FT /Sig, partial name `opensig-seal-` and the first
// 16 hex digits of the document digest, one widget kid per manifest field in
// manifest order, each widget /F 132 (Print and Locked). A date widget shows the
// date only, and its /Contents reads "Date from unsigned server time (UTC)".
//
// The /Sig dictionary (research.md, Engine decision): /Type /Sig, /Filter
// /Adobe.PPKLite, /SubFilter /ETSI.CAdES.detached, /ByteRange, /Contents, /M and
// /Reason. /M is the caller's `sealTime` (T038 passes the time of the
// envelope.seal_started event); the composer reads no clock. /Reason reads
// "Organization seal. The signing time is unsigned server time, not a trusted
// timestamp." (data-model.md, Global rules; spec.md FR-006). /Contents
// is a hex string of exactly 2 x signedDataLength(certificate) zero digits, with
// no padding (request #39, Part F). /ByteRange is a fixed-width slot that the
// composer fills itself once every offset is known, so the composed bytes are
// final except for the /Contents digits: their SHA-256 is the approval manifest's
// approved_composition_digest, and the sealing worker (T037) only overwrites the
// digits.
//
// Determinism (CP-06): no clock, no randomness, no locale; numbers are integers in
// fixed units written by syntax.ts decimal; dictionaries keep the report's key
// order or a fixed order; values are placed in field-manifest order whatever their
// order in the approvals. The trailer /ID keeps the base's first identifier and
// takes as its second the first 16 bytes of SHA-256 over the base and the
// appended objects (with the /ByteRange slot unfilled); a base without /ID gets
// that value twice.
//
// Worst-case update size (request #43: no output cap; the budgets bound it).
// - From the request: at most UPDATE_REQUEST_BOUND = 1,100,000 bytes. Page boxes are
//   within +-1,000,000 points, so a stroke operand has at most 14 characters and a
//   point line (`x y l`) at most 32 bytes: 2 approvals x 15,000 points = 960,000.
//   Then 1,000 strokes (20 values x 50) at 2 bytes; 20 appearance streams at most
//   600 bytes each beyond their points (a typed line is at most 160 hex digits);
//   20 widgets at most 400; the font, the field and a new AcroForm at most 600;
//   the /Sig dictionary at most 300 plus 2 x signedDataLength for a 16 KiB
//   certificate (at most 2 x (2 x 16,384 + 1,024) = 67,584 digits); the
//   cross-reference section at most 2,700 beyond the copied first /ID. That is
//   at most 1,053,184 bytes.
// - From the base: the rewritten objects (the catalog, the AcroForm and at most 20
//   pages) and the copied first /ID. A rewritten value is at most three times its
//   JSON size in the parse report (syntax.ts), whose byte budget is 1,376,256 for
//   the 10 MiB input cap; the objects themselves add at most one report, the
//   inline copies of /Fields and /Annots arrays at most 21 more (one per rewritten
//   dictionary), each at most 3 x 1,376,256, and the /ID at most one report: so at
//   most 65 x 1,376,256 + 22 x 400 = 89,465,440 bytes.
// - In all, at most UPDATE_BOUND = 90,565,440 bytes. A real base adds only its own
//   catalog, form and pages, so a maximal request on a small base stays near the
//   request bound (CP-01).
// Both constants live in bounds.ts with MAX_SEALED_PDF_BYTES (48 MiB) and the upload
// predicate (request #44). The composer refuses a composition above the bound as an
// invariant (422 unsupported_pdf, detail composition_too_large, not retryable),
// stopping as soon as the objects it writes cross it; an uploaded document cannot
// reach it once T034 applies the predicate. Numbers are checked only in the objects
// the composer rewrites (detail number_range, not retryable); the base bytes are
// never re-read, so a number anywhere else never matters. The eight report-only
// refusals (composition_too_large, number_range, dangling_form_reference,
// annots_shape, acroform_shape, xref_size, page_box, name_character) are the ones the
// predicate reports for T034 (requests #45 and #46); after upload each is a broken
// invariant, 422 unsupported_pdf, not retryable. Every field is placed with
// appearance.ts placeField(), the rule index.ts exports for T007's prepare check.
// Rewrites count depth but no nodes: the report's node budget and the size bound
// already bound them, and a composition-time node limit could strand a document.

import { createHash } from 'node:crypto';

import { CertificateError, signedDataLength } from '../cms/index.ts';
import {
  DIGEST_PATTERN,
  FIELD_KEY_PATTERN,
  MAX_COORDINATE,
  MAX_FIELD_VALUES,
  MAX_POINTS_PER_APPROVAL,
  MAX_POINTS_PER_STROKE,
  MAX_POINTS_PER_VALUE,
  MAX_STROKES_PER_VALUE,
  MAX_TYPED_TEXT_LENGTH,
  MIN_POINTS_PER_STROKE,
} from '../../domain/approval/values.ts';
import { MAX_DOCUMENT_BYTES, MAX_DOCUMENT_PAGES } from '../../pdf/limits.ts';
import {
  centipointArray,
  checkRect,
  drawnAppearance,
  encodeWinAnsi,
  matrixArray,
  placeField,
  STROKE_SCALE,
  TEXT_FONT_DICT,
  TEXT_FONT_RESOURCE,
  textAppearance,
  type NormalizedRect,
  type Placement,
  type StrokePoint,
} from './appearance.ts';
import { withinSealedBound } from './bounds.ts';
import {
  acroformShape,
  annotsShape,
  certificateInvalid,
  compositionTooLarge,
  danglingReference,
  documentDigestMismatch,
  inputInvalid,
  reportInvalid,
  unsupportedCharacters,
  xrefSize,
} from './errors.ts';
import { checkReport, MAX_OBJECT_NUMBER, typedDict, type CheckedObject, type CheckedPage } from './report.ts';
import { dictEntries, entryOf, isCalendarDate, pdfAsciiString, pdfDate, pdfRef, refValue, rewriteDict, serializeValue, type Ref, type ValueBudget } from './syntax.ts';
import { classicSection, streamSection, type XrefEntry } from './xref.ts';

if (MAX_COORDINATE !== STROKE_SCALE) throw new Error('the stroke scale must equal the contract coordinate range');

/** The seal field's partial name is this prefix and the first 16 hex digits of the document digest. */
export const SEAL_FIELD_PREFIX = 'opensig-seal-';
/** The /Reason text, exactly (request #43). */
export const SEAL_REASON = 'Organization seal. The signing time is unsigned server time, not a trusted timestamp.';
/** A date widget's annotation /Contents text, exactly (request #43). */
export const DATE_WIDGET_CONTENTS = 'Date from unsigned server time (UTC)';

/** The seal field's partial name for a document whose SHA-256 is `documentDigest`. */
export function sealFieldName(documentDigest: string): string {
  return `${SEAL_FIELD_PREFIX}${documentDigest.slice(0, 16)}`;
}
/** Widget annotation flags: Print (4) and Locked (128). */
export const WIDGET_FLAGS = 132;
/** AcroForm /SigFlags bits: SignaturesExist (1) and AppendOnly (2). */
export const SIG_FLAGS = 3;
/** Width of the /ByteRange slot, brackets included: `[0` and three ten-digit numbers. */
export const BYTE_RANGE_WIDTH = 36;

// --- the request -------------------------------------------------------------------------------

/** A contract FieldManifest member, as frozen at prepare. */
export interface FieldInput {
  readonly key: string;
  readonly recipient_id: string;
  readonly recipient_ordinal: number;
  readonly page: number;
  readonly type: 'signature' | 'date';
  readonly rect: { readonly x: number; readonly y: number; readonly width: number; readonly height: number };
}

/** The contract FieldManifest. */
export interface FieldManifestInput {
  readonly schema: 'opensig.field-manifest/1';
  readonly envelope_id: string;
  readonly document_digest: string;
  readonly fields: readonly FieldInput[];
}

/** A contract FieldValue. */
export type FieldValueInput =
  | { readonly key: string; readonly type: 'signature'; readonly mode: 'drawn'; readonly strokes: ReadonlyArray<ReadonlyArray<readonly [number, number]>> }
  | { readonly key: string; readonly type: 'signature'; readonly mode: 'typed'; readonly text: string }
  | { readonly key: string; readonly type: 'date' };

/** The members of a contract ApprovalRecord that the composer reads; other members are ignored. */
export interface ApprovalInput {
  readonly recipient: { readonly id: string };
  readonly field_values: readonly FieldValueInput[];
  readonly date_values: ReadonlyArray<{ readonly key: string; readonly value: string }>;
}

export interface ComposeRequest {
  /** The frozen document bytes (the DocumentRevision blob). */
  readonly document: Uint8Array;
  /** The frozen field manifest. */
  readonly fieldManifest: FieldManifestInput;
  /** The approvals, in ordinal order. */
  readonly approvals: readonly ApprovalInput[];
  /** The unsigned server time written to /M, in UTC ISO 8601 form (`YYYY-MM-DDTHH:mm:ss[.sss]Z`). */
  readonly sealTime: string;
  /** The configured seal certificate (DER); it sizes the /Contents placeholder. */
  readonly certificateDer: Uint8Array;
}

const REQUEST_MEMBERS = ['approvals', 'certificateDer', 'document', 'fieldManifest', 'sealTime'];
const RECIPIENT_ID = /^[A-Za-z0-9_-]{16,64}$/;

type CheckedValue = { readonly kind: 'drawn'; readonly strokes: StrokePoint[][] } | { readonly kind: 'text'; readonly bytes: Uint8Array };

interface CheckedField {
  readonly key: string;
  readonly at: string;
  readonly recipientId: string;
  readonly page: number;
  readonly type: 'signature' | 'date';
  readonly rect: NormalizedRect;
}

export interface CheckedRequest {
  readonly document: Uint8Array;
  readonly documentDigest: string;
  readonly fields: readonly CheckedField[];
  readonly values: ReadonlyMap<string, CheckedValue>;
  /** The first typed value outside WinAnsiEncoding, refused with 422 after every 400 rule. */
  readonly unsupported: string | null;
  readonly sealDate: string;
  readonly signedDataLength: number;
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const isCoordinate = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_COORDINATE;
const isFieldType = (value: unknown): value is 'signature' | 'date' => value === 'signature' || value === 'date';

function checkFields(manifest: unknown): CheckedField[] {
  if (!isRecord(manifest) || manifest['schema'] !== 'opensig.field-manifest/1') throw inputInvalid('fieldManifest', 'invalid_manifest');
  const list = manifest['fields'];
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_FIELD_VALUES) throw inputInvalid('fieldManifest.fields', 'invalid_count');
  const keys = new Set<string>();
  return list.map((entry: unknown, index: number): CheckedField => {
    const at = `fieldManifest.fields[${index}]`;
    if (!isRecord(entry)) throw inputInvalid(at, 'invalid_type');
    const { key, recipient_id: recipientId, page, type } = entry;
    if (typeof key !== 'string' || !FIELD_KEY_PATTERN.test(key)) throw inputInvalid(`${at}.key`, 'invalid_key');
    if (keys.has(key)) throw inputInvalid(`${at}.key`, 'duplicate_key');
    keys.add(key);
    if (typeof recipientId !== 'string' || !RECIPIENT_ID.test(recipientId)) throw inputInvalid(`${at}.recipient_id`, 'invalid_id');
    if (typeof page !== 'number' || !Number.isSafeInteger(page) || page < 1 || page > MAX_DOCUMENT_PAGES) throw inputInvalid(`${at}.page`, 'invalid_page');
    if (!isFieldType(type)) throw inputInvalid(`${at}.type`, 'invalid_enum');
    const rect = checkRect(entry['rect']);
    if (rect === null) throw inputInvalid(`${at}.rect`, 'field_out_of_bounds');
    return Object.freeze({ key, at, recipientId, page, type, rect });
  });
}

function checkStrokes(value: unknown, at: string): { strokes: StrokePoint[][]; points: number } {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_STROKES_PER_VALUE) throw inputInvalid(`${at}.strokes`, 'invalid_count');
  const strokes: StrokePoint[][] = [];
  let points = 0;
  value.forEach((stroke: unknown, s: number) => {
    if (!Array.isArray(stroke) || stroke.length < MIN_POINTS_PER_STROKE || stroke.length > MAX_POINTS_PER_STROKE) throw inputInvalid(`${at}.strokes[${s}]`, 'invalid_count');
    const checked: StrokePoint[] = [];
    stroke.forEach((point: unknown, p: number) => {
      if (!Array.isArray(point) || point.length !== 2) throw inputInvalid(`${at}.strokes[${s}][${p}]`, 'invalid_point');
      const px: unknown = point[0];
      const py: unknown = point[1];
      if (!isCoordinate(px) || !isCoordinate(py)) throw inputInvalid(`${at}.strokes[${s}][${p}]`, 'invalid_coordinate');
      checked.push(Object.freeze([px, py] as const));
    });
    points += checked.length;
    strokes.push(checked);
  });
  if (points > MAX_POINTS_PER_VALUE) throw inputInvalid(`${at}.strokes`, 'point_budget');
  return { strokes, points };
}

/** Each manifest field's value, from the approval of the field's own recipient. */
function checkValues(approvals: unknown, fields: readonly CheckedField[]): { values: Map<string, CheckedValue>; unsupported: string | null } {
  if (!Array.isArray(approvals) || approvals.length < 1 || approvals.length > 2) throw inputInvalid('approvals', 'invalid_count');
  const byKey = new Map(fields.map((field) => [field.key, field] as const));
  const values = new Map<string, CheckedValue>();
  const seen = new Set<string>();
  let unsupported: string | null = null;
  approvals.forEach((approval: unknown, a: number) => {
    const at = `approvals[${a}]`;
    if (!isRecord(approval)) throw inputInvalid(at, 'invalid_type');
    const recipient: unknown = approval['recipient'];
    if (!isRecord(recipient)) throw inputInvalid(`${at}.recipient`, 'invalid_type');
    const recipientId: unknown = recipient['id'];
    if (typeof recipientId !== 'string') throw inputInvalid(`${at}.recipient.id`, 'invalid_id');
    const list = approval['field_values'];
    const dates = approval['date_values'];
    if (!Array.isArray(list) || list.length < 1 || list.length > MAX_FIELD_VALUES) throw inputInvalid(`${at}.field_values`, 'invalid_count');
    if (!Array.isArray(dates) || dates.length > MAX_FIELD_VALUES) throw inputInvalid(`${at}.date_values`, 'invalid_count');
    let points = 0;
    list.forEach((entry: unknown, v: number) => {
      const valueAt = `${at}.field_values[${v}]`;
      if (!isRecord(entry)) throw inputInvalid(valueAt, 'invalid_type');
      const key: unknown = entry['key'];
      if (typeof key !== 'string') throw inputInvalid(`${valueAt}.key`, 'invalid_key');
      const field = byKey.get(key);
      if (field === undefined) throw inputInvalid(`${valueAt}.key`, 'unknown_field');
      if (field.recipientId !== recipientId) throw inputInvalid(`${valueAt}.key`, 'recipient_mismatch');
      if (seen.has(key)) throw inputInvalid(`${valueAt}.key`, 'duplicate_value');
      seen.add(key);
      if (entry['type'] === 'date') {
        if (field.type !== 'date') throw inputInvalid(`${valueAt}.type`, 'type_mismatch');
        const date: unknown = dates.find((item: unknown) => isRecord(item) && item['key'] === key);
        const text = isRecord(date) ? date['value'] : undefined;
        if (typeof text !== 'string' || !isCalendarDate(text)) throw inputInvalid(`${at}.date_values`, 'date_value_missing');
        values.set(key, { kind: 'text', bytes: Buffer.from(text, 'latin1') });
      } else if (entry['type'] === 'signature' && entry['mode'] === 'drawn') {
        if (field.type !== 'signature') throw inputInvalid(`${valueAt}.type`, 'type_mismatch');
        const drawn = checkStrokes(entry['strokes'], valueAt);
        points += drawn.points;
        values.set(key, { kind: 'drawn', strokes: drawn.strokes });
      } else if (entry['type'] === 'signature' && entry['mode'] === 'typed') {
        if (field.type !== 'signature') throw inputInvalid(`${valueAt}.type`, 'type_mismatch');
        const text: unknown = entry['text'];
        if (typeof text !== 'string') throw inputInvalid(`${valueAt}.text`, 'invalid_type');
        const length = [...text].length;
        if (length < 1 || length > MAX_TYPED_TEXT_LENGTH) throw inputInvalid(`${valueAt}.text`, 'invalid_length');
        const bytes = encodeWinAnsi(text);
        if (bytes === null) {
          if (unsupported === null) unsupported = `${valueAt}.text`;
          return;
        }
        values.set(key, { kind: 'text', bytes });
      } else {
        throw inputInvalid(`${valueAt}.type`, 'invalid_enum');
      }
    });
    if (points > MAX_POINTS_PER_APPROVAL) throw inputInvalid(`${at}.field_values`, 'point_budget');
  });
  for (const field of fields) if (!seen.has(field.key)) throw inputInvalid(`${field.at}.key`, 'value_missing');
  // The 422 waits until every 400 rule has been judged, including those that need the
  // parse report (page_out_of_range, field_too_small): composeFromReport throws it (CP-04).
  return { values, unsupported };
}

/**
 * Check a composition request before anything parses: exactly the five members (no
 * option of any kind is accepted, so nothing can reach parsePdf; CP-08), the
 * manifest, every value, the seal time and the certificate. The document is copied,
 * so the bytes parsed and the bytes composed are the same bytes.
 */
export function checkRequest(request: unknown): CheckedRequest {
  if (!isRecord(request)) throw inputInvalid('request', 'invalid_type');
  const members = Object.keys(request).sort();
  if (members.join(',') !== REQUEST_MEMBERS.join(',')) throw inputInvalid('request', 'unknown_member');
  const { document, fieldManifest, approvals, sealTime, certificateDer } = request;
  if (!(document instanceof Uint8Array) || document.length < 1 || document.length > MAX_DOCUMENT_BYTES) throw inputInvalid('document', 'invalid_document');
  const fields = checkFields(fieldManifest);
  const { values, unsupported } = checkValues(approvals, fields);
  // Every remaining 400 rule, then the 500s; the 422 for unsupported characters comes later.
  if (typeof sealTime !== 'string') throw inputInvalid('sealTime', 'invalid_time');
  const sealDate = pdfDate(sealTime);
  if (sealDate === null) throw inputInvalid('sealTime', 'invalid_time');
  if (!(certificateDer instanceof Uint8Array)) throw inputInvalid('certificateDer', 'invalid_certificate');
  const frozenDigest = isRecord(fieldManifest) ? fieldManifest['document_digest'] : undefined;
  if (typeof frozenDigest !== 'string' || !DIGEST_PATTERN.test(frozenDigest)) throw inputInvalid('fieldManifest.document_digest', 'invalid_digest');
  let length: number;
  try {
    length = signedDataLength(Uint8Array.from(certificateDer));
  } catch (error) {
    if (error instanceof CertificateError) throw certificateInvalid(error.code);
    throw error;
  }
  const copy = Uint8Array.from(document);
  const documentDigest = createHash('sha256').update(copy).digest('hex');
  if (frozenDigest !== documentDigest) throw documentDigestMismatch();
  return Object.freeze({ document: copy, documentDigest, fields: Object.freeze(fields), values, unsupported, sealDate, signedDataLength: length });
}

// --- the result --------------------------------------------------------------------------------

export interface ComposedRevision {
  /** The base followed by the update; final except for the /Contents hex digits, which are zeros. */
  readonly bytes: Uint8Array;
  /** SHA-256 (lowercase hex) of `bytes`: the approval manifest's approved_composition_digest. */
  readonly digest: string;
  /** SHA-256 of the base: the field manifest's document_digest. */
  readonly documentDigest: string;
  /** The base's length: the revision boundary below the seal's revision. */
  readonly documentLength: number;
  /** [0, o1, o2, l2]: o1 is the offset of `<`, o2 the offset after `>`, o2 + l2 the length. */
  readonly byteRange: readonly [0, number, number, number];
  /** The /Contents hex digits: the offset of the first digit and their count (2 x signedDataLength). */
  readonly contents: { readonly offset: number; readonly hexLength: number };
  /** signedDataLength(certificate): the exact DER length T037 must embed. */
  readonly signedDataLength: number;
  /** The kind of the appended cross-reference section (the base's last kind). */
  readonly xrefKind: 'table' | 'stream';
  /** Object numbers of what the update wrote. */
  readonly objects: {
    readonly signatureField: number;
    readonly signature: number;
    readonly acroForm: number;
    readonly font: number | null;
    readonly widgets: readonly number[];
    readonly appearances: readonly number[];
  };
}

/** The two signed spans of a composed revision, in order, for contentDigestOf (T013). */
export function signedRanges(revision: Pick<ComposedRevision, 'bytes' | 'byteRange'>): [Uint8Array, Uint8Array] {
  const [, first, start, second] = revision.byteRange;
  return [revision.bytes.subarray(0, first), revision.bytes.subarray(start, start + second)];
}

/** The /ByteRange slot text for these offsets, padded with spaces to BYTE_RANGE_WIDTH. */
export function byteRangeText(first: number, start: number, second: number): string {
  const text = `[0 ${first} ${start} ${second}`;
  if (text.length > BYTE_RANGE_WIDTH - 1) throw new RangeError('the /ByteRange does not fit its slot');
  return `${text.padEnd(BYTE_RANGE_WIDTH - 1, ' ')}]`;
}

// --- composition -------------------------------------------------------------------------------

interface WrittenObject {
  readonly num: number;
  readonly gen: number;
  readonly body: string;
}

/** An array value (inline, or an indirect array object) with `additions` appended. */
function mergedArray(value: unknown, objects: ReadonlyMap<number, CheckedObject>, additions: readonly string[], what: string, budget: ValueBudget): string {
  let items: unknown[] = [];
  if (value !== undefined && value !== null) {
    const ref = refValue(value);
    let resolved: unknown = value;
    if (ref !== null) {
      const found = objects.get(ref[0]);
      if (found === undefined || found.gen !== ref[1]) throw danglingReference(what);
      resolved = found.value;
    }
    if (!Array.isArray(resolved)) throw what === 'annots' ? annotsShape() : acroformShape();
    items = resolved;
  }
  return `[${[...items.map((item) => serializeValue(item, budget, 1)), ...additions].join(' ')}]`;
}

/** The largest /SigFlags value combined rather than replaced: an unsigned 32-bit integer. */
const MAX_SIG_FLAGS = 0xffff_ffff;

/**
 * The AcroForm's new /SigFlags (CP-02): an integer from 0 to 4294967295, given
 * directly or through a reference the report resolves, combined with 3 by bitwise OR
 * (as an unsigned 32-bit value); any other value is replaced by 3.
 */
function sigFlagsOf(value: unknown, objects: ReadonlyMap<number, CheckedObject>): number {
  const ref = refValue(value);
  let flags: unknown = value;
  if (ref !== null) {
    const found = objects.get(ref[0]);
    flags = found !== undefined && found.gen === ref[1] ? found.value : undefined;
  }
  return typeof flags === 'number' && Number.isSafeInteger(flags) && flags >= 0 && flags <= MAX_SIG_FLAGS ? (flags | SIG_FLAGS) >>> 0 : SIG_FLAGS;
}

const ASCII = /^[\x00-\x7f]*$/;

function streamBody(dict: string, content: string): string {
  if (!ASCII.test(content)) throw new RangeError('an appearance stream is ASCII');
  return `<< ${dict} /Length ${content.length} >>\nstream\n${content}\nendstream`;
}

/**
 * Compose the seal revision from a checked request and the parse report of its
 * document. Pure and synchronous: it reads no clock, no file and no randomness.
 */
export function composeFromReport(request: CheckedRequest, report: unknown): ComposedRevision {
  const { document } = request;
  const checked = checkReport(document, request.documentDigest, report);
  const { objects } = checked;
  // checkReport bounded every reported value's nodes and depth once. What the rewrites
  // serialize is bounded by the output bound below, so they count depth only: inline
  // copies of a shared array never exhaust a node budget an honest document fits.
  const budget: ValueBudget = { nodes: Number.POSITIVE_INFINITY, maxDepth: checked.budget.maxDepth };

  // Pages and placements first: a field on a page the document lacks is a request defect.
  const located = request.fields.map((field) => {
    const page: CheckedPage | undefined = checked.pages[field.page - 1];
    if (page === undefined) throw inputInvalid(`${field.at}.page`, 'page_out_of_range');
    const placement: Placement | null = placeField(page, field.rect);
    if (placement === null) throw inputInvalid(`${field.at}.rect`, 'field_too_small');
    return { field, page, placement };
  });
  // Every 400 rule has now been judged: only then the 422 (CP-04).
  if (request.unsupported !== null) throw unsupportedCharacters(request.unsupported);
  const placed = located.map((item) => {
    const value = request.values.get(item.field.key);
    if (value === undefined) throw inputInvalid(`${item.field.at}.key`, 'value_missing');
    return { ...item, value };
  });

  // Object numbers, in a fixed order from the base's /Size.
  let next = checked.size;
  const take = (): number => {
    const num = next;
    next += 1;
    return num;
  };
  const font = placed.some((item) => item.value.kind === 'text') ? take() : null;
  const numbered = placed.map((item) => ({ ...item, appearance: take(), widget: take() }));
  const signatureField = take();
  const signature = take();

  const written = new Map<number, WrittenObject>();
  // The bound as an invariant: refuse as soon as what is written crosses it.
  let pending = document.length;
  const write = (num: number, gen: number, body: string, what: string): void => {
    if (written.has(num)) throw reportInvalid(`${what}-rewritten-twice`);
    pending += body.length;
    if (!withinSealedBound(pending)) throw compositionTooLarge();
    written.set(num, { num, gen, body });
  };

  // The catalog and the AcroForm.
  const catalog = typedDict(objects, checked.root, 'Catalog', 'catalog');
  const formValue = entryOf(catalog, 'AcroForm');
  const fieldRef = `${signatureField} 0 R`;
  let acroForm: number;
  // The AcroForm's own object when it is indirect: if it is also a page that gains widgets,
  // that object would be written twice, so the form is refused as acroform_shape.
  let formObject: number | null = null;
  if (formValue === undefined || formValue === null) {
    acroForm = take();
    write(acroForm, 0, `<< /Fields [${fieldRef}] /SigFlags ${SIG_FLAGS} >>`, 'acroform');
    write(checked.root[0], checked.root[1], rewriteDict(catalog, [['AcroForm', `${acroForm} 0 R`]], budget), 'catalog');
  } else {
    const formRef: Ref | null = refValue(formValue);
    let formEntries: Array<[string, unknown]> | null;
    if (formRef !== null) {
      const found = objects.get(formRef[0]);
      if (found === undefined || found.gen !== formRef[1]) throw danglingReference('acroform');
      formEntries = dictEntries(found.value);
    } else {
      formEntries = dictEntries(formValue);
    }
    if (formEntries === null) throw acroformShape();
    formObject = formRef === null ? null : formRef[0];
    const fields = mergedArray(entryOf(formEntries, 'Fields'), objects, [fieldRef], 'fields', budget);
    const flags = String(sigFlagsOf(entryOf(formEntries, 'SigFlags'), objects));
    const form = rewriteDict(formEntries, [['Fields', fields], ['SigFlags', flags]], budget);
    if (formRef !== null) {
      acroForm = formRef[0];
      write(formRef[0], formRef[1], form, 'acroform');
    } else {
      acroForm = checked.root[0];
      write(checked.root[0], checked.root[1], rewriteDict(catalog, [['AcroForm', form]], budget), 'catalog');
    }
  }
  const xrefSelf = checked.kind === 'stream' ? take() : null;
  const size = next;
  if (size - 1 > MAX_OBJECT_NUMBER) throw xrefSize();

  // Pages gaining widgets, in page order; widgets on a page in field-manifest order.
  for (const page of checked.pages) {
    const refs = numbered.filter((item) => item.page.number === page.number).map((item) => `${item.widget} 0 R`);
    if (refs.length === 0) continue;
    if (page.ref[0] === formObject) throw acroformShape();
    const entries = typedDict(objects, page.ref, 'Page', 'page');
    write(page.ref[0], page.ref[1], rewriteDict(entries, [['Annots', mergedArray(entryOf(entries, 'Annots'), objects, refs, 'annots', budget)]], budget), 'page');
  }

  // New objects.
  if (font !== null) write(font, 0, TEXT_FONT_DICT, 'font');
  for (const item of numbered) {
    const { width, height, rect, rotate, matrix } = item.placement;
    const content = item.value.kind === 'drawn' ? drawnAppearance(item.value.strokes, width, height) : textAppearance(item.value.bytes, width, height);
    const resources = item.value.kind === 'drawn' || font === null ? '<< >>' : `<< /Font << /${TEXT_FONT_RESOURCE} ${font} 0 R >> >>`;
    write(item.appearance, 0, streamBody(`/Type /XObject /Subtype /Form /FormType 1 /BBox ${centipointArray([0, 0, width, height])} /Matrix ${matrixArray(matrix)} /Resources ${resources}`, content), 'appearance');
    write(
      item.widget,
      0,
      `<< /Type /Annot /Subtype /Widget /Parent ${fieldRef} /P ${pdfRef(item.page.ref)} /Rect ${centipointArray(rect)} /F ${WIDGET_FLAGS} /MK << /R ${rotate} >> /AP << /N ${item.appearance} 0 R >>${
        item.field.type === 'date' ? ` /Contents ${pdfAsciiString(DATE_WIDGET_CONTENTS)}` : ''
      } >>`,
      'widget',
    );
  }
  write(
    signatureField,
    0,
    `<< /FT /Sig /T ${pdfAsciiString(sealFieldName(request.documentDigest))} /V ${signature} 0 R /Kids [${numbered.map((item) => `${item.widget} 0 R`).join(' ')}] >>`,
    'field',
  );

  // The /Sig dictionary, in parts whose offsets are recorded as it is written.
  const sigHead = '<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange ';
  const sigSlot = byteRangeText(0, 0, 0);
  const sigMiddle = ' /Contents ';
  const hexLength = 2 * request.signedDataLength;
  const sigContents = `<${'0'.repeat(hexLength)}>`;
  const sigTail = ` /M ${pdfAsciiString(request.sealDate)} /Reason ${pdfAsciiString(SEAL_REASON)} >>`;
  write(signature, 0, `${sigHead}${sigSlot}${sigMiddle}${sigContents}${sigTail}`, 'signature');

  // Serialize the objects in ascending number, after an end-of-line if the base lacks one.
  const last = document[document.length - 1];
  let text = last === 0x0a || last === 0x0d ? '' : '\n';
  const entries: XrefEntry[] = [];
  let slotAt = -1;
  for (const object of [...written.values()].sort((a, b) => a.num - b.num)) {
    entries.push({ num: object.num, gen: object.gen, offset: document.length + text.length });
    text += `${object.num} ${object.gen} obj\n`;
    if (object.num === signature) slotAt = document.length + text.length + sigHead.length;
    text += `${object.body}\nendobj\n`;
  }
  if (!ASCII.test(text) || slotAt < 0) throw new RangeError('the update is ASCII and holds the /Sig dictionary');
  const appended = Buffer.from(text, 'latin1');
  const first = slotAt + BYTE_RANGE_WIDTH + sigMiddle.length;
  const start = first + sigContents.length;

  // The trailer /ID: the base's permanent identifier, and a content identifier of this revision.
  const revisionId = createHash('sha256').update(document).update(appended).digest().subarray(0, 16).toString('hex');
  const id: readonly [string, string] = [checked.id === null ? revisionId : checked.id[0], revisionId];
  const at = document.length + appended.length;
  const trailer = { size, root: checked.root, info: checked.info, id, prev: checked.startxref };
  const section = xrefSelf === null ? classicSection(entries, trailer, at) : streamSection(entries, xrefSelf, trailer, at);

  if (!withinSealedBound(document.length + appended.length + section.length)) throw compositionTooLarge();
  const bytes = Buffer.concat([document, appended, section]);
  const second = bytes.length - start;
  bytes.write(byteRangeText(first, start, second), slotAt, 'latin1');

  // Self-checks: the base is untouched, the placeholder is where the ByteRange says.
  if (!bytes.subarray(0, document.length).equals(document)) throw new RangeError('the base bytes changed');
  if (bytes[first] !== 0x3c || bytes[start - 1] !== 0x3e || start - first !== hexLength + 2) throw new RangeError('the /Contents placeholder moved');
  for (let index = first + 1; index < start - 1; index += 1) if (bytes[index] !== 0x30) throw new RangeError('the /Contents placeholder is not zeros');

  return Object.freeze({
    bytes,
    digest: createHash('sha256').update(bytes).digest('hex'),
    documentDigest: request.documentDigest,
    documentLength: document.length,
    byteRange: Object.freeze([0, first, start, second] as const),
    contents: Object.freeze({ offset: first + 1, hexLength }),
    signedDataLength: request.signedDataLength,
    xrefKind: checked.kind,
    objects: Object.freeze({
      signatureField,
      signature,
      acroForm,
      font,
      widgets: Object.freeze(numbered.map((item) => item.widget)),
      appearances: Object.freeze(numbered.map((item) => item.appearance)),
    }),
  });
}
