// SPDX-License-Identifier: Apache-2.0
//
// The US2 sealed-PDF bound and the upload predicate (T036 follow-up; requests #44 and
// #45, rows SIZE-BOUND, T036-NUMRANGE and T036-FIXES).
//
// Import discipline: this module imports NOTHING, not even a type, so its whole
// import closure is this one file. T037's sealing worker runs under Node's
// permission model with a read grant on exactly this file, and T014 compares its
// own restated bound with MAX_SEALED_PDF_BYTES. It never reaches parsePdf
// (src/pdf/service.ts) or the composer. It restates two constants of other modules,
// MAX_DOCUMENT_BYTES (src/pdf/limits.ts) and MAX_FIELD_VALUES
// (src/domain/approval/values.ts), and tests/compose/ compares both with their
// owners' exports.
//
// The predicate, for T034's upload (EA-07):
//
//   estimateSealedSize(report: SealableReport): SealedSizeEstimate
//   SealedSizeEstimate = { worstCaseBytes: number; exceedsBound: boolean;
//                          refusals: readonly SealRefusal[] }
//   SealRefusal = { detail: SealRefusalDetail; refs: readonly ObjectRef[] }
//
//   - `report` is the live parse report exactly as parsePdf() returns it in
//     `outcome.report` (a ServiceReport): T034 calls this inside the upload request
//     on that object, before it stores the blob. The stored document input keeps no
//     objects and cannot be used.
//   - `worstCaseBytes`: an upper bound on the composed (sealed) PDF for ANY request
//     the budgets allow on this document, taking every page as a possible widget
//     page: the document's bytes, plus UPDATE_REQUEST_BOUND, plus what the composer
//     writes for the catalog and the AcroForm, plus the MAX_FIELD_VALUES (20)
//     costliest pages, a page's cost being everything the composer writes for it.
//     `exceedsBound` is worstCaseBytes > MAX_SEALED_PDF_BYTES.
//   - `refusals`: every refusal the composer could make from the report alone, for
//     some request, in the order of SEAL_REFUSAL_DETAILS, each kind once, with the
//     sorted references [num, gen] of the objects concerned and never a value. T034
//     refuses with 422 unsupported_pdf and the first refusal's detail. The composer
//     makes each as 422 unsupported_pdf with the same detail, not retryable:
//       composition_too_large    worstCaseBytes > MAX_SEALED_PDF_BYTES; refs: every
//                                object the worst case counts;
//       number_range             an exponent-form number in a value the composer
//                                writes; refs: the object it is written from (the
//                                rewritten dictionary, or the /Fields or /Annots
//                                array object copied inline);
//       dangling_form_reference  /AcroForm, /Fields or /Annots names an object the
//                                report does not hold; refs: the object holding it;
//       annots_shape             a page /Annots that is not an array; refs: the page;
//       acroform_shape           an AcroForm that is not a dictionary or whose
//                                /Fields is not an array (refs: the object holding
//                                the entry), or an AcroForm object that is also a
//                                page (refs: that object).
//     An empty list means the composer can seal this document for every request.
//   - Pure: no I/O, no clock, no randomness. Cost: one JSON.stringify per object it
//     sizes (each at most once) and one iterative walk over each value it scans, so
//     time and memory are linear in the report, which the parse service caps at
//     1,376,256 bytes and 266,240 values.
//
// Why it dominates the composer (CP-01). The composer's update is its request part
// plus its rewritten base objects and the copied first /ID.
// - The request part is at most UPDATE_REQUEST_BOUND for every request the budgets
//   allow and every page box the composer accepts (+-1,000,000 points); compose.ts
//   states the derivation, and CP-01 composes the real maximum under it.
// - The composer rewrites at most the catalog, the AcroForm and MAX_FIELD_VALUES
//   pages (one widget per field, at most 20 fields), copying inline the /Fields
//   array of the AcroForm and the /Annots array of each rewritten page. Each
//   rewritten value is written in at most three times its JSON size (syntax.ts:
//   names expand at most threefold, every other value never grows, and an exponent
//   number is refused rather than expanded), plus at most REWRITE_OVERHEAD_BYTES of
//   header and added entries per object. The predicate counts the catalog and the
//   AcroForm always and the 20 costliest pages, each with its copied array, so it is
//   at least what any request makes the composer write.
// - The refusals follow the composer's own rules over the same values, taking every
//   page as a widget page: the catalog's values when the composer rewrites it (no
//   AcroForm, or an inline one), the AcroForm's values except the /Fields and
//   /SigFlags it replaces, the /Fields items, and each page's values except /Annots
//   plus its /Annots items. So a document with no refusal composes for every request.

/** A sealed PDF is at most 48 MiB (request #44). */
export const MAX_SEALED_PDF_BYTES = 50_331_648;
/** The update-size bound from the request alone (derivation in compose.ts). */
export const UPDATE_REQUEST_BOUND = 1_100_000;
/** The mathematical worst-case update size (derivation in compose.ts). */
export const UPDATE_BOUND = 90_565_440;
/** Restated: the field budget (src/domain/approval/values.ts MAX_FIELD_VALUES), so the most pages that receive a widget. */
export const MAX_FIELD_VALUES = 20;
/** Restated: the input cap (src/pdf/limits.ts MAX_DOCUMENT_BYTES), 10 MiB. */
export const MAX_DOCUMENT_BYTES = 10_485_760;
/** Header, trailer and added entries of one rewritten object, beyond three times its value's JSON size. */
export const REWRITE_OVERHEAD_BYTES = 400;
/** The parse report's byte budget at MAX_DOCUMENT_BYTES (src/pdf/limits.ts reportBudget), used by UPDATE_BOUND. */
export const REPORT_BYTE_BUDGET = 64 * 1024 + Math.floor(MAX_DOCUMENT_BYTES / 8);

/** The refusals the composer can make from the parse report alone, in the order the predicate lists them. */
export const SEAL_REFUSAL_DETAILS = Object.freeze(['composition_too_large', 'number_range', 'dangling_form_reference', 'annots_shape', 'acroform_shape'] as const);

export type SealRefusalDetail = (typeof SEAL_REFUSAL_DETAILS)[number];
export type ObjectRef = readonly [number, number];

/** The members of a parse report (src/pdf/service.ts ServiceReport) the predicate reads. */
export interface SealableReport {
  readonly bytes: number;
  readonly pages: ReadonlyArray<{ readonly ref: ObjectRef }>;
  readonly trailer: { readonly root: ObjectRef; readonly id: readonly [string, string] | null };
  readonly objects: Readonly<Record<string, { readonly gen: number; readonly value: unknown }>>;
}

export interface SealRefusal {
  readonly detail: SealRefusalDetail;
  /** The objects concerned, sorted by number, each once; never a value. */
  readonly refs: readonly ObjectRef[];
}

export interface SealedSizeEstimate {
  /** An upper bound on the sealed PDF's size for any request the budgets allow. */
  readonly worstCaseBytes: number;
  /** worstCaseBytes > MAX_SEALED_PDF_BYTES. */
  readonly exceedsBound: boolean;
  /** Every refusal the composer could make from the report alone; empty when it can seal for every request. */
  readonly refusals: readonly SealRefusal[];
}

/** True when a composed PDF of `length` bytes is within the bound. */
export function withinSealedBound(length: number): boolean {
  return Number.isSafeInteger(length) && length >= 0 && length <= MAX_SEALED_PDF_BYTES;
}

/** True for a number JavaScript prints in exponent form: no bounded plain decimal exists. */
export function isExponentNumber(value: number): boolean {
  return String(value).includes('e');
}

type Entries = Readonly<Record<string, unknown>>;

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** The single own key of a JSON-form wrapper ({name}, {hex}, {ref}, {dict}), or undefined. */
function wrapped(value: unknown, key: string): unknown {
  if (!isRecord(value)) return undefined;
  const keys = Object.keys(value);
  return keys.length === 1 && keys[0] === key ? value[key] : undefined;
}

/** A reference as the composer reads one (syntax.ts refValue), or null. */
function refOf(value: unknown): ObjectRef | null {
  const ref = wrapped(value, 'ref');
  if (!Array.isArray(ref) || ref.length !== 2) return null;
  const [num, gen] = ref as [unknown, unknown];
  return typeof num === 'number' && typeof gen === 'number' && Number.isSafeInteger(num) && num >= 1 && Number.isSafeInteger(gen) && gen >= 0 && gen <= 65535
    ? [num, gen]
    : null;
}

/** A dictionary's entries as the composer reads them (syntax.ts dictEntries), or null. */
function dictOf(value: unknown): Entries | null {
  const dict = wrapped(value, 'dict');
  return isRecord(dict) ? dict : null;
}

/** The entries without `keys`: what the composer serializes from a dictionary whose `keys` it replaces. */
function without(entries: Entries, keys: readonly string[]): Entries {
  const kept: Record<string, unknown> = {};
  for (const key of Object.keys(entries)) if (!keys.includes(key)) kept[key] = entries[key];
  return kept;
}

/** Whether a value holds an exponent-form number anywhere (iterative walk). */
function holdsExponentNumber(value: unknown): boolean {
  const stack: unknown[] = [value];
  while (stack.length > 0) {
    const item = stack.pop();
    if (typeof item === 'number') {
      if (isExponentNumber(item)) return true;
    } else if (Array.isArray(item)) {
      for (const inner of item) stack.push(inner);
    } else if (isRecord(item)) {
      for (const key of Object.keys(item)) stack.push(item[key]);
    }
  }
  return false;
}

/** The worst-case composed size and every report-only refusal of a document (see the header). */
export function estimateSealedSize(report: SealableReport): SealedSizeEstimate {
  const objects = report.objects;
  const found = (ref: ObjectRef | null): { readonly gen: number; readonly value: unknown } | undefined => {
    if (ref === null) return undefined;
    const key = String(ref[0]);
    const object = Object.hasOwn(objects, key) ? objects[key] : undefined;
    return object !== undefined && object.gen === ref[1] ? object : undefined;
  };
  const jsonSizes = new Map<number, number>();
  const jsonSize = (ref: ObjectRef | null): number => {
    const object = found(ref);
    if (ref === null || object === undefined) return 0;
    let size = jsonSizes.get(ref[0]);
    if (size === undefined) {
      size = Buffer.byteLength(JSON.stringify(object.value) ?? '', 'utf8');
      jsonSizes.set(ref[0], size);
    }
    return size;
  };

  const findings = new Map<SealRefusalDetail, Map<number, ObjectRef>>();
  const refuse = (detail: SealRefusalDetail, ref: ObjectRef): void => {
    let refs = findings.get(detail);
    if (refs === undefined) {
      refs = new Map();
      findings.set(detail, refs);
    }
    if (!refs.has(ref[0])) refs.set(ref[0], [ref[0], ref[1]]);
  };
  /** Values the composer writes, each with the object it is written from. */
  const written: Array<readonly [ObjectRef, unknown]> = [];
  /**
   * An array the composer copies inline from `holder` (mergedArray): absent or null adds
   * nothing; a reference must name an array object; anything else must be an array.
   * Returns the referenced array's object, if any, and the size of its copy.
   */
  const copied = (value: unknown, holder: ObjectRef, shape: 'annots_shape' | 'acroform_shape'): { readonly ref: ObjectRef | null; readonly bytes: number } => {
    if (value === undefined || value === null) return { ref: null, bytes: 0 };
    const ref = refOf(value);
    if (ref !== null) {
      const object = found(ref);
      if (object === undefined) refuse('dangling_form_reference', holder);
      else if (!Array.isArray(object.value)) refuse(shape, holder);
      else {
        written.push([ref, object.value]);
        return { ref, bytes: 3 * jsonSize(ref) };
      }
      return { ref: null, bytes: 0 };
    }
    if (Array.isArray(value)) written.push([holder, value]);
    else refuse(shape, holder);
    return { ref: null, bytes: 0 };
  };

  // The catalog and the AcroForm (compose.ts, in the same order).
  const root = report.trailer.root;
  const counted = new Map<number, ObjectRef>([[root[0], root]]);
  let fixed = 3 * jsonSize(root) + REWRITE_OVERHEAD_BYTES;
  const catalog = dictOf(found(root)?.value) ?? {};
  const formValue = catalog['AcroForm'];
  let formObject: ObjectRef | null = null;
  if (formValue === undefined || formValue === null) {
    written.push([root, catalog]);
  } else {
    const formRef = refOf(formValue);
    let form: Entries | null = null;
    let holder: ObjectRef = root;
    if (formRef !== null) {
      const object = found(formRef);
      if (object === undefined) refuse('dangling_form_reference', root);
      else {
        form = dictOf(object.value);
        if (form === null) refuse('acroform_shape', root);
        else {
          formObject = formRef;
          holder = formRef;
          counted.set(formRef[0], formRef);
          fixed += 3 * jsonSize(formRef) + REWRITE_OVERHEAD_BYTES;
        }
      }
    } else {
      form = dictOf(formValue);
      if (form === null) refuse('acroform_shape', root);
      else written.push([root, without(catalog, ['AcroForm'])]);
    }
    if (form !== null) {
      written.push([holder, without(form, ['Fields', 'SigFlags'])]);
      const fields = copied(form['Fields'], holder, 'acroform_shape');
      fixed += fields.bytes;
      if (fields.ref !== null) counted.set(fields.ref[0], fields.ref);
    }
  }

  // Every page, as a possible widget page.
  const pageCosts = report.pages.map((page) => {
    if (formObject !== null && page.ref[0] === formObject[0]) refuse('acroform_shape', formObject);
    const entries = dictOf(found(page.ref)?.value) ?? {};
    written.push([page.ref, without(entries, ['Annots'])]);
    const annots = copied(entries['Annots'], page.ref, 'annots_shape');
    return { ref: page.ref, annots: annots.ref, bytes: 3 * jsonSize(page.ref) + REWRITE_OVERHEAD_BYTES + annots.bytes };
  });
  pageCosts.sort((a, b) => b.bytes - a.bytes || a.ref[0] - b.ref[0]);
  let pages = 0;
  for (const cost of pageCosts.slice(0, MAX_FIELD_VALUES)) {
    pages += cost.bytes;
    counted.set(cost.ref[0], cost.ref);
    if (cost.annots !== null) counted.set(cost.annots[0], cost.annots);
  }
  const id = report.trailer.id === null ? 0 : report.trailer.id[0].length + 2;
  const worstCaseBytes = report.bytes + 1 + UPDATE_REQUEST_BOUND + fixed + pages + id;
  const exceedsBound = worstCaseBytes > MAX_SEALED_PDF_BYTES;

  if (exceedsBound) for (const ref of counted.values()) refuse('composition_too_large', ref);
  for (const [ref, value] of written) if (holdsExponentNumber(value)) refuse('number_range', ref);

  const refusals: SealRefusal[] = [];
  for (const detail of SEAL_REFUSAL_DETAILS) {
    const refs = findings.get(detail);
    if (refs === undefined) continue;
    const sorted = [...refs.values()].sort((a, b) => a[0] - b[0]);
    refusals.push(Object.freeze({ detail, refs: Object.freeze(sorted) }));
  }
  return Object.freeze({ worstCaseBytes, exceedsBound, refusals: Object.freeze(refusals) });
}
