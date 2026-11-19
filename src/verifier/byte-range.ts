// SPDX-License-Identifier: Apache-2.0
//
// The verifier's own ByteRange locator and /Contents checks (T014).
//
// Locating (request #58 (1); VB-07). With the revision structure read, the seal
// is the one signature DICTIONARY among the effective objects, found by
// structure.ts as T033 finds one (/Type /Sig or /DocTimeStamp, or both
// /ByteRange and /Contents), never by text: a string that spells /ByteRange is
// not a signature. More than one, any /DocMDP or /UR3, or a /FT /Sig field
// whose /V is another value is a multi-signature input, outside the product
// profile, reported as one T014 cannot evaluate; so is a signature dictionary
// inside an object stream, whose offsets are not file offsets. None fails the
// signature-dictionary check. The range is then read at that dictionary's own
// /ByteRange key.
//
// With the structure check failed, no effective objects exist, so the OC-08
// end-of-file fallback keeps the lexical locator: exactly one /ByteRange name
// token, and two or more is a multi-signature input. Such a file never reaches
// coverage `complete` (coverage needs the structure), and T033 refuses it, so
// no base T033 accepts depends on this path.
//
// The ByteRange [o1 l1 o2 l2] passes only when:
// - o1 is 0, both ranges are non-empty and the gap [l1, o2) is non-empty;
// - o2 + l2 is within the file;
// - the gap is exactly one hex string `<...>` of an even number of hex digits
//   and nothing else, so the only unsigned bytes are the signature container;
// - the /ByteRange array itself lies inside the signed bytes;
// - with the revision structure read, o2 + l2 is a marked end of a revision
//   (the signed revision; see structure.ts) and the gap lies after the previous
//   revision;
// - with the structure check failed, o2 + l2 is exactly the file length: the
//   end-of-file fallback (plan.md OC-08). One byte short or past fails.
//
// Extraction. The hex digits decode to the CMS DER followed by zero padding.
// Non-zero padding fails `contents-padding`, which is caught by the
// exact-artifact digest and never changes integrity (OC-04).

import { VERIFIER_LIMITS } from './limits.ts';
import { DerFault, readTlv } from './der.ts';
import { byteAt, hexValue, indexOfAscii, isRegular, readUnsignedInt, skipWhitespace } from './pdf-syntax.ts';
import type { StructureResult } from './structure.ts';

export const SIGNATURE_DICTIONARY_DETAILS = [
  'no-byte-range',
  'byte-range-malformed',
  'multiple-signatures',
  'signature-compressed',
] as const;
export const BYTE_RANGE_DETAILS = [
  'range1-not-at-zero',
  'byte-range-malformed',
  'beyond-eof',
  'gap-not-contents',
  'byte-range-unsigned',
  'not-revision-boundary',
  'contents-outside-signed-revision',
  'not-to-eof',
] as const;
export const CMS_EXTRACTION_DETAILS = ['contents-too-large', 'cms-not-sequence', 'cms-truncated', 'cms-header-invalid', 'cms-too-large'] as const;
export const CONTENTS_PADDING_DETAILS = ['nonzero-padding'] as const;

export type ByteRangeDetail = (typeof BYTE_RANGE_DETAILS)[number];
export type CmsExtractionDetail = (typeof CMS_EXTRACTION_DETAILS)[number];

export interface ByteRangeField {
  /** Offset of the `/ByteRange` name. */
  readonly keyOffset: number;
  /** Offset just past the closing `]`. */
  readonly arrayEnd: number;
  readonly range: readonly [number, number, number, number];
}

export type LocateResult =
  | { readonly state: 'pass'; readonly field: ByteRangeField }
  | { readonly state: 'fail'; readonly detail: 'no-byte-range' | 'byte-range-malformed' }
  | { readonly state: 'unsupported'; readonly detail: 'multiple-signatures' | 'signature-compressed' };

const KEY = '/ByteRange';

/**
 * The seal's /ByteRange: through the one signature dictionary structure.ts
 * found among the effective objects, or, with the structure check failed, by
 * the lexical fallback.
 */
export function locateSignature(bytes: Uint8Array, structure: StructureResult): LocateResult {
  if (!structure.ok) return locateByteRange(bytes);
  const scan = structure.signature;
  if (scan.state === 'none') return { state: 'fail', detail: 'no-byte-range' };
  if (scan.state === 'unsupported') return { state: 'unsupported', detail: scan.detail };
  if (scan.byteRange === null) return { state: 'fail', detail: 'no-byte-range' };
  const field = parseRangeArray(bytes, scan.byteRange.at, scan.byteRange.valueAt);
  if (field === null) return { state: 'fail', detail: 'byte-range-malformed' };
  return { state: 'pass', field };
}

/** The OC-08 fallback: exactly one /ByteRange name token in the file (a narrow exception to VB-07, request #60 (3)). */
export function locateByteRange(bytes: Uint8Array): LocateResult {
  const positions: number[] = [];
  let from = 0;
  while (positions.length < 2) {
    const at = indexOfAscii(bytes, KEY, from, bytes.length);
    if (at < 0) break;
    if (!isRegular(byteAt(bytes, at + KEY.length))) positions.push(at);
    from = at + 1;
  }
  const [only, second] = positions;
  if (only === undefined) return { state: 'fail', detail: 'no-byte-range' };
  if (second !== undefined) return { state: 'unsupported', detail: 'multiple-signatures' };
  const field = parseRangeArray(bytes, only, only + KEY.length);
  if (field === null) return { state: 'fail', detail: 'byte-range-malformed' };
  return { state: 'pass', field };
}

/** `[o1 l1 o2 l2]` at `valueAt`: four unsigned integers of at most 15 digits (strict; a security check). */
function parseRangeArray(bytes: Uint8Array, keyOffset: number, valueAt: number): ByteRangeField | null {
  const end = bytes.length;
  let p = skipWhitespace(bytes, valueAt, end);
  if (byteAt(bytes, p) !== 0x5b) return null;
  p += 1;
  const values: number[] = [];
  for (let i = 0; i < 4; i += 1) {
    const at = skipWhitespace(bytes, p, end);
    if (i > 0 && at === p) return null;
    const n = readUnsignedInt(bytes, at, end);
    if (n === null) return null;
    values.push(n.value);
    p = n.next;
  }
  p = skipWhitespace(bytes, p, end);
  if (byteAt(bytes, p) !== 0x5d) return null;
  const [o1, l1, o2, l2] = values;
  if (o1 === undefined || l1 === undefined || o2 === undefined || l2 === undefined) return null;
  return { keyOffset, arrayEnd: p + 1, range: [o1, l1, o2, l2] };
}

export interface ByteRangeCheck {
  readonly result: 'pass' | 'fail';
  readonly detail: ByteRangeDetail | null;
  /** Index of the signed revision in file order (0 = first by position), or null when unknown. */
  readonly signedRevision: number | null;
}

function failed(detail: ByteRangeDetail): ByteRangeCheck {
  return { result: 'fail', detail, signedRevision: null };
}

export function checkByteRange(bytes: Uint8Array, field: ByteRangeField, structure: StructureResult): ByteRangeCheck {
  const [o1, l1, o2, l2] = field.range;
  const length = bytes.length;
  if (o1 !== 0) return failed('range1-not-at-zero');
  const gapStart = l1;
  const end = o2 + l2;
  if (l1 < 1 || o2 <= gapStart || l2 < 1) return failed('byte-range-malformed');
  if (end > length) return failed('beyond-eof');
  if (!isHexStringToken(bytes, gapStart, o2)) return failed('gap-not-contents');
  const arraySigned = field.arrayEnd <= gapStart || (field.keyOffset >= o2 && field.arrayEnd <= end);
  if (!arraySigned) return failed('byte-range-unsigned');
  if (structure.ok) {
    const revisions = structure.revisions;
    // A signature ends at a marked revision end: after its %%EOF line, or just
    // after %%EOF (an end-of-line that opens the next revision stays unsigned,
    // and that next revision makes coverage incomplete). The last revision
    // ends only at the file length.
    const signed = revisions.findIndex((r) => r.eofEnd !== null && (r.end === end || r.eofEnd === end));
    if (signed < 0) return failed('not-revision-boundary');
    const previous = signed === 0 ? undefined : revisions[signed - 1];
    const revisionStart = previous === undefined ? 0 : previous.eofEnd !== null ? previous.end : previous.start;
    if (gapStart < revisionStart) return failed('contents-outside-signed-revision');
    return { result: 'pass', detail: null, signedRevision: signed };
  }
  if (end !== length) return failed('not-to-eof');
  return { result: 'pass', detail: null, signedRevision: null };
}

/** True when [start, end) is exactly `<` + an even, non-zero count of hex digits + `>`. */
export function isHexStringToken(bytes: Uint8Array, start: number, end: number): boolean {
  if (start < 0 || end > bytes.length) return false;
  if (byteAt(bytes, start) !== 0x3c || byteAt(bytes, end - 1) !== 0x3e) return false;
  const digits = end - start - 2;
  if (digits < 2 || digits % 2 !== 0) return false;
  for (let i = start + 1; i < end - 1; i += 1) {
    if (hexValue(byteAt(bytes, i)) < 0) return false;
  }
  return true;
}

/** The two stated ranges, when both lie inside the file; else null. */
export function statedRanges(bytes: Uint8Array, field: ByteRangeField): readonly [Uint8Array, Uint8Array] | null {
  const [o1, l1, o2, l2] = field.range;
  if (o1 + l1 > bytes.length || o2 + l2 > bytes.length || o1 + l1 > o2) return null;
  return [bytes.subarray(o1, o1 + l1), bytes.subarray(o2, o2 + l2)];
}

export interface CmsExtraction {
  readonly result: 'pass' | 'fail';
  readonly detail: CmsExtractionDetail | null;
  readonly der: Uint8Array | null;
  readonly padding: 'pass' | 'fail' | 'not-run';
}

/** Decode the hex string at [start, end) (already checked by isHexStringToken). */
export function extractCms(bytes: Uint8Array, start: number, end: number): CmsExtraction {
  const fail = (detail: CmsExtractionDetail): CmsExtraction => ({ result: 'fail', detail, der: null, padding: 'not-run' });
  const digits = end - start - 2;
  if (digits > VERIFIER_LIMITS.maxContentsHexDigits) return fail('contents-too-large');
  const raw = new Uint8Array(digits / 2);
  for (let i = 0; i < raw.length; i += 1) {
    raw[i] = hexValue(byteAt(bytes, start + 1 + 2 * i)) * 16 + hexValue(byteAt(bytes, start + 2 + 2 * i));
  }
  if (byteAt(raw, 0) !== 0x30) return fail('cms-not-sequence');
  let total: number;
  try {
    total = readTlv(raw, 0, raw.length).end;
  } catch (error) {
    if (!(error instanceof DerFault)) throw error;
    return fail(error.code === 'length-exceeds-parent' || error.code === 'truncated' ? 'cms-truncated' : 'cms-header-invalid');
  }
  if (total > VERIFIER_LIMITS.maxCmsBytes) return fail('cms-too-large');
  let padding: 'pass' | 'fail' = 'pass';
  for (let i = total; i < raw.length; i += 1) {
    if (raw[i] !== 0) {
      padding = 'fail';
      break;
    }
  }
  return { result: 'pass', detail: null, der: raw.slice(0, total), padding };
}
