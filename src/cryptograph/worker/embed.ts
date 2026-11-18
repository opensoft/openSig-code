// SPDX-License-Identifier: Apache-2.0
//
// Placeholder checks and CMS embedding (T037). Pure functions; the child runs
// them, and the tests call them in-process as well.
//
// checkPlaceholder() refuses unless the composed bytes hold an unfilled
// signature placeholder exactly where the composer says (T036, request #39
// Part F, request #43):
// - byteRange is [0, o1, o2, l2] with 0 < o1, o1 + 2 < o2 and o2 + l2 equal to
//   the length, so the two spans cover every byte except [o1, o2);
// - bytes[o1] is "<" and bytes[o2 - 1] is ">", preceded by the key /Contents;
// - contents.offset is o1 + 1 and contents.hexLength is o2 - o1 - 2, even;
// - every digit in the placeholder is ASCII "0";
// - the signature dictionary's own /ByteRange array, written in the bytes,
//   holds exactly those four integers. It is found inside the indirect object
//   that holds the placeholder: after the last "obj" header before o1 and
//   before the first "endobj" after o2, each searched within
//   SIG_OBJECT_WINDOW bytes; it must occur exactly once there. T036
//   guarantees that layout (request #44, CP-05): one /Sig object with direct
//   /ByteRange and /Contents, under 4 KiB of text on each side of the
//   /Contents string. Its slot (compose.ts byteRangeText) is "[0 o1 o2 l2"
//   padded with spaces to BYTE_RANGE_WIDTH and closed by "]"; any PDF
//   whitespace and leading zeros are accepted here.
//
// embedSignedData() writes the CMS as lowercase hex over exactly
// [contents.offset, contents.offset + contents.hexLength) of a copy, and
// refuses a CMS whose hex length is not the placeholder's (no padding, no
// truncation, no partial artifact: the input is never modified).

import { SealError } from './errors.ts';

export const SIG_OBJECT_WINDOW = 4096;

export interface SealGeometry {
  readonly byteRange: readonly [number, number, number, number];
  readonly contentsOffset: number;
  readonly contentsHexLength: number;
}

const LESS = 0x3c;
const GREATER = 0x3e;
const ZERO_DIGIT = 0x30;
const OPEN_BRACKET = 0x5b;
const CLOSE_BRACKET = 0x5d;
const CONTENTS_KEY = Buffer.from('/Contents', 'latin1');
const BYTE_RANGE_KEY = Buffer.from('/ByteRange', 'latin1');
const OBJ = Buffer.from('obj', 'latin1');
const ENDOBJ = Buffer.from('endobj', 'latin1');
const MAX_INTEGER_DIGITS = 10;

const isWhite = (byte: number | undefined): boolean => byte === 0x00 || byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d || byte === 0x20;
const isDigit = (byte: number | undefined): boolean => byte !== undefined && byte >= 0x30 && byte <= 0x39;

function view(bytes: Uint8Array): Buffer {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length);
}

/** Every start index of `needle` in [from, to). */
function occurrences(buffer: Buffer, needle: Buffer, from: number, to: number): number[] {
  const found: number[] = [];
  let at = buffer.indexOf(needle, from);
  while (at !== -1 && at + needle.length <= to) {
    found.push(at);
    at = buffer.indexOf(needle, at + 1);
  }
  return found;
}

/** Parse "[i i i i]" (PDF whitespace allowed, digits only) starting at `at`, ending before `limit`. */
function parseFourIntegers(buffer: Buffer, at: number, limit: number): number[] | null {
  let i = at;
  while (i < limit && isWhite(buffer[i])) i += 1;
  if (buffer[i] !== OPEN_BRACKET) return null;
  i += 1;
  const values: number[] = [];
  for (let n = 0; n < 4; n += 1) {
    const start = i;
    while (i < limit && isWhite(buffer[i])) i += 1;
    if (n > 0 && i === start) return null;
    const digits = i;
    while (i < limit && isDigit(buffer[i])) i += 1;
    if (i === digits || i - digits > MAX_INTEGER_DIGITS) return null;
    values.push(Number(buffer.subarray(digits, i).toString('latin1')));
  }
  while (i < limit && isWhite(buffer[i])) i += 1;
  return buffer[i] === CLOSE_BRACKET && i < limit ? values : null;
}

function checkWrittenByteRange(buffer: Buffer, o1: number, o2: number, expected: readonly number[]): void {
  const mismatch = new SealError('byte-range-mismatch');
  const leftFloor = Math.max(0, o1 - SIG_OBJECT_WINDOW);
  const headers = occurrences(buffer, OBJ, leftFloor, o1).filter((at) => isWhite(buffer[at - 1]));
  const header = headers.at(-1);
  if (header === undefined) throw mismatch;
  const leftStart = header + OBJ.length;
  if (occurrences(buffer, ENDOBJ, leftStart, o1).length > 0) throw mismatch;
  const rightEnd = occurrences(buffer, ENDOBJ, o2, Math.min(buffer.length, o2 + SIG_OBJECT_WINDOW))[0];
  if (rightEnd === undefined) throw mismatch;
  const keys = [
    ...occurrences(buffer, BYTE_RANGE_KEY, leftStart, o1).map((at) => ({ at, limit: o1 })),
    ...occurrences(buffer, BYTE_RANGE_KEY, o2, rightEnd).map((at) => ({ at, limit: rightEnd })),
  ];
  if (keys.length !== 1) throw mismatch;
  const { at, limit } = keys[0]!;
  const after = at + BYTE_RANGE_KEY.length;
  if (!isWhite(buffer[after]) && buffer[after] !== OPEN_BRACKET) throw mismatch;
  const values = parseFourIntegers(buffer, after, limit);
  if (values === null || values.some((value, index) => value !== expected[index])) throw mismatch;
}

/** Refuse unless `document` holds an unfilled placeholder exactly at `geometry` (see the header). */
export function checkPlaceholder(document: Uint8Array, geometry: SealGeometry): void {
  const invalid = new SealError('placeholder-invalid');
  const { byteRange, contentsOffset, contentsHexLength } = geometry;
  if (!Array.isArray(byteRange) || byteRange.length !== 4 || !byteRange.every((value) => Number.isSafeInteger(value) && value >= 0)) throw invalid;
  const [b0, o1, o2, l2] = byteRange;
  if (b0 !== 0 || o1 < 1 || o2 <= o1 + 2 || l2 < 1 || o2 + l2 !== document.length) throw invalid;
  const buffer = view(document);
  if (buffer[o1] !== LESS || buffer[o2 - 1] !== GREATER) throw invalid;
  if (contentsOffset !== o1 + 1 || contentsHexLength !== o2 - o1 - 2 || contentsHexLength % 2 !== 0) throw invalid;
  for (let i = contentsOffset; i < contentsOffset + contentsHexLength; i += 1) {
    if (buffer[i] !== ZERO_DIGIT) throw invalid;
  }
  let key = o1 - 1;
  while (key >= 0 && isWhite(buffer[key])) key -= 1;
  const keyStart = key + 1 - CONTENTS_KEY.length;
  if (keyStart < 0 || !buffer.subarray(keyStart, key + 1).equals(CONTENTS_KEY)) throw invalid;
  checkWrittenByteRange(buffer, o1, o2, byteRange);
}

/** The two signed spans, in order: [0, o1) and [o2, o2 + l2). */
export function signedSpans(document: Uint8Array, byteRange: SealGeometry['byteRange']): [Uint8Array, Uint8Array] {
  const [, o1, o2, l2] = byteRange;
  return [document.subarray(0, o1), document.subarray(o2, o2 + l2)];
}

/** A copy of `document` with `cms` written as lowercase hex into the placeholder; refuses any other length. */
export function embedSignedData(document: Uint8Array, geometry: SealGeometry, cms: Uint8Array): Uint8Array {
  if (cms.length * 2 !== geometry.contentsHexLength) throw new SealError('length-mismatch');
  const sealed = Uint8Array.from(document);
  sealed.set(Buffer.from(Buffer.from(cms).toString('hex'), 'latin1'), geometry.contentsOffset);
  return sealed;
}
