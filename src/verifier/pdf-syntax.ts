// SPDX-License-Identifier: Apache-2.0
//
// The verifier's own bounded PDF syntax layer (T014). It is written for the
// verifier alone and shares nothing with src/pdf/ (VB-01). It reads only what
// the revision-structure reader needs: object headers, dictionaries, arrays,
// numbers, names, strings and indirect references. Content streams are never
// interpreted. Every read is bounded by VERIFIER_LIMITS, and a malformed token
// throws SyntaxFault, which callers turn into a structure verdict.

import { Buffer } from 'node:buffer';
import { VERIFIER_LIMITS } from './limits.ts';

export const SYNTAX_FAULTS = [
  'unexpected-end',
  'unexpected-byte',
  'unterminated',
  'too-deep',
  'too-many-items',
  'number-too-long',
  'string-too-long',
  'duplicate-key',
  'bad-hex',
  'bad-name',
] as const;

export type SyntaxFaultCode = (typeof SYNTAX_FAULTS)[number];

export class SyntaxFault extends Error {
  readonly code: SyntaxFaultCode;
  readonly offset: number;

  constructor(code: SyntaxFaultCode, offset: number) {
    super(code);
    this.name = 'SyntaxFault';
    this.code = code;
    this.offset = offset;
  }
}

export type PdfValue =
  | { readonly kind: 'int'; readonly value: number }
  | { readonly kind: 'real'; readonly value: number }
  | { readonly kind: 'bool' }
  | { readonly kind: 'null' }
  | { readonly kind: 'name'; readonly value: string }
  | { readonly kind: 'string' }
  | { readonly kind: 'hex' }
  | { readonly kind: 'ref'; readonly num: number; readonly gen: number }
  | { readonly kind: 'keyword'; readonly value: string }
  | { readonly kind: 'array'; readonly items: readonly PdfValue[] }
  | { readonly kind: 'dict'; readonly entries: ReadonlyMap<string, PdfValue>; readonly byteRangeKey: ByteRangeKey | null };

/** Where a dictionary's /ByteRange key sits: the offset of its solidus, and the offset just after the name. */
export interface ByteRangeKey {
  readonly at: number;
  readonly valueAt: number;
}

const CR = 0x0d;
const LF = 0x0a;

/** The byte at `i`, or -1 outside the buffer (noUncheckedIndexedAccess-safe). */
export function byteAt(bytes: Uint8Array, i: number): number {
  const v = bytes[i];
  return v === undefined ? -1 : v;
}

export function isWhitespace(b: number): boolean {
  return b === 0x00 || b === 0x09 || b === LF || b === 0x0c || b === CR || b === 0x20;
}

export function isDelimiter(b: number): boolean {
  return (
    b === 0x28 || b === 0x29 || b === 0x3c || b === 0x3e || b === 0x5b ||
    b === 0x5d || b === 0x7b || b === 0x7d || b === 0x2f || b === 0x25
  );
}

export function isRegular(b: number): boolean {
  return b >= 0 && !isWhitespace(b) && !isDelimiter(b);
}

export function isDigit(b: number): boolean {
  return b >= 0x30 && b <= 0x39;
}

export function hexValue(b: number): number {
  if (b >= 0x30 && b <= 0x39) return b - 0x30;
  if (b >= 0x41 && b <= 0x46) return b - 0x37;
  if (b >= 0x61 && b <= 0x66) return b - 0x57;
  return -1;
}

/** A zero-copy Buffer view, for bounded native searches. */
function view(bytes: Uint8Array, from: number, to: number): Buffer {
  const start = Math.max(0, from);
  const end = Math.min(bytes.length, to);
  return Buffer.from(bytes.buffer, bytes.byteOffset + start, Math.max(0, end - start));
}

export function matchAscii(bytes: Uint8Array, pos: number, text: string): boolean {
  if (pos < 0 || pos + text.length > bytes.length) return false;
  for (let i = 0; i < text.length; i += 1) {
    if (byteAt(bytes, pos + i) !== text.charCodeAt(i)) return false;
  }
  return true;
}

/**
 * `text` exactly at `pos`, followed by a byte that is not regular (the end of
 * the file counts as not regular). Nothing before `pos` is looked at, and no
 * white-space is skipped first: the form T033 accepts at a section start and
 * after an object header's generation (request #49).
 */
export function atKeyword(bytes: Uint8Array, pos: number, text: string): boolean {
  return matchAscii(bytes, pos, text) && !isRegular(byteAt(bytes, pos + text.length));
}

/** `text` at `pos` with no regular byte touching it on either side. */
export function matchKeyword(bytes: Uint8Array, pos: number, text: string): boolean {
  return (
    matchAscii(bytes, pos, text) &&
    !isRegular(byteAt(bytes, pos - 1)) &&
    !isRegular(byteAt(bytes, pos + text.length))
  );
}

/** First occurrence of `text` starting in [from, to - text.length], or -1. */
export function indexOfAscii(bytes: Uint8Array, text: string, from: number, to: number): number {
  if (to - from < text.length) return -1;
  const i = view(bytes, from, to).indexOf(text, 0, 'latin1');
  return i < 0 ? -1 : Math.max(0, from) + i;
}

/** Last occurrence of `text` starting in [lower, upper], or -1. */
export function lastIndexOfAscii(bytes: Uint8Array, text: string, upper: number, lower: number): number {
  const from = Math.max(0, lower);
  const to = Math.min(bytes.length, upper + text.length);
  if (to - from < text.length) return -1;
  const i = view(bytes, from, to).lastIndexOf(text, to - from - text.length, 'latin1');
  return i < 0 ? -1 : from + i;
}

export function skipWhitespace(bytes: Uint8Array, pos: number, end: number): number {
  let p = pos;
  while (p < end && isWhitespace(byteAt(bytes, p))) p += 1;
  return p;
}

export function skipWhitespaceAndComments(bytes: Uint8Array, pos: number, end: number): number {
  let p = pos;
  while (p < end) {
    const b = byteAt(bytes, p);
    if (isWhitespace(b)) {
      p += 1;
    } else if (b === 0x25) {
      while (p < end && byteAt(bytes, p) !== CR && byteAt(bytes, p) !== LF) p += 1;
    } else {
      break;
    }
  }
  return p;
}

/** 2 for CR LF, 1 for CR or LF, 0 otherwise. */
export function eolLength(bytes: Uint8Array, pos: number): number {
  const b = byteAt(bytes, pos);
  if (b === CR) return byteAt(bytes, pos + 1) === LF ? 2 : 1;
  return b === LF ? 1 : 0;
}

/**
 * Decimal digits only (no sign), at most maxIntegerDigits, not followed by a
 * regular byte; `end` itself counts as not regular, so a number may run right
 * up to the end of a region (T033's readUnsigned over an object stream's
 * header, which ends at /First).
 */
export function readUnsignedInt(bytes: Uint8Array, pos: number, end: number): { value: number; next: number } | null {
  let p = pos;
  let value = 0;
  while (p < end && isDigit(byteAt(bytes, p))) {
    if (p - pos >= VERIFIER_LIMITS.maxIntegerDigits) return null;
    value = value * 10 + (byteAt(bytes, p) - 0x30);
    p += 1;
  }
  if (p === pos || (p < end && isRegular(byteAt(bytes, p)))) return null;
  return { value, next: p };
}

interface Cursor {
  readonly bytes: Uint8Array;
  readonly end: number;
  pos: number;
}

/** Parse one value at `pos`; throws SyntaxFault. */
export function parseValue(bytes: Uint8Array, pos: number, end: number): { value: PdfValue; next: number } {
  const cursor: Cursor = { bytes, end: Math.min(end, bytes.length), pos };
  const value = readValue(cursor, 0);
  return { value, next: cursor.pos };
}

function readValue(c: Cursor, depth: number): PdfValue {
  if (depth > VERIFIER_LIMITS.maxNestingDepth) throw new SyntaxFault('too-deep', c.pos);
  c.pos = skipWhitespaceAndComments(c.bytes, c.pos, c.end);
  if (c.pos >= c.end) throw new SyntaxFault('unexpected-end', c.pos);
  const b = byteAt(c.bytes, c.pos);
  if (b === 0x2f) return readName(c);
  if (b === 0x28) return readLiteral(c);
  if (b === 0x3c) return byteAt(c.bytes, c.pos + 1) === 0x3c ? readDict(c, depth) : readHex(c);
  if (b === 0x5b) return readArray(c, depth);
  if (isDigit(b) || b === 0x2b || b === 0x2d || b === 0x2e) return readNumberOrRef(c);
  if (isRegular(b)) return readKeyword(c);
  throw new SyntaxFault('unexpected-byte', c.pos);
}

function readName(c: Cursor): PdfValue {
  let p = c.pos + 1;
  let text = '';
  while (p < c.end && isRegular(byteAt(c.bytes, p))) {
    if (text.length >= VERIFIER_LIMITS.maxStringBytes) throw new SyntaxFault('string-too-long', p);
    const b = byteAt(c.bytes, p);
    if (b === 0x23) {
      const hi = hexValue(byteAt(c.bytes, p + 1));
      const lo = hexValue(byteAt(c.bytes, p + 2));
      if (hi < 0 || lo < 0) throw new SyntaxFault('bad-name', p);
      text += String.fromCharCode(hi * 16 + lo);
      p += 3;
    } else {
      text += String.fromCharCode(b);
      p += 1;
    }
  }
  c.pos = p;
  return { kind: 'name', value: text };
}

function readLiteral(c: Cursor): PdfValue {
  let p = c.pos + 1;
  let open = 1;
  while (open > 0) {
    if (p >= c.end) throw new SyntaxFault('unterminated', c.pos);
    if (p - c.pos > VERIFIER_LIMITS.maxStringBytes) throw new SyntaxFault('string-too-long', c.pos);
    const b = byteAt(c.bytes, p);
    if (b === 0x5c) p += 2;
    else {
      if (b === 0x28) open += 1;
      else if (b === 0x29) open -= 1;
      p += 1;
    }
  }
  c.pos = p;
  return { kind: 'string' };
}

function readHex(c: Cursor): PdfValue {
  let p = c.pos + 1;
  for (;;) {
    if (p >= c.end) throw new SyntaxFault('unterminated', c.pos);
    if (p - c.pos > VERIFIER_LIMITS.maxStringBytes) throw new SyntaxFault('string-too-long', c.pos);
    const b = byteAt(c.bytes, p);
    if (b === 0x3e) break;
    if (hexValue(b) < 0 && !isWhitespace(b)) throw new SyntaxFault('bad-hex', p);
    p += 1;
  }
  c.pos = p + 1;
  return { kind: 'hex' };
}

function readDict(c: Cursor, depth: number): PdfValue {
  const start = c.pos;
  c.pos += 2;
  const entries = new Map<string, PdfValue>();
  let byteRangeKey: ByteRangeKey | null = null;
  for (;;) {
    c.pos = skipWhitespaceAndComments(c.bytes, c.pos, c.end);
    if (c.pos >= c.end) throw new SyntaxFault('unterminated', start);
    if (byteAt(c.bytes, c.pos) === 0x3e && byteAt(c.bytes, c.pos + 1) === 0x3e) {
      c.pos += 2;
      return { kind: 'dict', entries, byteRangeKey };
    }
    if (byteAt(c.bytes, c.pos) !== 0x2f) throw new SyntaxFault('unexpected-byte', c.pos);
    const keyAt = c.pos;
    const key = readName(c);
    if (key.kind === 'name' && key.value === 'ByteRange') byteRangeKey = { at: keyAt, valueAt: c.pos };
    if (key.kind !== 'name') throw new SyntaxFault('bad-name', c.pos);
    if (entries.has(key.value)) throw new SyntaxFault('duplicate-key', c.pos);
    if (entries.size >= VERIFIER_LIMITS.maxContainerItems) throw new SyntaxFault('too-many-items', c.pos);
    const value = readValue(c, depth + 1);
    if (value.kind === 'keyword') throw new SyntaxFault('unexpected-byte', c.pos);
    entries.set(key.value, value);
  }
}

function readArray(c: Cursor, depth: number): PdfValue {
  const start = c.pos;
  c.pos += 1;
  const items: PdfValue[] = [];
  for (;;) {
    c.pos = skipWhitespaceAndComments(c.bytes, c.pos, c.end);
    if (c.pos >= c.end) throw new SyntaxFault('unterminated', start);
    if (byteAt(c.bytes, c.pos) === 0x5d) {
      c.pos += 1;
      return { kind: 'array', items };
    }
    if (items.length >= VERIFIER_LIMITS.maxContainerItems) throw new SyntaxFault('too-many-items', c.pos);
    const value = readValue(c, depth + 1);
    if (value.kind === 'keyword') throw new SyntaxFault('unexpected-byte', c.pos);
    items.push(value);
  }
}

/**
 * A number token as T033's readValue reads one: an optional sign, digits, an
 * optional point and digits (`+12`, `-.5`, `3.`, `0012.50`), at most
 * maxNumberChars characters, followed by a byte that is not regular. A
 * non-negative integral number may open an indirect reference `num gen R`,
 * with white-space and comments skipped before the generation and before `R`.
 */
function readNumberOrRef(c: Cursor): PdfValue {
  const start = c.pos;
  let p = c.pos;
  const signed = byteAt(c.bytes, p) === 0x2b || byteAt(c.bytes, p) === 0x2d;
  if (signed) p += 1;
  let digits = 0;
  let real = false;
  while (p < c.end) {
    const b = byteAt(c.bytes, p);
    if (isDigit(b)) digits += 1;
    else if (b === 0x2e && !real) real = true;
    else break;
    p += 1;
    if (p - start > VERIFIER_LIMITS.maxNumberChars) throw new SyntaxFault('number-too-long', start);
  }
  if (digits === 0 || isRegular(byteAt(c.bytes, p))) throw new SyntaxFault('unexpected-byte', start);
  c.pos = p;
  const value = Number(Buffer.from(c.bytes.buffer, c.bytes.byteOffset + start, p - start).toString('latin1'));
  if (!Number.isFinite(value)) throw new SyntaxFault('unexpected-byte', start);
  const number: PdfValue = real ? { kind: 'real', value } : { kind: 'int', value };
  if (!Number.isInteger(value) || value < 0) return number;
  const genStart = skipWhitespaceAndComments(c.bytes, p, c.end);
  if (genStart === p) return number;
  const gen = readUnsignedInt(c.bytes, genStart, c.end);
  if (gen === null) return number;
  const r = skipWhitespaceAndComments(c.bytes, gen.next, c.end);
  if (r > gen.next && r < c.end && byteAt(c.bytes, r) === 0x52 && !isRegular(byteAt(c.bytes, r + 1))) {
    c.pos = r + 1;
    return { kind: 'ref', num: value, gen: gen.value };
  }
  return number;
}

function readKeyword(c: Cursor): PdfValue {
  let p = c.pos;
  while (p < c.end && isRegular(byteAt(c.bytes, p))) {
    if (p - c.pos > 32) throw new SyntaxFault('unexpected-byte', c.pos);
    p += 1;
  }
  const word = Buffer.from(c.bytes.buffer, c.bytes.byteOffset + c.pos, p - c.pos).toString('latin1');
  c.pos = p;
  if (word === 'true' || word === 'false') return { kind: 'bool' };
  if (word === 'null') return { kind: 'null' };
  return { kind: 'keyword', value: word };
}

export interface ObjectHeader {
  readonly num: number;
  readonly gen: number;
  /** Offset of the object number's first digit (after any skipped white-space and comments). */
  readonly start: number;
  /** Offset just after the `obj` keyword. */
  readonly next: number;
  /** White-space and comment bytes skipped before and between the header's tokens. */
  readonly skipped: number;
}

/**
 * The `num gen obj` header at `offset`, or null. As T033's parser reads one
 * (request #49, T014-XREFSTART): white-space and comments are skipped before
 * the object number and between the tokens; each number is 1 to
 * maxIntegerDigits digits, leading zeros allowed, followed by a byte that is
 * not regular; `obj` is followed by a byte that is not regular. So an offset
 * may name white-space or a comment before the header. The caller compares the
 * number and generation with the entry that led here.
 */
export function readObjectHeader(bytes: Uint8Array, offset: number): ObjectHeader | null {
  const end = bytes.length;
  if (offset < 0 || offset >= end) return null;
  const start = skipWhitespaceAndComments(bytes, offset, end);
  const num = readUnsignedInt(bytes, start, end);
  if (num === null) return null;
  const genAt = skipWhitespaceAndComments(bytes, num.next, end);
  const gen = readUnsignedInt(bytes, genAt, end);
  if (gen === null) return null;
  const kw = skipWhitespaceAndComments(bytes, gen.next, end);
  if (!atKeyword(bytes, kw, 'obj')) return null;
  const skipped = start - offset + (genAt - num.next) + (kw - gen.next);
  return { num: num.value, gen: gen.value, start, next: kw + 3, skipped };
}

export interface IndirectObject {
  readonly num: number;
  readonly gen: number;
  /** The header read at the offset (its start, and the bytes skipped to reach it). */
  readonly header: ObjectHeader;
  readonly value: PdfValue;
  /** Offset of the first stream byte when the object is a stream, else null. */
  readonly streamStart: number | null;
}

/** The indirect object at `offset`: null when no header is there (see readObjectHeader); throws SyntaxFault on a broken body. */
export function readIndirectObject(bytes: Uint8Array, offset: number): IndirectObject | null {
  const header = readObjectHeader(bytes, offset);
  if (header === null) return null;
  const { value, next } = parseValue(bytes, header.next, bytes.length);
  let streamStart: number | null = null;
  if (value.kind === 'dict') {
    const kw = skipWhitespaceAndComments(bytes, next, bytes.length);
    if (atKeyword(bytes, kw, 'stream')) {
      const eol = kw + 6;
      if (byteAt(bytes, eol) === CR && byteAt(bytes, eol + 1) === LF) streamStart = eol + 2;
      else if (byteAt(bytes, eol) === LF) streamStart = eol + 1;
      else throw new SyntaxFault('unexpected-byte', eol);
    }
  }
  return { num: header.num, gen: header.gen, header, value, streamStart };
}

export function dictEntry(value: PdfValue, key: string): PdfValue | undefined {
  return value.kind === 'dict' ? value.entries.get(key) : undefined;
}

/**
 * An integer value: an integer token, or an integral real such as `123.0`,
 * which T033 accepts wherever it needs an integer (its isNonNegativeInteger
 * tests the parsed number). Callers check the sign and range they need.
 */
export function intValue(value: PdfValue | undefined): number | null {
  if (value === undefined) return null;
  if (value.kind === 'int') return value.value;
  if (value.kind === 'real' && Number.isInteger(value.value)) return value.value;
  return null;
}

export function nameValue(value: PdfValue | undefined): string | null {
  return value !== undefined && value.kind === 'name' ? value.value : null;
}
