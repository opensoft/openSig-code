// SPDX-License-Identifier: Apache-2.0
//
// PDF object syntax (ISO 32000-1 section 7.3) for the bounded parser (T033): numbers,
// names with #xx escapes, literal and hexadecimal strings, arrays, dictionaries, indirect
// references and the keywords true, false and null. Array and dictionary nesting is
// bounded by maxDepth, so hostile input cannot exhaust the call stack. Duplicate
// dictionary keys are rejected, because readers disagree on which one wins.

import { Buffer } from 'node:buffer';

import { limitExceeded, malformed } from './errors.ts';

export interface PdfName {
  readonly t: 'name';
  readonly v: string;
}
export interface PdfString {
  readonly t: 'str';
  readonly v: Uint8Array;
}
export interface PdfRef {
  readonly t: 'ref';
  readonly num: number;
  readonly gen: number;
}
export interface PdfDict {
  readonly t: 'dict';
  readonly map: Map<string, PdfValue>;
}
export type PdfValue = null | boolean | number | PdfName | PdfString | PdfRef | PdfDict | PdfValue[];

type Tagged = PdfName | PdfString | PdfRef | PdfDict;

function tagged(value: PdfValue | undefined): Tagged | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value : null;
}

export function isDict(value: PdfValue | undefined): value is PdfDict {
  return tagged(value)?.t === 'dict';
}

export function isRef(value: PdfValue | undefined): value is PdfRef {
  return tagged(value)?.t === 'ref';
}

export function isName(value: PdfValue | undefined): value is PdfName {
  return tagged(value)?.t === 'name';
}

export function isString(value: PdfValue | undefined): value is PdfString {
  return tagged(value)?.t === 'str';
}

/** The name stored under `key`, or null. */
export function nameOf(dict: PdfDict, key: string): string | null {
  const value = dict.map.get(key);
  return isName(value) ? value.v : null;
}

export function isNonNegativeInteger(value: PdfValue | undefined): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

const WHITESPACE = new Uint8Array(256);
for (const code of [0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20]) WHITESPACE[code] = 1;
const DELIMITER = new Uint8Array(256);
for (const ch of '()<>[]{}/%') DELIMITER[ch.charCodeAt(0)] = 1;

const NUMBER_CHAR = new Uint8Array(256);
for (const ch of '0123456789+-.') NUMBER_CHAR[ch.charCodeAt(0)] = 1;
const NUMBER_SYNTAX = /^[+-]?(?:\d+\.?\d*|\.\d+)$/;

function hexValue(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x37;
  if (code >= 0x61 && code <= 0x66) return code - 0x57;
  return -1;
}

export function latin1(bytes: Uint8Array, start = 0, end = bytes.length): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset + start, end - start).toString('latin1');
}

export class Lexer {
  readonly bytes: Uint8Array;
  readonly end: number;
  readonly maxDepth: number;
  pos: number;
  /** Deepest container nesting seen by this lexer. */
  deepest = 0;

  constructor(bytes: Uint8Array, pos: number, end: number, maxDepth: number) {
    this.bytes = bytes;
    this.pos = pos;
    this.end = end;
    this.maxDepth = maxDepth;
  }

  byteAt(index: number): number {
    return index >= 0 && index < this.end ? (this.bytes[index] ?? -1) : -1;
  }

  isWhitespace(code: number): boolean {
    return code >= 0 && WHITESPACE[code] === 1;
  }

  isRegular(code: number): boolean {
    return code >= 0 && WHITESPACE[code] !== 1 && DELIMITER[code] !== 1;
  }

  /** Skip whitespace and comments. */
  skipWhitespace(): void {
    for (;;) {
      const code = this.byteAt(this.pos);
      if (this.isWhitespace(code)) {
        this.pos += 1;
      } else if (code === 0x25) {
        while (this.pos < this.end && this.byteAt(this.pos) !== 0x0a && this.byteAt(this.pos) !== 0x0d) this.pos += 1;
      } else {
        return;
      }
    }
  }

  /** A run of regular characters at the current position (possibly empty). */
  readKeyword(): string {
    const start = this.pos;
    while (this.isRegular(this.byteAt(this.pos))) this.pos += 1;
    return latin1(this.bytes, start, this.pos);
  }

  /** True when `word` followed by a non-regular character starts at the current position. */
  atKeyword(word: string): boolean {
    for (let i = 0; i < word.length; i += 1) if (this.byteAt(this.pos + i) !== word.charCodeAt(i)) return false;
    return !this.isRegular(this.byteAt(this.pos + word.length));
  }

  /** An unsigned decimal integer at the current position, or null (position unchanged). */
  readUnsigned(): number | null {
    const start = this.pos;
    while (this.byteAt(this.pos) >= 0x30 && this.byteAt(this.pos) <= 0x39) this.pos += 1;
    if (this.pos === start || this.pos - start > 15 || this.isRegular(this.byteAt(this.pos))) {
      this.pos = start;
      return null;
    }
    return Number(latin1(this.bytes, start, this.pos));
  }

  readValue(depth: number): PdfValue {
    this.skipWhitespace();
    const start = this.pos;
    const code = this.byteAt(start);
    if (code < 0) throw malformed(`unexpected end of data at byte ${start}`);
    if (code === 0x2f) return this.readName();
    if (code === 0x28) return this.readLiteralString();
    if (code === 0x3c) return this.byteAt(start + 1) === 0x3c ? this.readDictionary(depth) : this.readHexString();
    if (code === 0x5b) return this.readArray(depth);
    if (NUMBER_CHAR[code] === 1) return this.readNumberOrReference();
    if (this.isRegular(code)) {
      const word = this.readKeyword();
      if (word === 'true') return true;
      if (word === 'false') return false;
      if (word === 'null') return null;
      throw malformed(`unexpected keyword at byte ${start}`);
    }
    throw malformed(`unexpected delimiter at byte ${start}`);
  }

  private enter(depth: number): void {
    if (depth >= this.maxDepth) throw limitExceeded('nesting-depth');
    if (depth + 1 > this.deepest) this.deepest = depth + 1;
  }

  readName(): PdfName {
    this.pos += 1;
    const out: number[] = [];
    while (this.isRegular(this.byteAt(this.pos))) {
      const code = this.byteAt(this.pos);
      if (code === 0x23) {
        const high = hexValue(this.byteAt(this.pos + 1));
        const low = hexValue(this.byteAt(this.pos + 2));
        if (high < 0 || low < 0) throw malformed(`invalid #xx escape in a name at byte ${this.pos}`);
        out.push(high * 16 + low);
        this.pos += 3;
      } else {
        out.push(code);
        this.pos += 1;
      }
    }
    return { t: 'name', v: Buffer.from(out).toString('latin1') };
  }

  private readLiteralString(): PdfString {
    const start = this.pos;
    this.pos += 1;
    const out: number[] = [];
    let nesting = 1;
    for (;;) {
      const code = this.byteAt(this.pos);
      if (code < 0) throw malformed(`unterminated literal string at byte ${start}`);
      this.pos += 1;
      if (code === 0x5c) {
        const escaped = this.byteAt(this.pos);
        if (escaped < 0) throw malformed(`unterminated literal string at byte ${start}`);
        this.pos += 1;
        if (escaped === 0x6e) out.push(0x0a);
        else if (escaped === 0x72) out.push(0x0d);
        else if (escaped === 0x74) out.push(0x09);
        else if (escaped === 0x62) out.push(0x08);
        else if (escaped === 0x66) out.push(0x0c);
        else if (escaped === 0x0d) {
          if (this.byteAt(this.pos) === 0x0a) this.pos += 1;
        } else if (escaped === 0x0a) {
          // line continuation
        } else if (escaped >= 0x30 && escaped <= 0x37) {
          let value = escaped - 0x30;
          for (let i = 0; i < 2; i += 1) {
            const digit = this.byteAt(this.pos);
            if (digit < 0x30 || digit > 0x37) break;
            value = value * 8 + (digit - 0x30);
            this.pos += 1;
          }
          out.push(value & 0xff);
        } else out.push(escaped);
      } else if (code === 0x28) {
        nesting += 1;
        out.push(code);
      } else if (code === 0x29) {
        nesting -= 1;
        if (nesting === 0) break;
        out.push(code);
      } else out.push(code);
    }
    return { t: 'str', v: Uint8Array.from(out) };
  }

  private readHexString(): PdfString {
    const start = this.pos;
    this.pos += 1;
    const digits: number[] = [];
    for (;;) {
      const code = this.byteAt(this.pos);
      if (code < 0) throw malformed(`unterminated hexadecimal string at byte ${start}`);
      this.pos += 1;
      if (code === 0x3e) break;
      if (this.isWhitespace(code)) continue;
      const value = hexValue(code);
      if (value < 0) throw malformed(`invalid hexadecimal string at byte ${start}`);
      digits.push(value);
    }
    if (digits.length % 2 === 1) digits.push(0);
    const out = new Uint8Array(digits.length / 2);
    for (let i = 0; i < out.length; i += 1) out[i] = (digits[2 * i] ?? 0) * 16 + (digits[2 * i + 1] ?? 0);
    return { t: 'str', v: out };
  }

  private readArray(depth: number): PdfValue[] {
    this.enter(depth);
    const start = this.pos;
    this.pos += 1;
    const items: PdfValue[] = [];
    for (;;) {
      this.skipWhitespace();
      const code = this.byteAt(this.pos);
      if (code < 0) throw malformed(`unterminated array at byte ${start}`);
      if (code === 0x5d) {
        this.pos += 1;
        return items;
      }
      items.push(this.readValue(depth + 1));
    }
  }

  private readDictionary(depth: number): PdfDict {
    this.enter(depth);
    const start = this.pos;
    this.pos += 2;
    const map = new Map<string, PdfValue>();
    for (;;) {
      this.skipWhitespace();
      const code = this.byteAt(this.pos);
      if (code < 0) throw malformed(`unterminated dictionary at byte ${start}`);
      if (code === 0x3e && this.byteAt(this.pos + 1) === 0x3e) {
        this.pos += 2;
        return { t: 'dict', map };
      }
      if (code !== 0x2f) throw malformed(`dictionary key expected at byte ${this.pos}`);
      const key = this.readName().v;
      if (map.has(key)) throw malformed(`duplicate dictionary key at byte ${this.pos}`);
      map.set(key, this.readValue(depth + 1));
    }
  }

  private readNumberOrReference(): PdfValue {
    const start = this.pos;
    while (NUMBER_CHAR[this.byteAt(this.pos)] === 1 && this.byteAt(this.pos) >= 0) this.pos += 1;
    const text = latin1(this.bytes, start, this.pos);
    if (!NUMBER_SYNTAX.test(text) || this.isRegular(this.byteAt(this.pos)) || text.length > 32) {
      throw malformed(`invalid number at byte ${start}`);
    }
    const value = Number(text);
    if (!Number.isFinite(value)) throw malformed(`invalid number at byte ${start}`);
    if (/^\d+$/.test(text) && Number.isSafeInteger(value)) {
      const save = this.pos;
      this.skipWhitespace();
      const gen = this.readUnsigned();
      if (gen !== null) {
        this.skipWhitespace();
        if (this.byteAt(this.pos) === 0x52 && !this.isRegular(this.byteAt(this.pos + 1))) {
          this.pos += 1;
          if (value < 1 || gen > 65535) throw malformed(`invalid indirect reference at byte ${start}`);
          return { t: 'ref', num: value, gen };
        }
      }
      this.pos = save;
    }
    return value;
  }
}
