// SPDX-License-Identifier: Apache-2.0
//
// Strict I-JSON (RFC 7493) parser for JSON text that is about to be
// canonicalized or digested. Unlike JSON.parse it refuses duplicate member
// names (which JSON.parse resolves silently to the last one), lone surrogates,
// numbers that do not fit an IEEE 754 double, a leading byte order mark and
// nesting deeper than MAX_DEPTH. Members are defined as own data properties,
// so a "__proto__" name cannot change an object's prototype.

import { CanonicalJsonError, MAX_DEPTH, type JsonValue } from './canonicalize.ts';

const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const ESCAPES: Readonly<Record<string, string>> = Object.freeze({
  '"': '"',
  '\\': '\\',
  '/': '/',
  b: '\b',
  f: '\f',
  n: '\n',
  r: '\r',
  t: '\t',
});

class Parser {
  readonly #text: string;
  #at = 0;

  constructor(text: string) {
    this.#text = text;
  }

  #fail(message: string): never {
    throw new CanonicalJsonError(`invalid JSON at offset ${this.#at}: ${message}`);
  }

  #whitespace(): void {
    for (;;) {
      const c = this.#text.charCodeAt(this.#at);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.#at += 1;
      else return;
    }
  }

  document(): JsonValue {
    this.#whitespace();
    const value = this.#value(0);
    this.#whitespace();
    if (this.#at !== this.#text.length) this.#fail('unexpected trailing content');
    return value;
  }

  #value(depth: number): JsonValue {
    if (depth > MAX_DEPTH) this.#fail(`nesting deeper than ${MAX_DEPTH}`);
    const c = this.#text[this.#at];
    if (c === '{') return this.#object(depth);
    if (c === '[') return this.#array(depth);
    if (c === '"') return this.#string();
    if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) return this.#number();
    for (const [literal, value] of [
      ['true', true],
      ['false', false],
      ['null', null],
    ] as const) {
      if (this.#text.startsWith(literal, this.#at)) {
        this.#at += literal.length;
        return value;
      }
    }
    return this.#fail('expected a value');
  }

  #object(depth: number): JsonValue {
    this.#at += 1;
    const result: { [key: string]: JsonValue } = {};
    const seen = new Set<string>();
    this.#whitespace();
    if (this.#text[this.#at] === '}') {
      this.#at += 1;
      return result;
    }
    for (;;) {
      this.#whitespace();
      if (this.#text[this.#at] !== '"') this.#fail('expected a member name');
      const name = this.#string();
      if (seen.has(name)) this.#fail('duplicate member name');
      seen.add(name);
      this.#whitespace();
      if (this.#text[this.#at] !== ':') this.#fail('expected ":"');
      this.#at += 1;
      this.#whitespace();
      const value = this.#value(depth + 1);
      Object.defineProperty(result, name, { value, enumerable: true, writable: true, configurable: true });
      this.#whitespace();
      const next = this.#text[this.#at];
      this.#at += 1;
      if (next === '}') return result;
      if (next !== ',') this.#fail('expected "," or "}"');
    }
  }

  #array(depth: number): JsonValue {
    this.#at += 1;
    const result: JsonValue[] = [];
    this.#whitespace();
    if (this.#text[this.#at] === ']') {
      this.#at += 1;
      return result;
    }
    for (;;) {
      this.#whitespace();
      result.push(this.#value(depth + 1));
      this.#whitespace();
      const next = this.#text[this.#at];
      this.#at += 1;
      if (next === ']') return result;
      if (next !== ',') this.#fail('expected "," or "]"');
    }
  }

  #string(): string {
    this.#at += 1;
    let out = '';
    for (;;) {
      const c = this.#text[this.#at];
      if (c === undefined) this.#fail('unterminated string');
      const code = c.charCodeAt(0);
      if (c === '"') {
        this.#at += 1;
        break;
      }
      if (code < 0x20) this.#fail('unescaped control character in string');
      if (c !== '\\') {
        out += c;
        this.#at += 1;
        continue;
      }
      const escape = this.#text[this.#at + 1];
      if (escape === 'u') {
        const digits = this.#text.slice(this.#at + 2, this.#at + 6);
        if (!/^[0-9A-Fa-f]{4}$/.test(digits)) this.#fail('invalid \\u escape');
        out += String.fromCharCode(Number.parseInt(digits, 16));
        this.#at += 6;
      } else if (escape !== undefined && Object.hasOwn(ESCAPES, escape)) {
        out += ESCAPES[escape];
        this.#at += 2;
      } else {
        this.#fail('invalid escape');
      }
    }
    if (!out.isWellFormed()) this.#fail('string contains a lone surrogate');
    return out;
  }

  #number(): number {
    NUMBER.lastIndex = this.#at;
    const match = NUMBER.exec(this.#text);
    if (match === null) this.#fail('invalid number');
    this.#at += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) this.#fail('number outside the IEEE 754 double range');
    return value;
  }
}

/** Parse JSON text strictly (I-JSON); see the module comment for what is refused. */
export function parseJson(text: string): JsonValue {
  if (typeof text !== 'string') throw new CanonicalJsonError('JSON text must be a string');
  if (text.charCodeAt(0) === 0xfeff) throw new CanonicalJsonError('JSON text must not start with a byte order mark');
  return new Parser(text).document();
}
