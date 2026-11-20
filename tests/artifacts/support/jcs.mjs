// SPDX-License-Identifier: Apache-2.0
//
// T016 test support: a test-local RFC 8785 (JSON Canonicalization Scheme) serializer.
// It is written from RFC 8785 § 3.2 and imports nothing from src/, so PK-05's recomputation
// and the fixtures' digests cannot share a defect with src/domain/canonical/ (the tasks.md
// T016 line requires exactly that independence).
//
// - Literals: null, true and false.
// - Numbers (§ 3.2.2.3): the ECMAScript Number-to-String form; -0 is written 0, and NaN
//   and the infinities are refused.
// - Strings (§ 3.2.2.2): the two-character escapes \" \\ \b \f \n \r \t, \u00XX with
//   lowercase hex for every other code unit below 0x20, and every other character as
//   itself. A lone surrogate is refused.
// - Objects (§ 3.2.3): members sorted by their names' UTF-16 code units, which is what
//   Array.prototype.sort() compares when given no comparator.
// The output is a string; jcsBytes() gives its UTF-8 bytes.

import { createHash } from 'node:crypto';

const SHORT_ESCAPES = Object.freeze({ '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t' });
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const NEEDS_ESCAPE = /["\\\u0000-\u001f]/g;

function quote(text) {
  if (LONE_SURROGATE.test(text)) throw new TypeError('jcs: a string holds a lone surrogate');
  return `"${text.replace(NEEDS_ESCAPE, (unit) => SHORT_ESCAPES[unit] ?? `\\u${unit.charCodeAt(0).toString(16).padStart(4, '0')}`)}"`;
}

function number(value) {
  if (!Number.isFinite(value)) throw new TypeError('jcs: NaN and the infinities have no JSON form');
  return value === 0 ? '0' : value.toString();
}

/** The RFC 8785 form of a JSON value (plain objects, arrays, strings, finite numbers, booleans, null). */
export function jcs(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return number(value);
    case 'string':
      return quote(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map((item) => jcs(item)).join(',')}]`;
      const names = Object.keys(value).sort();
      return `{${names.map((name) => `${quote(name)}:${jcs(value[name])}`).join(',')}}`;
    }
    default:
      throw new TypeError(`jcs: a ${typeof value} has no JSON form`);
  }
}

export function jcsBytes(value) {
  return Buffer.from(jcs(value), 'utf8');
}

/** Lowercase hex SHA-256 of the RFC 8785 form. */
export function jcsDigest(value) {
  return createHash('sha256').update(jcsBytes(value)).digest('hex');
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
