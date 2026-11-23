// SPDX-License-Identifier: Apache-2.0
//
// RFC 8785 JSON Canonicalization Scheme (JCS), the project's single
// canonicalizer. Every digest over canonical JSON (field manifest, recipients,
// field values, approvals, audit events, receipts) is computed through this
// module; no other canonicalizer may exist in src/.
//
// Rules implemented (RFC 8785 section 3.2):
// - Literals: null, true, false.
// - Numbers: IEEE 754 doubles serialized with the ECMAScript
//   Number.prototype.toString algorithm (section 3.2.2.3); -0 becomes "0";
//   NaN and the infinities are refused.
// - Strings: '"' and '\' escaped, U+0008/09/0A/0C/0D as \b \t \n \f \r, other
//   code units below U+0020 as \u00xx with lowercase hex, everything else
//   literal (section 3.2.2.2). Lone surrogates are refused (I-JSON).
// - Objects: members sorted by their names compared as arrays of UTF-16 code
//   units (section 3.2.3); no whitespace anywhere.
// - Output is the UTF-8 encoding of the canonical text.
//
// Input must be plain JSON data: null-or-Object-prototype objects with own
// enumerable data properties, dense arrays, finite numbers, well-formed
// strings, booleans and null. Anything else (undefined, functions, symbols,
// bigint, class instances, accessors, cycles, sparse arrays) is refused rather
// than silently dropped or converted, so a digest can never cover a value
// different from the one the caller holds.

import { createHash } from 'node:crypto';

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

export class CanonicalJsonError extends Error {
  readonly code = 'canonical_json';

  constructor(message: string) {
    super(message);
    this.name = 'CanonicalJsonError';
  }
}

export const MAX_DEPTH = 256;

/** ECMAScript Number.prototype.toString, as RFC 8785 section 3.2.2.3 requires. */
export function serializeNumber(value: number): string {
  if (!Number.isFinite(value)) throw new CanonicalJsonError('NaN and Infinity are not JSON numbers');
  return Object.is(value, -0) ? '0' : String(value);
}

function hex4(code: number): string {
  return code.toString(16).padStart(4, '0');
}

/** RFC 8785 section 3.2.2.2 string serialization; refuses lone surrogates. */
export function serializeString(value: string): string {
  let out = '"';
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new CanonicalJsonError('string contains a lone high surrogate');
      out += value.slice(i, i + 2);
      i += 1;
      continue;
    }
    if (code >= 0xdc00 && code <= 0xdfff) throw new CanonicalJsonError('string contains a lone low surrogate');
    switch (code) {
      case 0x22:
        out += '\\"';
        break;
      case 0x5c:
        out += '\\\\';
        break;
      case 0x08:
        out += '\\b';
        break;
      case 0x09:
        out += '\\t';
        break;
      case 0x0a:
        out += '\\n';
        break;
      case 0x0c:
        out += '\\f';
        break;
      case 0x0d:
        out += '\\r';
        break;
      default:
        out += code < 0x20 ? `\\u${hex4(code)}` : value.charAt(i);
    }
  }
  return `${out}"`;
}

function describe(value: unknown): string {
  if (value === undefined) return 'undefined';
  if (value === null) return 'null';
  if (typeof value === 'object') return (value as object).constructor?.name ?? 'object';
  return typeof value;
}

function serializeArray(value: unknown[], depth: number, stack: Set<object>): string {
  if (Object.getPrototypeOf(value) !== Array.prototype) throw new CanonicalJsonError('arrays must be plain arrays');
  if (Object.getOwnPropertySymbols(value).length > 0) throw new CanonicalJsonError('arrays must not carry symbol properties');
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== value.length + 1) throw new CanonicalJsonError('arrays must be dense, with no extra properties');
  const parts: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined) throw new CanonicalJsonError('arrays must be dense');
    if (!('value' in descriptor)) throw new CanonicalJsonError('array elements must be data properties');
    parts.push(serializeValue(descriptor.value, depth + 1, stack));
  }
  return `[${parts.join(',')}]`;
}

function serializeObject(value: object, depth: number, stack: Set<object>): string {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new CanonicalJsonError(`objects must be plain objects, not ${describe(value)}`);
  }
  if (Object.getOwnPropertySymbols(value).length > 0) throw new CanonicalJsonError('objects must not carry symbol keys');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const names = Object.keys(descriptors);
  const members: [string, unknown][] = [];
  for (const name of names) {
    const descriptor = descriptors[name];
    if (descriptor === undefined || !descriptor.enumerable) throw new CanonicalJsonError('objects must not carry hidden properties');
    if (!('value' in descriptor)) throw new CanonicalJsonError(`member ${serializeString(name)} is an accessor`);
    members.push([name, descriptor.value]);
  }
  // Default sort compares strings by UTF-16 code units (RFC 8785 section 3.2.3).
  members.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const parts = members.map(([name, member]) => `${serializeString(name)}:${serializeValue(member, depth + 1, stack)}`);
  return `{${parts.join(',')}}`;
}

function serializeValue(value: unknown, depth: number, stack: Set<object>): string {
  if (depth > MAX_DEPTH) throw new CanonicalJsonError(`nesting deeper than ${MAX_DEPTH}`);
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return serializeNumber(value);
    case 'string':
      return serializeString(value);
    case 'object': {
      if (stack.has(value)) throw new CanonicalJsonError('cyclic structure');
      stack.add(value);
      try {
        return Array.isArray(value) ? serializeArray(value, depth, stack) : serializeObject(value, depth, stack);
      } finally {
        stack.delete(value);
      }
    }
    default:
      throw new CanonicalJsonError(`${describe(value)} is not a JSON value`);
  }
}

/** The RFC 8785 canonical text of `value`. */
export function canonicalize(value: unknown): string {
  return serializeValue(value, 0, new Set());
}

/** The UTF-8 bytes of the canonical text. */
export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}

/** Lowercase hex SHA-256 of the canonical bytes. */
export function canonicalDigest(value: unknown): string {
  return createHash('sha256').update(canonicalBytes(value)).digest('hex');
}
