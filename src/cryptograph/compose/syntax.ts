// SPDX-License-Identifier: Apache-2.0
//
// PDF syntax for the composer (T036): exact decimal numbers, names, hex strings,
// references, and the bounded conversion of the parse report's JSON values
// (src/pdf/parser.ts toJson form: names {name}, strings {hex}, references {ref},
// dictionaries {dict}) back to PDF syntax.
//
// Every number the composer computes itself is an integer in a fixed unit
// (centipoints, micropoints) and is written by `decimal`, which never uses an
// exponent and never rounds, so equal inputs always give equal text
// (determinism; CP-09). A number copied from the report is written in its
// shortest round-trip decimal form; one that would need an exponent is refused
// (PDF has no exponent syntax).
//
// The report is untrusted (A-009 LBR-4, CP-08): every value is shape-checked,
// its nesting is bounded by the parser's own depth limit, and the values of the
// whole report share one node budget, so a lying report fails closed with
// report-invalid instead of costing unbounded work.

import { reportInvalid } from './errors.ts';

/** `units / 10^scale` as an exact decimal: no exponent, no rounding, trailing zeros dropped. */
export function decimal(units: number, scale: number): string {
  if (!Number.isSafeInteger(units) || !Number.isSafeInteger(scale) || scale < 0 || scale > 12) {
    throw new RangeError('decimal() takes a safe integer and a scale of 0..12');
  }
  const digits = String(Math.abs(units)).padStart(scale + 1, '0');
  const whole = digits.slice(0, digits.length - scale);
  const fraction = digits.slice(digits.length - scale).replace(/0+$/, '');
  const text = fraction.length > 0 ? `${whole}.${fraction}` : whole;
  return units < 0 && text !== '0' ? `-${text}` : text;
}

/**
 * A finite number from the report, as a PDF number: its shortest round-trip decimal
 * form, exactly as JSON writes it. A number JavaScript would print with an exponent
 * (nonzero and below 10^-6 in magnitude, or at least 10^21) has no plain form of
 * bounded length, so it is refused (number-range): PDF has no exponent syntax, and
 * the update-size bound relies on every rewritten value being at most three times
 * its JSON size.
 */
export function reportNumber(value: number): string {
  if (!Number.isFinite(value)) throw reportInvalid('number-not-finite');
  if (Object.is(value, -0)) return '0';
  const text = String(value);
  if (text.includes('e')) throw reportInvalid('number-range');
  return text;
}

const NAME_DELIMITERS = new Set(['(', ')', '<', '>', '[', ']', '{', '}', '/', '%', '#']);

/** A PDF name from its decoded characters (each a byte, U+0001..U+00FF), escaping with #xx. */
export function pdfName(decoded: string): string {
  let out = '/';
  for (let index = 0; index < decoded.length; index += 1) {
    const code = decoded.charCodeAt(index);
    if (code === 0 || code > 0xff) throw reportInvalid('name-character');
    const char = decoded[index] ?? '';
    if (code >= 0x21 && code <= 0x7e && !NAME_DELIMITERS.has(char)) out += char;
    else out += `#${code.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return out;
}

/** A PDF hex string from lowercase hex digits. */
export function pdfHexString(hex: string): string {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) throw reportInvalid('string-not-hex');
  return `<${hex}>`;
}

export type Ref = readonly [number, number];

/** An indirect reference `n g R`. */
export function pdfRef(ref: Ref): string {
  return `${ref[0]} ${ref[1]} R`;
}

/** A reference pair from the report: object number >= 1, generation 0..65535. */
export function isRefPair(value: unknown): value is Ref {
  return (
    Array.isArray(value) &&
    value.length === 2 &&
    Number.isSafeInteger(value[0]) &&
    (value[0] as number) >= 1 &&
    Number.isSafeInteger(value[1]) &&
    (value[1] as number) >= 0 &&
    (value[1] as number) <= 65535
  );
}

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/** The single own key of a JSON-form wrapper ({name}, {hex}, {ref} or {dict}), or null. */
function wrapperKey(value: Record<string, unknown>): string | null {
  const keys = Object.keys(value);
  return keys.length === 1 ? (keys[0] ?? null) : null;
}

/** The shared budget for converting one report: nodes left and the depth ceiling. */
export interface ValueBudget {
  nodes: number;
  readonly maxDepth: number;
}

/**
 * Convert one JSON-form value to PDF syntax, checking its shape. Each value takes
 * one node from `budget`, as the parser counts them; past the budget, or deeper than
 * `budget.maxDepth`, the report is refused.
 */
export function serializeValue(value: unknown, budget: ValueBudget, depth = 0): string {
  budget.nodes -= 1;
  if (budget.nodes < 0) throw reportInvalid('report-nodes');
  if (depth > budget.maxDepth) throw reportInvalid('report-depth');
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') return reportNumber(value);
  if (Array.isArray(value)) return `[${value.map((item: unknown) => serializeValue(item, budget, depth + 1)).join(' ')}]`;
  if (!isRecord(value)) throw reportInvalid('value-shape');
  const key = wrapperKey(value);
  const inner = key === null ? undefined : value[key];
  if (key === 'name' && typeof inner === 'string') return pdfName(inner);
  if (key === 'hex' && typeof inner === 'string') return pdfHexString(inner);
  if (key === 'ref' && isRefPair(inner)) return pdfRef(inner);
  if (key === 'dict' && isRecord(inner)) {
    const parts: string[] = [];
    for (const entryKey of Object.keys(inner)) parts.push(`${pdfName(entryKey)} ${serializeValue(inner[entryKey], budget, depth + 1)}`);
    return parts.length === 0 ? '<< >>' : `<< ${parts.join(' ')} >>`;
  }
  throw reportInvalid('value-shape');
}

/** The own entries of a JSON-form dictionary, in order, or null when `value` is not one. */
export function dictEntries(value: unknown): Array<[string, unknown]> | null {
  if (!isRecord(value) || wrapperKey(value) !== 'dict') return null;
  const inner = value['dict'];
  if (!isRecord(inner)) return null;
  return Object.keys(inner).map((key): [string, unknown] => [key, inner[key]]);
}

/** The decoded name of a JSON-form name, or null. */
export function nameValue(value: unknown): string | null {
  if (!isRecord(value) || wrapperKey(value) !== 'name') return null;
  const inner = value['name'];
  return typeof inner === 'string' ? inner : null;
}

/** The reference of a JSON-form reference, or null. */
export function refValue(value: unknown): Ref | null {
  if (!isRecord(value) || wrapperKey(value) !== 'ref') return null;
  const inner = value['ref'];
  return isRefPair(inner) ? inner : null;
}

/** The value of `key` in a dictionary's entries, or undefined. */
export function entryOf(entries: ReadonlyArray<readonly [string, unknown]>, key: string): unknown {
  for (const [name, inner] of entries) if (name === key) return inner;
  return undefined;
}

/**
 * Write a dictionary from the report's entries with some entries replaced or added.
 * A replaced key keeps its position; an added key follows the existing ones in the
 * order given. `replacements` maps a key to already-serialized PDF syntax.
 */
export function rewriteDict(entries: ReadonlyArray<readonly [string, unknown]>, replacements: ReadonlyArray<readonly [string, string]>, budget: ValueBudget): string {
  const pending = new Map(replacements.map(([key, text]) => [key, text] as const));
  const parts: string[] = [];
  for (const [key, inner] of entries) {
    const replaced = pending.get(key);
    if (replaced !== undefined) {
      parts.push(`${pdfName(key)} ${replaced}`);
      pending.delete(key);
    } else {
      parts.push(`${pdfName(key)} ${serializeValue(inner, budget, 1)}`);
    }
  }
  for (const [key, text] of pending) parts.push(`${pdfName(key)} ${text}`);
  return `<< ${parts.join(' ')} >>`;
}

/** A literal PDF string from printable ASCII; parentheses and backslashes are escaped. */
export function pdfAsciiString(text: string): string {
  if (!/^[\x20-\x7e]*$/.test(text)) throw new RangeError('pdfAsciiString() takes printable ASCII');
  return `(${text.replace(/[()\\]/g, (char) => `\\${char}`)})`;
}

const SEAL_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/;

function daysInMonth(year: number, month: number): number {
  if (month === 2) return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0 ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

/**
 * The PDF date `D:YYYYMMDDHHmmSSZ` of an unsigned server time given in UTC ISO 8601
 * form (`YYYY-MM-DDTHH:mm:ss[.fraction]Z`), or null when it is not one. Fractions of
 * a second are dropped; nothing reads a clock.
 */
export function pdfDate(serverTime: string): string | null {
  const match = SEAL_TIME.exec(serverTime);
  if (match === null) return null;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month) || hour > 23 || minute > 59 || second > 59) return null;
  return `D:${match.slice(1, 7).join('')}Z`;
}

/** True for a calendar date `YYYY-MM-DD` (a server-filled date value). */
export function isCalendarDate(text: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  return year >= 1 && month >= 1 && month <= 12 && day >= 1 && day <= daysInMonth(year, month);
}
