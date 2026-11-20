// SPDX-License-Identifier: Apache-2.0
//
// Stream decoding for the structural streams the parser must read: cross-reference
// streams and object streams (T033). Only no filter or a single /FlateDecode, with an
// optional PNG predictor, is supported. Inflation is bounded twice: per stream by the
// decompression ratio, and across the document by the total inflated-byte budget. Both
// are enforced through zlib's maxOutputLength, so a decompression bomb never allocates
// more than the remaining allowance.

import { inflateSync } from 'node:zlib';

import { limitExceeded, malformed, ParseFailure } from './errors.ts';
import { isDict, isName, type PdfDict, type PdfValue } from './lexer.ts';

export interface InflateBudget {
  readonly maxRatio: number;
  /** Bytes that may still be inflated across the document. */
  remaining: number;
  /** Bytes inflated so far. */
  inflated: number;
  /** Streams decoded so far. */
  decoded: number;
}

export function createBudget(maxRatio: number, maxInflatedBytes: number): InflateBudget {
  return { maxRatio, remaining: maxInflatedBytes, inflated: 0, decoded: 0 };
}

function filterNames(dict: PdfDict): string[] {
  const filter = dict.map.get('Filter');
  if (filter === undefined || filter === null) return [];
  if (isName(filter)) return [filter.v];
  if (Array.isArray(filter) && filter.every((item) => isName(item))) return filter.map((item) => (item as { v: string }).v);
  throw malformed('stream /Filter is neither a name nor an array of names');
}

function decodeParms(dict: PdfDict): PdfDict | null {
  const parms = dict.map.get('DecodeParms');
  if (parms === undefined || parms === null) return null;
  if (isDict(parms)) return parms;
  if (Array.isArray(parms) && parms.length === 1) {
    const only: PdfValue | undefined = parms[0];
    if (only === null) return null;
    if (isDict(only)) return only;
  }
  throw malformed('stream /DecodeParms is not a dictionary');
}

function intParam(parms: PdfDict, key: string, fallback: number): number {
  const value = parms.map.get(key);
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) throw malformed(`invalid /${key} in /DecodeParms`);
  return value;
}

function inflate(raw: Uint8Array, budget: InflateBudget): Uint8Array {
  const ratioCap = Math.max(raw.length, 1) * budget.maxRatio;
  const cap = Math.min(ratioCap, budget.remaining);
  const binding = budget.remaining < ratioCap ? 'inflated-bytes' : 'decompression-ratio';
  let out: Uint8Array;
  try {
    out = inflateSync(raw, { maxOutputLength: cap + 1 });
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    if (error instanceof RangeError || code === 'ERR_BUFFER_TOO_LARGE') throw limitExceeded(binding);
    throw malformed('invalid FlateDecode data in a structural stream');
  }
  if (out.length > cap) throw limitExceeded(binding);
  budget.remaining -= out.length;
  budget.inflated += out.length;
  return out;
}

/** Undo a PNG predictor (/Predictor 10..15) for 8-bit components. */
function unpredictPng(data: Uint8Array, parms: PdfDict): Uint8Array {
  const colors = intParam(parms, 'Colors', 1);
  const bits = intParam(parms, 'BitsPerComponent', 8);
  const columns = intParam(parms, 'Columns', 1);
  if (bits !== 8 || colors < 1 || colors > 4 || columns < 1) throw new ParseFailure('unsupported-feature', 'PNG predictor parameters');
  const bpp = colors;
  const rowLength = columns * colors;
  if (data.length % (rowLength + 1) !== 0) throw malformed('PNG predictor data is not a whole number of rows');
  const rows = data.length / (rowLength + 1);
  const out = new Uint8Array(rows * rowLength);
  for (let row = 0; row < rows; row += 1) {
    const type = data[row * (rowLength + 1)] ?? 0;
    const src = row * (rowLength + 1) + 1;
    const dst = row * rowLength;
    for (let i = 0; i < rowLength; i += 1) {
      const raw = data[src + i] ?? 0;
      const left = i >= bpp ? (out[dst + i - bpp] ?? 0) : 0;
      const up = row > 0 ? (out[dst - rowLength + i] ?? 0) : 0;
      const upLeft = row > 0 && i >= bpp ? (out[dst - rowLength + i - bpp] ?? 0) : 0;
      let value: number;
      if (type === 0) value = raw;
      else if (type === 1) value = raw + left;
      else if (type === 2) value = raw + up;
      else if (type === 3) value = raw + Math.floor((left + up) / 2);
      else if (type === 4) {
        const p = left + up - upLeft;
        const pa = Math.abs(p - left);
        const pb = Math.abs(p - up);
        const pc = Math.abs(p - upLeft);
        value = raw + (pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft);
      } else throw malformed('invalid PNG predictor row type');
      out[dst + i] = value & 0xff;
    }
  }
  return out;
}

/** Decode a structural stream (cross-reference or object stream). */
export function decodeStructuralStream(dict: PdfDict, raw: Uint8Array, budget: InflateBudget): Uint8Array {
  const filters = filterNames(dict);
  budget.decoded += 1;
  if (filters.length === 0) return raw;
  if (filters.length > 1 || filters[0] !== 'FlateDecode') {
    throw new ParseFailure('unsupported-feature', 'structural stream filter other than a single /FlateDecode');
  }
  const inflated = inflate(raw, budget);
  const parms = decodeParms(dict);
  if (parms === null) return inflated;
  const predictor = intParam(parms, 'Predictor', 1);
  if (predictor === 1) return inflated;
  if (predictor >= 10 && predictor <= 15) return unpredictPng(inflated, parms);
  throw new ParseFailure('unsupported-feature', 'stream predictor other than PNG');
}

/** Filter names of any stream (used for feature detection such as JBIG2 and JPX). */
export function streamFilterNames(dict: PdfDict): string[] {
  try {
    return filterNames(dict);
  } catch {
    return [];
  }
}

