// SPDX-License-Identifier: Apache-2.0
//
// Cross-reference stream reading for the T012 oracle (A-010, request #39):
// uncompressed or /FlateDecode data, with no predictor or a PNG predictor
// (10..15; each row's filter byte governs). Uses only the node:zlib built-in.

import { inflateSync } from 'node:zlib';
import { WS, directInt, fail, readObjectDict, readStreamData, scanDictEnd } from './pdf-lex.mjs';

const MAX_INFLATED = 32 * 1024 * 1024;

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

/** Undo PNG row filters (one byte per pixel); rejects unknown filter bytes. */
export function pngUnfilter(data, columns) {
  const rowLength = columns + 1;
  if (columns < 1 || data.length % rowLength !== 0) return fail('xref-predictor-row-length');
  const rows = data.length / rowLength;
  const out = Buffer.alloc(rows * columns);
  for (let r = 0; r < rows; r += 1) {
    const type = data[r * rowLength];
    if (type > 4) return fail('xref-predictor-invalid');
    for (let i = 0; i < columns; i += 1) {
      const left = i > 0 ? out[r * columns + i - 1] : 0;
      const up = r > 0 ? out[(r - 1) * columns + i] : 0;
      const upLeft = r > 0 && i > 0 ? out[(r - 1) * columns + i - 1] : 0;
      const add = [0, left, up, (left + up) >> 1, paeth(left, up, upLeft)][type];
      out[r * columns + i] = (data[r * rowLength + 1 + i] + add) & 0xff;
    }
  }
  return { ok: true, data: out };
}

function decode(dict, raw) {
  const filter = new RegExp(`/Filter${WS}*(/[A-Za-z0-9]+|\\[)`).exec(dict);
  let data = raw;
  if (filter) {
    if (filter[1] !== '/FlateDecode') return fail('xref-stream-filter-unsupported');
    try {
      data = inflateSync(raw, { maxOutputLength: MAX_INFLATED });
    } catch {
      return fail('xref-stream-inflate-failed');
    }
  }
  const parmsAt = new RegExp(`/DecodeParms${WS}*<<`).exec(dict);
  if (!parmsAt) return { ok: true, data };
  if (!filter) return fail('xref-stream-parms-without-filter');
  const start = parmsAt.index + parmsAt[0].length - 2;
  const parmsEnd = scanDictEnd(dict, start);
  if (parmsEnd < 0) return fail('xref-stream-parms-unterminated');
  const parms = dict.slice(start, parmsEnd);
  const predictor = directInt(parms, 'Predictor') ?? 1;
  if ((directInt(parms, 'Colors') ?? 1) !== 1 || (directInt(parms, 'BitsPerComponent') ?? 8) !== 8) {
    return fail('xref-predictor-unsupported');
  }
  if (predictor === 1) return { ok: true, data };
  if (predictor < 10 || predictor > 15) return fail('xref-predictor-unsupported');
  return pngUnfilter(data, directInt(parms, 'Columns') ?? 1);
}

function field(data, at, width) {
  let v = 0;
  for (let i = 0; i < width; i += 1) v = v * 256 + data[at + i];
  return v;
}

/** One cross-reference stream section at `offset`. */
export function parseXrefStream(s, offset) {
  const obj = readObjectDict(s, offset);
  if (!obj.ok) return obj;
  if (!new RegExp(`/Type${WS}*/XRef(?![A-Za-z0-9])`).test(obj.dict)) return fail('xref-stream-not-type-xref');
  const stream = readStreamData(s, obj);
  if (!stream.ok) return stream;
  const w = new RegExp(`/W${WS}*\\[${WS}*(\\d+)${WS}+(\\d+)${WS}+(\\d+)${WS}*\\]`).exec(obj.dict);
  const size = directInt(obj.dict, 'Size');
  if (!w || size === null) return fail('xref-stream-dictionary');
  const widths = w.slice(1, 4).map(Number);
  if (widths.some((x) => x > 6) || widths[1] === 0) return fail('xref-stream-width');
  const idx = new RegExp(`/Index${WS}*\\[([0-9\\r\\n\\t ]*)\\]`).exec(obj.dict);
  const index = idx ? idx[1].trim().split(/[\r\n\t ]+/).filter(Boolean).map(Number) : [0, size];
  if (index.length % 2 !== 0) return fail('xref-stream-index');
  const decoded = decode(obj.dict, stream.data);
  if (!decoded.ok) return decoded;
  const rowWidth = widths[0] + widths[1] + widths[2];
  let count = 0;
  for (let k = 1; k < index.length; k += 2) count += index[k];
  if (decoded.data.length !== count * rowWidth) return fail('xref-stream-length-mismatch');
  const entries = [];
  let at = 0;
  for (let k = 0; k < index.length; k += 2) {
    for (let n = 0; n < index[k + 1]; n += 1) {
      const type = widths[0] === 0 ? 1 : field(decoded.data, at, widths[0]);
      const f1 = field(decoded.data, at + widths[0], widths[1]);
      const f2 = field(decoded.data, at + widths[0] + widths[1], widths[2]);
      at += rowWidth;
      const num = index[k] + n;
      if (type === 0) entries.push({ num, kind: 'f' });
      else if (type === 1) entries.push({ num, kind: 'n', offset: f1, gen: f2 });
      else if (type === 2) entries.push({ num, kind: 'c', objstm: f1, index: f2 });
      else return fail('xref-stream-entry-type');
    }
  }
  return { ok: true, entries, prev: directInt(obj.dict, 'Prev'), selfNum: obj.num, tailFrom: stream.end };
}
