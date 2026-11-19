// SPDX-License-Identifier: Apache-2.0
//
// T014's own minimal PDF builder for the verifier's unit tests. It is written
// for these tests alone and shares nothing with the oracle's builder or with
// src/cryptograph/compose/. Every document is synthetic: one page of fixed
// text, built at test time from structural descriptions.
//
// A "doc" is { bytes, kind, startxref, size, root }: `kind` is the kind of the
// last cross-reference section ('table' or 'stream'), which an update repeats.

import { Buffer } from 'node:buffer';
import { deflateSync } from 'node:zlib';

class Writer {
  constructor(prefix) {
    this.parts = prefix === undefined ? [] : [Buffer.from(prefix)];
    this.length = prefix === undefined ? 0 : prefix.length;
  }

  write(chunk) {
    const b = typeof chunk === 'string' ? Buffer.from(chunk, 'latin1') : Buffer.from(chunk);
    this.parts.push(b);
    this.length += b.length;
    return this;
  }

  get offset() {
    return this.length;
  }

  bytes() {
    return Buffer.concat(this.parts);
  }
}

const OBJ1 = '<< /Type /Catalog /Pages 2 0 R >>';
const OBJ2 = '<< /Type /Pages /Kids [3 0 R] /Count 1 >>';
const OBJ3 =
  '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ' +
  '/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Contents 4 0 R >>';
const CONTENT = 'BT /F1 12 Tf 72 720 Td (synthetic verifier fixture) Tj ET';

export const pad10 = (n) => String(n).padStart(10, '0');
const tableEntry = (offset, gen, kind) => `${pad10(offset)} ${String(gen).padStart(5, '0')} ${kind} \n`;

/** Rows of big-endian fields, one row per [type, field2, field3]. */
export function xrefRows(entries, widths) {
  const row = widths[0] + widths[1] + widths[2];
  const out = Buffer.alloc(entries.length * row);
  entries.forEach((fields, r) => {
    let p = r * row;
    fields.forEach((value, f) => {
      for (let i = widths[f] - 1; i >= 0; i -= 1) out[p + i] = Math.floor(value / 256 ** (widths[f] - 1 - i)) % 256;
      p += widths[f];
    });
  });
  return out;
}

function paeth(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

/**
 * PNG-predict `data` in rows of `columns` bytes; filters[r] picks each row's
 * filter (default Up); `bpp` is the bytes per pixel (/Colors at 8 bits).
 */
export function pngEncode(data, columns, filters = [], bpp = 1) {
  const rows = data.length / columns;
  const out = Buffer.alloc(rows * (columns + 1));
  for (let r = 0; r < rows; r += 1) {
    const filter = filters[r] ?? 2;
    out[r * (columns + 1)] = filter;
    for (let i = 0; i < columns; i += 1) {
      const x = data[r * columns + i];
      const left = i >= bpp ? data[r * columns + i - bpp] : 0;
      const up = r > 0 ? data[(r - 1) * columns + i] : 0;
      const upLeft = i >= bpp && r > 0 ? data[(r - 1) * columns + i - bpp] : 0;
      let v = x;
      if (filter === 1) v = x - left;
      else if (filter === 2) v = x - up;
      else if (filter === 3) v = x - ((left + up) >> 1);
      else if (filter === 4) v = x - paeth(left, up, upLeft);
      out[r * (columns + 1) + 1 + i] = v & 0xff;
    }
  }
  return out;
}

/** The object stream holding objects 1 to 3, as text (a deflated body is carried as latin1). */
function objectStream(options) {
  // objStmTight: object 1's value is `true` (a regular byte) and the header has
  // no trailing space, so its last offset runs right up to /First.
  const first = options.objStmTight ? 'true' : OBJ1;
  const o2 = first.length + 1;
  const o3 = o2 + OBJ2.length + 1;
  const nums = [1, 2, 3];
  if (options.objStmHeaderOverride) nums[options.objStmHeaderOverride.index] = options.objStmHeaderOverride.num;
  let header = `${nums[0]} 0 ${nums[1]} ${o2} ${nums[2]} ${o3}${options.objStmTight ? '' : ' '}`;
  let data = `${header}${first} ${OBJ2} ${OBJ3}`;
  if (options.objStmAdjacent) {
    // Objects 7 (`12`) and 8 (`true`) with no byte between them: object 7 ends
    // at object 8's header offset (T033's readCompressed; request #60 (1)).
    const o7 = o3 + OBJ3.length + 1;
    header = `${nums[0]} 0 ${nums[1]} ${o2} ${nums[2]} ${o3} 7 ${o7} 8 ${o7 + 2} `;
    data = `${header}${first} ${OBJ2} ${OBJ3} 12true`;
  }
  const body = options.objStmFlate ? deflateSync(Buffer.from(data, 'latin1')).toString('latin1') : data;
  let filter = options.objStmFlate ? ' /Filter /FlateDecode' : '';
  if (options.objStmFilterName) filter = ` /Filter /${options.objStmFilterName}`;
  const length = options.objStmIndirectLength ? `7 ${options.objStmLengthRefGen ?? 0} R` : String(body.length);
  const count = options.objStmCount ?? (options.objStmAdjacent ? 5 : 3);
  const text = `<< /Type /ObjStm /N ${count} /First ${header.length} /Length ${length}${filter} >>\nstream\n${body}\nendstream`;
  return { text, bodyLength: body.length };
}

function contentObject() {
  return `<< /Length ${CONTENT.length} >>\nstream\n${CONTENT}\nendstream`;
}

/**
 * A one-page base. options:
 * - xref: 'table' (default), 'stream', 'stream-flate' or 'hybrid';
 * - pngRowFilters: the PNG filter byte of each row (stream-flate);
 * - type2StreamOverride / hiddenType2StreamOverride: object number written as
 *   the object stream of the compressed entries (in the stream, or the hybrid's
 *   hidden stream);
 * - type2IndexOverride: { num, index } written as one compressed entry's index
 *   in its object stream (stream and hybrid bases; the stream's /N is 3);
 * - objStmHeaderOverride: { index, num } written as the object number of one
 *   header pair of the object stream (stream and hybrid bases);
 * - objStmFlate: the object stream's data FlateDecoded (stream and hybrid);
 * - objStmCount: the /N written for the object stream (default 3, its pair count);
 * - objStmTight: object 1's value is `true` and the header ends at /First with
 *   no space, so its last offset runs right up to a regular byte;
 * - objStmFilterName: the object stream's /Filter name (data left as it is);
 * - xrefWidths: the cross-reference stream's /W (stream bases; default [1 4 2]);
 * - xrefPng: { colors, columns } for the PNG predictor (stream-flate; default
 *   one colour, one row per entry);
 * - xrefDictExtra: text added to the cross-reference stream dictionary (stream);
 * - hiddenShadowsInUse: the hybrid's hidden stream also lists object 4;
 * - objStmLengthRefGen: the generation written in objStmIndirectLength's
 *   `7 g R` (object 7's entry keeps generation 0);
 * - objStmAdjacent: two more compressed objects, 7 (`12`) and 8 (`true`), with
 *   no byte between them (stream bases);
 * - hiddenStreamPadding: white-space before the hybrid's hidden stream header,
 *   which /XRefStm names (the doc's xrefStm gives that offset);
 * - hiddenFreeRows: that many free rows for objects 10 onward in the hybrid's
 *   hidden stream, FlateDecoded with /W [6 6 6] (18 inflated bytes a row);
 * - objStmIndirectLength: the object stream's /Length as `7 0 R`, object 7
 *   holding it (stream bases only; /Size becomes 8);
 * - xrefStmDelta, startxrefDelta: added to the written offsets;
 * - entryDelta: { num, delta } added to one in-use entry's offset;
 * - trailingBytes: text appended after the final %%EOF;
 * - contentPadding: spaces added to the content stream (table bases only);
 * - tableStyle: 'records' (20-byte entries, the default) or 'tokens' (T033's
 *   token form: E1's comment after `xref`, comments between tokens, leading
 *   zeros; table bases only);
 * - commentBeforeObjects, pointAtComment: a comment line before each object
 *   header, and in-use entries naming the comment instead of the header
 *   (table bases only). A negative startxrefDelta, xrefStmDelta or entryDelta
 *   names the white-space before a section or header (E2's shape);
 * - commentPadding: bytes ('.') added to the comment before object 1 (with
 *   commentBeforeObjects), so one skipped run can fill nearly the whole file.
 */
export function buildBase(options = {}) {
  const xref = options.xref ?? 'table';
  const delta = (num) => (options.entryDelta?.num === num ? options.entryDelta.delta : 0);
  const index = (num, i) => (options.type2IndexOverride?.num === num ? options.type2IndexOverride.index : i);
  const w = new Writer();
  w.write('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n');
  if (xref === 'table') {
    const offsets = [];
    // An optional comment line before each header; entries may name it (pointAtComment).
    const beforeHeader = (num) => {
      const at = w.offset;
      if (options.commentBeforeObjects) {
        w.write('% a synthetic note before the object header');
        if (num === 1 && options.commentPadding) w.write(Buffer.alloc(options.commentPadding, 0x2e));
        w.write('\n');
      }
      return options.pointAtComment ? at : w.offset;
    };
    for (const [num, text] of [[1, OBJ1], [2, OBJ2], [3, OBJ3]]) {
      offsets[num] = beforeHeader(num);
      w.write(`${num} 0 obj\n${text}\nendobj\n`);
    }
    // The content stream, optionally padded with spaces (written as a Buffer) to reach an exact size.
    const padding = options.contentPadding ?? 0;
    offsets[4] = beforeHeader(4);
    w.write(`4 0 obj\n<< /Length ${CONTENT.length + padding} >>\nstream\n${CONTENT}`);
    if (padding > 0) w.write(Buffer.alloc(padding, 0x20));
    w.write('\nendstream\nendobj\n');
    const xrefAt = w.offset;
    if (options.tableStyle === 'tokens') {
      // T033's token form: a comment directly after `xref` (E1), comments and
      // mixed white-space between the tokens, and 15-digit leading-zero offsets.
      w.write('xref% a comment directly after the keyword\n');
      w.write('0\t5 % the subsection header\r\n');
      w.write(`${'0'.repeat(15)} 65535 f\n`);
      for (let num = 1; num <= 4; num += 1) {
        w.write(`${String(offsets[num] + delta(num)).padStart(15, '0')}  00000\tn % entry ${num}\r\n`);
      }
    } else {
      w.write('xref\n0 5\n');
      w.write(tableEntry(0, 65535, 'f'));
      for (let num = 1; num <= 4; num += 1) w.write(tableEntry(offsets[num] + delta(num), 0, 'n'));
    }
    w.write(`trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n${xrefAt + (options.startxrefDelta ?? 0)}\n%%EOF\n`);
    if (options.trailingBytes) w.write(options.trailingBytes);
    return { bytes: w.bytes(), kind: 'table', startxref: xrefAt, size: 5, root: '1 0 R' };
  }
  const off4 = w.offset;
  w.write(`4 0 obj\n${contentObject()}\nendobj\n`);
  const off5 = w.offset;
  const stmObject = objectStream(options);
  w.write(`5 0 obj\n${stmObject.text}\nendobj\n`);
  let off7 = null;
  if (options.objStmIndirectLength) {
    if (xref === 'hybrid' || options.objStmAdjacent) throw new Error('objStmIndirectLength is for stream bases without objStmAdjacent');
    off7 = w.offset;
    w.write(`7 0 obj\n${stmObject.bodyLength}\nendobj\n`);
  }
  // hiddenStreamPadding: white-space before the hybrid's hidden stream header,
  // and /XRefStm names the start of that white-space.
  const paddingAt = w.offset;
  if (xref === 'hybrid' && options.hiddenStreamPadding) w.write(Buffer.alloc(options.hiddenStreamPadding, 0x20));
  const off6 = w.offset;
  const widths = [1, 4, 2];
  if (xref === 'hybrid') {
    const stm = options.hiddenType2StreamOverride ?? 5;
    const hiddenRows = [[2, stm, index(1, 0)], [2, stm, index(2, 1)], [2, stm, index(3, 2)]];
    // hiddenShadowsInUse: the hidden stream also lists object 4, in use in the
    // table, as compressed in object 4 (not an object stream); the table's
    // in-use entry must win (B1 (c)).
    if (options.hiddenShadowsInUse) hiddenRows.push([2, 4, 0]);
    let rows = xrefRows(hiddenRows, widths);
    let hiddenDict = `/Size 7 /W [1 4 2] /Index [1 ${hiddenRows.length}]`;
    if (options.hiddenFreeRows) {
      // hiddenFreeRows: that many free rows (all zero, /W [6 6 6]) for objects
      // 10 onward, FlateDecoded, so each decode of the hidden stream inflates
      // 18 bytes per row.
      const wide = [6, 6, 6];
      rows = deflateSync(Buffer.concat([xrefRows(hiddenRows, wide), Buffer.alloc(options.hiddenFreeRows * 18)]));
      hiddenDict = `/Size ${10 + options.hiddenFreeRows} /W [6 6 6] /Index [1 ${hiddenRows.length} 10 ${options.hiddenFreeRows}] /Filter /FlateDecode`;
    }
    w.write(`6 0 obj\n<< /Type /XRef ${hiddenDict} /Length ${rows.length} >>\nstream\n`);
    w.write(rows);
    w.write('\nendstream\nendobj\n');
    const xrefAt = w.offset;
    w.write('xref\n0 7\n');
    w.write(tableEntry(0, 65535, 'f'));
    for (let num = 1; num <= 3; num += 1) w.write(tableEntry(0, 0, 'f'));
    w.write(tableEntry(off4 + delta(4), 0, 'n'));
    w.write(tableEntry(off5 + delta(5), 0, 'n'));
    w.write(tableEntry(off6 + delta(6), 0, 'n'));
    const xrefStm = options.hiddenStreamPadding ? paddingAt : off6 + (options.xrefStmDelta ?? 0);
    w.write(`trailer\n<< /Size 7 /Root 1 0 R /XRefStm ${xrefStm} >>\n`);
    w.write(`startxref\n${xrefAt + (options.startxrefDelta ?? 0)}\n%%EOF\n`);
    if (options.trailingBytes) w.write(options.trailingBytes);
    return { bytes: w.bytes(), kind: 'table', startxref: xrefAt, size: 7, root: '1 0 R', xrefStm };
  }
  const stm = options.type2StreamOverride ?? 5;
  const entries = [
    [0, 0, 65535],
    [2, stm, index(1, 0)],
    [2, stm, index(2, 1)],
    [2, stm, index(3, 2)],
    [1, off4 + delta(4), 0],
    [1, off5 + delta(5), 0],
    [1, off6 + delta(6), 0],
  ];
  if (off7 !== null) entries.push([1, off7, 0]);
  if (options.objStmAdjacent) entries.push([2, stm, 3], [2, stm, 4]);
  const size = entries.length;
  const streamWidths = options.xrefWidths ?? widths;
  const rowWidth = streamWidths[0] + streamWidths[1] + streamWidths[2];
  let body = xrefRows(entries, streamWidths);
  let filter = options.xrefDictExtra ?? '';
  if (xref === 'stream-flate') {
    const png = options.xrefPng ?? { colors: 1, columns: rowWidth };
    body = deflateSync(pngEncode(body, png.colors * png.columns, options.pngRowFilters ?? [], png.colors));
    const parms = png.colors === 1 ? `/Columns ${png.columns}` : `/Colors ${png.colors} /Columns ${png.columns}`;
    filter = ` /Filter /FlateDecode /DecodeParms << /Predictor 12 ${parms} >>`;
  }
  const w0 = `[${streamWidths.join(' ')}]`;
  w.write(`6 0 obj\n<< /Type /XRef /Size ${size} /W ${w0} /Root 1 0 R /Length ${body.length}${filter} >>\nstream\n`);
  w.write(body);
  w.write(`\nendstream\nendobj\nstartxref\n${off6 + (options.startxrefDelta ?? 0)}\n%%EOF\n`);
  if (options.trailingBytes) w.write(options.trailingBytes);
  return { bytes: w.bytes(), kind: 'stream', startxref: off6, size, root: '1 0 R' };
}

function endsWithEol(bytes) {
  const last = bytes[bytes.length - 1];
  return last === 0x0a || last === 0x0d;
}

/**
 * Append one incremental update holding `objects` ([{ num, text }]), with a
 * cross-reference section of the doc's kind. options.prevDelta and
 * options.startxrefDelta are added to the written /Prev and startxref.
 */
export function appendUpdate(doc, objects, options = {}) {
  const w = new Writer(doc.bytes);
  if (!endsWithEol(doc.bytes)) w.write('\n');
  const sorted = [...objects].sort((a, b) => a.num - b.num);
  const offsets = new Map();
  for (const { num, text } of sorted) {
    offsets.set(num, w.offset);
    w.write(`${num} 0 obj\n${text}\nendobj\n`);
  }
  const prev = doc.startxref + (options.prevDelta ?? 0);
  const size = Math.max(doc.size, ...sorted.map((o) => o.num + 1));
  if (doc.kind === 'table') {
    const xrefAt = w.offset;
    w.write('xref\n');
    for (const { num } of sorted) w.write(`${num} 1\n${tableEntry(offsets.get(num), 0, 'n')}`);
    w.write(`trailer\n<< /Size ${size} /Root ${doc.root} /Prev ${prev}${options.trailerExtra ?? ''} >>\nstartxref\n${xrefAt + (options.startxrefDelta ?? 0)}\n%%EOF\n`);
    return { bytes: w.bytes(), kind: 'table', startxref: xrefAt, size, root: doc.root };
  }
  const xnum = size;
  const xrefAt = w.offset;
  const rows = xrefRows([...sorted.map(({ num }) => [1, offsets.get(num), 0]), [1, xrefAt, 0]], [1, 4, 2]);
  const index = [...sorted.map(({ num }) => `${num} 1`), `${xnum} 1`].join(' ');
  w.write(`${xnum} 0 obj\n<< /Type /XRef /Size ${xnum + 1} /W [1 4 2] /Index [${index}] /Root ${doc.root} /Prev ${prev} /Length ${rows.length} >>\nstream\n`);
  w.write(rows);
  w.write(`\nendstream\nendobj\nstartxref\n${xrefAt + (options.startxrefDelta ?? 0)}\n%%EOF\n`);
  return { bytes: w.bytes(), kind: 'stream', startxref: xrefAt, size: xnum + 1, root: doc.root };
}

/** A doc description of existing bytes (for appending to a sealed corpus or product file). */
export function docFromBytes(bytes) {
  const buf = Buffer.from(bytes);
  const kw = buf.lastIndexOf('startxref');
  const startxref = Number(/startxref\s+(\d+)/.exec(buf.subarray(kw).toString('latin1'))[1]);
  const section = buf.subarray(startxref).toString('latin1');
  const kind = section.startsWith('xref') ? 'table' : 'stream';
  const size = Number(/\/Size\s+(\d+)/.exec(section)[1]);
  const root = /\/Root\s+(\d+\s+\d+\s+R)/.exec(section)[1];
  return { bytes: buf, kind, startxref, size, root };
}

/** Append a metadata-only revision after the last one (the OC-03-b class). */
export function appendInfoRevision(bytes) {
  const doc = docFromBytes(bytes);
  return appendUpdate(doc, [{ num: doc.size, text: '<< /Producer (opensig synthetic info revision) >>' }]).bytes;
}

const PLACEHOLDER = '[0000000000 0000000000 0000000000 0000000000]';

/**
 * Append a signature revision with a fixed-width /ByteRange and a /Contents of
 * `hexDigits` zeros. options.byteRange({ l1, o2, length }) may return a
 * deliberately wrong range for negative tests. Returns the layout.
 */
export function appendSignaturePlaceholder(doc, options = {}) {
  const hexDigits = options.hexDigits ?? 16384;
  const num = doc.size;
  const text =
    `<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange ${PLACEHOLDER} ` +
    `/Contents <${'0'.repeat(hexDigits)}> /M (D:20261118000000Z)${options.sigDictExtra ?? ''} >>`;
  // options.extraObjects(num): more objects for the same revision, numbered after the signature.
  const extra = options.extraObjects ? options.extraObjects(num) : [];
  const updated = appendUpdate(doc, [{ num, text }, ...extra], options);
  const bytes = Buffer.from(updated.bytes);
  const objectAt = bytes.lastIndexOf(`\n${num} 0 obj`);
  const rangeAt = bytes.indexOf(PLACEHOLDER, objectAt);
  const lt = bytes.indexOf('/Contents <', objectAt) + '/Contents '.length;
  const o2 = lt + hexDigits + 2;
  const natural = [0, lt, o2, bytes.length - o2];
  const range = options.byteRange ? options.byteRange({ l1: lt, o2, length: bytes.length }) : natural;
  bytes.write(`[${range.map(pad10).join(' ')}]`, rangeAt, 'latin1');
  return { ...updated, bytes, byteRange: range, contentsStart: lt, contentsEnd: o2, hexDigits };
}

/**
 * Append one update whose cross-reference section is a stream with the given
 * /W and rows: `objects` ([{ num, text }]) are written first, then the stream
 * object numbered `xnum` (default doc.size) with /Index from `groups`
 * ([{ first, rows: [[type, field2, field3], ...] }]), or from `rowsFor`, called
 * with the written offsets and the stream's own offset.
 */
export function appendXrefStreamSection(doc, { objects = [], widths, groups, rowsFor, xnum = doc.size }) {
  const w = new Writer(doc.bytes);
  if (!endsWithEol(doc.bytes)) w.write('\n');
  const offsets = new Map();
  for (const { num, text } of objects) {
    offsets.set(num, w.offset);
    w.write(`${num} 0 obj\n${text}\nendobj\n`);
  }
  const xrefAt = w.offset;
  const list = groups ?? rowsFor(offsets, xrefAt);
  const index = list.map((g) => `${g.first} ${g.rows.length}`).join(' ');
  const body = Buffer.concat(list.map((g) => xrefRows(g.rows, widths)));
  const size = Math.max(doc.size, xnum + 1, ...list.map((g) => g.first + g.rows.length));
  w.write(`${xnum} 0 obj\n<< /Type /XRef /Size ${size} /W [${widths.join(' ')}] /Index [${index}] /Root ${doc.root} /Prev ${doc.startxref} /Length ${body.length} >>\nstream\n`);
  w.write(body);
  w.write(`\nendstream\nendobj\nstartxref\n${xrefAt}\n%%EOF\n`);
  return { bytes: w.bytes(), kind: 'stream', startxref: xrefAt, size, root: doc.root };
}

/** The bytes the stated ranges cover, in order. */
export function signedContent(layout) {
  const [o1, l1, o2, l2] = layout.byteRange;
  return Buffer.concat([layout.bytes.subarray(o1, o1 + l1), layout.bytes.subarray(o2, o2 + l2)]);
}

/** Write the CMS as lowercase hex over the placeholder's leading zeros. */
export function embedCms(layout, der) {
  const hex = Buffer.from(der).toString('hex');
  if (hex.length > layout.hexDigits) throw new Error('the CMS is larger than the placeholder');
  const bytes = Buffer.from(layout.bytes);
  bytes.write(hex, layout.contentsStart + 1, 'latin1');
  return bytes;
}
