// SPDX-License-Identifier: Apache-2.0
//
// Deterministic hand-built minimal PDFs for the T012 oracle: a one-page base
// (classic xref table, or a cross-reference stream with an object stream,
// optionally FlateDecode with the PNG Up predictor, or a hybrid table whose
// trailer carries /XRefStm), an incremental update
// carrying a /Sig dictionary with fixed-width /ByteRange and /Contents
// placeholders (same section kind as the base), and a further revision.

import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';

const EOL = '\n';
const W = [1, 4, 2];
export const DEFAULT_CONTENTS_CAPACITY = 8192; // DER bytes; 16384 hex digits
export const BASE_TEXT = 'Synthetic integrity oracle document';
export const SIGNING_DATE = 'D:20261118000000Z';
const FONT = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>';

function pad10(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`offset ${n} is not a non-negative integer`);
  const s = String(n).padStart(10, '0');
  if (s.length !== 10) throw new Error(`offset ${n} exceeds 10 digits`);
  return s;
}

const xrefEntry = (offset, gen, kind) => `${pad10(offset)} ${String(gen).padStart(5, '0')} ${kind} \n`; // 20 bytes
const fileId = (seed) => createHash('sha256').update(`opensig-oracle:${seed}`).digest('hex').slice(0, 32).toUpperCase();
const streamObject = (text) => `<< /Length ${text.length} >>${EOL}stream${EOL}${text}${EOL}endstream`;

function pageDict({ contents = '4 0 R', widget = null } = {}) {
  const annots = widget === null ? '' : ` /Annots [${widget} 0 R]`;
  return `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents ${contents}${annots} >>`;
}

class Writer {
  constructor(prefix) {
    this.chunks = prefix ? [prefix] : [];
    this.length = prefix ? prefix.length : 0;
  }

  bytes(b) {
    this.chunks.push(b);
    this.length += b.length;
  }

  text(s) {
    this.bytes(Buffer.from(s, 'latin1'));
  }

  object(num, body) {
    const offset = this.length;
    this.text(`${num} 0 obj${EOL}${body}${EOL}endobj${EOL}`);
    return offset;
  }

  build() {
    return Buffer.concat(this.chunks);
  }
}

/** PNG Up filter (predictor 12) over rows of `columns` bytes. */
export function pngUpEncode(data, columns) {
  const rows = data.length / columns;
  const out = Buffer.alloc(rows * (columns + 1));
  for (let r = 0; r < rows; r += 1) {
    out[r * (columns + 1)] = 2;
    for (let i = 0; i < columns; i += 1) {
      const up = r > 0 ? data[(r - 1) * columns + i] : 0;
      out[r * (columns + 1) + 1 + i] = (data[r * columns + i] - up) & 0xff;
    }
  }
  return out;
}

/** rows: [num, type, f1, f2] sorted by num; writes the stream as object `num`. */
function writeXrefStream(w, { num, rows, size, prev, id, flate }) {
  const offset = w.length;
  const all = [...rows, [num, 1, offset, 0]].sort((a, b) => a[0] - b[0]);
  const index = [];
  for (const [n] of all) {
    if (index.length > 0 && index[index.length - 2] + index[index.length - 1] === n) index[index.length - 1] += 1;
    else index.push(n, 1);
  }
  const data = Buffer.alloc(all.length * 7);
  all.forEach(([, type, f1, f2], k) => {
    data.writeUInt8(type, k * 7);
    data.writeUInt32BE(f1, k * 7 + 1);
    data.writeUInt16BE(f2, k * 7 + 5);
  });
  const payload = flate ? deflateSync(pngUpEncode(data, 7)) : data;
  const filter = flate ? ' /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >>' : '';
  const prevEntry = prev === null ? '' : ` /Prev ${prev}`;
  w.text(`${num} 0 obj${EOL}<< /Type /XRef /Size ${size} /W [${W.join(' ')}] /Index [${index.join(' ')}] /Root 1 0 R${prevEntry} /ID [<${id}> <${id}>]${filter} /Length ${payload.length} >>${EOL}stream${EOL}`);
  w.bytes(payload);
  w.text(`${EOL}endstream${EOL}endobj${EOL}`);
  return offset;
}

/** xref: 'table' | 'stream' | 'stream-flate' | 'hybrid'. defects (OC-08): type2StreamOverride, xrefStmDelta. */
export function buildBaseRevision({ seed = 'base', xref = 'table', defects = {} } = {}) {
  const w = new Writer();
  w.text(`%PDF-1.7${EOL}`);
  w.bytes(Buffer.from([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]));
  const off = {};
  off[1] = w.object(1, '<< /Type /Catalog /Pages 2 0 R >>');
  off[2] = w.object(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
  off[3] = w.object(3, pageDict());
  off[4] = w.object(4, streamObject(`BT /F1 12 Tf 72 720 Td (${BASE_TEXT}) Tj ET`));
  const id = fileId(seed);
  if (xref === 'table') {
    off[5] = w.object(5, FONT);
    const xrefOffset = w.length;
    w.text(`xref${EOL}0 6${EOL}${xrefEntry(0, 65535, 'f')}`);
    for (let n = 1; n <= 5; n += 1) w.text(xrefEntry(off[n], 0, 'n'));
    w.text(`trailer${EOL}<< /Size 6 /Root 1 0 R /ID [<${id}> <${id}>] >>${EOL}startxref${EOL}${xrefOffset}${EOL}%%EOF${EOL}`);
    return { bytes: w.build(), xrefOffset, id, size: 6, xrefKind: 'table', flate: false };
  }
  if (!['stream', 'stream-flate', 'hybrid'].includes(xref)) throw new Error(`unknown xref kind ${xref}`);
  const objstmData = `5 0 ${FONT}`;
  off[6] = w.object(6, `<< /Type /ObjStm /N 1 /First 4 /Length ${objstmData.length} >>${EOL}stream${EOL}${objstmData}${EOL}endstream`);
  if (xref === 'hybrid') {
    // A classic table whose trailer's /XRefStm names a cross-reference stream
    // holding the compressed object 5; the table omits object 5. defects:
    // xrefStmDelta (OC-08), type2StreamOverride.
    off[7] = writeXrefStream(w, { num: 7, rows: [[5, 2, defects.type2StreamOverride ?? 6, 0]], size: 8, prev: null, id, flate: false });
    const xrefOffset = w.length;
    w.text(`xref${EOL}0 5${EOL}${xrefEntry(0, 65535, 'f')}`);
    for (let n = 1; n <= 4; n += 1) w.text(xrefEntry(off[n], 0, 'n'));
    w.text(`6 2${EOL}${xrefEntry(off[6], 0, 'n')}${xrefEntry(off[7], 0, 'n')}`);
    const xrefStm = off[7] + (defects.xrefStmDelta ?? 0);
    w.text(`trailer${EOL}<< /Size 8 /Root 1 0 R /XRefStm ${xrefStm} /ID [<${id}> <${id}>] >>${EOL}startxref${EOL}${xrefOffset}${EOL}%%EOF${EOL}`);
    // The last section is a table, so the signature update appends a table (T036 rule).
    return { bytes: w.build(), xrefOffset, id, size: 8, xrefKind: 'table', flate: false };
  }
  const rows = [[0, 0, 0, 65535], [1, 1, off[1], 0], [2, 1, off[2], 0], [3, 1, off[3], 0], [4, 1, off[4], 0],
    [5, 2, defects.type2StreamOverride ?? 6, 0], [6, 1, off[6], 0]];
  const flate = xref === 'stream-flate';
  const xrefOffset = writeXrefStream(w, { num: 7, rows, size: 8, prev: null, id, flate });
  w.text(`startxref${EOL}${xrefOffset}${EOL}%%EOF${EOL}`);
  return { bytes: w.build(), xrefOffset, id, size: 8, xrefKind: 'stream', flate };
}

/**
 * Append the signature revision, using the base's section kind. defects
 * (OC-08) are written before signing: startxrefDelta, prevDelta, prevSelf,
 * sigXrefDelta.
 */
export function appendSignatureRevision(base, { contentsCapacity = DEFAULT_CONTENTS_CAPACITY, defects = {} } = {}) {
  const sigNum = base.size;
  const widgetNum = base.size + 1;
  const w = new Writer(base.bytes);
  const off = {};
  off[1] = w.object(1, `<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [${widgetNum} 0 R] /SigFlags 3 >> >>`);
  off[3] = w.object(3, pageDict({ widget: widgetNum }));
  off.sig = w.length;
  w.text(`${sigNum} 0 obj${EOL}<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [`);
  const byteRangeStart = w.length;
  w.text([0, 0, 0, 0].map(pad10).join(' '));
  w.text('] /Contents <');
  const contentsStart = w.length - 1; // offset of '<'
  w.text('0'.repeat(contentsCapacity * 2));
  w.text('>');
  const contentsEnd = w.length; // offset just after '>'
  w.text(` /M (${SIGNING_DATE}) >>${EOL}endobj${EOL}`);
  off.widget = w.object(widgetNum, `<< /Type /Annot /Subtype /Widget /FT /Sig /T (OracleSeal) /V ${sigNum} 0 R /F 132 /Rect [0 0 0 0] /P 3 0 R >>`);
  const sigEntry = off.sig + (defects.sigXrefDelta ?? 0);
  const prevFor = (xrefOffset) => (defects.prevSelf ? xrefOffset : base.xrefOffset + (defects.prevDelta ?? 0));
  let xrefOffset;
  let size;
  if (base.xrefKind === 'table') {
    size = widgetNum + 1;
    xrefOffset = w.length;
    w.text(`xref${EOL}1 1${EOL}${xrefEntry(off[1], 0, 'n')}3 1${EOL}${xrefEntry(off[3], 0, 'n')}`);
    w.text(`${sigNum} 2${EOL}${xrefEntry(sigEntry, 0, 'n')}${xrefEntry(off.widget, 0, 'n')}`);
    w.text(`trailer${EOL}<< /Size ${size} /Root 1 0 R /Prev ${prevFor(xrefOffset)} /ID [<${base.id}> <${base.id}>] >>${EOL}`);
  } else {
    size = widgetNum + 2;
    const rows = [[1, 1, off[1], 0], [3, 1, off[3], 0], [sigNum, 1, sigEntry, 0], [widgetNum, 1, off.widget, 0]];
    xrefOffset = writeXrefStream(w, { num: widgetNum + 1, rows, size, prev: prevFor(w.length), id: base.id, flate: base.flate });
  }
  w.text(`startxref${EOL}${xrefOffset + (defects.startxrefDelta ?? 0)}${EOL}%%EOF${EOL}`);
  return {
    bytes: w.build(), xrefOffset, id: base.id, size, widgetNum, xrefKind: base.xrefKind,
    layout: { byteRangeStart, contentsStart, contentsEnd },
  };
}

/** Byte range excluding exactly the /Contents hex string, to end of file. */
export function naturalByteRange(bytes, layout) {
  return [0, layout.contentsStart, layout.contentsEnd, bytes.length - layout.contentsEnd];
}

export function writeByteRange(bytes, layout, values) {
  if (values.length !== 4) throw new Error('a ByteRange has four integers');
  const out = Buffer.from(bytes);
  out.write(values.map(pad10).join(' '), layout.byteRangeStart, 'latin1');
  return out;
}

export function rangesOf(bytes, [o1, l1, o2, l2]) {
  if (o1 + l1 > bytes.length || o2 + l2 > bytes.length) throw new Error('ByteRange runs past the end of the file');
  return Buffer.concat([bytes.subarray(o1, o1 + l1), bytes.subarray(o2, o2 + l2)]);
}

export function embedCms(bytes, layout, der) {
  const room = layout.contentsEnd - layout.contentsStart - 2;
  const hex = Buffer.from(der).toString('hex').toUpperCase();
  if (hex.length > room) throw new Error(`CMS of ${der.length} bytes exceeds the /Contents capacity`);
  const out = Buffer.from(bytes);
  out.write(hex.padEnd(room, '0'), layout.contentsStart + 1, 'latin1');
  return out;
}

/** OC-03: a further classic incremental update after the signed revision. */
export function appendUpdateRevision(prior, variant) {
  if (prior.xrefKind !== 'table') throw new Error('OC-03 appends to a classic-table corpus document only');
  const w = new Writer(prior.bytes);
  const extra = prior.size;
  const entries = [];
  if (variant === 'page-content') {
    entries.push([extra, w.object(extra, streamObject('BT /F1 12 Tf 72 690 Td (Appended after sealing) Tj ET'))]);
    entries.push([3, w.object(3, pageDict({ contents: `[4 0 R ${extra} 0 R]`, widget: prior.widgetNum }))]);
  } else if (variant === 'info-only') {
    entries.push([extra, w.object(extra, '<< /Producer (openSig oracle appended revision) >>')]);
  } else {
    throw new Error(`unknown appended-revision variant ${variant}`);
  }
  const xrefOffset = w.length;
  w.text(`xref${EOL}`);
  for (const [num, offset] of entries.sort((a, b) => a[0] - b[0])) w.text(`${num} 1${EOL}${xrefEntry(offset, 0, 'n')}`);
  const info = variant === 'info-only' ? ` /Info ${extra} 0 R` : '';
  w.text(`trailer${EOL}<< /Size ${extra + 1} /Root 1 0 R${info} /Prev ${prior.xrefOffset} /ID [<${prior.id}> <${prior.id}>] >>${EOL}`);
  w.text(`startxref${EOL}${xrefOffset}${EOL}%%EOF${EOL}`);
  return { bytes: w.build(), xrefOffset, id: prior.id, size: extra + 1, widgetNum: prior.widgetNum, xrefKind: 'table' };
}
