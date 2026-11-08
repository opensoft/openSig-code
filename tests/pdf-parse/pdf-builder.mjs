// SPDX-License-Identifier: Apache-2.0
//
// Builders for synthetic structural PDF variants used by the parser-limits tests (T033).
// Every document is generated at test runtime from a structural description; nothing is
// downloaded or committed. Written independently of src/pdf/.

import { deflateSync } from 'node:zlib';

const BINARY_COMMENT = Buffer.from([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]);

const bytes = (value) => (typeof value === 'string' ? Buffer.from(value, 'latin1') : value);

/** An uncompressed (or pre-encoded) stream object body. */
export function streamObject(dictEntries, data) {
  const payload = bytes(data);
  return Buffer.concat([bytes(`<< ${dictEntries ? `${dictEntries} ` : ''}/Length ${payload.length} >>\nstream\n`), payload, bytes('\nendstream')]);
}

/** Catalog (1), page tree root (2) and one page (3), with optional extra entries. */
export function basicObjects({ catalog = '', pages = '', page = '' } = {}) {
  return [
    `<< /Type /Catalog /Pages 2 0 R${catalog ? ` ${catalog}` : ''} >>`,
    `<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792]${pages ? ` ${pages}` : ''} >>`,
    `<< /Type /Page /Parent 2 0 R${page ? ` ${page}` : ''} >>`,
  ];
}

/** Classic cross-reference table document; bodies are objects 1..N. */
export function classicPdf(bodies, { trailer = '', root = 1 } = {}) {
  const chunks = [bytes('%PDF-1.7\n'), BINARY_COMMENT];
  let length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const offsets = [];
  bodies.forEach((body, index) => {
    offsets.push(length);
    const object = Buffer.concat([bytes(`${index + 1} 0 obj\n`), bytes(body), bytes('\nendobj\n')]);
    chunks.push(object);
    length += object.length;
  });
  const size = bodies.length + 1;
  const lines = [`xref\n0 ${size}\n0000000000 65535 f \n`, ...offsets.map((offset) => `${String(offset).padStart(10, '0')} 00000 n \n`)];
  chunks.push(bytes(lines.join('')));
  chunks.push(bytes(`trailer\n<< /Size ${size} /Root ${root} 0 R${trailer ? ` ${trailer}` : ''} >>\nstartxref\n${length}\n%%EOF\n`));
  return Buffer.concat(chunks);
}

/** PNG "Up" predictor encoding (filter type 2 on every row). */
function pngUp(data, columns) {
  const rows = data.length / columns;
  const out = Buffer.alloc(rows * (columns + 1));
  for (let row = 0; row < rows; row += 1) {
    out[row * (columns + 1)] = 2;
    for (let i = 0; i < columns; i += 1) {
      const value = data[row * columns + i];
      const up = row > 0 ? data[(row - 1) * columns + i] : 0;
      out[row * (columns + 1) + 1 + i] = (value - up) & 0xff;
    }
  }
  return out;
}

/**
 * Cross-reference-stream document. `bodies` are objects 1..N (strings or stream Buffers).
 * `packed` lists object numbers placed in object streams: an array of arrays, one inner
 * array per object stream. `objstmTail` appends bytes to each object stream's decoded data
 * (used for inflation tests); `objstmExtra` appends dictionary entries to each object stream.
 * Object streams (unless compress is false) and the xref stream are FlateDecode; the xref
 * stream uses a PNG Up predictor.
 */
export function xrefStreamPdf(bodies, { packed = [], objstmTail = () => '', compress = true, objstmExtra = '' } = {}) {
  const packedSet = new Set(packed.flat());
  const all = bodies.map((body, index) => ({ num: index + 1, body }));
  const streams = [];
  packed.forEach((group, groupIndex) => {
    const pairs = [];
    const parts = [];
    let relative = 0;
    for (const num of group) {
      const body = String(bodies[num - 1]);
      pairs.push(`${num} ${relative}`);
      parts.push(body);
      relative += Buffer.byteLength(body, 'latin1') + 1;
    }
    const header = `${pairs.join(' ')}\n`;
    const decoded = Buffer.concat([bytes(header + parts.join('\n')), bytes(objstmTail(groupIndex))]);
    const data = compress ? deflateSync(decoded) : decoded;
    const num = all.length + 1;
    all.push({
      num,
      body: streamObject(`/Type /ObjStm /N ${group.length} /First ${header.length}${compress ? ' /Filter /FlateDecode' : ''}${objstmExtra ? ` ${objstmExtra}` : ''}`, data),
    });
    streams.push({ num, group });
  });
  const xrefNum = all.length + 1;
  const size = xrefNum + 1;

  const chunks = [bytes('%PDF-1.7\n'), BINARY_COMMENT];
  let length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const rows = Buffer.alloc(size * 7);
  const put = (num, type, f1, f2) => {
    rows[num * 7] = type;
    rows.writeUInt32BE(f1, num * 7 + 1);
    rows.writeUInt16BE(f2, num * 7 + 5);
  };
  put(0, 0, 0, 0xffff);
  for (const { num, body } of all) {
    if (packedSet.has(num)) continue;
    put(num, 1, length, 0);
    const object = Buffer.concat([bytes(`${num} 0 obj\n`), bytes(body), bytes('\nendobj\n')]);
    chunks.push(object);
    length += object.length;
  }
  for (const { num, group } of streams) group.forEach((member, index) => put(member, 2, num, index));
  put(xrefNum, 1, length, 0);
  const encoded = deflateSync(pngUp(rows, 7));
  chunks.push(
    bytes(`${xrefNum} 0 obj\n`),
    streamObject(`/Type /XRef /Size ${size} /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >>`, encoded),
    bytes('\nendobj\n'),
    bytes(`startxref\n${length}\n%%EOF\n`),
  );
  return Buffer.concat(chunks);
}

/** A document with `count` extra small dictionaries (memory and CPU heavy to parse). */
export function heavyDocument(count) {
  const bodies = basicObjects();
  for (let i = 0; i < count; i += 1) bodies.push(`<< /K [0 1 2 3 4 5 6 7 8 9] /N ${i} >>`);
  return classicPdf(bodies);
}

/** Deterministic pseudo-random hex text (poorly compressible). */
export function noiseText(length, seed = 1) {
  let state = seed >>> 0;
  const out = Buffer.alloc(length);
  for (let i = 0; i < length; i += 1) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    out[i] = '0123456789abcdef'.charCodeAt(state >>> 28);
  }
  return out.toString('latin1');
}
