// SPDX-License-Identifier: Apache-2.0
//
// Minimal, independent PDF structure reader for the T004 fixture tests (tests/dev/).
// It is written separately from scripts/gen-fixtures.mjs and imports nothing from it.
// It reads only what the fixtures declare: the header, startxref, classic cross-reference
// tables and uncompressed cross-reference streams (with /Prev chains), object streams,
// and the page tree with inherited /Rotate and /MediaBox. It is not a general PDF parser
// and it is not the product parser (T033).

export function text(buffer) {
  return buffer.toString('latin1');
}

/** The startxref value, or null when the file does not end with startxref / %%EOF. */
export function readStartxref(buffer) {
  const match = /startxref\s+(\d+)\s+%%EOF\s*$/.exec(text(buffer));
  return match ? Number(match[1]) : null;
}

// --- dictionary value helpers (fixture syntax: single spaces, no comments) ---------------

export function ref(dict, key) {
  const match = new RegExp(`/${key}\\s+(\\d+)\\s+0\\s+R`).exec(dict);
  return match ? Number(match[1]) : null;
}

export function refs(dict, key) {
  const match = new RegExp(`/${key}\\s*\\[([^\\]]*)\\]`).exec(dict);
  return match ? [...match[1].matchAll(/(\d+)\s+0\s+R/g)].map((m) => Number(m[1])) : null;
}

export function int(dict, key) {
  const match = new RegExp(`/${key}\\s+(-?\\d+)(?!\\d|\\s+\\d+\\s+R)`).exec(dict);
  return match ? Number(match[1]) : null;
}

export function numbers(dict, key) {
  const match = new RegExp(`/${key}\\s*\\[([^\\]]*)\\]`).exec(dict);
  return match ? match[1].trim().split(/\s+/).map(Number) : null;
}

export function name(dict, key) {
  const match = new RegExp(`/${key}\\s*/([A-Za-z0-9.#_-]+)`).exec(dict);
  return match ? match[1] : null;
}

// --- cross-reference sections -----------------------------------------------------------

function readTable(source, offset, entries) {
  const sticky = (pattern, at) => {
    const re = new RegExp(pattern, 'y');
    re.lastIndex = at;
    return re.exec(source);
  };
  let pos = offset + 'xref'.length;
  const ws = sticky('\\s*', pos);
  pos += ws[0].length;
  for (;;) {
    const sub = sticky('(\\d+) (\\d+)[ ]*\\r?\\n', pos);
    if (!sub) break;
    pos += sub[0].length;
    const start = Number(sub[1]);
    const count = Number(sub[2]);
    for (let i = 0; i < count; i += 1) {
      const line = sticky('(\\d{10}) (\\d{5}) ([nf])[ \\r][\\r\\n]', pos);
      if (!line) throw new Error(`malformed cross-reference entry at byte ${pos}`);
      pos += 20;
      const num = start + i;
      if (line[3] === 'n' && !entries.has(num)) entries.set(num, { type: 1, offset: Number(line[1]) });
    }
  }
  if (!source.startsWith('trailer', pos)) throw new Error(`expected trailer at byte ${pos}`);
  const end = source.indexOf('startxref', pos);
  return source.slice(pos + 'trailer'.length, end < 0 ? undefined : end).trim();
}

function streamData(buffer, source, objectStart) {
  const keyword = source.indexOf('stream', objectStart);
  const dict = source.slice(objectStart, keyword);
  if (/\/Filter/.test(dict)) throw new Error('compressed streams are outside this reader');
  const length = int(dict, 'Length');
  let start = keyword + 'stream'.length;
  if (source[start] === '\r') start += 1;
  if (source[start] === '\n') start += 1;
  return { dict, data: buffer.subarray(start, start + length), start, length };
}

function readXrefStream(buffer, source, offset, entries) {
  const header = /^(\d+) 0 obj\s*/.exec(source.slice(offset, offset + 32));
  if (!header) throw new Error(`startxref ${offset} points at neither "xref" nor an object`);
  const { dict, data } = streamData(buffer, source, offset);
  if (name(dict, 'Type') !== 'XRef') throw new Error('startxref object is not a cross-reference stream');
  const widths = numbers(dict, 'W');
  const index = numbers(dict, 'Index') ?? [0, int(dict, 'Size')];
  const rowLength = widths.reduce((a, b) => a + b, 0);
  const field = (row, which) => {
    let at = row * rowLength;
    for (let i = 0; i < which; i += 1) at += widths[i];
    let value = 0;
    for (let i = 0; i < widths[which]; i += 1) value = value * 256 + data[at + i];
    return value;
  };
  let row = 0;
  for (let i = 0; i < index.length; i += 2) {
    for (let k = 0; k < index[i + 1]; k += 1, row += 1) {
      const num = index[i] + k;
      const type = widths[0] === 0 ? 1 : field(row, 0);
      if (entries.has(num)) continue;
      if (type === 1) entries.set(num, { type: 1, offset: field(row, 1) });
      else if (type === 2) entries.set(num, { type: 2, stream: field(row, 1), index: field(row, 2) });
    }
  }
  return dict;
}

/**
 * Walk startxref and every /Prev. Returns { entries, trailer, trailers, sections }.
 * Throws on a /Prev cycle or an out-of-range offset.
 */
export function readXref(buffer) {
  const source = text(buffer);
  let offset = readStartxref(buffer);
  if (offset === null) throw new Error('no startxref / %%EOF at the end of the file');
  const entries = new Map();
  const trailers = [];
  const seen = new Set();
  while (offset !== null) {
    if (seen.has(offset)) throw new Error(`cross-reference /Prev cycle at byte ${offset}`);
    seen.add(offset);
    if (offset >= buffer.length) throw new Error(`cross-reference offset ${offset} is beyond the end of the file`);
    const trailer = source.startsWith('xref', offset)
      ? readTable(source, offset, entries)
      : readXrefStream(buffer, source, offset, entries);
    trailers.push(trailer);
    const prev = int(trailer, 'Prev');
    offset = prev;
  }
  return { entries, trailer: trailers[0], trailers, sections: trailers.length };
}

/** The text between "N 0 obj" and "endobj" (or the object's slice of an object stream). */
export function objectText(buffer, xref, num) {
  const entry = xref.entries.get(num);
  if (!entry) throw new Error(`object ${num} is not in the cross-reference data`);
  const source = text(buffer);
  if (entry.type === 1) {
    const header = `${num} 0 obj`;
    if (!source.startsWith(header, entry.offset)) {
      throw new Error(`cross-reference entry for object ${num} does not point at "${header}"`);
    }
    const end = source.indexOf('endobj', entry.offset);
    return source.slice(entry.offset + header.length, end).trim();
  }
  const stmEntry = xref.entries.get(entry.stream);
  const { dict, data } = streamData(buffer, source, stmEntry.offset);
  if (name(dict, 'Type') !== 'ObjStm') throw new Error(`object ${entry.stream} is not an object stream`);
  const first = int(dict, 'First');
  const body = text(data);
  const pairs = body.slice(0, first).trim().split(/\s+/).map(Number);
  if (pairs[entry.index * 2] !== num) throw new Error(`object stream ${entry.stream} index ${entry.index} is not object ${num}`);
  const start = first + pairs[entry.index * 2 + 1];
  const next = entry.index * 2 + 3 < pairs.length ? first + pairs[entry.index * 2 + 3] : body.length;
  return body.slice(start, next).trim();
}

// --- page tree --------------------------------------------------------------------------

export function displayedGeometry(mediaBox, rotateValue) {
  const rotate = ((rotateValue % 360) + 360) % 360;
  const width = mediaBox[2] - mediaBox[0];
  const height = mediaBox[3] - mediaBox[1];
  return rotate % 180 === 0 ? { width, height, rotate } : { width: height, height: width, rotate };
}

/**
 * Resolve the catalog and walk the page tree with /Rotate and /MediaBox inheritance.
 * Returns { xref, catalog, pages } where pages are { number, width, height, rotate,
 * media_box, object }. Throws on a revisited node or a /Count mismatch.
 */
export function readPages(buffer) {
  const xref = readXref(buffer);
  const catalog = objectText(buffer, xref, ref(xref.trailer, 'Root'));
  if (name(catalog, 'Type') !== 'Catalog') throw new Error('/Root is not a catalog');
  const pages = [];
  const visited = new Set();
  const walk = (num, inherited) => {
    if (visited.has(num)) throw new Error(`page tree revisits object ${num}`);
    visited.add(num);
    const dict = objectText(buffer, xref, num);
    const effective = {
      mediaBox: numbers(dict, 'MediaBox') ?? inherited.mediaBox,
      rotate: int(dict, 'Rotate') ?? inherited.rotate,
    };
    const type = name(dict, 'Type');
    if (type === 'Pages') {
      const before = pages.length;
      for (const kid of refs(dict, 'Kids') ?? []) walk(kid, effective);
      const count = int(dict, 'Count');
      if (count !== pages.length - before) throw new Error(`/Count ${count} of object ${num} != ${pages.length - before} leaves`);
      return;
    }
    if (type !== 'Page') throw new Error(`object ${num} in the page tree has /Type ${type}`);
    if (!effective.mediaBox) throw new Error(`page object ${num} has no effective /MediaBox`);
    pages.push({
      number: pages.length + 1,
      ...displayedGeometry(effective.mediaBox, effective.rotate ?? 0),
      media_box: effective.mediaBox,
      object: num,
    });
  };
  walk(ref(catalog, 'Pages'), { mediaBox: null, rotate: 0 });
  return { xref, catalog, pages };
}
