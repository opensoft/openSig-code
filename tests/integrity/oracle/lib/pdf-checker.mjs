// SPDX-License-Identifier: Apache-2.0
//
// Independent PDF structure checks for the T012 oracle: the revision chain
// (classic xref tables, cross-reference streams and hybrid tables whose
// trailer carries /XRefStm), the signature-dictionary
// locator, ByteRange coverage and extraction of the CMS DER from /Contents.
// Every function returns a verdict object and never throws on hostile input.

import { DerError, readTlv } from './der.mjs';
import { OBJECT_HEADER, WS, directInt, fail, readObjectDict, scanDictEnd } from './pdf-lex.mjs';
import { parseXrefStream } from './xref-stream.mjs';

export { scanDictEnd };

const SUBSECTION = /(\d+) (\d+)[ \t]*(?:\r\n|\r|\n)/y;
const ENTRY = /(\d{10}) (\d{5}) ([nf])(?: \r| \n|\r\n)/y;
const TRAILER = new RegExp(`trailer${WS}*`, 'y');
const REVISION_TAIL = new RegExp(`${WS}*startxref${WS}+(\\d+)${WS}+%%EOF(?:\\r\\n|\\r|\\n)?`, 'y');

function parseXrefTable(s, offset) {
  const eol = /[ \t]*(?:\r\n|\r|\n)/y;
  eol.lastIndex = offset + 4;
  if (!eol.exec(s)) return fail('xref-keyword-malformed');
  let i = eol.lastIndex;
  const entries = [];
  for (;;) {
    SUBSECTION.lastIndex = i;
    const m = SUBSECTION.exec(s);
    if (!m) break;
    i = SUBSECTION.lastIndex;
    for (let k = 0; k < Number(m[2]); k += 1) {
      ENTRY.lastIndex = i;
      const e = ENTRY.exec(s);
      if (!e) return fail('xref-entry-malformed');
      i = ENTRY.lastIndex;
      const num = Number(m[1]) + k;
      entries.push(e[3] === 'n' ? { num, kind: 'n', offset: Number(e[1]), gen: Number(e[2]) } : { num, kind: 'f' });
    }
  }
  if (entries.length === 0) return fail('xref-empty');
  TRAILER.lastIndex = i;
  if (!TRAILER.exec(s)) return fail('trailer-missing');
  const dictEnd = scanDictEnd(s, TRAILER.lastIndex);
  if (dictEnd < 0) return fail('trailer-unterminated');
  const trailer = s.slice(TRAILER.lastIndex, dictEnd);
  const base = { ok: true, entries, prev: directInt(trailer, 'Prev'), selfNum: null, xrefStm: null, tailFrom: dictEnd };
  if (!/\/XRefStm(?![A-Za-z0-9])/.test(trailer)) return base;
  // Hybrid file (A-010 request #39 Part F): the trailer's /XRefStm names a
  // cross-reference stream in the same revision; its entries supplement the
  // table (an object the table defines in use keeps the table's entry).
  const xrefStm = directInt(trailer, 'XRefStm');
  if (xrefStm === null) return fail('xrefstm-not-direct');
  if (xrefStm <= 0 || xrefStm >= offset) return fail('xrefstm-out-of-range');
  if (!OBJECT_HEADER.test(s.slice(xrefStm, xrefStm + 40))) return fail('xrefstm-not-xref-stream');
  const hidden = parseXrefStream(s, xrefStm);
  if (!hidden.ok) return fail(hidden.detail === 'xref-stream-not-type-xref' ? 'xrefstm-not-xref-stream' : hidden.detail);
  const inUse = new Set(entries.filter((e) => e.kind === 'n').map((e) => e.num));
  for (const e of hidden.entries) if (e.kind !== 'f' && !inUse.has(e.num)) entries.push(e);
  return { ...base, xrefStm };
}

function parseSection(s, offset, hop) {
  let section;
  if (s.startsWith('xref', offset)) section = parseXrefTable(s, offset);
  else if (OBJECT_HEADER.test(s.slice(offset, offset + 40))) section = parseXrefStream(s, offset);
  else return fail(hop === 0 ? 'startxref-not-xref' : 'prev-not-xref');
  if (!section.ok) return section;
  REVISION_TAIL.lastIndex = section.tailFrom;
  const tail = REVISION_TAIL.exec(s);
  if (!tail) return fail('revision-startxref-missing');
  return { ...section, startxref: Number(tail[1]), end: REVISION_TAIL.lastIndex };
}

function checkEntries(s, chain) {
  const located = new Map(); // object number -> latest type-1 offset
  for (let r = 0; r < chain.length; r += 1) {
    const start = r === 0 ? 0 : chain[r - 1].end;
    const rev = chain[r];
    if (rev.xrefOffset < start) return 'revision-overlap';
    if (rev.xrefStm !== null && rev.xrefStm < start) return 'xrefstm-outside-revision';
    for (const e of rev.entries) {
      if (e.kind !== 'n') continue;
      const self = e.offset === rev.xrefOffset && e.num === rev.selfNum;
      if (!self && (e.offset < start || e.offset >= rev.xrefOffset)) return 'xref-entry-outside-revision';
      const h = OBJECT_HEADER.exec(s.slice(e.offset, e.offset + 40));
      if (!h || Number(h[1]) !== e.num || Number(h[2]) !== e.gen) return 'xref-entry-mismatch';
      located.set(e.num, e.offset);
    }
    for (const e of rev.entries) {
      if (e.kind !== 'c') continue;
      if (!located.has(e.objstm)) return 'xref-type2-object-stream-unlocated';
      const obj = readObjectDict(s, located.get(e.objstm));
      if (!obj.ok || !new RegExp(`/Type${WS}*/ObjStm(?![A-Za-z0-9])`).test(obj.dict)) return 'xref-type2-not-object-stream';
      if (e.index >= (directInt(obj.dict, 'N') ?? 0)) return 'xref-type2-index-out-of-range';
    }
  }
  return null;
}

/** The revision chain, earliest first, or { ok: false, detail }. */
export function parseRevisions(s) {
  if (!s.startsWith('%PDF-')) return fail('no-header');
  const last = new RegExp(`startxref${WS}+(\\d+)${WS}+%%EOF(?:\\r\\n|\\r|\\n)?$`).exec(s.slice(-64));
  if (!last) return fail('no-final-startxref-eof');
  const chain = [];
  let offset = Number(last[1]);
  for (let hop = 0; ; hop += 1) {
    if (!Number.isSafeInteger(offset) || offset <= 0 || offset >= s.length) {
      return fail(hop === 0 ? 'startxref-out-of-range' : 'prev-out-of-range');
    }
    const section = parseSection(s, offset, hop);
    if (!section.ok) return section;
    if (section.startxref !== offset) return fail('revision-startxref-mismatch');
    chain.unshift({ xrefOffset: offset, end: section.end, entries: section.entries, selfNum: section.selfNum, xrefStm: section.xrefStm ?? null });
    if (section.prev === null) break;
    if (section.prev >= offset) return fail('prev-not-earlier');
    offset = section.prev;
  }
  if (chain[chain.length - 1].end !== s.length) return fail('bytes-after-last-revision');
  const problem = checkEntries(s, chain);
  if (problem) return fail(problem);
  return { ok: true, revisions: chain.map((c, r) => ({ start: r === 0 ? 0 : chain[r - 1].end, xrefOffset: c.xrefOffset, end: c.end })) };
}

function readSignatureDictionary(s, at) {
  const objPos = s.lastIndexOf(' obj', at);
  const dictStart = objPos < 0 ? -1 : s.indexOf('<<', objPos);
  if (dictStart < 0 || dictStart > at) return fail('signature-dictionary-not-found');
  const dictEnd = scanDictEnd(s, dictStart);
  if (dictEnd < 0 || at >= dictEnd) return fail('signature-dictionary-unterminated');
  const dict = s.slice(dictStart, dictEnd);
  const br = new RegExp(`^/ByteRange${WS}*\\[${WS}*(\\d+)${WS}+(\\d+)${WS}+(\\d+)${WS}+(\\d+)${WS}*\\]`).exec(s.slice(at, dictEnd));
  if (!br) return fail('byterange-malformed');
  const byteRange = br.slice(1, 5).map(Number);
  if (!byteRange.every(Number.isSafeInteger)) return fail('byterange-malformed');
  const key = new RegExp(`/Contents${WS}*<(?!<)`).exec(dict);
  if (!key) return fail('contents-not-direct-hex-string');
  const start = dictStart + key.index + key[0].length - 1; // '<'
  const close = s.indexOf('>', start + 1);
  if (close < 0 || close >= dictEnd) return fail('contents-unterminated');
  const hex = s.slice(start + 1, close);
  if (!/^[0-9A-Fa-f]*$/.test(hex) || hex.length % 2 !== 0) return fail('contents-not-hex');
  const isSig = new RegExp(`/Type${WS}*/Sig(?![A-Za-z0-9])`).test(dict);
  return { ok: true, byteRange, dictStart, dictEnd, isSig, contents: { start, end: close + 1, hex } };
}

/** Every /ByteRange outside stream data, with its signature dictionary. */
export function locateSignatures(s) {
  const candidates = [];
  const token = /\/ByteRange(?![A-Za-z0-9])|stream(?:\r\n|\n)/g;
  for (let m = token.exec(s); m !== null; m = token.exec(s)) {
    if (m[0].startsWith('stream')) {
      if (!/>>[\r\n\t ]*$/.test(s.slice(Math.max(0, m.index - 8), m.index))) continue; // e.g. 'endstream'
      const end = s.indexOf('endstream', token.lastIndex);
      if (end < 0) break;
      token.lastIndex = end + 'endstream'.length;
      continue;
    }
    candidates.push(readSignatureDictionary(s, m.index));
  }
  return candidates;
}

/** ByteRange must exclude exactly /Contents and end at a revision boundary. */
export function checkByteRange(fileLength, sig, structure) {
  const [o1, l1, o2, l2] = sig.byteRange;
  if (o1 !== 0) return fail('range1-not-at-zero');
  if (l1 !== sig.contents.start || o2 !== sig.contents.end) return fail('gap-not-contents');
  if (o2 + l2 > fileLength) return fail('beyond-eof');
  const endsAt = o2 + l2;
  if (!structure.ok) return endsAt === fileLength ? { ok: true, signedRevision: null } : fail('not-to-eof');
  const index = structure.revisions.findIndex((r) => r.end === endsAt);
  if (index < 0) return fail('not-revision-boundary');
  if (sig.dictStart < structure.revisions[index].start) return fail('signature-outside-signed-revision');
  return { ok: true, signedRevision: index };
}

/** The stated ranges, when they lie inside the file (diagnostics only). */
export function statedRangesWithin(fileLength, [o1, l1, o2, l2]) {
  return o1 + l1 <= fileLength && o2 + l2 <= fileLength && o1 + l1 <= o2;
}

/** DER from the /Contents hex string; trailing bytes must be zero padding. */
export function extractCms(sig) {
  const buf = Buffer.from(sig.contents.hex, 'hex');
  if (buf.length === 0) return fail('contents-empty');
  try {
    const top = readTlv(buf, 0);
    return { ok: true, der: Buffer.from(buf.subarray(0, top.end)), paddingZero: buf.subarray(top.end).every((b) => b === 0) };
  } catch (error) {
    if (error instanceof DerError) return fail(`cms-${error.code}`);
    throw error;
  }
}
