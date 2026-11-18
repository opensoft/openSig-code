// SPDX-License-Identifier: Apache-2.0
//
// Shared lexical helpers for the T012 oracle's structure checker: dictionary
// scanning, indirect-object headers, direct integers and stream data.
// Inputs are latin1 strings (one character per byte). Never throws on input.

export const WS = '[\\r\\n\\t ]';
export const fail = (detail) => ({ ok: false, detail });
export const OBJECT_HEADER = new RegExp(`^(\\d+)${WS}+(\\d+)${WS}+obj(?![A-Za-z0-9])`);

function skipLiteralString(s, start) {
  let depth = 0;
  for (let i = start; i < s.length; i += 1) {
    const c = s[i];
    if (c === '\\') i += 1;
    else if (c === '(') depth += 1;
    else if (c === ')') {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

/** Index just after the dictionary that starts with '<<' at `start`, or -1. */
export function scanDictEnd(s, start) {
  if (s.slice(start, start + 2) !== '<<') return -1;
  let depth = 0;
  let i = start;
  while (i < s.length) {
    const c = s[i];
    if (c === '<' && s[i + 1] === '<') {
      depth += 1;
      i += 2;
    } else if (c === '>' && s[i + 1] === '>') {
      depth -= 1;
      i += 2;
      if (depth === 0) return i;
    } else if (c === '<') {
      const close = s.indexOf('>', i + 1); // hex string
      if (close < 0) return -1;
      i = close + 1;
    } else if (c === '>') {
      return -1;
    } else if (c === '(') {
      i = skipLiteralString(s, i);
      if (i < 0) return -1;
    } else {
      i += 1;
    }
  }
  return -1;
}

/** A direct (not indirect-reference) non-negative integer value of /key. */
export function directInt(dict, key) {
  const m = new RegExp(`/${key}${WS}+(\\d+)(?![0-9])(?!${WS}+\\d+${WS}+R(?![A-Za-z0-9]))`).exec(dict);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isSafeInteger(n) ? n : null;
}

/** "N G obj << ... >>" at `offset`: object number, generation and dict text. */
export function readObjectDict(s, offset) {
  const head = OBJECT_HEADER.exec(s.slice(offset, offset + 40));
  if (!head) return fail('object-header-missing');
  const lead = new RegExp(`${WS}*`, 'y');
  lead.lastIndex = offset + head[0].length;
  lead.exec(s);
  const dictStart = lead.lastIndex;
  const dictEnd = scanDictEnd(s, dictStart);
  if (dictEnd < 0) return fail('object-dictionary-unterminated');
  return { ok: true, num: Number(head[1]), gen: Number(head[2]), dict: s.slice(dictStart, dictEnd), dictEnd };
}

/** Stream data of an object read by readObjectDict; /Length must be direct. */
export function readStreamData(s, obj) {
  const kw = /^[\r\n\t ]*stream(?:\r\n|\n)/.exec(s.slice(obj.dictEnd, obj.dictEnd + 40));
  if (!kw) return fail('stream-keyword-missing');
  const length = directInt(obj.dict, 'Length');
  if (length === null) return fail('stream-length-not-direct');
  const dataStart = obj.dictEnd + kw[0].length;
  const dataEnd = dataStart + length;
  if (dataEnd > s.length) return fail('stream-length-overrun');
  const tail = new RegExp(`^(?:\\r\\n|\\r|\\n)?endstream${WS}+endobj(?![A-Za-z0-9])`).exec(s.slice(dataEnd, dataEnd + 40));
  if (!tail) return fail('stream-not-terminated');
  return { ok: true, data: Buffer.from(s.slice(dataStart, dataEnd), 'latin1'), end: dataEnd + tail[0].length };
}
