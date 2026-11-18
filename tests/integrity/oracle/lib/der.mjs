// SPDX-License-Identifier: Apache-2.0
//
// Minimal DER reader for the independent integrity oracle (T012), plus a
// deliberately tiny writer used only by the OC-09 attribute splice.
// Written without reference to src/; it imports nothing.

export class DerError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.name = 'DerError';
    this.code = code;
  }
}

/**
 * Read one TLV at `offset` inside buf[offset, limit). DER only: single-byte
 * tags, definite minimal lengths of at most four length octets.
 */
export function readTlv(buf, offset, limit = buf.length) {
  if (!Number.isInteger(offset) || offset < 0 || offset >= limit) {
    throw new DerError('der-offset', `no TLV at offset ${offset}`);
  }
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) throw new DerError('der-high-tag');
  let pos = offset + 1;
  if (pos >= limit) throw new DerError('der-truncated', 'length octet missing');
  const first = buf[pos];
  pos += 1;
  let length;
  if (first < 0x80) {
    length = first;
  } else if (first === 0x80) {
    throw new DerError('der-indefinite');
  } else {
    const count = first & 0x7f;
    if (count > 4) throw new DerError('der-length-too-long');
    if (pos + count > limit) throw new DerError('der-truncated', 'length octets run past the end');
    if (buf[pos] === 0) throw new DerError('der-non-minimal-length');
    length = 0;
    for (let i = 0; i < count; i += 1) length = length * 256 + buf[pos + i];
    pos += count;
    if (length < 0x80) throw new DerError('der-non-minimal-length');
  }
  const end = pos + length;
  if (end > limit) throw new DerError('der-truncated', `content of ${length} bytes runs past the end`);
  return { tag, constructed: (tag & 0x20) !== 0, start: offset, contentStart: pos, end, length };
}

/** The TLVs directly inside a constructed TLV, in order. */
export function children(buf, parent) {
  if (!parent.constructed) throw new DerError('der-not-constructed');
  const out = [];
  let pos = parent.contentStart;
  while (pos < parent.end) {
    const child = readTlv(buf, pos, parent.end);
    out.push(child);
    pos = child.end;
  }
  return out;
}

export function contentOf(buf, node) {
  return buf.subarray(node.contentStart, node.end);
}

export function rawOf(buf, node) {
  return buf.subarray(node.start, node.end);
}

/** Dotted form of an OBJECT IDENTIFIER's content octets (arcs as BigInt). */
export function decodeOid(bytes) {
  if (bytes.length === 0) throw new DerError('oid-empty');
  const arcs = [];
  let value = 0n;
  let inArc = false;
  for (const b of bytes) {
    if (!inArc && b === 0x80) throw new DerError('oid-non-minimal');
    value = (value << 7n) | BigInt(b & 0x7f);
    inArc = true;
    if ((b & 0x80) === 0) {
      arcs.push(value);
      value = 0n;
      inArc = false;
    }
  }
  if (inArc) throw new DerError('oid-truncated');
  const head = arcs[0];
  const firstTwo = head < 40n ? [0n, head] : head < 80n ? [1n, head - 40n] : [2n, head - 80n];
  return [...firstTwo, ...arcs.slice(1)].map(String).join('.');
}

export function encodeLength(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new DerError('der-length');
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v % 256);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag, ...contents) {
  const body = Buffer.concat(contents);
  return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
}

/** Full TLV of an OBJECT IDENTIFIER from its dotted form. */
export function encodeOid(dotted) {
  if (!/^[0-2](\.(0|[1-9][0-9]*))+$/.test(dotted)) throw new DerError('oid-syntax');
  const arcs = dotted.split('.').map((arc) => BigInt(arc));
  const [a0, a1] = arcs;
  if (a0 < 2n && a1 >= 40n) throw new DerError('oid-syntax');
  const bytes = [];
  for (const id of [a0 * 40n + a1, ...arcs.slice(2)]) {
    const group = [];
    let v = id;
    do {
      group.unshift(Number(v & 0x7fn));
      v >>= 7n;
    } while (v > 0n);
    for (let i = 0; i < group.length - 1; i += 1) group[i] |= 0x80;
    bytes.push(...group);
  }
  return tlv(0x06, Buffer.from(bytes));
}

/** X.690 SET OF order: octet-wise, the shorter padded with trailing zeros. */
export function compareSetMembers(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const x = i < a.length ? a[i] : 0;
    const y = i < b.length ? b[i] : 0;
    if (x !== y) return x - y;
  }
  return 0;
}
