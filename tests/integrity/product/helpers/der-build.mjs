// SPDX-License-Identifier: Apache-2.0
//
// A test-local DER encoder for T014's CMS-profile and trust tests. It is
// written for these tests alone and shares nothing with T013's encoder
// (src/cryptograph/cms/) or the verifier's decoder. Lengths are definite and
// minimal unless a test asks for a raw, deliberately wrong encoding.

import { Buffer } from 'node:buffer';

function lengthBytes(n) {
  if (n < 0x80) return Buffer.from([n]);
  const out = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) out.unshift(v % 256);
  return Buffer.from([0x80 | out.length, ...out]);
}

export function tlv(tag, ...contents) {
  const body = Buffer.concat(contents.map((c) => Buffer.from(c)));
  return Buffer.concat([Buffer.from([tag]), lengthBytes(body.length), body]);
}

/** A TLV with caller-chosen length bytes (for non-minimal or wrong lengths). */
export function rawTlv(tag, length, content) {
  return Buffer.concat([Buffer.from([tag]), Buffer.from(length), Buffer.from(content)]);
}

export const seq = (...items) => tlv(0x30, ...items);
/** A SET in the given order (no sorting). */
export const setRaw = (...items) => tlv(0x31, ...items);

export function compareDer(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x - y;
  }
  return 0;
}

/** A SET OF in DER order. */
export const set = (...items) => setRaw(...[...items].map((i) => Buffer.from(i)).sort(compareDer));

export const ctx = (n, ...items) => tlv(0xa0 | n, ...items);
export const ctxPrimitive = (n, content) => tlv(0x80 | n, content);
export const octets = (bytes) => tlv(0x04, bytes);
export const nul = () => Buffer.from([0x05, 0x00]);
export const bool = (value) => tlv(0x01, Buffer.from([value ? 0xff : 0x00]));
export const utf8 = (text) => tlv(0x0c, Buffer.from(text, 'utf8'));
export const bitString = (bytes) => tlv(0x03, Buffer.from([0]), bytes);

export function integer(value) {
  let v = BigInt(value);
  if (v < 0n) throw new RangeError('non-negative integers only');
  const out = [];
  do {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  } while (v > 0n);
  if (out[0] & 0x80) out.unshift(0);
  return tlv(0x02, Buffer.from(out));
}

/** An INTEGER from content bytes taken as they are (a serial number). */
export const integerBytes = (bytes) => tlv(0x02, bytes);

export function oid(text) {
  const arcs = text.split('.').map((a) => BigInt(a));
  const [a, b, ...rest] = arcs;
  const out = [];
  for (const arc of [a * 40n + b, ...rest]) {
    const chunk = [Number(arc & 0x7fn)];
    for (let v = arc >> 7n; v > 0n; v >>= 7n) chunk.unshift(Number(v & 0x7fn) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
}

function two(n) {
  return String(n).padStart(2, '0');
}

export function utcTime(date) {
  const text = `${two(date.getUTCFullYear() % 100)}${two(date.getUTCMonth() + 1)}${two(date.getUTCDate())}` +
    `${two(date.getUTCHours())}${two(date.getUTCMinutes())}${two(date.getUTCSeconds())}Z`;
  return tlv(0x17, Buffer.from(text, 'latin1'));
}

export const algorithm = (oidText, parameters = 'null') =>
  parameters === 'null' ? seq(oid(oidText), nul()) : seq(oid(oidText));

/** The value bytes of a DER TLV with a definite length (test-side reading only). */
export function contentOf(encoding) {
  const first = encoding[1];
  if (first < 0x80) return encoding.subarray(2, 2 + first);
  const count = first & 0x7f;
  let length = 0;
  for (let i = 0; i < count; i += 1) length = length * 256 + encoding[2 + i];
  return encoding.subarray(2 + count, 2 + count + length);
}
