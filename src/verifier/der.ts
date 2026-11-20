// SPDX-License-Identifier: Apache-2.0
//
// The verifier's own strict DER reader (T014). It shares nothing with T013's
// encoder (VB-01). It accepts only definite, minimal lengths inside the parent,
// single-byte tags, minimal INTEGERs and minimal base-128 OBJECT IDENTIFIER
// arcs; anything else throws DerFault. Every read is bounded by its parent and
// by VERIFIER_LIMITS.maxDerChildren.

import { VERIFIER_LIMITS } from './limits.ts';

export const DER_FAULTS = [
  'truncated',
  'high-tag-number',
  'indefinite-length',
  'length-too-large',
  'non-minimal-length',
  'length-exceeds-parent',
  'unexpected-tag',
  'not-constructed',
  'too-many-children',
  'bad-oid',
  'bad-integer',
  'bad-null',
  'trailing-bytes',
] as const;

export type DerFaultCode = (typeof DER_FAULTS)[number];

export class DerFault extends Error {
  readonly code: DerFaultCode;

  constructor(code: DerFaultCode) {
    super(code);
    this.name = 'DerFault';
    this.code = code;
  }
}

export interface Tlv {
  readonly tag: number;
  readonly start: number;
  readonly valueStart: number;
  readonly end: number;
}

export const TAG = Object.freeze({
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
  CONTEXT_0: 0xa0,
  CONTEXT_1: 0xa1,
  CONTEXT_3: 0xa3,
  CONTEXT_4: 0xa4,
  CONTEXT_0_PRIMITIVE: 0x80,
});

function at(buf: Uint8Array, i: number): number {
  const v = buf[i];
  if (v === undefined) throw new DerFault('truncated');
  return v;
}

/** One TLV starting at `pos`, which must end at or before `limit`. */
export function readTlv(buf: Uint8Array, pos: number, limit: number): Tlv {
  if (pos >= limit) throw new DerFault('truncated');
  const tag = at(buf, pos);
  if ((tag & 0x1f) === 0x1f) throw new DerFault('high-tag-number');
  let p = pos + 1;
  if (p >= limit) throw new DerFault('truncated');
  const first = at(buf, p);
  p += 1;
  let length: number;
  if (first < 0x80) {
    length = first;
  } else if (first === 0x80) {
    throw new DerFault('indefinite-length');
  } else {
    const count = first & 0x7f;
    if (count > 3) throw new DerFault('length-too-large');
    if (p + count > limit) throw new DerFault('truncated');
    if (at(buf, p) === 0) throw new DerFault('non-minimal-length');
    length = 0;
    for (let i = 0; i < count; i += 1) length = length * 256 + at(buf, p + i);
    p += count;
    if (length < 0x80) throw new DerFault('non-minimal-length');
  }
  if (p + length > limit) throw new DerFault('length-exceeds-parent');
  return { tag, start: pos, valueStart: p, end: p + length };
}

/** The single TLV that fills buf exactly. */
export function readWhole(buf: Uint8Array): Tlv {
  const tlv = readTlv(buf, 0, buf.length);
  if (tlv.end !== buf.length) throw new DerFault('trailing-bytes');
  return tlv;
}

/** The children of a constructed TLV, filling its value exactly. */
export function children(buf: Uint8Array, parent: Tlv, max: number = VERIFIER_LIMITS.maxDerChildren): Tlv[] {
  if ((parent.tag & 0x20) === 0) throw new DerFault('not-constructed');
  const out: Tlv[] = [];
  let p = parent.valueStart;
  while (p < parent.end) {
    if (out.length >= max) throw new DerFault('too-many-children');
    const child = readTlv(buf, p, parent.end);
    out.push(child);
    p = child.end;
  }
  return out;
}

export function expectTag(tlv: Tlv | undefined, tag: number): Tlv {
  if (tlv === undefined || tlv.tag !== tag) throw new DerFault('unexpected-tag');
  return tlv;
}

export function valueOf(buf: Uint8Array, tlv: Tlv): Uint8Array {
  return buf.subarray(tlv.valueStart, tlv.end);
}

export function encodingOf(buf: Uint8Array, tlv: Tlv): Uint8Array {
  return buf.subarray(tlv.start, tlv.end);
}

/** Dotted OID text; arcs are read as BigInt so 2.25 UUID arcs stay exact. */
export function oidOf(buf: Uint8Array, tlv: Tlv): string {
  expectTag(tlv, TAG.OID);
  const value = valueOf(buf, tlv);
  if (value.length === 0 || value.length > 64) throw new DerFault('bad-oid');
  const arcs: bigint[] = [];
  let current = 0n;
  let fresh = true;
  for (let i = 0; i < value.length; i += 1) {
    const b = at(value, i);
    if (fresh && b === 0x80) throw new DerFault('bad-oid');
    current = (current << 7n) | BigInt(b & 0x7f);
    fresh = (b & 0x80) === 0;
    if (fresh) {
      arcs.push(current);
      current = 0n;
    }
  }
  if (!fresh) throw new DerFault('bad-oid');
  const [head, ...rest] = arcs;
  if (head === undefined) throw new DerFault('bad-oid');
  const first = head < 40n ? 0n : head < 80n ? 1n : 2n;
  return [first, head - first * 40n, ...rest].map((arc) => arc.toString()).join('.');
}

/** The minimal two's-complement content bytes of an INTEGER. */
export function integerBytes(buf: Uint8Array, tlv: Tlv): Uint8Array {
  expectTag(tlv, TAG.INTEGER);
  const value = valueOf(buf, tlv);
  if (value.length === 0) throw new DerFault('bad-integer');
  if (value.length > 1) {
    const b0 = at(value, 0);
    const b1 = at(value, 1);
    if ((b0 === 0x00 && (b1 & 0x80) === 0) || (b0 === 0xff && (b1 & 0x80) !== 0)) throw new DerFault('bad-integer');
  }
  return value;
}

/** A small non-negative INTEGER (a version number). */
export function smallInteger(buf: Uint8Array, tlv: Tlv | undefined): number {
  const value = integerBytes(buf, expectTag(tlv, TAG.INTEGER));
  if (value.length > 2 || (at(value, 0) & 0x80) !== 0) throw new DerFault('bad-integer');
  let n = 0;
  for (let i = 0; i < value.length; i += 1) n = n * 256 + at(value, i);
  return n;
}

export interface AlgorithmIdentifier {
  readonly oid: string;
  readonly parameters: 'absent' | 'null' | 'other';
}

export function algorithmIdentifier(buf: Uint8Array, tlv: Tlv | undefined): AlgorithmIdentifier {
  const parts = children(buf, expectTag(tlv, TAG.SEQUENCE), 2);
  const [oidTlv, params] = parts;
  const oid = oidOf(buf, expectTag(oidTlv, TAG.OID));
  if (params === undefined) return { oid, parameters: 'absent' };
  if (params.tag === TAG.NULL) {
    if (params.end !== params.valueStart) throw new DerFault('bad-null');
    return { oid, parameters: 'null' };
  }
  return { oid, parameters: 'other' };
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

/** X.690 11.6: SET OF elements compare as octet strings, the shorter padded with trailing zeros. */
export function compareDerElements(a: Uint8Array, b: Uint8Array): number {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x - y;
  }
  return 0;
}
