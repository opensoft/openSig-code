// SPDX-License-Identifier: Apache-2.0
//
// Minimal DER encoder for the openSig organization seal (T013; research.md
// § Engine decision, `src/cryptograph/cms/`). It encodes only the types the
// detached CMS SignedData profile needs, always in canonical DER (X.690 § 10
// and § 11):
//
// - identifier octets in the low-tag-number form only (tag number 0..30);
// - definite lengths, short form below 128 and otherwise the long form with
//   the fewest length octets (no leading zero octet);
// - INTEGER as minimal two's complement (a 0x00 sign octet only when the
//   high bit of a non-negative value is set);
// - OBJECT IDENTIFIER arcs in base 128 with no leading 0x80 octet, using
//   BigInt so that a 2.25 UUID arc (up to 128 bits) encodes exactly;
// - SET OF with its element encodings in ascending order, compared as octet
//   strings with the shorter one padded at its end with zero octets (§ 11.6);
// - a DEFAULT value is never encoded (§ 11.5): callers omit the field.

export class DerError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'DerError';
    this.code = code;
  }
}

/** The largest content length this encoder writes (four length octets). */
export const MAX_DER_LENGTH = 0xffffffff;

const MAX_OID_TEXT = 256;

export function concat(parts: readonly Uint8Array[]): Uint8Array {
  return Buffer.concat(parts);
}

/** Length octets for a definite length, in the shortest form. */
export function encodeLength(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0 || length > MAX_DER_LENGTH) {
    throw new DerError('length-out-of-range', 'a DER length must be an integer from 0 to 2^32 - 1');
  }
  if (length < 0x80) return Uint8Array.of(length);
  const octets: number[] = [];
  let rest = length;
  while (rest > 0) {
    octets.unshift(rest % 256);
    rest = Math.floor(rest / 256);
  }
  return Uint8Array.from([0x80 | octets.length, ...octets]);
}

/** One TLV. `tag` is a single identifier octet in the low-tag-number form. */
export function tlv(tag: number, content: Uint8Array): Uint8Array {
  if (!Number.isInteger(tag) || tag < 0 || tag > 0xff || (tag & 0x1f) === 0x1f) {
    throw new DerError('tag-unsupported', 'only single-octet, low-tag-number identifiers are encoded');
  }
  return concat([Uint8Array.of(tag), encodeLength(content.length), content]);
}

export function sequence(...items: readonly Uint8Array[]): Uint8Array {
  return tlv(0x30, concat(items));
}

/** X.690 § 11.6 order: octet-string comparison, the shorter padded with trailing zero octets. */
export function compareDer(a: Uint8Array, b: Uint8Array): number {
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const left = a[index] ?? 0;
    const right = b[index] ?? 0;
    if (left !== right) return left - right;
  }
  return 0;
}

/** The content octets of a SET OF: the element encodings in ascending DER order. */
export function sortedSetContent(items: readonly Uint8Array[]): Uint8Array {
  return concat([...items].sort(compareDer));
}

/** A SET OF (tag 0x31 unless an IMPLICIT tag is given) with sorted elements. */
export function setOf(items: readonly Uint8Array[], tag = 0x31): Uint8Array {
  return tlv(tag, sortedSetContent(items));
}

/** A constructed context-specific tag [n] around already-encoded content. */
export function contextConstructed(tagNumber: number, content: Uint8Array): Uint8Array {
  if (!Number.isInteger(tagNumber) || tagNumber < 0 || tagNumber > 30) {
    throw new DerError('tag-unsupported', 'a context-specific tag number must be from 0 to 30');
  }
  return tlv(0xa0 | tagNumber, content);
}

function integerContent(value: bigint): Uint8Array {
  if (value === 0n) return Uint8Array.of(0);
  const octets: number[] = [];
  let rest = value;
  for (;;) {
    const octet = Number(rest & 0xffn);
    octets.unshift(octet);
    rest >>= 8n;
    const signBitSet = (octet & 0x80) !== 0;
    if ((rest === 0n && !signBitSet) || (rest === -1n && signBitSet)) break;
  }
  return Uint8Array.from(octets);
}

/** INTEGER as minimal two's complement. */
export function integer(value: bigint | number): Uint8Array {
  let big: bigint;
  if (typeof value === 'bigint') big = value;
  else if (Number.isSafeInteger(value)) big = BigInt(value);
  else throw new DerError('integer-invalid', 'an INTEGER must be a bigint or a safe integer');
  return tlv(0x02, integerContent(big));
}

export function octetString(bytes: Uint8Array): Uint8Array {
  return tlv(0x04, bytes);
}

export function derNull(): Uint8Array {
  return Uint8Array.of(0x05, 0x00);
}

function base128(value: bigint): number[] {
  const octets = [Number(value & 0x7fn)];
  let rest = value >> 7n;
  while (rest > 0n) {
    octets.unshift(Number(rest & 0x7fn) | 0x80);
    rest >>= 7n;
  }
  return octets;
}

/** OBJECT IDENTIFIER from dotted decimal text, e.g. "1.2.840.113549.1.7.2". */
export function objectIdentifier(dotted: string): Uint8Array {
  if (typeof dotted !== 'string' || dotted.length > MAX_OID_TEXT || !/^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))+$/.test(dotted)) {
    throw new DerError('oid-invalid', 'an OBJECT IDENTIFIER is two or more canonical decimal arcs');
  }
  const arcs = dotted.split('.').map((arc) => BigInt(arc));
  const first = arcs[0] ?? -1n;
  const second = arcs[1] ?? -1n;
  if (first > 2n || (first < 2n && second > 39n)) {
    throw new DerError('oid-invalid', 'the first arc is 0, 1 or 2, and below 2 the second arc is at most 39');
  }
  const octets = [...base128(first * 40n + second)];
  for (const arc of arcs.slice(2)) octets.push(...base128(arc));
  return tlv(0x06, Uint8Array.from(octets));
}
