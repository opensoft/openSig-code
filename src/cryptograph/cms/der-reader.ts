// SPDX-License-Identifier: Apache-2.0
//
// Strict minimal DER reader (T013). The seal builder uses it for one job: to
// take the signer certificate's issuer Name and serialNumber TLVs verbatim
// for the SignerInfo sid. It accepts only the low-tag-number form and minimal
// definite lengths, and every element must lie inside its parent. It is not
// the shipped verifier's decoder: T014 keeps its own (`src/verifier/`).

import { DerError } from './der.ts';

export interface DerElement {
  /** The single identifier octet. */
  readonly tag: number;
  /** Offset of the identifier octet. */
  readonly start: number;
  /** Offset of the first content octet. */
  readonly contentStart: number;
  /** Offset just past the last content octet. */
  readonly end: number;
}

/** Read one element at `offset`; it must end at or before `limit`. */
export function readElement(bytes: Uint8Array, offset: number, limit: number = bytes.length): DerElement {
  if (!Number.isSafeInteger(offset) || offset < 0 || limit > bytes.length || offset + 2 > limit) {
    throw new DerError('truncated', 'a DER element is truncated');
  }
  const tag = bytes[offset] ?? 0;
  if ((tag & 0x1f) === 0x1f) throw new DerError('tag-unsupported', 'high-tag-number identifiers are not accepted');
  const first = bytes[offset + 1] ?? 0;
  let length: number;
  let contentStart: number;
  if (first < 0x80) {
    length = first;
    contentStart = offset + 2;
  } else {
    const count = first & 0x7f;
    if (count === 0) throw new DerError('indefinite-length', 'indefinite lengths are not DER');
    if (count > 4) throw new DerError('length-out-of-range', 'a DER length has at most four length octets here');
    if (offset + 2 + count > limit) throw new DerError('truncated', 'a DER length is truncated');
    if ((bytes[offset + 2] ?? 0) === 0) throw new DerError('length-not-minimal', 'a DER length has a leading zero octet');
    length = 0;
    for (let index = 0; index < count; index += 1) length = length * 256 + (bytes[offset + 2 + index] ?? 0);
    if (length < 0x80) throw new DerError('length-not-minimal', 'a DER length below 128 uses the short form');
    contentStart = offset + 2 + count;
  }
  const end = contentStart + length;
  if (end > limit) throw new DerError('truncated', 'a DER element runs past its parent');
  return { tag, start: offset, contentStart, end };
}

/** Read the only element of `bytes`; trailing octets are refused. */
export function readWhole(bytes: Uint8Array): DerElement {
  const element = readElement(bytes, 0);
  if (element.end !== bytes.length) throw new DerError('trailing-data', 'octets follow the outermost DER element');
  return element;
}

/** The elements that exactly fill a constructed element's content. */
export function children(bytes: Uint8Array, parent: DerElement): DerElement[] {
  if ((parent.tag & 0x20) === 0) throw new DerError('not-constructed', 'a primitive element has no children');
  const out: DerElement[] = [];
  let offset = parent.contentStart;
  while (offset < parent.end) {
    const child = readElement(bytes, offset, parent.end);
    out.push(child);
    offset = child.end;
  }
  return out;
}

/** The whole TLV of an element. */
export function encodingOf(bytes: Uint8Array, element: DerElement): Uint8Array {
  return bytes.subarray(element.start, element.end);
}

/** The content octets of an element. */
export function contentOf(bytes: Uint8Array, element: DerElement): Uint8Array {
  return bytes.subarray(element.contentStart, element.end);
}
