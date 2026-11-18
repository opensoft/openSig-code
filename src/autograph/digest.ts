// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// SHA-256 in the browser (Web Crypto, a secure context: HTTPS, or loopback in development).
// The shell checks what it shows against the session's digests: the document bytes against
// document.digest (the approval then carries the digest of the bytes this browser received),
// the manifest bytes against manifest_digest, and the consent text against text_digest.

const HEX = Array.from({ length: 256 }, (_value, index) => index.toString(16).padStart(2, '0'));

export function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += HEX[byte] ?? '';
  return out;
}

export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  return hex(new Uint8Array(digest));
}

/** SHA-256 of the UTF-8 bytes of `text` (ConsentText.text_digest). */
export function textDigest(text: string): Promise<string> {
  const encoded = new TextEncoder().encode(text);
  const copy = new Uint8Array(encoded.length);
  copy.set(encoded);
  return sha256Hex(copy.buffer);
}
