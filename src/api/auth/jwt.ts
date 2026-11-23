// SPDX-License-Identifier: Apache-2.0
//
// Compact JWS (RFC 7515) handling for operator access tokens (T005). Strict by design:
// - exactly three canonical base64url segments, at most MAX_TOKEN_LENGTH characters;
// - the protected header and payload must be JSON objects;
// - headers that name or embed keys (jwk, jku, x5u, x5c) and any crit header are refused, so
//   a token can never choose its own verification key;
// - typ, when present, must be JWT or at+jwt (RFC 9068);
// - only RS256 (RSASSA-PKCS1-v1_5, SHA-256, RSA >= 2048 bits) and ES256 (ECDSA P-256,
//   SHA-256, 64-byte IEEE P1363 signature) verify, and only with a key of the matching type.

import { Buffer } from 'node:buffer';
import { verify, type KeyObject } from 'node:crypto';

export const MAX_TOKEN_LENGTH = 8192;
export const SUPPORTED_ALGORITHMS = Object.freeze(['RS256', 'ES256'] as const);
export type Algorithm = (typeof SUPPORTED_ALGORITHMS)[number];

const SEGMENT = /^[A-Za-z0-9_-]+$/;
const FORBIDDEN_HEADERS = Object.freeze(['jwk', 'jku', 'x5u', 'x5c', 'crit']);
const ALLOWED_TYP = new Set(['jwt', 'at+jwt', 'application/at+jwt']);

export class TokenError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(reason);
    this.name = 'TokenError';
    this.reason = reason;
  }
}

export interface DecodedToken {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: Buffer;
  signature: Buffer;
}

export function isAlgorithm(value: unknown): value is Algorithm {
  return typeof value === 'string' && (SUPPORTED_ALGORITHMS as readonly string[]).includes(value);
}

/** Strict base64url: the alphabet only, no padding, and canonical (re-encodes identically). */
export function decodeBase64Url(segment: string): Buffer {
  if (!SEGMENT.test(segment) || segment.length % 4 === 1) throw new TokenError('malformed');
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment) throw new TokenError('malformed');
  return bytes;
}

function jsonObject(segment: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(decodeBase64Url(segment).toString('utf8'));
  } catch (error) {
    if (error instanceof TokenError) throw error;
    throw new TokenError('malformed');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TokenError('malformed');
  return value as Record<string, unknown>;
}

/** Split and decode a compact JWS without verifying it. */
export function decodeToken(token: string): DecodedToken {
  if (token.length === 0 || token.length > MAX_TOKEN_LENGTH) throw new TokenError('malformed');
  const parts = token.split('.');
  if (parts.length !== 3) throw new TokenError('malformed');
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const header = jsonObject(headerPart);
  const payload = jsonObject(payloadPart);
  const signature = decodeBase64Url(signaturePart);
  for (const name of FORBIDDEN_HEADERS) if (Object.hasOwn(header, name)) throw new TokenError('header');
  if (!isAlgorithm(header.alg)) throw new TokenError('algorithm');
  if (typeof header.kid !== 'string' || header.kid.length === 0) throw new TokenError('unknown-key');
  if (header.typ !== undefined && (typeof header.typ !== 'string' || !ALLOWED_TYP.has(header.typ.toLowerCase()))) {
    throw new TokenError('header');
  }
  return { header, payload, signingInput: Buffer.from(`${headerPart}.${payloadPart}`, 'ascii'), signature };
}

/** Verify the signature with `key`, which must match `alg`. */
export function verifySignature(decoded: DecodedToken, alg: Algorithm, key: KeyObject): boolean {
  if (alg === 'RS256') {
    if (key.asymmetricKeyType !== 'rsa') return false;
    return verify('sha256', decoded.signingInput, key, decoded.signature);
  }
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return false;
  if (decoded.signature.length !== 64) return false;
  return verify('sha256', decoded.signingInput, { key, dsaEncoding: 'ieee-p1363' }, decoded.signature);
}
