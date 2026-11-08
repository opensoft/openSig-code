// SPDX-License-Identifier: Apache-2.0
//
// JSON Web Key Set validation for operator token verification (T005). Keys come from
// configuration only; nothing here fetches a URL. A configured set is refused when it:
// - holds private key material (d, p, q, dp, dq, qi, oth, k);
// - names a remote key (x5u) or carries an unknown member;
// - has a missing or duplicate kid;
// - has a key that is not RSA >= 2048 bits or EC P-256;
// - declares a use other than sig, key_ops without verify, or an alg outside the pins.

import { createPublicKey, type JsonWebKey, type KeyObject } from 'node:crypto';

import { isAlgorithm, type Algorithm } from './jwt.ts';

export interface VerificationKey {
  kid: string;
  kty: 'RSA' | 'EC';
  alg: Algorithm | null;
  key: KeyObject;
}

const COMMON_MEMBERS = new Set(['kty', 'kid', 'use', 'alg', 'key_ops', 'x5c', 'x5t', 'x5t#S256']);
const RSA_MEMBERS = new Set(['n', 'e']);
const EC_MEMBERS = new Set(['crv', 'x', 'y']);
const MIN_RSA_BITS = 2048;

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/** Validate a JWKS object and import its public keys, keyed by kid. */
export function loadJwks(jwks: unknown, algorithms: readonly Algorithm[], label: string): Map<string, VerificationKey> {
  if (typeof jwks !== 'object' || jwks === null || Array.isArray(jwks)) throw new ConfigError(`${label}: JWKS must be an object`);
  const record = jwks as Record<string, unknown>;
  const extra = Object.keys(record).filter((key) => key !== 'keys');
  if (extra.length > 0) throw new ConfigError(`${label}: unknown JWKS member ${extra[0]}`);
  if (!Array.isArray(record.keys) || record.keys.length === 0) throw new ConfigError(`${label}: JWKS needs a non-empty keys array`);
  const keys = new Map<string, VerificationKey>();
  for (const [index, candidate] of record.keys.entries()) {
    const where = `${label}: key ${index}`;
    if (typeof candidate !== 'object' || candidate === null || Array.isArray(candidate)) throw new ConfigError(`${where} is not an object`);
    const jwk = candidate as Record<string, unknown>;
    const kty = jwk.kty;
    if (kty !== 'RSA' && kty !== 'EC') throw new ConfigError(`${where}: kty must be RSA or EC`);
    const allowed = kty === 'RSA' ? RSA_MEMBERS : EC_MEMBERS;
    for (const member of Object.keys(jwk)) {
      if (!COMMON_MEMBERS.has(member) && !allowed.has(member)) {
        throw new ConfigError(`${where}: member ${member} is not allowed (private, remote or unknown key data)`);
      }
    }
    if (typeof jwk.kid !== 'string' || jwk.kid.length === 0 || jwk.kid.length > 256) throw new ConfigError(`${where}: kid is required`);
    if (keys.has(jwk.kid)) throw new ConfigError(`${where}: duplicate kid`);
    if (jwk.use !== undefined && jwk.use !== 'sig') throw new ConfigError(`${where}: use must be sig`);
    if (jwk.key_ops !== undefined && !(Array.isArray(jwk.key_ops) && jwk.key_ops.includes('verify'))) {
      throw new ConfigError(`${where}: key_ops must include verify`);
    }
    let alg: Algorithm | null = null;
    if (jwk.alg !== undefined) {
      if (!isAlgorithm(jwk.alg) || !algorithms.includes(jwk.alg)) throw new ConfigError(`${where}: alg is outside the pinned algorithms`);
      if ((jwk.alg === 'RS256') !== (kty === 'RSA')) throw new ConfigError(`${where}: alg does not match kty`);
      alg = jwk.alg;
    }
    const material: Record<string, unknown> = { kty };
    for (const member of allowed) material[member] = jwk[member];
    let key: KeyObject;
    try {
      key = createPublicKey({ key: material as JsonWebKey, format: 'jwk' });
    } catch {
      throw new ConfigError(`${where}: not a valid ${kty} public key`);
    }
    if (kty === 'RSA' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_BITS) {
      throw new ConfigError(`${where}: RSA keys must be at least ${MIN_RSA_BITS} bits`);
    }
    if (kty === 'EC' && key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new ConfigError(`${where}: EC keys must use P-256`);
    keys.set(jwk.kid, { kid: jwk.kid, kty, alg, key });
  }
  return keys;
}
