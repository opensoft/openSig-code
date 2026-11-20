// SPDX-License-Identifier: Apache-2.0
//
// Test support for operator authentication (T005). Every key is generated at test
// runtime; private keys stay in memory and are never written. A public JWKS file is
// written to a mkdtemp directory with mode 0600 and removed by cleanup(). Tenants,
// issuers and audiences come from the T004 synthetic identities fixture.

import { generateKeyPairSync, sign } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
export const identities = JSON.parse(readFileSync(join(REPO, 'fixtures', 'synthetic', 'identities', 'identities.json'), 'utf8'));
export const [ALPHA, BETA] = identities.tenants;
export const NOW = 1_800_000_000;

function rsa(bits = 2048) {
  return generateKeyPairSync('rsa', { modulusLength: bits });
}

function ec(namedCurve = 'P-256') {
  return generateKeyPairSync('ec', { namedCurve });
}

/** Runtime key pairs, labelled by purpose. */
export const keys = {
  alphaRsa: rsa(),
  alphaEc: ec(),
  betaRsa: rsa(),
  impostorRsa: rsa(),
  impostorEc: ec(),
  weakRsa: rsa(1024),
  p384: ec('P-384'),
};

export function publicJwk(pair, kid, extra = {}) {
  return { ...pair.publicKey.export({ format: 'jwk' }), kid, ...extra };
}

const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

/** Sign a compact JWS. `alg` selects the signing primitive; the header can lie about it. */
export function signToken({ header, payload, privateKey, as = header.alg }) {
  const input = `${b64(header)}.${b64(payload)}`;
  let signature;
  if (as === 'RS256') signature = sign('sha256', Buffer.from(input), privateKey);
  else if (as === 'ES256') signature = sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  else if (as === 'none') signature = Buffer.alloc(0);
  else throw new Error(`unsupported test algorithm ${as}`);
  return `${input}.${signature.toString('base64url')}`;
}

const operator = (tenant, kind) => tenant.operators.find((op) => op.kind === kind && (kind === 'service' || op.roles.includes('sender')));
const admin = (tenant) => tenant.operators.find((op) => op.roles.includes('tenant_admin'));

/** Claims for a synthetic operator of `tenant`, in the tenant's configured claim names. */
export function claimsFor(tenant, who = 'sender', overrides = {}) {
  const op = who === 'service' ? operator(tenant, 'service') : who === 'admin' ? admin(tenant) : operator(tenant, 'human-operator');
  const claimNames = tenant.oidc.claims;
  const roleValue = { sender: 'opensig-sender', admin: 'opensig-tenant-admin', service: 'opensig-service' }[who];
  const scopes = {
    sender: 'envelopes:read envelopes:write envelopes:send envelopes:confirm-send envelopes:void artifacts:read',
    admin: 'envelopes:read envelopes:write envelopes:send envelopes:confirm-send envelopes:void finalization:retry artifacts:read webhooks:admin',
    service: 'envelopes:read envelopes:write envelopes:send artifacts:read',
  }[who];
  return {
    iss: tenant.oidc.issuer,
    aud: tenant.oidc.audience,
    sub: op.subject,
    iat: NOW - 10,
    nbf: NOW - 10,
    exp: NOW + 300,
    [claimNames.tenant]: tenant.id,
    [claimNames.roles]: [roleValue],
    [claimNames.principal_kind]: who === 'service' ? 'service' : 'human',
    scope: scopes,
    ...overrides,
  };
}

export const ROLE_MAP = { 'opensig-sender': 'sender', 'opensig-tenant-admin': 'tenant_admin', 'opensig-service': 'service' };
export const KIND_MAP = { human: 'human-operator', service: 'service' };

export function tenantConfig(tenant, jwks, extra = {}) {
  return {
    tenantId: tenant.id,
    issuer: tenant.oidc.issuer,
    audience: tenant.oidc.audience,
    algorithms: ['RS256', 'ES256'],
    ...(typeof jwks === 'string' ? { jwksFile: jwks } : { jwks }),
    claims: { tenant: tenant.oidc.claims.tenant, roles: tenant.oidc.claims.roles, principalKind: tenant.oidc.claims.principal_kind },
    roleMap: ROLE_MAP,
    kindMap: KIND_MAP,
    ...extra,
  };
}

const temps = [];

/** Write a public JWKS to a 0600 file in a fresh mkdtemp directory. */
export function jwksFile(jwks) {
  const dir = mkdtempSync(join(tmpdir(), 'opensig-auth-'));
  temps.push(dir);
  const path = join(dir, 'jwks.json');
  writeFileSync(path, JSON.stringify(jwks), { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

export function cleanup() {
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
}

/** The standard two-tenant configuration: alpha from a JWKS file (RSA + EC), beta inline (RSA). */
export function standardConfig(extra = {}) {
  const alphaJwks = { keys: [publicJwk(keys.alphaRsa, 'alpha-rsa-1', { use: 'sig', alg: 'RS256' }), publicJwk(keys.alphaEc, 'alpha-ec-1', { use: 'sig' })] };
  return {
    clockSkewSeconds: 60,
    tenants: [tenantConfig(ALPHA, jwksFile(alphaJwks)), tenantConfig(BETA, { keys: [publicJwk(keys.betaRsa, 'beta-rsa-1')] })],
    ...extra,
  };
}

export const rsaHeader = (kid = 'alpha-rsa-1', extra = {}) => ({ alg: 'RS256', kid, typ: 'JWT', ...extra });
export const ecHeader = (kid = 'alpha-ec-1', extra = {}) => ({ alg: 'ES256', kid, ...extra });
