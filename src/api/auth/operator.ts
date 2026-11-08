// SPDX-License-Identifier: Apache-2.0
//
// Operator authentication (T005). Operators present OIDC access tokens as
// `Authorization: Bearer <JWS>` and nothing else: there is no operator browser session, so
// no other header, query parameter or request body is ever read for operator credentials.
//
// A token is accepted only when:
// - its issuer exactly equals a configured tenant issuer (no normalization);
// - its algorithm is pinned for that tenant (RS256 or ES256) and its kid names a configured
//   key of the matching type, under which the signature verifies;
// - its audience exactly equals the tenant audience (a string, or a one-element array);
// - exp is present and not passed, nbf is not in the future and iat is not in the future,
//   each within the configured skew (at most 60 s);
// - the tenant claim (when configured) carries the tenant's value, sub is a string, and
//   the principal-kind claim maps to human-operator or service;
// - the mapped roles are consistent with the kind: a service principal holds only
//   `service`, and a human operator never holds `service`.
// Failures are a uniform 401 with WWW-Authenticate: Bearer; the internal reason is for
// tests and logs only and never echoes token content.

import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

import type { OperatorAuthConfig, OperatorRole, PrincipalKind, TenantIdentity } from './config.ts';
import { decodeToken, TokenError, verifySignature, type Algorithm, type DecodedToken } from './jwt.ts';

export interface OperatorPrincipal {
  readonly scheme: 'operator';
  readonly tenant_id: string;
  readonly kind: PrincipalKind;
  readonly roles: readonly OperatorRole[];
  readonly scopes: readonly string[];
  /** Opaque, tenant-scoped reference (contract PrincipalRef.ref); never the raw subject. */
  readonly ref: string;
  readonly issuer: string;
  readonly expires_at: number;
}

export type AuthenticationResult =
  | { ok: true; principal: OperatorPrincipal }
  | { ok: false; status: 401; code: 'unauthenticated'; reason: string; wwwAuthenticate: string };

export type HeaderBag = Readonly<Record<string, string | readonly string[] | undefined>>;

const BEARER = /^Bearer[ ]+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i;

function unauthenticated(reason: string, tokenPresented: boolean): AuthenticationResult {
  return {
    ok: false,
    status: 401,
    code: 'unauthenticated',
    reason,
    wwwAuthenticate: tokenPresented ? 'Bearer error="invalid_token"' : 'Bearer',
  };
}

function principalRef(tenantId: string, issuer: string, subject: string): string {
  const digest = createHash('sha256').update(`opensig-operator\0${tenantId}\0${issuer}\0${subject}`).digest();
  return `op_${Buffer.from(digest).toString('base64url').slice(0, 40)}`;
}

function claimValues(value: unknown): string[] | null {
  if (typeof value === 'string') return value.split(' ').filter((part) => part.length > 0);
  if (Array.isArray(value) && value.every((item) => typeof item === 'string')) return [...(value as string[])];
  return null;
}

function audienceMatches(aud: unknown, expected: string): boolean {
  if (typeof aud === 'string') return aud === expected;
  return Array.isArray(aud) && aud.length === 1 && aud[0] === expected;
}

function numericDate(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** Check one candidate tenant; returns the principal or a failure reason. */
function evaluate(decoded: DecodedToken, tenant: TenantIdentity, skew: number, now: number): OperatorPrincipal | string {
  const alg = decoded.header.alg as Algorithm;
  if (!tenant.algorithms.includes(alg)) return 'algorithm';
  const entry = tenant.keys.get(decoded.header.kid as string);
  if (entry === undefined) return 'unknown-key';
  if (entry.alg !== null && entry.alg !== alg) return 'algorithm';
  if (!verifySignature(decoded, alg, entry.key)) return 'signature';

  const claims = decoded.payload;
  if (!audienceMatches(claims.aud, tenant.audience)) return 'audience';
  const exp = numericDate(claims.exp);
  if (exp === null) return 'expiry-missing';
  if (now >= exp + skew) return 'expired';
  if (claims.nbf !== undefined) {
    const nbf = numericDate(claims.nbf);
    if (nbf === null || now < nbf - skew) return 'not-yet-valid';
  }
  if (claims.iat !== undefined) {
    const iat = numericDate(claims.iat);
    if (iat === null || iat > now + skew) return 'issued-in-future';
  }
  if (tenant.tenantClaim !== null && claims[tenant.tenantClaim.name] !== tenant.tenantClaim.value) return 'tenant';
  if (typeof claims.sub !== 'string' || claims.sub.length === 0 || claims.sub.length > 256) return 'subject';

  const kindValue = claims[tenant.kindClaim];
  const kind = typeof kindValue === 'string' ? tenant.kindMap.get(kindValue) : undefined;
  if (kind === undefined) return 'principal-kind';
  const roleValues = claims[tenant.rolesClaim] === undefined ? [] : claimValues(claims[tenant.rolesClaim]);
  if (roleValues === null) return 'roles';
  const roles = [...new Set(roleValues.map((value) => tenant.roleMap.get(value)).filter((role) => role !== undefined))].sort();
  if (kind === 'service' && roles.some((role) => role !== 'service')) return 'service-role-conflict';
  if (kind === 'human-operator' && roles.includes('service')) return 'human-role-conflict';
  const scopeValues = claims[tenant.scopeClaim] === undefined ? [] : claimValues(claims[tenant.scopeClaim]);
  if (scopeValues === null) return 'scopes';

  return Object.freeze({
    scheme: 'operator',
    tenant_id: tenant.tenantId,
    kind,
    roles: Object.freeze(roles),
    scopes: Object.freeze([...new Set(scopeValues)].sort()),
    ref: principalRef(tenant.tenantId, tenant.issuer, claims.sub),
    issuer: tenant.issuer,
    expires_at: exp,
  });
}

export interface OperatorAuthenticator {
  /** Authenticate from request headers; only `authorization` is read. */
  authenticate(headers: HeaderBag, nowSeconds?: number): AuthenticationResult;
  /** Authenticate a bare compact token (the value after "Bearer "). */
  verifyToken(token: string, nowSeconds?: number): AuthenticationResult;
}

export function createOperatorAuthenticator(config: OperatorAuthConfig): OperatorAuthenticator {
  const verifyToken = (token: string, nowSeconds: number = Date.now() / 1000): AuthenticationResult => {
    let decoded: DecodedToken;
    try {
      decoded = decodeToken(token);
    } catch (error) {
      return unauthenticated(error instanceof TokenError ? error.reason : 'malformed', true);
    }
    const issuer = decoded.payload.iss;
    const candidates = typeof issuer === 'string' ? config.tenants.filter((tenant) => tenant.issuer === issuer) : [];
    if (candidates.length === 0) return unauthenticated('issuer', true);
    let reason = 'issuer';
    for (const tenant of candidates) {
      const result = evaluate(decoded, tenant, config.clockSkewSeconds, nowSeconds);
      if (typeof result !== 'string') return { ok: true, principal: result };
      reason = result;
    }
    return unauthenticated(reason, true);
  };

  return {
    verifyToken,
    authenticate(headers: HeaderBag, nowSeconds?: number): AuthenticationResult {
      let header = headers.authorization;
      if (Array.isArray(header)) {
        if (header.length !== 1) return unauthenticated('authorization-header', true);
        header = header[0];
      }
      if (header === undefined || header === '') return unauthenticated('missing', false);
      const match = typeof header === 'string' ? BEARER.exec(header) : null;
      if (match === null || match[1] === undefined) return unauthenticated('authorization-scheme', true);
      return verifyToken(match[1], nowSeconds);
    },
  };
}
