// SPDX-License-Identifier: Apache-2.0
//
// Operator identity configuration (T005; data-model Tenant identity mapping). Each tenant
// maps an exact issuer and audience, pinned algorithms, a JWKS (inline, or read once from
// a local file; never fetched) and the claims that carry the tenant, roles, principal kind
// and scopes. Unknown members are refused, which also refuses discovery or remote-key
// settings such as jwks_uri. Two tenants may share an issuer only when both name a tenant
// claim with distinct values.

import { readFileSync } from 'node:fs';

import { ConfigError, loadJwks, type VerificationKey } from './jwks.ts';
import { isAlgorithm, type Algorithm } from './jwt.ts';

export type OperatorRole = 'sender' | 'tenant_admin' | 'service';
export type PrincipalKind = 'human-operator' | 'service';

export const MAX_CLOCK_SKEW_SECONDS = 60;
const OPERATOR_ROLES: readonly string[] = ['sender', 'tenant_admin', 'service'];
const PRINCIPAL_KINDS: readonly string[] = ['human-operator', 'service'];
const ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const CLAIM_NAME = /^[A-Za-z0-9_.:/-]{1,128}$/;

/** Configuration as supplied (JSON-compatible). */
export interface TenantIdentityInput {
  tenantId: string;
  issuer: string;
  audience: string;
  algorithms: Algorithm[];
  jwks?: unknown;
  jwksFile?: string;
  claims: { tenant?: string; tenantValue?: string; roles: string; principalKind: string; scope?: string };
  roleMap: Record<string, OperatorRole>;
  kindMap: Record<string, PrincipalKind>;
}

export interface OperatorAuthInput {
  clockSkewSeconds?: number;
  tenants: TenantIdentityInput[];
}

export interface TenantIdentity {
  tenantId: string;
  issuer: string;
  audience: string;
  algorithms: readonly Algorithm[];
  keys: ReadonlyMap<string, VerificationKey>;
  tenantClaim: { name: string; value: string } | null;
  rolesClaim: string;
  kindClaim: string;
  scopeClaim: string;
  roleMap: ReadonlyMap<string, OperatorRole>;
  kindMap: ReadonlyMap<string, PrincipalKind>;
}

export interface OperatorAuthConfig {
  clockSkewSeconds: number;
  tenants: readonly TenantIdentity[];
}

const TENANT_MEMBERS = new Set(['tenantId', 'issuer', 'audience', 'algorithms', 'jwks', 'jwksFile', 'claims', 'roleMap', 'kindMap']);
const CLAIM_MEMBERS = new Set(['tenant', 'tenantValue', 'roles', 'principalKind', 'scope']);

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new ConfigError(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function onlyMembers(record: Record<string, unknown>, allowed: Set<string>, label: string): void {
  for (const key of Object.keys(record)) if (!allowed.has(key)) throw new ConfigError(`${label}: unknown member ${key}`);
}

function claimName(value: unknown, label: string): string {
  if (typeof value !== 'string' || !CLAIM_NAME.test(value)) throw new ConfigError(`${label} must be a claim name`);
  return value;
}

function stringMap<T extends string>(value: unknown, allowed: readonly string[], label: string): Map<string, T> {
  const record = object(value, label);
  const map = new Map<string, T>();
  for (const [claimValue, mapped] of Object.entries(record)) {
    if (typeof mapped !== 'string' || !allowed.includes(mapped)) throw new ConfigError(`${label}: ${claimValue} maps to an unknown value`);
    map.set(claimValue, mapped as T);
  }
  if (map.size === 0) throw new ConfigError(`${label} must not be empty`);
  return map;
}

function tenantIdentity(input: unknown, index: number): TenantIdentity {
  const label = `tenants[${index}]`;
  const record = object(input, label);
  onlyMembers(record, TENANT_MEMBERS, label);
  const tenantId = record.tenantId;
  if (typeof tenantId !== 'string' || !ID_PATTERN.test(tenantId)) throw new ConfigError(`${label}.tenantId must match ${ID_PATTERN}`);
  const issuer = record.issuer;
  if (typeof issuer !== 'string' || !/^https:\/\/[^\s]+$/.test(issuer)) throw new ConfigError(`${label}.issuer must be an https URL`);
  const audience = record.audience;
  if (typeof audience !== 'string' || audience.length === 0 || audience.length > 256) throw new ConfigError(`${label}.audience is required`);
  const algorithms = record.algorithms;
  if (!Array.isArray(algorithms) || algorithms.length === 0 || !algorithms.every((alg) => isAlgorithm(alg))) {
    throw new ConfigError(`${label}.algorithms must be a non-empty subset of RS256 and ES256`);
  }
  if ((record.jwks === undefined) === (record.jwksFile === undefined)) throw new ConfigError(`${label} needs exactly one of jwks and jwksFile`);
  let jwks = record.jwks;
  if (record.jwksFile !== undefined) {
    if (typeof record.jwksFile !== 'string' || record.jwksFile.length === 0) throw new ConfigError(`${label}.jwksFile must be a path`);
    try {
      jwks = JSON.parse(readFileSync(record.jwksFile, 'utf8'));
    } catch {
      throw new ConfigError(`${label}.jwksFile is not a readable JSON file`);
    }
  }
  const keys = loadJwks(jwks, algorithms as Algorithm[], `${label}.jwks`);

  const claims = object(record.claims, `${label}.claims`);
  onlyMembers(claims, CLAIM_MEMBERS, `${label}.claims`);
  let tenantClaim: TenantIdentity['tenantClaim'] = null;
  if (claims.tenant !== undefined) {
    const value = claims.tenantValue ?? tenantId;
    if (typeof value !== 'string' || value.length === 0) throw new ConfigError(`${label}.claims.tenantValue must be a string`);
    tenantClaim = { name: claimName(claims.tenant, `${label}.claims.tenant`), value };
  } else if (claims.tenantValue !== undefined) {
    throw new ConfigError(`${label}.claims.tenantValue needs claims.tenant`);
  }
  return {
    tenantId,
    issuer,
    audience,
    algorithms: Object.freeze([...(algorithms as Algorithm[])]),
    keys,
    tenantClaim,
    rolesClaim: claimName(claims.roles, `${label}.claims.roles`),
    kindClaim: claimName(claims.principalKind, `${label}.claims.principalKind`),
    scopeClaim: claims.scope === undefined ? 'scope' : claimName(claims.scope, `${label}.claims.scope`),
    roleMap: stringMap<OperatorRole>(record.roleMap, OPERATOR_ROLES, `${label}.roleMap`),
    kindMap: stringMap<PrincipalKind>(record.kindMap, PRINCIPAL_KINDS, `${label}.kindMap`),
  };
}

/** Validate operator authentication configuration. Throws ConfigError. */
export function loadOperatorAuthConfig(input: unknown): OperatorAuthConfig {
  const record = object(input, 'operator auth configuration');
  onlyMembers(record, new Set(['clockSkewSeconds', 'tenants']), 'operator auth configuration');
  const skew = record.clockSkewSeconds ?? MAX_CLOCK_SKEW_SECONDS;
  if (typeof skew !== 'number' || !Number.isInteger(skew) || skew < 0 || skew > MAX_CLOCK_SKEW_SECONDS) {
    throw new ConfigError(`clockSkewSeconds must be an integer from 0 to ${MAX_CLOCK_SKEW_SECONDS}`);
  }
  if (!Array.isArray(record.tenants) || record.tenants.length === 0) throw new ConfigError('tenants must be a non-empty array');
  const tenants = record.tenants.map((tenant, index) => tenantIdentity(tenant, index));
  const ids = new Set<string>();
  for (const tenant of tenants) {
    if (ids.has(tenant.tenantId)) throw new ConfigError(`duplicate tenantId ${tenant.tenantId}`);
    ids.add(tenant.tenantId);
    const peers = tenants.filter((other) => other.issuer === tenant.issuer);
    if (peers.length > 1) {
      const values = peers.map((peer) => (peer.tenantClaim ? `${peer.tenantClaim.name}=${peer.tenantClaim.value}` : null));
      if (values.includes(null) || new Set(values).size !== values.length) {
        throw new ConfigError(`tenants sharing issuer ${tenant.issuer} must each name a distinct tenant claim value`);
      }
    }
  }
  return { clockSkewSeconds: skew, tenants: Object.freeze(tenants) };
}

export { ConfigError };
