// SPDX-License-Identifier: Apache-2.0
//
// Storage-backed tenant role policy and the startup agreement check (T031, A-008 P11, SEC-07).
//
// The canonical tenants table (T003) owns each tenant's identity mapping and allowed_roles;
// the deployment configuration (OPENSIG_OPERATOR_AUTH_FILE, T005) adds the keys and pinned
// algorithms and repeats the identity mapping. When operator authentication is configured the
// server opens the existing, migrated database (never creating it) and refuses to start
// unless the two agree:
// - the same set of tenant ids;
// - per tenant: issuer, audience, role claim, role map, principal-kind claim and
//   principal-kind map equal (a table row with no principal-kind map disagrees);
// - allowed_roles_json is a list of known operator roles.
// Refusals name the tenant and the field, never a value from either source.
//
// The TenantPolicy given to the authenticator reads allowed_roles from the table on every
// operator request, so a change to a tenant's allowed roles applies without a restart. A
// tenant missing from the table, or a malformed value, makes the authenticator fail closed.

import { existsSync } from 'node:fs';

import type { OperatorAuthConfig, TenantIdentity } from '../api/auth/config.ts';
import type { TenantPolicy } from '../api/auth/operator.ts';
import { openDatabase, type Database, type Row } from '../storage/db/index.ts';
import { loadMigrations } from '../storage/schema/migrations.ts';
import { ServerConfigError } from './config.ts';

const OPERATOR_ROLES: readonly string[] = ['sender', 'tenant_admin', 'service'];

export interface TenantPolicySource {
  readonly policy: TenantPolicy;
  /** The tenant ids the configuration and the table agree on, sorted. */
  readonly tenantIds: readonly string[];
  close(): void;
}

/** The allowed roles recorded in a tenants row, or null when the value is malformed. */
function allowedRoles(row: Row | undefined): string[] | null {
  if (row === undefined || typeof row['allowed_roles_json'] !== 'string') return null;
  let value: unknown;
  try {
    value = JSON.parse(row['allowed_roles_json']);
  } catch {
    return null;
  }
  if (!Array.isArray(value) || value.length > OPERATOR_ROLES.length) return null;
  if (!value.every((role) => typeof role === 'string' && OPERATOR_ROLES.includes(role))) return null;
  if (new Set(value).size !== value.length) return null;
  return [...(value as string[])];
}

function jsonObject(text: unknown): Record<string, unknown> | null {
  if (typeof text !== 'string') return null;
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function sameMap(configured: ReadonlyMap<string, string>, recorded: Record<string, unknown> | null): boolean {
  if (recorded === null) return false;
  const keys = Object.keys(recorded);
  return keys.length === configured.size && keys.every((key) => configured.get(key) === recorded[key]);
}

/** The first field on which the configured tenant and its table row disagree, or null. */
function disagreement(tenant: TenantIdentity, row: Row): string | null {
  if (row['oidc_issuer'] !== tenant.issuer) return 'issuer';
  if (row['oidc_audience'] !== tenant.audience) return 'audience';
  if (row['role_claim'] !== tenant.rolesClaim) return 'role claim';
  if (!sameMap(tenant.roleMap, jsonObject(row['role_map_json']))) return 'role map';
  if (row['principal_kind_claim'] !== tenant.kindClaim) return 'principal-kind claim';
  if (!sameMap(tenant.kindMap, jsonObject(row['principal_kind_map_json']))) return 'principal-kind map';
  if (allowedRoles(row) === null) return 'allowed roles (not a list of known operator roles)';
  return null;
}

function refuse(message: string): never {
  throw new ServerConfigError(`operator authentication refused: ${message}`);
}

function checkAgreement(db: Database, auth: OperatorAuthConfig): string[] {
  const expected = loadMigrations().length;
  const version = db.checkSchema();
  if (version !== expected) refuse(`the database schema is at version ${version}, not ${expected}; migrate it first`);
  const recorded = db.listTenantIds();
  const configured = auth.tenants.map((tenant) => tenant.tenantId);
  const missing = configured.filter((id) => !recorded.includes(id));
  if (missing.length > 0) refuse(`tenant ${missing.join(', ')} is configured in OPENSIG_OPERATOR_AUTH_FILE but absent from the tenants table`);
  const unconfigured = recorded.filter((id) => !configured.includes(id));
  if (unconfigured.length > 0) refuse(`tenant ${unconfigured.join(', ')} is in the tenants table but absent from OPENSIG_OPERATOR_AUTH_FILE`);
  for (const tenant of auth.tenants) {
    const row = db.forTenant(tenant.tenantId).get('tenants', {});
    const field = row === undefined ? 'row' : disagreement(tenant, row);
    if (field !== null) refuse(`tenant ${tenant.tenantId}: the ${field} differs between OPENSIG_OPERATOR_AUTH_FILE and the tenants table`);
  }
  return [...configured].sort();
}

/**
 * Open the tenants table at `databasePath` and check it against `auth`. Throws
 * ServerConfigError when no database is configured, it does not exist, cannot be opened, is
 * not migrated, or disagrees with the configuration.
 */
export function openTenantPolicy(databasePath: string | null, auth: OperatorAuthConfig): TenantPolicySource {
  if (databasePath === null) refuse('the tenants table is required: set OPENSIG_DATABASE (or OPENSIG_DATA_DIR)');
  if (!existsSync(databasePath)) refuse('the database named by OPENSIG_DATABASE does not exist');
  let db: Database;
  try {
    db = openDatabase({ path: databasePath });
  } catch {
    refuse('the database named by OPENSIG_DATABASE could not be opened (it must be a 0600 regular file)');
  }
  let tenantIds: string[];
  try {
    tenantIds = checkAgreement(db, auth);
  } catch (error) {
    db.close();
    if (error instanceof ServerConfigError) throw error;
    refuse('the tenants table could not be read');
  }
  const policy: TenantPolicy = Object.freeze({
    allowedRoles(tenantId: string): string[] | null {
      return allowedRoles(db.forTenant(tenantId).get('tenants', {}));
    },
  });
  return Object.freeze({ policy, tenantIds: Object.freeze(tenantIds), close: () => db.close() });
}
