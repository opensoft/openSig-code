// SPDX-License-Identifier: Apache-2.0
//
// Test support for the server tests (T031). Keys are generated at runtime (private keys in
// memory only); the operator auth configuration and JWKS go to a 0600 file in a mkdtemp
// directory removed by cleanup(). Servers bind 127.0.0.1 with an OS-chosen port. The tenants
// table the server checks the configuration against (SEC-07) is a migrated SQLite database
// created in a mkdtemp directory at test runtime with the synthetic alpha tenant.

import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createOperatorAuthenticator, loadOperatorAuthConfig } from '../../src/api/auth/index.ts';
import { openDatabase } from '../../src/storage/db/index.ts';
import { ROUTES } from '../../src/api/routes.ts';
import { createApp, createAppServer } from '../../src/server/app.ts';
import { loadServerConfig } from '../../src/server/config.ts';
import { createLogger } from '../../src/server/redact.ts';

export const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const identities = JSON.parse(readFileSync(join(REPO, 'fixtures', 'synthetic', 'identities', 'identities.json'), 'utf8'));
export const ALPHA = identities.tenants[0];
export const ENVELOPE_ID = 'env_synthetic_00000001';

const keyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const temps = [];

export function tempDir(label = 'server') {
  const dir = mkdtempSync(join(tmpdir(), `opensig-${label}-`));
  temps.push(dir);
  return dir;
}

export function cleanup() {
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
}

export const authInput = () => ({
  tenants: [
    {
      tenantId: ALPHA.id,
      issuer: ALPHA.oidc.issuer,
      audience: ALPHA.oidc.audience,
      algorithms: ['ES256'],
      jwks: { keys: [{ ...keyPair.publicKey.export({ format: 'jwk' }), kid: 'server-test-1' }] },
      claims: { tenant: ALPHA.oidc.claims.tenant, roles: ALPHA.oidc.claims.roles, principalKind: ALPHA.oidc.claims.principal_kind },
      roleMap: { 'opensig-sender': 'sender', 'opensig-tenant-admin': 'tenant_admin', 'opensig-service': 'service' },
      kindMap: { human: 'human-operator', service: 'service' },
    },
  ],
});

/** Write the operator auth configuration (default: authInput()) to a 0600 file and return its path. */
export function authFile(input = authInput()) {
  const path = join(tempDir('auth'), 'operator-auth.json');
  writeFileSync(path, JSON.stringify(input), { mode: 0o600 });
  return path;
}

/** The tenants row that agrees with authInput() for the alpha tenant. */
export function alphaTenantRow(allowedRoles = ['sender', 'tenant_admin', 'service']) {
  const tenant = authInput().tenants[0];
  const now = new Date(Date.UTC(2026, 10, 16, 12, 0, 0)).toISOString();
  return {
    oidc_issuer: tenant.issuer,
    oidc_audience: tenant.audience,
    role_claim: tenant.claims.roles,
    role_map_json: JSON.stringify(tenant.roleMap),
    principal_kind_claim: tenant.claims.principalKind,
    principal_kind_map_json: JSON.stringify(tenant.kindMap),
    allowed_roles_json: JSON.stringify(allowedRoles),
    created_at: now,
    updated_at: now,
  };
}

/**
 * Create a migrated database whose tenants table holds `rows` (tenant id to row; default:
 * the alpha tenant agreeing with authInput()) and return its path.
 */
export function tenantDatabase(rows = { [ALPHA.id]: alphaTenantRow() }, { migrate = true } = {}) {
  const path = join(tempDir('db'), 'opensig.db');
  const db = openDatabase({ path });
  try {
    if (migrate) {
      db.migrate();
      db.transaction(() => {
        for (const [tenantId, row] of Object.entries(rows)) db.forTenant(tenantId).insert('tenants', row);
      });
    }
  } finally {
    db.close();
  }
  return path;
}

/** A bearer token for the synthetic alpha operator `who` (sender, admin or service). */
export function bearer(who = 'sender', overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const roles = { sender: 'opensig-sender', admin: 'opensig-tenant-admin', service: 'opensig-service' };
  const op = ALPHA.operators.find((o) => (who === 'service' ? o.kind === 'service' : who === 'admin' ? o.roles.includes('tenant_admin') : o.roles.includes('sender')));
  const payload = {
    iss: ALPHA.oidc.issuer,
    aud: ALPHA.oidc.audience,
    sub: op.subject,
    exp: now + 300,
    [ALPHA.oidc.claims.tenant]: ALPHA.id,
    [ALPHA.oidc.claims.roles]: [roles[who]],
    [ALPHA.oidc.claims.principal_kind]: who === 'service' ? 'service' : 'human',
    scope: 'envelopes:read envelopes:write envelopes:send envelopes:confirm-send envelopes:void artifacts:read finalization:retry webhooks:admin',
    ...overrides,
  };
  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${b64({ alg: 'ES256', kid: 'server-test-1', typ: 'JWT' })}.${b64(payload)}`;
  const signature = sign('sha256', Buffer.from(input), { key: keyPair.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${signature.toString('base64url')}`;
}

/**
 * Serve the real application on 127.0.0.1. `handlers` replaces the handler of named
 * operations in a copy of the production registry (the policy under test is the server's;
 * the handlers only produce a response to apply it to).
 */
export async function serveApp({ handlers = {}, origins = ['http://127.0.0.1:1'], auth = true } = {}) {
  const lines = [];
  const logger = createLogger((line) => lines.push(line));
  const routes = ROUTES.map((route) => (handlers[route.operationId] ? { ...route, handler: handlers[route.operationId] } : route));
  const authenticator = auth ? createOperatorAuthenticator(loadOperatorAuthConfig(authInput())) : null;
  const config = loadServerConfig({ OPENSIG_PORT: '0' });
  const app = createApp({ routes, config, logger, authenticator, allowedOrigins: new Set(origins) });
  // Built as the entrypoint builds it (src/server/main.ts), client-error handling included.
  const server = createAppServer(app);
  await new Promise((resolveListen) => server.listen({ host: '127.0.0.1', port: 0 }, resolveListen));
  const { port } = server.address();
  return {
    port,
    lines,
    logText: () => lines.join('\n'),
    close: () =>
      new Promise((resolveClose) => {
        server.close(resolveClose);
        server.closeAllConnections();
      }),
  };
}

/** One HTTP request; resolves with { status, headers, text, json }. */
export function send(port, { method = 'GET', path = '/', headers = {}, body, socketPath } = {}) {
  return new Promise((resolveResponse, reject) => {
    const target = socketPath ? { socketPath } : { host: '127.0.0.1', port };
    const req = request({ ...target, method, path, headers, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {
          json = null;
        }
        resolveResponse({ status: res.statusCode, headers: res.headers, text, json, bytes: Buffer.concat(chunks) });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/**
 * Stream `total` bytes in `chunk`-sized pieces (chunked transfer unless contentLength is
 * given) and stop as soon as a response arrives. Resolves with the response and the
 * number of bytes the client managed to write.
 */
export function streamUpload(port, { method = 'PUT', path, headers = {}, total, chunk = 64 * 1024, fill = 0x20 }) {
  return new Promise((resolveUpload, reject) => {
    let written = 0;
    let response = null;
    const piece = Buffer.alloc(chunk, fill);
    const req = request({ host: '127.0.0.1', port, method, path, headers, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        response = { status: res.statusCode, headers: res.headers, json: JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null') };
        resolveUpload({ ...response, written });
        req.destroy();
      });
    });
    req.on('error', (error) => {
      if (response === null && !['ECONNRESET', 'EPIPE'].includes(error.code)) reject(error);
    });
    const pump = () => {
      while (response === null && written < total) {
        const size = Math.min(chunk, total - written);
        written += size;
        if (!req.write(size === chunk ? piece : piece.subarray(0, size))) {
          req.once('drain', pump);
          return;
        }
      }
      if (response === null && written >= total) req.end();
    };
    pump();
  });
}
