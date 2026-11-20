// SPDX-License-Identifier: Apache-2.0
//
// Test support for the server tests (T031). Keys are generated at runtime (private keys in
// memory only); the operator auth configuration and JWKS go to a 0600 file in a mkdtemp
// directory removed by cleanup(). Servers bind 127.0.0.1 with an OS-chosen port. The tenants
// table the server checks the configuration against (SEC-07) is a migrated SQLite database
// created in a mkdtemp directory at test runtime with the synthetic alpha tenant.
// Since the US1 composition (row WIRE-US1) the entrypoint always composes the database, the
// blob store (<OPENSIG_DATA_DIR>/blobs), the T032 notifier and the 0600 challenge-HMAC key
// file: composedEnv() builds that environment, each file in its own mkdtemp directory, with
// mail to a mkdtemp spool only.
// Since the US2 composition (row ARTIFACT-ROUTES) the seal and trust-anchor settings are
// optional, so composedEnv() leaves them out and its server composes no finalization runner.
// sealFiles() and anchorsFile() add them: a synthetic RSA-3072 seal key generated in memory at
// first use, written only as a 0600 PKCS#8 file in its own mkdtemp directory, and self-signed
// synthetic certificates built in memory by T014's test-local builder
// (tests/integrity/product/helpers/cert-build.mjs, node built-ins only; imported read-only).

import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
import { buildCertificate, rsaKeyPair } from '../integrity/product/helpers/cert-build.mjs';

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

export const CONSENT_WORDING = 'I have reviewed this synthetic document and I approve it as shown.';

/** Give the alpha tenant of the database at `path` a consent text in force (the recipient session state needs one). */
export function seedConsent(path, tenantId = ALPHA.id) {
  const db = openDatabase({ path });
  try {
    const id = `consent_${randomBytes(9).toString('base64url')}`;
    const now = new Date(Date.UTC(2026, 10, 16, 12, 0, 0)).toISOString();
    db.transaction(() => {
      const store = db.forTenant(tenantId);
      store.insert('consent_texts', {
        id,
        version: '2026.11-synthetic',
        locale: 'en',
        text: CONSENT_WORDING,
        text_digest: createHash('sha256').update(CONSENT_WORDING, 'utf8').digest('hex'),
        effective_from: now,
        created_at: now,
      });
      store.update('tenants', {}, { consent_text_id: id });
    });
  } finally {
    db.close();
  }
}

/**
 * A challenge-HMAC key file in its own mkdtemp directory: `bytes` (default 32 random bytes,
 * generated now and never printed) with `mode` (default 0600). Returns its path.
 */
export function keyFile({ bytes = randomBytes(32), mode = 0o600 } = {}) {
  const path = join(tempDir('key'), 'challenge-hmac.key');
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, mode);
  return path;
}

/**
 * The environment of a composed server (WIRE-US1) on 127.0.0.1 with an OS-chosen port: a data
 * directory, a migrated database (default: the alpha tenant agreeing with authInput()), the
 * 0600 key file and a mkdtemp mail spool. `overrides` replace or add settings; a value of
 * undefined removes one.
 */
export function composedEnv(overrides = {}) {
  const dataDir = tempDir('data');
  const env = {
    OPENSIG_PORT: '0',
    OPENSIG_DATA_DIR: dataDir,
    OPENSIG_DATABASE: tenantDatabase(),
    OPENSIG_CHALLENGE_KEY_FILE: keyFile(),
    OPENSIG_MAIL_TRANSPORT: 'spool',
    OPENSIG_SPOOL_DIR: join(tempDir('spool'), 'spool'),
    ...overrides,
  };
  for (const [name, value] of Object.entries(env)) if (value === undefined) delete env[name];
  return env;
}

const DAY = 24 * 60 * 60 * 1000;
let sealKeys = null;

/** This test process's synthetic seal key pair (RSA-3072, exponent 65537), generated at first use and held in memory. */
export function sealKeyPair() {
  sealKeys ??= rsaKeyPair(3072);
  return sealKeys;
}

/** A synthetic self-signed certificate for `keyPair`, valid from a day ago for 30 days: { der, pem }. */
export function certificateFor(keyPair, { commonName = 'T031 Development Seal (seal.example.test)', serial = 0x3101 } = {}) {
  const now = Date.now();
  const built = buildCertificate({ commonName, keyPair, serial, notBefore: new Date(now - DAY), notAfter: new Date(now + 30 * DAY) });
  return { der: built.der, pem: built.x509.toString() };
}

/**
 * The seal settings (row ARTIFACT-ROUTES): OPENSIG_SEAL_KEY_FILE, the PKCS#8 private key of
 * `keyPair` (or `keyBytes`) at `keyMode` (default 0600), and OPENSIG_SEAL_CERT_FILE, its
 * self-signed certificate as PEM (or `certificate`), each in its own mkdtemp directory.
 */
export function sealFiles({ keyPair = sealKeyPair(), keyMode = 0o600, keyBytes, certificate } = {}) {
  const keyPath = join(tempDir('seal-key'), 'seal.key');
  writeFileSync(keyPath, keyBytes ?? keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  chmodSync(keyPath, keyMode);
  const certPath = join(tempDir('seal-cert'), 'seal-cert.pem');
  writeFileSync(certPath, certificate ?? certificateFor(keyPair).pem, { mode: 0o600 });
  return { OPENSIG_SEAL_KEY_FILE: keyPath, OPENSIG_SEAL_CERT_FILE: certPath };
}

/** OPENSIG_TRUST_ANCHORS_FILE holding `text` (default: one synthetic anchor certificate), in its own mkdtemp directory. */
export function anchorsFile(text) {
  const path = join(tempDir('anchors'), 'anchors.pem');
  const anchor = () => certificateFor(rsaKeyPair(3072), { commonName: 'T031 Development Anchor (anchor.example.test)', serial: 0x3102 }).pem;
  writeFileSync(path, text ?? anchor(), { mode: 0o600 });
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
export async function serveApp({ handlers = {}, origins = ['http://127.0.0.1:1'], auth = true, serverOptions = {}, staticHandler = null } = {}) {
  const lines = [];
  const logger = createLogger((line) => lines.push(line));
  const routes = ROUTES.map((route) => (handlers[route.operationId] ? { ...route, handler: handlers[route.operationId] } : route));
  const authenticator = auth ? createOperatorAuthenticator(loadOperatorAuthConfig(authInput())) : null;
  const config = loadServerConfig({ OPENSIG_PORT: '0' });
  // SEC-01 (extended, STATIC-CACHE) passes a stub static handler; every other test serves none.
  const app = createApp({ routes, config, logger, authenticator, allowedOrigins: new Set(origins), staticHandler });
  // Built as the entrypoint builds it (src/server/main.ts), client-error handling included.
  const server = createAppServer(app, serverOptions);
  await new Promise((resolveListen) => server.listen({ host: '127.0.0.1', port: 0 }, resolveListen));
  const { port } = server.address();
  return {
    port,
    server,
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
