// SPDX-License-Identifier: Apache-2.0
//
// Test support for approval and decline (T010). Everything is synthetic and local,
// generated at run time and removed afterwards:
// - two tenants, alpha and beta, from the T004 synthetic identities fixture, each with its
//   own runtime ES256 key pair (private keys in memory only), a tenants row that agrees with
//   the operator auth configuration (SEC-07), and its consent text in force;
// - a migrated SQLite database, a blob store, a mail spool and the 0600 challenge-HMAC key
//   file, each in its own mkdtemp directory;
// - synthetic PDF-shaped document bytes built here (approval never parses a document);
// - recipient identities on example.test only.
// The application is the real one (src/server/app.ts) built by createAppServer, with the
// production route registry and the T008, T034 and T010 handler maps installed
// (withRecipientHandlers, withEnvelopeHandlers, withApprovalHandlers), the real T005
// authenticator with T031's storage-backed tenant role policy, and the T008 ceremony, the
// T034 EnvelopeApi and the T010 ApprovalApi in its locals. Mail goes through the T032
// notifier to the spool only. The server is bound to 127.0.0.1 on an OS-chosen port.
// Nothing here replaces a production module.
//
// Envelopes are created, uploaded, prepared and sent through the T007 envelope service of
// the T034 EnvelopeApi (whose onChange is the ceremony's), so the send issues and mails
// recipient 1's invitation exactly as the operator route does; sessions are opened through
// the real recipient routes with the mailed token and code. Capability values (invitation
// tokens, codes, session values, CSRF tokens) are read back from the spool or the responses,
// kept in memory, and never put in a test name or an assertion message.

import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { chmodSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { createOperatorAuthenticator, loadOperatorAuthConfig } from '../../src/api/auth/index.ts';
import { capabilityHash, csrfToken, newCsrfSecret, newSessionValue } from '../../src/api/auth/recipient-session.ts';
import { ENVELOPE_API, EnvelopeApi } from '../../src/api/envelopes/index.ts';
import { APPROVAL_API, ApprovalApi } from '../../src/api/recipients/approval.ts';
import { RECIPIENT_CEREMONY, RecipientCeremony, loadChallengeKey } from '../../src/api/recipients/index.ts';
import { ROUTES, withApprovalHandlers, withEnvelopeHandlers, withRecipientHandlers } from '../../src/api/routes.ts';
import { createNotifier, createSpoolTransport } from '../../src/notifications/index.ts';
import { createApp, createAppServer } from '../../src/server/app.ts';
import { loadServerConfig } from '../../src/server/config.ts';
import { createLogger } from '../../src/server/redact.ts';
import { openTenantPolicy } from '../../src/server/tenants.ts';
import { openBlobStore } from '../../src/storage/blobs/index.ts';
import { insertSession } from '../../src/storage/repositories/recipients.ts';
import { loadVendoredContract } from '../contract/envelopes/lib/contract.mjs';
import { validate } from '../contract/envelopes/lib/schema.mjs';
import { BASE_TIME, makeScratch, openTemp, sid, ts } from '../storage/support/fixtures.mjs';

export { BASE_TIME, sid, ts };

export const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const identities = JSON.parse(readFileSync(join(REPO, 'fixtures', 'synthetic', 'identities', 'identities.json'), 'utf8'));

export const ORIGIN = 'https://sign.alpha.test';
export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;
export const COOKIE = '__Host-opensig_rs';
export const CONSENT_WORDING = 'I have reviewed this synthetic document and I approve it as shown.';
export const APPROVAL_PATH = '/v1/recipient-session/approval';
export const DECLINE_PATH = '/v1/recipient-session/decline';
export const SESSION_PATH = '/v1/recipient-session';
/** The operator actor of envelopes the tests create through the domain. */
export const HUMAN = Object.freeze({ kind: 'human-operator', ref: 'operator-approval-tests' });
/** Generous ceremony limits: every test request comes from 127.0.0.1. */
const LIMITS = Object.freeze({
  challengePerAddress: { limit: 10_000, windowMs: 10 * MINUTE },
  challengePerInvitation: { limit: 1_000, windowMs: 10 * MINUTE },
  sessionPerAddress: { limit: 10_000, windowMs: 10 * MINUTE },
  sessionPerInvitation: { limit: 1_000, windowMs: 10 * MINUTE },
});

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** The two synthetic tenants, by short name. */
export const TENANTS = Object.freeze({ alpha: identities.tenants[0], beta: identities.tenants[1] });

const KEYS = { alpha: generateKeyPairSync('ec', { namedCurve: 'P-256' }), beta: generateKeyPairSync('ec', { namedCurve: 'P-256' }) };
const ROLE_MAP = Object.freeze({ 'opensig-sender': 'sender', 'opensig-tenant-admin': 'tenant_admin', 'opensig-service': 'service' });
const KIND_MAP = Object.freeze({ human: 'human-operator', service: 'service' });
const ROLE_VALUE = Object.freeze({ sender: 'opensig-sender', admin: 'opensig-tenant-admin', service: 'opensig-service' });
const ROLE_SCOPES = Object.freeze({
  sender: Object.freeze(['envelopes:read', 'envelopes:write', 'envelopes:send', 'envelopes:confirm-send', 'envelopes:void', 'artifacts:read']),
  admin: Object.freeze(['envelopes:read', 'envelopes:write', 'envelopes:send', 'envelopes:confirm-send', 'envelopes:void', 'finalization:retry', 'artifacts:read', 'webhooks:admin']),
  service: Object.freeze(['envelopes:read', 'envelopes:write', 'envelopes:send', 'artifacts:read']),
});

function authInput() {
  return {
    tenants: Object.entries(TENANTS).map(([name, tenant]) => ({
      tenantId: tenant.id,
      issuer: tenant.oidc.issuer,
      audience: tenant.oidc.audience,
      algorithms: ['ES256'],
      jwks: { keys: [{ ...KEYS[name].publicKey.export({ format: 'jwk' }), kid: `${name}-approval-1` }] },
      claims: { tenant: tenant.oidc.claims.tenant, roles: tenant.oidc.claims.roles, principalKind: tenant.oidc.claims.principal_kind },
      roleMap: { ...ROLE_MAP },
      kindMap: { ...KIND_MAP },
    })),
  };
}

function tenantRow(entry) {
  const now = ts(0);
  return {
    oidc_issuer: entry.issuer,
    oidc_audience: entry.audience,
    role_claim: entry.claims.roles,
    role_map_json: JSON.stringify(entry.roleMap),
    principal_kind_claim: entry.claims.principalKind,
    principal_kind_map_json: JSON.stringify(entry.kindMap),
    allowed_roles_json: JSON.stringify(['sender', 'tenant_admin', 'service']),
    created_at: now,
    updated_at: now,
  };
}

/**
 * A bearer token, valid for ten minutes of real time, for the synthetic operator `who`
 * (sender, admin or service) of `tenant`, signed with that tenant's runtime key: a credential
 * the T005 authenticator accepts on operator routes.
 */
export function bearer(tenant = 'alpha', who = 'sender') {
  const identity = TENANTS[tenant];
  const op = identity.operators.find((o) => (who === 'service' ? o.kind === 'service' : who === 'admin' ? o.roles.includes('tenant_admin') : o.roles.includes('sender')));
  const claims = identity.oidc.claims;
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: identity.oidc.issuer,
    aud: identity.oidc.audience,
    sub: op.subject,
    exp: now + 600,
    [claims.tenant]: identity.id,
    [claims.roles]: [ROLE_VALUE[who]],
    [claims.principal_kind]: who === 'service' ? 'service' : 'human',
    scope: ROLE_SCOPES[who].join(' '),
  };
  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${b64({ alg: 'ES256', kid: `${tenant}-approval-1`, typ: 'JWT' })}.${b64(payload)}`;
  const signature = sign('sha256', Buffer.from(input), { key: KEYS[tenant].privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${signature.toString('base64url')}`;
}

// --- contract -------------------------------------------------------------------------------

let contractDoc;
export function contract() {
  contractDoc ??= loadVendoredContract().doc;
  return contractDoc;
}

/** Errors of `value` against a component schema of the vendored contract. */
export function contractErrors(schemaName, value) {
  const schema = contract().components.schemas[schemaName];
  assert.ok(schema, `the contract defines ${schemaName}`);
  return validate(contract(), schema, value);
}

/** An Error body without its correlation_id, for comparing two refusals. */
export function errorShape(response) {
  const { correlation_id: _ignored, ...rest } = response.json ?? {};
  return rest;
}

/** Assert a contract Error response with this status and code. */
export function assertError(response, status, code, what) {
  assert.equal(response.status, status, `${what}: status ${response.status} ${response.json?.code ?? ''}`);
  assert.equal(response.json?.code, code, `${what}: code`);
  assert.deepEqual(contractErrors('Error', response.json), [], `${what}: a contract Error body`);
}

// --- HTTP -----------------------------------------------------------------------------------

/**
 * One HTTP request; resolves with { status, headers, rawHeaders, bytes, text, json } once the
 * whole response is in. A string body is sent exactly as given (application/json unless
 * headers say otherwise); any other body is JSON.stringify'd.
 */
export function call(port, { method = 'GET', path, headers = {}, body } = {}) {
  return new Promise((resolveResponse, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
    const allHeaders = { ...headers };
    if (payload !== undefined) {
      if (!Object.keys(allHeaders).some((name) => name.toLowerCase() === 'content-type')) allHeaders['content-type'] = 'application/json';
      allHeaders['content-length'] = String(payload.length);
    }
    const req = request({ host: '127.0.0.1', port, method, path, headers: allHeaders, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const bytes = Buffer.concat(chunks);
        const text = bytes.toString('utf8');
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {
          json = null;
        }
        resolveResponse({ status: res.statusCode, headers: res.headers, rawHeaders: [...res.rawHeaders], bytes, text, json });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

/** A controllable clock: { clock, advance(ms), set(ms), now }. */
export function testClock(start = BASE_TIME) {
  const state = { now: start };
  return {
    clock: () => new Date(state.now),
    advance(ms) {
      state.now += ms;
    },
    set(ms) {
      state.now = ms;
    },
    get now() {
      return new Date(state.now);
    },
  };
}

/**
 * Columns a refused recipient mutation may still change: the T008 guard moves the session's
 * last_seen_at once the session and its CSRF token pass, before the approval or decline runs.
 */
export const GUARD_TOUCH = Object.freeze({ recipient_sessions: Object.freeze(['last_seen_at']) });

/** Tables an approval, a decline, a void or an expiry could change. */
export const APPROVAL_TABLES = Object.freeze([
  'envelopes',
  'recipients',
  'invitations',
  'challenges',
  'recipient_sessions',
  'approvals',
  'approval_receipts',
  'signing_jobs',
  'idempotency_records',
  'audit_events',
  'outbox_events',
]);

/** Synthetic PDF-shaped bytes (approval serves no document; the digest is what binds). */
export function syntheticPdf(label) {
  return Buffer.from(['%PDF-1.7', `% synthetic approval document ${label} ${randomBytes(6).toString('hex')}`, '1 0 obj << /Type /Catalog >> endobj', 'trailer << /Root 1 0 R >>', '%%EOF', ''].join('\n'), 'latin1');
}

/**
 * The synthetic world. `busyTimeoutMs` is the database's bounded wait for the write lock
 * (the race test raises it for its own world only). `wiring` is 't010' (default: T008's and
 * T034's handler maps with T010's installed over them, as WIRE-US1 will compose them) or
 * 't008' (T008's and T034's maps only: approval and decline keep T008's guard-only entries,
 * though the ApprovalApi is composed; AP-15).
 */
export async function createWorld({ busyTimeoutMs, wiring = 't010' } = {}) {
  const scratch = makeScratch();
  const { db, path } = openTemp(scratch, busyTimeoutMs === undefined ? {} : { busyTimeoutMs });
  const input = authInput();
  const consent = {};
  db.transaction(() => {
    for (const entry of input.tenants) db.forTenant(entry.tenantId).insert('tenants', tenantRow(entry));
  });
  for (const [name, tenant] of Object.entries(TENANTS)) {
    const record = { id: sid('consent'), version: '2026.11-synthetic', text: CONSENT_WORDING, digest: sha256(Buffer.from(CONSENT_WORDING, 'utf8')) };
    db.transaction(() => {
      const store = db.forTenant(tenant.id);
      store.insert('consent_texts', { id: record.id, version: record.version, locale: 'en', text: record.text, text_digest: record.digest, effective_from: ts(0), created_at: ts(0) });
      store.update('tenants', {}, { consent_text_id: record.id });
    });
    consent[name] = record;
  }
  const authConfig = loadOperatorAuthConfig(input);
  const tenantPolicy = openTenantPolicy(path, authConfig);
  const authenticator = createOperatorAuthenticator(authConfig, { tenantPolicy: tenantPolicy.policy });

  const keyPath = join(scratch.dir('opensig-key-'), 'challenge-hmac.key');
  writeFileSync(keyPath, randomBytes(32), { mode: 0o600 });
  chmodSync(keyPath, 0o600);
  const blobRoot = scratch.dir('opensig-blobs-');
  const blobs = openBlobStore({ root: blobRoot });
  const spoolDir = join(scratch.dir('opensig-spool-'), 'spool');
  const time = testClock();
  const lines = [];
  const logger = createLogger((line) => lines.push(line));
  const notifier = createNotifier({
    transport: createSpoolTransport({ dir: spoolDir }),
    from: 'no-reply@opensig.test',
    publicOrigin: ORIGIN,
    rateLimit: { limit: 10_000, windowMs: 10 * MINUTE },
    logger,
    now: () => time.now.getTime(),
  });
  const ceremony = new RecipientCeremony({ db, blobs, notifier, challengeKey: loadChallengeKey({ path: keyPath }), clock: time.clock, logger, limits: LIMITS });
  const envelopeApi = new EnvelopeApi({ db, blobs, ceremony, clock: time.clock });
  const approvalApi = new ApprovalApi({ db, ceremony, clock: time.clock });

  const t008 = withEnvelopeHandlers(withRecipientHandlers(ROUTES));
  const routes = wiring === 't008' ? t008 : withApprovalHandlers(t008);
  const app = createApp({ routes, config: loadServerConfig({ OPENSIG_PORT: '0' }), logger, authenticator, allowedOrigins: new Set([ORIGIN]) });
  app.locals.set(RECIPIENT_CEREMONY, ceremony);
  app.locals.set(ENVELOPE_API, envelopeApi);
  app.locals.set(APPROVAL_API, approvalApi);
  const server = createAppServer(app);
  await new Promise((resolveListen) => server.listen({ host: '127.0.0.1', port: 0 }, resolveListen));
  const { port } = server.address();
  const seen = new Set();

  const world = {
    db,
    path,
    scratch,
    keyPath,
    blobRoot,
    blobs,
    spoolDir,
    consent,
    time,
    lines,
    ceremony,
    envelopeApi,
    approvalApi,
    authenticator,
    /** The T007 envelope service the EnvelopeApi mutates through (onChange: the ceremony's). */
    envelopes: envelopeApi.envelopes,
    app,
    routes,
    port,
    server,
    tenantId: (tenant) => TENANTS[tenant].id,
    /** A domain operator request for `tenant`. */
    req: (tenant = 'alpha', actor = HUMAN) => ({ tenantId: TENANTS[tenant].id, actor }),
    store: (tenant = 'alpha') => db.forTenant(TENANTS[tenant].id),
    logText: () => lines.join('\n'),
    http: (options) => call(port, options),
    /** Every spool message, oldest first: { name, kind, to, text }. */
    mails() {
      let names;
      try {
        names = readdirSync(spoolDir).filter((name) => name.endsWith('.eml') && !name.startsWith('.')).sort();
      } catch {
        return [];
      }
      return names.map((name) => {
        const text = readFileSync(join(spoolDir, name), 'latin1');
        return { name, kind: /^X-OpenSig-Notification: (\S+)\r$/m.exec(text)?.[1] ?? null, to: /^To: (\S+)\r$/m.exec(text)?.[1] ?? null, text };
      });
    },
    /** Spool messages not taken before, of `kind` to `to`, oldest first; each is taken once. */
    takeMails(kind, to) {
      const fresh = world.mails().filter((mail) => !seen.has(mail.name) && mail.kind === kind && (to === undefined || mail.to === to));
      for (const mail of fresh) seen.add(mail.name);
      return fresh;
    },
    /** True when the table exists in the migrated schema. */
    hasTable(table) {
      const raw = new DatabaseSync(path, { readOnly: true });
      try {
        return raw.prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?").get(table) !== undefined;
      } finally {
        raw.close();
      }
    },
    /** Rows of a table through a read-only connection (as any reader of the file would see them). */
    rows(table, where = '', parameters = []) {
      const raw = new DatabaseSync(path, { readOnly: true });
      try {
        return raw.prepare(`SELECT * FROM ${table} ${where} ORDER BY rowid`).all(...parameters).map((row) => ({ ...row }));
      } finally {
        raw.close();
      }
    },
    /** The content of every approval table that exists, one JSON string per table; `omit` maps a table to columns left out. */
    snapshot(omit = {}) {
      const raw = new DatabaseSync(path, { readOnly: true });
      try {
        const out = {};
        for (const table of APPROVAL_TABLES) {
          if (raw.prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?").get(table) === undefined) continue;
          const rows = raw.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all().map((row) => {
            const copy = {};
            for (const [column, value] of Object.entries(row)) {
              if ((omit[table] ?? []).includes(column)) continue;
              copy[column] = value instanceof Uint8Array ? `bytes:${Buffer.from(value).toString('hex')}` : typeof value === 'bigint' ? String(value) : value;
            }
            return copy;
          });
          out[table] = sha256(JSON.stringify(rows));
        }
        return out;
      } finally {
        raw.close();
      }
    },
    async close() {
      await new Promise((resolveClose) => {
        server.close(resolveClose);
        server.closeAllConnections();
      });
      tenantPolicy.close();
      db.close();
      scratch.cleanup();
    },
  };
  return world;
}

// --- envelopes, invitations and sessions ------------------------------------------------------

export function createInput(recipients = 1, overrides = {}) {
  const list = [{ email: 'signer.one@example.test', role: 'approver', ordinal: 1 }];
  if (recipients === 2) list.push({ email: 'signer.two@example.test', role: 'countersigner', ordinal: 2 });
  return { source: { app: 'manual', record: 'synthetic-record-0001', version: 'v1' }, recipients: list, ...overrides };
}

/** Recipient 1 signs and dates; recipient 2 (if any) signs. */
export function fieldsFor(recipients = 1) {
  const fields = [
    { key: 'sig_1', recipient_ordinal: 1, page: 1, type: 'signature', rect: { x: 0.1, y: 0.8, width: 0.3, height: 0.08 } },
    { key: 'date_1', recipient_ordinal: 1, page: 1, type: 'date', rect: { x: 0.45, y: 0.8, width: 0.2, height: 0.05 } },
  ];
  if (recipients === 2) fields.push({ key: 'sig_2', recipient_ordinal: 2, page: 2, type: 'signature', rect: { x: 0.1, y: 0.9, width: 0.3, height: 0.08 } });
  return fields;
}

/** The invitation token in an invitation mail (the URL fragment). */
export function tokenOf(mail) {
  const match = /\/sign#i=([A-Za-z0-9_-]{43,128})\r?$/m.exec(mail.text);
  assert.ok(match, 'the invitation mail carries a /sign link with the invitation in its fragment');
  return match[1];
}

/** The code in a challenge mail. */
export function codeOf(mail) {
  const match = /^ {4}([0-9A-Z]{10})\r$/m.exec(mail.text);
  assert.ok(match, 'the challenge mail carries a 10-character code');
  return match[1];
}

/** The session value from a createRecipientSession response's Set-Cookie. */
export function cookieOf(response) {
  const header = [response.headers['set-cookie'] ?? []].flat()[0] ?? '';
  const match = new RegExp(`^${COOKIE}=([A-Za-z0-9_-]{43,128});`).exec(header);
  assert.ok(match, 'the response sets the session cookie');
  return match[1];
}

/**
 * A human-created envelope taken to sent through the T007 service, its document stored in
 * the blob store, the send run inside the ceremony so recipient 1's invitation is mailed
 * after the commit. Returns { envelope, token }.
 */
export async function sentEnvelope(world, { tenant = 'alpha', recipients = 1, fields, expiresAt } = {}) {
  const req = world.req(tenant);
  const tenantId = world.tenantId(tenant);
  const pdf = syntheticPdf(sid('doc'));
  const put = world.blobs.put(tenantId, pdf);
  const pages = [
    { number: 1, width: 612, height: 792, rotate: 0 },
    { number: 2, width: 612, height: 792, rotate: 90 },
  ];
  const created = world.envelopes.create(req, createInput(recipients, expiresAt === undefined ? {} : { expires_at: expiresAt })).body;
  const uploaded = world.envelopes.uploadDocument(req, created.id, created.version, {
    digest: put.digest,
    bytes: pdf.length,
    pages,
    parseReport: { pages: 2, network_sandbox: 'netns+fs-enforced (local)' },
  }).body;
  const prepared = world.envelopes.prepare(req, created.id, { expected_version: uploaded.version, fields: fields ?? fieldsFor(recipients) }).body;
  const sent = (await world.ceremony.run(() => world.envelopes.send(req, prepared.id, { expected_version: prepared.version }))).body;
  const invitations = world.takeMails('recipient_invitation', 'signer.one@example.test');
  assert.equal(invitations.length, 1, 'sending mails exactly one invitation to recipient 1');
  return { envelope: sent, token: tokenOf(invitations[0]) };
}

/** Challenge plus session for `token`: { cookie, csrf, state }. */
export async function openSession(world, token, to = 'signer.one@example.test') {
  const challenge = await world.http({ method: 'POST', path: '/v1/recipient-session/challenges', headers: { origin: ORIGIN }, body: { invitation: token } });
  assert.equal(challenge.status, 202, 'requestChallenge answers 202');
  await world.ceremony.drain();
  const codes = world.takeMails('recipient_challenge', to);
  assert.equal(codes.length, 1, 'a live invitation receives one code');
  const response = await world.http({ method: 'POST', path: SESSION_PATH, headers: { origin: ORIGIN }, body: { invitation: token, code: codeOf(codes[0]) } });
  assert.equal(response.status, 201, 'the right code creates a session');
  return { cookie: cookieOf(response), csrf: response.json.csrf_token, state: response.json };
}

/** GET readRecipientSession with the session cookie. */
export function readSession(world, session, headers = {}) {
  return world.http({ method: 'GET', path: SESSION_PATH, headers: { cookie: `${COOKIE}=${session.cookie}`, ...headers } });
}

/** The current RecipientSessionState of a live session. */
export async function stateOf(world, session) {
  const response = await readSession(world, session);
  assert.equal(response.status, 200, 'the session is readable');
  return response.json;
}

/**
 * A valid Approval body from a RecipientSessionState: every input it returned, consent true,
 * and one value per field of the recipient (typed signatures by default, dates without a
 * value). `overrides` replaces top-level members.
 */
export function approvalBody(state, { text = 'Synthetic Signer', drawn = false, overrides = {} } = {}) {
  return {
    expected_version: state.envelope_version,
    document_digest: state.document.digest,
    manifest_digest: state.manifest_digest,
    prior_approval_digest: state.prior_approval_digest,
    consent_version: state.consent.version,
    consent_text_digest: state.consent.text_digest,
    consent: true,
    field_values: state.fields.map((field) => {
      if (field.type === 'date') return { key: field.key, type: 'date' };
      if (drawn) return { key: field.key, type: 'signature', mode: 'drawn', strokes: [[[0, 0], [5000, 2500], [10000, 10000]]] };
      return { key: field.key, type: 'signature', mode: 'typed', text };
    }),
    ...overrides,
  };
}

/** POST approveAsHuman with the session's cookie and CSRF token from the allowlisted origin. */
export function postApproval(world, session, body, headers = {}) {
  return world.http({ method: 'POST', path: APPROVAL_PATH, headers: { origin: ORIGIN, cookie: `${COOKIE}=${session.cookie}`, 'x-csrf-token': session.csrf, ...headers }, body });
}

/** POST declineAsRecipient with the session's cookie and CSRF token from the allowlisted origin. */
export function postDecline(world, session, body, headers = {}) {
  return world.http({ method: 'POST', path: DECLINE_PATH, headers: { origin: ORIGIN, cookie: `${COOKIE}=${session.cookie}`, 'x-csrf-token': session.csrf, ...headers }, body });
}

/** Recipient 1 of a sent envelope opens a session and approves; returns { envelope, session, receipt, response }. */
export async function approvedByFirst(world, { tenant = 'alpha', recipients = 2, envelope: given } = {}) {
  const { envelope, token } = given ?? (await sentEnvelope(world, { tenant, recipients }));
  const session = await openSession(world, token);
  const response = await postApproval(world, session, approvalBody(session.state));
  assert.equal(response.status, 200, `recipient 1 approves: ${response.status} ${response.json?.code ?? ''}`);
  return { envelope, session, receipt: response.json, response };
}

/** Recipient 2's invitation token, mailed after recipient 1's approval committed. */
export function secondToken(world) {
  const mails = world.takeMails('recipient_invitation', 'signer.two@example.test');
  assert.equal(mails.length, 1, "recipient 2's invitation is mailed once recipient 1 has approved");
  return tokenOf(mails[0]);
}

/**
 * A session for `recipientId` written at storage level through the T008 repository
 * (insertSession), as a mis-issued capability would be: SC002-01 needs a live session for a
 * recipient whose turn has not come, which the ceremony never issues. It is bound to the
 * envelope's frozen revision and manifest, so the T008 guard accepts it; the subject under
 * test, the approval's own order check, is real code. Returns { cookie, csrf }.
 */
export function forgeSession(world, tenant, envelopeId, recipientId) {
  const envelope = world.store(tenant).get('envelopes', { id: envelopeId });
  assert.ok(envelope, 'the envelope exists');
  const value = newSessionValue();
  const secret = newCsrfSecret();
  const id = sid('sess');
  world.db.transaction(() =>
    insertSession(world.store(tenant), {
      id,
      valueHash: capabilityHash(value),
      envelopeId,
      recipientId,
      revisionId: String(envelope.base_revision_id),
      manifestDigest: String(envelope.manifest_digest),
      csrfSecret: secret,
      now: world.time.now.toISOString(),
    }),
  );
  return { cookie: value, csrf: csrfToken(secret, id) };
}

/** The envelope row as a reader of the file sees it. */
export function envelopeRow(world, envelopeId) {
  const [row] = world.rows('envelopes', 'WHERE id = ?', [envelopeId]);
  assert.ok(row, 'the envelope exists');
  return row;
}

/** Audit events of an envelope, oldest first. */
export function auditOf(world, envelopeId) {
  return world.rows('audit_events', 'WHERE envelope_id = ?', [envelopeId]);
}

/** True when no capability value in `values` appears in the captured log lines. */
export function logsFreeOf(world, values) {
  const text = world.logText();
  return values.every((value) => typeof value === 'string' && value.length > 0 && !text.includes(value));
}

/** Audit events of `type` (all envelopes), oldest first. */
export function auditEvents(world, type) {
  return world.rows('audit_events', 'WHERE type = ?', [type]);
}

/** The audit metadata of an event row as JSON. */
export function metadataOf(event) {
  return JSON.parse(String(event.metadata_json));
}

/** Outbox events of `type` for one envelope, oldest first, with the parsed WebhookEvent payload. */
export function outboxOf(world, envelopeId, type) {
  return world.rows('outbox_events', 'WHERE envelope_id = ? AND type = ?', [envelopeId, type]).map((row) => ({ ...row, payload: JSON.parse(String(row.payload_json)) }));
}
