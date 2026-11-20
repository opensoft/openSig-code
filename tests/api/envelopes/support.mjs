// SPDX-License-Identifier: Apache-2.0
//
// Test support for the operator envelope handlers (T034). Everything is synthetic and local,
// generated at run time and removed afterwards:
// - two tenants, alpha and beta, from the T004 synthetic identities fixture, each with its
//   own runtime ES256 key pair (private keys in memory only) and a tenants row that agrees
//   with the operator auth configuration, as the server's startup check requires (SEC-07);
// - a migrated SQLite database, a blob store, a mail spool and the 0600 challenge-HMAC key
//   file, each in its own mkdtemp directory;
// - documents from the T004 synthetic fixture set (fixtures/synthetic/documents), parsed by
//   the real isolated parse service (T033);
// - recipient identities on example.test only.
// The application is the real one (src/server/app.ts) built by createAppServer, with the
// production route registry and the T008 and T034 handler maps installed
// (withRecipientHandlers, withEnvelopeHandlers), the real T005 authenticator with T031's
// storage-backed tenant role policy (src/server/tenants.ts), the T008 ceremony and the
// T034 EnvelopeApi in its locals, and mail through the T032 notifier to the spool only. It is
// bound to 127.0.0.1 on an OS-chosen port. Nothing here replaces a production module.
// Capability values (invitation tokens, codes, session values, CSRF tokens) are read back
// from the spool or responses, kept in memory, and never put in a test name or an assertion
// message.

import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { chmodSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { connect } from 'node:net';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { ARTIFACT_API, ArtifactApi } from '../../../src/api/artifacts/index.ts';
import { createOperatorAuthenticator, loadOperatorAuthConfig } from '../../../src/api/auth/index.ts';
import { ENVELOPE_API, EnvelopeApi, uploadsInFlight } from '../../../src/api/envelopes/index.ts';
import { FINALIZATION_RETRY, FinalizationRetryApi } from '../../../src/api/envelopes/retry.ts';
import { RECIPIENT_CEREMONY, RecipientCeremony, loadChallengeKey } from '../../../src/api/recipients/index.ts';
import { ROUTES, withEnvelopeHandlers, withRecipientHandlers } from '../../../src/api/routes.ts';
import { createNotifier, createSpoolTransport } from '../../../src/notifications/index.ts';
import { DEFAULT_SERVICE_LIMITS } from '../../../src/pdf/limits.ts';
import { bodyReadCapacity, parseAdmissions, parseCapacity } from '../../../src/pdf/service.ts';
import { createApp, createAppServer } from '../../../src/server/app.ts';
import { loadServerConfig } from '../../../src/server/config.ts';
import { createLogger } from '../../../src/server/redact.ts';
import { openTenantPolicy } from '../../../src/server/tenants.ts';
import { AuditWriter } from '../../../src/storage/audit/index.ts';
import { openBlobStore } from '../../../src/storage/blobs/index.ts';
import { loadVendoredContract } from '../../contract/envelopes/lib/contract.mjs';
import { validate } from '../../contract/envelopes/lib/schema.mjs';
import { codeOf, cookieOf, tokenOf } from '../../recipients/support.mjs';
import { BASE_TIME, makeScratch, openTemp, sid, ts } from '../../storage/support/fixtures.mjs';

export { BASE_TIME, codeOf, cookieOf, sid, tokenOf, ts };

export const REPO = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
const identities = JSON.parse(readFileSync(join(REPO, 'fixtures', 'synthetic', 'identities', 'identities.json'), 'utf8'));

export const ORIGIN = 'https://sign.alpha.test';
export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;
export const COOKIE = '__Host-opensig_rs';
export const CONSENT_WORDING = 'I have reviewed this synthetic document and I approve it as shown.';

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** The two synthetic tenants, by short name. */
export const TENANTS = Object.freeze({ alpha: identities.tenants[0], beta: identities.tenants[1] });

const KEYS = { alpha: generateKeyPairSync('ec', { namedCurve: 'P-256' }), beta: generateKeyPairSync('ec', { namedCurve: 'P-256' }) };
const ROLE_MAP = Object.freeze({ 'opensig-sender': 'sender', 'opensig-tenant-admin': 'tenant_admin', 'opensig-service': 'service' });
const KIND_MAP = Object.freeze({ human: 'human-operator', service: 'service' });
const ROLE_VALUE = Object.freeze({ sender: 'opensig-sender', admin: 'opensig-tenant-admin', service: 'opensig-service' });

/** Every operator scope the contract defines (operatorOAuth). */
export const ALL_SCOPES = Object.freeze([
  'envelopes:read',
  'envelopes:write',
  'envelopes:send',
  'envelopes:confirm-send',
  'envelopes:void',
  'finalization:retry',
  'artifacts:read',
  'webhooks:admin',
]);

/** The scopes each synthetic operator holds by default (contract operatorOAuth flows). */
export const ROLE_SCOPES = Object.freeze({
  sender: Object.freeze(['envelopes:read', 'envelopes:write', 'envelopes:send', 'envelopes:confirm-send', 'envelopes:void', 'artifacts:read']),
  admin: Object.freeze([...ALL_SCOPES]),
  service: Object.freeze(['envelopes:read', 'envelopes:write', 'envelopes:send', 'artifacts:read']),
});

/** The operator auth configuration (T005) for both tenants. */
export function authInput() {
  return {
    tenants: Object.entries(TENANTS).map(([name, tenant]) => ({
      tenantId: tenant.id,
      issuer: tenant.oidc.issuer,
      audience: tenant.oidc.audience,
      algorithms: ['ES256'],
      jwks: { keys: [{ ...KEYS[name].publicKey.export({ format: 'jwk' }), kid: `${name}-envelope-api-1` }] },
      claims: { tenant: tenant.oidc.claims.tenant, roles: tenant.oidc.claims.roles, principalKind: tenant.oidc.claims.principal_kind },
      roleMap: { ...ROLE_MAP },
      kindMap: { ...KIND_MAP },
    })),
  };
}

/** The tenants row that agrees with authInput() (SEC-07 agreement). */
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
 * A bearer token for the synthetic operator `who` (sender, admin or service) of tenant
 * `tenant` (alpha or beta), valid for ten minutes of real time. `roles` replaces the role
 * claim values (operator roles such as 'sender'), `scopes` the scope list.
 */
export function bearer(tenant = 'alpha', who = 'sender', { roles, scopes, overrides = {} } = {}) {
  const identity = TENANTS[tenant];
  assert.ok(identity, `known tenant ${tenant}`);
  const op = identity.operators.find((o) => (who === 'service' ? o.kind === 'service' : who === 'admin' ? o.roles.includes('tenant_admin') : o.roles.includes('sender')));
  const claims = identity.oidc.claims;
  const roleValues = (roles ?? [who === 'admin' ? 'tenant_admin' : who]).map((role) => ROLE_VALUE[role === 'tenant_admin' ? 'admin' : role]);
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: identity.oidc.issuer,
    aud: identity.oidc.audience,
    sub: op.subject,
    exp: now + 600,
    [claims.tenant]: identity.id,
    [claims.roles]: roleValues,
    [claims.principal_kind]: who === 'service' ? 'service' : 'human',
    scope: (scopes ?? ROLE_SCOPES[who]).join(' '),
    ...overrides,
  };
  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${b64({ alg: 'ES256', kid: `${tenant}-envelope-api-1`, typ: 'JWT' })}.${b64(payload)}`;
  const signature = sign('sha256', Buffer.from(input), { key: KEYS[tenant].privateKey, dsaEncoding: 'ieee-p1363' });
  return `${input}.${signature.toString('base64url')}`;
}

/** A fresh contract-valid Idempotency-Key. */
export function newKey() {
  return `ik-${randomBytes(18).toString('base64url')}`;
}

/** A well-formed identifier that names nothing. */
export function absentId() {
  return `absent-${randomBytes(12).toString('base64url')}`;
}

// --- documents (T004 synthetic fixtures) ------------------------------------------------------

const DOCUMENTS = join(REPO, 'fixtures', 'synthetic', 'documents');

/** Bytes of a committed T004 synthetic document. */
export function documentBytes(file) {
  return readFileSync(join(DOCUMENTS, file));
}

export const SINGLE_PAGE = 'single-page.pdf';
export const MULTI_PAGE = 'agreement-multipage.pdf';

export function createInput(recipients = 1, overrides = {}) {
  const list = [{ email: 'signer.one@example.test', role: 'approver', ordinal: 1 }];
  if (recipients === 2) list.push({ email: 'signer.two@example.test', role: 'countersigner', ordinal: 2 });
  return { source: { app: 'manual', record: 'synthetic-record-0001', version: 'v1' }, recipients: list, ...overrides };
}

export function fieldsFor(recipients = 1) {
  const fields = [
    { key: 'sig_1', recipient_ordinal: 1, page: 1, type: 'signature', rect: { x: 0.1, y: 0.8, width: 0.3, height: 0.08 } },
    { key: 'date_1', recipient_ordinal: 1, page: 1, type: 'date', rect: { x: 0.45, y: 0.8, width: 0.2, height: 0.05 } },
  ];
  if (recipients === 2) fields.push({ key: 'sig_2', recipient_ordinal: 2, page: 2, type: 'signature', rect: { x: 0.1, y: 0.9, width: 0.3, height: 0.08 } });
  return fields;
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

// --- HTTP -----------------------------------------------------------------------------------

/**
 * One HTTP request; resolves with { status, headers, rawHeaders, bytes, text, json } once the
 * whole response is in. A body without a Content-Type is sent as application/json unless
 * `defaultType` is false (the T006 harness sends its requests exactly as it built them).
 */
export function call(port, { method = 'GET', path, headers = {}, body, defaultType = true } = {}) {
  return new Promise((resolveResponse, reject) => {
    const payload = body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
    const allHeaders = { ...headers };
    if (payload !== undefined) {
      if (defaultType && !Object.keys(allHeaders).some((name) => name.toLowerCase() === 'content-type')) allHeaders['content-type'] = 'application/json';
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

/** Every raw response header, name as sent and value, in order, except date and x-correlation-id. */
export function comparableHeaders(response) {
  const pairs = [];
  for (let index = 0; index < response.rawHeaders.length; index += 2) {
    const name = response.rawHeaders[index];
    if (name.toLowerCase() === 'date' || name.toLowerCase() === 'x-correlation-id') continue;
    pairs.push([name, response.rawHeaders[index + 1]]);
  }
  return pairs;
}

/** An Error body without its correlation_id, for comparing two refusals. */
export function errorShape(response) {
  const { correlation_id: _ignored, ...rest } = response.json ?? {};
  return rest;
}

// --- barriers and the hang guard (no fixed sleep orders a test) --------------------------------

/** The one bound on every wait: three times the parse child's own wall-time limit. */
export const HANG_GUARD_MS = 3 * DEFAULT_SERVICE_LIMITS.wallMs;
const POLL_MS = 5;

/** The parse service's and the upload cap's state, for barriers and failure messages. */
export function serviceState() {
  const parse = parseCapacity();
  return { running: parse.running, waiting: parse.waiting, held: bodyReadCapacity().held, next_ticket: parseAdmissions().next_ticket, uploads: uploadsInFlight() };
}

export const showState = (s = serviceState()) => `running=${s.running} waiting=${s.waiting} held=${s.held} next_ticket=${s.next_ticket} uploads=${s.uploads}`;

export function isIdle() {
  const s = serviceState();
  return s.running === 0 && s.waiting === 0 && s.held === 0 && s.uploads === 0;
}

function hangGuard(what, started) {
  const label = typeof what === 'function' ? what() : what;
  assert.fail(`T034 hang guard fired after ${Math.round(performance.now() - started)} ms (bound ${HANG_GUARD_MS} ms): ${label}. Service state: ${showState()}. Report it verbatim; do not rerun to settle it.`);
}

/** Barrier: poll `check` (a bounded sleep between polls) until it holds, under the hang guard. */
export async function until(check, what) {
  const started = performance.now();
  while (!check()) {
    if (performance.now() - started > HANG_GUARD_MS) hangGuard(what, started);
    await sleep(POLL_MS);
  }
  return performance.now() - started;
}

/** Await `promise` under the hang guard; the guard's timer never outlives the wait. */
export async function settle(promise, what) {
  const started = performance.now();
  let timer;
  const guard = new Promise((_, rejectGuard) => {
    timer = setTimeout(() => {
      try {
        hangGuard(what, started);
      } catch (error) {
        rejectGuard(error);
      }
    }, HANG_GUARD_MS);
  });
  try {
    return await Promise.race([promise, guard]);
  } finally {
    clearTimeout(timer);
  }
}

/** Status and JSON body of a complete HTTP/1.1 response read from a raw socket (Content-Length framing). */
export function parseRawResponse(raw) {
  const text = raw.toString('latin1');
  const end = text.indexOf('\r\n\r\n');
  if (end < 0) throw new Error('no complete response head');
  const status = Number(/^HTTP\/1\.1 (\d{3}) /.exec(text.slice(0, end))?.[1]);
  const body = Buffer.from(text.slice(end + 4), 'latin1').toString('utf8');
  let json = null;
  try {
    json = body ? JSON.parse(body) : null;
  } catch {
    json = null;
  }
  return { status, json };
}

// --- table snapshots (A-010 T034R-DIFF) ---------------------------------------------------------

/**
 * Columns that hold a hash or a digest: the capability hashes (invitation token, challenge
 * code, session, CSRF), request and response-body digests, and the audit chain's hashes.
 */
const HASH_COLUMN = /(?:^|_)(?:hash|digest)$/i;
/** A run of 32 or more hex digits inside any other value (a digest in an audit event's details). */
const HEX_RUN = /[0-9a-f]{32,}/gi;
/** Each snapshot's full content, kept out of the snapshot object, so no diff or print can show it. */
const FULL_CONTENT = new WeakMap();

/** A value as a snapshot shows it: hash columns, bytes and hex runs are masked. */
function maskedValue(column, value) {
  if (value === null) return null;
  if (HASH_COLUMN.test(column)) return '<hash>';
  if (value instanceof Uint8Array) return `<bytes ${value.length}>`;
  if (typeof value === 'bigint') return String(value);
  if (typeof value === 'string') return value.replace(HEX_RUN, '<hex>');
  return value;
}

/** A value as the full content keeps it, for comparison only. */
function fullValue(value) {
  if (value instanceof Uint8Array) return `bytes:${Buffer.from(value).toString('hex')}`;
  return typeof value === 'bigint' ? String(value) : value;
}

/** What changed in one table, by row count and column name only: never a value. */
function describeTableChange(table, before, after) {
  const parts = [];
  if (before.length !== after.length) parts.push(`${before.length} -> ${after.length} rows`);
  const columns = new Set();
  for (let i = 0; i < Math.min(before.length, after.length); i += 1) {
    for (const column of new Set([...Object.keys(before[i]), ...Object.keys(after[i])])) {
      if (JSON.stringify(before[i][column]) !== JSON.stringify(after[i][column])) columns.add(column);
    }
  }
  if (columns.size > 0) parts.push(`changed columns: ${[...columns].sort().join(', ')}`);
  return `${table} (${parts.join('; ') || 'changed'})`;
}

/**
 * Assert that no row changed between two world snapshots. The full content is compared,
 * hash columns included, so a change in any column fails; the failure names the tables, row
 * counts and changed columns only, so it never prints a hash, a digest or any other value.
 */
export function assertSameRows(after, before, label) {
  const later = FULL_CONTENT.get(after);
  const earlier = FULL_CONTENT.get(before);
  assert.ok(later !== undefined && earlier !== undefined, `${label}: two world snapshots are compared`);
  const changes = [];
  for (const table of new Set([...Object.keys(earlier), ...Object.keys(later)])) {
    if (earlier[table] === later[table]) continue;
    if (earlier[table] === undefined || later[table] === undefined) changes.push(`${table} (in one snapshot only)`);
    else changes.push(describeTableChange(table, JSON.parse(earlier[table]), JSON.parse(later[table])));
  }
  if (changes.length > 0) assert.fail(`${label}: ${changes.join('; ')}`);
}

// --- the world --------------------------------------------------------------------------------

/** Tables an operator envelope request could change. */
export const ENVELOPE_TABLES = Object.freeze([
  'envelopes',
  'recipients',
  'document_revisions',
  'field_definitions',
  'field_manifests',
  'send_confirmations',
  'invitations',
  'challenges',
  'recipient_sessions',
  'approvals',
  'idempotency_records',
  'signing_jobs',
  'audit_events',
  'outbox_events',
]);

/** A controllable clock: { clock, advance(ms), now }. */
export function testClock(start = BASE_TIME) {
  const state = { now: start };
  return {
    clock: () => new Date(state.now),
    advance(ms) {
      state.now += ms;
    },
    get now() {
      return new Date(state.now);
    },
  };
}

/** The T031 body timer options an EA-01 world may widen (request #16, doubt 4). */
const BODY_TIMER_OPTIONS = Object.freeze(['bodyIdleMs', 'bodyRateGraceMs']);

/**
 * The synthetic world. `bodyTiming` widens the server's per-request body timer, through T031's
 * existing config.limits options only (EA-01 only; see tests/api/envelopes/uploads.test.mjs);
 * every other test uses the server's defaults, and production defaults are never changed.
 */
export async function createWorld({ bodyTiming } = {}) {
  const base = loadServerConfig({ OPENSIG_PORT: '0' });
  for (const name of Object.keys(bodyTiming ?? {})) {
    if (!BODY_TIMER_OPTIONS.includes(name) || !Object.hasOwn(base.limits, name)) throw new TypeError(`bodyTiming: ${name} is not one of T031's existing body timer options`);
  }
  const scratch = makeScratch();
  const { db, path } = openTemp(scratch);
  const input = authInput();
  const consent = {};
  db.transaction(() => {
    for (const entry of input.tenants) db.forTenant(entry.tenantId).insert('tenants', tenantRow(entry));
  });
  for (const [name, tenant] of Object.entries(TENANTS)) {
    const record = { id: sid('consent'), version: '2026.11-synthetic', text: CONSENT_WORDING };
    db.transaction(() => {
      const store = db.forTenant(tenant.id);
      store.insert('consent_texts', {
        id: record.id,
        version: record.version,
        locale: 'en',
        text: record.text,
        text_digest: sha256(Buffer.from(record.text, 'utf8')),
        effective_from: ts(0),
        created_at: ts(0),
      });
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
  const blobs = openBlobStore({ root: scratch.dir('opensig-blobs-') });
  const spoolDir = join(scratch.dir('opensig-spool-'), 'spool');
  const time = testClock();
  const lines = [];
  const logger = createLogger((line) => lines.push(line));
  const notifier = createNotifier({
    transport: createSpoolTransport({ dir: spoolDir }),
    from: 'no-reply@opensig.test',
    publicOrigin: ORIGIN,
    rateLimit: { limit: 1000, windowMs: 10 * MINUTE },
    logger,
    now: () => time.now.getTime(),
  });
  const ceremony = new RecipientCeremony({ db, blobs, notifier, challengeKey: loadChallengeKey({ path: keyPath }), clock: time.clock, logger });
  const api = new EnvelopeApi({ db, blobs, ceremony, clock: time.clock });

  const routes = withEnvelopeHandlers(withRecipientHandlers(ROUTES));
  const config = bodyTiming ? Object.freeze({ ...base, limits: Object.freeze({ ...base.limits, ...bodyTiming }) }) : base;
  const app = createApp({ routes, config, logger, authenticator, allowedOrigins: new Set([ORIGIN]) });
  app.locals.set(RECIPIENT_CEREMONY, ceremony);
  app.locals.set(ENVELOPE_API, api);
  // A-010 row ARTIFACT-ROUTES (request #46): the artifact API, so SC002-26 meets T016's and T038's installed handlers.
  app.locals.set(ARTIFACT_API, new ArtifactApi({ db, blobs, clock: time.clock }));
  app.locals.set(FINALIZATION_RETRY, new FinalizationRetryApi({ db, audit: new AuditWriter(db, { clock: time.clock }), clock: time.clock }));
  const server = createAppServer(app);
  await new Promise((resolveListen) => server.listen({ host: '127.0.0.1', port: 0 }, resolveListen));
  const { port } = server.address();
  const seen = new Set();

  const world = {
    db,
    path,
    consent,
    routes,
    blobs,
    spoolDir,
    time,
    lines,
    ceremony,
    api,
    port,
    server,
    tenantId: (tenant) => TENANTS[tenant].id,
    logText: () => lines.join('\n'),
    /** Log records (parsed JSON lines) whose event is `event`. */
    logged: (event) => lines.map((line) => JSON.parse(line)).filter((record) => record.event === event),
    http: (options) => call(port, options),

    /**
     * An operator request. `who` is sender, admin or service, or null for no credential.
     * Mutations (POST and PUT) get a fresh Idempotency-Key unless `key` is given (null
     * leaves it out). A Buffer body is sent as application/pdf unless headers say otherwise.
     */
    op({ tenant = 'alpha', who = 'sender', method = 'GET', path: target, body, headers = {}, key, ifMatch, roles, scopes, overrides } = {}) {
      const all = {};
      if (who !== null) all.authorization = `Bearer ${bearer(tenant, who, { roles, scopes, overrides })}`;
      if ((method === 'POST' || method === 'PUT') && key !== null) all['idempotency-key'] = key ?? newKey();
      if (ifMatch !== undefined) all['if-match'] = typeof ifMatch === 'number' ? `"${ifMatch}"` : ifMatch;
      if (Buffer.isBuffer(body)) all['content-type'] = 'application/pdf';
      return call(port, { method, path: target, body, headers: { ...all, ...headers } });
    },

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
    /** Rows of a table through a read-only connection (as any reader of the file would see them). */
    rows(table, where = '', parameters = []) {
      const raw = new DatabaseSync(path, { readOnly: true });
      try {
        return raw.prepare(`SELECT * FROM ${table} ${where} ORDER BY rowid`).all(...parameters).map((row) => ({ ...row }));
      } finally {
        raw.close();
      }
    },
    /**
     * The content of `tables` (default: every envelope table); with `tenant` (alpha or beta),
     * only that tenant's rows. The snapshot object shows each table's rows masked (hash
     * columns, bytes and hex runs; T034R-DIFF); its full content is kept apart and compared
     * only by assertSameRows(), whose failure never prints a value.
     */
    snapshot(tenant = null, tables = ENVELOPE_TABLES) {
      const raw = new DatabaseSync(path, { readOnly: true });
      try {
        const masked = {};
        const full = {};
        for (const table of tables) {
          const statement = tenant === null ? raw.prepare(`SELECT * FROM ${table} ORDER BY rowid`) : raw.prepare(`SELECT * FROM ${table} WHERE tenant_id = ? ORDER BY rowid`);
          const rows = tenant === null ? statement.all() : statement.all(TENANTS[tenant].id);
          masked[table] = rows.map((row) => Object.fromEntries(Object.entries(row).map(([column, value]) => [column, maskedValue(column, value)])));
          full[table] = JSON.stringify(rows.map((row) => Object.fromEntries(Object.entries(row).map(([column, value]) => [column, fullValue(value)]))));
        }
        const snapshot = Object.freeze(masked);
        FULL_CONTENT.set(snapshot, Object.freeze(full));
        return snapshot;
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

// --- envelope drivers (each through the real HTTP API) ----------------------------------------

function expectStatus(response, status, what) {
  assert.equal(response.status, status, `${what}: status ${response.status}${response.json?.code ? ` ${response.json.code}` : ''}`);
  return response.json;
}

export async function createEnvelope(world, { tenant = 'alpha', who = 'sender', recipients = 1, input, key } = {}) {
  const response = await world.op({ tenant, who, method: 'POST', path: '/v1/envelopes', body: input ?? createInput(recipients), key });
  return expectStatus(response, 201, 'createEnvelope');
}

export function uploadRequest(world, { tenant = 'alpha', who = 'sender', envelope, pdf = documentBytes(SINGLE_PAGE), key, ifMatch } = {}) {
  return world.op({ tenant, who, method: 'PUT', path: `/v1/envelopes/${envelope.id}/document`, body: pdf, key, ifMatch: ifMatch ?? envelope.version });
}

export async function uploadDocument(world, options) {
  return expectStatus(await uploadRequest(world, options), 200, 'uploadDocument');
}

export async function prepareEnvelope(world, { tenant = 'alpha', who = 'sender', envelope, fields, key } = {}) {
  const recipients = envelope.recipients.length;
  const response = await world.op({ tenant, who, method: 'POST', path: `/v1/envelopes/${envelope.id}/prepare`, body: { expected_version: envelope.version, fields: fields ?? fieldsFor(recipients) }, key });
  return expectStatus(response, 200, 'prepareEnvelope');
}

/** create, upload (a multi-page document for two recipients) and prepare, all as `who`. */
export async function preparedEnvelope(world, { tenant = 'alpha', who = 'sender', recipients = 1 } = {}) {
  const created = await createEnvelope(world, { tenant, who, recipients });
  const uploaded = await uploadDocument(world, { tenant, who, envelope: created, pdf: documentBytes(recipients === 2 ? MULTI_PAGE : SINGLE_PAGE) });
  return prepareEnvelope(world, { tenant, who, envelope: uploaded });
}

export async function readPreview(world, { tenant = 'alpha', who = 'sender', envelope }) {
  return expectStatus(await world.op({ tenant, who, path: `/v1/envelopes/${envelope.id}/preview` }), 200, 'readRecipientPreview');
}

/** confirmSend of the current preview by `who` (a human operator); returns the response. */
export async function confirmRequest(world, { tenant = 'alpha', who = 'sender', envelope, key } = {}) {
  const preview = await readPreview(world, { tenant, who: 'sender', envelope });
  return world.op({
    tenant,
    who,
    method: 'POST',
    path: `/v1/envelopes/${envelope.id}/send-confirmations`,
    body: { expected_version: preview.version, document_digest: preview.document.digest, manifest_digest: preview.manifest_digest, recipients_digest: preview.recipients_digest },
    key,
  });
}

export function sendRequest(world, { tenant = 'alpha', who = 'sender', envelope, reference, key, version } = {}) {
  const body = { expected_version: version ?? envelope.version };
  if (reference !== undefined) body.authorization_reference = reference;
  return world.op({ tenant, who, method: 'POST', path: `/v1/envelopes/${envelope.id}/send`, body, key });
}

/** A human-created envelope prepared and sent by the sender; returns { envelope, token } (recipient 1's invitation, from the spool). */
export async function sentEnvelope(world, { tenant = 'alpha', recipients = 1 } = {}) {
  const prepared = await preparedEnvelope(world, { tenant, recipients });
  const envelope = expectStatus(await sendRequest(world, { tenant, envelope: prepared }), 200, 'sendEnvelope');
  const invitations = world.takeMails('recipient_invitation', 'signer.one@example.test');
  assert.equal(invitations.length, 1, 'sending mails exactly one invitation to recipient 1');
  return { envelope, token: tokenOf(invitations[0]) };
}

/** The one invitation mailed to `to` since the last take; returns its token (in memory only). */
export function takeInvitation(world, to = 'signer.one@example.test') {
  const mails = world.takeMails('recipient_invitation', to);
  assert.equal(mails.length, 1, 'exactly one invitation was mailed');
  return tokenOf(mails[0]);
}

export function resendRequest(world, { tenant = 'alpha', who = 'sender', overrides, envelope, recipient, key, version } = {}) {
  return world.op({
    tenant,
    who,
    overrides,
    method: 'POST',
    path: `/v1/envelopes/${envelope.id}/recipients/${recipient.id}/resend-invitation`,
    body: { expected_version: version ?? envelope.version },
    key,
  });
}

export function voidRequest(world, { tenant = 'alpha', who = 'sender', envelope, key, reason = 'sender-cancelled', version } = {}) {
  return world.op({ tenant, who, method: 'POST', path: `/v1/envelopes/${envelope.id}/void`, body: { expected_version: version ?? envelope.version, reason_code: reason }, key });
}

export async function readEnvelope(world, { tenant = 'alpha', who = 'sender', envelope }) {
  return expectStatus(await world.op({ tenant, who, path: `/v1/envelopes/${envelope.id}` }), 200, 'readEnvelope');
}

// --- recipient ceremony (anonymous and recipient-scheme routes) --------------------------------

/** requestChallenge from the allowlisted origin, then settle the work it starts after its 202. */
export async function requestChallenge(world, invitation) {
  const response = await world.http({ method: 'POST', path: '/v1/recipient-session/challenges', headers: { origin: ORIGIN }, body: { invitation } });
  await world.ceremony.drain();
  return response;
}

/** A challenge plus a session for `invitation`: { code, session, csrf } (raw values, in memory only). */
export async function openSession(world, invitation, to = 'signer.one@example.test') {
  assert.equal((await requestChallenge(world, invitation)).status, 202, 'requestChallenge answers 202');
  const mails = world.takeMails('recipient_challenge', to);
  assert.equal(mails.length, 1, 'a live invitation receives one code');
  const code = codeOf(mails[0]);
  const response = await world.http({ method: 'POST', path: '/v1/recipient-session', headers: { origin: ORIGIN }, body: { invitation, code } });
  assert.equal(response.status, 201, 'the right code creates a session');
  return { code, session: cookieOf(response), csrf: response.json.csrf_token };
}

// --- controlled upload streams (EA-01) ---------------------------------------------------------

/** The request head of an upload of `length` bytes to `envelope`, as `who` of `tenant`. */
export function uploadHead({ tenant = 'alpha', who = 'sender', envelope, length, key = newKey(), ifMatch }) {
  return [
    `PUT /v1/envelopes/${envelope.id}/document HTTP/1.1`,
    'Host: 127.0.0.1',
    `Authorization: Bearer ${bearer(tenant, who)}`,
    `Idempotency-Key: ${key}`,
    `If-Match: "${ifMatch ?? envelope.version}"`,
    'Content-Type: application/pdf',
    `Content-Length: ${length}`,
    '',
    '',
  ].join('\r\n');
}

/**
 * A controlled upload on a raw socket: it declares the whole document and sends only its
 * first `sendBytes` bytes, then nothing more until the test destroys it. With 1 byte it
 * stands for a minimum-rate sender; with all but the last byte, for a front-loaded upload
 * that then trickles. `sockets` collects it for the test's unconditional cleanup.
 */
export function heldUpload(world, sockets, { tenant = 'alpha', envelope, pdf, sendBytes }) {
  const socket = connect({ host: '127.0.0.1', port: world.port });
  sockets.add(socket);
  socket.on('error', () => {});
  socket.on('close', () => sockets.delete(socket));
  socket.write(uploadHead({ tenant, envelope, length: pdf.length }));
  if (sendBytes > 0) socket.write(pdf.subarray(0, sendBytes));
  return socket;
}

/**
 * An upload that sends its headers only: it declares the document's length and never sends a
 * body byte, so a response can only come from a refusal that does not read the body.
 * Returns { response, bodyBytesSent() }; response resolves with { status, json }.
 */
export function headersOnlyUpload(world, sockets, { tenant = 'alpha', envelope, pdf }) {
  const socket = connect({ host: '127.0.0.1', port: world.port });
  sockets.add(socket);
  socket.on('error', () => {});
  const head = uploadHead({ tenant, envelope, length: pdf.length });
  socket.write(head);
  const response = new Promise((resolveResponse, rejectResponse) => {
    const chunks = [];
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('end', () => {
      try {
        resolveResponse(parseRawResponse(Buffer.concat(chunks)));
      } catch (error) {
        rejectResponse(error);
      }
    });
    socket.on('close', () => {
      sockets.delete(socket);
      rejectResponse(new Error('the connection closed before a complete response'));
    });
  });
  response.catch(() => {});
  return { response, bodyBytesSent: () => socket.bytesWritten - Buffer.byteLength(head) };
}

/** The server's `request` log records of `operation` on `path`. */
/**
 * A JSON request on a raw socket (request #25): it declares its whole body and sends only the
 * first `sendBytes` bytes, then nothing more until the test destroys it, which is a client
 * abort. `sockets` collects it for the test's cleanup.
 */
export function heldJsonRequest(world, sockets, { tenant = 'alpha', who = 'sender', method = 'POST', path, key, body, sendBytes }) {
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  assert.ok(sendBytes < payload.length, 'a held request leaves part of its body unsent');
  const socket = connect({ host: '127.0.0.1', port: world.port });
  sockets.add(socket);
  socket.on('error', () => {});
  socket.on('close', () => sockets.delete(socket));
  socket.write(
    [
      `${method} ${path} HTTP/1.1`,
      'Host: 127.0.0.1',
      `Authorization: Bearer ${bearer(tenant, who)}`,
      `Idempotency-Key: ${key}`,
      'Content-Type: application/json',
      `Content-Length: ${payload.length}`,
      '',
      '',
    ].join('\r\n'),
  );
  if (sendBytes > 0) socket.write(payload.subarray(0, sendBytes));
  return socket;
}

/**
 * An upload whose body is streamed with chunked transfer encoding and no Content-Length, so the
 * router cannot refuse it by its declared length and only reading it can find it too large
 * (request #25). Resolves with { status, headers, json } once the response has ended; a write
 * error after the response (the server closing an over-limit request) is ignored.
 */
export function streamedUpload(world, { tenant = 'alpha', who = 'sender', envelope, bytes, key = newKey(), ifMatch, chunkBytes = 64 * 1024 }) {
  return new Promise((resolveResponse, rejectResponse) => {
    let answered = false;
    const req = request(
      {
        host: '127.0.0.1',
        port: world.port,
        method: 'PUT',
        path: `/v1/envelopes/${envelope.id}/document`,
        agent: false,
        headers: { authorization: `Bearer ${bearer(tenant, who)}`, 'idempotency-key': key, 'if-match': `"${ifMatch ?? envelope.version}"`, 'content-type': 'application/pdf' },
      },
      (res) => {
        answered = true;
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('error', () => {});
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch {
            json = null;
          }
          resolveResponse({ status: res.statusCode, headers: res.headers, json });
        });
      },
    );
    req.on('error', (error) => {
      if (!answered) rejectResponse(error);
    });
    for (let at = 0; at < bytes.length; at += chunkBytes) req.write(bytes.subarray(at, at + chunkBytes));
    req.end();
  });
}

export function requestLog(world, operation, path) {
  return world.logged('request').filter((record) => record.operation === operation && record.path === path);
}
