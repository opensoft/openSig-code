// SPDX-License-Identifier: Apache-2.0
//
// T011's own harness for the US1 acceptance flows in Chromium (SC004-01..SC004-04, US1-01,
// US1-02). It imports production modules and T035's build entry only, never another task's
// test helpers (nothing from tests/browser/autograph/). Everything is synthetic and made at
// test runtime in mkdtemp directories, removed by close():
// - the review shell (T009's src/autograph/) built by scripts/build-ui.mjs (T035) into a
//   temporary directory and served through StartOptions.distDir (A-010 row DIST-DIR): the
//   repository's dist/ is never written;
// - a migrated SQLite database with the synthetic alpha tenant of
//   fixtures/synthetic/identities/identities.json, its tenants row agreeing with the operator
//   authentication file (SEC-07), and a consent text in force whose wording has a line break
//   and a non-ASCII apostrophe;
// - the operator authentication file (T005 format, 0600): an ES256 key pair generated now,
//   private key in memory only, public key as the tenant's JWKS; operator tokens for the
//   synthetic alpha sender, admin and service principal are signed with it per request;
// - a 0600 challenge-HMAC key file of 32 random bytes and a mail spool;
// - the real entrypoint, startServer() (src/server/main.ts), in this process, on plain
//   http://127.0.0.1 with an OS-chosen port and no OPENSIG_ALLOWED_ORIGINS (so the bound
//   loopback origin is the one allowed Origin). Its parse plan is T033's own (no seam), so
//   uploadDocument runs the real sandboxed parse service. Every operator step goes through the
//   contract's operator routes with a bearer token, and every recipient step through the browser.
// The server's own record is read three ways, never through the page: a read-only connection
// to its database, its mail spool, and its JSON request log (logSink), whose request lines
// carry the correlation id each response also carries in X-Correlation-Id.
// The invitation link, the challenge code and the session cookie value are kept in memory and
// never put in a test name, an assertion message or the evidence.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { ASSURANCE, SEAL_NOTICE } from '../../../src/domain/consent/index.ts';
import { startServer } from '../../../src/server/main.ts';
import { openDatabase } from '../../../src/storage/db/index.ts';

export { ASSURANCE, SEAL_NOTICE };

export const REPO = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
export const DOCUMENTS = join(REPO, 'fixtures', 'synthetic', 'documents');
const IDENTITIES = JSON.parse(readFileSync(join(REPO, 'fixtures', 'synthetic', 'identities', 'identities.json'), 'utf8'));
export const ALPHA = IDENTITIES.tenants[0];
export const OPERATORS = Object.freeze({
  sender: ALPHA.operators.find((operator) => operator.kind === 'human-operator' && operator.roles.includes('sender')),
  admin: ALPHA.operators.find((operator) => operator.kind === 'human-operator' && operator.roles.includes('tenant_admin')),
  service: ALPHA.operators.find((operator) => operator.kind === 'service'),
});
const ROLE_CLAIMS = Object.freeze({ sender: 'opensig-sender', tenant_admin: 'opensig-tenant-admin', service: 'opensig-service' });
const SCOPES = 'envelopes:read envelopes:write envelopes:send envelopes:confirm-send';

export const COOKIE = '__Host-opensig_rs';
export const CORRELATION_HEADER = 'x-correlation-id';
export const CONSENT_VERSION = '2026.11-us1-acceptance';
export const CONSENT_TEXT = 'I have reviewed this synthetic document in full and I approve it as shown.\nI understand that the organization’s seal, not a personal certificate, completes it.';
export const PATHS = Object.freeze({
  shell: '/sign',
  challenge: '/v1/recipient-session/challenges',
  session: '/v1/recipient-session',
  document: '/v1/recipient-session/document',
  approval: '/v1/recipient-session/approval',
});
/** Tables a recipient or operator action can change; SC004-04 and the refusals compare their content. */
export const STATE_TABLES = Object.freeze([
  'envelopes',
  'recipients',
  'document_revisions',
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
/** How long a test waits, at most, for a request line to reach the log sink. */
const LOG_WAIT_MS = 2_000;
const LOG_STEP_MS = 25;

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function key(label = 'us1') {
  return `${label}-${randomBytes(16).toString('base64url')}`;
}

const pause = (ms) => new Promise((resolveWait) => setTimeout(resolveWait, ms));

let documentManifest;
export function fixture(file) {
  documentManifest ??= JSON.parse(readFileSync(join(DOCUMENTS, 'manifest.json'), 'utf8'));
  const entry = documentManifest.documents.find((document) => document.file === file);
  assert.ok(entry, `the fixture manifest lists ${file}`);
  const bytes = readFileSync(join(DOCUMENTS, file));
  assert.equal(sha256(bytes), entry.sha256, `${file} matches its manifest`);
  return { entry, bytes };
}

/** Which tables differ between two snapshot() results, in STATE_TABLES order. The one comparison every no-change claim and the positive control use. */
export function changedTables(before, after) {
  return STATE_TABLES.filter((table) => before[table] !== after[table]);
}

/** One HTTP request to 127.0.0.1:port; resolves with { status, headers, json, bytes }. */
export function http(port, { method = 'GET', path, headers = {}, body } = {}) {
  return new Promise((resolveResponse, reject) => {
    const payload = body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const all = { ...headers };
    if (payload !== undefined) {
      all['content-type'] ??= 'application/json';
      all['content-length'] = String(payload.length);
    }
    const req = request({ host: '127.0.0.1', port, method, path, headers: all, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const bytes = Buffer.concat(chunks);
        let json = null;
        try {
          json = JSON.parse(bytes.toString('utf8'));
        } catch {
          json = null;
        }
        resolveResponse({ status: res.statusCode, headers: res.headers, json, bytes });
      });
    });
    req.on('error', reject);
    req.setTimeout(30_000, () => req.destroy(new Error(`no answer to ${method} ${path} within 30 s`)));
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

/** Build the review shell into `out`, a temporary directory, with T035's builder (its --out option). */
export function buildShell(out) {
  const run = spawnSync(process.execPath, [join(REPO, 'scripts', 'build-ui.mjs'), '--out', out], { cwd: REPO, encoding: 'utf8', timeout: 120_000 });
  assert.equal(run.status, 0, `the review shell builds (T035): ${(run.stderr ?? '').trim().slice(0, 600)}`);
  assert.match(run.stdout, /^build-ui: OK /m, 'the builder reports OK');
  return JSON.parse(readFileSync(join(out, 'build-provenance.json'), 'utf8'));
}

/** A request line of the log sink as the tests compare it. */
function requestRecord(record) {
  return {
    correlation: record.correlation_id,
    method: record.method,
    path: record.path,
    operation: record.operation,
    status: record.status,
    error: record.error_code ?? null,
  };
}

/** Start the US1 world; close it with world.close(). */
export async function startWorld() {
  const dirs = [];
  const dir = (label) => {
    const made = mkdtempSync(join(tmpdir(), `opensig-us1-${label}-`));
    dirs.push(made);
    return made;
  };
  const cleanup = () => {
    for (const made of dirs.splice(0)) rmSync(made, { recursive: true, force: true });
  };
  try {
    const distDir = join(dir('dist'), 'dist');
    const build = buildShell(distDir);

    const keyPair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const kid = `us1-${randomBytes(6).toString('hex')}`;
    const tenantAuth = {
      tenantId: ALPHA.id,
      issuer: ALPHA.oidc.issuer,
      audience: ALPHA.oidc.audience,
      algorithms: ['ES256'],
      jwks: { keys: [{ ...keyPair.publicKey.export({ format: 'jwk' }), kid }] },
      claims: { tenant: ALPHA.oidc.claims.tenant, roles: ALPHA.oidc.claims.roles, principalKind: ALPHA.oidc.claims.principal_kind },
      roleMap: { [ROLE_CLAIMS.sender]: 'sender', [ROLE_CLAIMS.tenant_admin]: 'tenant_admin', [ROLE_CLAIMS.service]: 'service' },
      kindMap: { human: 'human-operator', service: 'service' },
    };
    const authPath = join(dir('auth'), 'operator-auth.json');
    writeFileSync(authPath, JSON.stringify({ tenants: [tenantAuth] }), { mode: 0o600 });
    chmodSync(authPath, 0o600);

    const dataDir = dir('data');
    const dbPath = join(dataDir, 'opensig.db');
    const consentId = `consent_${randomBytes(9).toString('base64url')}`;
    const consentDigest = sha256(Buffer.from(CONSENT_TEXT, 'utf8'));
    const now = new Date(Date.now() - 60_000).toISOString();
    const seed = openDatabase({ path: dbPath });
    try {
      seed.migrate();
      seed.transaction(() => {
        const store = seed.forTenant(ALPHA.id);
        store.insert('tenants', {
          oidc_issuer: tenantAuth.issuer,
          oidc_audience: tenantAuth.audience,
          role_claim: tenantAuth.claims.roles,
          role_map_json: JSON.stringify(tenantAuth.roleMap),
          principal_kind_claim: tenantAuth.claims.principalKind,
          principal_kind_map_json: JSON.stringify(tenantAuth.kindMap),
          allowed_roles_json: JSON.stringify(['sender', 'tenant_admin', 'service']),
          created_at: now,
          updated_at: now,
        });
        store.insert('consent_texts', { id: consentId, version: CONSENT_VERSION, locale: 'en', text: CONSENT_TEXT, text_digest: consentDigest, effective_from: now, created_at: now });
        store.update('tenants', {}, { consent_text_id: consentId });
      });
    } finally {
      seed.close();
    }

    const keyPath = join(dir('key'), 'challenge-hmac.key');
    writeFileSync(keyPath, randomBytes(32), { mode: 0o600 });
    chmodSync(keyPath, 0o600);
    const spoolDir = join(dir('spool'), 'spool');
    const lines = [];
    const running = await startServer(
      {
        OPENSIG_HOST: '127.0.0.1',
        OPENSIG_PORT: '0',
        OPENSIG_DATA_DIR: dataDir,
        OPENSIG_DATABASE: dbPath,
        OPENSIG_CHALLENGE_KEY_FILE: keyPath,
        OPENSIG_OPERATOR_AUTH_FILE: authPath,
        OPENSIG_MAIL_TRANSPORT: 'spool',
        OPENSIG_SPOOL_DIR: spoolDir,
        // Only the mailed links use it; the browser goes to the bound port.
        OPENSIG_PUBLIC_ORIGIN: 'http://127.0.0.1:8443',
      },
      { logSink: (line) => lines.push(line), distDir },
    );
    const port = running.port;
    const origin = `http://127.0.0.1:${port}`;

    // The entrypoint must serve this very build (distDir honoured), never the shared dist/.
    const shell = await http(port, { path: PATHS.shell });
    if (shell.status !== 200 || !shell.bytes.equals(readFileSync(join(distDir, 'autograph', 'index.html')))) {
      await running.close();
      assert.fail(`the server does not serve the temporary build (StartOptions.distDir, row DIST-DIR): GET /sign answered ${shell.status}`);
    }

    const seen = new Set();
    const readOnly = (fn) => {
      const raw = new DatabaseSync(dbPath, { readOnly: true });
      try {
        return fn(raw);
      } finally {
        raw.close();
      }
    };
    const world = {
      port,
      origin,
      build,
      lines,
      running,
      consent: { version: CONSENT_VERSION, text: CONSENT_TEXT, digest: consentDigest },
      /** A fresh recipient address on the reserved test domain. */
      address(label) {
        return `${label}.${randomBytes(4).toString('hex')}@example.test`;
      },
      /** A bearer token for the synthetic alpha `who` (sender, admin or service), signed now. */
      bearer(who) {
        const operator = OPERATORS[who];
        assert.ok(operator, `a synthetic ${who} operator exists`);
        const seconds = Math.floor(Date.now() / 1000);
        const payload = {
          iss: tenantAuth.issuer,
          aud: tenantAuth.audience,
          sub: operator.subject,
          iat: seconds,
          exp: seconds + 300,
          [tenantAuth.claims.tenant]: ALPHA.id,
          [tenantAuth.claims.roles]: operator.roles.map((role) => ROLE_CLAIMS[role]),
          [tenantAuth.claims.principalKind]: operator.kind === 'service' ? 'service' : 'human',
          scope: SCOPES,
        };
        const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
        const input = `${b64({ alg: 'ES256', kid, typ: 'JWT' })}.${b64(payload)}`;
        const signature = sign('sha256', Buffer.from(input), { key: keyPair.privateKey, dsaEncoding: 'ieee-p1363' });
        return `${input}.${signature.toString('base64url')}`;
      },
      /** A request with `who`'s bearer token (operator routes, or a refusal test on a recipient route). */
      operator(who, { method = 'GET', path, body, headers = {} }) {
        return http(port, { method, path, body, headers: { authorization: `Bearer ${world.bearer(who)}`, ...headers } });
      },
      /** readEnvelope (GET /v1/envelopes/{envelope_id}) as `who`; asserts 200. */
      async readEnvelope(id, who = 'sender') {
        const read = await world.operator(who, { path: `/v1/envelopes/${id}` });
        assert.equal(read.status, 200, `readEnvelope answers 200 (${read.json?.code ?? ''})`);
        return read.json;
      },
      /**
       * The sender's whole setup, through the operator routes: createEnvelope, uploadDocument
       * (the real T033 parse service), prepareEnvelope, readRecipientPreview, confirmSend and
       * sendEnvelope. Returns { envelope, preview, recipients, fields, entry, bytes, invitation }.
       */
      async sentEnvelope({ recipients, document = 'agreement-multipage.pdf', fields }) {
        const { entry, bytes } = fixture(document);
        const page = entry.pages.length;
        const chosen = fields ?? [
          { key: 'sig_1', recipient_ordinal: 1, page, type: 'signature', rect: { x: 0.1, y: 0.72, width: 0.36, height: 0.08 } },
          { key: 'date_1', recipient_ordinal: 1, page, type: 'date', rect: { x: 0.55, y: 0.74, width: 0.2, height: 0.05 } },
          ...(recipients.length > 1
            ? [
                { key: 'sig_2', recipient_ordinal: 2, page, type: 'signature', rect: { x: 0.1, y: 0.86, width: 0.36, height: 0.08 } },
                { key: 'date_2', recipient_ordinal: 2, page, type: 'date', rect: { x: 0.55, y: 0.88, width: 0.2, height: 0.05 } },
              ]
            : []),
        ];
        const roles = ['Approver', 'Countersigner'];
        const created = await world.operator('sender', {
          method: 'POST',
          path: '/v1/envelopes',
          headers: { 'idempotency-key': key('create') },
          body: { source: { app: 'manual', record: key('record'), version: 'v1' }, recipients: recipients.map((email, index) => ({ email, role: roles[index], ordinal: index + 1 })) },
        });
        assert.equal(created.status, 201, `createEnvelope answers 201 (${created.json?.code ?? ''})`);
        const id = created.json.id;
        const uploaded = await world.operator('sender', {
          method: 'PUT',
          path: `/v1/envelopes/${id}/document`,
          headers: { 'idempotency-key': key('upload'), 'if-match': `"${created.json.version}"`, 'content-type': 'application/pdf' },
          body: bytes,
        });
        assert.equal(uploaded.status, 200, `uploadDocument answers 200 through the T033 parse service (${uploaded.json?.code ?? ''})`);
        assert.equal(uploaded.json.document.digest, entry.sha256);
        const prepared = await world.operator('sender', {
          method: 'POST',
          path: `/v1/envelopes/${id}/prepare`,
          headers: { 'idempotency-key': key('prepare') },
          body: { expected_version: uploaded.json.version, fields: chosen },
        });
        assert.equal(prepared.status, 200, `prepareEnvelope answers 200 (${prepared.json?.code ?? ''})`);
        const preview = await world.operator('sender', { path: `/v1/envelopes/${id}/preview` });
        assert.equal(preview.status, 200, 'readRecipientPreview answers 200');
        const confirmed = await world.operator('sender', {
          method: 'POST',
          path: `/v1/envelopes/${id}/send-confirmations`,
          headers: { 'idempotency-key': key('confirm') },
          body: {
            expected_version: preview.json.version,
            document_digest: preview.json.document.digest,
            manifest_digest: preview.json.manifest_digest,
            recipients_digest: preview.json.recipients_digest,
          },
        });
        assert.equal(confirmed.status, 201, `confirmSend answers 201 (${confirmed.json?.code ?? ''})`);
        const sent = await world.operator('sender', {
          method: 'POST',
          path: `/v1/envelopes/${id}/send`,
          headers: { 'idempotency-key': key('send') },
          body: { expected_version: preview.json.version, authorization_reference: confirmed.json.authorization_reference },
        });
        assert.equal(sent.status, 200, `sendEnvelope answers 200 (${sent.json?.code ?? ''})`);
        assert.equal(sent.json.state, 'sent');
        assert.equal(JSON.stringify(sent.json).includes('/sign#'), false, 'no invitation link is ever returned to the operator');
        return { envelope: sent.json, preview: preview.json, recipients, fields: chosen, entry, bytes, invitation: world.invitation(recipients[0]) };
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
      /** Every spool message to `to`, of any kind, taken or not (a read only). */
      mailsTo(to) {
        return world.mails().filter((mail) => mail.to === to);
      },
      /** Spool messages of `kind` to `to` not taken before; each is taken once. */
      takeMails(kind, to) {
        const fresh = world.mails().filter((mail) => !seen.has(mail.name) && mail.kind === kind && mail.to === to);
        for (const mail of fresh) seen.add(mail.name);
        return fresh;
      },
      /** The one fresh invitation mailed to `to`: { token, url } (url on the bound origin). */
      invitation(to) {
        const mails = world.takeMails('recipient_invitation', to);
        assert.equal(mails.length, 1, 'exactly one invitation is mailed');
        const match = /\/sign#i=([A-Za-z0-9_-]{43,128})\r?$/m.exec(mails[0].text);
        assert.ok(match, 'the invitation mail carries a /sign link with the invitation in its fragment');
        return { token: match[1], url: `${origin}/sign#i=${match[1]}` };
      },
      /** Settle requestChallenge's post-response work, then the one fresh code mailed to `to`. */
      async code(to) {
        await running.composition.ceremony.drain();
        const mails = world.takeMails('recipient_challenge', to);
        assert.equal(mails.length, 1, 'exactly one code is mailed');
        const match = /^ {4}([0-9A-Z]{10})\r$/m.exec(mails[0].text);
        assert.ok(match, 'the challenge mail carries a 10-character code');
        return match[1];
      },
      /**
       * Per-table SHA-256 of STATE_TABLES, read through a read-only connection (the server's own
       * record). One column is left out: recipient_sessions.last_seen_at, the idle timer that any
       * authenticated read of a recipient's own open page moves (its viewer included). A new or
       * revoked session still changes the table; footprint() counts sessions separately.
       */
      snapshot() {
        return readOnly((raw) => {
          const out = {};
          for (const table of STATE_TABLES) {
            const rows = raw.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all().map((row) => {
              const copy = {};
              for (const [column, value] of Object.entries(row)) {
                if (table === 'recipient_sessions' && column === 'last_seen_at') continue;
                copy[column] = value instanceof Uint8Array ? `bytes:${Buffer.from(value).toString('hex')}` : typeof value === 'bigint' ? String(value) : value;
              }
              return copy;
            });
            out[table] = `${rows.length}:${sha256(JSON.stringify(rows))}`;
          }
          return out;
        });
      },
      /** Rows of one table for one envelope, read-only. */
      rows(table, envelopeId) {
        return readOnly((raw) => raw.prepare(`SELECT * FROM ${table} WHERE envelope_id = ? ORDER BY rowid`).all(envelopeId).map((row) => ({ ...row })));
      },
      /**
       * What the store holds for the recipient of `ordinal` on the envelope, read-only:
       * { invitations, challenges, sessions } counts. A challenge names its invitation only
       * (migration 0003), so challenges are counted through that recipient's invitations.
       */
      footprint(envelopeId, ordinal) {
        return readOnly((raw) => {
          const recipient = raw.prepare('SELECT id FROM recipients WHERE envelope_id = ? AND ordinal = ?').get(envelopeId, ordinal);
          assert.ok(recipient, `the envelope has a recipient ${ordinal}`);
          const count = (sql) => Number(raw.prepare(sql).get(envelopeId, recipient.id).n);
          return {
            invitations: count('SELECT count(*) AS n FROM invitations WHERE envelope_id = ? AND recipient_id = ?'),
            challenges: count('SELECT count(*) AS n FROM challenges WHERE invitation_id IN (SELECT id FROM invitations WHERE envelope_id = ? AND recipient_id = ?)'),
            sessions: count('SELECT count(*) AS n FROM recipient_sessions WHERE envelope_id = ? AND recipient_id = ?'),
          };
        });
      },
      /** The server's own request log since line `from`: [{ correlation, method, path, operation, status, error }]. */
      requestsSince(from) {
        return lines
          .slice(from)
          .map((line) => JSON.parse(line))
          .filter((record) => record.event === 'request')
          .map(requestRecord);
      },
      /** The request line with this correlation id, waiting at most LOG_WAIT_MS for it; null when absent. */
      async loggedRequest(correlation) {
        if (typeof correlation !== 'string' || correlation.length === 0) return null;
        for (let waited = 0; ; waited += LOG_STEP_MS) {
          const found = world.requestsSince(0).find((entry) => entry.correlation === correlation);
          if (found !== undefined) return found;
          if (waited >= LOG_WAIT_MS) return null;
          await pause(LOG_STEP_MS);
        }
      },
      /** The first request line after line `from` that `predicate` accepts, waiting at most `maxMs`; null when none. */
      async nextRequest(from, predicate, maxMs) {
        for (let waited = 0; ; waited += LOG_STEP_MS * 2) {
          const found = world.requestsSince(from).find(predicate);
          if (found !== undefined) return found;
          if (waited >= maxMs) return null;
          await pause(LOG_STEP_MS * 2);
        }
      },
      async close() {
        try {
          await running.close();
        } finally {
          cleanup();
        }
      },
    };
    return world;
  } catch (error) {
    cleanup();
    throw error;
  }
}
