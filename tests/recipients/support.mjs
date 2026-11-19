// SPDX-License-Identifier: Apache-2.0
//
// Test support for the recipient ceremony (T008). Everything is synthetic and
// local, generated at run time and removed afterwards:
// - a migrated SQLite database, a blob store, a mail spool and the 0600
//   challenge-HMAC key file, each in its own mkdtemp directory;
// - identities on example.test, digests of synthetic labels, and documents that
//   are synthetic PDF-shaped bytes built here;
// - the real application (src/server/app.ts) with the production route registry
//   and the T008 handlers installed (withRecipientHandlers), bound to 127.0.0.1
//   on an OS-chosen port; the T007 envelope service reports its changes to the
//   real ceremony, and mail goes through the T032 notifier to the spool only.
//   The server is built by createAppServer (T031), so the recipient tests run
//   with the server's SEC-11 client-error handling.
// requestChallenge's per-invitation work runs after its 202 (data-model.md,
// "Generic 202 (A-010)"). The helpers below settle it through the ceremony's
// drain() hook before they look at storage or the spool; no test sleeps. CH-07
// holds that work with heldWork() and heldNotifier() instead.
// Capability values (invitation tokens, codes, session values, CSRF tokens) are
// read back from the spool or the responses, kept in memory, and never put in a
// test name or an assertion message.

import assert from 'node:assert/strict';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import { chmodSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { RECIPIENT_CEREMONY, RecipientCeremony, loadChallengeKey } from '../../src/api/recipients/index.ts';
import { ROUTES, withRecipientHandlers } from '../../src/api/routes.ts';
import { EnvelopeService } from '../../src/domain/envelopes/index.ts';
import { createNotifier, createSpoolTransport } from '../../src/notifications/index.ts';
import { createApp, createAppServer } from '../../src/server/app.ts';
import { loadServerConfig } from '../../src/server/config.ts';
import { createLogger } from '../../src/server/redact.ts';
import { openBlobStore } from '../../src/storage/blobs/index.ts';
import { loadVendoredContract } from '../contract/envelopes/lib/contract.mjs';
import { validate } from '../contract/envelopes/lib/schema.mjs';
import { BASE_TIME, createTenant, hex, makeScratch, openTemp, sid, ts } from '../storage/support/fixtures.mjs';

export { BASE_TIME, hex, sid, ts };

export const ORIGIN = 'https://sign.alpha.test';
export const MINUTE = 60_000;
export const HOUR = 60 * MINUTE;
export const DAY = 24 * HOUR;
export const HUMAN = Object.freeze({ kind: 'human-operator', ref: 'operator-1' });
export const COOKIE = '__Host-opensig_rs';
export const CONSENT_WORDING = 'I have reviewed this synthetic document and I approve it as shown.';
export const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const CODE_SHAPE = /^[0-9A-HJKMNP-TV-Z]{10}$/;

/** Tables whose content a recipient request could change. */
export const CEREMONY_TABLES = Object.freeze([
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

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

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

/** Synthetic PDF-shaped bytes (the ceremony serves bytes; it never parses them). */
export function syntheticPdf(label) {
  return Buffer.from(
    ['%PDF-1.7', `% synthetic review document ${label} ${randomBytes(6).toString('hex')}`, '1 0 obj << /Type /Catalog >> endobj', 'trailer << /Root 1 0 R >>', '%%EOF', ''].join('\n'),
    'latin1',
  );
}

let contractDoc;
/** Errors of `value` against a component schema of the vendored contract. */
export function contractErrors(schemaName, value) {
  contractDoc ??= loadVendoredContract().doc;
  const schema = contractDoc.components.schemas[schemaName];
  assert.ok(schema, `the contract defines ${schemaName}`);
  return validate(contractDoc, schema, value);
}

/** One HTTP request to the world's server; resolves with { status, headers, rawHeaders, json, bytes } once the whole response is in. */
export function call(port, { method = 'GET', path, headers = {}, body } = {}) {
  return new Promise((resolveResponse, reject) => {
    const payload = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
    const allHeaders = { ...headers };
    if (payload !== undefined) {
      allHeaders['content-type'] ??= 'application/json';
      allHeaders['content-length'] = String(Buffer.byteLength(payload));
    }
    const req = request({ host: '127.0.0.1', port, method, path, headers: allHeaders, agent: false }, (res) => {
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
        resolveResponse({ status: res.statusCode, headers: res.headers, rawHeaders: [...res.rawHeaders], json, bytes });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

/**
 * A synthetic world: database with one tenant and its consent text in force,
 * blob store, spool, 0600 key file, ceremony, envelope service and the real app.
 * CH-07 passes `scheduleWork` (heldWork().schedule), `wrapNotifier`
 * (heldNotifier().wrap) and `wrapDb` to hold or fail the ceremony's
 * post-response work; CH-09 passes a short `busyTimeoutMs` (the database's
 * bounded wait for the write lock); every other test uses the defaults.
 */
export async function createWorld({ limits, idempotencyBodyLimit, scheduleWork, wrapNotifier, wrapDb, busyTimeoutMs } = {}) {
  const scratch = makeScratch();
  const { db, path } = openTemp(scratch, busyTimeoutMs === undefined ? {} : { busyTimeoutMs });
  const tenant = sid('tenant');
  createTenant(db, tenant);
  const consent = { id: sid('consent'), version: '2026.11-synthetic', text: CONSENT_WORDING, digest: sha256(Buffer.from(CONSENT_WORDING, 'utf8')) };
  db.transaction(() => {
    const store = db.forTenant(tenant);
    store.insert('consent_texts', { id: consent.id, version: consent.version, locale: 'en', text: consent.text, text_digest: consent.digest, effective_from: ts(0), created_at: ts(0) });
    store.update('tenants', {}, { consent_text_id: consent.id });
  });

  const keyPath = join(scratch.dir('opensig-key-'), 'challenge-hmac.key');
  const keyBytes = randomBytes(32);
  writeFileSync(keyPath, keyBytes, { mode: 0o600 });
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
  const ceremony = new RecipientCeremony({
    db: wrapDb ? wrapDb(db) : db,
    blobs,
    notifier: wrapNotifier ? wrapNotifier(notifier) : notifier,
    challengeKey: loadChallengeKey({ path: keyPath }),
    clock: time.clock,
    logger,
    ...(limits ? { limits } : {}),
    ...(scheduleWork ? { scheduleWork } : {}),
  });
  const service = new EnvelopeService({
    db,
    clock: time.clock,
    onChange: ceremony.onEnvelopeChange,
    ...(idempotencyBodyLimit ? { idempotencyBodyLimit } : {}),
  });

  const app = createApp({ routes: withRecipientHandlers(ROUTES), config: loadServerConfig({ OPENSIG_PORT: '0' }), logger, authenticator: null, allowedOrigins: new Set([ORIGIN]) });
  app.locals.set(RECIPIENT_CEREMONY, ceremony);
  const server = createAppServer(app);
  await new Promise((resolveListen) => server.listen({ host: '127.0.0.1', port: 0 }, resolveListen));
  const { port } = server.address();
  const seen = new Set();

  const world = {
    db,
    path,
    tenant,
    consent,
    keyBytes,
    keyPath,
    blobs,
    spoolDir,
    time,
    lines,
    ceremony,
    service,
    port,
    /** The node:http server built by createAppServer; CH-07 observes its responses from the test process. */
    server,
    scratch,
    logText: () => lines.join('\n'),
    req: (actor = HUMAN) => ({ tenantId: tenant, actor }),
    http: (options) => call(port, options),
    store: () => db.forTenant(tenant),
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
    rows(table, where = '') {
      const raw = new DatabaseSync(path, { readOnly: true });
      try {
        return raw.prepare(`SELECT * FROM ${table} ${where} ORDER BY rowid`).all().map((row) => ({ ...row }));
      } finally {
        raw.close();
      }
    },
    /** Per-table SHA-256 of the content of the ceremony tables; `omit` maps a table to columns left out. */
    snapshot(omit = {}) {
      const raw = new DatabaseSync(path, { readOnly: true });
      try {
        const out = {};
        for (const table of CEREMONY_TABLES) {
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
      db.close();
      scratch.cleanup();
    },
  };
  return world;
}

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

/** Extract the invitation token from an invitation mail (the URL fragment). */
export function tokenOf(mail) {
  const match = /\/sign#i=([A-Za-z0-9_-]{43,128})\r?$/m.exec(mail.text);
  assert.ok(match, 'the invitation mail carries a /sign link with the invitation in its fragment');
  return match[1];
}

/** Extract the code from a challenge mail. */
export function codeOf(mail) {
  const match = /^ {4}([0-9A-Z]{10})\r$/m.exec(mail.text);
  assert.ok(match, 'the challenge mail carries a 10-character code');
  return match[1];
}

/** A different code of the same shape (one character changed). */
export function wrongCode(code, shift = 1) {
  const index = shift % code.length;
  const next = CROCKFORD[(CROCKFORD.indexOf(code[index]) + 1 + Math.floor(shift / code.length)) % CROCKFORD.length];
  return code.slice(0, index) + next + code.slice(index + 1);
}

/**
 * The page list T034's upload stores in the parse report (request #53): each displayed
 * page with its MediaBox and an equal CropBox, the box sized so that the displayed
 * width and height follow under the page's rotation (a quarter-turned 612 x 792 page
 * has the box [0, 0, 792, 612]).
 */
export function pageReport(pages) {
  return pages.map((page) => {
    const box = page.rotate % 180 === 0 ? [0, 0, page.width, page.height] : [0, 0, page.height, page.width];
    return { ...page, media_box: box, crop_box: [...box] };
  });
}

/**
 * A human-created envelope taken to sent through the T007 service, its
 * document stored in the blob store, the send run inside the ceremony so the
 * invitation is mailed after the commit. Returns { envelope, token, pdf }.
 */
export async function sentEnvelope(world, { recipients = 1, expiresAt } = {}) {
  const pdf = syntheticPdf(sid('doc'));
  const put = world.blobs.put(world.tenant, pdf);
  const pages = Array.from({ length: 2 }, (_, index) => ({ number: index + 1, width: 612, height: 792, rotate: index === 0 ? 0 : 90 }));
  const created = world.service.create(world.req(), createInput(recipients, expiresAt === undefined ? {} : { expires_at: expiresAt })).body;
  const uploaded = world.service.uploadDocument(world.req(), created.id, created.version, {
    digest: put.digest,
    bytes: pdf.length,
    pages,
    parseReport: { pages: pageReport(pages), network_sandbox: 'netns+fs-enforced (local)' },
  }).body;
  const prepared = world.service.prepare(world.req(), created.id, { expected_version: uploaded.version, fields: fieldsFor(recipients) }).body;
  const sent = (await world.ceremony.run(() => world.service.send(world.req(), prepared.id, { expected_version: prepared.version }))).body;
  const invitations = world.takeMails('recipient_invitation', 'signer.one@example.test');
  assert.equal(invitations.length, 1, 'sending mails exactly one invitation to recipient 1');
  return { envelope: sent, token: tokenOf(invitations[0]), pdf };
}

/** Wait until the ceremony's post-response work (requestChallenge after its 202) has settled. */
export async function settle(world) {
  await world.ceremony.drain();
}

/** POST requestChallenge from the allowlisted origin, without settling the work it starts (CH-07). */
export function postChallenge(world, invitation, headers = {}) {
  return world.http({ method: 'POST', path: '/v1/recipient-session/challenges', headers: { origin: ORIGIN, ...headers }, body: { invitation } });
}

/** POST requestChallenge, then settle the per-invitation work it started (the lookup, the challenge write and the mail). */
export async function requestChallenge(world, invitation, headers = {}) {
  const response = await postChallenge(world, invitation, headers);
  await settle(world);
  return response;
}

/** requestChallenge, then the code mailed to `to` (null when nothing was mailed). */
export async function requestCode(world, invitation, to = 'signer.one@example.test') {
  const response = await requestChallenge(world, invitation);
  assert.equal(response.status, 202, 'requestChallenge answers 202');
  const mails = world.takeMails('recipient_challenge', to);
  assert.ok(mails.length <= 1, 'at most one code is mailed per request');
  return mails.length === 0 ? null : codeOf(mails[0]);
}

/** POST createRecipientSession from the allowlisted origin. */
export function createSession(world, invitation, code, headers = {}) {
  return world.http({ method: 'POST', path: '/v1/recipient-session', headers: { origin: ORIGIN, ...headers }, body: { invitation, code } });
}

/** The session value from a createRecipientSession response's Set-Cookie. */
export function cookieOf(response) {
  const header = [response.headers['set-cookie'] ?? []].flat()[0] ?? '';
  const match = new RegExp(`^${COOKIE}=([A-Za-z0-9_-]{43,128});`).exec(header);
  assert.ok(match, 'the response sets the session cookie');
  return match[1];
}

/** Challenge plus session for `invitation`: { session, csrf, state }. */
export async function openSession(world, invitation, to = 'signer.one@example.test') {
  const code = await requestCode(world, invitation, to);
  assert.ok(code !== null, 'a live invitation receives a code');
  const response = await createSession(world, invitation, code);
  assert.equal(response.status, 201, 'the right code creates a session');
  return { session: cookieOf(response), csrf: response.json.csrf_token, state: response.json };
}

/** GET (or HEAD) a recipient route with the session cookie. */
export function readAs(world, session, path = '/v1/recipient-session', { method = 'GET', headers = {} } = {}) {
  return world.http({ method, path, headers: { cookie: `${COOKIE}=${session}`, ...headers } });
}

/** The HMAC the ceremony is expected to store for `code` (recomputed from the test's own key bytes). */
export function expectedHmac(keyBytes, invitationId, challengeId, code) {
  return createHmac('sha256', keyBytes).update(`opensig.challenge/1\n${invitationId}\n${challengeId}\n${code}`, 'utf8').digest('hex');
}

/** A synthetic Approval row for `recipient` (T010 writes real ones). */
export function insertApproval(store, { envelope, recipientId, consent, prior = null, serverTime }) {
  const id = sid('appr');
  const digest = hex(`approval-${id}`);
  store.insert('approvals', {
    id,
    envelope_id: envelope.id,
    recipient_id: recipientId,
    document_digest: envelope.document.digest,
    manifest_digest: envelope.manifest_digest,
    prior_approval_digest: prior,
    consent_text_id: consent.id,
    consent_version: consent.version,
    consent_text_digest: consent.digest,
    field_values_json: '[]',
    field_values_digest: hex(`field-values-${id}`),
    assurance_method: 'mailbox-challenge',
    assurance_level: 'mailbox-control',
    server_time: serverTime,
    approval_digest: digest,
  });
  return { id, digest };
}

/**
 * Recipient 1 approves (synthetic Approval row plus the T007 state machine) in
 * one transaction inside the ceremony, as T010 will: recipient 2's invitation is
 * mailed after the commit. Returns { approval, outcome, token } (token of recipient 2, if any).
 */
export async function approveFirst(world, envelope) {
  const recipient = envelope.recipients.find((entry) => entry.ordinal === 1);
  const result = await world.ceremony.run(() =>
    world.db.transaction(() => {
      const store = world.store();
      const approval = insertApproval(store, { envelope, recipientId: recipient.id, consent: world.consent, serverTime: world.time.now.toISOString() });
      const outcome = world.service.advanceOnApproval(store, { envelopeId: envelope.id, expectedVersion: envelope.version, recipientId: recipient.id, approvalId: approval.id });
      return { approval, outcome };
    }),
  );
  const mails = world.takeMails('recipient_invitation', 'signer.two@example.test');
  return { ...result, token: mails.length === 1 ? tokenOf(mails[0]) : null };
}

/**
 * Resend `recipient`'s invitation inside the ceremony (the invitation half of
 * T034's resendInvitation; its old token is dead) and return the fresh token.
 */
export async function resend(world, envelope, recipient, actor) {
  await world.ceremony.run(() => world.db.transaction(() => world.ceremony.resendInvitation(world.store(), envelope.id, recipient.id, actor)));
  const mails = world.takeMails('recipient_invitation', recipient.email);
  assert.equal(mails.length, 1, 'the resend mails one invitation');
  return tokenOf(mails[0]);
}

/** Twenty wrong codes, five per challenge: the invitation is revoked by the cumulative lockout. */
export async function lockOut(world, token) {
  for (let round = 1; round <= 4; round += 1) {
    const code = await requestCode(world, token);
    assert.ok(code !== null, `lockout round ${round}: a code is mailed`);
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      assert.equal((await createSession(world, token, wrongCode(code, attempt))).status, 401, `lockout round ${round}: wrong code ${attempt}`);
    }
  }
  assert.equal((await createSession(world, token, 'ABCDEFGHJK')).status, 429, 'the invitation is locked');
}

/** True when no capability value in `values` appears in the captured log lines. */
export function logsFreeOf(world, values) {
  const text = world.logText();
  return values.every((value) => typeof value === 'string' && value.length > 0 && !text.includes(value));
}

/** The comparable form of a response's headers: every raw header, name as sent and value, in order, except date and x-correlation-id. */
export function comparableHeaders(response) {
  const pairs = [];
  for (let index = 0; index < response.rawHeaders.length; index += 2) {
    const name = response.rawHeaders[index];
    if (name.toLowerCase() === 'date' || name.toLowerCase() === 'x-correlation-id') continue;
    pairs.push([name, response.rawHeaders[index + 1]]);
  }
  return pairs;
}

/**
 * A scheduler for the ceremony's post-response work (the scheduleWork option).
 * Open, it starts each task on a later turn of the event loop, as the default
 * does; held, it keeps the tasks, in order, until release().
 */
export function heldWork() {
  const tasks = [];
  let held = false;
  return {
    schedule(task) {
      if (held) tasks.push(task);
      else setImmediate(task);
    },
    hold() {
      held = true;
    },
    /** Start every held task, in order, and stay held. */
    release() {
      for (const task of tasks.splice(0)) task();
    },
    /** Start every held task and stop holding. */
    open() {
      held = false;
      for (const task of tasks.splice(0)) task();
    },
    get waiting() {
      return tasks.length;
    },
  };
}

/**
 * A notifier wrapper (the wrapNotifier option). Open, each send goes straight
 * to the real notifier; held, each send waits, in order, until release() lets
 * it through to the spool or fail() makes it throw. whenWaiting(n) resolves
 * once n sends are waiting: it is settled by the sends themselves, never by
 * time.
 */
export function heldNotifier() {
  const queue = [];
  const watchers = [];
  let held = false;
  let real = null;
  const check = () => {
    for (const watcher of [...watchers]) {
      if (queue.length >= watcher.n) {
        watchers.splice(watchers.indexOf(watcher), 1);
        watcher.resolve();
      }
    }
  };
  return {
    wrap(notifier) {
      real = notifier;
      return {
        send(requestValue) {
          if (!held) return real.send(requestValue);
          return new Promise((resolveSend, rejectSend) => {
            queue.push({ resolveSend, rejectSend });
            check();
          }).then(() => real.send(requestValue));
        },
      };
    },
    hold() {
      held = true;
    },
    /** Let the oldest waiting send through. */
    release() {
      const next = queue.shift();
      assert.ok(next, 'a send is waiting');
      next.resolveSend();
    },
    /** Make the oldest waiting send throw `error`. */
    fail(error) {
      const next = queue.shift();
      assert.ok(next, 'a send is waiting');
      next.rejectSend(error);
    },
    /** Let every waiting send through and stop holding. */
    open() {
      held = false;
      for (const next of queue.splice(0)) next.resolveSend();
    },
    whenWaiting(n) {
      return new Promise((resolveWatch) => {
        watchers.push({ n, resolve: resolveWatch });
        check();
      });
    },
    get waiting() {
      return queue.length;
    },
  };
}
