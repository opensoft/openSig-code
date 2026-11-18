// SPDX-License-Identifier: Apache-2.0
//
// Test support for the composed server (T031 US1 composition, A-010 row WIRE-US1; SEC-12,
// SEC-15, SEC-16). Everything is synthetic and local, generated at run time in mkdtemp
// directories and removed by support.mjs cleanup():
// - the server under test is the real entrypoint's startServer() (src/server/main.ts) with the
//   composed environment (support.mjs composedEnv): its own database, blob store, notifier,
//   0600 key file, ceremony, EnvelopeApi and ApprovalApi, all built by main.ts;
// - "the test side" is a second connection to the same database file and the same blob store,
//   with the T007 envelope service and a T008 ceremony of its own (the same key file, mail to
//   a spool of the test's own): it sets up what the HTTP API cannot reach without the T033
//   parse service (a document recorded from a synthetic parse result, a sent envelope, an
//   upload idempotency record), the way the T008 and T010 test worlds do. It never replaces
//   a production module of the server under test;
// - a loopback SMTP relay of the test's own (smtpRelay) stands in for the mail relay at the
//   network boundary, so the composed notifier's real SMTP transport can be held (a blocked
//   notifier: the greeting is withheld) and then released.
// Capability values (invitation tokens, codes, session values, CSRF tokens) are read back from
// spools or responses, kept in memory, and never put in a test name or assertion message.

import { randomBytes } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { request } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { RecipientCeremony, loadChallengeKey } from '../../src/api/recipients/index.ts';
import { EnvelopeService } from '../../src/domain/envelopes/index.ts';
import { createNotifier, createSpoolTransport } from '../../src/notifications/index.ts';
import { createLogger } from '../../src/server/redact.ts';
import { openBlobStore } from '../../src/storage/blobs/index.ts';
import { openDatabase } from '../../src/storage/db/index.ts';
import { ALPHA, tempDir } from './support.mjs';

export const ORIGIN = 'https://sign.alpha.test';
export const COOKIE = '__Host-opensig_rs';
export const RECIPIENT_ONE = 'signer.one@example.test';
export const HUMAN = Object.freeze({ kind: 'human-operator', ref: 'operator-test-side-1' });
const MINUTE = 60_000;

/** Synthetic PDF-shaped bytes; the ceremony serves bytes and never parses them. */
export function syntheticPdf(label = randomBytes(6).toString('hex')) {
  return Buffer.from(['%PDF-1.7', `% synthetic review document ${label}`, '1 0 obj << /Type /Catalog >> endobj', 'trailer << /Root 1 0 R >>', '%%EOF', ''].join('\n'), 'latin1');
}

export function createInput(overrides = {}) {
  return { source: { app: 'manual', record: 'synthetic-record-0001', version: 'v1' }, recipients: [{ email: RECIPIENT_ONE, role: 'approver', ordinal: 1 }], ...overrides };
}

export const FIELDS = Object.freeze([
  Object.freeze({ key: 'sig_1', recipient_ordinal: 1, page: 1, type: 'signature', rect: Object.freeze({ x: 0.1, y: 0.8, width: 0.3, height: 0.08 }) }),
  Object.freeze({ key: 'date_1', recipient_ordinal: 1, page: 1, type: 'date', rect: Object.freeze({ x: 0.45, y: 0.8, width: 0.2, height: 0.05 }) }),
]);

/** Spool messages of `kind` in `dir`, oldest first: { name, kind, to, text }. */
export function mails(dir, kind) {
  let names;
  try {
    names = readdirSync(dir).filter((name) => name.endsWith('.eml') && !name.startsWith('.')).sort();
  } catch {
    return [];
  }
  return names
    .map((name) => {
      const text = readFileSync(join(dir, name), 'latin1');
      return { name, kind: /^X-OpenSig-Notification: (\S+)\r$/m.exec(text)?.[1] ?? null, to: /^To: (\S+)\r$/m.exec(text)?.[1] ?? null, text };
    })
    .filter((mail) => kind === undefined || mail.kind === kind);
}

/** The invitation token of an invitation mail (the URL fragment), or null. */
export function tokenOf(mail) {
  return /\/sign#i=([A-Za-z0-9_-]{43,128})\r?$/m.exec(mail.text)?.[1] ?? null;
}

/** The code of a challenge mail, or null. */
export function codeOf(mail) {
  return /^ {4}([0-9A-Z]{10})\r$/m.exec(mail.text)?.[1] ?? null;
}

/** The session value of a createRecipientSession response's Set-Cookie, or null. */
export function cookieOf(response) {
  const header = [response.headers['set-cookie'] ?? []].flat()[0] ?? '';
  return new RegExp(`^${COOKIE}=([A-Za-z0-9_-]{43,128});`).exec(header)?.[1] ?? null;
}

/** Rows of `sql` through a read-only connection to `path`, as any reader of the file sees them. */
export function rows(path, sql, ...parameters) {
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    return raw.prepare(sql).all(...parameters).map((row) => ({ ...row }));
  } finally {
    raw.close();
  }
}

/**
 * The test side of a composed world started from `env` (after startServer): a second database connection, the same blob store, the T007 envelope service
 * reporting to a T008 ceremony of the test's own (the same key file; mail to the test's own
 * spool). `clock` is the test side's clock (default: real time, as the server's).
 */
export function testSide(env, { clock = () => new Date() } = {}) {
  const db = openDatabase({ path: env.OPENSIG_DATABASE });
  // The server creates this directory at startup; created here too (0700) so a head without the
  // composition fails on its answers, not in this setup.
  mkdirSync(join(env.OPENSIG_DATA_DIR, 'blobs'), { recursive: true, mode: 0o700 });
  const blobs = openBlobStore({ root: join(env.OPENSIG_DATA_DIR, 'blobs') });
  const spoolDir = join(tempDir('test-side-spool'), 'spool');
  const logger = createLogger(() => {});
  const notifier = createNotifier({ transport: createSpoolTransport({ dir: spoolDir }), from: 'no-reply@opensig.test', publicOrigin: ORIGIN, rateLimit: { limit: 1000, windowMs: 10 * MINUTE }, logger });
  const ceremony = new RecipientCeremony({ db, blobs, notifier, challengeKey: loadChallengeKey({ path: env.OPENSIG_CHALLENGE_KEY_FILE }), clock, logger });
  const service = new EnvelopeService({ db, clock, onChange: ceremony.onEnvelopeChange });
  const req = (actor = HUMAN, idempotency) => ({ tenantId: ALPHA.id, actor, ...(idempotency ? { idempotency } : {}) });
  const side = {
    db,
    blobs,
    spoolDir,
    ceremony,
    service,
    req,
    /** A draft (version 1) created on the test side; `input` overrides createInput(). */
    draft(input = {}, actor = HUMAN) {
      return service.create(req(actor), createInput(input)).body;
    },
    /**
     * Record a synthetic document on `envelope` (a draft at `envelope.version`) as T034 would
     * after a parse, through the domain: the blob is stored first. With `key`, the domain writes
     * the upload's idempotency record for `actor` (route uploadDocument) in the same transaction.
     */
    recordDocument(envelope, { actor = HUMAN, key } = {}) {
      const pdf = syntheticPdf();
      const put = blobs.put(ALPHA.id, pdf);
      const pages = [{ number: 1, width: 612, height: 792, rotate: 0 }];
      const document = { digest: put.digest, bytes: pdf.length, pages, parseReport: { pages: 1, network_sandbox: 'netns+fs-enforced (local)' } };
      const idempotency = key === undefined ? undefined : { key, request: { expected_version: envelope.version, document_digest: put.digest, document_bytes: pdf.length } };
      return { envelope: service.uploadDocument(req(actor, idempotency), envelope.id, envelope.version, document).body, pdf };
    },
    /** A one-recipient envelope taken to sent on the test side; its invitation is mailed to the test spool. */
    async sentEnvelope() {
      const { envelope: uploaded, pdf } = side.recordDocument(side.draft());
      const prepared = service.prepare(req(), uploaded.id, { expected_version: uploaded.version, fields: FIELDS }).body;
      const sent = (await ceremony.run(() => service.send(req(), prepared.id, { expected_version: prepared.version }))).body;
      const invitation = mails(spoolDir, 'recipient_invitation').filter((mail) => mail.to === RECIPIENT_ONE).pop();
      const token = invitation === undefined ? null : tokenOf(invitation);
      if (token === null) throw new Error('test side: sending mailed no invitation');
      return { envelope: sent, token, pdf };
    },
    close() {
      db.close();
    },
  };
  return side;
}

/** One HTTP request; resolves with { status, headers, bytes, text, json } once the whole response is in. */
export function call(port, { method = 'GET', path, headers = {}, body, socketPath } = {}) {
  return new Promise((resolveResponse, reject) => {
    const payload = body === undefined ? undefined : Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
    const all = { ...headers };
    if (payload !== undefined) {
      if (!Object.keys(all).some((name) => name.toLowerCase() === 'content-type')) all['content-type'] = 'application/json';
      all['content-length'] = String(payload.length);
    }
    const target = socketPath ? { socketPath } : { host: '127.0.0.1', port };
    const req = request({ ...target, method, path, headers: all, agent: false }, (res) => {
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
        resolveResponse({ status: res.statusCode, headers: res.headers, bytes, text, json });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

/**
 * A loopback SMTP relay of the test's own, the network boundary of the composed notifier's
 * SMTP transport. While `held`, a connection is accepted and its greeting withheld, so a
 * delivery waits (a blocked notifier); release() greets every held connection and serves the
 * minimal RFC 5321 dialogue, accepting each message. Deliveries are counted, never printed.
 */
export async function smtpRelay({ held = true } = {}) {
  let holding = held;
  const waiting = [];
  const sockets = new Set();
  const state = { connections: 0, delivered: 0 };
  const listeners = new Set();
  const notify = () => {
    for (const listener of [...listeners]) listener();
  };
  const serve = (socket) => {
    socket.write('220 relay.test ESMTP\r\n');
    let buffer = '';
    let inData = false;
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1');
      for (;;) {
        if (inData) {
          const end = buffer.indexOf('\r\n.\r\n');
          if (end < 0) return;
          buffer = buffer.slice(end + 5);
          inData = false;
          state.delivered += 1;
          socket.write('250 accepted\r\n');
          notify();
          continue;
        }
        const end = buffer.indexOf('\r\n');
        if (end < 0) return;
        const line = buffer.slice(0, end).toUpperCase();
        buffer = buffer.slice(end + 2);
        if (line.startsWith('DATA')) {
          inData = true;
          socket.write('354 go ahead\r\n');
        } else if (line.startsWith('QUIT')) {
          socket.end('221 bye\r\n');
          return;
        } else {
          socket.write('250 ok\r\n');
        }
      }
    });
  };
  const server = createNetServer((socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
    state.connections += 1;
    if (holding) waiting.push(socket);
    else serve(socket);
    notify();
  });
  await new Promise((resolveListen) => server.listen({ host: '127.0.0.1', port: 0 }, resolveListen));
  return {
    port: server.address().port,
    state,
    /** Resolves once `predicate(state)` holds; re-checked on every relay event (no polling). */
    until(predicate) {
      if (predicate(state)) return Promise.resolve();
      return new Promise((resolveWait) => {
        const listener = () => {
          if (!predicate(state)) return;
          listeners.delete(listener);
          resolveWait();
        };
        listeners.add(listener);
      });
    },
    /** Greet the oldest held connection only (later ones stay held). */
    releaseOne() {
      const socket = waiting.shift();
      if (socket !== undefined && !socket.destroyed) serve(socket);
    },
    /** Greet every held connection and stop holding new ones. */
    release() {
      holding = false;
      for (const socket of waiting.splice(0)) if (!socket.destroyed) serve(socket);
    },
    close() {
      for (const socket of sockets) socket.destroy();
      return new Promise((resolveClose) => server.close(() => resolveClose()));
    },
  };
}

/** Await `promise`, failing with `label` after `ms` (a hang guard; never a pass criterion). */
export async function guarded(promise, label, ms = 20_000) {
  let timer;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}: hang guard fired after ${ms} ms (it bounds a failure and is not the oracle)`)), ms);
  });
  try {
    return await Promise.race([promise, guard]);
  } finally {
    clearTimeout(timer);
  }
}

/** A macrotask turn: every nextTick, microtask and immediate queued before it has run. */
export const turn = () => new Promise((resolveTurn) => setImmediate(() => setImmediate(resolveTurn)));
