// SPDX-License-Identifier: Apache-2.0
//
// The server world of the review-shell tests (T009, AG-01..AG-07). Everything is synthetic
// and local, made at run time and removed afterwards:
// - the review shell is built once per test file by scripts/build-ui.mjs (T035) into a
//   temporary directory, which the server's static handler serves through the test-only
//   StartOptions.distDir (A-010 row DIST-DIR, request #34 B1): the repository's dist/ is
//   never written;
// - a migrated SQLite database with one tenant and its consent text in force (a wording with
//   a line break and a non-ASCII apostrophe, so "exact text" is tested byte for byte), a
//   0600 challenge-HMAC key file and a mail spool, each in its own mkdtemp directory;
// - the real server, started in this process by startServer() (src/server/main.ts, the US1
//   composition of row WIRE-US1) on 127.0.0.1 with an OS-chosen port: the browser talks to
//   exactly what production serves, Origin allowlist, CSRF and the real __Host-opensig_rs
//   cookie included, over plain http://127.0.0.1 (row LOOPBACK-COOKIE; no bypass flag, no
//   weakened attribute). Its parse plan is T033's plan for an empty launcher set, as SEC-12's
//   DIST-DIR case uses it, so no sandbox probe runs at startup: these tests upload nothing
//   over HTTP, and the documents come from the envelope service below;
// - envelopes taken to sent through the T007 envelope service on the composition's own
//   database, blob store and ceremony (operator routes need OIDC, which these tests do not
//   exercise), with documents from fixtures/synthetic/documents and their manifest geometry;
// - invitation tokens and codes read back from the spool only. They are kept in memory and
//   never put in a test name or an assertion message.
// requestChallenge's work runs after its 202; code() settles it through the ceremony's drain()
// before it reads the spool, so no test sleeps.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ASSURANCE, SEAL_NOTICE } from '../../../src/domain/consent/index.ts';
import { EnvelopeService } from '../../../src/domain/envelopes/index.ts';
import { createParseServiceForTests } from '../../../src/pdf/service.ts';
import { startServer } from '../../../src/server/main.ts';
import { openDatabase } from '../../../src/storage/db/index.ts';

export { ASSURANCE, SEAL_NOTICE };

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
export const DOCUMENTS = join(ROOT, 'fixtures', 'synthetic', 'documents');
export const HUMAN = Object.freeze({ kind: 'human-operator', ref: 'operator-review-shell' });
export const CONSENT_VERSION = '2026.11-review-shell';
export const CONSENT_TEXT = 'I have reviewed this synthetic document in full and I approve it as shown.\nI understand that my approval is recorded with the organization\u2019s seal notice.';
export const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const DOCUMENT_PATH = '/v1/recipient-session/document';
export const APPROVAL_PATH = '/v1/recipient-session/approval';
export const CHALLENGE_PATH = '/v1/recipient-session/challenges';
export const SESSION_PATH = '/v1/recipient-session';
export const JSON_BODY_LIMIT = 256 * 1024;

// T033's plan for an empty launcher set: no sandbox probe at startup (see the header).
const unprobedPlan = createParseServiceForTests({ launchers: [] }).plan;

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sid(prefix) {
  return `${prefix}-${randomBytes(12).toString('base64url')}`;
}

let manifestCache;
/** The fixture manifest entry of `file` (displayed geometry and SHA-256). */
export function fixture(file) {
  manifestCache ??= JSON.parse(readFileSync(join(DOCUMENTS, 'manifest.json'), 'utf8'));
  const entry = manifestCache.documents.find((document) => document.file === file);
  assert.ok(entry, `the fixture manifest lists ${file}`);
  return entry;
}

/** Build the review shell into `out`, a temporary directory (T035's builder, --out). */
export function buildShell(out) {
  const run = spawnSync(process.execPath, [join(ROOT, 'scripts', 'build-ui.mjs'), '--out', out], { cwd: ROOT, encoding: 'utf8', timeout: 120_000 });
  assert.equal(run.status, 0, `the review shell builds (T035): ${(run.stderr ?? '').trim().slice(0, 600)}`);
  assert.match(run.stdout, /^build-ui: OK /m);
}

/** A different code of the same shape (one character changed). */
export function wrongCode(code) {
  const next = CROCKFORD[(CROCKFORD.indexOf(code[3]) + 1) % CROCKFORD.length];
  return code.slice(0, 3) + next + code.slice(4);
}

/** The code as a person might type it: lower case, spaced and dashed, O for 0 and l for 1. */
export function sloppyCode(code) {
  const lower = code.toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l');
  return ` ${lower.slice(0, 5)} - ${lower.slice(5)} `;
}

/**
 * Start a world: the shell built into a temporary distDir, database, key, spool, the real
 * server with the US1 composition on plain http://127.0.0.1, and the envelope service on the
 * composition's database. Close with world.close().
 */
export async function startWorld() {
  const dirs = [];
  const dir = (prefix) => {
    const made = mkdtempSync(join(tmpdir(), prefix));
    dirs.push(made);
    return made;
  };
  const distDir = join(dir('opensig-autograph-dist-'), 'dist');
  buildShell(distDir);
  const dataDir = dir('opensig-autograph-data-');
  const dbPath = join(dataDir, 'opensig.db');
  const tenant = sid('tenant');
  const consentId = sid('consent');
  const now = new Date(Date.now() - 60_000).toISOString();
  const seed = openDatabase({ path: dbPath });
  try {
    seed.migrate();
    seed.transaction(() => {
      const store = seed.forTenant(tenant);
      store.insert('tenants', {
        oidc_issuer: 'https://issuer.example.test',
        oidc_audience: 'opensig-api',
        role_claim: 'roles',
        role_map_json: JSON.stringify({ 'opensig-sender': 'sender', 'opensig-admin': 'tenant_admin' }),
        principal_kind_claim: 'principal_kind',
        allowed_roles_json: JSON.stringify(['sender', 'tenant_admin', 'service']),
        created_at: now,
        updated_at: now,
      });
      store.insert('consent_texts', {
        id: consentId,
        version: CONSENT_VERSION,
        locale: 'en',
        text: CONSENT_TEXT,
        text_digest: sha256(Buffer.from(CONSENT_TEXT, 'utf8')),
        effective_from: now,
        created_at: now,
      });
      store.update('tenants', {}, { consent_text_id: consentId });
    });
  } finally {
    seed.close();
  }
  const keyPath = join(dir('opensig-autograph-key-'), 'challenge-hmac.key');
  writeFileSync(keyPath, randomBytes(32), { mode: 0o600 });
  chmodSync(keyPath, 0o600);
  const spoolDir = join(dir('opensig-autograph-spool-'), 'spool');
  const lines = [];
  const running = await startServer(
    {
      OPENSIG_HOST: '127.0.0.1',
      OPENSIG_PORT: '0',
      OPENSIG_DATA_DIR: dataDir,
      OPENSIG_DATABASE: dbPath,
      OPENSIG_CHALLENGE_KEY_FILE: keyPath,
      OPENSIG_MAIL_TRANSPORT: 'spool',
      OPENSIG_SPOOL_DIR: spoolDir,
      // Only the mailed links use it; the browser goes to the bound port. With no
      // OPENSIG_ALLOWED_ORIGINS, the bound loopback origin is the one allowed Origin.
      OPENSIG_PUBLIC_ORIGIN: 'http://127.0.0.1:8443',
    },
    { logSink: (line) => lines.push(line), distDir, parsePlan: unprobedPlan },
  );
  // The server must serve this very build (distDir honoured), not the repository's dist/.
  const served = await fetch(`http://127.0.0.1:${running.port}/sign`, { redirect: 'error' });
  const shell = Buffer.from(await served.arrayBuffer());
  if (served.status !== 200 || !shell.equals(readFileSync(join(distDir, 'autograph', 'index.html')))) {
    await running.close();
    for (const made of dirs) rmSync(made, { recursive: true, force: true });
    assert.fail(`the server does not serve the temporary build (StartOptions.distDir, row DIST-DIR): GET /sign answered ${served.status}`);
  }
  const { composition } = running;
  const service = new EnvelopeService({ db: composition.db, clock: () => new Date(), onChange: composition.ceremony.onEnvelopeChange });
  const origin = `http://127.0.0.1:${running.port}`;
  const seen = new Set();
  let serial = 0;

  const world = {
    origin,
    distDir,
    tenant,
    running,
    composition,
    service,
    lines,
    consent: { version: CONSENT_VERSION, text: CONSENT_TEXT, digest: sha256(Buffer.from(CONSENT_TEXT, 'utf8')) },
    /** A fresh recipient address on the reserved test domain. */
    address(label = 'signer') {
      serial += 1;
      return `${label}.${serial}.${randomBytes(3).toString('hex')}@example.test`;
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
    /** Spool messages not taken before, of `kind` to `to`; each is taken once. */
    takeMails(kind, to) {
      const fresh = world.mails().filter((mail) => !seen.has(mail.name) && mail.kind === kind && mail.to === to);
      for (const mail of fresh) seen.add(mail.name);
      return fresh;
    },
    /**
     * An envelope taken to sent, recipient 1's invitation mailed through the server's own
     * notifier. `fields` use recipient ordinals; `recipients` are addresses in order.
     * Returns { envelope, token, url, pdf, entry, recipients, fields }.
     */
    async sentEnvelope({ document = 'agreement-multipage.pdf', recipients = [world.address()], fields } = {}) {
      const entry = fixture(document);
      const pdf = readFileSync(join(DOCUMENTS, document));
      assert.equal(sha256(pdf), entry.sha256, 'the fixture bytes match their manifest');
      const put = composition.blobs.put(tenant, pdf);
      const pages = entry.pages.map((page) => ({ number: page.number, width: page.width, height: page.height, rotate: page.rotate }));
      const lastPage = pages.length;
      const chosen = fields ?? [
        { key: 'sig_1', recipient_ordinal: 1, page: lastPage, type: 'signature', rect: { x: 0.1, y: 0.72, width: 0.36, height: 0.08 } },
        { key: 'date_1', recipient_ordinal: 1, page: lastPage, type: 'date', rect: { x: 0.55, y: 0.74, width: 0.2, height: 0.05 } },
        ...(recipients.length > 1 ? [{ key: 'sig_2', recipient_ordinal: 2, page: lastPage, type: 'signature', rect: { x: 0.1, y: 0.86, width: 0.36, height: 0.08 } }] : []),
      ];
      const request = { tenantId: tenant, actor: HUMAN };
      const roles = ['approver', 'countersigner', 'witness'];
      const created = service.create(request, {
        source: { app: 'manual', record: sid('record'), version: 'v1' },
        recipients: recipients.map((email, index) => ({ email, role: roles[index] ?? 'approver', ordinal: index + 1 })),
      }).body;
      const uploaded = service.uploadDocument(request, created.id, created.version, {
        digest: put.digest,
        bytes: pdf.length,
        pages,
        // The page list T034's upload stores (request #53): each manifest page with its own MediaBox and an equal CropBox.
        parseReport: { pages: entry.pages.map((page, index) => ({ ...pages[index], media_box: [...page.media_box], crop_box: [...page.media_box] })), network_sandbox: 'netns+fs-enforced (local)' },
      }).body;
      const prepared = service.prepare(request, created.id, { expected_version: uploaded.version, fields: chosen }).body;
      const sent = (await composition.ceremony.run(() => service.send(request, prepared.id, { expected_version: prepared.version }))).body;
      const token = world.invitation(recipients[0]);
      return { envelope: sent, token, url: `${origin}/sign#i=${token}`, pdf, entry, recipients, fields: chosen };
    },
    /** The token of the one fresh invitation mailed to `to`. */
    invitation(to) {
      const mails = world.takeMails('recipient_invitation', to);
      assert.equal(mails.length, 1, 'exactly one invitation is mailed');
      const match = /\/sign#i=([A-Za-z0-9_-]{43,128})\r?$/m.exec(mails[0].text);
      assert.ok(match, 'the invitation mail carries a /sign link with the invitation in its fragment');
      return match[1];
    },
    /** Settle requestChallenge's post-response work, then the one fresh code mailed to `to`. */
    async code(to) {
      await composition.ceremony.drain();
      const mails = world.takeMails('recipient_challenge', to);
      assert.equal(mails.length, 1, 'exactly one code is mailed');
      const match = /^ {4}([0-9A-Z]{10})\r$/m.exec(mails[0].text);
      assert.ok(match, 'the challenge mail carries a 10-character code');
      return match[1];
    },
    async close() {
      try {
        await running.close();
      } finally {
        for (const made of dirs) rmSync(made, { recursive: true, force: true });
      }
    },
  };
  return world;
}
