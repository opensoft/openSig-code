// SPDX-License-Identifier: Apache-2.0
//
// T015 per-case world: one temporary, migrated SQLite database and one blob store per case, each
// in an owner-only mkdtemp directory (0700; openDatabase creates the file 0600), a 0700 directory
// for the case's job files (0600), release FIFOs (0600) and the synthetic seal-key placeholder
// (0600; never a key), and, for T010's racers, a runtime 0600 challenge-key file and a mail
// spool. Everything is synthetic and removed on close, on every path.
//
// The seed is T038's own: tests/completion/support/world.mjs seedSealable, a one-recipient
// envelope walked legally to finalizing (version 4) with real seal records (a frozen document
// blob of labelled filler, the field manifest, the consent text, the approval) and T010's
// reservation. The decline case adds a live recipient session for that recipient through T008's
// insertSession, as tests/approval/support.mjs forgeSession does.
//
// Clocks are fixed instants (request #61 (8)): the seed at T038's BASE_TIME, every first runner
// at CASE_START_MS, each later child at an instant read from the database.

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { capabilityHash, newCsrfSecret, newSessionValue } from '../../../src/api/auth/recipient-session.ts';
import { openBlobStore } from '../../../src/storage/blobs/index.ts';
import { blobRef } from '../../../src/storage/blobs/refs.ts';
import { insertSession } from '../../../src/storage/repositories/recipients.ts';
import { BASE_TIME, seedSealable } from '../../completion/support/world.mjs';
import { createTenant, makeScratch, openTemp, sid } from '../../storage/support/fixtures.mjs';

export const REPO = resolve(fileURLToPath(new URL('../../..', import.meta.url)));
/** Busy timeout of every connection in a case: longer than any hold a case makes. */
export const CASE_BUSY_TIMEOUT_MS = 20_000;
/** The first runner's instant, one minute after the seed. */
export const CASE_START_MS = BASE_TIME + 60_000;
/** Every runner's lease length: lease_expires_at = its instant + LEASE_MS (grantLease). */
export const LEASE_MS = 60_000;

/** Tables a case can touch, for "writes nothing" snapshots. */
export const SNAPSHOT_TABLES = Object.freeze([
  'envelopes',
  'recipients',
  'approvals',
  'recipient_sessions',
  'signing_jobs',
  'final_artifacts',
  'verification_reports',
  'outbox_events',
  'audit_events',
  'audit_checkpoints',
  'finalization_attempt_blobs',
  'idempotency_records',
  'disposal_records',
]);

const ownerOnly = (path) => (lstatSync(path).mode & 0o077) === 0;

/** The children run on the pinned Node: the runner starts this file with it (process.execPath). */
export function assertPinnedNode() {
  const pinned = readFileSync(join(REPO, '.node-version'), 'utf8').trim();
  assert.equal(process.version, `v${pinned}`, `premise: the case runs on the pinned Node v${pinned} (found ${process.version}), so its children do too`);
}

export function createCaseWorld({ maxAttempts = 5, declineSession = false } = {}) {
  const scratch = makeScratch();
  try {
    const { db, path, dir } = openTemp(scratch, { busyTimeoutMs: CASE_BUSY_TIMEOUT_MS });
    const blobRoot = join(dir, 'blobs');
    mkdirSync(blobRoot, { mode: 0o700 });
    const jobsDir = scratch.dir('opensig-recovery-jobs-');
    const keyPath = join(scratch.dir('opensig-recovery-key-'), 'challenge-hmac.key');
    writeFileSync(keyPath, randomBytes(32), { mode: 0o600 });
    chmodSync(keyPath, 0o600);
    const sealKeyFile = join(jobsDir, 'synthetic-seal-key');
    writeFileSync(sealKeyFile, 'synthetic placeholder, never a key\n', { mode: 0o600 });
    const spoolDir = join(scratch.dir('opensig-recovery-spool-'), 'spool');
    for (const owned of [dir, blobRoot, jobsDir]) assert.ok(ownerOnly(owned), `premise: case directory ${owned.split('/').pop()} is owner-only (0700)`);
    assert.ok(ownerOnly(path) && ownerOnly(keyPath) && ownerOnly(sealKeyFile), 'premise: the database, the challenge key and the seal placeholder are owner-only (0600)');
    const blobs = openBlobStore({ root: blobRoot });

    // T038's seed, on this case's database, blob store and tenant.
    const tenantId = sid('tenant');
    createTenant(db, tenantId);
    const store = db.forTenant(tenantId);
    const seedIso = new Date(BASE_TIME).toISOString();
    const seeded = seedSealable({ db, store, blobs, tenantId, clock: { iso: () => seedIso, now: () => new Date(BASE_TIME) } }, { maxAttempts });
    let declineCookie = null;
    if (declineSession) {
      const envelope = store.get('envelopes', { id: seeded.envelopeId });
      const value = newSessionValue();
      db.transaction(() => {
        // The seeded consent text in force, as tests/approval/support.mjs sets it for its tenants.
        const [consent] = store.list('consent_texts', {});
        assert.ok(consent, 'premise: the seed stored a consent text');
        store.update('tenants', {}, { consent_text_id: consent.id });
        insertSession(store, {
          id: sid('sess'),
          valueHash: capabilityHash(value),
          envelopeId: seeded.envelopeId,
          recipientId: seeded.recipientId,
          revisionId: String(envelope.base_revision_id),
          manifestDigest: String(envelope.manifest_digest),
          csrfSecret: newCsrfSecret(),
          now: seedIso,
        });
      });
      declineCookie = value;
    }

    const world = {
      db,
      path,
      dir,
      blobRoot,
      blobs,
      jobsDir,
      keyPath,
      spoolDir,
      sealKeyFile,
      scratch,
      ctx: Object.freeze({
        tenantId,
        envelopeId: seeded.envelopeId,
        reservedVersion: seeded.reservedVersion,
        recipientId: seeded.recipientId,
        seedBlobRefs: Object.freeze([blobRef(tenantId, seeded.documentDigest)]),
        seedAuditHeadSeq: Number(db.forTenant(tenantId).count('audit_events')),
      }),
      /** In memory only, for the decline racer's job file (0600); never logged or asserted. */
      declineCookie,
      /** Rows of a table through a read-only connection; `table` is always a constant. */
      rows(table, where = '', parameters = []) {
        const raw = new DatabaseSync(path, { readOnly: true });
        try {
          return raw.prepare(`SELECT * FROM ${table} ${where} ORDER BY rowid`).all(...parameters).map((row) => ({ ...row }));
        } finally {
          raw.close();
        }
      },
      /** Row counts and a content digest per table, through a read-only connection. */
      snapshot(tables = SNAPSHOT_TABLES) {
        const raw = new DatabaseSync(path, { readOnly: true });
        try {
          const out = {};
          for (const table of tables) {
            const rows = raw.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all();
            const text = JSON.stringify(rows, (_key, value) => (value instanceof Uint8Array ? `bytes:${Buffer.from(value).toString('hex')}` : typeof value === 'bigint' ? String(value) : value));
            out[table] = `${rows.length} rows, sha256 ${createHash('sha256').update(text).digest('hex').slice(0, 16)}`;
          }
          return out;
        } finally {
          raw.close();
        }
      },
      close() {
        try {
          db.close();
        } finally {
          scratch.cleanup();
        }
      },
    };
    return world;
  } catch (error) {
    scratch.cleanup();
    throw error;
  }
}

/** Every table a case can touch, plus the tenant's published blobs, as one flat comparable map. */
export function observe(world) {
  const digests = world.blobs.list(world.ctx.tenantId);
  return { ...world.snapshot(), 'blob store': `${digests.length} blobs, sha256 ${createHash('sha256').update(digests.join(',')).digest('hex').slice(0, 16)}` };
}

/** The envelope's SigningJob row. */
export function jobRow(world) {
  const [row] = world.rows('signing_jobs', 'WHERE tenant_id = ? AND envelope_id = ?', [world.ctx.tenantId, world.ctx.envelopeId]);
  assert.ok(row, `the job of envelope ${world.ctx.envelopeId} exists`);
  return row;
}

/** The envelope row. */
export function envelopeRow(world) {
  const [row] = world.rows('envelopes', 'WHERE tenant_id = ? AND id = ?', [world.ctx.tenantId, world.ctx.envelopeId]);
  assert.ok(row, `envelope ${world.ctx.envelopeId} exists`);
  return row;
}

/** One-line discriminating values of the job (request #70 (6)): ids, statuses, counts and instants. */
export function describeJob(job) {
  return `job ${job.status} attempts ${job.attempt_count}/${job.max_attempts} attempt-no ${job.fencing_token} owner ${job.lease_owner} lease ${job.lease_expires_at} retry ${job.retry_at} error ${job.last_error_code} v${job.version}`;
}

/** A lease granted at `clockMs` expires at clockMs + LEASE_MS (grantLease). */
export function expiryOf(clockMs) {
  return clockMs + LEASE_MS;
}

/** Premise: the held attempt's lease is the one the harness predicts. */
export function assertLease(world, clockMs) {
  const job = jobRow(world);
  const expected = new Date(expiryOf(clockMs)).toISOString();
  assert.equal(job.status, 'running', `premise: the attempt holds the lease (${describeJob(job)})`);
  assert.equal(job.lease_expires_at, expected, `premise: lease_expires_at ${job.lease_expires_at} is the grant instant plus ${LEASE_MS} ms (${expected})`);
  return job;
}
