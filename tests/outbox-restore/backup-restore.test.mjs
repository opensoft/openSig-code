// SPDX-License-Identifier: Apache-2.0
//
// Backup and restore (T030): OR-03 restore verifies blob digests (and the
// database file) and writes nothing when refused; OR-04 restore verifies
// audit-chain continuity and refuses a chain head older than the last
// exported head; OR-06 the scripts/backup.mjs command line; OR-07 snapshot
// consistency, layout and backup refusals; OR-08 the exported-head ledger.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, cpSync, existsSync, readdirSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalize } from '../../src/domain/canonical/index.ts';
import { verifyChain } from '../../src/storage/audit/index.ts';
import {
  BackupError,
  createBackup,
  LedgerError,
  readLedger,
  recordExportedHead,
  restoreBackup,
  RestoreRefusedError,
  verifyBackup,
} from '../../src/storage/backup/index.ts';
import { openDatabase, StorageUsageError } from '../../src/storage/db/index.ts';
import { enqueueOutboxEvent } from '../../src/storage/outbox/index.ts';
import { makeScratch, tenantRow } from '../storage/support/fixtures.mjs';
import { BASE_TIME, createTenant, environment, hex, sid, steppingClock, terminalEnvelope } from '../audit-chain/support/chain.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = join(REPO_ROOT, 'scripts', 'backup.mjs');
const scratch = makeScratch();
after(() => scratch.cleanup());

const clock = steppingClock(BASE_TIME + 3_600_000);

/** A live system: database, blob store, audit writer, ledger path, one populated tenant. */
function liveSystem({ events = 4 } = {}) {
  const env = environment(scratch, steppingClock());
  const tenant = sid('tenant');
  createTenant(env.db, tenant);
  const envelope = terminalEnvelope(env.db, env.blobs, tenant, { state: 'completed' });
  appendEvents(env, tenant, events, envelope.env);
  const artifact = env.db.forTenant(tenant).get('final_artifacts', { envelope_id: envelope.env });
  env.db.transaction(() =>
    enqueueOutboxEvent(env.db, tenant, { type: 'envelope.completed', envelopeId: envelope.env, envelopeVersion: 2, artifactId: artifact.artifact_id, artifactDigest: artifact.artifact_digest }, { clock }),
  );
  return { ...env, tenant, envelope, blobRoot: join(env.dir, 'blobs'), ledgerPath: join(env.dir, 'exported-heads.json') };
}

function appendEvents(env, tenant, count, envelopeId = null) {
  env.db.transaction(() => {
    for (let i = 0; i < count; i += 1) env.audit.append(tenant, { type: 'envelope.updated', actor: { kind: 'system', ref: 'test' }, envelopeId, metadata: { step: i } });
  });
}

function backupOf(system) {
  const outDir = join(scratch.dir(), 'backup');
  return createBackup({ databasePath: system.path, blobRoot: system.blobRoot, outDir, ledgerPath: system.ledgerPath, clock }).then((manifest) => ({ outDir, manifest }));
}

function target() {
  const dir = scratch.dir();
  return { databasePath: join(dir, 'restored.db'), blobRoot: join(dir, 'blobs') };
}

function copyBackup(outDir) {
  const copy = join(scratch.dir(), 'copy');
  cpSync(outDir, copy, { recursive: true });
  return copy;
}

/** Rewrite the manifest's database digest, as an attacker who edits both would. */
function resealManifest(backupDir) {
  const file = join(backupDir, 'opensig.db');
  const bytes = readFileSync(file);
  const manifest = JSON.parse(readFileSync(join(backupDir, 'manifest.json'), 'utf8'));
  manifest.database = { ...manifest.database, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
  writeFileSync(join(backupDir, 'manifest.json'), canonicalize(manifest));
}

function refusedWith(pattern) {
  return (error) => error instanceof RestoreRefusedError && error.reasons.some((reason) => pattern.test(reason));
}

function tableRows(db, tenant, table, order) {
  return db.forTenant(tenant).list(table, {}, { orderBy: [[order, 'asc']] }).map((row) => ({ ...row }));
}

test('[OR-03] restore verifies every blob digest and the database digest, and writes nothing when it refuses', async () => {
  const system = liveSystem();
  try {
    const { outDir, manifest } = await backupOf(system);
    assert.equal(manifest.tenants.length, 1);
    assert.equal(manifest.tenants[0].blob_count, 3);

    const corrupt = copyBackup(outDir);
    const blobFile = join(corrupt, 'blobs', 'tenants', system.tenant, 'sha256', system.envelope.pdf.digest);
    chmodSync(blobFile, 0o600);
    const bytes = readFileSync(blobFile);
    bytes[10] ^= 0xff;
    writeFileSync(blobFile, bytes);
    assert.throws(() => verifyBackup({ backupDir: corrupt, ledgerPath: system.ledgerPath }), refusedWith(/blob .* failed verification/));
    const refusedTarget = target();
    assert.throws(() => restoreBackup({ backupDir: corrupt, ledgerPath: system.ledgerPath, ...refusedTarget }), refusedWith(/failed verification/));
    assert.equal(existsSync(refusedTarget.databasePath), false, 'no database was written');
    assert.equal(existsSync(refusedTarget.blobRoot), false, 'no blob root was created');
    assert.deepEqual(readdirSync(dirname(refusedTarget.databasePath)), [], 'no staging file was left behind');

    const missing = copyBackup(outDir);
    unlinkSync(join(missing, 'blobs', 'tenants', system.tenant, 'sha256', system.envelope.doc.digest));
    assert.throws(() => verifyBackup({ backupDir: missing, ledgerPath: system.ledgerPath }), refusedWith(/required blob .* is missing/));

    const altered = copyBackup(outDir);
    writeFileSync(join(altered, 'opensig.db'), Buffer.concat([readFileSync(join(altered, 'opensig.db')), Buffer.from([0])]));
    assert.throws(() => verifyBackup({ backupDir: altered, ledgerPath: system.ledgerPath }), refusedWith(/does not match the manifest digest/));
    const noManifest = copyBackup(outDir);
    unlinkSync(join(noManifest, 'manifest.json'));
    assert.throws(() => verifyBackup({ backupDir: noManifest, ledgerPath: system.ledgerPath }), refusedWith(/manifest is missing/));

    const restoredTarget = target();
    const report = restoreBackup({ backupDir: outDir, ledgerPath: system.ledgerPath, ...restoredTarget });
    assert.deepEqual(report.tenants.map((tenant) => [tenant.tenant_id, tenant.events, tenant.blobs]), [[system.tenant, 4, 3]]);
    assert.equal(statSync(restoredTarget.databasePath).mode & 0o777, 0o600);
    const restored = openDatabase({ path: restoredTarget.databasePath });
    try {
      for (const [table, order] of [
        ['envelopes', 'id'],
        ['document_revisions', 'id'],
        ['final_artifacts', 'artifact_id'],
        ['audit_events', 'seq'],
        ['outbox_events', 'event_id'],
      ]) {
        assert.deepEqual(tableRows(restored, system.tenant, table, order), tableRows(system.db, system.tenant, table, order), `${table} restored`);
      }
      assert.equal(verifyChain(restored, system.tenant).ok, true);
    } finally {
      restored.close();
    }
    const { openBlobStore } = await import('../../src/storage/blobs/index.ts');
    const restoredBlobs = openBlobStore({ root: restoredTarget.blobRoot });
    for (const blob of [system.envelope.doc, system.envelope.pdf, system.envelope.evidence]) {
      assert.deepEqual(restoredBlobs.read(system.tenant, blob.digest), system.blobs.read(system.tenant, blob.digest));
    }
    assert.throws(() => restoreBackup({ backupDir: outDir, ledgerPath: system.ledgerPath, ...restoredTarget }), (error) => error instanceof StorageUsageError && /never overwrites/.test(error.message));
  } finally {
    system.db.close();
  }
});

test('[OR-04] restore verifies audit-chain continuity and refuses a chain head older than the last exported head', async () => {
  const system = liveSystem({ events: 5 });
  try {
    const first = await backupOf(system);
    assert.equal(readLedger(system.ledgerPath)[system.tenant].seq, 5);
    appendEvents(system, system.tenant, 3);
    const lateTenant = sid('tenant');
    createTenant(system.db, lateTenant);
    appendEvents(system, lateTenant, 2);
    const second = await backupOf(system);
    assert.equal(readLedger(system.ledgerPath)[system.tenant].seq, 8);
    assert.equal(readLedger(system.ledgerPath)[lateTenant].seq, 2);

    assert.throws(
      () => restoreBackup({ backupDir: first.outDir, ledgerPath: system.ledgerPath, ...target() }),
      (error) =>
        refusedWith(new RegExp(`tenant ${system.tenant}: audit chain head is older than the last exported head \\(seq 8\\)`))(error) &&
        refusedWith(new RegExp(`tenant ${lateTenant}: audit chain head is older than the last exported head`))(error),
    );
    assert.equal(verifyBackup({ backupDir: second.outDir, ledgerPath: system.ledgerPath }).tenants.length, 2);

    // A row edited inside the backup (manifest resealed) breaks continuity.
    const edited = copyBackup(second.outDir);
    const raw = new DatabaseSync(join(edited, 'opensig.db'));
    raw.exec('DROP TRIGGER audit_events_append_only_update');
    raw.prepare('UPDATE audit_events SET metadata_json = ? WHERE tenant_id = ? AND seq = 3').run('{"step":42}', system.tenant);
    raw.close();
    resealManifest(edited);
    assert.throws(() => verifyBackup({ backupDir: edited, ledgerPath: system.ledgerPath }), refusedWith(/audit chain digest-mismatch at seq 3/));

    // A rewritten head diverges from the exported head even when internally consistent.
    const forged = copyBackup(second.outDir);
    const forgedDb = new DatabaseSync(join(forged, 'opensig.db'));
    forgedDb.exec('DROP TRIGGER audit_events_append_only_update');
    const { eventDigest, eventFromRow } = await import('../../src/storage/audit/index.ts');
    const head = eventFromRow(forgedDb.prepare('SELECT * FROM audit_events WHERE tenant_id = ? AND seq = 8').get(system.tenant));
    const rewritten = { ...head, metadata: { step: 'rewritten' } };
    forgedDb
      .prepare('UPDATE audit_events SET metadata_json = ?, event_digest = ? WHERE tenant_id = ? AND seq = 8')
      .run(canonicalize(rewritten.metadata), eventDigest(rewritten), system.tenant);
    forgedDb.close();
    resealManifest(forged);
    const manifest = JSON.parse(readFileSync(join(forged, 'manifest.json'), 'utf8'));
    manifest.tenants = manifest.tenants.map((tenant) => (tenant.tenant_id === system.tenant ? { ...tenant, audit_head: { seq: 8, digest: eventDigest(rewritten) } } : tenant));
    writeFileSync(join(forged, 'manifest.json'), canonicalize(manifest));
    assert.throws(() => verifyBackup({ backupDir: forged, ledgerPath: system.ledgerPath }), refusedWith(/diverges from the last exported head at seq 8/));

    const restoredTarget = target();
    const report = restoreBackup({ backupDir: second.outDir, ledgerPath: system.ledgerPath, ...restoredTarget });
    assert.deepEqual(
      report.tenants.map((tenant) => [tenant.tenant_id, tenant.head.seq]).sort(),
      [
        [system.tenant, 8],
        [lateTenant, 2],
      ].sort(),
    );
  } finally {
    system.db.close();
  }
});

function cli(...args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 120_000 });
}

test('[OR-06] scripts/backup.mjs creates, verifies and restores, and exits 1 on refusal and 2 on usage errors', () => {
  const system = liveSystem();
  try {
    const outDir = join(scratch.dir(), 'cli-backup');
    const created = cli('create', '--db', system.path, '--blobs', system.blobRoot, '--out', outDir, '--ledger', system.ledgerPath);
    assert.equal(created.status, 0, created.stderr);
    assert.match(created.stdout, /^backup: PASS created tenants=1 blobs=3 schema=\d+\n$/);
    const verified = cli('verify', '--from', outDir, '--ledger', system.ledgerPath);
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stdout, /^backup: PASS verified tenants=1 events=4 blobs=3 schema=\d+\n$/);
    const restoredTarget = target();
    const restored = cli('restore', '--from', outDir, '--ledger', system.ledgerPath, '--db', restoredTarget.databasePath, '--blobs', restoredTarget.blobRoot);
    assert.equal(restored.status, 0, restored.stderr);
    assert.match(restored.stdout, /^backup: PASS restored tenants=1 events=4 blobs=3/);

    const corrupt = copyBackup(outDir);
    unlinkSync(join(corrupt, 'blobs', 'tenants', system.tenant, 'sha256', system.envelope.evidence.digest));
    const refused = cli('verify', '--from', corrupt, '--ledger', system.ledgerPath);
    assert.equal(refused.status, 1);
    assert.match(refused.stdout, /^backup: REFUSED 1 reason\(s\): tenant .* required blob .* is missing\n$/);

    for (const args of [
      [],
      ['explode'],
      ['verify', '--from', outDir],
      ['verify', '--from', outDir, '--ledger', system.ledgerPath, '--extra', 'x'],
      ['verify', '--from', 'relative/dir', '--ledger', system.ledgerPath],
      ['restore', '--from', outDir, '--ledger', system.ledgerPath, '--db', restoredTarget.databasePath, '--blobs', restoredTarget.blobRoot],
    ]) {
      const run = cli(...args);
      assert.equal(run.status, 2, `${args.join(' ')} -> ${run.stdout}${run.stderr}`);
      assert.match(run.stderr, /^backup: USAGE /);
    }
  } finally {
    system.db.close();
  }
});

test('[OR-07] a backup is a consistent private snapshot, and it refuses a damaged source or a used directory', async () => {
  const system = liveSystem();
  try {
    // Committed (but not checkpointed) data is in the snapshot; another
    // connection's uncommitted changes are not.
    const committed = sid('tenant');
    createTenant(system.db, committed);
    const uncommitted = sid('tenant');
    const row = tenantRow();
    const writer = new DatabaseSync(system.path, { timeout: 2_000 });
    let backup;
    writer.exec('BEGIN IMMEDIATE');
    try {
      writer
        .prepare('INSERT INTO tenants (tenant_id, oidc_issuer, oidc_audience, role_claim, role_map_json, principal_kind_claim, allowed_roles_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .run(uncommitted, row.oidc_issuer, row.oidc_audience, row.role_claim, row.role_map_json, row.principal_kind_claim, row.allowed_roles_json, row.created_at, row.updated_at);
      writer.prepare('UPDATE tenants SET oidc_audience = ? WHERE tenant_id = ?').run('uncommitted-change', committed);
      backup = await backupOf(system);
    } finally {
      writer.exec('ROLLBACK');
      writer.close();
    }
    const ids = backup.manifest.tenants.map((tenant) => tenant.tenant_id);
    assert.ok(ids.includes(committed), 'committed tenant included');
    assert.ok(!ids.includes(uncommitted), 'uncommitted tenant excluded');
    const staged = target();
    restoreBackup({ backupDir: backup.outDir, ledgerPath: system.ledgerPath, ...staged });
    const restored = openDatabase({ path: staged.databasePath });
    try {
      assert.equal(restored.forTenant(committed).get('tenants', {}).oidc_audience, 'opensig-api', 'uncommitted changes are not in the snapshot');
    } finally {
      restored.close();
    }

    assert.deepEqual(readdirSync(backup.outDir).sort(), ['blobs', 'manifest.json', 'opensig.db']);
    assert.equal(statSync(backup.outDir).mode & 0o777, 0o700);
    for (const file of ['opensig.db', 'manifest.json']) assert.equal(statSync(join(backup.outDir, file)).mode & 0o777, 0o600);
    const manifestText = readFileSync(join(backup.outDir, 'manifest.json'), 'utf8');
    const manifest = JSON.parse(manifestText);
    assert.equal(manifestText, canonicalize(manifest), 'the manifest is canonical JSON');
    assert.equal(manifest.schema, 'opensig.backup/1');
    assert.equal(manifest.database.sha256, createHash('sha256').update(readFileSync(join(backup.outDir, 'opensig.db'))).digest('hex'));

    const used = scratch.dir();
    writeFileSync(join(used, 'keep.txt'), 'existing');
    await assert.rejects(createBackup({ databasePath: system.path, blobRoot: system.blobRoot, outDir: used, ledgerPath: system.ledgerPath, clock }), /must be empty/);
    assert.deepEqual(readdirSync(used), ['keep.txt']);

    const blobFile = join(system.blobRoot, 'tenants', system.tenant, 'sha256', system.envelope.doc.digest);
    chmodSync(blobFile, 0o600);
    const original = readFileSync(blobFile);
    writeFileSync(blobFile, Buffer.concat([original.subarray(0, 100), Buffer.from('x'), original.subarray(101)]));
    const failedDir = join(scratch.dir(), 'failed-backup');
    await assert.rejects(createBackup({ databasePath: system.path, blobRoot: system.blobRoot, outDir: failedDir, ledgerPath: system.ledgerPath, clock }), /failed verification/);
    assert.equal(existsSync(failedDir), false, 'a failed backup leaves no directory');
    writeFileSync(blobFile, original);

    const raw = new DatabaseSync(system.path, { timeout: 2_000 });
    raw.exec('DROP TRIGGER audit_events_append_only_update');
    raw.prepare('UPDATE audit_events SET actor_ref = ? WHERE tenant_id = ? AND seq = 2').run('someone-else', system.tenant);
    raw.close();
    await assert.rejects(backupOf(system), (error) => error instanceof BackupError && /audit chain does not verify/.test(error.message));
  } finally {
    system.db.close();
  }
});

test('[OR-08] the exported-head ledger lives outside the database, only moves forward, and fails closed when damaged', async () => {
  const dir = scratch.dir();
  const ledger = join(dir, 'exported-heads.json');
  const tenant = sid('tenant');
  const fixed = () => new Date(BASE_TIME);
  assert.deepEqual(readLedger(ledger), {});
  const first = recordExportedHead(ledger, tenant, { seq: 5, digest: hex('five') }, { clock: fixed, source: 'backup' });
  assert.deepEqual(first, { seq: 5, digest: hex('five'), exported_at: new Date(BASE_TIME).toISOString(), source: 'backup' });
  assert.equal(statSync(ledger).mode & 0o777, 0o600);
  const text = readFileSync(ledger, 'utf8');
  assert.equal(text, canonicalize(JSON.parse(text)));
  assert.deepEqual(recordExportedHead(ledger, tenant, { seq: 3, digest: hex('three') }, { clock: fixed, source: 'receipt' }), first, 'a head never moves back');
  assert.equal(readFileSync(ledger, 'utf8'), text);
  assert.throws(() => recordExportedHead(ledger, tenant, { seq: 5, digest: hex('other') }, { clock: fixed, source: 'backup' }), LedgerError);
  assert.equal(recordExportedHead(ledger, tenant, { seq: 9, digest: hex('nine') }, { clock: fixed, source: 'receipt' }).seq, 9);
  assert.deepEqual(readdirSync(dir), ['exported-heads.json'], 'atomic replacement leaves no temp files');

  for (const bad of [
    'not json',
    '{"schema":"other","tenants":{}}',
    `{"schema":"opensig.exported-heads/1","tenants":{"${tenant}":{"seq":0,"digest":"${hex('x')}","exported_at":"2026-11-08T10:00:00.000Z","source":"backup"}}}`,
    `{"schema":"opensig.exported-heads/1","tenants":{"${tenant}":{"seq":1,"digest":"XYZ","exported_at":"2026-11-08T10:00:00.000Z","source":"backup"}}}`,
    `{"schema":"opensig.exported-heads/1","tenants":{"${tenant}":{"seq":1,"digest":"${hex('x')}","exported_at":"2026-11-08T10:00:00.000Z","source":"backup","extra":1}}}`,
    '{"schema":"opensig.exported-heads/1","tenants":{},"extra":1}',
  ]) {
    writeFileSync(ledger, bad);
    assert.throws(() => readLedger(ledger), LedgerError, bad.slice(0, 60));
  }
  assert.throws(() => recordExportedHead(ledger, 'short', { seq: 1, digest: hex('x') }, { clock: fixed, source: 'backup' }), StorageUsageError);
  assert.throws(() => recordExportedHead(join(dir, 'other.json'), tenant, { seq: 1, digest: hex('x') }, { clock: fixed, source: 'Bad Source' }), StorageUsageError);
  assert.throws(() => readLedger('relative/ledger.json'), StorageUsageError);

  // A restore with a damaged ledger fails closed instead of skipping the head check.
  const system = liveSystem();
  try {
    const { outDir } = await backupOf(system);
    writeFileSync(system.ledgerPath, 'damaged');
    assert.throws(() => verifyBackup({ backupDir: outDir, ledgerPath: system.ledgerPath }), LedgerError);
    rmSync(system.ledgerPath);
    assert.equal(verifyBackup({ backupDir: outDir, ledgerPath: system.ledgerPath }).tenants.length, 1, 'a missing ledger means nothing was exported yet');
  } finally {
    system.db.close();
  }
});
