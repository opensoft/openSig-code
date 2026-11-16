// SPDX-License-Identifier: Apache-2.0
//
// Backup and restore (T030): OR-03 restore verifies blob digests (and the
// database file) and writes nothing when refused; OR-04 restore verifies
// audit-chain continuity and refuses a chain head older than the last
// exported head; OR-06 the scripts/backup.mjs command line; OR-07 snapshot
// consistency, layout and backup refusals; OR-08 the exported-head ledger;
// OR-09 backup checks the exported head; OR-10 the ledger requires ancestry
// and restore refuses forked state; OR-11 a missing ledger fails closed;
// OR-12 shared-reference disposals in the required-blob set; OR-13 the
// required-blob rows are read past 10,000.

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
  requiredBlobRefs,
  LedgerError,
  readLedger,
  recordExportedHead,
  restoreBackup,
  RestoreRefusedError,
  verifyBackup,
} from '../../src/storage/backup/index.ts';
import { MAX_LIST_LIMIT, openDatabase, StorageUsageError } from '../../src/storage/db/index.ts';
import { enqueueOutboxEvent } from '../../src/storage/outbox/index.ts';
import { RetentionService } from '../../src/storage/retention/index.ts';
import { makeScratch, tenantRow } from '../storage/support/fixtures.mjs';
import {
  BASE_TIME,
  createTenant,
  envelopeRow,
  environment,
  fixedClock,
  hex,
  rawConnection,
  sid,
  steppingClock,
  syntheticBytes,
  terminalEnvelope,
  ts,
} from '../audit-chain/support/chain.mjs';

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

/**
 * Back up a test system. Its first backup creates the ledger (the explicit
 * firstBackup option); every later backup requires the ledger. OR-11 tests a
 * missing ledger.
 */
function backupOf(system, { ledgerPath = system.ledgerPath, firstBackup = !existsSync(ledgerPath) } = {}) {
  const outDir = join(scratch.dir(), 'backup');
  return createBackup({ databasePath: system.path, blobRoot: system.blobRoot, outDir, ledgerPath, clock, firstBackup }).then((manifest) => ({ outDir, manifest }));
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
    const created = cli('create', '--db', system.path, '--blobs', system.blobRoot, '--out', outDir, '--ledger', system.ledgerPath, '--first-backup');
    assert.equal(created.status, 0, created.stderr);
    assert.match(created.stdout, /^backup: published directory=\S+ tenants=1 blobs=3 schema=\d+\n$/);
    const verified = cli('verify', '--from', outDir, '--ledger', system.ledgerPath);
    assert.equal(verified.status, 0, verified.stderr);
    assert.match(verified.stdout, /^backup: verified tenants=1 events=4 blobs=3 schema=\d+\n$/);
    const restoredTarget = target();
    const restored = cli('restore', '--from', outDir, '--ledger', system.ledgerPath, '--db', restoredTarget.databasePath, '--blobs', restoredTarget.blobRoot);
    assert.equal(restored.status, 0, restored.stderr);
    assert.match(restored.stdout, /^backup: restored tenants=1 events=4 blobs=3/);

    const corrupt = copyBackup(outDir);
    unlinkSync(join(corrupt, 'blobs', 'tenants', system.tenant, 'sha256', system.envelope.evidence.digest));
    const refused = cli('verify', '--from', corrupt, '--ledger', system.ledgerPath);
    assert.equal(refused.status, 1);
    assert.match(refused.stdout, /^backup: refused 1 reason\(s\): tenant .* required blob .* is missing\n$/);

    for (const args of [
      [],
      ['explode'],
      ['verify', '--from', outDir],
      ['verify', '--from', outDir, '--ledger', system.ledgerPath, '--extra', 'x'],
      ['verify', '--from', outDir, '--ledger', system.ledgerPath, '--first-backup'],
      ['verify', '--from', outDir, '--ledger', system.ledgerPath, '--first-restore', '--first-restore'],
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
  // One synthetic chain: the event digests at seq 3, 5 and 9.
  const chain = new Map([
    [3, hex('three')],
    [5, hex('five')],
    [9, hex('nine')],
  ]);
  const digestAt = (seq) => chain.get(seq);
  assert.throws(() => readLedger(ledger), (error) => error instanceof LedgerError && /ledger is missing/.test(error.message), 'a missing ledger fails closed');
  assert.deepEqual(readLedger(ledger, { allowMissing: true }), {}, 'only the explicit first-run option reads it as empty');
  assert.throws(() => recordExportedHead(ledger, tenant, { seq: 5, digest: hex('five') }, { clock: fixed, source: 'backup', digestAt }), LedgerError, 'recording needs the ledger');
  assert.equal(existsSync(ledger), false);
  const first = recordExportedHead(ledger, tenant, { seq: 5, digest: hex('five') }, { clock: fixed, source: 'backup', digestAt, createIfMissing: true });
  assert.deepEqual(first, { seq: 5, digest: hex('five'), exported_at: new Date(BASE_TIME).toISOString(), source: 'backup' });
  assert.equal(statSync(ledger).mode & 0o777, 0o600);
  const text = readFileSync(ledger, 'utf8');
  assert.equal(text, canonicalize(JSON.parse(text)));
  assert.deepEqual(recordExportedHead(ledger, tenant, { seq: 3, digest: hex('three') }, { clock: fixed, source: 'receipt', digestAt }), first, 'a head never moves back');
  assert.equal(readFileSync(ledger, 'utf8'), text);
  const forked = (seq) => (seq === 5 ? hex('other') : chain.get(seq));
  assert.throws(() => recordExportedHead(ledger, tenant, { seq: 5, digest: hex('other') }, { clock: fixed, source: 'backup', digestAt: forked }), LedgerError);
  assert.equal(readFileSync(ledger, 'utf8'), text);
  assert.equal(recordExportedHead(ledger, tenant, { seq: 9, digest: hex('nine') }, { clock: fixed, source: 'receipt', digestAt }).seq, 9);
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
  assert.throws(() => recordExportedHead(ledger, 'short', { seq: 1, digest: hex('x') }, { clock: fixed, source: 'backup', digestAt }), StorageUsageError);
  assert.throws(() => recordExportedHead(join(dir, 'other.json'), tenant, { seq: 1, digest: hex('x') }, { clock: fixed, source: 'Bad Source', digestAt }), StorageUsageError);
  assert.throws(() => readLedger('relative/ledger.json'), StorageUsageError);

  // A restore with a damaged or missing ledger fails closed instead of
  // skipping the head check; only the explicit first-restore option proceeds
  // without a ledger (OR-11 covers backup, restore and the CLI).
  const system = liveSystem();
  try {
    const { outDir } = await backupOf(system);
    writeFileSync(system.ledgerPath, 'damaged');
    assert.throws(() => verifyBackup({ backupDir: outDir, ledgerPath: system.ledgerPath }), LedgerError);
    assert.throws(() => verifyBackup({ backupDir: outDir, ledgerPath: system.ledgerPath, firstRestore: true }), LedgerError, 'a damaged ledger is never treated as absent');
    rmSync(system.ledgerPath);
    assert.throws(() => verifyBackup({ backupDir: outDir, ledgerPath: system.ledgerPath }), (error) => error instanceof LedgerError && /ledger is missing/.test(error.message));
    assert.equal(verifyBackup({ backupDir: outDir, ledgerPath: system.ledgerPath, firstRestore: true }).tenants.length, 1, 'the explicit first restore proceeds');
  } finally {
    system.db.close();
  }
});

/**
 * Roll the tenant's chain back to `keep` events (as an attacker with file
 * access would, dropping the append-only trigger) and, when `forged` > 0,
 * write a forked continuation through the normal writer.
 */
function rollBack(system, tenant, keep, forged = 0) {
  const raw = rawConnection(system.path);
  try {
    raw.exec('DROP TRIGGER IF EXISTS audit_events_append_only_delete');
    raw.prepare('DELETE FROM audit_events WHERE tenant_id = ? AND seq > ?').run(tenant, keep);
  } finally {
    raw.close();
  }
  system.db.transaction(() => {
    for (let i = 0; i < forged; i += 1) system.audit.append(tenant, { type: 'envelope.updated', actor: { kind: 'system', ref: 'forger' }, metadata: { forged: i } });
  });
}

const ledgerBytes = (system) => readFileSync(system.ledgerPath);

test('[OR-09] backup checks each chain against the exported head: rolled-back or rewritten state is refused and the ledger does not move', async () => {
  // The reviewer's P02 scenario: ledger at seq 5, database rolled back to
  // seq 2 and rewritten to a forked seq 8.
  const system = liveSystem({ events: 5 });
  try {
    await backupOf(system);
    const exported = readLedger(system.ledgerPath)[system.tenant];
    assert.equal(exported.seq, 5);
    const before = ledgerBytes(system);
    rollBack(system, system.tenant, 2, 6);
    const fork = verifyChain(system.db, system.tenant);
    assert.deepEqual([fork.ok, fork.head.seq], [true, 8], 'the forked chain is internally consistent');
    assert.equal(verifyChain(system.db, system.tenant, { expectedHead: exported }).problems[0].kind, 'head-mismatch');

    const forkedDir = join(scratch.dir(), 'forked-backup');
    await assert.rejects(
      createBackup({ databasePath: system.path, blobRoot: system.blobRoot, outDir: forkedDir, ledgerPath: system.ledgerPath, clock }),
      (error) => error instanceof BackupError && /audit chain does not verify \(head-mismatch\); it diverges from the last exported head at seq 5/.test(error.message),
    );
    assert.equal(existsSync(forkedDir), false, 'a refused backup leaves no directory');
    assert.deepEqual(ledgerBytes(system), before, 'the ledger did not move to the fork');
    assert.equal(readLedger(system.ledgerPath)[system.tenant].seq, 5);
    await assert.rejects(backupOf(system, { firstBackup: true }), BackupError, 'the first-backup option does not bypass an existing ledger');
    assert.deepEqual(ledgerBytes(system), before);
  } finally {
    system.db.close();
  }

  // Rolled back without a rewrite: the chain ends before the exported head.
  const cut = liveSystem({ events: 5 });
  try {
    await backupOf(cut);
    const before = ledgerBytes(cut);
    rollBack(cut, cut.tenant, 3);
    await assert.rejects(backupOf(cut), (error) => error instanceof BackupError && /its head is older than the last exported head \(seq 5\)/.test(error.message));
    assert.deepEqual(ledgerBytes(cut), before);

    // A tenant whose head was exported but has no chain in the database.
    const vanished = sid('tenant');
    const chain = new Map([[4, hex('vanished-4')]]);
    recordExportedHead(cut.ledgerPath, vanished, { seq: 4, digest: hex('vanished-4') }, { clock, source: 'backup', digestAt: (seq) => chain.get(seq) });
    const withVanished = ledgerBytes(cut);
    rollBack(cut, cut.tenant, 3, 2);
    await assert.rejects(backupOf(cut), (error) => error instanceof BackupError && new RegExp(`tenant ${vanished}: the ledger has an exported head \\(seq 4\\) but the database has no such tenant`).test(error.message));
    assert.deepEqual(ledgerBytes(cut), withVanished);
  } finally {
    cut.db.close();
  }
});

test('[OR-10] the ledger moves only along one chain, and restore refuses forked state even from a backup made with a fresh ledger', async () => {
  const system = liveSystem({ events: 5 });
  try {
    const original = await backupOf(system);
    const exported = readLedger(system.ledgerPath)[system.tenant];
    const before = ledgerBytes(system);
    const store = system.db.forTenant(system.tenant);
    const digestAt = (seq) => store.get('audit_events', { seq })?.event_digest;

    // Ancestry: a descendant of the recorded head moves the ledger forward.
    appendEvents(system, system.tenant, 2);
    const head = verifyChain(system.db, system.tenant).head;
    assert.deepEqual(recordExportedHead(system.ledgerPath, system.tenant, head, { clock, source: 'receipt', digestAt }).seq, 7);
    const advanced = ledgerBytes(system);
    assert.notDeepEqual(advanced, before);

    // Fork the chain below the recorded head: nothing that comes from the fork
    // can be recorded, however far it reaches.
    rollBack(system, system.tenant, 4, 6);
    const forkHead = verifyChain(system.db, system.tenant).head;
    assert.equal(forkHead.seq, 10);
    assert.throws(
      () => recordExportedHead(system.ledgerPath, system.tenant, forkHead, { clock, source: 'backup', digestAt }),
      (error) => error instanceof LedgerError && /does not contain the last exported head \(seq 7\)/.test(error.message),
    );
    assert.throws(() => recordExportedHead(system.ledgerPath, system.tenant, { seq: 10, digest: hex('not-in-chain') }, { clock, source: 'backup', digestAt }), LedgerError);
    assert.throws(() => recordExportedHead(system.ledgerPath, system.tenant, forkHead, { clock, source: 'backup' }), StorageUsageError, 'digestAt is required');
    assert.deepEqual(ledgerBytes(system), advanced, 'refused records leave the ledger unchanged');

    // A backup of the forked state made against a fresh, separate ledger
    // succeeds there (that ledger knows nothing), but the real ledger refuses
    // to restore it, through the API and the command line.
    const freshLedger = join(scratch.dir(), 'fresh-heads.json');
    const forked = await backupOf(system, { ledgerPath: freshLedger, firstBackup: true });
    assert.equal(forked.manifest.tenants[0].audit_head.seq, 10);
    const refusedTarget = target();
    assert.throws(
      () => restoreBackup({ backupDir: forked.outDir, ledgerPath: system.ledgerPath, ...refusedTarget }),
      refusedWith(new RegExp(`tenant ${system.tenant}: audit chain diverges from the last exported head at seq 7`)),
    );
    assert.equal(existsSync(refusedTarget.databasePath), false, 'nothing restored');
    const cliRefused = cli('verify', '--from', forked.outDir, '--ledger', system.ledgerPath);
    assert.equal(cliRefused.status, 1);
    assert.match(cliRefused.stdout, /^backup: refused .*diverges from the last exported head at seq 7/);
    assert.deepEqual(ledgerBytes(system), advanced);

    // The backup taken before the fork is older than the advanced head.
    assert.throws(() => verifyBackup({ backupDir: original.outDir, ledgerPath: system.ledgerPath }), refusedWith(/older than the last exported head \(seq 7\)/));
    assert.equal(exported.seq, 5);
  } finally {
    system.db.close();
  }
});

test('[OR-11] a missing ledger fails closed: backup, verify and restore need the explicit first-backup or first-restore option', async () => {
  const system = liveSystem({ events: 3 });
  try {
    // No ledger and no option: the backup is refused before anything is written.
    const refusedDir = join(scratch.dir(), 'no-ledger-backup');
    await assert.rejects(
      createBackup({ databasePath: system.path, blobRoot: system.blobRoot, outDir: refusedDir, ledgerPath: system.ledgerPath, clock }),
      (error) => error instanceof LedgerError && /ledger is missing/.test(error.message),
    );
    assert.equal(existsSync(refusedDir), false);
    assert.equal(existsSync(system.ledgerPath), false, 'no ledger was created');

    // The explicit first backup creates the ledger.
    const older = await backupOf(system, { firstBackup: true });
    assert.equal(readLedger(system.ledgerPath)[system.tenant].seq, 3);
    appendEvents(system, system.tenant, 2);
    await backupOf(system, { firstBackup: false });
    assert.equal(readLedger(system.ledgerPath)[system.tenant].seq, 5);
    assert.throws(() => verifyBackup({ backupDir: older.outDir, ledgerPath: system.ledgerPath }), refusedWith(/older than the last exported head \(seq 5\)/));

    // Deleting the ledger does not make the rolled-back backup acceptable.
    rmSync(system.ledgerPath);
    const missing = (error) => error instanceof LedgerError && /ledger is missing/.test(error.message);
    assert.throws(() => verifyBackup({ backupDir: older.outDir, ledgerPath: system.ledgerPath }), missing);
    const refusedTarget = target();
    assert.throws(() => restoreBackup({ backupDir: older.outDir, ledgerPath: system.ledgerPath, ...refusedTarget }), missing);
    assert.equal(existsSync(refusedTarget.databasePath), false);
    assert.equal(existsSync(refusedTarget.blobRoot), false);
    const cliRefused = cli('verify', '--from', older.outDir, '--ledger', system.ledgerPath);
    assert.equal(cliRefused.status, 1);
    assert.match(cliRefused.stdout, /^backup: refused ledger_invalid: the exported-head ledger is missing/);
    // Nor can a backup recreate the ledger without the explicit option.
    await assert.rejects(backupOf(system, { firstBackup: false }), missing);
    assert.equal(existsSync(system.ledgerPath), false);

    // Only the explicit first restore proceeds without a ledger.
    assert.equal(verifyBackup({ backupDir: older.outDir, ledgerPath: system.ledgerPath, firstRestore: true }).tenants[0].head.seq, 3);
    const cliFirst = cli('verify', '--from', older.outDir, '--ledger', system.ledgerPath, '--first-restore');
    assert.equal(cliFirst.status, 0, cliFirst.stderr);
    assert.match(cliFirst.stdout, /^backup: verified tenants=1 events=3 /);
    const restoredTarget = target();
    const restored = cli('restore', '--from', older.outDir, '--ledger', system.ledgerPath, '--db', restoredTarget.databasePath, '--blobs', restoredTarget.blobRoot, '--first-restore');
    assert.equal(restored.status, 0, restored.stderr);
    assert.equal(existsSync(restoredTarget.databasePath), true);
    assert.equal(readLedger(system.ledgerPath)[system.tenant].seq, 3, 'the first restore wrote the restored heads (A-009 D3, OR-24)');
  } finally {
    system.db.close();
  }
});

/** A system with a retention policy, for the required-blob cases. */
function retentionSystem(policy) {
  const env = environment(scratch, steppingClock());
  const tenant = sid('tenant');
  createTenant(env.db, tenant);
  env.db.transaction(() => env.db.forTenant(tenant).update('tenants', {}, { retention_json: JSON.stringify(policy) }));
  return { ...env, tenant, blobRoot: join(env.dir, 'blobs'), ledgerPath: join(env.dir, 'exported-heads.json') };
}

test('[OR-12] the required-blob set follows shared-reference disposals: a blob removed by a later disposal is not demanded, a retained artifact is', async () => {
  const DAY = 86_400_000;
  const system = retentionSystem({ policy_ref: 'synthetic-retention', dispose_after_days: 30 });
  try {
    const { db, blobs, audit, tenant } = system;
    // Two envelopes share one document; the second becomes eligible later.
    const early = terminalEnvelope(db, blobs, tenant, { state: 'declined', updatedMinutes: 10, documentSeed: 'shared-document' });
    const late = terminalEnvelope(db, blobs, tenant, { state: 'declined', updatedMinutes: 40 * 24 * 60, documentSeed: 'shared-document' });
    assert.equal(early.doc.ref, late.doc.ref);
    const completed = terminalEnvelope(db, blobs, tenant, { state: 'completed', updatedMinutes: 10 });

    const first = new RetentionService({ db, blobs, audit, clock: fixedClock(new Date(BASE_TIME + 31 * DAY).toISOString()) }).run(tenant);
    assert.deepEqual(first.disposals.map((disposal) => disposal.envelopeId).sort(), [early.env, completed.env].sort());
    assert.deepEqual(first.keptSharedBlobRefs, [early.doc.ref], 'kept while the later envelope still uses it');
    const second = new RetentionService({ db, blobs, audit, clock: fixedClock(new Date(BASE_TIME + 80 * DAY).toISOString()) }).run(tenant);
    assert.deepEqual(second.disposals.map((disposal) => [disposal.envelopeId, disposal.disposedBlobRefs]), [[late.env, [late.doc.ref]]]);
    assert.equal(blobs.check(tenant, early.doc.digest), 'missing', 'the shared blob is gone');
    // The earlier envelope's DisposalRecord does not list the shared ref (it
    // was kept then), yet no row that still needs it remains.
    const earlyRecord = db.forTenant(tenant).get('disposal_records', { envelope_id: early.env });
    assert.deepEqual(JSON.parse(earlyRecord.disposed_blob_refs_json), []);

    const required = requiredBlobRefs(db, tenant);
    assert.equal(required.has(early.doc.ref), false, 'a blob given up by every referencing envelope is not required');
    assert.ok(required.has(completed.pdf.ref) && required.has(completed.evidence.ref), 'scope documents keeps the final artifacts required');
    assert.equal(required.has(completed.doc.ref), false);

    const { outDir } = await backupOf(system);
    const restoredTarget = target();
    assert.equal(restoreBackup({ backupDir: outDir, ledgerPath: system.ledgerPath, ...restoredTarget }).tenants[0].tenant_id, tenant);

    // A retained artifact blob that goes missing is still caught.
    unlinkSync(join(system.blobRoot, 'tenants', tenant, 'sha256', completed.pdf.digest));
    await assert.rejects(backupOf(system), (error) => error instanceof BackupError && error.message.includes(completed.pdf.ref));
  } finally {
    system.db.close();
  }
});

test('[OR-13] the required-blob rows are read past 10,000, so a missing blob referenced after them is still caught', async () => {
  const system = retentionSystem({ policy_ref: 'synthetic-retention', dispose_after_days: 30 });
  try {
    const { db, blobs, tenant } = system;
    const present = blobs.put(tenant, syntheticBytes('present-document', 256));
    const absentDigest = createHash('sha256').update('never-stored-document').digest('hex');
    const absentRef = `tenants/${tenant}/sha256/${absentDigest}`;
    const store = db.forTenant(tenant);
    const envelope = sid('env');
    // Ids ascend, so the absent blob's row is the last one in insertion,
    // primary-key and envelope-index order alike: past any 10,000-row cap.
    const revision = (id, digest, ref) => ({
      id,
      envelope_id: envelope,
      content_digest: digest,
      blob_ref: ref,
      bytes: 256,
      pages: 1,
      page_geometry_json: '[]',
      parse_report_json: '{}',
      created_at: ts(2),
    });
    db.transaction(() => {
      store.insert('envelopes', envelopeRow(envelope));
      for (let i = 0; i < MAX_LIST_LIMIT; i += 1) store.insert('document_revisions', revision(`rev_${String(i).padStart(12, '0')}`, present.digest, present.ref));
      store.insert('document_revisions', revision('rev_zzzzzzzzzzzz', absentDigest, absentRef));
    });
    assert.equal(store.count('document_revisions'), MAX_LIST_LIMIT + 1);
    const required = requiredBlobRefs(db, tenant);
    assert.deepEqual([...required].sort(), [absentRef, present.ref].sort(), 'the row after the first 10,000 is read');

    const outDir = join(scratch.dir(), 'many-rows-backup');
    await assert.rejects(
      createBackup({ databasePath: system.path, blobRoot: system.blobRoot, outDir, ledgerPath: system.ledgerPath, clock, firstBackup: true }),
      (error) => error instanceof BackupError && error.message.includes(`a blob required by the database is missing (${absentRef})`),
    );
    assert.equal(existsSync(outDir), false);
    assert.equal(existsSync(system.ledgerPath), false, 'a refused first backup creates no ledger');
  } finally {
    system.db.close();
  }
});
