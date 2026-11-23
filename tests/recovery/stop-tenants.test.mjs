// SPDX-License-Identifier: Apache-2.0
//
// CONTINGENT (row RUNNER-STOP; the T038 slot recheck's surviving mutant S7: after stop(), runOnce
// must not reclaim or claim on a LATER tenant). Included only if the orchestrator relays that
// ruling; the case ID REC-03 is PROPOSED, an extra ID like REC-01 and REC-02, never required.
// Tests only: this file and support/stop-child.mjs.
//
// Two tenants, T1 and T2 = T1 + '-z'. listTenantIds orders by tenant_id, so T2 comes after T1:
// - T1: envelope A (createCaseWorld's sealable seed) and envelope A2 (seedFinalizing, its job
//   updated one second later, so listClaimableJobs lists it after A);
// - T2: envelope B1, leased by a crashed holder whose lease expired before the pass's instant,
//   and envelope B2 (both seedFinalizing).
// The extra envelopes use seedFinalizing because seedSealable stores a consent text 'v1'/'en' per
// call, which consent_texts' UNIQUE (tenant_id, version, locale) refuses a second time, and a
// second document blob in T1 would be untracked by A's I6.
// One runner pass in its own OS process (support/stop-child.mjs) claims A, and the stop() it
// calls while A's composition is awaited aborts that attempt (finalize.ts:417-423, lease.ts
// :113-115 at 00b260f). Then:
// - A ends 'lost' and writes nothing after the abort (:257 refuses, :210): its anchor (:246,
//   written before the stop) and its lease stay, with no attempt record, artifact, report,
//   checkpoint or failure, to be reclaimed at the lease expiry as after a crash;
// - A2 is listed but not claimed (runAttempt after stop(), :179);
// - T2 is neither reclaimed nor claimed (:360): every T2 row and blob is unchanged.
// Mutant S7 (the :360 break removed) reclaims B1: killed by `reclaimed` and the T2 comparison.
// Dropping :179 lets A2 be claimed: killed by the attempts list and A2's job row.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { grantLease } from '../../src/storage/repositories/jobs.ts';
import { BASE_TIME, seedFinalizing } from '../completion/support/world.mjs';
import { createTenant } from '../storage/support/fixtures.mjs';
import { checkInvariants, readCase, summary } from './support/invariants.mjs';
import { CASE_BUSY_TIMEOUT_MS, CASE_START_MS, LEASE_MS, REPO, SNAPSHOT_TABLES, assertPinnedNode, createCaseWorld, describeJob } from './support/world.mjs';

const STOP_CHILD = fileURLToPath(new URL('./support/stop-child.mjs', import.meta.url));
const CHILD_LIMIT_MS = 60_000;
const REPLACER = (_key, value) => (value instanceof Uint8Array ? `bytes:${Buffer.from(value).toString('hex')}` : typeof value === 'bigint' ? String(value) : value);

/** Every row of one tenant in every table a case can touch, and its stored blobs, as one comparable map. */
function tenantState(world, tenantId) {
  const out = {};
  for (const table of SNAPSHOT_TABLES) out[table] = JSON.stringify(world.rows(table, 'WHERE tenant_id = ?', [tenantId]), REPLACER);
  out['blob store'] = world.blobs.list(tenantId).join(',');
  return out;
}

/** seedFinalizing on `tenantId` with its clock fixed at `atMs`. */
function seedAt(world, tenantId, atMs) {
  const iso = new Date(atMs).toISOString();
  return seedFinalizing({ db: world.db, store: world.db.forTenant(tenantId), blobs: world.blobs, tenantId, clock: { iso: () => iso, now: () => new Date(atMs) } });
}

function jobOf(world, tenantId, envelopeId) {
  const [row] = world.rows('signing_jobs', 'WHERE tenant_id = ? AND envelope_id = ?', [tenantId, envelopeId]);
  assert.ok(row, `the job of envelope ${envelopeId} exists`);
  return row;
}

test('[REC-03] after stop() inside an attempt, the pass writes nothing more, claims nothing more on its tenant and neither reclaims nor claims on a later tenant', { timeout: 120_000 }, async () => {
  assertPinnedNode();
  const world = createCaseWorld();
  let child = null;
  try {
    const t1 = world.ctx.tenantId;
    const a2 = seedAt(world, t1, BASE_TIME + 1_000).envelopeId;
    const t2 = `${t1}-z`;
    createTenant(world.db, t2);
    const b1 = seedAt(world, t2, BASE_TIME).envelopeId;
    const b2 = seedAt(world, t2, BASE_TIME + 1_000).envelopeId;
    const crashed = world.db.transaction(() => grantLease(world.db.forTenant(t2), b1, { owner: 'recovery-crashed', now: new Date(BASE_TIME + 30_000), leaseMs: LEASE_MS }));
    const clockMs = CASE_START_MS + LEASE_MS;
    assert.ok(crashed !== null && Date.parse(crashed.leaseExpiresAt) <= clockMs, `premise: B1 ${b1}'s crashed lease (${crashed?.leaseExpiresAt}) has expired by the pass's instant ${new Date(clockMs).toISOString()}`);
    assert.deepEqual(world.db.listTenantIds(), [t1, t2], `premise: T2 ${t2} is listed after T1 ${t1}`);
    const t2Before = tenantState(world, t2);

    const jobPath = join(world.jobsDir, 'stop-1.json');
    writeFileSync(jobPath, JSON.stringify({ dbPath: world.path, blobRoot: world.blobRoot, sealKeyFile: world.sealKeyFile, owner: 'recovery-stop-1', leaseMs: LEASE_MS, busyTimeoutMs: CASE_BUSY_TIMEOUT_MS, clockMs }), { mode: 0o600 });
    child = spawn(process.execPath, [STOP_CHILD, jobPath], { cwd: REPO, env: { PATH: process.env.PATH ?? '' }, stdio: ['ignore', 'pipe', 'pipe'], detached: false });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk.toString('utf8')));
    child.stderr.on('data', (chunk) => (stderr = (stderr + chunk.toString('utf8')).slice(-2000)));
    const closed = new Promise((resolveClose) => child.on('close', (code, signal) => resolveClose({ code, signal })));
    let guard;
    const exit = await Promise.race([closed, new Promise((resolveLate) => (guard = setTimeout(() => resolveLate({ code: null, signal: 'hang-guard' }), CHILD_LIMIT_MS)))]);
    clearTimeout(guard);
    assert.deepEqual([exit.code, exit.signal], [0, null], `the stop child exits 0 by itself within ${CHILD_LIMIT_MS} ms (stdout ${stdout.trim()}; stderr ${stderr.trim().slice(-300)})`);
    const lines = stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.deepEqual(lines.map((line) => line.event), ['outcome'], `one outcome line (stdout ${stdout.trim()})`);
    const [outcome] = lines;

    const label = (tenant) => (tenant === t1 ? 'T1' : tenant === t2 ? 'T2' : `other ${tenant}`);
    assert.deepEqual(
      { reclaimed: outcome.reclaimed, attempts: outcome.attempts.map((entry) => `${label(entry.tenant)}:${entry.outcome}`), stopCalls: outcome.stopCalls },
      { reclaimed: 0, attempts: ['T1:lost', 'T1:not-claimed'], stopCalls: 1 },
      `after stop(): A lost, A2 not claimed, nothing reclaimed or claimed on T2 (child reported ${JSON.stringify(outcome)})`,
    );
    const t2After = tenantState(world, t2);
    for (const key of Object.keys(t2Before)) assert.equal(t2After[key], t2Before[key], `T2 ${t2} ${key} unchanged: B1 ${b1} (${describeJob(jobOf(world, t2, b1))}) and B2 ${b2} (${describeJob(jobOf(world, t2, b2))})`);

    const s = readCase(world);
    const anchors = s.audit.filter((row) => row.type === 'envelope.seal_started').length;
    assert.deepEqual(
      { status: s.job.status, attempts: Number(s.job.attempt_count), owner: s.job.lease_owner, anchors, records: s.records.length, artifacts: s.artifacts.length, reports: s.reports.length, checkpoints: s.checkpoints.length, outbox: s.outbox.length },
      { status: 'running', attempts: 1, owner: 'recovery-stop-1', anchors: 1, records: 0, artifacts: 0, reports: 0, checkpoints: 0, outbox: 0 },
      `A wrote nothing after the abort and keeps its lease for the reclaim: ${summary(s)}`,
    );
    const jobA2 = jobOf(world, t1, a2);
    assert.deepEqual([jobA2.status, Number(jobA2.attempt_count)], ['pending', 0], `A2 ${a2} was not claimed after stop() (${describeJob(jobA2)})`);
    checkInvariants(world, { state: 'finalizing', attempts: 1, failedMoves: 0 }, { nowMs: clockMs });
  } finally {
    if (child !== null && child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    world.close();
  }
});
