// SPDX-License-Identifier: Apache-2.0
//
// T015 test-only orchestration: one scripted case, end to end, serially.
//
// Every case: a fresh world with T038's seed (world.mjs) → the group's script, in which each
// runner is its own OS process (process.mjs, runner-child.mjs) on one fixed instant, a held
// runner is SIGKILLed or released at its phase's hook (src/domain/finalization/fault-hook.ts) →
// I1..I10 (invariants.mjs) → the receipt (receipts.mjs). Cleanup runs on every path: the case's
// own children end (their recorded PIDs only) before its directories are removed.
//
// Recovery is T038's (bound at 00b260f): runOnce reclaims a strictly expired lease into
// `retryable` with a bounded retry_at (src/storage/repositories/jobs.ts:337-356, retryDelayMs
// :186-189; src/jobs/finalize.ts:363-365), or into `failed` with its one announcement at the
// limit (src/domain/finalization/transitions.ts:139-151), and a later pass claims the job when
// it is due (finalize.ts:366-369; grantLease jobs.ts:241-277). With fixed clocks that is two
// children (request #79 (1)): B reclaims at lease_expires_at, C takes the one further attempt
// at the retry_at B wrote; where B finds the job succeeded, no C runs.
//
// Racers: void, decline and the expiry sweep are T010's landed race child, read-only
// (tests/approval/support/race.mjs; request #61 (9)); the void and the decline assert 409
// state_conflict (request #79 (5)). The operator retry is T038's retryFinalization
// (src/domain/finalization/retry.ts:104-169), called in this process, a separate OS process from
// the held runner. A retry writes the job and its audit event only on an actual transition
// (retryJob jobs.ts:386-413, retry.ts:138-147; requests #80 (1), #82), so I9 holds by the rule; REC-02
// shows a second retry before the next attempt writing neither.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { FAULT_HOOK_FLAG, FAULT_PHASES, faultPoint, parseFaultHookFlag } from '../../../src/domain/finalization/fault-hook.ts';
import { retryFinalization } from '../../../src/domain/finalization/index.ts';
import { AuditWriter } from '../../../src/storage/audit/index.ts';
import { startRacer } from '../../approval/support/race.mjs';
import { entryById } from './catalog.mjs';
import { expectRacerRefused, expectRetryNoOp, expectRetryRaisesByOne, expectRetryRefusedWhileRunning, expectStaleHolderWroteNothing, expectUnchanged } from './expectations.mjs';
import { checkInvariants, readCase, summary } from './invariants.mjs';
import { BLOCKED_WATCH_MS, assertOutcome, childGroup, startRunner } from './process.mjs';
import { counters, newRecord, recordCase } from './receipts.mjs';
import { assertLease, assertPinnedNode, CASE_START_MS, createCaseWorld, describeJob, envelopeRow, expiryOf, jobRow, observe, REPO } from './world.mjs';

/** Per-test hang guard for one case (the runner's per-file timeout is 10 minutes). */
export const CASE_TIMEOUT_MS = 180_000;

const ALL_ROLES = Object.freeze(['composed', 'sealed', 'evidence', 'package']);
/** What the first attempt has made durable when its hook holds it (request #61 (2)): the phase not begun, everything before it committed. */
const AT_HOLD = Object.freeze({
  reserve: { anchors: 0, roles: [], checkpoints: 0, artifacts: 0 },
  compose: { anchors: 0, roles: [], checkpoints: 0, artifacts: 0 },
  seal: { anchors: 1, roles: ['composed'], checkpoints: 0, artifacts: 0 },
  verify: { anchors: 1, roles: ['composed'], checkpoints: 0, artifacts: 0 },
  'store PDF': { anchors: 1, roles: ['composed'], checkpoints: 0, artifacts: 0 },
  'store evidence': { anchors: 1, roles: ['composed', 'sealed'], checkpoints: 0, artifacts: 0 },
  publish: { anchors: 1, roles: ALL_ROLES, checkpoints: 1, artifacts: 0 },
  outbox: { anchors: 1, roles: ALL_ROLES, checkpoints: 1, artifacts: 1 },
});

export async function runCase(t, caseId) {
  const entry = entryById(caseId);
  assertPinnedNode();
  const world = createCaseWorld({ maxAttempts: entry.seed?.maxAttempts ?? 5, declineSession: entry.race === 'decline' });
  const group = childGroup();
  const record = newRecord(entry);
  const run = { t, world, entry, group, record };
  try {
    const { nowMs } = await SCRIPTS[entry.group](run);
    const { results, state } = checkInvariants(world, entry.expect, { nowMs });
    record.invariants = results;
    Object.assign(record, counters(state));
    record.verdict = 'pass';
  } catch (error) {
    record.verdict = 'fail';
    throw error;
  } finally {
    try {
      record.children = await group.stopAll();
    } finally {
      try {
        recordCase(t, record);
      } finally {
        world.close();
      }
    }
  }
}

const runner = (run, role, clockMs, phase = null) => startRunner(run.group, run.world, { role, clockMs, phase });

/** Runner A on the case's start instant, held at the entry's phase. */
async function holdA(run) {
  const a = runner(run, 'A', CASE_START_MS, run.entry.phase);
  const held = await a.held();
  run.record.phase_reached = held.phase;
  return a;
}

/** Premise: what attempt 1 has made durable at its hold. */
function assertAtHold(world, label) {
  const s = readCase(world);
  const want = AT_HOLD[label];
  const seen = {
    anchors: s.audit.filter((row) => row.type === 'envelope.seal_started').length,
    roles: s.records.filter((row) => row.fencingToken === 1).map((row) => row.role),
    checkpoints: s.checkpoints.length,
    artifacts: s.artifacts.length,
  };
  assert.deepEqual(seen, { ...want, roles: [...want.roles] }, `premise: held at ${label}, attempt 1 has made exactly this durable: ${summary(s)}`);
  return s;
}

/** B reclaims at the strict expiry; C runs the attempt at the retry_at B wrote. Returns C's instant. */
async function recover(run, expiryMs) {
  const { world, record } = run;
  const b = runner(run, 'B', expiryMs);
  assertOutcome(b, await b.outcome(), { reclaimed: 1, attempts: [] });
  const job = jobRow(world);
  assert.deepEqual([job.status, job.last_error_code], ['retryable', 'lease_expired.reclaimed'], `B reclaimed the lease at its expiry into retryable (${describeJob(job)})`);
  const retryMs = Date.parse(job.retry_at);
  assert.ok(retryMs > expiryMs, `premise: the bounded retry_at ${job.retry_at} follows the reclaim`);
  const c = runner(run, 'C', retryMs);
  assertOutcome(c, await c.outcome(), { reclaimed: 0, attempts: ['published'] });
  record.expectations.push('reclaimed at the strict expiry, then one more attempt published');
  return retryMs;
}

/** SC003-01..08. */
async function sigkillScript(run) {
  const { world, entry, record } = run;
  const label = entry.phase.label;
  const a = await holdA(run);
  const atHold = assertAtHold(world, label);
  const killed = await a.kill();
  assert.equal(killed.signal, 'SIGKILL', `premise: ${a.describe()} died by the SIGKILL at its hook`);
  const expiry = expiryOf(CASE_START_MS);
  if (label === 'outbox') {
    const job = jobRow(world);
    assert.equal(job.status, 'succeeded', `premise: the publish committed before the SIGKILL (${describeJob(job)})`);
    const b = runner(run, 'B', expiry);
    assertOutcome(b, await b.outcome(), { reclaimed: 0, attempts: [] });
    record.expectations.push('a fresh runner finds the job succeeded and takes no attempt');
    return { nowMs: expiry };
  }
  assertLease(world, CASE_START_MS);
  const reused = entry.expect.reuse
    ? { anchor: atHold.audit.find((row) => row.type === 'envelope.seal_started').seq, checkpoint: [atHold.checkpoints[0].seq, atHold.checkpoints[0].event_digest] }
    : null;
  const nowMs = await recover(run, expiry);
  if (reused !== null) {
    const s = readCase(world);
    const anchors = s.audit.filter((row) => row.type === 'envelope.seal_started').map((row) => row.seq);
    assert.deepEqual(
      { anchors, checkpoint: s.checkpoints.map((row) => [row.seq, row.event_digest]) },
      { anchors: [reused.anchor], checkpoint: [reused.checkpoint] },
      `SC003-07: the rolled-back publish's anchor and checkpoint are the ones the retry used: ${summary(s)}`,
    );
    record.expectations.push('the uncommitted publish rolled back; the anchor and the checkpoint were reused');
  }
  return { nowMs };
}

/** SC003-09..16. */
async function staleLeaseScript(run) {
  const { world, entry, record } = run;
  const label = entry.phase.label;
  const a = await holdA(run);
  assertAtHold(world, label);
  const expiry = expiryOf(CASE_START_MS);
  if (label === 'outbox') assert.equal(jobRow(world).status, 'succeeded', `premise: held after the publish commit (${describeJob(jobRow(world))})`);
  else assertLease(world, CASE_START_MS);
  const beforeProbe = observe(world);
  const probe = runner(run, 'probe', expiry - 1);
  assertOutcome(probe, await probe.outcome(), { reclaimed: 0, attempts: [] });
  expectUnchanged(beforeProbe, observe(world), 'the probe 1 ms before the expiry');
  record.expectations.push('strict expiry: the probe at lease_expires_at - 1 ms reclaimed nothing');
  if (label === 'publish' || label === 'outbox') {
    const b = runner(run, 'B', expiry);
    if (label === 'publish') assert.equal(await b.absentFor(BLOCKED_WATCH_MS), true, `${b.describe()} queues behind the held publish transaction`);
    else assertOutcome(b, await b.outcome(), { reclaimed: 0, attempts: [] });
    a.release();
    assertOutcome(a, await a.outcome(), { reclaimed: 0, attempts: ['published'] });
    if (label === 'publish') assertOutcome(b, await b.outcome(), { reclaimed: 0, attempts: [] });
    record.expectations.push(label === 'publish' ? "the holder's fenced commit stood; the queued runner wrote nothing" : 'the second runner found the job succeeded');
    return { nowMs: expiry };
  }
  const nowMs = await recover(run, expiry);
  const beforeRelease = observe(world);
  a.release();
  assertOutcome(a, await a.outcome(), { reclaimed: 0, attempts: ['lost'] });
  expectStaleHolderWroteNothing(beforeRelease, observe(world), 1);
  record.expectations.push('the released stale holder wrote nothing');
  return { nowMs };
}

/** One T010 racer as its own OS process, recorded in the case's group (its PID only). */
async function t010Racer(run, job) {
  const racer = startRacer(run.world, run.world.jobsDir, { tenantId: run.world.ctx.tenantId, ...job });
  run.group.add({ role: `racer-${job.action}`, stop: () => racer.stop() });
  return { result: await racer.result(), events: racer.events };
}

function operatorRetry(world, expectedVersion, clockMs, key = `recovery-retry-${clockMs}`) {
  const clock = () => new Date(clockMs);
  return retryFinalization(
    world.db,
    new AuditWriter(world.db, { clock }),
    { tenantId: world.ctx.tenantId, envelopeId: world.ctx.envelopeId, actor: { kind: 'human-operator', ref: 'operator-recovery' }, idempotency: { key, request: { expected_version: expectedVersion } } },
    { clock },
  );
}

/** SC003-17..20. */
async function raceScript(run) {
  const { world, entry, record } = run;
  const a = await holdA(run);
  assertAtHold(world, entry.phase.label);
  assertLease(world, CASE_START_MS);
  const envelope = envelopeRow(world);
  const version = Number(envelope.version);
  assert.deepEqual([envelope.state, version], ['finalizing', world.ctx.reservedVersion], `premise: envelope ${envelope.id} is finalizing at its reserved version`);
  const before = observe(world);
  if (entry.race === 'operator retry') {
    let refusal = null;
    try {
      operatorRetry(world, version, CASE_START_MS);
    } catch (error) {
      refusal = error;
    }
    expectRetryRefusedWhileRunning(refusal, before, observe(world));
  } else {
    const job =
      entry.race === 'void'
        ? { action: 'void', envelopeId: envelope.id, clockMs: CASE_START_MS, body: { expected_version: version, reason_code: 'sender-cancelled' } }
        : entry.race === 'decline'
          ? { action: 'decline', cookie: world.declineCookie, clockMs: CASE_START_MS, body: { expected_version: version } }
          : { action: 'sweep', clockMs: Date.parse(String(envelope.expires_at)) + 60_000 };
    const { result, events } = await t010Racer(run, job);
    if (entry.race === 'decline') assert.equal(events.find((event) => event.event === 'authenticated')?.ok, true, 'premise: the decline racer authenticated with the seeded session');
    expectRacerRefused(result, entry.expect.racer, before, observe(world), entry.race);
  }
  record.expectations.push(`${entry.race} refused with nothing written`);
  a.release();
  assertOutcome(a, await a.outcome(), { reclaimed: 0, attempts: ['published'] });
  return { nowMs: CASE_START_MS };
}

/** REC-02: the attempt limit (seeded max_attempts 2). */
async function limitScript(run) {
  const { world, entry, record } = run;
  const a = runner(run, 'A', CASE_START_MS, entry.phase);
  record.phase_reached = (await a.held()).phase;
  assert.equal((await a.kill()).signal, 'SIGKILL', `premise: ${a.describe()} died at its hook`);
  const b = runner(run, 'B', expiryOf(CASE_START_MS));
  assertOutcome(b, await b.outcome(), { reclaimed: 1, attempts: [] });
  const retryMs = Date.parse(jobRow(world).retry_at);
  const c = runner(run, 'C', retryMs, entry.phase);
  await c.held();
  const last = assertLease(world, retryMs);
  assert.deepEqual([Number(last.attempt_count), Number(last.max_attempts)], [2, 2], `premise: C holds the last allowed attempt (${describeJob(last)})`);
  assert.equal((await c.kill()).signal, 'SIGKILL', `premise: ${c.describe()} died at its hook`);
  const expiry = expiryOf(retryMs);
  const d = runner(run, 'D', expiry);
  assertOutcome(d, await d.outcome(), { reclaimed: 1, attempts: [] });
  const failed = jobRow(world);
  assert.deepEqual([failed.status, failed.last_error_code], ['failed', 'lease_expired.reclaimed'], `the reclaim at the limit moved the job to failed, naming the lease expiry (${describeJob(failed)})`);
  const retried = () => world.rows('audit_events', "WHERE tenant_id = ? AND envelope_id = ? AND type = 'envelope.finalization_retried'", [world.ctx.tenantId, world.ctx.envelopeId]);
  const result = operatorRetry(world, Number(envelopeRow(world).version), expiry);
  const raised = jobRow(world);
  expectRetryRaisesByOne(result, failed, raised, retried());
  // RETRY-BOUND (request #80 (1)): a second retry, under a fresh key and one second later, before
  // the next attempt finds the job retryable and due: 202, and neither the job nor the audit chain
  // changes (a no-op that rewrote retry_at or updated_at at its own instant would show).
  const againMs = expiry + 1_000;
  assert.ok(Date.parse(raised.retry_at) <= againMs, `premise: the raised job is due at the second retry (${describeJob(raised)})`);
  const beforeNoOp = observe(world);
  const again = operatorRetry(world, Number(envelopeRow(world).version), againMs, `recovery-retry-again-${againMs}`);
  expectRetryNoOp(again, beforeNoOp, observe(world), retried());
  const nextMs = againMs;
  const e = runner(run, 'E', nextMs);
  assertOutcome(e, await e.outcome(), { reclaimed: 0, attempts: ['published'] });
  record.expectations.push('failed once at the limit, raised by one, then completed');
  return { nowMs: nextMs };
}

const stripComments = (text) => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');

/** REC-01's static half: the hook reads only its flag; the flag and the hook points live where the T015 line puts them. */
function staticHookCheck() {
  const sources = readdirSync(join(REPO, 'src'), { recursive: true })
    .map(String)
    .filter((rel) => rel.endsWith('.ts'))
    .map((rel) => ({ rel: `src/${rel.split('\\').join('/')}`, code: stripComments(readFileSync(join(REPO, 'src', rel), 'utf8')) }));
  const hook = sources.find((file) => file.rel === 'src/domain/finalization/fault-hook.ts');
  assert.ok(hook, 'the hook module exists');
  const reads = { argv: (hook.code.match(/process\.argv/g) ?? []).length, env: (hook.code.match(/process\.env|execArgv|getenv/g) ?? []).length };
  const imports = [...hook.code.matchAll(/from\s+'([^']+)'/g)].map((match) => match[1]).sort();
  assert.deepEqual({ ...reads, imports }, { argv: 1, env: 0, imports: ['node:fs', 'node:path'] }, `the hook reads process.argv once, no environment, and imports only node:fs and node:path (got ${JSON.stringify({ ...reads, imports })})`);
  const flagHolders = sources.filter((file) => file.code.includes(FAULT_HOOK_FLAG)).map((file) => file.rel);
  assert.deepEqual(flagHolders, ['src/domain/finalization/fault-hook.ts'], `only the hook spells the flag in src/ (found in ${flagHolders.join(', ')})`);
  const callers = sources.filter((file) => file.rel !== hook.rel && /\bfaultPoint\b/.test(file.code));
  const calls = callers.flatMap((file) => [...file.code.matchAll(/\bfaultPoint\(([^)]*)\)/g)].map((match) => `${file.rel}:${match[1]}`)).sort();
  const expected = [...FAULT_PHASES.map((phase) => `${phase === 'publish' ? 'src/domain/finalization/publish.ts' : 'src/jobs/finalize.ts'}:'${phase}'`)].sort();
  assert.deepEqual(calls, expected, `exactly one literal hook point per phase, in the runner and the publish transaction (got ${calls.join(' | ')})`);
}

/** REC-01. */
async function hookScript(run) {
  const { world, record } = run;
  staticHookCheck();
  assert.equal(parseFaultHookFlag(process.argv), null, 'premise: this test process carries no harness flag');
  for (const phase of FAULT_PHASES) assert.equal(faultPoint(phase), undefined, `faultPoint('${phase}') returns at once without the flag`);
  const a = runner(run, 'A', CASE_START_MS);
  assertOutcome(a, await a.outcome(), { reclaimed: 0, attempts: ['published'] });
  assert.equal(a.events.filter((event) => event.event === 'fault-hook').length, 0, `${a.describe()}: without the flag no hook point holds`);
  const s = readCase(world);
  assert.deepEqual(
    { roles: s.records.map((row) => `${row.fencingToken}:${row.role}`), audit: s.audit.map((row) => row.type) },
    { roles: ALL_ROLES.map((role) => `1:${role}`), audit: ['envelope.seal_started', 'envelope.completed'] },
    `the flagless run is an unhooked run's: one attempt's four records and the anchor and completion only: ${summary(s)}`,
  );
  record.expectations.push('hook inert without the flag; the hook reads only its flag');
  return { nowMs: CASE_START_MS };
}

const SCRIPTS = Object.freeze({ sigkill: sigkillScript, 'stale-lease': staleLeaseScript, race: raceScript, limit: limitScript, hook: hookScript });
