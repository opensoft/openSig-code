// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-24 (A-010 LBR3-1): the parent's cost of a child report is bounded.
//
// - A maximal lying report (the largest the parent reads, in each costly JSON shape, and a
//   16 MiB one past the budget) is refused, or is accepted within 128 MiB of added parent
//   memory: peak resident memory and committed V8 heap, each measured in a fresh process.
//   The event-loop block of each decode is measured and reported, and stays bounded.
// - Honest documents at the report budget (limits.ts reportBudget, derived from maxBytes)
//   parse; one value or a few bytes more is the parser's own 422 limit-exceeded.
// - At most MAX_CONCURRENT_PARSES (2) parse children run at once, counted from /proc; up to
//   MAX_WAITING_PARSES (32) more wait, and one more is refused at once with 429 rate_limited,
//   without its input being read. FIFO admission is proved from the gate's own read-only
//   admission record (arrival tickets in the order slots were granted), with each call issued
//   only once the previous one has entered the gate; completion order is never asserted,
//   because FIFO admission does not order completions (A-010 PL24-ORC).
//
// Every lying child is a test-only entry module written to a mkdtemp directory and run
// through createParseServiceForTests() in the real sandbox, exactly as the worker is.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import * as limits from '../../src/pdf/limits.ts';
import * as service from '../../src/pdf/service.ts';
import { basicObjects, classicPdf } from './pdf-builder.mjs';
import { REPO } from './support.mjs';

const MIB = 1024 * 1024;
const CEILING_MIB = 128;
const BLOCK_BOUND_MS = 1500;
// The documented derivation (limits.ts reportBudget) at the FR-002 input ceiling of 10 MiB.
const BUDGET = { bytes: 64 * 1024 + Math.floor((10 * MIB) / 8), nodes: 4096 + Math.floor((10 * MIB) / 40) };

const dir = mkdtempSync(join(tmpdir(), 'opensig-pl24-'));
after(() => rmSync(dir, { recursive: true, force: true }));
let files = 0;
const write = (name, text) => {
  files += 1;
  const file = join(dir, `${files}-${name}`);
  writeFileSync(file, text, { mode: 0o600 });
  return file;
};

/**
 * Measurement script, run in a fresh process (--expose-gc) so the baseline is clean. It warms
 * the service with one honest parse, then runs one parse and prints one JSON line: the
 * outcome, the peak resident memory and committed V8 heap added by that parse, and the
 * longest event-loop block while it ran (sampled every millisecond, and read only after the
 * loop has run timers again, so a block at the very end is counted).
 */
const MEASURE = `
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { getHeapStatistics } from 'node:v8';
const [repo, mode, shape, capText, workDir] = process.argv.slice(2);
const cap = Number(capText);
const svc = await import(pathToFileURL(join(repo, 'src/pdf/service.ts')).href);
const { basicObjects, classicPdf } = await import(pathToFileURL(join(repo, 'tests/pdf-parse/pdf-builder.mjs')).href);
const base = classicPdf(basicObjects());
const warm = await svc.parsePdf(base);
if (!warm.ok) throw new Error('warm-up parse failed: ' + warm.reason);
let parse = (input) => svc.parsePdf(input);
let input = base;
if (mode === 'lying') {
  const report = structuredClone(warm.report);
  delete report.digest;
  delete report.network_sandbox;
  const head = JSON.stringify({ ok: true, report });
  const at = head.indexOf('"Type":{"name":"Page"}');
  const before = head.slice(0, at);
  const rest = head.slice(at);
  const units = { number: '0', array: '[]', dict: '{"dict":{}}', hex: '{"hex":""}' };
  let body;
  if (units[shape]) {
    const n = Math.floor((cap - head.length - 16) / (units[shape].length + 1));
    body = 'const body = Array(' + n + ').fill(' + JSON.stringify(units[shape]) + ').join(",");' +
      'process.stdout.write(' + JSON.stringify(before + '"X":[') + ' + body + ' + JSON.stringify('],' + rest) + ' + "\\\\n");';
  } else {
    const n = Math.floor((cap - head.length - 32) / 12);
    body = 'const parts = []; for (let i = 0; i < ' + n + '; i += 1) parts.push(\\'"k\\' + i.toString(36).padStart(6, "0") + \\'":0\\');' +
      'process.stdout.write(' + JSON.stringify(before + '"X":{"dict":{') + ' + parts.join(",") + ' + JSON.stringify('}},' + rest) + ' + "\\\\n");';
  }
  const entry = join(workDir, 'lying-' + shape + '-' + cap + '.mjs');
  writeFileSync(entry, 'for await (const chunk of process.stdin) void chunk;\\n' + body + '\\n', { mode: 0o600 });
  const lying = svc.createParseServiceForTests({ workerEntry: entry });
  parse = (bytes) => lying.parse(bytes);
} else {
  const k = Math.floor((cap - 8192) / 12);
  input = classicPdf(basicObjects({ page: '/X [' + '<<>> '.repeat(k) + ']' }));
}
globalThis.gc();
globalThis.gc();
const heap0 = getHeapStatistics().total_heap_size;
const rss0 = process.resourceUsage().maxRSS * 1024;
const delay = monitorEventLoopDelay({ resolution: 1 });
delay.enable();
const outcome = await parse(input);
await new Promise((resolve) => setTimeout(resolve, 50));
delay.disable();
const rss1 = process.resourceUsage().maxRSS * 1024;
const heap1 = getHeapStatistics().total_heap_size;
const page = outcome.ok ? outcome.report.objects[String(outcome.report.pages[0].ref[0])].value.dict.X : undefined;
process.stdout.write(JSON.stringify({
  status: outcome.status, reason: outcome.ok ? null : outcome.reason, detail: outcome.ok ? null : outcome.detail,
  values: Array.isArray(page) ? page.length : page && page.dict ? Object.keys(page.dict).length : null,
  rss_mib: (rss1 - rss0) / ${MIB}, heap_mib: (heap1 - heap0) / ${MIB}, block_ms: delay.max / 1e6,
}) + '\\n');
`;

function measure(mode, shape, cap) {
  const script = write('measure.mjs', MEASURE);
  const run = spawnSync(process.execPath, ['--expose-gc', script, REPO, mode, shape, String(cap), dir], {
    env: process.env,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 4 * MIB,
  });
  assert.equal(run.status, 0, `measurement ${mode} ${shape} exited ${run.status}: ${run.stderr.slice(0, 400)}`);
  return JSON.parse(run.stdout.trim().split('\n').at(-1));
}

const fmt = (m) => `${m.status} ${m.reason ?? ''} values=${m.values} rss+${m.rss_mib.toFixed(1)}MiB heap+${m.heap_mib.toFixed(1)}MiB block=${m.block_ms.toFixed(0)}ms`;

function assertBounded(m, label) {
  assert.ok(m.rss_mib <= CEILING_MIB, `${label}: peak resident memory grew ${m.rss_mib.toFixed(1)} MiB (ceiling ${CEILING_MIB})`);
  assert.ok(m.heap_mib <= CEILING_MIB, `${label}: committed heap grew ${m.heap_mib.toFixed(1)} MiB (ceiling ${CEILING_MIB})`);
  assert.ok(m.block_ms <= BLOCK_BOUND_MS, `${label}: the event loop was blocked ${m.block_ms.toFixed(0)} ms (bound ${BLOCK_BOUND_MS})`);
}

test('[PL-24] a maximal lying report is refused or stays within 128 MiB of parent memory, with a bounded event-loop block', async (t) => {
  // Past the budget: a 16 MiB report (the largest the parent read before LBR3-1) is cut off.
  const oversized = measure('lying', 'array', 16 * MIB);
  t.diagnostic(`lying 16 MiB array: ${fmt(oversized)}`);
  assert.deepEqual([oversized.status, oversized.reason], [500, 'service-failure'], `a 16 MiB lying report must be refused: ${fmt(oversized)}`);
  assert.match(oversized.detail, /report budget/);
  assertBounded(oversized, 'lying 16 MiB array');

  // At the byte budget, in the costliest shapes: past the node budget it is refused; within
  // both budgets it is a well-formed report and is accepted, within the ceiling.
  const expected = { array: 'refused', number: 'refused', dict: 'accepted', hex: 'accepted', wide: 'accepted' };
  for (const [shape, fate] of Object.entries(expected)) {
    const m = measure('lying', shape, BUDGET.bytes);
    t.diagnostic(`lying ${shape} at ${BUDGET.bytes} bytes: ${fmt(m)}`);
    if (fate === 'refused') {
      assert.deepEqual([m.status, m.reason], [500, 'service-failure'], `${shape}: more values than the node budget must be refused`);
      assert.match(m.detail, /invalid report/);
    } else {
      assert.equal(m.status, 200, `${shape}: ${m.reason} ${m.detail}`);
      assert.ok(m.values > 90_000, `${shape}: the report carried ${m.values} values`);
    }
    assertBounded(m, `lying ${shape}`);
  }

  // An honest document whose report is close to the byte budget, in the costliest shape.
  const honest = measure('honest', 'dicts', BUDGET.bytes);
  t.diagnostic(`honest dictionaries near ${BUDGET.bytes} bytes: ${fmt(honest)}`);
  assert.equal(honest.status, 200, `${honest.reason} ${honest.detail}`);
  assertBounded(honest, 'honest dictionaries');
});

/** JSON values in the reported objects, counted as the child and the parent count them. */
function countValues(value) {
  if (value === null || typeof value !== 'object') return 1;
  if (Array.isArray(value)) return 1 + value.reduce((sum, item) => sum + countValues(item), 0);
  if (value.dict !== undefined) return 1 + Object.values(value.dict).reduce((sum, item) => sum + countValues(item), 0);
  return 1;
}

const childLine = (report) => {
  const copy = structuredClone(report);
  delete copy.digest;
  delete copy.network_sandbox;
  return Buffer.byteLength(`${JSON.stringify({ ok: true, report: copy })}\n`);
};

test('[PL-24] honest documents at the report budget parse; one value or a few bytes more is the parser\'s own 422', async () => {
  // Node budget: exactly at it parses; one more value is limit-exceeded report-nodes.
  const withValues = (k) => classicPdf(basicObjects({ page: `/X [${'0 '.repeat(k)}]` }));
  const empty = await service.parsePdf(withValues(0));
  assert.equal(empty.ok, true, empty.ok ? '' : empty.detail);
  const baseValues = Object.values(empty.report.objects).reduce((sum, entry) => sum + countValues(entry.value), 0);
  const room = BUDGET.nodes - baseValues;
  const [atNodes, overNodes] = await Promise.all([service.parsePdf(withValues(room)), service.parsePdf(withValues(room + 1))]);
  assert.equal(atNodes.ok, true, atNodes.ok ? '' : `${atNodes.status} ${atNodes.reason} ${atNodes.detail}`);
  assert.equal(Object.values(atNodes.report.objects).reduce((sum, entry) => sum + countValues(entry.value), 0), BUDGET.nodes);
  assert.deepEqual([overNodes.ok, overNodes.status, overNodes.reason, overNodes.detail], [false, 422, 'limit-exceeded', 'report-nodes']);

  // Byte budget: a report a little under it parses; a few bytes over is limit-exceeded report-size.
  const withString = (n) => classicPdf(basicObjects({ page: `/S <${'ab'.repeat(n)}>` }));
  const small = await service.parsePdf(withString(0));
  assert.equal(small.ok, true, small.ok ? '' : small.detail);
  const line0 = childLine(small.report);
  const under = Math.floor((BUDGET.bytes - 4096 - line0) / 2);
  const over = Math.ceil((BUDGET.bytes + 64 - line0) / 2);
  const [underOutcome, overOutcome] = await Promise.all([service.parsePdf(withString(under)), service.parsePdf(withString(over))]);
  assert.equal(underOutcome.ok, true, underOutcome.ok ? '' : `${underOutcome.status} ${underOutcome.reason} ${underOutcome.detail}`);
  const underLine = childLine(underOutcome.report);
  assert.ok(underLine <= BUDGET.bytes && underLine > BUDGET.bytes - 8192, `the near-budget report is ${underLine} bytes`);
  assert.deepEqual([overOutcome.ok, overOutcome.status, overOutcome.reason, overOutcome.detail], [false, 422, 'limit-exceeded', 'report-size']);

  // The budget is the documented derivation from maxBytes, and follows a lowered maxBytes.
  assert.deepEqual(limits.reportBudget(limits.DEFAULT_PARSER_LIMITS), BUDGET);
  assert.deepEqual(limits.reportBudget({ maxBytes: MIB }), { bytes: 64 * 1024 + MIB / 8, nodes: 4096 + Math.floor(MIB / 40) });
  const lowered = await service.parsePdf(withValues(room), { limits: { maxBytes: MIB } });
  assert.deepEqual([lowered.status, lowered.reason, lowered.detail], [422, 'limit-exceeded', 'report-nodes']);
  // maxReportBytes is no longer a separate service limit that could exceed the derived budget.
  await assert.rejects(service.parsePdf(withValues(0), { service: { maxReportBytes: 64 * MIB } }), TypeError);
});

/** Direct children of this process (each running parse has exactly one: its launcher shell). */
function directChildren() {
  let count = 0;
  for (const name of readdirSync('/proc')) {
    if (!/^\d+$/.test(name)) continue;
    let stat;
    try {
      stat = readFileSync(`/proc/${name}/stat`, 'latin1');
    } catch {
      continue;
    }
    const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    if (Number(fields[1]) === process.pid) count += 1;
  }
  return count;
}

/** Poll `check` every 2 ms until it holds; fail with `label` after `ms`. */
async function until(check, ms, label) {
  const deadline = Date.now() + ms;
  while (!check()) {
    if (Date.now() > deadline) assert.fail(`${label} within ${ms} ms`);
    await new Promise((resolveTick) => setTimeout(resolveTick, 2));
  }
}

test('[PL-24] at most two parse children run at once; 32 more wait and are admitted in arrival order, and one more is a clean 429', async (t) => {
  // A child that waits 800 ms when its input starts with "slow" (5 s with "hold"), then
  // reports a rejection.
  const entry = write(
    'slow-child.mjs',
    `let input = '';
for await (const chunk of process.stdin) input += chunk;
if (input.startsWith('slow')) await new Promise((resolve) => setTimeout(resolve, 800));
if (input.startsWith('hold')) await new Promise((resolve) => setTimeout(resolve, 5000));
process.stdout.write(JSON.stringify({ ok: false, reason: 'malformed', detail: 'synthetic ' + input.slice(0, 12) }) + '\\n');
`,
  );
  const children = service.createParseServiceForTests({ workerEntry: entry });

  // Six slow parses at once: never more than two children alive.
  const samples = { children: 0, running: 0, waiting: 0 };
  const sampler = setInterval(() => {
    samples.children = Math.max(samples.children, directChildren());
    const capacity = service.parseCapacity?.() ?? { running: 0, waiting: 0 };
    samples.running = Math.max(samples.running, capacity.running);
    samples.waiting = Math.max(samples.waiting, capacity.waiting);
  }, 5);
  const started = Date.now();
  const six = await Promise.all(Array.from({ length: 6 }, (_, i) => children.parse(Buffer.from(`slow-${i}`))));
  const elapsed = Date.now() - started;
  clearInterval(sampler);
  t.diagnostic(`six slow parses: ${elapsed} ms, at most ${samples.children} children, running ${samples.running}, waiting ${samples.waiting}`);
  assert.ok(samples.children <= 2, `at most two parse children at once (saw ${samples.children})`);
  assert.ok(samples.children >= 1);
  assert.ok(elapsed >= 3 * 800, `six 800 ms children two at a time take at least 2.4 s (took ${elapsed} ms)`);
  six.forEach((outcome, i) => assert.deepEqual([outcome.status, outcome.reason, outcome.detail], [422, 'malformed', `synthetic slow-${i}`]));
  assert.deepEqual([samples.running, samples.waiting], [2, 4]);
  assert.deepEqual(service.parseCapacity(), { running: 0, waiting: 0, max_concurrent: 2, max_waiting: 32 });
  assert.deepEqual([service.MAX_CONCURRENT_PARSES, service.MAX_WAITING_PARSES], [2, 32]);

  // Two holding parses take both slots and 32 fast ones queue. Each call is issued only once
  // the previous one has entered the gate (its ticket drawn, and for a queued one the waiting
  // count grown), so the arrival order is exactly the issue order.
  const tickets = {};
  const pending = [];
  const issue = async (label, admittedAtOnce) => {
    const before = service.parseCapacity();
    const ticket = service.parseAdmissions().next_ticket;
    tickets[label] = ticket;
    pending.push(children.parse(Buffer.from(label)));
    await until(() => service.parseAdmissions().next_ticket === ticket + 1, 5000, `${label} enters the gate`);
    const after = service.parseCapacity();
    if (admittedAtOnce) assert.equal(after.running, before.running + 1, `${label} takes a free slot`);
    else assert.deepEqual([after.running, after.waiting], [2, before.waiting + 1], `${label} queues behind the two slot holders`);
  };
  await issue('hold-0', true);
  await issue('hold-1', true);
  for (let i = 0; i < 32; i += 1) await issue(`fast-${String(i).padStart(2, '0')}`, false);
  assert.deepEqual(service.parseCapacity(), { running: 2, waiting: 32, max_concurrent: 2, max_waiting: 32 });
  let pulled = 0;
  const stream = (async function* body() {
    pulled += 1;
    yield Buffer.from('fast-extra');
  })();
  const refusedAt = Date.now();
  const refused = await children.parse(stream);
  const refusedMs = Date.now() - refusedAt;
  t.diagnostic(`overflow refused in ${refusedMs} ms: ${refused.status} ${refused.code} ${refused.reason}`);
  assert.deepEqual([refused.ok, refused.status, refused.code, refused.reason], [false, 429, 'rate_limited', 'parse-capacity']);
  assert.equal(pulled, 0, 'the refused parse never read its input');
  assert.ok(refusedMs < 400, `refused at once, not after a slot freed (${refusedMs} ms)`);
  const outcomes = await Promise.all(pending);
  outcomes.forEach((outcome) => assert.equal(outcome.status, 422, `${outcome.reason} ${outcome.detail}`));
  assert.deepEqual(service.parseCapacity(), { running: 0, waiting: 0, max_concurrent: 2, max_waiting: 32 });

  // Admission order, from the gate's record (never completion order): the two holders first,
  // then the waiting parses in exact arrival order 0..31. The refused parse drew no ticket.
  const labels = ['hold-0', 'hold-1', ...Array.from({ length: 32 }, (_, i) => `fast-${String(i).padStart(2, '0')}`)];
  const record = service.parseAdmissions();
  assert.equal(record.next_ticket, tickets['hold-0'] + 34, 'one ticket per admitted parse, none for the refused one');
  const byTicket = new Map(Object.entries(tickets).map(([label, ticket]) => [ticket, label]));
  const admitted = record.admitted.filter((ticket) => byTicket.has(ticket)).map((ticket) => byTicket.get(ticket));
  assert.deepEqual(admitted.slice(0, 2), ['hold-0', 'hold-1'], 'the two holders are admitted first');
  assert.deepEqual(admitted.slice(2), labels.slice(2), 'the waiting parses are admitted in exact arrival order 0..31');
  t.diagnostic(`admission order: ${admitted.join(',')}`);

  // The record is bounded and read-only.
  assert.equal(record.max_records, 128);
  assert.ok(record.admitted.length <= record.max_records);
  assert.ok(Object.isFrozen(record) && Object.isFrozen(record.admitted));
  assert.throws(() => record.admitted.push(0), TypeError);
  assert.deepEqual(service.parseAdmissions().admitted, record.admitted, 'a fresh read is unchanged');
});
