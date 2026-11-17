// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-11 and PL-12: the parse child is killed at its memory, CPU and
// wall-time limits and the kill is a 422 resource-limit rejection; the child runs under
// the Node permission model with no fs-write, child-process or worker grant and an empty
// environment; and src/pdf/ imports no network module. PL-12 is an import boundary kept
// as defence in depth; the network isolation itself is the namespace sandbox (PL-13).
//
// PL-11 wall-time oracle (A-010 PL11-WALL). A timed check times ONLY the parse call: the clock
// stops when the call resolves, before any assertion or /proc scan. Its bound is one default
// wall period, read from DEFAULT_SERVICE_LIMITS.wallMs and first checked to be at least 10
// times the configured 300 ms. The default watchdog cannot fire inside that bound, so a
// wall-time outcome within it shows the configured limit, not the default, ended the child.
// A worker that blocks without using CPU shows the kill reaches the real child. A hang guard
// above the bound turns a call that never settles into a failure under its own message; it is
// never a pass criterion. Elapsed times are logged as diagnostics.
//
// KILL-RSS and KILL-CPU (A-010) put a memory-holding and a CPU-burning worker against the RSS
// and CPU limits. PL-26 (A-010 PL11-ESC) uses test-only launch seams: a kill decided while
// start-up is held, a launcher that ends before its captured child (the orphan path), and a
// channel to the worker from which the live process tree of each usable launcher is read.
// Every kill case also checks that no process of the sandbox is left when the parse settles.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { closeSync, mkdtempSync, openSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { after, test } from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';

import { DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS } from '../../src/pdf/limits.ts';
import { createParseServiceForTests, parseOrphans, parsePdf, WORKER_ENTRY, workerCommand } from '../../src/pdf/service.ts';
import { heavyDocument } from './pdf-builder.mjs';
import { fixtureBytes, REPO } from './support.mjs';

const PDF_DIR = join(REPO, 'src', 'pdf');
const HEAVY = heavyDocument(100_000);
const HEAVY_LIMITS = { maxObjects: 1_000_000 };

/** The configured wall-time limit under test, and the deadline: one default wall period. */
const WALL_MS = 300;
const DEFAULT_WALL_MS = DEFAULT_SERVICE_LIMITS.wallMs;
/** Turns a parse call that never settles into a failure; never a pass criterion. */
const HANG_GUARD_MS = 2 * DEFAULT_WALL_MS;
/** Containment of the blocking worker (below); after the deadline and the hang guard. */
const SELF_EXIT_MS = 2 * HANG_GUARD_MS;

// A test-only worker, written at run time (as for PL-17, PL-18 and PL-24) and run through
// createParseServiceForTests() in the real sandbox. It reads its input as the real worker
// does, then blocks without using CPU: Atomics.wait parks its main thread in the kernel, with
// no timer and no polling. It never writes a report, so only a kill can end its parse.
// Why no orphan can survive: if no kill ever reaches it, it stops waiting after SELF_EXIT_MS
// and exits by itself, so even a kill that misses the child never leaves a process behind on
// the host, and nothing ever has to be killed from outside. That self-exit can never produce
// a pass: the deadline (one default wall period) and the hang guard (two) both fail the case
// first, and assertTimingOrder() checks deadline < hang guard < self-exit.
const scratch = mkdtempSync(join(tmpdir(), 'opensig-pl11-'));
after(() => rmSync(scratch, { recursive: true, force: true }));

/** Write a test-only worker entry; returns its path and its real path (as the service runs it). */
function writeWorker(name, source) {
  const path = join(scratch, name);
  writeFileSync(path, source, { mode: 0o600 });
  return { path, real: realpathSync(path) };
}

const PARK = `Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ${SELF_EXIT_MS});\nprocess.exit(75);\n`;
const blockingWorker = writeWorker('blocking-worker.mjs', `for await (const chunk of process.stdin) void chunk;\n${PARK}`);
const BLOCKING_WORKER = blockingWorker.path;
const BLOCKING_WORKER_REAL = blockingWorker.real;

/** Each process's argv, by pid (this process excluded). */
function processes() {
  const found = [];
  for (const pid of readdirSync('/proc').filter((name) => /^\d+$/.test(name))) {
    if (Number(pid) === process.pid) continue;
    try {
      found.push({ pid: Number(pid), argv: readFileSync(`/proc/${pid}/cmdline`, 'latin1').split('\0') });
    } catch {
      // gone
    }
  }
  return found;
}

/**
 * Live processes of a test worker itself: node (argv[0] is this runtime) running the worker's
 * entry (an exact argv element). The launcher and the sandbox's init carry the entry path only
 * as bind arguments, under their own argv[0], so they never match.
 */
const liveWorkersOf = (real) => processes().filter(({ argv }) => argv[0] === process.execPath && argv.includes(real)).map(({ pid }) => pid);
const liveBlockingWorkers = () => liveWorkersOf(BLOCKING_WORKER_REAL);

/**
 * Every live process of a test sandbox: each carries the test worker's unique entry path as an
 * argument (the launch shell and any start-up stage, the launcher, the namespace init and the
 * worker). A zombie has no command line, so it does not count: it can no longer run.
 */
const liveProcessesNaming = (real) => processes().filter(({ argv }) => argv.includes(real)).map(({ pid }) => pid);

/** ppid, process group and session of `pid`, from /proc/<pid>/stat. */
function procStat(pid) {
  const text = readFileSync(`/proc/${pid}/stat`, 'latin1');
  const [, ppid, pgrp, session] = text.slice(text.lastIndexOf(')') + 2).split(' ').map(Number);
  return { ppid, pgrp, session };
}

/** The pids of `pid` in each nested PID namespace, outermost first (/proc/<pid>/status NSpid). */
function nsPids(pid) {
  const line = readFileSync(`/proc/${pid}/status`, 'latin1').split('\n').find((row) => row.startsWith('NSpid:'));
  return line === undefined ? [] : line.slice('NSpid:'.length).trim().split(/\s+/).map(Number);
}

/** The children of `pid`, from /proc/<pid>/task/<pid>/children. */
function childrenOf(pid) {
  return readFileSync(`/proc/${pid}/task/${pid}/children`, 'latin1').trim().split(/\s+/).filter((item) => item !== '').map(Number);
}

/** The state letter of the process a /proc/<pid> handle names, or 'reaped' once it has been reaped. */
function handleState(fd) {
  try {
    const text = readFileSync(`/proc/self/fd/${fd}/stat`, 'latin1');
    return text.slice(text.lastIndexOf(')') + 2).split(' ')[0];
  } catch {
    return 'reaped';
  }
}

/** No process of a test sandbox is left (D2): the launcher, the namespace init and the worker. */
function assertSandboxGone(real, label) {
  assert.deepEqual(liveProcessesNaming(real), [], `${label}: when the parse settles, no process of its sandbox (launcher, namespace init, worker) is left`);
}

/** The stop latency the service recorded for its latest parse child (A-010 PL11-ESC; diagnostic). */
function stopDiagnostic(t, service, label) {
  const lifecycle = service.lifecycles().at(-1);
  t.diagnostic(`${label}: launcher stop to sandbox signals ${lifecycle?.stop_ms ?? 'n/a'} ms (diagnostic)`);
}

/** `promise`, or a failure under its own message if it does not settle within HANG_GUARD_MS. */
async function withinGuard(promise, what) {
  let timer;
  const guard = new Promise((_, rejectGuard) => {
    timer = setTimeout(
      () => rejectGuard(new assert.AssertionError({ message: `PL-26 hang guard: ${what} did not happen within ${HANG_GUARD_MS} ms; never a pass criterion` })),
      HANG_GUARD_MS,
    );
  });
  try {
    return await Promise.race([promise, guard]);
  } finally {
    clearTimeout(timer);
  }
}

/** The first line `stream` sends; a failure if it ends first. */
function readLine(stream, what) {
  return new Promise((resolveLine, rejectLine) => {
    let text = '';
    const done = (error, line) => {
      stream.off('data', onData);
      stream.off('end', onEnd);
      stream.off('close', onEnd);
      if (error === null) resolveLine(line);
      else rejectLine(error);
    };
    const onData = (chunk) => {
      text += chunk.toString('latin1');
      const end = text.indexOf('\n');
      if (end !== -1) done(null, text.slice(0, end));
    };
    const onEnd = () => done(new assert.AssertionError({ message: `${what} closed before it sent a line (received ${JSON.stringify(text)})` }));
    stream.on('data', onData);
    stream.once('end', onEnd);
    stream.once('close', onEnd);
  });
}

/** Live processes whose command line names this repository's parse worker. */
function liveWorkers() {
  const found = [];
  for (const pid of readdirSync('/proc').filter((name) => /^\d+$/.test(name))) {
    let cmdline;
    try {
      cmdline = readFileSync(`/proc/${pid}/cmdline`, 'latin1');
    } catch {
      continue;
    }
    if (cmdline.includes(WORKER_ENTRY) && Number(pid) !== process.pid) found.push(Number(pid));
  }
  return found;
}

function resourceRejection(outcome, detail, label, survivors = liveWorkers) {
  assert.equal(outcome.ok, false, `${label} must be killed`);
  assert.equal(outcome.reason, 'resource-limit', `${label}: ${outcome.reason} ${outcome.detail}`);
  assert.equal(outcome.detail, detail, label);
  assert.equal(outcome.status, 422);
  assert.equal(outcome.code, 'unsupported_pdf');
  assert.deepEqual(survivors(), [], `${label}: no parse child survives`);
}

const ms = (value) => `${value.toFixed(1)} ms`;

/** The deadline separates the configured limit from the default one, and deadline < hang guard < self-exit. */
function assertTimingOrder() {
  assert.ok(DEFAULT_WALL_MS >= 10 * WALL_MS, `one default wall period (${DEFAULT_WALL_MS} ms) is at least 10 times the configured ${WALL_MS} ms`);
  assert.ok(
    WALL_MS < DEFAULT_WALL_MS && DEFAULT_WALL_MS < HANG_GUARD_MS && HANG_GUARD_MS < SELF_EXIT_MS,
    `deadline ${DEFAULT_WALL_MS} ms < hang guard ${HANG_GUARD_MS} ms < blocking worker self-exit ${SELF_EXIT_MS} ms`,
  );
}

/**
 * Time ONLY the parse call: the clock starts right before the call and stops when the call
 * resolves, before any assertion or /proc scan. If the call never settles, the hang guard fails
 * the test under its own message, naming the live processes `survivors()` finds.
 */
async function timedParse(call, what, survivors = liveWorkers) {
  let elapsed = Number.NaN;
  const started = performance.now();
  const parse = call().then((outcome) => {
    elapsed = performance.now() - started;
    return outcome;
  });
  parse.catch(() => {});
  let timer;
  const guard = new Promise((_, rejectGuard) => {
    timer = setTimeout(() => {
      const message =
        `PL-11 hang guard: ${what} did not settle within ${HANG_GUARD_MS} ms (twice the default wall period). ` +
        `The guard only turns a hang into a failure and is never a pass criterion. Live processes of this worker: [${survivors().join(', ')}]`;
      rejectGuard(new assert.AssertionError({ message }));
    }, HANG_GUARD_MS);
  });
  try {
    const outcome = await Promise.race([parse, guard]);
    return { outcome, elapsed };
  } finally {
    clearTimeout(timer);
  }
}

test('[PL-11] the heavy document parses within the default resource limits (control)', async () => {
  assert.ok(HEAVY.length < 10 * 1024 * 1024);
  const outcome = await parsePdf(HEAVY, { limits: HEAVY_LIMITS });
  assert.equal(outcome.ok, true, outcome.ok ? '' : `${outcome.reason} ${outcome.detail}`);
  assert.equal(outcome.report.stats.objects, 100_003);
});

test('[PL-11] memory limits kill the parse child: V8 heap and resident memory', async () => {
  resourceRejection(await parsePdf(HEAVY, { limits: HEAVY_LIMITS, service: { heapMiB: 24 } }), 'memory', 'heap 24 MiB');
  resourceRejection(await parsePdf(HEAVY, { limits: HEAVY_LIMITS, service: { heapMiB: 512, rssBytes: 100 * 1024 * 1024 } }), 'memory', 'RSS 100 MiB');
});

test('[PL-11] CPU and wall-time limits kill the parse child', async (t) => {
  resourceRejection(await parsePdf(HEAVY, { limits: HEAVY_LIMITS, service: { heapMiB: 512, cpuMs: 1_000, wallMs: 60_000 } }), 'cpu', 'CPU 1000 ms');
  assertTimingOrder();
  const { outcome, elapsed } = await timedParse(
    () => parsePdf(HEAVY, { limits: HEAVY_LIMITS, service: { heapMiB: 512, cpuMs: 60_000, wallMs: WALL_MS } }),
    `the heavy document's parse at wall ${WALL_MS} ms`,
  );
  t.diagnostic(`real parser, wall ${WALL_MS} ms: the parse call took ${ms(elapsed)} (diagnostic; bound ${DEFAULT_WALL_MS} ms)`);
  resourceRejection(outcome, 'wall-time', `wall ${WALL_MS} ms (parse call ${ms(elapsed)})`);
  assert.ok(
    elapsed < DEFAULT_WALL_MS,
    `the configured ${WALL_MS} ms wall limit, not the default, ended the child: the parse call took ${ms(elapsed)}, bound ${DEFAULT_WALL_MS} ms (one default wall period)`,
  );
});

test('[PL-11] a worker that blocks without using CPU is ended by the configured wall-time limit, and the kill reaches the real child', async (t) => {
  // Recorded limit (A-010 PL11-WALL): PL-11 does not prove termination within any fixed
  // latency after 300 ms under arbitrary host load. This oracle is stronger on two properties:
  // the kill reaches the real child (this worker never exits by itself and holds the child's
  // stdio, so the call can only resolve once it is dead, and no process of it may survive),
  // and the configured limit, not the default, ended it (the bound). It is looser on latency.
  assertTimingOrder();
  const blocking = createParseServiceForTests({ workerEntry: BLOCKING_WORKER });
  const { outcome, elapsed } = await timedParse(
    () => blocking.parse(Buffer.from('blocking-worker input'), { service: { cpuMs: 60_000, wallMs: WALL_MS } }),
    `the blocking worker's parse at wall ${WALL_MS} ms`,
    liveBlockingWorkers,
  );
  t.diagnostic(`blocking worker, wall ${WALL_MS} ms: the parse call took ${ms(elapsed)} (diagnostic; bound ${DEFAULT_WALL_MS} ms)`);
  stopDiagnostic(t, blocking, 'blocking worker');
  // Checked after the timed window: a wall-time rejection, and no process of the worker left.
  resourceRejection(outcome, 'wall-time', `blocking worker, wall ${WALL_MS} ms (parse call ${ms(elapsed)})`, liveBlockingWorkers);
  assertSandboxGone(BLOCKING_WORKER_REAL, 'blocking worker');
  // The deadline: a kill delayed past one default wall period fails here.
  assert.ok(
    elapsed < DEFAULT_WALL_MS,
    `the configured ${WALL_MS} ms wall limit, not the default, ended the blocking worker: the parse call took ${ms(elapsed)}, bound ${DEFAULT_WALL_MS} ms (one default wall period)`,
  );
});

// --- KILL-RSS and KILL-CPU (A-010): workers that never end by themselves --------------------

const MIB = 1024 * 1024;
const RSS_LIMIT = 96 * MIB;
const RSS_HELD = 128 * MIB;
// Holds RSS_HELD bytes of resident memory outside the V8 heap (a touched Buffer backing store),
// then parks without using CPU, as the blocking worker does.
const rssWorker = writeWorker(
  'rss-worker.mjs',
  `for await (const chunk of process.stdin) void chunk;\nconst held = Buffer.allocUnsafeSlow(${RSS_HELD});\nheld.fill(1);\n${PARK}`,
);
// Burns CPU until a CPU limit ends it; the same self-exit containment, never reached in practice.
const cpuWorker = writeWorker(
  'cpu-worker.mjs',
  `for await (const chunk of process.stdin) void chunk;\nconst end = Date.now() + ${SELF_EXIT_MS};\nwhile (Date.now() < end);\nprocess.exit(75);\n`,
);

test('[PL-11] a worker holding resident memory outside the V8 heap is ended by the RSS limit, and no process of it survives (KILL-RSS)', async (t) => {
  // Only the parent's poller and its kill enforce rssBytes; the launch sets no OS memory limit.
  // A missed trigger lets the worker park until the wall limit, so the detail is wall-time; a
  // missed signal leaves it parked for good, which the hang guard reports.
  assertTimingOrder();
  const holding = createParseServiceForTests({ workerEntry: rssWorker.path });
  const survivors = () => liveWorkersOf(rssWorker.real);
  const { outcome, elapsed } = await timedParse(
    () => holding.parse(Buffer.from('rss-worker input'), { service: { rssBytes: RSS_LIMIT, cpuMs: 60_000, wallMs: DEFAULT_WALL_MS } }),
    `the RSS-holding worker's parse at rssBytes ${RSS_LIMIT / MIB} MiB`,
    survivors,
  );
  t.diagnostic(`RSS-holding worker, rssBytes ${RSS_LIMIT / MIB} MiB: the parse call took ${ms(elapsed)} (diagnostic)`);
  stopDiagnostic(t, holding, 'RSS-holding worker');
  resourceRejection(outcome, 'memory', `RSS ${RSS_LIMIT / MIB} MiB against ${RSS_HELD / MIB} MiB held outside the V8 heap (parse call ${ms(elapsed)})`, survivors);
  assertSandboxGone(rssWorker.real, 'RSS-holding worker');
  assert.ok(elapsed < DEFAULT_WALL_MS, `the RSS limit, not the wall limit, ended the worker: the parse call took ${ms(elapsed)}, bound ${DEFAULT_WALL_MS} ms`);
});

test('[PL-11] a worker burning CPU is ended by the CPU limit, and no process of it survives (KILL-CPU; the limit, not which mechanism)', async (t) => {
  // Two mechanisms can end this worker, and both report cpu: the parent's poller and kill, and
  // the kernel's RLIMIT_CPU backstop (ulimit -t, ceil(cpuMs/1000) + 1 s, inherited through the
  // launcher). This case proves only that the CPU limit ends the child; it claims neither
  // mechanism.
  assertTimingOrder();
  const burning = createParseServiceForTests({ workerEntry: cpuWorker.path });
  const survivors = () => liveWorkersOf(cpuWorker.real);
  const { outcome, elapsed } = await timedParse(
    () => burning.parse(Buffer.from('cpu-worker input'), { service: { cpuMs: 1_000, wallMs: DEFAULT_WALL_MS } }),
    "the CPU-burning worker's parse at cpuMs 1000",
    survivors,
  );
  t.diagnostic(`CPU-burning worker, cpuMs 1000: the parse call took ${ms(elapsed)} (diagnostic)`);
  stopDiagnostic(t, burning, 'CPU-burning worker');
  resourceRejection(outcome, 'cpu', `CPU 1000 ms against a CPU-burning worker (parse call ${ms(elapsed)})`, survivors);
  assertSandboxGone(cpuWorker.real, 'CPU-burning worker');
  assert.ok(elapsed < DEFAULT_WALL_MS, `the CPU limit, not the wall limit, ended the worker: the parse call took ${ms(elapsed)}, bound ${DEFAULT_WALL_MS} ms`);
});

// --- PL-26 (A-010 PL11-ESC): the kill ends the whole owned sandbox ---------------------------

// If it ever runs, it writes a short reply at once and exits, as the real worker does with a
// rejection: so any output after the kill shows that part of the sandbox ran on after it.
const lateWorker = writeWorker('late-worker.mjs', `process.stdout.write(JSON.stringify({ ok: false, reason: 'malformed', detail: 'PL-26 late worker' }) + '\\n');\n`);
// Reads its input, says `started` over fd 3 (the channel seam), then waits without CPU until
// the test closes the channel, and replies. A blocking read; should fd 3 be non-blocking, it
// waits 10 ms between reads (a kernel wait, never a spin). If the test process dies, the
// channel closes with it, so the probe never outlives the test.
const probeWorker = writeWorker(
  'structure-probe.mjs',
  `import { readSync, writeSync } from 'node:fs';
for await (const chunk of process.stdin) void chunk;
writeSync(3, 'started\\n');
const buffer = Buffer.alloc(64);
for (;;) {
  let read;
  try {
    read = readSync(3, buffer, 0, buffer.length, null);
  } catch (error) {
    if (error.code !== 'EAGAIN') throw error;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
    continue;
  }
  if (read === 0) break;
}
process.stdout.write(JSON.stringify({ ok: false, reason: 'malformed', detail: 'PL-26 structure probe' }) + '\\n');
`,
);

test('[PL-26] a kill decided while the sandbox is still starting ends the whole owned sandbox, including start-up that would go on after the decision', async (t) => {
  // A deterministic start-up kill. The hold-startup seam holds the launch at a known point,
  // before the launcher runs, and lets it go on only after the service has signalled its
  // decided kill. The wall budget runs from spawn, so the 300 ms wall limit always decides the
  // kill while start-up is held. PL11-SLOW run 14 motivates the case. OBSERVED there: the
  // namespace init survived the launcher, and output arrived after the launcher's death.
  // INFERRED, not observed: that node ran late, and how it exited.
  assertTimingOrder();
  await assert.rejects(parsePdf(fixtureBytes('single-page.pdf'), { seam: 'hold-startup' }), TypeError, 'parsePdf() never takes a launch seam');
  assert.throws(() => createParseServiceForTests({ seam: 'detach' }), TypeError, 'only the known seams exist');
  const held = createParseServiceForTests({ workerEntry: lateWorker.path, seam: 'hold-startup' });
  const ownProcesses = () => liveProcessesNaming(lateWorker.real);
  const { outcome, elapsed } = await timedParse(
    () => held.parse(Buffer.from('late-worker input'), { service: { cpuMs: 60_000, wallMs: WALL_MS } }),
    `the held start-up's parse at wall ${WALL_MS} ms`,
    ownProcesses,
  );
  t.diagnostic(`held start-up, wall ${WALL_MS} ms: the parse call took ${ms(elapsed)} (diagnostic)`);
  stopDiagnostic(t, held, 'held start-up');
  // Read as soon as the call settles: the held start-up stage, the launcher it would start, the
  // namespace init and the worker all carry the worker's entry, and none may be left.
  assert.deepEqual(ownProcesses(), [], 'the outcome settled only once every process of the sandbox was gone');
  const lifecycles = held.lifecycles();
  assert.equal(lifecycles.length, 1, 'one parse child');
  const [lifecycle] = lifecycles;
  assert.equal(lifecycle.kill, 'wall-time', 'the wall limit decided the kill during start-up');
  assert.equal(
    lifecycle.output_after_kill,
    0,
    `no output arrives after the kill, but ${lifecycle.output_after_kill} byte(s) did: part of the sandbox ran on after the decided kill`,
  );
  assert.equal(lifecycle.orphans_ended, 0, 'the decided kill ended the start-up stage while the launcher was held, not as an orphan');
  resourceRejection(outcome, 'wall-time', `held start-up, wall ${WALL_MS} ms (parse call ${ms(elapsed)})`, ownProcesses);
  assert.ok(elapsed < DEFAULT_WALL_MS, `the kill ended the held start-up within one default wall period: the parse call took ${ms(elapsed)}, bound ${DEFAULT_WALL_MS} ms`);
});

test('[PL-26] a captured child that outlives its launcher is ended through its captured identity, before any limit fires (the orphan path)', async (t) => {
  // The orphan-launcher seam holds start-up as above. As soon as the service has captured the
  // start-up stage (the launcher's child), it kills the launcher alone. The stage, now an
  // orphan, blocks on a channel the service never closes and holds the child's stdio, so the
  // call can only settle once the service has ended it. No limit can do that in time: the wall
  // limit is one default period and the bound below is that same period.
  assertTimingOrder();
  const orphaned = createParseServiceForTests({ workerEntry: lateWorker.path, seam: 'orphan-launcher' });
  const ownProcesses = () => liveProcessesNaming(lateWorker.real);
  // The process-wide orphan count (A-010 request #15), as a before/after delta.
  const orphansBefore = parseOrphans().orphans_ended;
  const { outcome, elapsed } = await timedParse(
    () => orphaned.parse(Buffer.from('late-worker input'), { service: { cpuMs: 60_000, wallMs: DEFAULT_WALL_MS } }),
    "the orphaned start-up stage's parse",
    ownProcesses,
  );
  t.diagnostic(`orphaned start-up stage: the parse call took ${ms(elapsed)} (diagnostic)`);
  assert.deepEqual(ownProcesses(), [], 'the outcome settled only once the orphaned stage was gone');
  const lifecycles = orphaned.lifecycles();
  assert.equal(lifecycles.length, 1, 'one parse child');
  const [lifecycle] = lifecycles;
  assert.equal(lifecycle.kill, null, 'no limit decided a kill: the orphan path, not the wall limit, ended the stage');
  assert.equal(lifecycle.orphans_ended, 1, 'exactly one captured child was ended as an orphan');
  const orphansDelta = parseOrphans().orphans_ended - orphansBefore;
  assert.equal(orphansDelta, lifecycle.orphans_ended, `the process-wide orphan count rose by ${orphansDelta}, as the lifecycle record says (1)`);
  assert.equal(lifecycle.output_after_kill, 0);
  assert.ok(elapsed < DEFAULT_WALL_MS, `the orphan path ended the stage before the wall limit could: the parse call took ${ms(elapsed)}, bound ${DEFAULT_WALL_MS} ms`);
  // The launcher itself was ended by SIGKILL, which the service has always reported as a CPU
  // resource limit (the RLIMIT_CPU backstop's hard kill); unchanged here.
  assert.deepEqual([outcome.status, outcome.reason, outcome.detail], [422, 'resource-limit', 'cpu']);
});

test('[PL-26] the kill reaches the sandbox as launched: the launcher stays in the service process group, its only child is the namespace init, and the worker lives in that namespace', async (t) => {
  // Read from the live tree of a real launch, under each launcher this host can use. The probe
  // worker says `started` over the channel seam and then waits for the test to close it, so the
  // tree is read at a known point. The normal teardown is then checked by properties (A-010
  // request #17), the same under both launchers: (a) the normal outcome; (b) no limit-decided
  // kill; (c) the captured init has terminated by settlement (reaped, or a zombie, which is the
  // service's own settle condition) and is reaped within one default wall period of the channel
  // closing; (d) nothing runnable after settlement; (e) the process-wide orphan count rose by
  // exactly the lifecycle record's ended children. No orphan count is presumed: in a normal bwrap
  // teardown the launcher can exit before its namespace init, which then already has its death
  // signal pending, and the service ends it through its identity (observed, O1).
  const self = procStat(process.pid);
  let checked = 0;
  for (const kind of ['bwrap', 'util-linux']) {
    const probe = createParseServiceForTests({ workerEntry: probeWorker.path, launchers: [kind], seam: 'channel' });
    const plan = await probe.plan();
    if (plan.mode !== 'sandboxed') {
      t.diagnostic(`launcher ${kind}: unavailable here; its structure is not read`);
      continue;
    }
    assert.equal(plan.probe.launcher, kind);
    checked += 1;
    const orphansBefore = parseOrphans().orphans_ended;
    const pending = probe.parse(Buffer.from('structure-probe input'));
    const settledFirst = pending.then((outcome) => {
      throw new assert.AssertionError({ message: `the structure probe's parse settled before its child started: ${outcome.status} ${outcome.reason} ${outcome.detail}` });
    });
    settledFirst.catch(() => {});
    const channel = await withinGuard(Promise.race([probe.nextChannel(), settledFirst]), `the structure probe's launch under ${kind}`);
    let initHandle = null;
    let endedAt = Number.NaN;
    try {
      const line = await withinGuard(readLine(channel, `the structure probe under ${kind}`), `the structure probe's start under ${kind}`);
      assert.equal(line, 'started', `${kind}: fd 3 reaches the worker (it said started over the channel)`);
      const workers = liveWorkersOf(probeWorker.real);
      assert.equal(workers.length, 1, `one live probe worker under ${kind}: [${workers.join(', ')}]`);
      const [worker] = workers;
      const w = procStat(worker);
      const init = kind === 'bwrap' ? w.ppid : worker;
      // A handle on the captured init: it names that one process, and reads fail once it is reaped.
      initHandle = openSync(`/proc/${init}`, 'r');
      const i = procStat(init);
      const launcher = i.ppid;
      const l = procStat(launcher);
      t.diagnostic(
        `${kind}: service ${process.pid} pgrp=${self.pgrp} session=${self.session}; launcher ${launcher} ppid=${l.ppid} pgrp=${l.pgrp} session=${l.session}; ` +
          `init ${init} pgrp=${i.pgrp} session=${i.session} NSpid=${nsPids(init).join('/')}; worker ${worker} pgrp=${w.pgrp} session=${w.session} NSpid=${nsPids(worker).join('/')}`,
      );
      assert.equal(l.ppid, process.pid, `${kind}: the launcher is the service process's own child`);
      assert.deepEqual(
        [l.pgrp, l.session],
        [self.pgrp, self.session],
        `${kind}: the launcher is not detached; it stays in the service process group and session, so group kills and parent death reach it as before`,
      );
      assert.deepEqual(childrenOf(launcher), [init], `${kind}: the launcher's only child is the namespace init`);
      assert.equal(nsPids(init).at(-1), 1, `${kind}: the init is pid 1 of its PID namespace, so its death ends every process in that namespace`);
      const level = nsPids(process.pid).length + 1;
      assert.equal(nsPids(init).length, level, `${kind}: the init is one PID namespace below the service`);
      if (kind === 'bwrap') {
        // Observed (A-010 PL11-ESC structure proof): bwrap runs --new-session in the init, before
        // it forks the worker. The kill does not depend on this; it is recorded as observed.
        assert.deepEqual([i.session, i.pgrp], [init, init], 'under bwrap the init leads its own session and process group (--new-session runs in the init)');
        assert.deepEqual(childrenOf(init), [worker], "under bwrap the worker's parent is the init (its only child)");
        assert.equal(nsPids(worker).length, level, "under bwrap the worker is inside the init's PID namespace");
        assert.notEqual(nsPids(worker).at(-1), 1, 'under bwrap the worker is not the namespace init');
        assert.deepEqual([w.session, w.pgrp], [init, init], "under bwrap the worker is in the init's session and process group");
      } else {
        assert.equal(nsPids(worker).at(-1), 1, 'under util-linux the worker itself is the namespace init');
      }
    } finally {
      endedAt = performance.now();
      channel.end();
    }
    try {
      const outcome = await withinGuard(pending, `the structure probe's parse under ${kind}`);
      // Read at settlement, before anything else.
      const settledMs = performance.now() - endedAt;
      const initAtSettle = handleState(initHandle);
      const sandboxAtSettle = liveProcessesNaming(probeWorker.real);
      const orphansDelta = parseOrphans().orphans_ended - orphansBefore;
      const lifecycle = probe.lifecycles().at(-1);
      let reapedMs = initAtSettle === 'reaped' ? settledMs : Number.NaN;
      while (handleState(initHandle) !== 'reaped' && performance.now() - endedAt < DEFAULT_WALL_MS) await sleep(10);
      if (Number.isNaN(reapedMs) && handleState(initHandle) === 'reaped') reapedMs = performance.now() - endedAt;
      t.diagnostic(
        `${kind}: normal teardown settled ${ms(settledMs)} after the channel closed; captured init at settlement: ${initAtSettle}; ` +
          `reaped by ${ms(reapedMs)}; orphans_ended=${lifecycle?.orphans_ended} (process-wide count +${orphansDelta})`,
      );
      assert.deepEqual([outcome.status, outcome.reason, outcome.detail], [422, 'malformed', 'PL-26 structure probe'], `${kind}: (a) the normal outcome`);
      assert.equal(lifecycle?.kill, null, `${kind}: (b) no limit-decided kill in a normal run`);
      assert.ok(
        ['reaped', 'Z', 'X'].includes(initAtSettle),
        `${kind}: (c, d) the captured init has terminated by settlement and cannot run, but it was in state ${initAtSettle}`,
      );
      assert.deepEqual(sandboxAtSettle, [], `${kind}: (d) when the parse settles, no process of its sandbox (launcher, namespace init, worker) is left`);
      assert.ok(settledMs < DEFAULT_WALL_MS, `${kind}: (c) the normal teardown settled within one default wall period (${ms(settledMs)}, bound ${DEFAULT_WALL_MS} ms)`);
      assert.ok(reapedMs < DEFAULT_WALL_MS, `${kind}: (c) the captured init was reaped within one default wall period of the channel closing (${ms(reapedMs)}, bound ${DEFAULT_WALL_MS} ms)`);
      assert.equal(orphansDelta, lifecycle?.orphans_ended, `${kind}: (e) the process-wide orphan count rose by exactly the lifecycle record's ended children`);
      assert.ok(lifecycle.orphans_ended <= 1, `${kind}: at most the launcher's one captured child was ended`);
    } finally {
      if (initHandle !== null) closeSync(initHandle);
    }
  }
  assert.ok(checked > 0, 'the structure of at least one launcher was read');
});

test('[PL-11] the child runs under the permission model with no write, spawn or worker grant', async () => {
  const outcome = await parsePdf(fixtureBytes('single-page.pdf'));
  assert.equal(outcome.ok, true, outcome.ok ? '' : outcome.detail);
  const { isolation } = outcome.report;
  assert.equal(isolation.permission_model, true);
  assert.equal(isolation.fs_write, false);
  assert.equal(isolation.child_process, false);
  assert.equal(isolation.worker, false);
  assert.ok(isolation.environment.every((name) => name === 'PWD'), `child environment names: ${isolation.environment.join(',')}`);

  const { file, args } = workerCommand(DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS);
  assert.equal(file, '/bin/sh');
  assert.equal(args[3], String(Math.ceil(DEFAULT_SERVICE_LIMITS.cpuMs / 1000) + 1), 'RLIMIT_CPU backstop in seconds');
  const nodeArgs = args.slice(args.indexOf(process.execPath) + 1);
  assert.deepEqual(nodeArgs.slice(0, 4), [
    `--max-old-space-size=${DEFAULT_SERVICE_LIMITS.heapMiB}`,
    '--permission',
    `--allow-fs-read=${PDF_DIR}/`,
    '--disallow-code-generation-from-strings',
  ]);
  assert.equal(nodeArgs[4], WORKER_ENTRY);
  assert.equal(nodeArgs.filter((arg) => arg.startsWith('--allow-')).length, 1, 'read access to src/pdf/ is the only grant');

  // The exact flag set, applied to a probe, denies writes, reads outside src/pdf/, child
  // processes, worker threads and code generation from strings.
  const flags = nodeArgs.slice(0, 4);
  const probe = `
import fs from 'node:fs'; import cp from 'node:child_process'; import { Worker } from 'node:worker_threads';
const out = {};
const attempt = async (name, fn) => { try { await fn(); out[name] = 'allowed'; } catch (error) { out[name] = error.code ?? error.name; } };
await attempt('write', () => fs.writeFileSync(${JSON.stringify(join(tmpdir(), 'opensig-pl11-probe'))}, 'x'));
await attempt('readOutside', () => fs.readFileSync(${JSON.stringify(join(REPO, 'package.json'))}));
await attempt('readInside', () => fs.readFileSync(${JSON.stringify(join(PDF_DIR, 'limits.ts'))}));
await attempt('spawn', () => { const run = cp.spawnSync('true'); if (run.error) throw run.error; });
await attempt('worker', () => new Worker('0', { eval: true }));
await attempt('eval', () => eval('1'));
process.stdout.write(JSON.stringify(out));`;
  const run = spawnSync(process.execPath, [...flags, '--input-type=module', '-e', probe], { cwd: PDF_DIR, env: {}, encoding: 'utf8', timeout: 30_000 });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), {
    write: 'ERR_ACCESS_DENIED',
    readOutside: 'ERR_ACCESS_DENIED',
    readInside: 'allowed',
    spawn: 'ERR_ACCESS_DENIED',
    worker: 'ERR_ACCESS_DENIED',
    eval: 'EvalError',
  });

  // Without the permission model the worker refuses to parse (fails closed).
  const unguarded = spawnSync(process.execPath, [WORKER_ENTRY, '{}'], { input: fixtureBytes('single-page.pdf'), env: {}, encoding: 'utf8', timeout: 30_000 });
  assert.equal(unguarded.status, 70);
  assert.equal(JSON.parse(unguarded.stdout).reason, 'isolation');
});

// --- PL-12 import boundary -----------------------------------------------------------------

const NETWORK_MODULES = ['net', 'http', 'https', 'dns', 'tls', 'dgram', 'http2'];

/** Import specifiers of a source text; non-literal dynamic imports are reported as such. */
function importSpecifiers(source) {
  const found = [];
  const patterns = [
    /\bfrom\s*['"]([^'"]+)['"]/g,
    /\bimport\s*['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) for (const match of source.matchAll(pattern)) found.push(match[1]);
  if (/\bimport\s*\(\s*(?!['"])/.test(source)) found.push('<dynamic import>');
  if (/\b(?:process\.binding|internalBinding|createRequire|process\.dlopen)\b/.test(source)) found.push('<loader escape>');
  return found;
}

function sourceFiles(dir) {
  const files = [];
  for (const name of readdirSync(dir).sort()) {
    const abs = join(dir, name);
    if (statSync(abs).isDirectory()) files.push(...sourceFiles(abs));
    else files.push(abs);
  }
  return files;
}

const bare = (specifier) => specifier.replace(/^node:/, '').split('/')[0];

test('[PL-12] import boundary (defence in depth), not network isolation: src/pdf/ imports no net, http, https, dns, tls or dgram module', () => {
  // The checker itself finds what it must find.
  assert.deepEqual(importSpecifiers(`import net from 'node:net';\nconst h = await import("https");\nexport * from './x.ts';`), ['node:net', './x.ts', 'https']);
  assert.deepEqual(importSpecifiers('const m = await import(name);'), ['<dynamic import>']);

  const files = sourceFiles(PDF_DIR);
  assert.ok(files.length >= 6, 'src/pdf/ sources are present');
  const graph = new Map();
  for (const file of files) {
    assert.match(file, /\.ts$/, `${relative(REPO, file)} is a TypeScript source`);
    const specifiers = importSpecifiers(readFileSync(file, 'utf8'));
    for (const specifier of specifiers) {
      assert.ok(!specifier.startsWith('<'), `${relative(REPO, file)}: ${specifier}`);
      assert.ok(!NETWORK_MODULES.includes(bare(specifier)), `${relative(REPO, file)} imports ${specifier}`);
      if (specifier.startsWith('.')) {
        const target = resolve(dirname(file), specifier);
        assert.ok(target.startsWith(`${PDF_DIR}/`), `${relative(REPO, file)} imports outside src/pdf/: ${specifier}`);
        assert.ok(files.includes(target), `${relative(REPO, file)} imports a missing module: ${specifier}`);
      } else {
        assert.match(specifier, /^node:/, `${relative(REPO, file)} imports a non-builtin package: ${specifier}`);
      }
      assert.doesNotMatch(specifier, /storage|domain\/canonical/, 'lane B code never imports lane A modules');
    }
    graph.set(file, specifiers);
  }

  // The worker's transitive closure (what runs inside the parse child) uses only buffer and zlib.
  const builtins = new Set();
  const seen = new Set();
  const visit = (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    for (const specifier of graph.get(file) ?? []) {
      if (specifier.startsWith('.')) visit(resolve(dirname(file), specifier));
      else builtins.add(specifier);
    }
  };
  visit(WORKER_ENTRY);
  assert.deepEqual([...builtins].sort(), ['node:buffer', 'node:zlib']);
  assert.ok(!seen.has(join(PDF_DIR, 'service.ts')), 'the child never loads the service (child_process)');
});
