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

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { after, test } from 'node:test';

import { DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS } from '../../src/pdf/limits.ts';
import { createParseServiceForTests, parsePdf, WORKER_ENTRY, workerCommand } from '../../src/pdf/service.ts';
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
const BLOCKING_WORKER = join(scratch, 'blocking-worker.mjs');
writeFileSync(
  BLOCKING_WORKER,
  `for await (const chunk of process.stdin) void chunk;
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ${SELF_EXIT_MS});
process.exit(75);
`,
  { mode: 0o600 },
);
const BLOCKING_WORKER_REAL = realpathSync(BLOCKING_WORKER);

/**
 * Live processes of the blocking worker itself: node (argv[0] is this runtime) running the
 * worker's entry (an exact argv element). The launcher and the sandbox's init carry the entry
 * path only as bind arguments, under their own argv[0], so they never match.
 */
function liveBlockingWorkers() {
  const found = [];
  for (const pid of readdirSync('/proc').filter((name) => /^\d+$/.test(name))) {
    let argv;
    try {
      argv = readFileSync(`/proc/${pid}/cmdline`, 'latin1').split('\0');
    } catch {
      continue;
    }
    if (argv[0] === process.execPath && argv.includes(BLOCKING_WORKER_REAL) && Number(pid) !== process.pid) found.push(Number(pid));
  }
  return found;
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
  // Checked after the timed window: a wall-time rejection, and no process of the worker left.
  resourceRejection(outcome, 'wall-time', `blocking worker, wall ${WALL_MS} ms (parse call ${ms(elapsed)})`, liveBlockingWorkers);
  // The deadline: a kill delayed past one default wall period fails here.
  assert.ok(
    elapsed < DEFAULT_WALL_MS,
    `the configured ${WALL_MS} ms wall limit, not the default, ended the blocking worker: the parse call took ${ms(elapsed)}, bound ${DEFAULT_WALL_MS} ms (one default wall period)`,
  );
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
