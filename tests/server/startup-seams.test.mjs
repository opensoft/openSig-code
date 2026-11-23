// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-12 (A-010 request #34): the post-composition T031 commit's startup seams.
// - Row DIST-DIR: startServer's optional, test-only `distDir` reaches T035's static handler as
//   createStaticHandler({ config, distDir }); without it the handler gets no distDir, so it keeps
//   its own default (the repository's dist/); and the real entrypoint never sets it. T035's
//   static.ts does not exist yet, so these cases run a byte-identical copy of src/ in a
//   temporary directory with a stand-in static.ts beside the copied main.ts, written at run time:
//   it records what startup passes and serves a stand-in review shell. The stand-in stands in
//   for T035's handler, not for the entrypoint under test, and nothing is written to the
//   repository (its dist/ included).
// - Note 2: App.routes is a read-only property, so it cannot show a registry other than the one
//   the app was built from (dispatch uses a compiled copy made at creation).
// - Row SIGTERM-RACE (A-010 request #54), SEC-12 extended: the entrypoint installs its SIGINT
//   and SIGTERM handlers before startup begins. A SIGTERM sent on the entrypoint's first output
//   line lands before start can finish; it is held, and the server closes once it is running and
//   exits 0. Start is held through the existing static seam: startup imports src/server/static.ts
//   before either listener exists, so a stand-in written into the copy can hold it at its top
//   level until the test releases it, after the signal was sent and before any `listening` line.
// - Row T031RACE-TESTS (A-010 request #55), at this slot's touch of tests/server/ (row
//   ARTIFACT-ROUTES): (1) after the exit check the case asserts that the hold marker was seen, so
//   a head that bypassed the stand-in seam fails it (M-J2); (2) a SIGINT case beside the SIGTERM
//   case; (3) a start failure with a signal sent during it exits 1 with the failure message, and
//   the entrypoint's signal handlers are removed (M-OFF): the failing stand-in keeps the process
//   up after the failure and reports its SIGINT and SIGTERM listener counts on request; (4) the
//   wording says the signal lands before start can finish (the handler runs before the hold).
// Waits are barriers on observable state; the only timers are hang guards.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { copyFileSync, cpSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { pathToFileURL } from 'node:url';

import { ROUTES } from '../../src/api/routes.ts';
import { createParseServiceForTests } from '../../src/pdf/service.ts';
import { createApp } from '../../src/server/app.ts';
import { loadServerConfig } from '../../src/server/config.ts';
import { createLogger } from '../../src/server/redact.ts';
import { call, guarded } from './composed-support.mjs';
import { cleanup, composedEnv, REPO, tempDir } from './support.mjs';

after(cleanup);

/**
 * The bound for the entrypoint's `listening` line: startup settles T033's sandbox plan first,
 * and its probe may take up to 10 s for each of its two launcher kinds.
 */
const LISTENING_BOUND_MS = 60_000;

const STAND_IN_STATIC = `// SPDX-License-Identifier: Apache-2.0
// Stand-in for T035's src/server/static.ts, written at test run time into a temporary copy of
// src/ (SEC-12, row DIST-DIR): it records the options startup passes to createStaticHandler.
import { writeFileSync } from 'node:fs';

export const received = [];

export function createStaticHandler(options) {
  received.push(options);
  const record = { keys: Object.keys(options).sort(), distDir: options.distDir ?? null, configHost: options.config?.host ?? null };
  writeFileSync(new URL('./static-received.json', import.meta.url), JSON.stringify(record));
  return async (ctx) => (ctx.operationId === 'openReviewShell' ? { status: 200, body: Buffer.from('stand-in review shell\\n'), contentType: 'text/html; charset=utf-8' } : null);
}
`;

const STAND_IN_HOLD = `// SPDX-License-Identifier: Apache-2.0
// Stand-in for T035's src/server/static.ts, written at test run time into a temporary copy of
// src/ (SEC-12, row SIGTERM-RACE). Startup imports it before either listener exists, so its top
// level holds start: it writes one marker line, then waits for one chunk on stdin.
await new Promise((resolveRelease) => {
  process.stdin.once('data', () => resolveRelease());
  process.stdout.write('{"event":"test_start_held"}\\n');
});
process.stdin.destroy();

export function createStaticHandler() {
  return async () => null;
}
`;

const STAND_IN_HOLD_FAIL = `// SPDX-License-Identifier: Apache-2.0
// Stand-in for T035's src/server/static.ts, written at test run time into a temporary copy of
// src/ (SEC-12, row T031RACE-TESTS). Its top level holds start until the first stdin chunk, then
// fails start with a configuration-style error. A stdin listener keeps the process up after the
// failure: a chunk holding "count" is answered with the process's SIGINT and SIGTERM listener
// counts, and any other chunk ends stdin, so the process can exit.
class StandInConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StandInConfigError';
  }
}
await new Promise((resolveRelease) => {
  process.stdin.once('data', () => resolveRelease());
  process.stdout.write('{"event":"test_start_held"}\\n');
});
process.stdin.on('data', (chunk) => {
  if (String(chunk).includes('count')) {
    process.stdout.write(JSON.stringify({ event: 'test_signal_listeners', sigint: process.listenerCount('SIGINT'), sigterm: process.listenerCount('SIGTERM') }) + '\\n');
  } else {
    process.stdin.destroy();
  }
});
throw new StandInConfigError('stand-in start failure');
`;

/** A temporary copy of src/ with a stand-in static.ts (default: the recording one) beside the copied main.ts. */
function copiedSource(standIn = STAND_IN_STATIC) {
  const root = tempDir('static-seam');
  cpSync(join(REPO, 'src'), join(root, 'src'), { recursive: true });
  copyFileSync(join(REPO, 'package.json'), join(root, 'package.json'));
  writeFileSync(join(root, 'src', 'server', 'static.ts'), standIn);
  assert.ok(readFileSync(join(root, 'src', 'server', 'main.ts')).equals(readFileSync(join(REPO, 'src', 'server', 'main.ts'))), 'premise: the copied entrypoint is byte-identical to the real one');
  return root;
}

// T033's own plan for an empty launcher set: no probe runs, so the in-process cases start fast.
const unprobedPlan = createParseServiceForTests({ launchers: [] }).plan;

test('[SEC-12] the test-only distDir reaches the static handler as createStaticHandler({ config, distDir }); without it the handler gets none and keeps its default; a relative distDir is refused before anything starts (row DIST-DIR)', async () => {
  const root = copiedSource();
  const { startServer } = await import(pathToFileURL(join(root, 'src', 'server', 'main.ts')).href);
  const standIn = await import(pathToFileURL(join(root, 'src', 'server', 'static.ts')).href);
  const dist = tempDir('dist');

  const lines = [];
  const running = await guarded(startServer(composedEnv(), { logSink: (line) => lines.push(line), parsePlan: unprobedPlan, distDir: dist }), 'startServer with distDir');
  try {
    assert.equal(standIn.received.length, 1, 'startup built the static handler once');
    const given = standIn.received[0];
    assert.equal(given.distDir, dist, 'the distDir option reaches createStaticHandler');
    assert.equal(given.config.host, '127.0.0.1', 'beside the server configuration');
    const listening = lines.map((line) => JSON.parse(line)).find((record) => record.event === 'listening');
    assert.equal(listening?.static_shell, true, 'the listening line reports the static shell');
    const shell = await call(running.port, { path: '/sign' });
    assert.deepEqual([shell.status, shell.bytes.toString('utf8')], [200, 'stand-in review shell\n'], 'the handler createStaticHandler returned serves the review shell');
  } finally {
    await running.close();
  }

  const plain = await guarded(startServer(composedEnv(), { logSink: () => {}, parsePlan: unprobedPlan }), 'startServer without distDir');
  try {
    assert.equal(standIn.received.length, 2);
    assert.equal(standIn.received[1].distDir, undefined, 'without the option the static handler gets no distDir, so it keeps its own default');
    assert.equal(standIn.received[1].config.host, '127.0.0.1');
  } finally {
    await plain.close();
  }

  const env = composedEnv();
  for (const distDir of ['dist', '', 42]) {
    await assert.rejects(startServer(env, { logSink: () => {}, parsePlan: unprobedPlan, distDir }), (error) => error instanceof TypeError && /distDir must be an absolute path/.test(error.message), `distDir ${JSON.stringify(distDir)} is refused`);
  }
  assert.equal(standIn.received.length, 2, 'a refused distDir builds no static handler');
  assert.equal(existsSync(join(env.OPENSIG_DATA_DIR, 'blobs')), false, 'and composes nothing');
});

test('[SEC-12] the real entrypoint never sets distDir: node src/server/main.ts builds the static handler with the configuration only (row DIST-DIR)', async () => {
  const root = copiedSource();
  const received = join(root, 'src', 'server', 'static-received.json');
  const child = spawn(process.execPath, [join(root, 'src', 'server', 'main.ts')], { cwd: root, env: { PATH: process.env.PATH ?? '', ...composedEnv() }, stdio: ['ignore', 'pipe', 'pipe'] });
  const output = { stdout: '', stderr: '' };
  child.stdout.setEncoding('utf8').on('data', (chunk) => (output.stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk) => (output.stderr += chunk));
  const exited = new Promise((resolveExit) => child.on('exit', (code, signal) => resolveExit({ code, signal })));
  try {
    const listening = new Promise((resolveListening, reject) => {
      const check = () => {
        if (!output.stdout.includes('"event":"listening"')) return;
        child.stdout.off('data', check);
        resolveListening();
      };
      child.stdout.on('data', check);
      exited.then(({ code, signal }) => reject(new Error(`the entrypoint exited (${code ?? signal}) before listening; stderr: ${output.stderr}`)));
      check();
    });
    await guarded(listening, 'the entrypoint listening line', LISTENING_BOUND_MS);
    const record = JSON.parse(readFileSync(received, 'utf8'));
    assert.deepEqual(record, { keys: ['config'], distDir: null, configHost: '127.0.0.1' }, 'the entrypoint passes the configuration and no distDir');
    child.kill('SIGTERM');
    const { code, signal } = await guarded(exited, 'the entrypoint exit after SIGTERM');
    assert.deepEqual([code, signal], [0, null], `the entrypoint shuts down cleanly (stderr: ${output.stderr})`);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    rmSync(received, { force: true });
  }
});

/**
 * The entrypoint of a copy of src/ with `standIn` as its static.ts, spawned with the composed
 * environment, with barriers on its output (row SIGTERM-RACE, row T031RACE-TESTS).
 */
function spawnCopied(standIn) {
  const root = copiedSource(standIn);
  const child = spawn(process.execPath, [join(root, 'src', 'server', 'main.ts')], { cwd: root, env: { PATH: process.env.PATH ?? '', ...composedEnv() }, stdio: ['pipe', 'pipe', 'pipe'] });
  const output = { stdout: '', stderr: '' };
  child.stdout.setEncoding('utf8').on('data', (chunk) => (output.stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk) => (output.stderr += chunk));
  child.stdin.on('error', () => {});
  // 'close', not 'exit': it comes once the child has ended and its stdout and stderr are drained.
  const exited = new Promise((resolveExit) => child.on('close', (code, signal) => resolveExit({ code, signal })));
  /** Barrier: the first complete line of `stream` that `matches`, or null once the child has ended without one. */
  const seen = (stream, matches) =>
    new Promise((resolveLine) => {
      const check = () => {
        const line = output[stream].split('\n').slice(0, -1).find(matches);
        if (line === undefined) return;
        child[stream].off('data', check);
        resolveLine(line);
      };
      child[stream].on('data', check);
      exited.then(() => {
        check();
        resolveLine(null);
      });
      check();
    });
  return { child, output, exited, lineSeen: (matches) => seen('stdout', matches), errorSeen: (matches) => seen('stderr', matches) };
}

/** Row SIGTERM-RACE (SIGTERM) and row T031RACE-TESTS (SIGINT): a signal that lands before start can finish is held. */
async function heldSignalCase(signalName) {
  const { child, output, exited, lineSeen } = spawnCopied(STAND_IN_HOLD);
  try {
    // The first line the entrypoint writes: startup has begun, and it cannot finish before the
    // stand-in releases it, so the signal lands before start can finish.
    const first = await guarded(lineSeen(() => true), 'the entrypoint\'s first output line', LISTENING_BOUND_MS);
    assert.notEqual(first, null, `premise: the entrypoint wrote a line before it ended (stderr: ${output.stderr})`);
    child.kill(signalName);
    const held = await guarded(lineSeen((line) => line.includes('"event":"test_start_held"')), 'start held at the static seam', LISTENING_BOUND_MS);
    if (held !== null) {
      assert.equal(output.stdout.includes('"event":"listening"'), false, `premise: the ${signalName} landed before start could finish, before any listening line`);
      child.stdin.end('release');
    }
    const { code, signal } = await guarded(exited, `the entrypoint exit after a ${signalName} that landed during startup`);
    assert.deepEqual([code, signal], [0, null], `the entrypoint holds a ${signalName} sent during startup, then closes and exits 0 (stderr: ${output.stderr})`);
    // T031RACE-TESTS (1): the hold went through the stand-in seam (a head that bypassed it never writes the marker).
    assert.notEqual(held, null, `the start hold marker was seen, so the ${signalName} landed while the stand-in held start`);
    const events = output.stdout
      .split('\n')
      .filter((line) => line.startsWith('{'))
      .map((line) => JSON.parse(line).event);
    assert.ok(events.includes('listening') && events.indexOf('closed') > events.indexOf('listening'), `the server started, then completed its close (events: ${events.join(', ')})`);
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
}

test('[SEC-12] a SIGTERM that arrives during startup is held: node src/server/main.ts, signalled on its first output line so the signal lands before start can finish, closes once it is running and exits 0 (row SIGTERM-RACE)', async () => {
  await heldSignalCase('SIGTERM');
});

test('[SEC-12] a SIGINT that arrives during startup is held the same way: the entrypoint closes once it is running and exits 0 (row T031RACE-TESTS)', async () => {
  await heldSignalCase('SIGINT');
});

test('[SEC-12] a signal sent during a start failure does not turn it into a clean exit: the entrypoint exits 1 with the failure message, and its SIGINT and SIGTERM handlers are removed (row T031RACE-TESTS)', async () => {
  const { child, output, exited, lineSeen, errorSeen } = spawnCopied(STAND_IN_HOLD_FAIL);
  try {
    const first = await guarded(lineSeen(() => true), 'the entrypoint\'s first output line', LISTENING_BOUND_MS);
    assert.notEqual(first, null, `premise: the entrypoint wrote a line before it ended (stderr: ${output.stderr})`);
    child.kill('SIGTERM');
    const held = await guarded(lineSeen((line) => line.includes('"event":"test_start_held"')), 'start held at the static seam', LISTENING_BOUND_MS);
    assert.notEqual(held, null, `premise: the start hold marker was seen (stderr: ${output.stderr})`);
    child.stdin.write('release');
    // The start failure: main() writes its message, removes its handlers and sets exit code 1; the stand-in keeps the process up.
    const failure = await guarded(errorSeen((line) => line.startsWith('opensig: ')), 'the start failure message', LISTENING_BOUND_MS);
    assert.equal(failure, 'opensig: stand-in start failure', `the start failure message (got ${JSON.stringify(failure)})`);
    child.stdin.write('count');
    const counted = await guarded(lineSeen((line) => line.includes('"event":"test_signal_listeners"')), 'the listener counts', LISTENING_BOUND_MS);
    assert.notEqual(counted, null, 'premise: the stand-in reported the listener counts');
    const { sigint, sigterm } = JSON.parse(counted);
    assert.deepEqual({ sigint, sigterm }, { sigint: 0, sigterm: 0 }, `after a start failure no SIGINT or SIGTERM handler remains (SIGINT ${sigint}, SIGTERM ${sigterm})`);
    child.stdin.end('end');
    const { code, signal } = await guarded(exited, 'the entrypoint exit after a start failure');
    assert.deepEqual([code, signal], [1, null], `a start failure exits 1 even with a signal held (got ${code ?? signal})`);
    assert.equal(output.stdout.includes('"event":"listening"'), false, 'nothing listened');
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
});

test('[SEC-12] App.routes is a read-only property over the registry the app was built from: it can be neither reassigned, redefined nor deleted (request #34 note 2)', () => {
  const app = createApp({ routes: ROUTES, config: loadServerConfig({ OPENSIG_PORT: '0' }), logger: createLogger(() => {}), authenticator: null, allowedOrigins: new Set() });
  assert.equal(app.routes, ROUTES, 'it shows the registry itself');
  assert.throws(() => {
    app.routes = [];
  }, TypeError, 'assigning it fails');
  assert.throws(() => Object.defineProperty(app, 'routes', { value: [] }), TypeError, 'redefining it fails');
  assert.throws(() => {
    delete app.routes;
  }, TypeError, 'deleting it fails');
  assert.equal(app.routes, ROUTES, 'it still shows the registry the app was built from');
});
