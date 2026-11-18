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

/** A temporary copy of src/ with the stand-in static.ts beside the copied main.ts. */
function copiedSource() {
  const root = tempDir('static-seam');
  cpSync(join(REPO, 'src'), join(root, 'src'), { recursive: true });
  copyFileSync(join(REPO, 'package.json'), join(root, 'package.json'));
  writeFileSync(join(root, 'src', 'server', 'static.ts'), STAND_IN_STATIC);
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
