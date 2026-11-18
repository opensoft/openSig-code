// SPDX-License-Identifier: Apache-2.0
//
// T004 DV-03: the local dev launcher binds only 127.0.0.1, refuses non-loopback and SMTP
// settings, and starts src/server/main.ts once it exists.
//
// Subprocess cases run a byte-identical copy of scripts/dev.mjs inside a temporary
// repository layout, so they do not depend on whether the real src/server/main.ts exists
// yet. The server entrypoints written there are test doubles that record what the
// launcher handed them; they stand in for T031's server, not for the launcher under test.
// Since DEV-COMPOSE (DV-04) the launcher prepares the database through the storage layer
// before it starts a server, so a layout with an entrypoint links the real src/storage/,
// and the launcher's temporary directory (its per-run key) is a scratch directory here.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { DEFAULT_PORT, LOOPBACK_HOST, resolveDevConfig, serverEnv } from '../../scripts/dev.mjs';

const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const DEV = join(REPO, 'scripts', 'dev.mjs');
const temps = [];
/** The launchers' TMPDIR, so a per-run key directory never lands outside this test's scratch. */
const LAUNCHER_TMP = mkdtempSync(join(tmpdir(), 'opensig-dv03-tmp-'));
temps.push(LAUNCHER_TMP);

after(() => {
  for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

const MARKER_SERVER = `import { writeFileSync } from 'node:fs';
writeFileSync(new URL('../../server-started.marker', import.meta.url), 'started\\n');
`;

const LISTENING_SERVER = `import { createServer } from 'node:net';
const server = createServer((socket) => socket.end('ok\\n'));
server.listen({ host: process.env.OPENSIG_HOST, port: Number(process.env.OPENSIG_PORT) }, () => {
  const address = server.address();
  const env = {};
  for (const key of Object.keys(process.env).sort()) env[key] = key.startsWith('OPENSIG_') || key === 'NODE_ENV' ? process.env[key] : '(set)';
  process.stdout.write('SERVER ' + JSON.stringify({ address: address.address, port: address.port, execArgv: process.execArgv, env }) + '\\n');
});
process.on('SIGTERM', () => server.close(() => process.exit(0)));
`;

/** A temporary repository layout holding a copy of scripts/dev.mjs. */
function layout(serverSource) {
  const root = mkdtempSync(join(tmpdir(), 'opensig-dv03-'));
  temps.push(root);
  mkdirSync(join(root, 'scripts'));
  copyFileSync(DEV, join(root, 'scripts', 'dev.mjs'));
  copyFileSync(join(REPO, '.node-version'), join(root, '.node-version'));
  writeFileSync(join(root, 'package.json'), '{ "private": true, "type": "module" }\n');
  if (serverSource) {
    mkdirSync(join(root, 'src', 'server'), { recursive: true });
    writeFileSync(join(root, 'src', 'server', 'main.ts'), serverSource);
    // The real storage layer: the launcher creates and migrates the database through it (DV-04).
    symlinkSync(join(REPO, 'src', 'storage'), join(root, 'src', 'storage'), 'dir');
  }
  return root;
}

function baseEnv(extra = {}) {
  return { PATH: process.env.PATH ?? '', HOME: tmpdir(), LANG: 'C', TMPDIR: LAUNCHER_TMP, ...extra };
}

function runDev(root, args, extraEnv = {}) {
  return spawnSync(process.execPath, [join(root, 'scripts', 'dev.mjs'), ...args], {
    cwd: root,
    encoding: 'utf8',
    env: baseEnv(extraEnv),
    timeout: 30_000,
  });
}

test('[DV-03] the resolved configuration binds only 127.0.0.1 and hands the server a spool-only environment', () => {
  const defaults = resolveDevConfig({ argv: [], env: {}, root: REPO });
  assert.equal(defaults.ok, true, JSON.stringify(defaults.problems));
  assert.equal(defaults.config.host, LOOPBACK_HOST);
  assert.equal(LOOPBACK_HOST, '127.0.0.1');
  assert.equal(defaults.config.port, DEFAULT_PORT);
  assert.equal(DEFAULT_PORT, 8443);
  assert.equal(defaults.config.mailTransport, 'spool');
  assert.equal(defaults.config.spoolDir, join(REPO, 'var', 'spool'));

  const explicit = resolveDevConfig({ argv: ['--host', '127.0.0.1', '--port', '9000'], env: { OPENSIG_HOST: '127.0.0.1', OPENSIG_MAIL_TRANSPORT: 'spool' }, root: REPO });
  assert.equal(explicit.ok, true, JSON.stringify(explicit.problems));
  assert.equal(explicit.config.port, 9000);
  assert.equal(resolveDevConfig({ env: { OPENSIG_PORT: '9100' }, root: REPO }).config.port, 9100);
  assert.equal(resolveDevConfig({ argv: ['--port', '70000'], root: REPO }).status, 2);
  assert.equal(resolveDevConfig({ env: { OPENSIG_PORT: 'eighty' }, root: REPO }).status, 1);

  const wrongRuntime = resolveDevConfig({ root: REPO, version: 'v24.21.0' });
  assert.equal(wrongRuntime.ok, false);
  assert.equal(wrongRuntime.status, 1);
  assert.match(wrongRuntime.problems.join('\n'), /differs from the pinned v24\.22\.2/);

  const { env, dropped } = serverEnv(defaults.config, {
    PATH: '/usr/bin',
    HOME: '/home/synthetic',
    LC_ALL: 'C',
    OPENSIG_HOST: '127.0.0.1',
    OPENSIG_OIDC_ISSUER: 'https://issuer.alpha.test',
    OPENSIG_HMAC_KEY: 'placeholder-not-a-secret',
    NODE_OPTIONS: '--max-old-space-size=64',
    CLOUD_PROVIDER_CREDENTIAL_ID: 'synthetic-value',
  });
  // OPENSIG_DATABASE is launcher-set since DEV-COMPOSE; the key file only once a run has one (DV-04).
  assert.deepEqual(Object.keys(env).sort(), [
    'HOME',
    'LC_ALL',
    'NODE_ENV',
    'OPENSIG_DATABASE',
    'OPENSIG_DATA_DIR',
    'OPENSIG_ENV',
    'OPENSIG_HOST',
    'OPENSIG_MAIL_TRANSPORT',
    'OPENSIG_OIDC_ISSUER',
    'OPENSIG_PORT',
    'OPENSIG_SPOOL_DIR',
    'PATH',
  ]);
  assert.equal(env.OPENSIG_HOST, '127.0.0.1');
  assert.equal(env.OPENSIG_PORT, '8443');
  assert.equal(env.OPENSIG_MAIL_TRANSPORT, 'spool');
  assert.equal(env.OPENSIG_ENV, 'development');
  assert.deepEqual(dropped, ['OPENSIG_HMAC_KEY'], 'secret-like settings never reach the server environment');
});

test('[DV-03] non-loopback bind addresses and loopback aliases are refused without starting the server', () => {
  const root = layout(MARKER_SERVER);
  const marker = join(root, 'server-started.marker');
  const hosts = ['0.0.0.0', '::', '192.0.2.10', '203.0.113.5', 'opensig.example.com', 'localhost', '::1', '127.0.0.2', '[::1]'];
  for (const host of hosts) {
    for (const [args, env] of [
      [['--host', host], {}],
      [[], { OPENSIG_HOST: host }],
    ]) {
      const run = runDev(root, args, env);
      assert.equal(run.status, 1, `host ${host} via ${args.length ? '--host' : 'OPENSIG_HOST'}: ${run.stderr}`);
      assert.match(run.stderr, /refused: .*binds only 127\.0\.0\.1/);
      assert.equal(existsSync(marker), false, `the server must not start for ${host}`);
    }
  }
  const nonLoopback = runDev(root, ['--host', '0.0.0.0']);
  assert.match(nonLoopback.stderr, /non-loopback bind address/);
  const alias = runDev(root, ['--host', 'localhost']);
  assert.match(alias.stderr, /loopback alias/);
  assert.equal(existsSync(marker), false);
});

test('[DV-03] SMTP and mail-relay settings are refused by name, never echoing their values', () => {
  const root = layout(MARKER_SERVER);
  const marker = join(root, 'server-started.marker');
  const cases = [
    ['OPENSIG_SMTP_HOST', 'smtp.relay.example.com'],
    ['OPENSIG_SMTP_HOST', '127.0.0.1'],
    ['SMTP_URL', 'smtps://relay.example.com:465'],
    ['smtp_port', '2525'],
    ['MAILER_DSN', 'smtp://relay.example.com:587'],
    ['OPENSIG_MAIL_HOST', 'relay.example.com'],
    ['OPENSIG_MAIL_TRANSPORT', 'smtp'],
  ];
  for (const [nameOfSetting, value] of cases) {
    for (const args of [[], ['--check']]) {
      const run = runDev(root, args, { [nameOfSetting]: value });
      assert.equal(run.status, 1, `${nameOfSetting}: ${run.stderr}`);
      assert.ok(run.stderr.includes(`refused: ${nameOfSetting} `), `the refusal names ${nameOfSetting}`);
      assert.equal((run.stdout + run.stderr).includes(value), false, `the value of ${nameOfSetting} is never printed`);
      assert.equal(existsSync(marker), false);
    }
  }
  const spool = runDev(root, ['--check'], { OPENSIG_MAIL_TRANSPORT: 'spool' });
  assert.equal(spool.status, 0, spool.stderr);
  assert.match(spool.stdout, /^dev: mail transport spool -> var\/spool$/m);
});

test('[DV-03] src/server/main.ts is started bound to 127.0.0.1 and termination is forwarded', async () => {
  const root = layout(LISTENING_SERVER);
  const child = spawn(process.execPath, [join(root, 'scripts', 'dev.mjs'), '--port', '0'], {
    cwd: root,
    env: baseEnv({
      OPENSIG_HOST: '127.0.0.1',
      OPENSIG_OIDC_AUDIENCE: 'opensig-local-alpha',
      OPENSIG_WEBHOOK_SECRET: 'placeholder-not-a-secret',
      NODE_OPTIONS: '--max-old-space-size=64',
      UNRELATED_SETTING: 'synthetic',
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk) => (stderr += chunk));
  const exited = new Promise((resolveExit) => child.on('exit', (code, signal) => resolveExit({ code, signal })));
  try {
    const report = await new Promise((resolveReport, reject) => {
      const timer = setTimeout(() => reject(new Error(`no server report within 20 s; stderr: ${stderr}`)), 20_000);
      const poll = setInterval(() => {
        const line = stdout.split('\n').find((candidate) => candidate.startsWith('SERVER '));
        if (line) {
          clearInterval(poll);
          clearTimeout(timer);
          resolveReport(JSON.parse(line.slice('SERVER '.length)));
        } else if (child.exitCode !== null) {
          clearInterval(poll);
          clearTimeout(timer);
          reject(new Error(`launcher exited ${child.exitCode}; stderr: ${stderr}`));
        }
      }, 25);
    });

    assert.match(stdout, /^dev: starting src\/server\/main\.ts on 127\.0\.0\.1:0 \(mail: spool\)$/m);
    assert.equal(report.address, '127.0.0.1', 'the server bound the loopback address it was given');
    assert.ok(report.port > 0);
    assert.deepEqual(report.execArgv, [], 'no node flags reach the server');
    assert.equal(report.env.OPENSIG_HOST, '127.0.0.1');
    assert.equal(report.env.OPENSIG_MAIL_TRANSPORT, 'spool');
    assert.equal(report.env.OPENSIG_SPOOL_DIR, join(root, 'var', 'spool'));
    assert.equal(report.env.OPENSIG_OIDC_AUDIENCE, 'opensig-local-alpha');
    assert.equal(report.env.NODE_ENV, 'development');
    for (const absent of ['NODE_OPTIONS', 'UNRELATED_SETTING', 'OPENSIG_WEBHOOK_SECRET']) assert.equal(absent in report.env, false, `${absent} is not passed`);
    assert.match(stderr, /not passed to the server .*: OPENSIG_WEBHOOK_SECRET$/m);
    assert.equal(stderr.includes('placeholder-not-a-secret'), false);
    assert.equal(statSync(join(root, 'var', 'spool')).mode & 0o777, 0o700);

    const reply = await new Promise((resolveReply, reject) => {
      const socket = connect({ host: '127.0.0.1', port: report.port });
      let data = '';
      socket.setEncoding('utf8').on('data', (chunk) => (data += chunk));
      socket.on('end', () => resolveReply(data));
      socket.on('error', reject);
    });
    assert.equal(reply, 'ok\n', 'the server answers on 127.0.0.1');

    child.kill('SIGTERM');
    const { code, signal } = await exited;
    assert.equal(signal, null);
    assert.equal(code, 0, 'the launcher forwards SIGTERM and returns the server status');
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
});

test('[DV-03] an absent entrypoint starts nothing, unknown flags are usage errors, and no compose file exists', () => {
  const root = layout(null);
  const absent = runDev(root, []);
  assert.equal(absent.status, 3, absent.stderr);
  assert.match(absent.stderr, /src\/server\/main\.ts does not exist yet/);
  assert.equal(existsSync(join(root, 'var')), false, 'nothing is created when nothing starts');

  const check = runDev(root, ['--check']);
  assert.equal(check.status, 0, check.stderr);
  assert.match(check.stdout, /^dev: bind 127\.0\.0\.1:8443$/m);
  assert.match(check.stdout, /^dev: server entrypoint src\/server\/main\.ts absent \(created by T031\)$/m);
  assert.match(check.stdout, /^dev: CHECK OK$/m);

  for (const args of [['--smtp-host', 'relay.example.com'], ['--allow-remote'], ['--port'], ['--port', '1', '--port', '2'], ['--port', 'x']]) {
    const run = runDev(root, args);
    assert.equal(run.status, 2, `${args.join(' ')}: ${run.stderr}`);
    assert.match(run.stderr, /usage error/);
  }

  // The real script, in place, validates the same way (independent of main.ts existing).
  const real = spawnSync(process.execPath, [DEV, '--check'], { cwd: REPO, encoding: 'utf8', env: baseEnv(), timeout: 30_000 });
  assert.equal(real.status, 0, real.stderr);
  assert.match(real.stdout, /^dev: CHECK OK$/m);
  assert.ok(readFileSync(DEV).equals(readFileSync(join(root, 'scripts', 'dev.mjs'))));

  for (const file of ['compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml']) {
    assert.equal(existsSync(join(REPO, file)), false, `${file} is deferred and must not exist`);
  }
});
