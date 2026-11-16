// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits: isolation of the parse child (A-008 rework, A-009 LBR-1 and LBR-3).
//
// PL-13: the parse child cannot reach the network from its sandbox and still parses; the
//   no-launcher branch fails closed, with the explicit development label as the only escape.
// PL-15: unsandboxed parsing needs OPENSIG_PARSER_ALLOW_UNSANDBOXED=1 exactly and no usable
//   launcher; OPENSIG_ENV and NODE_ENV never select it (the T004 dev launcher sets both).
// PL-18: host IPC is unreachable from the sandbox: a pathname AF_UNIX connect fails, and so
//   do TCP, UDP and abstract-socket connects; the root is read-only and hides host paths.
//   Checked for each launcher (bwrap, util-linux) the host provides.
// PL-19: no caller-supplied option can downgrade or relabel the sandbox, and the probe
//   confirms isolation instead of trusting an exit status.
// PL-23 (re-check LBR2-3): /dev in the sandbox root holds only a read-only, nodev /dev/null;
//   nothing in /dev can be created, there is no /dev/shm and no device node can be opened,
//   under each launcher the host provides.
//
// The no-launcher branch is exercised for real: a child driver (sandbox-driver.mjs) runs the
// unmodified service inside an outer user and mount namespace in which the bwrap binary is
// masked with /dev/null and user.max_user_namespaces is 0, so no launcher can run (on a host
// that cannot create that namespace, no launcher can run there either, and the driver runs
// directly). Nothing on the host is changed. All listeners are parent-side and loopback or
// private paths.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { chmodSync, existsSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { resolveDevConfig, serverEnv } from '../../scripts/dev.mjs';
import { DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS } from '../../src/pdf/limits.ts';
import * as service from '../../src/pdf/service.ts';
import { basicObjects, classicPdf } from './pdf-builder.mjs';
import { fixtureBytes, REPO } from './support.mjs';

const FLAG = 'OPENSIG_PARSER_ALLOW_UNSANDBOXED';
const ENFORCED = 'netns+fs-enforced (local)';
const DRIVER = join(REPO, 'tests', 'pdf-parse', 'sandbox-driver.mjs');
const OS_CONNECT_FAILURE = /^error:(?:ENETUNREACH|ECONNREFUSED|EHOSTUNREACH|EADDRNOTAVAIL|EACCES|EPERM|ENOENT)$/;
const PATH_FAILURE = /^error:(?:ENOENT|ECONNREFUSED|EACCES|EPERM)$/;
const LAUNCHER_NAME = /(?:^|\/)(?:bwrap|unshare|chroot|setpriv)(?:$|\s)/;
const REFUSAL = { ok: false, status: 500, code: 'internal', reason: 'sandbox-unavailable', label: 'unavailable' };

const scripts = mkdtempSync(join(tmpdir(), 'opensig-pl18-scripts-'));
const sockets = mkdtempSync(join(tmpdir(), 'opensig-pl18-sockets-'));
chmodSync(sockets, 0o700);
after(() => {
  rmSync(scripts, { recursive: true, force: true });
  rmSync(sockets, { recursive: true, force: true });
});

const settle = () => new Promise((resolveTick) => setTimeout(resolveTick, 150));
const listen = (server, arg) => new Promise((resolveListen, rejectListen) => {
  server.once('error', rejectListen);
  server.listen(arg, () => resolveListen());
});

/** Parent-side listeners: TCP and UDP on 127.0.0.1, an abstract and a pathname AF_UNIX socket. */
async function hostListeners() {
  const counts = { tcp: 0, udp: 0, abstract: 0, path: 0 };
  const tcp = createServer((socket) => {
    counts.tcp += 1;
    socket.destroy();
  });
  await listen(tcp, { host: '127.0.0.1', port: 0 });
  const udp = createSocket('udp4');
  udp.on('message', (message, peer) => {
    counts.udp += 1;
    udp.send(message, peer.port, peer.address);
  });
  await new Promise((resolveBind) => udp.bind(0, '127.0.0.1', resolveBind));
  const abstractName = `opensig-pl18-${process.pid}-${Date.now()}`;
  const abstract = createServer((socket) => {
    counts.abstract += 1;
    socket.destroy();
  });
  await listen(abstract, { path: `\0${abstractName}` });
  const socketPath = join(sockets, `daemon-${process.pid}.sock`);
  const pathname = createServer((socket) => {
    counts.path += 1;
    socket.destroy();
  });
  await listen(pathname, { path: socketPath });
  chmodSync(socketPath, 0o666);
  return {
    targets: { tcp: tcp.address().port, udp: udp.address().port, abstract: abstractName, path: socketPath, socketDir: sockets },
    counts: () => ({ ...counts }),
    close: async () => {
      udp.close();
      await Promise.all([tcp, abstract, pathname].map((server) => new Promise((resolveClose) => server.close(resolveClose))));
    },
  };
}

/** An IPC probe with its targets baked in. mode: 'fs' (plain JSON plus a file-system view) or 'worker' (a parse rejection line). */
function ipcProbe(targets, mode) {
  const file = join(scripts, `ipc-${mode}-${Date.now()}-${Math.random().toString(16).slice(2)}.mjs`);
  writeFileSync(
    file,
    `import { connect } from 'node:net';
import { createSocket } from 'node:dgram';
import * as fs from 'node:fs';
const T = ${JSON.stringify(targets)};
const stream = (options) => new Promise((resolve) => {
  let socket;
  try { socket = connect(options); } catch (error) { resolve('throw:' + (error.code ?? error.name)); return; }
  const timer = setTimeout(() => { socket.destroy(); resolve('timeout'); }, 3000);
  socket.on('connect', () => { clearTimeout(timer); socket.destroy(); resolve('connected'); });
  socket.on('error', (error) => { clearTimeout(timer); resolve('error:' + error.code); });
});
const datagram = () => new Promise((resolve) => {
  let socket;
  try { socket = createSocket('udp4'); } catch (error) { resolve('throw:' + (error.code ?? error.name)); return; }
  const timer = setTimeout(() => { socket.close(); resolve('no-echo'); }, 1500);
  socket.on('message', () => { clearTimeout(timer); socket.close(); resolve('echoed'); });
  socket.on('error', (error) => { clearTimeout(timer); try { socket.close(); } catch {} resolve('error:' + error.code); });
  socket.send(Buffer.from('probe'), T.udp, '127.0.0.1', (error) => { if (error) { clearTimeout(timer); try { socket.close(); } catch {} resolve('error:' + error.code); } });
});
const view = (path) => { try { fs.statSync(path); return 'visible'; } catch (error) { return error.code; } };
const result = { path: await stream({ path: T.path }), tcp: await stream({ host: '127.0.0.1', port: T.tcp }), udp: await datagram(), abstract: await stream({ path: '\\0' + T.abstract }) };
if (${JSON.stringify(mode)} === 'fs') {
  Object.assign(result, { socket_dir: view(T.socketDir), run: view('/run'), proc: view('/proc/self'), etc: view('/etc/passwd') });
  try { fs.writeFileSync('/opensig-pl18', 'x'); result.root_write = 'ok'; } catch (error) { result.root_write = error.code; }
  process.stdout.write(JSON.stringify(result) + '\\n');
} else {
  process.stdout.write(JSON.stringify({ ok: false, reason: 'malformed', detail: 'ipc:' + JSON.stringify(result) }) + '\\n');
}
`,
    { mode: 0o600 },
  );
  return file;
}

/** Run a probe asynchronously, so the parent-side listeners (including the UDP echo) stay live. */
function runJson(file, args) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(file, args, { env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 60_000);
    child.stdout.setEncoding('utf8').on('data', (chunk) => (stdout += chunk));
    child.stderr.setEncoding('utf8').on('data', (chunk) => (stderr += chunk));
    child.on('error', rejectRun);
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) return rejectRun(new Error(`probe exited ${code}: ${stderr}`));
      resolveRun(JSON.parse(stdout.trim().split('\n').at(-1)));
    });
  });
}

function assertIsolated(result, label) {
  assert.match(result.path, PATH_FAILURE, `${label}: a pathname AF_UNIX connect must fail inside the sandbox (got ${result.path})`);
  assert.match(result.tcp, OS_CONNECT_FAILURE, `${label}: TCP (got ${result.tcp})`);
  assert.ok(result.udp === 'no-echo' || OS_CONNECT_FAILURE.test(result.udp), `${label}: UDP (got ${result.udp})`);
  assert.match(result.abstract, OS_CONNECT_FAILURE, `${label}: abstract AF_UNIX (got ${result.abstract})`);
}

let prefix;

/**
 * A command prefix that runs its argument where no sandbox launcher can run, or null when
 * this host cannot build one (no user namespaces: then no launcher can run here either, and
 * every driver run asserts that its plan found none). Each candidate is tried once.
 */
function noLauncherPrefix() {
  if (prefix !== undefined) return prefix;
  const candidates = [];
  const unshare = ['/usr/bin/unshare', '/bin/unshare'].find((path) => existsSync(path));
  const mount = ['/usr/bin/mount', '/bin/mount'].find((path) => existsSync(path));
  if (unshare && mount) {
    const script =
      'echo 0 > /proc/sys/user/max_user_namespaces || exit 90; ' +
      'for t in /usr/bin/bwrap /bin/bwrap; do if [ -e "$t" ]; then "$0" --bind /dev/null "$t" || exit 91; fi; done; exec "$@"';
    candidates.push([unshare, '--user', '--map-root-user', '--mount', '--', '/bin/sh', '-c', script, mount]);
  }
  const bwrap = ['/usr/bin/bwrap', '/bin/bwrap'].find((path) => existsSync(path));
  if (bwrap) candidates.push([bwrap, '--dev-bind', '/', '/', '--ro-bind', '/dev/null', bwrap, '--']);
  const works = (candidate) => spawnSync(candidate[0], [...candidate.slice(1), '/bin/true'], { env: {}, timeout: 30_000 }).status === 0;
  prefix = candidates.find(works) ?? null;
  return prefix;
}

/** Run the driver with exactly `env`, optionally where no launcher can run. */
function drive(env, { restricted }) {
  let file = process.execPath;
  let args = [DRIVER];
  if (restricted) {
    const outer = noLauncherPrefix();
    if (outer !== null) {
      file = outer[0];
      args = [...outer.slice(1), process.execPath, DRIVER];
    }
  }
  const run = spawnSync(file, args, { env, cwd: REPO, encoding: 'utf8', timeout: 120_000 });
  assert.equal(run.status, 0, `driver exited ${run.status}: ${run.stderr}`);
  return JSON.parse(run.stdout.trim().split('\n').at(-1));
}

/** A worker replacement that connects to the parent listener and reports the result. */
function connectChild(port) {
  const file = join(scripts, `connect-${port}-${Date.now()}.mjs`);
  writeFileSync(
    file,
    `import { connect } from 'node:net';
const result = await new Promise((resolve) => {
  const socket = connect(${port}, '127.0.0.1');
  socket.on('connect', () => { socket.destroy(); resolve('connected'); });
  socket.on('error', (error) => resolve('error:' + error.code));
  setTimeout(() => { socket.destroy(); resolve('timeout'); }, 5000).unref();
});
process.stdout.write(JSON.stringify({ ok: false, reason: 'malformed', detail: 'connect:' + result }) + '\\n');
`,
    { mode: 0o600 },
  );
  return file;
}

function noGateClaim(outcome) {
  const text = JSON.stringify(outcome);
  assert.ok(!text.includes('parser-network-sandbox') && !/pass(?:ed)?/i.test(text), 'the outcome never claims the production gate');
}

/** The unsandboxed command: the worker directly under the RLIMIT_CPU shell, no launcher anywhere. */
function assertNoLauncher(command, entry, label) {
  assert.notEqual(command, null, `${label}: an unsandboxed child command exists`);
  assert.equal(command.file, '/bin/sh', `${label}: the RLIMIT_CPU shell, not a launcher`);
  assert.equal(command.args[4], process.execPath, `${label}: node runs directly under the shell`);
  assert.ok(!command.args.some((arg) => LAUNCHER_NAME.test(arg)), `${label}: no launcher in the unsandboxed command`);
  assert.ok(command.args.includes('--permission') && command.args.includes(entry), `${label}: the permission-model worker entry`);
}

/** A driver run in which no launcher is usable and the opt-in is absent or not exactly "1". */
function assertRefusedRun(result, label) {
  assert.equal(result.plan.available, false, `${label}: the restricted child has no usable launcher`);
  assert.deepEqual(result.plan, { mode: 'refused', label: 'unavailable', available: false, launcher: null }, label);
  assert.equal(result.command, null, `${label}: serviceCommand() builds no child command`);
  assert.deepEqual(result.outcome, REFUSAL, label);
  assert.equal(Object.hasOwn(result.full, 'report'), false, `${label}: the refusal carries no report`);
  noGateClaim(result.full);
  // Fail-closed happens before the input is read: an oversized body gets the refusal, not a
  // 413, and a streamed oversized body is never pulled from.
  assert.deepEqual(result.oversized, REFUSAL, `${label}: oversized body refused before it is read`);
  assert.deepEqual(result.oversized_stream, { ...REFUSAL, pulled: 0 }, `${label}: oversized stream never read`);
}

/** A driver run under the explicit development opt-in with no usable launcher. */
function assertDevelopmentRun(result, label) {
  assert.deepEqual(result.plan, { mode: 'unsandboxed', label: 'unavailable', available: false, launcher: null }, label);
  assert.equal(result.worker_entry, service.WORKER_ENTRY, `${label}: the driver ran the service's own worker entry`);
  assertNoLauncher(result.command, result.worker_entry, label);
  assert.deepEqual(result.outcome, { ok: true, status: 200, label: 'unavailable', report_label: 'unavailable' }, label);
  noGateClaim(result.full);
  // Only when a child may run is the body read: the oversized body is the ordinary 413.
  assert.deepEqual([result.oversized.status, result.oversized.reason, result.oversized.label], [413, 'size-limit', 'unavailable'], label);
}

test('[PL-18] host IPC is unreachable from the parse sandbox: pathname, abstract, TCP and UDP connects all fail', async (t) => {
  const host = await hostListeners();
  try {
    const plan = await service.parseServicePlan();
    if (!plan.probe.available) {
      t.diagnostic('no sandbox launcher on this host: asserting the fail-closed production path');
      const refused = await service.parsePdf(classicPdf(basicObjects()));
      assert.equal(refused.reason, process.env[FLAG] === '1' ? undefined : 'sandbox-unavailable');
      return;
    }
    // The service's own launcher around a plain probe (no permission model): sockets and file system view.
    const fsProbe = ipcProbe(host.targets, 'fs');
    const launched = service.sandboxedCommand(plan.probe, process.execPath, [fsProbe], [fsProbe]);
    const inside = await runJson(launched.file, launched.args);
    assertIsolated(inside, `production launcher ${plan.probe.launcher}`);
    // (The probe script itself is bound read-only from a temporary directory, so only the
    // sibling socket directory, not the whole temporary directory, must be absent.)
    for (const key of ['socket_dir', 'run', 'proc', 'etc']) assert.equal(inside[key], 'ENOENT', `${key} is absent from the sandbox root`);
    assert.equal(inside.root_write, 'EROFS', 'the sandbox root is read-only');
    await settle();
    assert.deepEqual(host.counts(), { tcp: 0, udp: 0, abstract: 0, path: 0 }, 'nothing reached a parent-side listener');

    // Unsandboxed control: the same probe reaches every listener.
    const control = await runJson(process.execPath, [fsProbe]);
    assert.deepEqual([control.path, control.tcp, control.udp, control.abstract], ['connected', 'connected', 'echoed', 'connected']);
    await settle();
    assert.deepEqual(host.counts(), { tcp: 1, udp: 1, abstract: 1, path: 1 });

    // Each launcher the host provides, through the exact worker launch (permission model included).
    for (const kind of ['bwrap', 'util-linux']) {
      const probe = service.createParseServiceForTests({ launchers: [kind], workerEntry: ipcProbe(host.targets, 'worker') });
      const kindPlan = await probe.plan();
      if (kindPlan.mode !== 'sandboxed') {
        t.diagnostic(`launcher ${kind}: unavailable here; the narrowed service refuses`);
        assert.equal(kindPlan.mode, 'refused');
        continue;
      }
      t.diagnostic(`launcher ${kind}: ${ENFORCED}`);
      const before = host.counts();
      const outcome = await probe.parse(Buffer.from('synthetic input'));
      assert.match(outcome.detail, /^ipc:/, `${kind}: ${outcome.reason} ${outcome.detail}`);
      assertIsolated(JSON.parse(outcome.detail.slice(4)), `worker launch via ${kind}`);
      assert.equal(outcome.network_sandbox, ENFORCED);
      const direct = service.sandboxedCommand(kindPlan.probe, process.execPath, [fsProbe], [fsProbe]);
      const viaLauncher = await runJson(direct.file, direct.args);
      assertIsolated(viaLauncher, `launcher ${kind}`);
      assert.equal(viaLauncher.root_write, 'EROFS');
      assert.equal(viaLauncher.socket_dir, 'ENOENT');
      await settle();
      assert.deepEqual(host.counts(), before, `${kind}: nothing reached a parent-side listener`);
    }
    assert.equal(plan.network_sandbox, ENFORCED);
  } finally {
    await host.close();
  }
});

test('[PL-13] the parse child cannot reach the network from its sandbox and still parses; without a launcher it fails closed', async (t) => {
  const plan = await service.parseServicePlan();
  const host = await hostListeners();
  try {
    if (plan.probe.available) {
      t.diagnostic(`host branch: ${ENFORCED}, launcher ${plan.probe.launcher}`);
      assert.equal(plan.mode, 'sandboxed');
      assert.equal(plan.network_sandbox, ENFORCED);

      // 1. The service's sandbox launcher: OS-level connect failure inside, success outside.
      const probe = ipcProbe(host.targets, 'fs');
      const launched = service.sandboxedCommand(plan.probe, process.execPath, [probe], [probe]);
      assert.equal(launched.file, plan.probe.tools[plan.probe.launcher === 'bwrap' ? 'bwrap' : 'unshare']);
      const inside = await runJson(launched.file, launched.args);
      assert.match(inside.tcp, OS_CONNECT_FAILURE, `sandboxed probe: ${inside.tcp}`);
      await settle();
      assert.equal(host.counts().tcp, 0, 'nothing reached the parent-side listener from the sandbox');
      const outside = await runJson(process.execPath, [probe]);
      assert.equal(outside.tcp, 'connected', 'the unsandboxed control connects');
      await settle();
      assert.equal(host.counts().tcp, 1);

      // 2. A child launched exactly as the worker is launched cannot connect; run plainly, it can.
      const entry = connectChild(host.targets.tcp);
      const blocked = await service.createParseServiceForTests({ workerEntry: entry }).parse(fixtureBytes('single-page.pdf'));
      assert.equal(blocked.network_sandbox, ENFORCED);
      assert.match(blocked.detail, /^connect:/, `${blocked.reason} ${blocked.detail}`);
      assert.match(blocked.detail.slice('connect:'.length), OS_CONNECT_FAILURE);
      await settle();
      assert.equal(host.counts().tcp, 1, 'the sandboxed child reached nothing');
      const plain = spawnSync(process.execPath, [entry], { env: {}, encoding: 'utf8', timeout: 30_000 });
      assert.equal(JSON.parse(plain.stdout).detail, 'connect:connected', 'control: the same child without the sandbox connects');
      await settle();
      assert.equal(host.counts().tcp, 2);

      // 3. The real worker parses inside the sandbox, under the exact sandboxed command.
      const command = service.serviceCommand(plan, DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS);
      assert.equal(command.file, '/bin/sh');
      assert.equal(command.args[4], launched.file, 'the launcher runs under the RLIMIT_CPU shell');
      assert.ok(command.args.includes('--permission') && command.args.includes(process.execPath));
      assert.ok(command.args.includes(realpathSync(service.WORKER_ENTRY)), 'the sandboxed command runs the real worker entry');
      const parsed = await service.parsePdf(fixtureBytes('agreement-multipage.pdf'));
      assert.equal(parsed.ok, true, parsed.ok ? '' : `${parsed.reason} ${parsed.detail}`);
      assert.equal(parsed.network_sandbox, ENFORCED);
      assert.equal(parsed.report.network_sandbox, ENFORCED);
      assert.ok(parsed.report.pages.length > 1);
      noGateClaim(parsed);
    } else {
      t.diagnostic('host branch: unavailable (no usable sandbox launcher on this host)');
      assert.equal(plan.network_sandbox, 'unavailable');
      assert.notEqual(plan.mode, 'sandboxed');
    }

    // The no-launcher branch, exercised for real in a child where no launcher can run.
    assertRefusedRun(drive({}, { restricted: true }), 'no launcher, no opt-in');
    const development = drive({ [FLAG]: '1' }, { restricted: true });
    assertDevelopmentRun(development, 'no launcher, explicit opt-in');
    t.diagnostic('no-launcher branch: fail-closed and the explicit development label both asserted');
  } finally {
    await host.close();
  }
});

test('[PL-15] unsandboxed parsing needs OPENSIG_PARSER_ALLOW_UNSANDBOXED=1 and no usable launcher; OPENSIG_ENV and NODE_ENV never select it', async () => {
  const dev = resolveDevConfig({ argv: [], env: {} });
  assert.equal(dev.ok, true);
  const launcherEnv = serverEnv(dev.config, {}).env;
  assert.equal(launcherEnv.OPENSIG_ENV, 'development');
  assert.equal(launcherEnv.NODE_ENV, 'development');

  const refusedEnvs = {
    'empty environment': {},
    'OPENSIG_ENV and NODE_ENV set to development': { OPENSIG_ENV: 'development', NODE_ENV: 'development' },
    'the T004 dev launcher environment': launcherEnv,
    'flag "true"': { [FLAG]: 'true' },
    'flag "yes"': { [FLAG]: 'yes' },
    'flag " 1"': { [FLAG]: ' 1' },
    'flag "01"': { [FLAG]: '01' },
    'flag "1\\n"': { [FLAG]: '1\n' },
    'flag empty': { [FLAG]: '' },
    'similar names': { OPENSIG_PARSER_ALLOW_UNSANDBOX: '1', OPENSIG_ALLOW_UNSANDBOXED: '1' },
  };
  for (const [name, env] of Object.entries(refusedEnvs)) assertRefusedRun(drive(env, { restricted: true }), name);

  // The explicit opt-in, with no usable launcher: unsandboxed, labelled unavailable.
  const optIn = drive({ [FLAG]: '1', OPENSIG_ENV: 'production', NODE_ENV: 'production' }, { restricted: true });
  assertDevelopmentRun(optIn, 'explicit opt-in with production names set');

  // serviceCommand() itself: a refused plan has no child command; an unsandboxed plan runs
  // WORKER_ENTRY under the shell with no launcher; the host's own plan matches its mode.
  const limits = [DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS];
  const noProbe = { available: false, launcher: null, tools: {} };
  assert.equal(service.serviceCommand({ mode: 'refused', network_sandbox: 'unavailable', probe: noProbe }, ...limits), null, 'refused: no child command');
  assertNoLauncher(service.serviceCommand({ mode: 'unsandboxed', network_sandbox: 'unavailable', probe: noProbe }, ...limits), service.WORKER_ENTRY, 'unsandboxed plan');
  const hostPlan = await service.parseServicePlan();
  const hostCommand = service.serviceCommand(hostPlan, ...limits);

  // The opt-in never downgrades a host where a launcher works.
  const host = drive({ [FLAG]: '1' }, { restricted: false });
  noGateClaim(host.full);
  if (hostPlan.probe.available) {
    assert.deepEqual([host.plan.mode, host.plan.label, host.outcome.report_label], ['sandboxed', ENFORCED, ENFORCED]);
    const launcher = hostPlan.probe.tools[hostPlan.probe.launcher === 'bwrap' ? 'bwrap' : 'unshare'];
    for (const command of [host.command, hostCommand]) {
      assert.equal(command.file, '/bin/sh');
      assert.equal(command.args[4], launcher, 'the opt-in does not remove the launcher');
      assert.ok(command.args.includes(host.worker_entry_real), 'the sandboxed command runs the real worker entry');
    }
  } else {
    assert.deepEqual([host.plan.mode, host.plan.label], ['unsandboxed', 'unavailable']);
    assertNoLauncher(host.command, host.worker_entry, 'host without a launcher, opt-in set');
    if (hostPlan.mode === 'unsandboxed') assertNoLauncher(hostCommand, service.WORKER_ENTRY, 'this process, opt-in set');
    else assert.equal(hostCommand, null, 'this process, no opt-in: no child command');
  }
});

test('[PL-19] no caller-supplied option can downgrade or relabel the sandbox, and the probe verifies isolation', async () => {
  const pdf = classicPdf(basicObjects());
  // The 245d2c0 seams are gone from parsePdf(): any option other than limits and service is refused.
  for (const options of [
    { runtime: { unshareCandidates: ['/nonexistent/unshare'], env: { [FLAG]: '1' } } },
    { runtime: { unshareCandidates: ['/usr/bin/true'] } },
    { workerEntry: DRIVER },
    { launchers: [] },
    { env: { [FLAG]: '1' } },
  ]) {
    await assert.rejects(service.parsePdf(pdf, options), TypeError, JSON.stringify(Object.keys(options)));
  }

  // The test factory narrows launchers only: an empty set refuses even with the opt-in set,
  // because the host still has a usable launcher; parsePdf() stays sandboxed.
  const hostPlan = await service.parseServicePlan();
  const saved = process.env[FLAG];
  process.env[FLAG] = '1';
  try {
    const narrowed = service.createParseServiceForTests({ launchers: [] });
    const narrowedPlan = await narrowed.plan();
    const narrowedOutcome = await narrowed.parse(pdf);
    const production = await service.parsePdf(pdf);
    if (hostPlan.probe.available) {
      assert.equal(narrowedPlan.mode, 'refused');
      assert.deepEqual([narrowedOutcome.status, narrowedOutcome.reason, narrowedOutcome.network_sandbox], [500, 'sandbox-unavailable', 'unavailable']);
      assert.equal(production.network_sandbox, ENFORCED);
    } else {
      assert.equal(narrowedPlan.mode, 'unsandboxed');
      assert.equal(production.network_sandbox, 'unavailable');
    }
  } finally {
    if (saved === undefined) delete process.env[FLAG];
    else process.env[FLAG] = saved;
  }
  assert.throws(() => service.createParseServiceForTests({ launchers: ['/usr/bin/true'] }), TypeError);
  assert.throws(() => service.createParseServiceForTests({ workerEntry: 'worker.ts' }), TypeError);

  // The probe confirms isolation from inside and from the host; an exit status proves nothing.
  const sandbox = await import('../../src/pdf/sandbox.ts');
  const binds = sandbox.rootBinds([]);
  assert.equal(await sandbox.confirmIsolation('bwrap', () => ({ file: '/usr/bin/true', args: [] }), binds), null, '`true` exits 0 but isolates nothing');
  assert.equal(await sandbox.confirmIsolation('bwrap', (file, args) => ({ file, args }), binds), null, 'no wrapper at all');
  const unshare = ['/usr/bin/unshare', '/bin/unshare'].find((path) => existsSync(path));
  if (unshare) {
    const netOnly = (file, args) => ({ file: unshare, args: ['--user', '--net', '--map-current-user', '--', file, ...args] });
    assert.equal(await sandbox.confirmIsolation('util-linux', netOnly, binds), null, 'the 245d2c0 network-only namespace is not accepted');
  }
  if (hostPlan.probe.available) {
    const evidence = await sandbox.confirmIsolation(hostPlan.probe.launcher, (file, args) => sandbox.launcherCommand(hostPlan.probe, binds, file, args), binds);
    assert.notEqual(evidence, null);
    assert.deepEqual(evidence.capabilities, { effective: '0000000000000000', permitted: '0000000000000000', bounding: '0000000000000000' });
    assert.deepEqual(evidence.namespacesDiffer, { net: true, mnt: true });
    assert.equal(evidence.rootWrite, 'EROFS');
  }
  // The launcher binaries come from a fixed table of absolute paths.
  for (const paths of Object.values(sandbox.TOOL_PATHS)) for (const path of paths) assert.match(path, /^\/(?:usr\/)?s?bin\/[a-z]+$/);
});

test('[PL-23] /dev in the parse sandbox holds only a read-only, nodev /dev/null: not writable, no /dev/shm, under each launcher', async (t) => {
  const file = join(scripts, `dev-${Date.now()}.mjs`);
  writeFileSync(
    file,
    `import * as fs from 'node:fs';
const attempt = (action) => { try { action(); return 'ok'; } catch (error) { return error.code; } };
const result = {
  entries: attempt(() => fs.readdirSync('/dev')) === 'ok' ? fs.readdirSync('/dev').sort() : null,
  create: attempt(() => fs.writeFileSync('/dev/opensig-pl23', 'x')),
  mkdir: attempt(() => fs.mkdirSync('/dev/opensig-pl23-dir')),
  shm: attempt(() => fs.statSync('/dev/shm')),
  shm_create: attempt(() => fs.writeFileSync('/dev/shm/opensig-pl23', 'x')),
  null_write: attempt(() => fs.writeFileSync('/dev/null', 'x')),
  null_read: attempt(() => fs.readFileSync('/dev/null')),
};
process.stdout.write(JSON.stringify(result) + '\\n');
`,
    { mode: 0o600 },
  );
  const hostPlan = await service.parseServicePlan();
  if (!hostPlan.probe.available) {
    t.diagnostic('no sandbox launcher on this host: nothing runs, the service refuses');
    assert.notEqual(hostPlan.mode, 'sandboxed');
    return;
  }
  let checked = 0;
  for (const kind of ['bwrap', 'util-linux']) {
    const kindPlan = await service.createParseServiceForTests({ launchers: [kind] }).plan();
    if (kindPlan.mode !== 'sandboxed') {
      t.diagnostic(`launcher ${kind}: unavailable here`);
      continue;
    }
    const command = service.sandboxedCommand(kindPlan.probe, process.execPath, [file], [file]);
    const dev = await runJson(command.file, command.args);
    t.diagnostic(`launcher ${kind}: ${JSON.stringify(dev)}`);
    assert.deepEqual(dev.entries, ['null'], `${kind}: /dev holds only null`);
    assert.equal(dev.create, 'EROFS', `${kind}: no file can be created in /dev`);
    assert.equal(dev.mkdir, 'EROFS', `${kind}: no directory can be created in /dev`);
    assert.equal(dev.shm, 'ENOENT', `${kind}: there is no /dev/shm`);
    assert.equal(dev.shm_create, 'ENOENT', `${kind}: nothing can be written under /dev/shm`);
    assert.match(dev.null_write, /^(?:EROFS|EACCES|EPERM)$/, `${kind}: /dev/null cannot be opened for writing`);
    assert.match(dev.null_read, /^(?:EACCES|EPERM)$/, `${kind}: /dev/null is nodev, so no device node can be opened`);
    checked += 1;
  }
  assert.ok(checked >= 1, 'at least the launcher the host plan chose was checked');
  // The worker itself still parses inside that root.
  const parsed = await service.parsePdf(classicPdf(basicObjects()));
  assert.equal(parsed.ok, true, parsed.ok ? '' : `${parsed.reason} ${parsed.detail}`);
  assert.equal(parsed.network_sandbox, ENFORCED);
});
