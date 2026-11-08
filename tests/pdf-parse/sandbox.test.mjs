// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-13 and PL-15 (A-008 rework): network isolation of the parse child.
//
// PL-13: where the service's probe finds unprivileged user + network namespaces, a probe
// launched through the service's own sandbox launcher fails to connect to a parent-side
// loopback listener at the OS level while an unsandboxed control connects; a test child
// launched exactly as parsePdf() launches the worker cannot connect either (and connects
// when the sandbox is absent); and the real worker still parses inside the sandbox. Where
// namespaces are unavailable, PL-13 asserts the fail-closed default and the explicit
// development label instead, and reports which branch ran as a test diagnostic.
//
// PL-15: unsandboxed mode needs OPENSIG_PARSER_ALLOW_UNSANDBOXED=1 exactly, and only while
// namespaces are unavailable. OPENSIG_ENV and NODE_ENV never select it, so the T004 dev
// launcher (which always sets both to development) cannot opt in implicitly.
//
// Namespace unavailability is simulated by pointing the probe at a missing unshare binary;
// nothing on the host is changed.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { resolveDevConfig, serverEnv } from '../../scripts/dev.mjs';
import { DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS } from '../../src/pdf/limits.ts';
import * as service from '../../src/pdf/service.ts';
import { fixtureBytes } from './support.mjs';

const dir = mkdtempSync(join(tmpdir(), 'opensig-pl13-'));
after(() => rmSync(dir, { recursive: true, force: true }));

const FLAG = 'OPENSIG_PARSER_ALLOW_UNSANDBOXED';
const NO_NAMESPACES = Object.freeze(['/nonexistent/opensig-unshare']);
const OS_CONNECT_FAILURE = /^error:(?:ENETUNREACH|ECONNREFUSED|EHOSTUNREACH|EACCES|EPERM)$/;

async function loopbackListener() {
  let count = 0;
  const server = createServer((socket) => {
    count += 1;
    socket.destroy();
  });
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  return {
    port: server.address().port,
    count: () => count,
    close: () => new Promise((resolveClose) => server.close(resolveClose)),
  };
}

const settle = () => new Promise((resolveTick) => setTimeout(resolveTick, 100));

/** Script that connects to 127.0.0.1:<port> and prints "connected" or "error:<code>". */
const connectScript = (port) =>
  `const s = require('node:net').connect(${port}, '127.0.0.1');` +
  `s.on('connect', () => { process.stdout.write('connected'); s.destroy(); });` +
  `s.on('error', (e) => process.stdout.write('error:' + e.code));` +
  `setTimeout(() => { process.stdout.write('timeout'); process.exit(0); }, 5000).unref();`;

/** A child entry (launched like the worker) that reports its connect attempt as a rejection detail. */
function connectChild(port) {
  const entry = join(dir, `connect-${port}.mjs`);
  writeFileSync(
    entry,
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
  return entry;
}

function noGateClaim(outcome) {
  const text = JSON.stringify(outcome);
  assert.ok(!text.includes('parser-network-sandbox') && !/pass(?:ed)?/i.test(text), 'the outcome never claims the production gate');
}

test('[PL-13] the parse child cannot reach the network from inside its namespace sandbox, and still parses', async (t) => {
  const plan = await service.parseServicePlan();
  const listener = await loopbackListener();
  try {
    if (plan.probe.available) {
      t.diagnostic(`branch: netns-enforced (local), unshare ${plan.probe.unshare}, mapping ${plan.probe.mapping}`);
      assert.equal(plan.mode, 'sandboxed');
      assert.equal(plan.network_sandbox, 'netns-enforced (local)');

      // 1. The service's sandbox launcher: OS-level connect failure inside, success outside.
      const launched = service.sandboxedCommand(plan.probe, process.execPath, ['-e', connectScript(listener.port)]);
      assert.equal(launched.file, plan.probe.unshare);
      assert.deepEqual(launched.args.slice(0, 4), ['--user', '--net', plan.probe.mapping === 'current-user' ? '--map-current-user' : '--map-root-user', '--']);
      const inside = spawnSync(launched.file, launched.args, { env: {}, encoding: 'utf8', timeout: 30_000 });
      assert.equal(inside.status, 0, inside.stderr);
      assert.match(inside.stdout, OS_CONNECT_FAILURE, `sandboxed probe: ${inside.stdout}`);
      await settle();
      assert.equal(listener.count(), 0, 'nothing reached the parent-side listener from the sandbox');
      const outside = spawnSync(process.execPath, ['-e', connectScript(listener.port)], { env: {}, encoding: 'utf8', timeout: 30_000 });
      assert.equal(outside.stdout, 'connected', 'the unsandboxed control connects');
      await settle();
      assert.equal(listener.count(), 1);

      // 2. A child launched exactly as parsePdf() launches the worker cannot connect ...
      const entry = connectChild(listener.port);
      const blocked = await service.parsePdf(fixtureBytes('single-page.pdf'), { workerEntry: entry });
      assert.equal(blocked.network_sandbox, 'netns-enforced (local)');
      assert.match(blocked.detail, /^connect:/, `${blocked.reason} ${blocked.detail}`);
      assert.match(blocked.detail.slice('connect:'.length), OS_CONNECT_FAILURE);
      await settle();
      assert.equal(listener.count(), 1, 'the sandboxed child reached nothing');
      // ... and the same child connects when the sandbox is absent (explicit development opt-in).
      const open = await service.parsePdf(fixtureBytes('single-page.pdf'), { workerEntry: entry, runtime: { unshareCandidates: NO_NAMESPACES, env: { [FLAG]: '1' } } });
      assert.equal(open.detail, 'connect:connected', 'control: the same child without the sandbox connects');
      assert.equal(open.network_sandbox, 'unavailable');
      await settle();
      assert.equal(listener.count(), 2);

      // 3. The real worker parses inside the sandbox, under the exact sandboxed command.
      const command = service.serviceCommand(plan, DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS);
      assert.equal(command.file, plan.probe.unshare);
      assert.deepEqual(command.args.slice(3, 5), ['--', '/bin/sh']);
      assert.ok(command.args.includes('--permission') && command.args.includes(service.WORKER_ENTRY));
      const parsed = await service.parsePdf(fixtureBytes('agreement-multipage.pdf'));
      assert.equal(parsed.ok, true, parsed.ok ? '' : `${parsed.reason} ${parsed.detail}`);
      assert.equal(parsed.network_sandbox, 'netns-enforced (local)');
      assert.equal(parsed.report.network_sandbox, 'netns-enforced (local)');
      assert.ok(parsed.report.pages.length > 1);
      noGateClaim(parsed);
    } else {
      t.diagnostic('branch: unavailable (no unprivileged user/network namespaces on this host)');
      assert.equal(plan.network_sandbox, 'unavailable');
      const refused = await service.parsePdf(fixtureBytes('single-page.pdf'), { runtime: { env: {} } });
      assert.deepEqual([refused.ok, refused.status, refused.reason, refused.network_sandbox], [false, 500, 'sandbox-unavailable', 'unavailable']);
      const development = await service.parsePdf(fixtureBytes('single-page.pdf'), { runtime: { env: { [FLAG]: '1' } } });
      assert.equal(development.ok, true, development.ok ? '' : development.detail);
      assert.equal(development.report.network_sandbox, 'unavailable');
      noGateClaim(development);
    }
  } finally {
    await listener.close();
  }
});

test('[PL-15] unsandboxed parsing needs OPENSIG_PARSER_ALLOW_UNSANDBOXED=1 and unavailable namespaces; OPENSIG_ENV and NODE_ENV never select it', async () => {
  const input = fixtureBytes('single-page.pdf');
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
    'a similar name': { OPENSIG_PARSER_ALLOW_UNSANDBOX: '1', OPENSIG_ALLOW_UNSANDBOXED: '1' },
  };
  for (const [name, env] of Object.entries(refusedEnvs)) {
    const runtime = { unshareCandidates: NO_NAMESPACES, env };
    const plan = await service.parseServicePlan(runtime);
    assert.deepEqual([plan.mode, plan.network_sandbox, plan.probe.available], ['refused', 'unavailable', false], name);
    assert.equal(service.serviceCommand(plan, DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS), null, `${name}: no child command`);
    const outcome = await service.parsePdf(input, { runtime });
    assert.equal(outcome.ok, false, `${name} must fail closed`);
    assert.deepEqual([outcome.status, outcome.code, outcome.reason, outcome.network_sandbox], [500, 'internal', 'sandbox-unavailable', 'unavailable'], name);
    assert.equal(outcome.report, undefined);
  }
  // Fail-closed happens before the input is read: even an oversized body gets the refusal.
  const oversized = await service.parsePdf(Buffer.alloc(10 * 1024 * 1024 + 1), { runtime: { unshareCandidates: NO_NAMESPACES, env: {} } });
  assert.equal(oversized.reason, 'sandbox-unavailable');

  // The explicit opt-in, with namespaces unavailable: unsandboxed, labelled unavailable.
  const optIn = { unshareCandidates: NO_NAMESPACES, env: { [FLAG]: '1', OPENSIG_ENV: 'production', NODE_ENV: 'production' } };
  const optInPlan = await service.parseServicePlan(optIn);
  assert.deepEqual([optInPlan.mode, optInPlan.network_sandbox], ['unsandboxed', 'unavailable']);
  assert.equal(service.serviceCommand(optInPlan, DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS).file, '/bin/sh', 'no unshare in the command');
  const unsandboxed = await service.parsePdf(input, { runtime: optIn });
  assert.equal(unsandboxed.ok, true, unsandboxed.ok ? '' : `${unsandboxed.reason} ${unsandboxed.detail}`);
  assert.equal(unsandboxed.network_sandbox, 'unavailable');
  assert.equal(unsandboxed.report.network_sandbox, 'unavailable');
  noGateClaim(unsandboxed);

  // The opt-in never downgrades a host where the sandbox works.
  const withFlag = await service.parseServicePlan({ env: { [FLAG]: '1' } });
  if (withFlag.probe.available) {
    assert.deepEqual([withFlag.mode, withFlag.network_sandbox], ['sandboxed', 'netns-enforced (local)']);
    const outcome = await service.parsePdf(input, { runtime: { env: { [FLAG]: '1' } } });
    assert.equal(outcome.report.network_sandbox, 'netns-enforced (local)');
  } else {
    assert.deepEqual([withFlag.mode, withFlag.network_sandbox], ['unsandboxed', 'unavailable']);
  }
});
