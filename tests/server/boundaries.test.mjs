// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-05: request boundaries. The Origin allowlist on mutating requests, the
// loopback default bind, and the Unix-domain-socket relay listener that serves operator
// routes only.
// Amended for the US1 composition (A-010 row WIRE-US1; § Rulings, T008 deviations D1) without
// weakening: each 501 that meant "dispatched to a handler not yet written" is now the
// contract's own boundary outcome from the real handler (an authorized read of an envelope
// absent from the tenant: 404 not_found; a recipient read without a session: 401
// unauthenticated), and each such answer is shown to come from the handler (its request log
// line names the operation), not from the router. The entrypoint is started with the composed
// environment (composedEnv: database, data directory, 0600 key file, spool).

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, lstatSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { loadServerConfig } from '../../src/server/config.ts';
import { startServer } from '../../src/server/main.ts';
import { authFile, bearer, cleanup, composedEnv, ENVELOPE_ID, REPO, send, serveApp, tempDir } from './support.mjs';

/** The request log lines of `lines` (JSON strings) as operation:status, optionally for one listener. */
const handled = (lines, listener) =>
  lines
    .map((line) => JSON.parse(line))
    .filter((record) => record.event === 'request' && (listener === undefined || record.listener === listener))
    .map((record) => `${record.operation}:${record.status}`);

after(cleanup);

const ALLOWED = 'https://sign.alpha.test';

test('[SEC-05] mutating requests must come from an allowlisted origin; no origin is reflected', async () => {
  const served = await serveApp({
    origins: [ALLOWED],
    handlers: {
      createEnvelope: async () => ({ status: 201, json: { created: true } }),
      requestChallenge: async () => ({ status: 202, json: {} }),
      readEnvelope: async () => ({ status: 200, json: { read: true } }),
    },
  });
  try {
    const operator = { authorization: `Bearer ${bearer('sender')}`, 'content-type': 'application/json' };
    const recipientHeaders = { 'content-type': 'application/json' };
    const post = (path, headers) => send(served.port, { method: 'POST', path, headers, body: '{}' });

    assert.equal((await post('/v1/envelopes', { ...operator, origin: ALLOWED })).status, 201, 'allowlisted origin');
    assert.equal((await post('/v1/envelopes', operator)).status, 201, 'operator API clients may omit Origin');
    for (const origin of ['https://evil.example.test', 'null', `${ALLOWED}.evil.example.test`, `${ALLOWED}/`, 'HTTPS://SIGN.ALPHA.TEST', 'http://sign.alpha.test']) {
      const rejected = await post('/v1/envelopes', { ...operator, origin });
      assert.equal(rejected.status, 403, `origin ${origin}`);
      assert.equal(rejected.json.code, 'origin_rejected');
    }
    assert.equal((await post('/v1/recipient-session/challenges', { ...recipientHeaders, origin: ALLOWED })).status, 202);
    const noOrigin = await post('/v1/recipient-session/challenges', recipientHeaders);
    assert.equal(noOrigin.status, 403, 'browser routes must send an Origin');
    assert.equal(noOrigin.json.code, 'origin_rejected');

    // Safe methods are not origin-checked, and no response ever carries CORS headers.
    const read = await send(served.port, { path: `/v1/envelopes/${ENVELOPE_ID}`, headers: { authorization: operator.authorization, origin: 'https://evil.example.test' } });
    assert.equal(read.status, 200);
    for (const response of [read, noOrigin]) {
      for (const name of Object.keys(response.headers)) assert.doesNotMatch(name, /^access-control-/);
    }
  } finally {
    await served.close();
  }
});

test('[SEC-05] the server binds loopback by default and refuses other addresses without an explicit opt-in', async () => {
  const running = await startServer(composedEnv(), { logSink: () => {} });
  try {
    assert.equal(running.host, '127.0.0.1');
    assert.deepEqual([...running.allowedOrigins], [`http://127.0.0.1:${running.port}`], 'the default origin is the server itself');
  } finally {
    await running.close();
  }
  for (const host of ['0.0.0.0', '::', '192.0.2.10', 'opensig.example.test']) {
    assert.throws(() => loadServerConfig({ OPENSIG_HOST: host }), /OPENSIG_HOST is not a loopback address/);
  }
  assert.equal(loadServerConfig({ OPENSIG_HOST: '::1' }).host, '::1');
  assert.equal(loadServerConfig({ OPENSIG_HOST: '192.0.2.10', OPENSIG_ALLOW_NON_LOOPBACK_BIND: '1' }).host, '192.0.2.10', 'explicit opt-in only (not bound here)');
  assert.throws(() => loadServerConfig({ OPENSIG_PORT: '70000' }), /OPENSIG_PORT/);
  assert.throws(() => loadServerConfig({ OPENSIG_ALLOWED_ORIGINS: 'https://sign.alpha.test/path' }), /OPENSIG_ALLOWED_ORIGINS/);
  assert.throws(() => loadServerConfig({ OPENSIG_RELAY_SOCKET: 'relative/socket' }), /OPENSIG_RELAY_SOCKET/);
});

test('[SEC-05] the relay socket is mode 0600 and serves operator routes only', async () => {
  const dir = tempDir('relay');
  const socketPath = join(dir, 'opensig.sock');
  const lines = [];
  const running = await startServer(composedEnv({ OPENSIG_RELAY_SOCKET: socketPath, OPENSIG_OPERATOR_AUTH_FILE: authFile() }), { logSink: (line) => lines.push(line) });
  try {
    const stat = lstatSync(socketPath);
    assert.ok(stat.isSocket());
    assert.equal(stat.mode & 0o777, 0o600);
    const viaSocket = (options) => send(0, { ...options, socketPath });
    assert.equal((await viaSocket({ path: `/v1/envelopes/${ENVELOPE_ID}` })).status, 401, 'operator routes still require a bearer token');
    // WIRE-US1 (was 501): the authorized service request reaches readEnvelope's real handler,
    // which answers the contract's 404 for an envelope absent from the tenant.
    const served = await viaSocket({ path: `/v1/envelopes/${ENVELOPE_ID}`, headers: { authorization: `Bearer ${bearer('service')}` } });
    assert.equal(served.status, 404, 'an authorized service request reaches the handler, which answers 404 for an absent envelope');
    assert.equal(served.json?.code, 'not_found');
    assert.equal(served.json?.correlation_id, served.headers['x-correlation-id']);
    assert.deepEqual(handled(lines, 'relay').slice(-1), ['readEnvelope:404'], 'the 404 is the handler\'s (the request line names the operation), not the router\'s');
    for (const path of ['/sign', '/v1/recipient-session', '/v1/recipient-session/document']) {
      assert.equal((await viaSocket({ path })).status, 404, `${path} is not served on the relay socket`);
    }
    const approve = await viaSocket({ method: 'POST', path: '/v1/recipient-session/approval', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(approve.status, 404, 'approval is unreachable through the relay');
    // WIRE-US1 (was 501): the TCP listener serves recipient routes through T008's handler, whose
    // session guard answers 401 to a request without a session.
    const recipient = await send(running.port, { path: '/v1/recipient-session' });
    assert.equal(recipient.status, 401, 'the TCP listener still serves recipient routes');
    assert.equal(recipient.json?.code, 'unauthenticated');
    assert.deepEqual(handled(lines).slice(-1), ['readRecipientSession:401'], 'the 401 is the handler\'s session guard');
  } finally {
    await running.close();
  }
  assert.equal(existsSync(socketPath), false, 'closing removes the socket file');

  const occupied = join(dir, 'regular-file');
  writeFileSync(occupied, 'not a socket');
  await assert.rejects(startServer(composedEnv({ OPENSIG_RELAY_SOCKET: occupied }), { logSink: () => {} }), /not a socket/);
});

test('[SEC-05] node src/server/main.ts starts on loopback, logs its address and stops on SIGTERM', async () => {
  const child = spawn(process.execPath, [join(REPO, 'src', 'server', 'main.ts')], {
    cwd: REPO,
    env: { PATH: process.env.PATH ?? '', ...composedEnv({ OPENSIG_OPERATOR_AUTH_FILE: authFile() }) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk) => (stderr += chunk));
  const exited = new Promise((resolveExit) => child.on('exit', (code, signal) => resolveExit({ code, signal })));
  try {
    const listening = await new Promise((resolveListening, reject) => {
      const timer = setTimeout(() => reject(new Error(`no listening line within 20 s: ${stderr}`)), 20_000);
      const poll = setInterval(() => {
        const line = stdout.split('\n').find((candidate) => candidate.includes('"event":"listening"'));
        if (line) {
          clearInterval(poll);
          clearTimeout(timer);
          resolveListening(JSON.parse(line));
        }
      }, 25);
    });
    assert.equal(listening.host, '127.0.0.1');
    assert.equal(listening.operator_auth, true);
    const response = await send(listening.port, { path: `/v1/envelopes/${ENVELOPE_ID}`, headers: { authorization: `Bearer ${bearer('sender')}` } });
    // WIRE-US1 (was 501): readEnvelope's real handler, 404 for an envelope absent from the tenant.
    assert.equal(response.status, 404);
    assert.equal(response.json?.code, 'not_found');
    child.kill('SIGTERM');
    assert.deepEqual(await exited, { code: 0, signal: null });
    assert.ok(handled(stdout.split('\n').filter((line) => line.startsWith('{'))).includes('readEnvelope:404'), 'the 404 was the handler\'s');
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }

  const refused = spawn(process.execPath, [join(REPO, 'src', 'server', 'main.ts')], { cwd: REPO, env: { PATH: process.env.PATH ?? '', OPENSIG_HOST: '0.0.0.0', OPENSIG_PORT: '0' } });
  let refusal = '';
  refused.stderr.setEncoding('utf8').on('data', (chunk) => (refusal += chunk));
  const result = await new Promise((resolveExit) => refused.on('exit', (code) => resolveExit(code)));
  assert.equal(result, 1);
  assert.match(refusal, /OPENSIG_HOST is not a loopback address/);
});
