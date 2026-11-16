// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-07 (A-008 P11) and SEC-09 (A-009 LBR-6).
//
// SEC-07: with operator authentication configured, the tenant role policy comes from the
// canonical tenants table (read on every request), and the server refuses to start when the
// deployment configuration (OPENSIG_OPERATOR_AUTH_FILE) and the tenants table disagree, or
// when the database is missing, not migrated or not configured.
// SEC-09: startup logs the authenticator's policy state, and never a key, token or secret.
//
// Every database is created at test runtime in a mkdtemp directory with synthetic tenants.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';

import { startServer } from '../../src/server/main.ts';
import { ALPHA, alphaTenantRow, authFile, authInput, bearer, cleanup, ENVELOPE_ID, REPO, send, tempDir, tenantDatabase } from './support.mjs';

after(cleanup);

const retry = (port, who) =>
  send(port, {
    method: 'POST',
    path: `/v1/envelopes/${ENVELOPE_ID}/finalization/retry`,
    headers: { authorization: `Bearer ${bearer(who)}`, 'content-type': 'application/json' },
    body: '{}',
  });

function setAllowedRoles(path, value) {
  const raw = new DatabaseSync(path);
  try {
    raw.prepare('UPDATE tenants SET allowed_roles_json = ? WHERE tenant_id = ?').run(value, ALPHA.id);
  } finally {
    raw.close();
  }
}

test('[SEC-07] the tenant role policy comes from the tenants table, read on every request', async () => {
  const database = tenantDatabase({ [ALPHA.id]: alphaTenantRow(['sender', 'service']) });
  const running = await startServer({ OPENSIG_PORT: '0', OPENSIG_OPERATOR_AUTH_FILE: authFile(), OPENSIG_DATABASE: database }, { logSink: () => {} });
  try {
    // tenant_admin is not an allowed role of the tenant: the role grants nothing.
    const denied = await retry(running.port, 'admin');
    assert.deepEqual([denied.status, denied.json?.code], [403, 'forbidden'], 'a role outside allowed_roles is removed');
    const read = await send(running.port, { path: `/v1/envelopes/${ENVELOPE_ID}`, headers: { authorization: `Bearer ${bearer('sender')}` } });
    assert.equal(read.status, 501, 'an allowed role reaches the (not yet implemented) handler');

    // The table is read per request: allowing tenant_admin applies without a restart ...
    setAllowedRoles(database, JSON.stringify(['sender', 'tenant_admin', 'service']));
    assert.equal((await retry(running.port, 'admin')).status, 501, 'tenant_admin now passes authorization');
    // ... and a malformed value fails closed.
    setAllowedRoles(database, JSON.stringify(['superuser']));
    const closed = await retry(running.port, 'admin');
    assert.deepEqual([closed.status, closed.json?.code], [401, 'unauthenticated']);
  } finally {
    await running.close();
  }
});

test('[SEC-07] the server refuses to start when the configuration and the tenants table disagree', async () => {
  const start = (env) => startServer({ OPENSIG_PORT: '0', OPENSIG_OPERATOR_AUTH_FILE: authFile(), ...env }, { logSink: () => {} });
  const row = (changes) => ({ [ALPHA.id]: { ...alphaTenantRow(), ...changes } });
  const second = 'tenant_beta_synthetic001';
  const cases = {
    'no database configured': [{}, /the tenants table is required/],
    'a database that does not exist': [{ OPENSIG_DATABASE: join(tempDir('db'), 'absent.db') }, /does not exist/],
    'a database that is not migrated': [{ OPENSIG_DATABASE: tenantDatabase({}, { migrate: false }) }, /schema is at version 0/],
    'a configured tenant absent from the table': [{ OPENSIG_DATABASE: tenantDatabase({}) }, new RegExp(`tenant ${ALPHA.id} is configured .* absent from the tenants table`)],
    'a table tenant absent from the configuration': [
      { OPENSIG_DATABASE: tenantDatabase({ [ALPHA.id]: alphaTenantRow(), [second]: { ...alphaTenantRow(), oidc_issuer: 'https://issuer.beta.test' } }) },
      new RegExp(`tenant ${second} is in the tenants table but absent`),
    ],
    'a different issuer': [{ OPENSIG_DATABASE: tenantDatabase(row({ oidc_issuer: 'https://issuer.other.test' })) }, /the issuer differs/],
    'a different audience': [{ OPENSIG_DATABASE: tenantDatabase(row({ oidc_audience: 'opensig-other' })) }, /the audience differs/],
    'a different role claim': [{ OPENSIG_DATABASE: tenantDatabase(row({ role_claim: 'groups' })) }, /the role claim differs/],
    'a different role map': [{ OPENSIG_DATABASE: tenantDatabase(row({ role_map_json: JSON.stringify({ 'opensig-sender': 'tenant_admin' }) })) }, /the role map differs/],
    'a different principal-kind claim': [{ OPENSIG_DATABASE: tenantDatabase(row({ principal_kind_claim: 'kind' })) }, /the principal-kind claim differs/],
    'no principal-kind map in the table': [{ OPENSIG_DATABASE: tenantDatabase(row({ principal_kind_map_json: null })) }, /the principal-kind map differs/],
    'malformed allowed roles': [{ OPENSIG_DATABASE: tenantDatabase(row({ allowed_roles_json: JSON.stringify(['superuser']) })) }, /allowed roles/],
  };
  for (const [label, [env, pattern]] of Object.entries(cases)) {
    let error = null;
    try {
      const running = await start(env);
      await running.close();
    } catch (caught) {
      error = caught;
    }
    assert.ok(error !== null, `${label}: the server must refuse to start`);
    assert.equal(error.name, 'ServerConfigError', label);
    assert.match(error.message, pattern, label);
    assert.doesNotMatch(error.message, /https:\/\/|opensig-other|groups|superuser|alpha-|eyJ/, `${label}: the refusal names fields, never values`);
  }
  assert.equal(existsSync(cases['a database that does not exist'][0].OPENSIG_DATABASE), false, 'a missing database is never created');

  // OPENSIG_DATA_DIR/opensig.db is the default location.
  const dataDir = tempDir('data');
  mkdirSync(dataDir, { recursive: true });
  renameSync(tenantDatabase(), join(dataDir, 'opensig.db'));
  const running = await start({ OPENSIG_DATA_DIR: dataDir });
  await running.close();

  // node src/server/main.ts exits 1 with the refusal and never listens.
  const child = spawn(process.execPath, [join(REPO, 'src', 'server', 'main.ts')], {
    cwd: REPO,
    env: { PATH: process.env.PATH ?? '', OPENSIG_PORT: '0', OPENSIG_OPERATOR_AUTH_FILE: authFile(), OPENSIG_DATABASE: tenantDatabase(row({ oidc_audience: 'opensig-other' })) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => (stdout += chunk));
  child.stderr.setEncoding('utf8').on('data', (chunk) => (stderr += chunk));
  const code = await new Promise((resolveExit) => child.on('exit', (exitCode) => resolveExit(exitCode)));
  assert.equal(code, 1);
  assert.match(stderr, /opensig: operator authentication refused: tenant \S+: the audience differs/);
  assert.doesNotMatch(stdout, /"event":"listening"/);
});

test('[SEC-09] startup logs the authenticator policy state and never a key, token or secret', async () => {
  const lines = [];
  const running = await startServer(
    { OPENSIG_PORT: '0', OPENSIG_OPERATOR_AUTH_FILE: authFile(), OPENSIG_DATABASE: tenantDatabase() },
    { logSink: (line) => lines.push(line) },
  );
  const token = bearer('sender');
  try {
    await send(running.port, { path: `/v1/envelopes/${ENVELOPE_ID}`, headers: { authorization: `Bearer ${token}` } });
  } finally {
    await running.close();
  }
  const records = lines.map((line) => JSON.parse(line));
  const policy = records.find((record) => record.event === 'operator_auth');
  assert.ok(policy, 'an operator_auth line is logged at startup');
  assert.deepEqual(
    { configured: policy.configured, policy: policy.policy, source: policy.policy_source, tenants: policy.tenants },
    { configured: true, policy: 'enforced', source: 'tenants-table', tenants: [ALPHA.id] },
  );
  assert.ok(records.indexOf(policy) < records.findIndex((record) => record.event === 'listening'), 'logged before listening');
  assert.equal(records.find((record) => record.event === 'listening').operator_policy, 'enforced');
  const log = lines.join('\n');
  const jwk = authInput().tenants[0].jwks.keys[0];
  for (const [label, value] of Object.entries({ x: jwk.x, y: jwk.y, token, signature: token.split('.')[2] })) {
    assert.equal(log.includes(value), false, `the log contains no ${label}`);
  }
  assert.doesNotMatch(log, /jwks|"kty"|-----BEGIN|PRIVATE KEY/i);

  // Without operator authentication the state is logged as not configured.
  const bare = [];
  const unconfigured = await startServer({ OPENSIG_PORT: '0' }, { logSink: (line) => bare.push(line) });
  await unconfigured.close();
  const bareRecords = bare.map((line) => JSON.parse(line));
  assert.deepEqual(
    (({ configured, policy: state }) => ({ configured, policy: state }))(bareRecords.find((record) => record.event === 'operator_auth')),
    { configured: false, policy: 'not-configured' },
  );
  assert.equal(bareRecords.find((record) => record.event === 'listening').operator_policy, 'not-configured');
});
