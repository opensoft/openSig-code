// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-06: the central log redactor. Requests carrying capability values,
// cookies, Authorization headers, webhook secrets and PEM blocks are served and logged,
// and the captured log is grepped for every one of those values. All values are generated
// at test runtime; key material is never written to disk.

import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { after, test } from 'node:test';

import { createLogger, redact, redactText, REDACTED } from '../../src/server/redact.ts';
import { bearer, cleanup, send, serveApp } from './support.mjs';

after(cleanup);

const runtimeSecret = (label) => `${label}${randomBytes(18).toString('base64url')}`;

test('[SEC-06] request and handler logs never contain capability values, cookies, credentials, secrets or PEM blocks', async () => {
  const token = bearer('sender');
  const sessionValue = runtimeSecret('rs');
  const csrf = runtimeSecret('csrf');
  const invitation = runtimeSecret('inv');
  const challengeCode = 'K7Q2M9X4ZP';
  const webhookSecret = runtimeSecret('whsec');
  const queryToken = runtimeSecret('qt');
  const pem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pemBody = pem.split('\n')[1];

  const served = await serveApp({
    origins: ['https://sign.alpha.test'],
    handlers: {
      createEnvelope: async (ctx) => {
        const body = await ctx.json();
        ctx.logger.info('handler_debug', {
          headers: ctx.request.headers,
          body,
          link: `https://sign.alpha.test/sign#i=${invitation}`,
          note: `retrying with Authorization: Bearer ${token}`,
          raw: JSON.stringify(body),
        });
        return { status: 201, json: { created: true } };
      },
      readEnvelope: async () => {
        throw new Error(`could not decrypt webhook key ${webhookSecret} with ${pem}`);
      },
    },
  });
  try {
    const created = await send(served.port, {
      method: 'POST',
      path: `/v1/envelopes?access_token=${queryToken}&code=${challengeCode}`,
      headers: {
        authorization: `Bearer ${token}`,
        cookie: `__Host-opensig_rs=${sessionValue}; theme=dark`,
        'x-csrf-token': csrf,
        'content-type': 'application/json',
        origin: 'https://sign.alpha.test',
      },
      body: JSON.stringify({ webhook_secret: webhookSecret, csrf_token: csrf, invitation, code: challengeCode, signing_key: pem, comment: `key follows ${pem}` }),
    });
    assert.equal(created.status, 201);
    const crashed = await send(served.port, { path: '/v1/envelopes/env_synthetic_00000001', headers: { authorization: `Bearer ${token}` } });
    assert.equal(crashed.status, 500);

    const log = served.logText();
    assert.match(log, /"event":"handler_debug"/, 'the handler log was captured');
    assert.match(log, /"event":"handler_exception"/, 'the exception was logged');
    assert.match(log, /"event":"request"/);
    const secrets = { token, tokenSignature: token.split('.')[2], sessionValue, csrf, invitation, challengeCode, webhookSecret, queryToken, pemBody };
    for (const [label, value] of Object.entries(secrets)) assert.equal(log.includes(value), false, `the log contains no ${label}`);
    assert.doesNotMatch(log, /-----BEGIN|PRIVATE KEY/, 'no PEM block');
    assert.doesNotMatch(log, /eyJ[A-Za-z0-9_-]{8,}\./, 'no JWT-shaped value');
    assert.match(log, /\[REDACTED/, 'redaction markers are present');
    assert.doesNotMatch(log, /access_token=|\?/, 'request paths are logged without query strings');
  } finally {
    await served.close();
  }
});

test('[SEC-06] the redactor scrubs by key at any depth and by value in free text', () => {
  const pem = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const value = runtimeSecret('v');
  const cyclic = { name: 'cycle' };
  cyclic.self = cyclic;
  const out = redact({
    Authorization: `Bearer ${value}`,
    nested: { deeper: [{ Cookie: `a=${value}` }, { 'Set-Cookie': `__Host-opensig_rs=${value}` }] },
    webhook_secret: value,
    client_secret: value,
    api_token: value,
    db_password: value,
    signing_key: value,
    'X-CSRF-Token': value,
    message: `connect with Basic ${Buffer.from(`user:${value}`).toString('base64')}`,
    pemText: `material:\n${pem}`,
    truncatedPem: `-----BEGIN RSA PRIVATE KEY-----\nAAAA${value}`,
    url: `https://sign.alpha.test/sign?token=${value}#i=${value}`,
    jwt: `eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.${value}`,
    bytes: Buffer.from(value),
    error: new Error(`failed with session=${value}`),
    cyclic,
    safe: { status: 'ok', count: 3, error_code: 'not_found' },
  });
  const text = JSON.stringify(out);
  assert.equal(text.includes(value), false, 'no occurrence of the secret value survives');
  assert.doesNotMatch(text, /-----BEGIN|PRIVATE KEY/);
  assert.equal(out.Authorization, REDACTED);
  assert.equal(out.nested.deeper[0].Cookie, REDACTED);
  assert.equal(out.webhook_secret, REDACTED);
  assert.equal(out.bytes, `[bytes ${Buffer.byteLength(value)}]`);
  assert.equal(out.cyclic.self, '[CYCLE]');
  assert.deepEqual(out.safe, { status: 'ok', count: 3, error_code: 'not_found' }, 'ordinary fields are kept');

  assert.equal(redactText(`header line X-CSRF-Token: ${value}`).includes(value), false);
  assert.equal(redactText(`{"webhook_secret":"${value}","code":"K7Q2M9X4ZP","status":"ok"}`), `{"webhook_secret":"${REDACTED}","code":"${REDACTED}","status":"ok"}`);

  const lines = [];
  const logger = createLogger((line) => lines.push(line)).child({ invitation_token: value });
  logger.warn('event', { detail: `Cookie: __Host-opensig_rs=${value}` });
  assert.equal(lines.length, 1);
  const record = JSON.parse(lines[0]);
  assert.equal(record.level, 'warn');
  assert.equal(record.invitation_token, REDACTED);
  assert.equal(lines[0].includes(value), false);
});
