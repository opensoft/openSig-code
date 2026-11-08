// SPDX-License-Identifier: Apache-2.0
//
// T005 auth: AU-09 role-by-operation matrix and authorization decisions, AU-10 bearer
// tokens only (no operator browser session).

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import * as auth from '../../src/api/auth/index.ts';
import { ALPHA, claimsFor, cleanup, ecHeader, keys, NOW, rsaHeader, signToken, standardConfig } from './support.mjs';

after(cleanup);

// x-opensig-role-matrix of the spec-leg contract (contracts/http-api.yaml, draft 0.2),
// transcribed in contract order. T034 asserts the module against the vendored contract.
const CONTRACT_MATRIX = {
  createEnvelope: { roles: ['sender', 'service'], scopes: ['envelopes:write'] },
  readEnvelope: { roles: ['sender', 'tenant_admin', 'service'], scopes: ['envelopes:read'] },
  uploadDocument: { roles: ['sender', 'service'], scopes: ['envelopes:write'] },
  prepareEnvelope: { roles: ['sender', 'service'], scopes: ['envelopes:write'] },
  readRecipientPreview: { roles: ['sender', 'tenant_admin', 'service'], scopes: ['envelopes:read'] },
  confirmSend: { roles: ['sender', 'tenant_admin'], scopes: ['envelopes:confirm-send'] },
  sendEnvelope: { roles: ['sender', 'service'], scopes: ['envelopes:send'] },
  voidEnvelope: { roles: ['sender', 'tenant_admin'], scopes: ['envelopes:void'] },
  reissueEnvelope: { roles: ['sender', 'tenant_admin'], scopes: ['envelopes:write'] },
  resendInvitation: { roles: ['sender', 'tenant_admin'], scopes: ['envelopes:send'] },
  retryFinalization: { roles: ['tenant_admin'], scopes: ['finalization:retry'] },
  readVerification: { roles: ['sender', 'tenant_admin', 'service'], scopes: ['artifacts:read'] },
  downloadFinalPdf: { roles: ['sender', 'tenant_admin', 'service'], scopes: ['artifacts:read'] },
  downloadPackage: { roles: ['sender', 'tenant_admin', 'service'], scopes: ['artifacts:read'] },
  createWebhookRegistration: { roles: ['tenant_admin'], scopes: ['webhooks:admin'] },
  readWebhookRegistration: { roles: ['tenant_admin'], scopes: ['webhooks:admin'] },
  disableWebhookRegistration: { roles: ['tenant_admin'], scopes: ['webhooks:admin'] },
  rotateWebhookKey: { roles: ['tenant_admin'], scopes: ['webhooks:admin'] },
  revokeWebhookKey: { roles: ['tenant_admin'], scopes: ['webhooks:admin'] },
  openReviewShell: { roles: ['anonymous'], scopes: [] },
  requestChallenge: { roles: ['anonymous'], scopes: [] },
  createRecipientSession: { roles: ['anonymous'], scopes: [] },
  readRecipientSession: { roles: ['recipient'], scopes: [] },
  endRecipientSession: { roles: ['recipient'], scopes: [] },
  readRecipientDocument: { roles: ['recipient'], scopes: [] },
  readRecipientManifest: { roles: ['recipient'], scopes: [] },
  approveAsHuman: { roles: ['recipient'], scopes: [] },
  declineAsRecipient: { roles: ['recipient'], scopes: [] },
};

const authenticator = auth.createOperatorAuthenticator(auth.loadOperatorAuthConfig(standardConfig()));
const principal = (who, overrides) =>
  authenticator.verifyToken(signToken({ header: ecHeader(), payload: claimsFor(ALPHA, who, overrides), privateKey: keys.alphaEc.privateKey }), NOW).principal;

test('[AU-09] the role-by-operation matrix module equals the contract matrix', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(auth.ROLE_MATRIX)), CONTRACT_MATRIX);
  assert.deepEqual(Object.keys(auth.ROLE_MATRIX), Object.keys(CONTRACT_MATRIX), 'contract order');
  assert.ok(Object.isFrozen(auth.ROLE_MATRIX) && Object.isFrozen(auth.ROLE_MATRIX.confirmSend.roles));
  assert.throws(() => {
    'use strict';
    auth.ROLE_MATRIX.confirmSend.roles.push('service');
  }, TypeError);
  for (const operation of Object.keys(CONTRACT_MATRIX)) {
    const { roles } = CONTRACT_MATRIX[operation];
    const scheme = roles.includes('anonymous') ? 'anonymous' : roles.includes('recipient') ? 'recipient' : 'operator';
    assert.equal(auth.operationScheme(operation), scheme, operation);
  }
  for (const unknown of ['approve', '__proto__', 'toString', 'constructor']) {
    assert.throws(() => auth.authorize(unknown, null), TypeError, unknown);
  }
});

test('[AU-09] authorization requires a listed role and every listed scope', () => {
  const people = { sender: principal('sender'), admin: principal('admin'), service: principal('service') };
  for (const [operation, required] of Object.entries(CONTRACT_MATRIX)) {
    for (const [who, actor] of Object.entries(people)) {
      const decision = auth.authorize(operation, actor);
      if (required.roles.includes('anonymous')) {
        assert.deepEqual(decision, { ok: true }, `${who} ${operation}`);
      } else if (required.roles.includes('recipient')) {
        assert.deepEqual(decision, { ok: false, status: 401, code: 'unauthenticated' }, `${who} ${operation}: operator bearer on a recipient route`);
      } else {
        const allowed = actor.roles.some((role) => required.roles.includes(role)) && required.scopes.every((scope) => actor.scopes.includes(scope));
        assert.deepEqual(decision, allowed ? { ok: true } : { ok: false, status: 403, code: 'forbidden' }, `${who} ${operation}`);
      }
    }
  }
  // Decisions the contract names explicitly.
  assert.equal(auth.authorize('confirmSend', people.service).status, 403, 'a service principal calling confirmSend gets 403');
  assert.equal(auth.authorize('approveAsHuman', people.service).status, 401, 'SC002-17: service credential on approve');
  assert.equal(auth.authorize('approveAsHuman', people.sender).status, 401, 'SC002-18: sender bearer on approve');
  assert.equal(auth.authorize('declineAsRecipient', people.admin).status, 401);
  assert.deepEqual(auth.authorize('createEnvelope', people.service), { ok: true });
  assert.deepEqual(auth.authorize('retryFinalization', people.admin), { ok: true });
  assert.equal(auth.authorize('retryFinalization', people.sender).status, 403);
  assert.equal(auth.authorize('createEnvelope', people.admin).status, 403, 'tenant_admin does not create envelopes');
  assert.equal(auth.authorize('createWebhookRegistration', people.service).status, 403);
  // A role without the scope, and a scope without the role, are both refused.
  assert.equal(auth.authorize('voidEnvelope', principal('sender', { scope: 'envelopes:read' })).status, 403);
  assert.equal(auth.authorize('retryFinalization', principal('sender', { scope: 'finalization:retry' })).status, 403);
  assert.equal(auth.authorize('readEnvelope', null).status, 401);
  assert.deepEqual(auth.authorize('openReviewShell', null), { ok: true });
});

test('[AU-10] operators authenticate with an Authorization bearer token only', () => {
  const token = signToken({ header: rsaHeader(), payload: claimsFor(ALPHA), privateKey: keys.alphaRsa.privateKey });
  assert.equal(authenticator.authenticate({ authorization: `Bearer ${token}` }, NOW).ok, true);
  assert.equal(authenticator.authenticate({ authorization: `bearer ${token}` }, NOW).ok, true, 'the scheme name is case-insensitive');
  assert.equal(authenticator.authenticate({ authorization: [`Bearer ${token}`] }, NOW).ok, true);

  // No cookie, query, alternative header or body ever carries an operator credential.
  const elsewhere = [
    {},
    { cookie: `access_token=${token}` },
    { cookie: `__Host-opensig_rs=${token}` },
    { 'x-access-token': token },
    { 'x-forwarded-access-token': token },
    { authorization: '' },
  ];
  for (const headers of elsewhere) {
    const result = authenticator.authenticate(headers, NOW);
    assert.equal(result.ok, false);
    assert.equal(result.status, 401);
    assert.equal(result.reason, 'missing');
    assert.equal(result.wwwAuthenticate, 'Bearer');
  }
  const badHeaders = [
    `Basic ${Buffer.from('alpha-sender-0001:x').toString('base64')}`,
    `Bearer ${token} ${token}`,
    `Bearer${token}`,
    `Token ${token}`,
    token,
  ];
  for (const authorization of badHeaders) {
    const result = authenticator.authenticate({ authorization }, NOW);
    assert.equal(result.reason, 'authorization-scheme');
    assert.equal(result.wwwAuthenticate, 'Bearer error="invalid_token"');
  }
  assert.equal(authenticator.authenticate({ authorization: [`Bearer ${token}`, `Bearer ${token}`] }, NOW).reason, 'authorization-header');

});

test('[AU-10] malformed compact tokens are refused', () => {
  const token = signToken({ header: rsaHeader(), payload: claimsFor(ALPHA), privateKey: keys.alphaRsa.privateKey });
  // Malformed compact tokens.
  const [h, p, s] = token.split('.');
  // A 256-byte RS256 signature ends in a character whose low four bits are padding; setting
  // one makes the encoding non-canonical.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  assert.equal(s.length % 4, 2);
  const nonCanonical = `${s.slice(0, -1)}${alphabet[alphabet.indexOf(s.at(-1)) + 1]}`;
  for (const bad of [`${h}.${p}`, `${h}.${p}.${s}.${s}`, `${h}=.${p}.${s}`, `${h}.${p}.${nonCanonical}`, `${h}.${p}.${s}%`, `${'A'.repeat(8193)}.${p}.${s}`, `${Buffer.from('[1]').toString('base64url')}.${p}.${s}`]) {
    const result = authenticator.verifyToken(bad, NOW);
    assert.equal(result.ok, false);
    assert.ok(['malformed', 'header'].includes(result.reason), `${result.reason}`);
  }

});

test('[AU-10] failures never echo the token and the module offers no session or cookie surface', () => {
  const token = signToken({ header: rsaHeader(), payload: claimsFor(ALPHA), privateKey: keys.alphaRsa.privateKey });
  const [h, p, s] = token.split('.');
  // Failures never echo the token or its claims, and the API offers no session or cookie surface.
  const failure = authenticator.authenticate({ authorization: `Bearer ${h}.${p}.${s.slice(0, -4)}AAAA` }, NOW);
  const rendered = JSON.stringify(failure);
  assert.equal(rendered.includes(p), false);
  assert.equal(rendered.includes(claimsFor(ALPHA).sub), false);
  for (const name of Object.keys(auth)) assert.doesNotMatch(name, /session|cookie|csrf|login/i, `export ${name}`);
});
