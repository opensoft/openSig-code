// SPDX-License-Identifier: Apache-2.0
//
// T005 auth AU-11 and AU-12 (A-008 P11): the tenant's allowed_roles, owned by the
// canonical tenants table, are enforced through an injected TenantPolicy. The policies
// here are plain test objects standing in for the storage-backed policy that the T031
// follow-up wires; the auth module defines no tenant table of its own.
//
// AU-11: a role outside the tenant's allowed_roles grants nothing, so operations that need
// it are denied. AU-12: an unknown tenant (no policy), a malformed policy value or a
// failing policy fails closed with 401.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import * as auth from '../../src/api/auth/index.ts';
import { ALPHA, BETA, claimsFor, cleanup, keys, NOW, rsaHeader, signToken, standardConfig } from './support.mjs';

after(cleanup);

const alphaToken = (who, overrides = {}) => signToken({ header: rsaHeader(), payload: claimsFor(ALPHA, who, overrides), privateKey: keys.alphaRsa.privateKey });
const betaToken = (who) => signToken({ header: rsaHeader('beta-rsa-1'), payload: claimsFor(BETA, who), privateKey: keys.betaRsa.privateKey });

/** A policy over a plain map, recording every lookup. */
function policyOf(table) {
  const lookups = [];
  return {
    lookups,
    allowedRoles(tenantId) {
      lookups.push(tenantId);
      return table[tenantId];
    },
  };
}

function authenticatorWith(tenantPolicy) {
  return auth.createOperatorAuthenticator(auth.loadOperatorAuthConfig(standardConfig()), tenantPolicy === undefined ? {} : { tenantPolicy });
}

const verify = (authenticator, token) => authenticator.verifyToken(token, NOW);

test('[AU-11] a role outside the tenant allowed_roles grants nothing and its operations are denied', () => {
  const policy = policyOf({ [ALPHA.id]: ['tenant_admin'], [BETA.id]: ['sender', 'tenant_admin', 'service'] });
  const authenticator = authenticatorWith(policy);
  assert.equal(authenticator.policy, 'enforced');

  // alpha does not allow sender: a sender token authenticates but holds no role.
  const sender = verify(authenticator, alphaToken('sender'));
  assert.equal(sender.ok, true, sender.reason);
  assert.deepEqual(sender.principal.roles, []);
  for (const operation of ['createEnvelope', 'uploadDocument', 'sendEnvelope', 'readEnvelope', 'confirmSend']) {
    assert.deepEqual(auth.authorize(operation, sender.principal), { ok: false, status: 403, code: 'forbidden' }, operation);
  }
  assert.ok(policy.lookups.every((tenantId) => tenantId === ALPHA.id), 'the policy is asked about the principal tenant');

  // alpha does not allow service: a service principal holds no role either.
  const service = verify(authenticator, alphaToken('service'));
  assert.equal(service.ok, true, service.reason);
  assert.deepEqual(service.principal.roles, []);
  assert.equal(auth.authorize('createEnvelope', service.principal).status, 403);

  // An allowed role keeps working, and only the disallowed role of a mixed token is removed.
  const admin = verify(authenticator, alphaToken('admin'));
  assert.deepEqual(admin.principal.roles, ['tenant_admin']);
  assert.deepEqual(auth.authorize('retryFinalization', admin.principal), { ok: true });
  const mixedClaims = { [ALPHA.oidc.claims.roles]: ['opensig-sender', 'opensig-tenant-admin'] };
  const mixed = verify(authenticator, alphaToken('admin', mixedClaims));
  assert.deepEqual(mixed.principal.roles, ['tenant_admin']);
  assert.deepEqual(auth.authorize('createWebhookRegistration', mixed.principal), { ok: true });
  assert.equal(auth.authorize('createEnvelope', mixed.principal).status, 403, 'sender rights do not leak through a mixed token');
  assert.ok(Object.isFrozen(mixed.principal) && Object.isFrozen(mixed.principal.roles));

  // Another tenant's policy is its own: beta allows sender.
  const beta = verify(authenticator, betaToken('sender'));
  assert.deepEqual(beta.principal.roles, ['sender']);
  assert.deepEqual(auth.authorize('createEnvelope', beta.principal), { ok: true });

  // Controls: a policy allowing every role changes nothing.
  const open = authenticatorWith(policyOf({ [ALPHA.id]: ['sender', 'tenant_admin', 'service'] }));
  assert.deepEqual(verify(open, alphaToken('sender')).principal.roles, ['sender']);
  assert.deepEqual(auth.authorize('createEnvelope', verify(open, alphaToken('sender')).principal), { ok: true });
  assert.deepEqual(verify(open, alphaToken('admin', mixedClaims)).principal.roles, ['sender', 'tenant_admin']);
  const empty = authenticatorWith(policyOf({ [ALPHA.id]: new Set() }));
  assert.deepEqual(verify(empty, alphaToken('admin')).principal.roles, [], 'a tenant with no allowed roles grants nothing');
});

test('[AU-12] an unknown tenant, a malformed policy or a failing policy fails closed', () => {
  const failing = {
    'no policy for the tenant (undefined)': policyOf({}),
    'no policy for the tenant (null)': policyOf({ [ALPHA.id]: null }),
    'an unknown role name': policyOf({ [ALPHA.id]: ['sender', 'superuser'] }),
    'a role name in another case': policyOf({ [ALPHA.id]: ['Sender'] }),
    'a string instead of a list': policyOf({ [ALPHA.id]: 'sender' }),
    'a non-iterable value': policyOf({ [ALPHA.id]: { sender: true } }),
    'a number': policyOf({ [ALPHA.id]: 7 }),
    'more entries than any role list': policyOf({ [ALPHA.id]: Array(17).fill('sender') }),
    'a policy that throws': {
      allowedRoles() {
        throw new Error('synthetic tenants table failure');
      },
    },
  };
  for (const [name, policy] of Object.entries(failing)) {
    const authenticator = authenticatorWith(policy);
    for (const who of ['sender', 'admin', 'service']) {
      const result = verify(authenticator, alphaToken(who));
      assert.equal(result.ok, false, `${name} (${who}) must fail closed`);
      assert.deepEqual([result.status, result.code, result.reason], [401, 'unauthenticated', 'tenant-policy'], name);
      assert.equal(result.wwwAuthenticate, 'Bearer error="invalid_token"');
      assert.equal(result.principal, undefined);
    }
    const viaHeader = authenticator.authenticate({ authorization: `Bearer ${alphaToken('sender')}` }, NOW);
    assert.equal(viaHeader.reason, 'tenant-policy', `${name} via the Authorization header`);
  }

  // A policy object without allowedRoles() is refused when the authenticator is built.
  const config = auth.loadOperatorAuthConfig(standardConfig());
  for (const bad of [null, {}, { allowedRoles: ['sender'] }, 'policy']) {
    assert.throws(() => auth.createOperatorAuthenticator(config, { tenantPolicy: bad }), TypeError);
  }

  // Without a policy the authenticator says so, for the server wiring to refuse (SEC-07).
  assert.equal(authenticatorWith(undefined).policy, 'not-configured');
  assert.equal(authenticatorWith(policyOf({})).policy, 'enforced');
});
