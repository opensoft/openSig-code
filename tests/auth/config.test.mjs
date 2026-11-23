// SPDX-License-Identifier: Apache-2.0
//
// T005 auth: configuration and claim mapping. AU-04 JWKS from configuration only, AU-07
// tenant, roles and scopes from configured claims, AU-08 principal kind and the service
// role restriction.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';

import { ConfigError, createOperatorAuthenticator, loadOperatorAuthConfig } from '../../src/api/auth/index.ts';
import {
  ALPHA,
  BETA,
  claimsFor,
  cleanup,
  ecHeader,
  jwksFile,
  keys,
  NOW,
  publicJwk,
  REPO,
  rsaHeader,
  signToken,
  standardConfig,
  tenantConfig,
} from './support.mjs';

after(cleanup);

const alphaRsa = keys.alphaRsa.privateKey;
const rsaJwks = () => ({ keys: [publicJwk(keys.alphaRsa, 'alpha-rsa-1')] });
const configWith = (tenantOverrides, jwks = rsaJwks()) => ({ tenants: [tenantConfig(ALPHA, jwks, tenantOverrides)] });
const refused = (config, pattern) => assert.throws(() => loadOperatorAuthConfig(config), (error) => error instanceof ConfigError && pattern.test(error.message));

test('[AU-04] verification keys come from configuration only and must be public RSA-2048+ or P-256 keys', () => {
  // Discovery and remote-key settings are not configuration members.
  refused({ tenants: [{ ...tenantConfig(ALPHA, rsaJwks()), jwks_uri: 'https://issuer.alpha.test/jwks' }] }, /unknown member jwks_uri/);
  refused({ tenants: [{ ...tenantConfig(ALPHA, rsaJwks()), discoveryUrl: 'https://issuer.alpha.test/.well-known/openid-configuration' }] }, /unknown member/);
  refused(configWith({}, { keys: [publicJwk(keys.alphaRsa, 'k1', { x5u: 'https://keys.example.test/cert' })] }), /member x5u/);
  refused(configWith({}, { keys: [] }), /non-empty keys/);
  refused(configWith({}, { keys: [{ ...publicJwk(keys.alphaRsa, 'k1') }, { ...publicJwk(keys.alphaEc, 'k1') }] }), /duplicate kid/);
  refused(configWith({}, { keys: [{ ...keys.alphaRsa.publicKey.export({ format: 'jwk' }) }] }), /kid is required/);
  // Private key material is never accepted, even though it would contain the public key.
  refused(configWith({}, { keys: [{ ...keys.alphaRsa.privateKey.export({ format: 'jwk' }), kid: 'k1' }] }), /member d is not allowed/);
  refused(configWith({}, { keys: [{ ...keys.alphaEc.privateKey.export({ format: 'jwk' }), kid: 'k1' }] }), /member d is not allowed/);
  refused(configWith({}, { keys: [{ kty: 'oct', kid: 'k1', k: 'AAAA' }] }), /kty must be RSA or EC/);
  // Weak or off-profile keys and inconsistent key metadata.
  refused(configWith({}, { keys: [publicJwk(keys.weakRsa, 'k1')] }), /at least 2048 bits/);
  refused(configWith({}, { keys: [publicJwk(keys.p384, 'k1')] }), /P-256/);
  refused(configWith({}, { keys: [publicJwk(keys.alphaRsa, 'k1', { use: 'enc' })] }), /use must be sig/);
  refused(configWith({}, { keys: [publicJwk(keys.alphaRsa, 'k1', { key_ops: ['encrypt'] })] }), /key_ops/);
  refused(configWith({}, { keys: [publicJwk(keys.alphaRsa, 'k1', { alg: 'RS512' })] }), /pinned/);
  refused(configWith({}, { keys: [publicJwk(keys.alphaRsa, 'k1', { alg: 'ES256' })] }), /does not match kty/);
  refused(configWith({ algorithms: ['RS256', 'HS256'] }), /algorithms/);
  refused(configWith({ algorithms: [] }), /algorithms/);
  refused(configWith({ issuer: 'http://issuer.alpha.test' }), /https/);
  refused({ tenants: [{ ...tenantConfig(ALPHA, rsaJwks()), jwksFile: '/nonexistent/opensig/jwks.json' }] }, /exactly one/);
  refused(configWith({}, join(dirname(jwksFile(rsaJwks())), 'missing.json')), /not a readable JSON file/);

});

test('[AU-04] a JWKS file is read once at load and never consulted again', () => {
  // A JWKS file is read once at load; authentication never goes back to it.
  const path = jwksFile(rsaJwks());
  const auth = createOperatorAuthenticator(loadOperatorAuthConfig(configWith({}, path)));
  rmSync(path);
  const token = signToken({ header: rsaHeader(), payload: claimsFor(ALPHA), privateKey: alphaRsa });
  assert.equal(auth.verifyToken(token, NOW).ok, true);

});

test('[AU-04] the operator auth modules import no network module and fetch nothing', () => {
  // The operator auth modules import no network module, and lane B code no lane A module.
  const dir = join(REPO, 'src', 'api', 'auth');
  const network = /^(?:node:)?(?:net|http|https|http2|dns|tls|dgram)(?:\/|$)/;
  const owned = ['config.ts', 'index.ts', 'jwks.ts', 'jwt.ts', 'matrix.ts', 'operator.ts'];
  for (const name of readdirSync(dir).filter((file) => file.endsWith('.ts'))) {
    const source = readFileSync(join(dir, name), 'utf8');
    const specifiers = [...source.matchAll(/\bfrom\s*['"]([^'"]+)['"]|\bimport\s*\(\s*['"]([^'"]+)['"]/g)].map((m) => m[1] ?? m[2]);
    for (const specifier of specifiers) {
      assert.doesNotMatch(specifier, network, `${name} imports ${specifier}`);
      if (owned.includes(name)) {
        assert.ok(specifier.startsWith('./') || ['node:crypto', 'node:fs', 'node:buffer'].includes(specifier), `${name} imports ${specifier}`);
      }
    }
    if (owned.includes(name)) assert.doesNotMatch(source, /\bimport\s*\(\s*(?!['"])|fetch\s*\(/, `${name} has no dynamic import or fetch`);
  }
});

test('[AU-07] tenant, roles and scopes come from the configured claims', () => {
  const auth = createOperatorAuthenticator(loadOperatorAuthConfig(standardConfig()));
  const verify = (overrides, header = rsaHeader()) => auth.verifyToken(signToken({ header, payload: claimsFor(ALPHA, 'sender', overrides), privateKey: alphaRsa }), NOW);
  const claimNames = ALPHA.oidc.claims;

  assert.equal(verify({ [claimNames.tenant]: undefined }).reason, 'tenant');
  assert.equal(verify({ [claimNames.tenant]: BETA.id }).reason, 'tenant', 'another tenant id under alpha issuer and key');
  const both = verify({ [claimNames.roles]: 'opensig-sender opensig-tenant-admin' });
  assert.deepEqual(both.principal.roles, ['sender', 'tenant_admin']);
  assert.deepEqual(verify({ [claimNames.roles]: ['opensig-superuser'] }).principal.roles, [], 'unmapped role values grant nothing');
  assert.deepEqual(verify({ [claimNames.roles]: undefined }).principal.roles, []);
  assert.equal(verify({ [claimNames.roles]: [1] }).reason, 'roles');
  assert.deepEqual(verify({ scope: 'envelopes:read  envelopes:read artifacts:read' }).principal.scopes, ['artifacts:read', 'envelopes:read']);
  assert.equal(verify({ scope: { read: true } }).reason, 'scopes');
  assert.deepEqual(verify({ scope: undefined }).principal.scopes, []);

  // Claim names are configuration: an IdP using groups/kind/scp claims maps the same way.
  const custom = createOperatorAuthenticator(
    loadOperatorAuthConfig({
      tenants: [tenantConfig(ALPHA, rsaJwks(), { claims: { tenant: 'org', roles: 'groups', principalKind: 'kind', scope: 'scp' } })],
    }),
  );
  const customToken = signToken({
    header: rsaHeader(),
    payload: { iss: ALPHA.oidc.issuer, aud: ALPHA.oidc.audience, sub: 'alpha-sender-0001', exp: NOW + 60, org: ALPHA.id, groups: ['opensig-sender'], kind: 'human', scp: ['envelopes:read'] },
    privateKey: alphaRsa,
  });
  const customPrincipal = custom.verifyToken(customToken, NOW).principal;
  assert.deepEqual([customPrincipal.roles, customPrincipal.scopes], [['sender'], ['envelopes:read']]);
  assert.equal(custom.verifyToken(signToken({ header: rsaHeader(), payload: claimsFor(ALPHA), privateKey: alphaRsa }), NOW).reason, 'tenant');

});

test('[AU-07] tenants sharing an issuer are told apart by the verified tenant claim', () => {
  const claimNames = ALPHA.oidc.claims;
  // Two tenants behind one issuer are told apart by the tenant claim, after verification.
  const shared = { keys: [publicJwk(keys.alphaRsa, 'shared-1')] };
  const gamma = { ...BETA, id: 'tenant_gamma_synthetic01', oidc: { ...BETA.oidc, issuer: ALPHA.oidc.issuer, audience: ALPHA.oidc.audience } };
  const sharedAuth = createOperatorAuthenticator(loadOperatorAuthConfig({ tenants: [tenantConfig(ALPHA, shared), tenantConfig(gamma, shared)] }));
  const forGamma = signToken({ header: rsaHeader('shared-1'), payload: claimsFor(ALPHA, 'sender', { [claimNames.tenant]: gamma.id }), privateKey: alphaRsa });
  assert.equal(sharedAuth.verifyToken(forGamma, NOW).principal.tenant_id, gamma.id);
  const forAlpha = signToken({ header: rsaHeader('shared-1'), payload: claimsFor(ALPHA), privateKey: alphaRsa });
  assert.equal(sharedAuth.verifyToken(forAlpha, NOW).principal.tenant_id, ALPHA.id);
  const withoutClaims = (tenant) => ({ ...tenantConfig(tenant, shared), claims: { roles: 'opensig_roles', principalKind: 'opensig_principal_kind' } });
  refused({ tenants: [withoutClaims(ALPHA), withoutClaims(gamma)] }, /sharing issuer/);
  refused({ tenants: [tenantConfig(ALPHA, shared), tenantConfig(ALPHA, shared)] }, /duplicate tenantId|sharing issuer/);
});

test('[AU-08] principal kind is mapped from its claim and a service principal never holds sender or tenant_admin', () => {
  const auth = createOperatorAuthenticator(loadOperatorAuthConfig(standardConfig()));
  const claimNames = ALPHA.oidc.claims;
  const verify = (who, overrides) =>
    auth.verifyToken(signToken({ header: ecHeader(), payload: claimsFor(ALPHA, who, overrides), privateKey: keys.alphaEc.privateKey }), NOW);

  assert.equal(verify('sender').principal.kind, 'human-operator');
  assert.equal(verify('service').principal.kind, 'service');
  for (const kind of [undefined, 'robot', ['service'], 1]) assert.equal(verify('sender', { [claimNames.principal_kind]: kind }).reason, 'principal-kind');

  for (const roles of [['opensig-sender'], ['opensig-tenant-admin'], ['opensig-service', 'opensig-sender'], 'opensig-service opensig-tenant-admin']) {
    assert.equal(verify('service', { [claimNames.roles]: roles }).reason, 'service-role-conflict', `service with ${roles}`);
  }
  assert.equal(verify('sender', { [claimNames.roles]: ['opensig-sender', 'opensig-service'] }).reason, 'human-role-conflict');
  assert.deepEqual(verify('service', { [claimNames.roles]: [] }).principal.roles, [], 'a service principal without roles holds nothing');
  assert.equal(verify('sender', { sub: undefined }).reason, 'subject');
  assert.equal(verify('sender', { sub: '' }).reason, 'subject');

  refused(configWith({ kindMap: { human: 'administrator' } }), /kindMap/);
  refused(configWith({ roleMap: { 'opensig-root': 'superuser' } }), /roleMap/);
  refused(configWith({ roleMap: { 'opensig-recipient': 'recipient' } }), /roleMap/);
  refused(configWith({ kindMap: {} }), /kindMap must not be empty/);
});
