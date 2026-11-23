// SPDX-License-Identifier: Apache-2.0
//
// T005 auth: token validation. AU-01 valid RS256/ES256 tokens, AU-02 algorithm pinning,
// AU-03 signature and key selection, AU-05 exact issuer and audience, AU-06 clock skew.

import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { after, test } from 'node:test';

import { createOperatorAuthenticator, loadOperatorAuthConfig } from '../../src/api/auth/index.ts';
import { ALPHA, BETA, claimsFor, cleanup, ecHeader, keys, NOW, publicJwk, rsaHeader, signToken, standardConfig } from './support.mjs';

after(cleanup);

const auth = createOperatorAuthenticator(loadOperatorAuthConfig(standardConfig()));
const alphaRsa = keys.alphaRsa.privateKey;
const alphaEc = keys.alphaEc.privateKey;

function accept(token, now = NOW) {
  const result = auth.verifyToken(token, now);
  assert.equal(result.ok, true, result.ok ? '' : `rejected: ${result.reason}`);
  return result.principal;
}

function reject(token, reason, now = NOW) {
  const result = auth.verifyToken(token, now);
  assert.equal(result.ok, false, `expected rejection (${reason})`);
  assert.equal(result.status, 401);
  assert.equal(result.code, 'unauthenticated');
  assert.equal(result.wwwAuthenticate, 'Bearer error="invalid_token"');
  if (reason) assert.equal(result.reason, reason);
  return result;
}

test('[AU-01] valid RS256 and ES256 tokens from the configured JWKS yield the operator principal', () => {
  const sender = accept(signToken({ header: rsaHeader(), payload: claimsFor(ALPHA, 'sender'), privateKey: alphaRsa }));
  assert.equal(sender.scheme, 'operator');
  assert.equal(sender.tenant_id, ALPHA.id);
  assert.equal(sender.kind, 'human-operator');
  assert.deepEqual(sender.roles, ['sender']);
  assert.ok(sender.scopes.includes('envelopes:confirm-send'));
  assert.equal(sender.issuer, ALPHA.oidc.issuer);
  assert.equal(sender.expires_at, NOW + 300);
  assert.match(sender.ref, /^op_[A-Za-z0-9_-]{40}$/);
  assert.equal(sender.ref.includes(claimsFor(ALPHA).sub), false, 'the reference is not the raw subject');
  assert.ok(Object.isFrozen(sender));

  const service = accept(signToken({ header: ecHeader(), payload: claimsFor(ALPHA, 'service'), privateKey: alphaEc }));
  assert.equal(service.kind, 'service');
  assert.deepEqual(service.roles, ['service']);

  const beta = accept(signToken({ header: rsaHeader('beta-rsa-1'), payload: claimsFor(BETA, 'admin'), privateKey: keys.betaRsa.privateKey }));
  assert.equal(beta.tenant_id, BETA.id);
  assert.deepEqual(beta.roles, ['tenant_admin']);

  // The reference is stable per tenant and subject, and differs across tenants.
  const again = accept(signToken({ header: rsaHeader(), payload: claimsFor(ALPHA, 'sender', { exp: NOW + 100 }), privateKey: alphaRsa }));
  assert.equal(again.ref, sender.ref);
  assert.notEqual(beta.ref, sender.ref);
  accept(signToken({ header: rsaHeader('alpha-rsa-1', { typ: 'at+jwt' }), payload: claimsFor(ALPHA), privateKey: alphaRsa }));
});

test('[AU-02] only the pinned RS256 and ES256 algorithms verify, with a key of the matching type', () => {
  const payload = claimsFor(ALPHA);
  // alg none, with and without a signature segment.
  const unsigned = signToken({ header: { alg: 'none', kid: 'alpha-rsa-1' }, payload, as: 'none' });
  reject(unsigned, 'malformed');
  reject(`${unsigned}AAAA`, 'algorithm');
  // HS256 using the RSA public key as the HMAC secret (algorithm confusion).
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', kid: 'alpha-rsa-1' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const secret = keys.alphaRsa.publicKey.export({ format: 'pem', type: 'spki' });
  const hmac = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  reject(`${header}.${body}.${hmac}`, 'algorithm');
  for (const alg of ['RS512', 'PS256', 'ES384', 'EdDSA', 'rs256']) {
    reject(signToken({ header: { alg, kid: 'alpha-rsa-1' }, payload, privateKey: alphaRsa, as: 'RS256' }), 'algorithm');
  }
  // Header and key type disagree: ES256 header naming the RSA key, RS256 naming the EC key.
  reject(signToken({ header: ecHeader('alpha-rsa-1'), payload, privateKey: alphaEc }), 'algorithm');
  reject(signToken({ header: rsaHeader('alpha-ec-1'), payload, privateKey: alphaRsa }), 'signature');

  // A tenant pinned to ES256 only refuses RS256 even with a valid key and signature.
  const esOnly = loadOperatorAuthConfig(
    standardConfig({
      tenants: [
        {
          ...standardConfig().tenants[0],
          algorithms: ['ES256'],
          jwksFile: undefined,
          jwks: { keys: [publicJwk(keys.alphaRsa, 'alpha-rsa-1'), publicJwk(keys.alphaEc, 'alpha-ec-1')] },
        },
      ],
    }),
  );
  const pinned = createOperatorAuthenticator(esOnly);
  assert.equal(pinned.verifyToken(signToken({ header: rsaHeader(), payload, privateKey: alphaRsa }), NOW).reason, 'algorithm');
  assert.equal(pinned.verifyToken(signToken({ header: ecHeader(), payload, privateKey: alphaEc }), NOW).ok, true);
});

test('[AU-03] tampered tokens and keys other than the configured kid fail verification', () => {
  const payload = claimsFor(ALPHA);
  const good = signToken({ header: rsaHeader(), payload, privateKey: alphaRsa });
  const [h, p, s] = good.split('.');
  // Payload changed after signing (role escalation attempt).
  const escalated = Buffer.from(JSON.stringify({ ...payload, opensig_roles: ['opensig-tenant-admin'] })).toString('base64url');
  reject(`${h}.${escalated}.${s}`, 'signature');
  // Signature bit flip.
  const flipped = Buffer.from(s, 'base64url');
  flipped[10] ^= 1;
  reject(`${h}.${p}.${flipped.toString('base64url')}`, 'signature');
  // A different key under a configured kid, an unknown kid and a missing kid.
  reject(signToken({ header: rsaHeader(), payload, privateKey: keys.impostorRsa.privateKey }), 'signature');
  reject(signToken({ header: ecHeader(), payload, privateKey: keys.impostorEc.privateKey }), 'signature');
  reject(signToken({ header: rsaHeader('alpha-rsa-9'), payload, privateKey: alphaRsa }), 'unknown-key');
  reject(signToken({ header: { alg: 'RS256' }, payload, privateKey: alphaRsa }), 'unknown-key');
  // Beta's key cannot sign for alpha's issuer.
  reject(signToken({ header: rsaHeader('beta-rsa-1'), payload, privateKey: keys.betaRsa.privateKey }), 'unknown-key');
});

test('[AU-03] headers that embed, point at or extend keys are refused before any key lookup', () => {
  const payload = claimsFor(ALPHA);
  // Headers that embed or point at keys, or demand extensions, are refused before any lookup.
  const impostorJwk = publicJwk(keys.impostorRsa, 'alpha-rsa-1');
  for (const extra of [{ jwk: impostorJwk }, { jku: 'https://keys.example.test/jwks' }, { x5u: 'https://keys.example.test/cert' }, { x5c: ['AAAA'] }, { crit: ['exp'] }]) {
    reject(signToken({ header: rsaHeader('alpha-rsa-1', extra), payload, privateKey: keys.impostorRsa.privateKey }), 'header');
  }
  reject(signToken({ header: rsaHeader('alpha-rsa-1', { typ: 'JWS' }), payload, privateKey: alphaRsa }), 'header');
  // Truncated ES256 signature.
  const ecToken = signToken({ header: ecHeader(), payload, privateKey: alphaEc }).split('.');
  reject(`${ecToken[0]}.${ecToken[1]}.${Buffer.from(ecToken[2], 'base64url').subarray(0, 63).toString('base64url')}`, 'signature');
});

test('[AU-05] issuer and audience must match exactly', () => {
  const sign = (overrides) => signToken({ header: rsaHeader(), payload: claimsFor(ALPHA, 'sender', overrides), privateKey: alphaRsa });
  for (const iss of [`${ALPHA.oidc.issuer}/`, ALPHA.oidc.issuer.toUpperCase(), 'https://issuer.alpha.test.example.test', 'http://issuer.alpha.test']) {
    reject(sign({ iss }), 'issuer');
  }
  const noIssuer = claimsFor(ALPHA);
  delete noIssuer.iss;
  reject(signToken({ header: rsaHeader(), payload: noIssuer, privateKey: alphaRsa }), 'issuer');
  for (const aud of [`${ALPHA.oidc.audience} `, BETA.oidc.audience, [ALPHA.oidc.audience, 'another-relying-party'], [], 7]) {
    reject(sign({ aud }), 'audience');
  }
  const noAudience = claimsFor(ALPHA);
  delete noAudience.aud;
  reject(signToken({ header: rsaHeader(), payload: noAudience, privateKey: alphaRsa }), 'audience');
  accept(sign({ aud: [ALPHA.oidc.audience] }));
  // Beta's audience with alpha's issuer and key is still alpha's tenant check: refused.
  reject(sign({ aud: BETA.oidc.audience, iss: ALPHA.oidc.issuer }), 'audience');
});

test('[AU-06] exp, nbf and iat are enforced with at most 60 seconds of skew', () => {
  const sign = (overrides) => signToken({ header: rsaHeader(), payload: claimsFor(ALPHA, 'sender', overrides), privateKey: alphaRsa });
  accept(sign({ exp: NOW - 59 }));
  reject(sign({ exp: NOW - 60 }), 'expired');
  reject(sign({ exp: NOW - 3600 }), 'expired');
  accept(sign({ nbf: NOW + 59 }));
  reject(sign({ nbf: NOW + 61 }), 'not-yet-valid');
  accept(sign({ iat: NOW + 59 }));
  reject(sign({ iat: NOW + 61 }), 'issued-in-future');
  reject(sign({ exp: String(NOW + 300) }), 'expiry-missing');
  reject(sign({ nbf: 'soon' }), 'not-yet-valid');
  const noExpiry = claimsFor(ALPHA);
  delete noExpiry.exp;
  reject(signToken({ header: rsaHeader(), payload: noExpiry, privateKey: alphaRsa }), 'expiry-missing');

  // A smaller configured skew is honoured; more than 60 seconds is refused at load.
  const strict = createOperatorAuthenticator(loadOperatorAuthConfig(standardConfig({ clockSkewSeconds: 0 })));
  assert.equal(strict.verifyToken(sign({ exp: NOW - 1 }), NOW).reason, 'expired');
  assert.equal(strict.verifyToken(sign({ exp: NOW + 1 }), NOW).ok, true);
  for (const clockSkewSeconds of [61, 300, -1, 1.5]) {
    assert.throws(() => loadOperatorAuthConfig(standardConfig({ clockSkewSeconds })), /clockSkewSeconds/);
  }
});
