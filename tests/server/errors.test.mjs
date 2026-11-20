// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-04: uniform contract Error bodies with server-generated correlation IDs,
// routing through the registry, and the authentication gate in front of every handler.
// Amended for the US1 composition (A-010 row WIRE-US1; § Rulings, T008 deviations D1) without
// weakening: every registry route either has its handler from the composed maps (T008, T034,
// T010) or stays null and answers the uniform 501 Error with a correlation ID, and no handler
// exists outside the registry.
// Amended for the US2 composition (A-010 row ARTIFACT-ROUTES, request #46) the same way: the
// composed maps now include T016's artifact map and T038's retry map. The 501 check moves from
// readVerification to a route still without a handler (readWebhookRegistration, T019), every
// route still without one keeps the 501, no T016 or T038 route is left without its handler, and
// each newly live route fails closed (a uniform 500, never a 2xx) in an app that holds no
// ArtifactApi or FinalizationRetryApi.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { ROLE_MATRIX } from '../../src/api/auth/index.ts';
// A namespace import, so a head without the composed registry fails these assertions, not the module load.
import * as registry from '../../src/api/routes.ts';
import { bearer, cleanup, ENVELOPE_ID, send, serveApp } from './support.mjs';

after(cleanup);

const ERROR_CODES = new Set([
  'invalid_request', 'unauthenticated', 'forbidden', 'not_found', 'version_conflict', 'state_conflict', 'order_conflict',
  'idempotency_conflict', 'confirmation_required', 'confirmation_invalid', 'not_completed', 'payload_too_large',
  'unsupported_media_type', 'unsupported_pdf', 'field_out_of_bounds', 'unsupported_characters', 'rate_limited', 'locked',
  'csrf_failed', 'origin_rejected', 'digest_mismatch', 'consent_mismatch', 'finalization_not_retryable',
  'destination_not_allowed', 'precondition_required', 'internal',
]);

/** Contract Error schema (components.schemas.Error), checked structurally. */
function assertErrorBody(response, status, code, label) {
  assert.equal(response.status, status, `${label}: status`);
  assert.match(response.headers['content-type'], /^application\/json/);
  const body = response.json;
  assert.ok(body && typeof body === 'object', `${label}: JSON body`);
  for (const key of Object.keys(body)) assert.ok(['code', 'message', 'correlation_id', 'details'].includes(key), `${label}: no extra property ${key}`);
  assert.ok(ERROR_CODES.has(body.code), `${label}: code in the contract enum`);
  assert.equal(body.code, code, `${label}: code`);
  assert.equal(typeof body.message, 'string');
  assert.ok(body.message.length <= 200);
  assert.match(body.correlation_id, /^[A-Za-z0-9_-]{8,64}$/);
  assert.equal(body.correlation_id, response.headers['x-correlation-id'], `${label}: body and header carry the same correlation ID`);
  return body;
}

// Contract operations: method and path (spec leg contracts/http-api.yaml, draft 0.2.1).
const CONTRACT_PATHS = {
  createEnvelope: 'POST /v1/envelopes',
  readEnvelope: 'GET /v1/envelopes/{envelope_id}',
  uploadDocument: 'PUT /v1/envelopes/{envelope_id}/document',
  prepareEnvelope: 'POST /v1/envelopes/{envelope_id}/prepare',
  readRecipientPreview: 'GET /v1/envelopes/{envelope_id}/preview',
  confirmSend: 'POST /v1/envelopes/{envelope_id}/send-confirmations',
  sendEnvelope: 'POST /v1/envelopes/{envelope_id}/send',
  voidEnvelope: 'POST /v1/envelopes/{envelope_id}/void',
  reissueEnvelope: 'POST /v1/envelopes/{envelope_id}/reissue',
  resendInvitation: 'POST /v1/envelopes/{envelope_id}/recipients/{recipient_id}/resend-invitation',
  retryFinalization: 'POST /v1/envelopes/{envelope_id}/finalization/retry',
  readVerification: 'GET /v1/envelopes/{envelope_id}/verification',
  downloadFinalPdf: 'GET /v1/envelopes/{envelope_id}/final-pdf',
  downloadPackage: 'GET /v1/envelopes/{envelope_id}/package',
  createWebhookRegistration: 'POST /v1/webhook-registrations',
  readWebhookRegistration: 'GET /v1/webhook-registrations/{registration_id}',
  disableWebhookRegistration: 'DELETE /v1/webhook-registrations/{registration_id}',
  rotateWebhookKey: 'POST /v1/webhook-registrations/{registration_id}/keys',
  revokeWebhookKey: 'DELETE /v1/webhook-registrations/{registration_id}/keys/{key_id}',
  openReviewShell: 'GET /sign',
  requestChallenge: 'POST /v1/recipient-session/challenges',
  createRecipientSession: 'POST /v1/recipient-session',
  readRecipientSession: 'GET /v1/recipient-session',
  endRecipientSession: 'DELETE /v1/recipient-session',
  readRecipientDocument: 'GET /v1/recipient-session/document',
  readRecipientManifest: 'GET /v1/recipient-session/manifest',
  approveAsHuman: 'POST /v1/recipient-session/approval',
  declineAsRecipient: 'POST /v1/recipient-session/decline',
};

/** The handler the composition installs for `operationId`: T038's, T016's, T010's over T008's, then T034's; else null. */
const { APPROVAL_HANDLERS = {}, ARTIFACT_HANDLERS = {}, CONTRACT_ROUTES = [], ENVELOPE_HANDLERS = {}, FINALIZATION_HANDLERS = {}, RECIPIENT_HANDLERS = {}, ROUTES } = registry;
const composedHandler = (operationId) =>
  FINALIZATION_HANDLERS[operationId] ?? ARTIFACT_HANDLERS[operationId] ?? APPROVAL_HANDLERS[operationId] ?? ENVELOPE_HANDLERS[operationId] ?? RECIPIENT_HANDLERS[operationId] ?? null;
const MAPS = { T008: RECIPIENT_HANDLERS, T034: ENVELOPE_HANDLERS, T010: APPROVAL_HANDLERS, T016: ARTIFACT_HANDLERS, T038: FINALIZATION_HANDLERS };
/** ARTIFACT-ROUTES: the operations each US2 map must carry (a map that lost one fails here, not only below). */
const US2_OPERATIONS = { T016: ['downloadFinalPdf', 'downloadPackage', 'readVerification'], T038: ['retryFinalization'] };

test('[SEC-04] the route registry has exactly one route per contract operation', () => {
  assert.deepEqual(ROUTES.map((route) => route.operationId).sort(), Object.keys(ROLE_MATRIX).sort());
  for (const route of ROUTES) {
    assert.equal(`${route.method} ${route.path}`, CONTRACT_PATHS[route.operationId], route.operationId);
    assert.equal(route.body, route.operationId === 'uploadDocument' ? 'pdf' : route.method === 'POST' ? 'json' : 'none', `${route.operationId} body kind`);
    assert.match(route.owner, /^T0\d\d$/);
    // WIRE-US1 (was: null until its task lands): the handler from the composed maps, or null.
    assert.equal(route.handler, composedHandler(route.operationId), `${route.operationId}: its handler from the composed maps, or null until its task lands`);
  }
  assert.ok(Object.isFrozen(ROUTES) && Object.isFrozen(ROUTES[0]));

  // The contract registry the maps are installed into: the same routes, every handler null.
  assert.deepEqual(CONTRACT_ROUTES.map((route) => `${route.operationId} ${route.method} ${route.path} ${route.body} ${route.owner}`), ROUTES.map((route) => `${route.operationId} ${route.method} ${route.path} ${route.body} ${route.owner}`));
  assert.ok(CONTRACT_ROUTES.every((route) => route.handler === null), 'the contract registry carries no handler');
  // No handler exists outside the registry: every map names registry operations only, and every
  // installed handler comes from a map.
  const registered = new Set(ROUTES.map((route) => route.operationId));
  for (const [owner, map] of Object.entries(MAPS)) {
    for (const operationId of Object.keys(map)) assert.ok(registered.has(operationId), `${owner}'s map names ${operationId}, a registry operation`);
  }
  const mapped = new Set(Object.values(MAPS).flatMap((map) => Object.values(map)));
  for (const route of ROUTES) if (route.handler !== null) assert.ok(mapped.has(route.handler), `${route.operationId}: the installed handler comes from a composed map`);
  // T010's approval and decline replace T008's guard-only entries.
  for (const operationId of ['approveAsHuman', 'declineAsRecipient']) {
    assert.notEqual(ROUTES.find((route) => route.operationId === operationId).handler, RECIPIENT_HANDLERS[operationId], `${operationId}: not T008's guard-only entry`);
  }
  // ARTIFACT-ROUTES: T016's and T038's maps carry exactly their operations, and ROUTES serves each through its owner's handler.
  for (const [owner, operations] of Object.entries(US2_OPERATIONS)) {
    assert.deepEqual(Object.keys(MAPS[owner]).sort(), operations, `${owner}'s map names ${JSON.stringify(Object.keys(MAPS[owner]).sort())}`);
    for (const operationId of operations) {
      const route = ROUTES.find((entry) => entry.operationId === operationId);
      assert.equal(route.owner, owner, `${operationId}: owner ${route.owner}`);
      assert.ok(route.handler !== null && route.handler === MAPS[owner][operationId], `${operationId}: ROUTES carries ${owner}'s handler (ARTIFACT-ROUTES)`);
    }
  }
});

test('[SEC-04] errors are uniform contract Error bodies with a fresh server-side correlation ID', async () => {
  const served = await serveApp({
    handlers: {
      readEnvelope: async () => {
        throw new Error('database file /var/opensig/tenant.db is locked by pid 4242');
      },
    },
  });
  try {
    const sender = { authorization: `Bearer ${bearer('sender')}` };
    const ids = new Set();
    const check = async (label, options, status, code) => {
      const body = assertErrorBody(await send(served.port, options), status, code, label);
      assert.equal(ids.has(body.correlation_id), false, `${label}: correlation IDs are unique`);
      ids.add(body.correlation_id);
      return body;
    };
    await check('unknown path', { path: '/v1/nothing-here' }, 404, 'not_found');
    await check('malformed identifier', { path: '/v1/envelopes/short', headers: sender }, 404, 'not_found');
    await check('identifier with a dot', { path: `/v1/envelopes/${ENVELOPE_ID}.json`, headers: sender }, 404, 'not_found');
    await check('trailing slash', { path: `/v1/envelopes/${ENVELOPE_ID}/`, headers: sender }, 404, 'not_found');
    await check('wrong method on a known path', { method: 'DELETE', path: `/v1/envelopes/${ENVELOPE_ID}`, headers: sender }, 404, 'not_found');
    const missing = await send(served.port, { path: `/v1/envelopes/${ENVELOPE_ID}` });
    assertErrorBody(missing, 401, 'unauthenticated', 'no credential');
    assert.equal(missing.headers['www-authenticate'], 'Bearer');
    const invalid = await send(served.port, { path: `/v1/envelopes/${ENVELOPE_ID}`, headers: { authorization: `Bearer ${bearer('sender', { exp: 1 })}` } });
    assertErrorBody(invalid, 401, 'unauthenticated', 'expired token');
    assert.equal(invalid.headers['www-authenticate'], 'Bearer error="invalid_token"');
    await check('service principal on confirmSend', { method: 'POST', path: `/v1/envelopes/${ENVELOPE_ID}/send-confirmations`, headers: { authorization: `Bearer ${bearer('service')}`, 'content-type': 'application/json' }, body: '{}' }, 403, 'forbidden');
    await check('sender on retryFinalization', { method: 'POST', path: `/v1/envelopes/${ENVELOPE_ID}/finalization/retry`, headers: { ...sender, 'content-type': 'application/json' }, body: '{}' }, 403, 'forbidden');
    await check('operator bearer on approve (SC002-18)', { method: 'POST', path: '/v1/recipient-session/approval', headers: { ...sender, 'content-type': 'application/json', origin: 'http://127.0.0.1:1' }, body: '{}' }, 401, 'unauthenticated');
    await check('service bearer on approve (SC002-17)', { method: 'POST', path: '/v1/recipient-session/approval', headers: { authorization: `Bearer ${bearer('service')}`, 'content-type': 'application/json', origin: 'http://127.0.0.1:1' }, body: '{}' }, 401, 'unauthenticated');
    // WIRE-US1: readRecipientPreview now has T034's handler, so this check moved to readVerification
    // (T016); ARTIFACT-ROUTES: readVerification now has T016's handler, so it moves to a route that
    // is still unimplemented (readWebhookRegistration, T019, tenant_admin only).
    const admin = { authorization: `Bearer ${bearer('admin')}` };
    await check('authorized request to an unimplemented operation', { path: `/v1/webhook-registrations/${ENVELOPE_ID}`, headers: admin }, 501, 'internal');
    // Every route still without a handler answers the uniform 501 after authentication.
    const unimplemented = ROUTES.filter((route) => route.handler === null);
    assert.deepEqual(unimplemented.map((route) => route.owner).filter((owner) => ['T008', 'T010', 'T034', 'T016', 'T038'].includes(owner)), [], 'no US1 route, and no T016 or T038 route, is left without a handler');
    assert.ok(unimplemented.length >= 1, `premise: ${unimplemented.length} route(s) still without a handler keep this check meaningful`);
    for (const route of unimplemented) {
      const path = route.path.replace(/\{[a-z_]+\}/g, ENVELOPE_ID);
      const roles = ROLE_MATRIX[route.operationId].roles;
      const headers = roles.includes('anonymous') ? {} : roles.includes('sender') ? { ...sender } : { ...admin };
      const options = { method: route.method, path, headers };
      if (route.body === 'json') Object.assign(options, { body: '{}', headers: { ...headers, 'content-type': 'application/json' } });
      await check(`${route.operationId} (owner ${route.owner}) without its handler`, options, 501, 'internal');
    }
    // A composed handler whose app holds no composition fails closed: a uniform 500, never a 2xx.
    await check('readRecipientPreview with no EnvelopeApi in the app', { path: `/v1/envelopes/${ENVELOPE_ID}/preview`, headers: sender }, 500, 'internal');
    // ARTIFACT-ROUTES: the newly live routes fail closed the same way (this app holds neither an
    // ArtifactApi nor a FinalizationRetryApi), each after the router's checks passed.
    for (const operationId of ['readVerification', 'downloadFinalPdf', 'downloadPackage']) {
      const path = ROUTES.find((route) => route.operationId === operationId).path.replace('{envelope_id}', ENVELOPE_ID);
      await check(`${operationId} with no ArtifactApi in the app`, { path, headers: sender }, 500, 'internal');
    }
    await check(
      'retryFinalization with no FinalizationRetryApi in the app',
      { method: 'POST', path: `/v1/envelopes/${ENVELOPE_ID}/finalization/retry`, headers: { ...admin, 'content-type': 'application/json', 'idempotency-key': 'ik-sec04-retry-0000000001' }, body: '{"expected_version":1}' },
      500,
      'internal',
    );

    // A handler exception is a generic 500: nothing of the exception reaches the client.
    const crashed = await check('handler exception', { path: `/v1/envelopes/${ENVELOPE_ID}`, headers: sender }, 500, 'internal');
    assert.doesNotMatch(JSON.stringify(crashed), /database|tenant\.db|4242|locked/);

    // A client-supplied correlation ID is ignored, and messages never echo the request.
    const echoed = await send(served.port, { path: '/v1/<script>alert(1)</script>?q=%3Cb%3E', headers: { 'x-correlation-id': 'client-chosen-id-123' } });
    const body = assertErrorBody(echoed, 404, 'not_found', 'hostile path');
    assert.notEqual(body.correlation_id, 'client-chosen-id-123');
    assert.doesNotMatch(echoed.text, /script|alert|%3C/);
  } finally {
    await served.close();
  }
});
