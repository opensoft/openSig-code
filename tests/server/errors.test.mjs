// SPDX-License-Identifier: Apache-2.0
//
// T031 server SEC-04: uniform contract Error bodies with server-generated correlation IDs,
// routing through the registry, and the authentication gate in front of every handler.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { ROLE_MATRIX } from '../../src/api/auth/index.ts';
import { ROUTES } from '../../src/api/routes.ts';
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

test('[SEC-04] the route registry has exactly one route per contract operation', () => {
  assert.deepEqual(ROUTES.map((route) => route.operationId).sort(), Object.keys(ROLE_MATRIX).sort());
  for (const route of ROUTES) {
    assert.equal(`${route.method} ${route.path}`, CONTRACT_PATHS[route.operationId], route.operationId);
    assert.equal(route.body, route.operationId === 'uploadDocument' ? 'pdf' : route.method === 'POST' ? 'json' : 'none', `${route.operationId} body kind`);
    assert.match(route.owner, /^T0\d\d$/);
    assert.equal(route.handler, null, `${route.operationId} has no handler until its task lands`);
  }
  assert.ok(Object.isFrozen(ROUTES) && Object.isFrozen(ROUTES[0]));
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
    await check('authorized request to an unimplemented operation', { path: `/v1/envelopes/${ENVELOPE_ID}/preview`, headers: sender }, 501, 'internal');

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
