// SPDX-License-Identifier: Apache-2.0
//
// The retryFinalization handler's T038 half (row ARTIFACT-ROUTES; FEN-03).
// T038 exports the handler and installs nothing: ROUTES keeps the route at
// 501 until the T031 US2 composition slot installs it (and amends SEC-04).
// FinalizationRetryApi maps the domain's FinalizationError to the contract's
// status, code and details. Synthetic data only.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { FINALIZATION_HANDLERS, FinalizationRetryApi, retryFinalizationHandler, withFinalizationHandlers } from '../../src/api/envelopes/retry.ts';
import { CONTRACT_ROUTES, ROUTES } from '../../src/api/routes.ts';
import { HttpError } from '../../src/server/types.ts';
import { fail, lease } from './support/steps.mjs';
import { makeWorld, RESERVED_VERSION, seedFinalizing } from './support/world.mjs';

function principal(world, kind = 'human-operator') {
  return { scheme: 'operator', tenant_id: world.tenantId, kind, roles: ['tenant_admin'], scopes: ['finalization:retry'], ref: 'admin-1', issuer: 'https://issuer.example.test', expires_at: Math.floor(world.clock.now().getTime() / 1000) + 600 };
}

test('[FEN-03] T038 installs no route: ROUTES keeps retryFinalization at 501, and withFinalizationHandlers installs exactly that one handler', () => {
  assert.deepEqual(Object.keys(FINALIZATION_HANDLERS), ['retryFinalization'], `handlers ${JSON.stringify(Object.keys(FINALIZATION_HANDLERS))}`);
  const served = ROUTES.find((definition) => definition.operationId === 'retryFinalization');
  assert.equal(served.handler, null, `ROUTES serves retryFinalization with ${served.handler === null ? 'no handler' : 'a handler'} (the T031 slot installs it)`);
  const installed = withFinalizationHandlers(CONTRACT_ROUTES);
  assert.equal(installed.length, CONTRACT_ROUTES.length, `${installed.length} routes from ${CONTRACT_ROUTES.length}`);
  installed.forEach((definition, index) => {
    if (definition.operationId === 'retryFinalization') assert.equal(definition.handler, retryFinalizationHandler, 'retryFinalization gets T038 handler');
    else assert.equal(definition, CONTRACT_ROUTES[index], `${definition.operationId} (route ${index}) is untouched`);
  });
});

test('[FEN-03] FinalizationRetryApi answers 202 with the exact bytes, replays them, and maps refusals to the contract’s status, code and details', () => {
  const world = makeWorld();
  try {
    const api = new FinalizationRetryApi({ db: world.db, audit: world.audit, clock: world.clock.now });
    const { envelopeId } = seedFinalizing(world, { maxAttempts: 1 });
    const operator = principal(world);
    const key = 'retry-handler-key-0001';
    const refused = (status, code, details) => (error) =>
      error instanceof HttpError && error.status === status && error.code === code && JSON.stringify(error.details) === JSON.stringify(details);
    assert.throws(() => api.retry(operator, envelopeId, key, { expected_version: RESERVED_VERSION }), refused(409, 'finalization_not_retryable', []), `pending ${envelopeId}`);
    assert.throws(() => api.retry(operator, envelopeId, key, { expected_version: 'four' }), refused(400, 'invalid_request', [{ field: 'expected_version', code: 'invalid' }]));
    assert.equal(api.hasLiveRecord(operator, key), false, 'no record after two refusals');
    const used = fail(world, lease(world, envelopeId, 'runner-a'), true, 'seal_failed.timeout');
    assert.equal(used, 'failed', `one attempt of one, used: ${used}`);
    const result = api.retry(operator, envelopeId, key, { expected_version: RESERVED_VERSION });
    assert.equal(result.status, 202, `status ${result.status}`);
    assert.equal(api.hasLiveRecord(operator, key), true, 'a live record after the 202');
    const replay = api.retry(operator, envelopeId, key, { expected_version: RESERVED_VERSION });
    assert.deepEqual(replay, result, `the replay (${replay.status}, ${replay.body?.length} bytes) is the result (${result.status}, ${result.body?.length} bytes), byte for byte`);
    assert.throws(() => api.retry(operator, envelopeId, key, { expected_version: RESERVED_VERSION + 1 }), refused(409, 'idempotency_conflict', []));
  } finally {
    world.close();
  }
});
