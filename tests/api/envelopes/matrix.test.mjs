// SPDX-License-Identifier: Apache-2.0
//
// T034 authorization matrices (EA-03; tasks.md § T006 readings, "401/403 per route: T034").
//
// - T005's role matrix (src/api/auth/matrix.ts) equals the vendored contract's
//   x-opensig-role-matrix, operation by operation and in contract order, and agrees with each
//   operation's own x-opensig-roles and operatorOAuth scopes.
// - A per-route 401/403 matrix is generated from x-opensig-role-matrix and sent through the
//   real router with the real authenticator: for every operator route, no credential is 401
//   (WWW-Authenticate: Bearer), and every operator role outside the route's matrix entry is 403
//   forbidden even when it holds every scope. As controls, every role inside the entry passes
//   the gate (neither 401 nor 403), and an allowed role without the route's scope is 403.
// Recipient and anonymous routes take no operator credential; their 401/403 cases belong to
// T008 and T010, so this matrix covers operator routes only and says how many it left out.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { ROLE_MATRIX } from '../../../src/api/auth/index.ts';
import { operationIndex, requestMediaTypes } from '../../contract/envelopes/lib/contract.mjs';
import { ALL_SCOPES, SINGLE_PAGE, absentId, contract, contractErrors, createWorld, documentBytes } from './support.mjs';

const OPERATOR_ROLES = Object.freeze(['sender', 'tenant_admin', 'service']);
/** The synthetic operator who holds each operator role. */
const HOLDER = Object.freeze({ sender: 'sender', tenant_admin: 'admin', service: 'service' });

let world;
before(async () => {
  world = await createWorld();
});
after(async () => {
  await world?.close();
});

/** The operator routes of the contract, from x-opensig-role-matrix, with their contract entries. */
function operatorRoutes() {
  const doc = contract();
  const index = operationIndex(doc);
  const matrix = doc['x-opensig-role-matrix'];
  const routes = [];
  const others = [];
  for (const [operationId, entry] of Object.entries(matrix)) {
    if (entry.roles.every((role) => OPERATOR_ROLES.includes(role))) routes.push({ operationId, entry, operation: index.get(operationId) });
    else others.push(operationId);
  }
  return { routes, others };
}

/** A request the route accepts in shape: its method and path, its declared headers and a body of its media type. */
function requestFor(route) {
  const op = route.operation;
  let path = op.pathTemplate;
  for (const match of op.pathTemplate.matchAll(/\{([^}]+)\}/g)) path = path.replace(match[0], absentId());
  const media = requestMediaTypes(contract(), op);
  const headers = {};
  let body;
  if (media.includes('application/pdf')) body = documentBytes(SINGLE_PAGE);
  else if (media.includes('application/json')) body = {};
  const ifMatch = op.parameters.some((parameter) => parameter.in === 'header' && parameter.name === 'If-Match') ? 1 : undefined;
  return { method: op.method, path, headers, body, ifMatch };
}

test('[EA-03] T005\'s role matrix equals the contract\'s x-opensig-role-matrix, operation by operation and in contract order', () => {
  const doc = contract();
  const matrix = doc['x-opensig-role-matrix'];
  assert.deepEqual(Object.keys(ROLE_MATRIX), Object.keys(matrix), 'the same operations, in contract order');
  for (const [operationId, entry] of Object.entries(matrix)) {
    const ours = ROLE_MATRIX[operationId];
    assert.deepEqual({ roles: [...ours.roles], scopes: [...ours.scopes] }, { roles: [...entry.roles], scopes: [...entry.scopes] }, operationId);
  }
  // The matrix agrees with each operation's own declarations.
  const index = operationIndex(doc);
  assert.equal(index.size, Object.keys(matrix).length, 'every contract operation has a matrix entry');
  for (const [operationId, entry] of Object.entries(matrix)) {
    const op = index.get(operationId);
    assert.ok(op, `${operationId} is a contract operation`);
    assert.deepEqual(op.operation['x-opensig-roles'], entry.roles, `${operationId}: x-opensig-roles`);
    const operatorScopes = (op.operation.security ?? []).flatMap((requirement) => requirement.operatorOAuth ?? []);
    assert.deepEqual(operatorScopes, entry.scopes, `${operationId}: operatorOAuth scopes`);
  }
});

test('[EA-03] every operator route answers 401 without a credential and 403 to every operator role outside its matrix entry, through the real router', async (t) => {
  const { routes, others } = operatorRoutes();
  assert.equal(routes.length + others.length, Object.keys(contract()['x-opensig-role-matrix']).length);
  assert.ok(others.every((id) => ROLE_MATRIX[id].roles.every((role) => role === 'recipient' || role === 'anonymous')), 'only recipient and anonymous routes are left to T008 and T010');
  let unauthenticated = 0;
  let forbidden = 0;
  for (const route of routes) {
    const shape = requestFor(route);
    const none = await world.op({ ...shape, who: null });
    assert.equal(none.status, 401, `${route.operationId}: no credential is 401 (got ${none.status})`);
    assert.equal(none.json?.code, 'unauthenticated', `${route.operationId}: unauthenticated`);
    assert.equal(none.headers['www-authenticate'], 'Bearer', `${route.operationId}: WWW-Authenticate: Bearer`);
    assert.deepEqual(contractErrors('Error', none.json), [], `${route.operationId}: a contract Error body`);
    unauthenticated += 1;
    for (const role of OPERATOR_ROLES.filter((candidate) => !route.entry.roles.includes(candidate))) {
      const refused = await world.op({ ...shape, who: HOLDER[role], scopes: [...ALL_SCOPES] });
      assert.equal(refused.status, 403, `${route.operationId}: role ${role} is outside the matrix, so 403 even with every scope (got ${refused.status})`);
      assert.equal(refused.json?.code, 'forbidden', `${route.operationId}: forbidden for ${role}`);
      forbidden += 1;
    }
  }
  t.diagnostic(`401/403 matrix: ${routes.length} operator routes, ${unauthenticated} unauthenticated and ${forbidden} role refusals; ${others.length} recipient or anonymous routes left to T008 and T010`);
  assert.ok(forbidden > 0, 'the matrix refuses at least one role somewhere');
});

test('[EA-03] every role inside a route\'s matrix entry passes the gate, and without the route\'s scope it is 403', async () => {
  const { routes } = operatorRoutes();
  for (const route of routes) {
    const shape = requestFor(route);
    for (const role of route.entry.roles) {
      const passed = await world.op({ ...shape, who: HOLDER[role], scopes: [...ALL_SCOPES] });
      assert.ok(passed.status !== 401 && passed.status !== 403, `${route.operationId}: role ${role} is in the matrix and passes the router's gate (got ${passed.status} ${passed.json?.code ?? ''})`);
      const scopes = ALL_SCOPES.filter((scope) => !route.entry.scopes.includes(scope));
      const unscoped = await world.op({ ...shape, who: HOLDER[role], scopes });
      assert.equal(unscoped.status, 403, `${route.operationId}: role ${role} without ${route.entry.scopes.join(' ')} is 403 (got ${unscoped.status})`);
      assert.equal(unscoped.json?.code, 'forbidden');
    }
  }
});
