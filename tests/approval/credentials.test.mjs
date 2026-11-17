// SPDX-License-Identifier: Apache-2.0
//
// T010 credentials: human approval and decline take the recipient session only.
// - SC002-17 and SC002-18: a service (Hermes) credential or a sender (or tenant admin) operator
//   bearer is 401, even beside a live session cookie and its valid CSRF token. Proven twice:
//   through the real server, where src/server/app.ts refuses an Authorization header on a
//   recipient route, and at the handler, calling the exported approveAsHuman and
//   declineAsRecipient with the credential on the request context, where the handlers' own
//   check refuses it before the session guard, so neither the body nor last_seen_at is touched.
//   The same context without the credential is accepted (the control).
// - AP-09: the recipient scheme's 401 and 403 cases for both routes: no, unknown, malformed,
//   ended or idle-expired session (401); a missing or foreign CSRF token (403 csrf_failed,
//   checked before last_seen_at moves); a missing or foreign Origin (403 origin_rejected).
//   The session comes before the body (A-010, request #24, ruling (8)): without a live
//   session a malformed body is 401, never 400 or 422, through the server and in the domain
//   (ApprovalService re-reads the session first).
// - AP-15 (ruling (7)): T010's handlers are its own map. T008's RECIPIENT_HANDLERS keeps its
//   guard-only entries (501 after the guard, even with an ApprovalApi composed) and ROUTES
//   keeps null; withApprovalHandlers() installs T010's handlers over T008's.
// - AP-03 (row SC002-16-POS): a valid session with its valid CSRF token and a valid approval
//   succeeds end to end; so does a valid decline.
// Every refusal here changes nothing at all, last_seen_at included. Everything is synthetic.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';

import { approveAsHuman } from '../../src/api/recipients/approval.ts';
import { declineAsRecipient } from '../../src/api/recipients/decline.ts';
import { APPROVAL_HANDLERS, RECIPIENT_HANDLERS, ROUTES, withApprovalHandlers, withRecipientHandlers } from '../../src/api/routes.ts';
import { ApprovalError } from '../../src/domain/approval/index.ts';
import { HttpError } from '../../src/server/types.ts';
import { canonicalize } from '../../src/domain/canonical/index.ts';
import {
  APPROVAL_PATH,
  COOKIE,
  DECLINE_PATH,
  MINUTE,
  ORIGIN,
  SESSION_PATH,
  GUARD_TOUCH,
  TENANTS,
  approvalBody,
  assertError,
  bearer,
  contractErrors,
  createWorld,
  envelopeRow,
  openSession,
  postApproval,
  postDecline,
  sentEnvelope,
} from './support.mjs';

/** A request context for calling a route handler directly, as the server builds it. */
function handlerContext(world, { operationId, headers, principal = null, body }) {
  const reads = { json: 0 };
  const ctx = {
    operationId,
    params: Object.freeze({}),
    principal,
    request: { headers, socket: { remoteAddress: '127.0.0.1' } },
    path: operationId === 'approveAsHuman' ? APPROVAL_PATH : DECLINE_PATH,
    correlationId: 'handler-ctx-0001',
    logger: { child: () => ctx.logger, info() {}, warn() {}, error() {}, debug() {} },
    config: null,
    locals: world.app.locals,
    json: async () => {
      reads.json += 1;
      return body;
    },
    pdf: () => {
      throw new Error('no PDF body here');
    },
  };
  return { ctx, reads };
}

/** The operator principal the T005 authenticator makes of `token`. */
function principalOf(world, token) {
  const result = world.authenticator.authenticate({ authorization: `Bearer ${token}` });
  assert.equal(result.ok, true, 'premise: the authenticator accepts the synthetic credential on operator routes');
  return result.principal;
}

const unauthenticated = (error) => error instanceof HttpError && error.status === 401 && error.code === 'unauthenticated';

/**
 * Both operations with `credential` through the server and at the handler. The session is
 * live and its CSRF token valid throughout, and nothing changes, last_seen_at included.
 */
async function refusesCredential(world, session, state, who) {
  const token = bearer('alpha', who);
  const principal = principalOf(world, token);
  assert.equal(principal.kind, who === 'service' ? 'service' : 'human-operator', `premise: the ${who} credential is an operator principal`);
  const headers = { origin: ORIGIN, cookie: `${COOKIE}=${session.cookie}`, 'x-csrf-token': session.csrf };
  const before = world.snapshot();

  // Through the server, with the credential beside the live session and its CSRF token.
  for (const authorization of [`Bearer ${token}`, `bearer ${token}`, `Basic ${Buffer.from('synthetic:credential').toString('base64')}`, 'Bearer']) {
    assertError(await postApproval(world, session, approvalBody(state), { authorization }), 401, 'unauthenticated', `${who}: approval with an Authorization header`);
    assertError(await postDecline(world, session, { expected_version: state.envelope_version }, { authorization }), 401, 'unauthenticated', `${who}: decline with an Authorization header`);
  }

  // At the handler: the credential as a header, as a principal, and both.
  for (const [operationId, handler, body] of [
    ['approveAsHuman', approveAsHuman, approvalBody(state)],
    ['declineAsRecipient', declineAsRecipient, { expected_version: state.envelope_version }],
  ]) {
    for (const [label, extra, withPrincipal] of [
      ['header and principal', { authorization: `Bearer ${token}` }, principal],
      ['principal only', {}, principal],
      ['header only', { authorization: `Bearer ${token}` }, null],
    ]) {
      const { ctx, reads } = handlerContext(world, { operationId, headers: { ...headers, ...extra }, principal: withPrincipal, body });
      await assert.rejects(handler(ctx), unauthenticated, `${who}: ${operationId} at the handler (${label}) is 401`);
      assert.equal(reads.json, 0, `${who}: ${operationId} (${label}): the body is never read`);
    }
  }
  assert.deepEqual(world.snapshot(), before, `${who}: nothing changes, last_seen_at included`);
  assert.equal(world.rows('approvals').length, 0, `${who}: no approval`);
}

test('[SC002-17] a service (Hermes) credential cannot approve or decline: 401 through the server and at the handler, even with a live session and its CSRF token', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world);
    const session = await openSession(world, token);
    await refusesCredential(world, session, session.state, 'service');
    assert.equal(envelopeRow(world, envelope.id).state, 'sent', 'the envelope is untouched');

    // The control: the same handler context without the credential approves.
    const headers = { origin: ORIGIN, cookie: `${COOKIE}=${session.cookie}`, 'x-csrf-token': session.csrf };
    const { ctx, reads } = handlerContext(world, { operationId: 'approveAsHuman', headers, body: approvalBody(session.state) });
    const result = await approveAsHuman(ctx);
    assert.equal(result.status, 200, 'the recipient session alone approves');
    assert.equal(reads.json, 1, 'the body is read once');
    assert.deepEqual(contractErrors('ApprovalReceipt', JSON.parse(Buffer.from(result.body).toString('utf8'))), [], 'a contract receipt');
  } finally {
    await world.close();
  }
});

test('[SC002-18] a sender or tenant-admin operator bearer cannot approve or decline: 401 through the server and at the handler, even with a live session and its CSRF token', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world);
    const session = await openSession(world, token);
    await refusesCredential(world, session, session.state, 'sender');
    await refusesCredential(world, session, session.state, 'admin');
    assert.equal(envelopeRow(world, envelope.id).state, 'sent', 'the envelope is untouched');

    // The control: without the bearer, the same session declines through the server.
    const declined = await postDecline(world, session, { expected_version: session.state.envelope_version });
    assert.equal(declined.status, 200, 'the recipient session alone declines');
    assert.deepEqual(declined.json, { envelope_state: 'declined' });
  } finally {
    await world.close();
  }
});

test('[AP-09] the recipient scheme guards approval and decline: 401 without a live session, 403 csrf_failed without its CSRF token, 403 origin_rejected without an allowed Origin, changing nothing', async () => {
  const world = await createWorld();
  try {
    const { token } = await sentEnvelope(world);
    const session = await openSession(world, token);
    const other = await openSession(world, (await sentEnvelope(world)).token);
    const state = session.state;
    const operations = [
      ['approval', APPROVAL_PATH, approvalBody(state)],
      ['decline', DECLINE_PATH, { expected_version: state.envelope_version }],
    ];
    const post = (path, body, headers) => world.http({ method: 'POST', path, headers, body });
    const cookie = (value) => `${COOKIE}=${value}`;
    const before = world.snapshot();

    for (const [name, path, body] of operations) {
      const cases = [
        ['no session cookie', 401, 'unauthenticated', { origin: ORIGIN, 'x-csrf-token': session.csrf }],
        ['an unknown session value', 401, 'unauthenticated', { origin: ORIGIN, cookie: cookie(randomBytes(32).toString('base64url')), 'x-csrf-token': session.csrf }],
        ['a malformed session value', 401, 'unauthenticated', { origin: ORIGIN, cookie: cookie('not a session'), 'x-csrf-token': session.csrf }],
        ['the session under another cookie name', 401, 'unauthenticated', { origin: ORIGIN, cookie: `opensig_rs=${session.cookie}`, 'x-csrf-token': session.csrf }],
        ['no CSRF token', 403, 'csrf_failed', { origin: ORIGIN, cookie: cookie(session.cookie) }],
        ['another session’s CSRF token', 403, 'csrf_failed', { origin: ORIGIN, cookie: cookie(session.cookie), 'x-csrf-token': other.csrf }],
        ['a CSRF token with one character changed', 403, 'csrf_failed', { origin: ORIGIN, cookie: cookie(session.cookie), 'x-csrf-token': session.csrf.slice(0, -1) + (session.csrf.endsWith('A') ? 'B' : 'A') }],
        ['no Origin', 403, 'origin_rejected', { cookie: cookie(session.cookie), 'x-csrf-token': session.csrf }],
        ['a foreign Origin', 403, 'origin_rejected', { origin: 'https://sign.beta.test', cookie: cookie(session.cookie), 'x-csrf-token': session.csrf }],
        ['an Origin with another scheme', 403, 'origin_rejected', { origin: 'http://sign.alpha.test', cookie: cookie(session.cookie), 'x-csrf-token': session.csrf }],
      ];
      for (const [label, status, code, headers] of cases) {
        assertError(await post(path, body, headers), status, code, `${name}: ${label}`);
      }
    }
    assert.deepEqual(world.snapshot(), before, 'nothing changes, last_seen_at included');

    // The session before the body: without a live session, a malformed body is 401.
    const malformed = [
      ['a typed text outside WinAnsiEncoding', approvalBody(state, { text: 'Synthetic \u0100' })],
      ['an unknown member', { ...approvalBody(state), extra: true }],
      ['JSON that does not parse', '{"expected_version":'],
    ];
    for (const [label, body] of malformed) {
      assertError(await post(APPROVAL_PATH, body, { origin: ORIGIN, 'x-csrf-token': session.csrf }), 401, 'unauthenticated', `approval without a session, ${label}`);
      assertError(await post(DECLINE_PATH, body, { origin: ORIGIN, cookie: cookie(randomBytes(32).toString('base64url')), 'x-csrf-token': session.csrf }), 401, 'unauthenticated', `decline with an unknown session, ${label}`);
    }
    assert.deepEqual(world.snapshot(), before, 'nothing changes, last_seen_at included');

    // An ended session is 401.
    const ended = await world.http({ method: 'DELETE', path: SESSION_PATH, headers: { origin: ORIGIN, cookie: cookie(other.cookie), 'x-csrf-token': other.csrf } });
    assert.equal(ended.status, 204, 'premise: the other session is ended');
    const afterEnd = world.snapshot();
    for (const [name, path, body] of operations) {
      assertError(await post(path, body, { origin: ORIGIN, cookie: cookie(other.cookie), 'x-csrf-token': other.csrf }), 401, 'unauthenticated', `${name}: an ended session`);
    }
    // An idle-expired session is 401.
    world.time.advance(31 * MINUTE);
    for (const [name, path, body] of operations) {
      assertError(await post(path, body, { origin: ORIGIN, cookie: cookie(session.cookie), 'x-csrf-token': session.csrf }), 401, 'unauthenticated', `${name}: an idle-expired session`);
    }
    assert.deepEqual(world.snapshot(), afterEnd, 'nothing changes, last_seen_at included');
    assert.equal(world.rows('approvals').length, 0, 'no approval');

    // The domain re-reads the session before it looks at the body: a session revoked after the
    // guard (here: the ended one) is 401 for any body, never 400 or 422.
    const [row] = world.rows('recipient_sessions', 'WHERE revoked_at IS NOT NULL');
    assert.ok(row, 'premise: the ended session is revoked');
    const revoked = { tenantId: TENANTS.alpha.id, sessionId: row.id, envelopeId: row.envelope_id, recipientId: row.recipient_id, revisionId: row.revision_id, manifestDigest: row.manifest_digest };
    const isUnauthenticated = (error) => error instanceof ApprovalError && error.status === 401 && error.code === 'unauthenticated';
    for (const [label, body] of [...malformed, ['a body that is no object', 42]]) {
      assert.throws(() => world.approvalApi.service.approve(revoked, body), isUnauthenticated, `the domain: approval with a revoked session, ${label}`);
      assert.throws(() => world.approvalApi.service.decline(revoked, body), isUnauthenticated, `the domain: decline with a revoked session, ${label}`);
    }
    assert.deepEqual(world.snapshot(), afterEnd, 'still nothing changes');
  } finally {
    await world.close();
  }
});

test('[AP-15] T010’s handlers are its own map: T008’s map keeps its guard-only entries even with an ApprovalApi composed, ROUTES keeps null, and withApprovalHandlers installs T010’s handlers', async () => {
  // The maps themselves.
  assert.deepEqual(Object.keys(APPROVAL_HANDLERS).sort(), ['approveAsHuman', 'declineAsRecipient']);
  assert.equal(APPROVAL_HANDLERS.approveAsHuman, approveAsHuman);
  assert.equal(APPROVAL_HANDLERS.declineAsRecipient, declineAsRecipient);
  for (const operation of ['approveAsHuman', 'declineAsRecipient']) {
    assert.equal(typeof RECIPIENT_HANDLERS[operation], 'function', `T008's map keeps its ${operation} entry`);
    assert.notEqual(RECIPIENT_HANDLERS[operation], APPROVAL_HANDLERS[operation], `T008's ${operation} entry is not T010's handler`);
    assert.equal(ROUTES.find((route) => route.operationId === operation).handler, null, `ROUTES keeps null for ${operation} until WIRE-US1`);
    assert.equal(withApprovalHandlers(withRecipientHandlers(ROUTES)).find((route) => route.operationId === operation).handler, APPROVAL_HANDLERS[operation], `withApprovalHandlers installs T010's ${operation} over T008's`);
    assert.equal(withRecipientHandlers(ROUTES).find((route) => route.operationId === operation).handler, RECIPIENT_HANDLERS[operation], `withRecipientHandlers installs T008's own ${operation}`);
  }
  assert.ok(Object.isFrozen(APPROVAL_HANDLERS) && Object.isFrozen(RECIPIENT_HANDLERS));

  // A world wired with T008's and T034's maps only: approval and decline pass T008's guard and
  // answer 501, recording nothing, although the ApprovalApi is in the locals.
  const world = await createWorld({ wiring: 't008' });
  try {
    const { envelope, token } = await sentEnvelope(world);
    const session = await openSession(world, token);
    assert.ok(world.approvalApi, 'premise: the ApprovalApi is composed in this world too');
    const before = world.snapshot(GUARD_TOUCH);
    assertError(await postApproval(world, session, approvalBody(session.state)), 501, 'internal', 'approval through T008’s map: the guard passes, then 501');
    assertError(await postDecline(world, session, { expected_version: session.state.envelope_version }), 501, 'internal', 'decline through T008’s map: the guard passes, then 501');
    assertError(await postApproval(world, session, approvalBody(session.state), { 'x-csrf-token': '' }), 403, 'csrf_failed', 'T008’s guard still refuses a bad token');
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');
    assert.equal(envelopeRow(world, envelope.id).state, 'sent', 'the envelope is untouched');
  } finally {
    await world.close();
  }
});

test('[AP-03] a valid CSRF token with a valid approval succeeds end to end, and a valid decline likewise (row SC002-16-POS)', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world);
    const session = await openSession(world, token);
    world.time.advance(MINUTE);
    const response = await postApproval(world, session, approvalBody(session.state));
    assert.equal(response.status, 200, `the approval succeeds: ${response.status} ${response.json?.code ?? ''}`);
    assert.match(String(response.headers['content-type']), /^application\/json; charset=utf-8$/);
    assert.deepEqual(contractErrors('ApprovalReceipt', response.json), [], 'a contract ApprovalReceipt');
    assert.equal(response.text, canonicalize(response.json), 'RFC 8785 bytes');
    assert.equal(response.json.envelope_state, 'finalizing');
    assert.equal(envelopeRow(world, envelope.id).state, 'finalizing');
    const [seen] = world.rows('recipient_sessions', 'WHERE envelope_id = ?', [envelope.id]);
    assert.equal(seen.last_seen_at, world.time.now.toISOString(), 'the guard refreshed the session');

    const declining = await sentEnvelope(world);
    const declineSession = await openSession(world, declining.token);
    const declined = await postDecline(world, declineSession, { expected_version: declineSession.state.envelope_version, reason_code: 'other' });
    assert.equal(declined.status, 200, 'the decline succeeds');
    assert.deepEqual(contractErrors('DeclineOutcome', declined.json), [], 'a contract DeclineOutcome');
    assert.equal(declined.text, '{"envelope_state":"declined"}');
    assert.equal(envelopeRow(world, declining.envelope.id).state, 'declined');
  } finally {
    await world.close();
  }
});
