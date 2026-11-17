// SPDX-License-Identifier: Apache-2.0
//
// T034 cross-tenant isolation (SC002-07, SC002-08, SC002-26). Tenant comes from the verified
// principal, never from a body or path, and "cross-tenant absence and inaccessibility are both
// 404" (contract info). Every request below goes through the real router and authenticator
// with a credential of tenant beta, against envelopes tenant alpha really holds. The answer
// must be the 404 not_found of an envelope that never existed, byte for byte except the
// correlation ID, and alpha's rows, mail and the parse gate must not move.
//
// SC002-26 generates its matrix from the vendored contract: every operation secured by
// operatorOAuth is an operator route, and the test's case table must name exactly those
// routes, so a contract route without a case fails (and so does a case for a route the
// contract does not have). The T034 routes are checked live. Routes whose handler another
// task owns (T038 retryFinalization, T016 artifacts, T019 webhooks) still have a case, and
// its expectation follows the installed handler map (request #16), so installing a handler
// never needs an edit here: while the handler is null the router answers 501 after
// authentication, never a 2xx or another tenant's data; once one is installed, an addressed
// route must give the uniform 404. The one other collection route, createWebhookRegistration
// (T019), names no envelope, so beta's request can act only in beta's tenant: with a handler
// it must give a response the contract declares for the operation, never a 5xx, and no row
// of alpha may change. The live cross-tenant cases of another owner's own resources (webhook
// registrations) stay with that owner.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { ROLE_MATRIX } from '../../../src/api/auth/index.ts';
import { ROUTES } from '../../../src/api/routes.ts';
import { parseAdmissions } from '../../../src/pdf/service.ts';
import { operationIndex } from '../../contract/envelopes/lib/contract.mjs';
import {
  MULTI_PAGE,
  SINGLE_PAGE,
  absentId,
  comparableHeaders,
  contract,
  contractErrors,
  createEnvelope,
  createInput,
  createWorld,
  documentBytes,
  errorShape,
  fieldsFor,
  preparedEnvelope,
  readPreview,
  sentEnvelope,
  uploadDocument,
  voidRequest,
} from './support.mjs';

let world;
before(async () => {
  world = await createWorld();
});
after(async () => {
  await world?.close();
});

/** Alpha's envelopes in each state a route needs: draft (with a document), prepared, sent, voided. */
async function alphaEnvelopes() {
  const created = await createEnvelope(world);
  const draft = await uploadDocument(world, { envelope: created, pdf: documentBytes(SINGLE_PAGE) });
  const prepared = await preparedEnvelope(world);
  const preview = await readPreview(world, { envelope: prepared });
  const { envelope: sent } = await sentEnvelope(world);
  const toVoid = await preparedEnvelope(world);
  const voided = (await voidRequest(world, { envelope: toVoid })).json;
  assert.equal(voided.state, 'voided');
  return { draft, prepared, preview, sent, voided };
}

/** The roles a beta credential takes for an operation: the first role its matrix entry allows. */
function whoFor(operationId) {
  const roles = ROLE_MATRIX[operationId].roles;
  if (roles.includes('sender')) return 'sender';
  if (roles.includes('tenant_admin')) return 'admin';
  return 'service';
}

/** The same request, on alpha's envelope and on an id that never existed, as `who` of beta. */
async function pair({ who = 'sender', method = 'GET', path, body, ifMatch, absentPath }) {
  const cross = await world.op({ tenant: 'beta', who, method, path, body, ifMatch });
  const absent = await world.op({ tenant: 'beta', who, method, path: absentPath, body, ifMatch });
  return { cross, absent };
}

function assertUniform404({ cross, absent }, label) {
  assert.equal(cross.status, 404, `${label}: another tenant's envelope is 404 (got ${cross.status} ${cross.json?.code ?? ''})`);
  assert.equal(cross.json?.code, 'not_found', `${label}: not_found`);
  assert.deepEqual(contractErrors('Error', cross.json), [], `${label}: a contract Error body`);
  assert.equal(absent.status, 404, `${label}: an envelope that never existed is 404`);
  assert.deepEqual(errorShape(cross), errorShape(absent), `${label}: the same body as an envelope that never existed`);
  assert.deepEqual(comparableHeaders(cross), comparableHeaders(absent), `${label}: the same headers as an envelope that never existed`);
}

const swap = (path, id) => path.replace(/\/v1\/envelopes\/[^/]+/, `/v1/envelopes/${id}`);

test('[SC002-07] a cross-tenant read is the uniform 404 of an envelope that never existed', async () => {
  const alpha = await alphaEnvelopes();
  for (const who of ['sender', 'admin', 'service']) {
    for (const envelope of [alpha.draft, alpha.prepared, alpha.sent, alpha.voided]) {
      const path = `/v1/envelopes/${envelope.id}`;
      assertUniform404(await pair({ who, path, absentPath: swap(path, absentId()) }), `readEnvelope (${envelope.state}) by beta ${who}`);
    }
    const preview = `/v1/envelopes/${alpha.prepared.id}/preview`;
    assertUniform404(await pair({ who, path: preview, absentPath: swap(preview, absentId()) }), `readRecipientPreview by beta ${who}`);
  }
  // Control: alpha reads its own envelope.
  const own = await world.op({ path: `/v1/envelopes/${alpha.sent.id}` });
  assert.equal(own.status, 200);
  assert.equal(own.json.id, alpha.sent.id);
});

test('[SC002-08] a cross-tenant mutation is the uniform 404 and changes nothing: no row, no mail, no parse', async () => {
  const alpha = await alphaEnvelopes();
  const rowsBefore = world.snapshot('alpha');
  const mailsBefore = world.mails().length;
  const ticketBefore = parseAdmissions().next_ticket;
  const recipient = alpha.sent.recipients[0];
  const attempts = [
    { label: 'uploadDocument', method: 'PUT', path: `/v1/envelopes/${alpha.draft.id}/document`, body: documentBytes(MULTI_PAGE), ifMatch: alpha.draft.version },
    { label: 'prepareEnvelope', method: 'POST', path: `/v1/envelopes/${alpha.draft.id}/prepare`, body: { expected_version: alpha.draft.version, fields: fieldsFor(1) } },
    {
      label: 'confirmSend (with alpha\'s own preview digests)',
      method: 'POST',
      path: `/v1/envelopes/${alpha.prepared.id}/send-confirmations`,
      body: { expected_version: alpha.preview.version, document_digest: alpha.preview.document.digest, manifest_digest: alpha.preview.manifest_digest, recipients_digest: alpha.preview.recipients_digest },
    },
    { label: 'sendEnvelope', method: 'POST', path: `/v1/envelopes/${alpha.prepared.id}/send`, body: { expected_version: alpha.prepared.version } },
    { label: 'voidEnvelope', method: 'POST', path: `/v1/envelopes/${alpha.sent.id}/void`, body: { expected_version: alpha.sent.version, reason_code: 'other' } },
    { label: 'reissueEnvelope', method: 'POST', path: `/v1/envelopes/${alpha.voided.id}/reissue`, body: { expected_version: alpha.voided.version } },
    { label: 'resendInvitation', method: 'POST', path: `/v1/envelopes/${alpha.sent.id}/recipients/${recipient.id}/resend-invitation`, body: { expected_version: alpha.sent.version } },
  ];
  for (const attempt of attempts) {
    const who = attempt.label.startsWith('sendEnvelope') || attempt.label.startsWith('prepare') || attempt.label.startsWith('upload') ? ['sender', 'service'] : ['sender', 'admin'];
    for (const role of who) {
      assertUniform404(await pair({ ...attempt, who: role, absentPath: swap(attempt.path, absentId()) }), `${attempt.label} by beta ${role}`);
    }
  }
  assert.deepEqual(world.snapshot('alpha'), rowsBefore, 'no row of tenant alpha changed');
  assert.equal(world.mails().length, mailsBefore, 'nothing was mailed');
  assert.equal(parseAdmissions().next_ticket, ticketBefore, 'the cross-tenant upload was refused before its body was parsed');

  // Control: alpha can make the same changes.
  const own = await voidRequest(world, { envelope: alpha.sent, reason: 'other' });
  assert.equal(own.status, 200);
  assert.equal(own.json.state, 'voided');
});

test('[SC002-26] the cross-tenant 404 matrix, generated from the contract\'s operator paths, has a case for every operator route', async (t) => {
  const doc = contract();
  const index = operationIndex(doc);
  const operator = [...index.values()].filter((entry) => (entry.operation.security ?? []).some((requirement) => Object.hasOwn(requirement, 'operatorOAuth')));
  const alpha = await alphaEnvelopes();
  const recipient = alpha.sent.recipients[0];

  // One case per operator route: the alpha envelope it addresses and a contract-valid body,
  // so that only the tenant decides the outcome.
  const cases = {
    createEnvelope: { collection: true },
    readEnvelope: { target: alpha.draft },
    uploadDocument: { target: alpha.draft, body: () => documentBytes(MULTI_PAGE), ifMatch: alpha.draft.version },
    prepareEnvelope: { target: alpha.draft, body: () => ({ expected_version: alpha.draft.version, fields: fieldsFor(1) }) },
    readRecipientPreview: { target: alpha.prepared },
    confirmSend: {
      target: alpha.prepared,
      body: () => ({ expected_version: alpha.preview.version, document_digest: alpha.preview.document.digest, manifest_digest: alpha.preview.manifest_digest, recipients_digest: alpha.preview.recipients_digest }),
    },
    sendEnvelope: { target: alpha.prepared, body: () => ({ expected_version: alpha.prepared.version }) },
    voidEnvelope: { target: alpha.sent, body: () => ({ expected_version: alpha.sent.version, reason_code: 'other' }) },
    reissueEnvelope: { target: alpha.voided, body: () => ({ expected_version: alpha.voided.version }) },
    resendInvitation: { target: alpha.sent, recipient, body: () => ({ expected_version: alpha.sent.version }) },
    retryFinalization: { target: alpha.sent, body: () => ({ expected_version: alpha.sent.version }) },
    readVerification: { target: alpha.sent },
    downloadFinalPdf: { target: alpha.sent },
    downloadPackage: { target: alpha.sent },
    createWebhookRegistration: { collection: true },
    readWebhookRegistration: { synthetic: true },
    disableWebhookRegistration: { synthetic: true },
    rotateWebhookKey: { synthetic: true, body: () => ({}) },
    revokeWebhookKey: { synthetic: true },
  };
  assert.deepEqual(Object.keys(cases).sort(), operator.map((entry) => entry.operationId).sort(), 'every operator route of the contract has a case, and no case names a route outside it');
  assert.equal(operator.length, ROUTES.filter((route) => !ROLE_MATRIX[route.operationId].roles.some((role) => role === 'recipient' || role === 'anonymous')).length, 'the registry has the same operator routes');

  const rowsBefore = world.snapshot('alpha');
  const mailsBefore = world.mails().length;
  let live = 0;
  let pending = 0;
  for (const entry of operator) {
    const id = entry.operationId;
    const spec = cases[id];
    const route = world.routes.find((candidate) => candidate.operationId === id);
    assert.ok(route, `${id} is in the installed registry`);
    const who = whoFor(id);
    if (spec.collection) {
      if (id === 'createEnvelope') {
        // The tenant comes from the principal: beta's envelope is beta's, and absent for alpha.
        const created = await world.op({ tenant: 'beta', who, method: 'POST', path: '/v1/envelopes', body: createInput(1) });
        assert.equal(created.status, 201, 'beta creates in its own tenant');
        const fromAlpha = await world.op({ tenant: 'alpha', who: 'sender', path: `/v1/envelopes/${created.json.id}` });
        const neverExisted = await world.op({ tenant: 'alpha', who: 'sender', path: `/v1/envelopes/${absentId()}` });
        assertUniform404({ cross: fromAlpha, absent: neverExisted }, 'createEnvelope: beta\'s envelope read by alpha');
        live += 1;
      } else {
        // Another owner's collection route: the expectation follows the installed handler map.
        const answer = await world.op({ tenant: 'beta', who, method: entry.method, path: entry.pathTemplate, body: {} });
        if (route.handler === null) {
          assert.equal(answer.status, 501, `${id} (owner ${route.owner}): no handler yet, so 501 after authentication`);
          assert.deepEqual(contractErrors('Error', answer.json), [], `${id}: a contract Error body`);
          pending += 1;
        } else {
          assert.ok(answer.status < 500, `${id} (owner ${route.owner}): its handler answers, never with a 5xx (got ${answer.status})`);
          assert.ok(Object.hasOwn(entry.operation.responses ?? {}, String(answer.status)), `${id}: ${answer.status} is a response the contract declares for the operation`);
          live += 1;
        }
      }
      continue;
    }
    let path = entry.pathTemplate;
    let absentPath = entry.pathTemplate;
    for (const name of [...entry.pathTemplate.matchAll(/\{([^}]+)\}/g)].map((match) => match[1])) {
      const value = name === 'envelope_id' && spec.target ? spec.target.id : name === 'recipient_id' && spec.recipient ? spec.recipient.id : absentId();
      path = path.replace(`{${name}}`, value);
      absentPath = absentPath.replace(`{${name}}`, absentId());
    }
    const body = spec.body ? spec.body() : undefined;
    const result = await pair({ who, method: entry.method, path, body, ifMatch: spec.ifMatch, absentPath });
    if (route.handler === null) {
      assert.notEqual(route.owner, 'T034', `${id} is a T034 route and must have its handler installed`);
      assert.equal(result.cross.status, 501, `${id} (owner ${route.owner}): no handler yet, so 501 after authentication, never a 2xx or another tenant's data`);
      assert.deepEqual(contractErrors('Error', result.cross.json), [], `${id}: a contract Error body`);
      pending += 1;
    } else {
      assertUniform404(result, `${id} by beta ${who}`);
      live += 1;
    }
  }
  t.diagnostic(`cross-tenant matrix: ${operator.length} operator routes, ${live} checked live, ${pending} waiting for their owner's handler`);
  assert.ok(live >= 10, 'every T034 route is checked live');
  assert.deepEqual(world.snapshot('alpha'), rowsBefore, 'no row of tenant alpha changed');
  assert.equal(world.mails().length, mailsBefore, 'nothing was mailed');
});
