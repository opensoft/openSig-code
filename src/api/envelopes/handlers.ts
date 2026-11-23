// SPDX-License-Identifier: Apache-2.0
//
// Route handlers of the operator envelope operations (T034). The server
// (src/server/app.ts, T031) has already applied its shared policy: routing, the Origin
// allowlist, operator authentication and the role-by-operation matrix (401/403), and the
// declared body length. Each handler reads its path parameters, headers and body
// (request.ts) and hands them to the app's EnvelopeApi (api.ts).
//
//   createEnvelope        POST /v1/envelopes                                     201 Envelope
//   readEnvelope          GET  /v1/envelopes/{envelope_id}                       200 Envelope
//   uploadDocument        PUT  /v1/envelopes/{envelope_id}/document              200 Envelope (If-Match)
//   prepareEnvelope       POST /v1/envelopes/{envelope_id}/prepare               200 Envelope
//   readRecipientPreview  GET  /v1/envelopes/{envelope_id}/preview               200 RecipientPreview
//   confirmSend           POST /v1/envelopes/{envelope_id}/send-confirmations    201 SendConfirmation
//   sendEnvelope          POST /v1/envelopes/{envelope_id}/send                  200 Envelope
//   voidEnvelope          POST /v1/envelopes/{envelope_id}/void                  200 Envelope
//   reissueEnvelope       POST /v1/envelopes/{envelope_id}/reissue               201 Envelope
//   resendInvitation      POST /v1/envelopes/{envelope_id}/recipients/{recipient_id}/resend-invitation  202 Accepted
//
// Every mutation needs an Idempotency-Key. Headers are checked before the body is read; an
// upload's media type is checked (415) before any of its bytes are read.
//
// Order in every idempotent handler (A-010 T034R-RESEND, request #23; request #16 for
// uploads): the router's checks (route, Origin, 401, the role matrix's 403, declared length
// 413); then here the principal, the path identifiers, the Idempotency-Key header (400) and,
// for confirmSend, void, reissue and resendInvitation, the human-only check (403); then the
// key, before the body is validated. A complete body that is not a JSON value under a key
// this principal already used on the route is 409 idempotency_conflict (keyedJson()); a JSON
// body goes to the EnvelopeApi, where the key is resolved (replay, or 409) before the body's
// own rules, existence, state and version. An upload checks its If-Match header (428/400) and
// media type (415), then resolves a recorded key before any parse (api.ts). Request #25: the
// framing answers (415, 413, 408) and upload's If-Match precondition keep their own answers
// before the key, and a body the client aborted is never compared, so it keeps T031's abort
// answer under a reused key too, never 409. None of these writes anything.
//
// The EnvelopeApi is app-scoped: the server stores one under ENVELOPE_API in its locals, and a
// request that finds none is a 500 (fail closed). ENVELOPE_HANDLERS is installed into a route
// registry by withEnvelopeHandlers() (src/api/routes.ts); production wiring is T031's US1
// composition slot (row WIRE-US1).

import type { OperationId } from '../auth/matrix.ts';
import type { JsonValue } from '../../domain/canonical/index.ts';
import { ROUTES as IDEMPOTENCY_ROUTES } from '../../domain/envelopes/index.ts';
import type { OperatorPrincipal } from '../auth/operator.ts';
import { HttpError, type RequestContext, type RouteHandler } from '../../server/types.ts';
import { ENVELOPE_API, EnvelopeApi, RESEND_ROUTE } from './api.ts';
import { idempotencyKeyOf, ifMatchOf, jsonBody, pathId, principalOf, requireHuman } from './request.ts';

/** The app's EnvelopeApi, or a 500 when the server was started without one. */
export function envelopeApiOf(ctx: RequestContext): EnvelopeApi {
  const api = ctx.locals.get(ENVELOPE_API);
  if (!(api instanceof EnvelopeApi)) throw new HttpError(500, 'internal');
  return api;
}

/**
 * The JSON body of an idempotent mutation, read after its key is resolved (T034R-RESEND).
 * Whether the key already has a live record is judged first, at arrival. The body's framing
 * answers keep their own status (415, 413, 408). A complete body that is not a JSON value
 * (400 from the server or from the canonical form) is, under a recorded key, a changed
 * payload: 409 idempotency_conflict. A body the client aborted was never received in full, so
 * it was never compared: it keeps T031's abort answer, as under a new key (request #25).
 */
async function keyedJson(ctx: RequestContext, api: EnvelopeApi, principal: OperatorPrincipal, route: string, key: string): Promise<JsonValue> {
  const recorded = api.hasLiveRecord(principal, route, key);
  try {
    return await jsonBody(ctx);
  } catch (error) {
    const comparable = ctx.request.complete;
    if (recorded && comparable && error instanceof HttpError && error.status === 400) throw new HttpError(409, 'idempotency_conflict');
    throw error;
  }
}

export const createEnvelope: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const key = idempotencyKeyOf(ctx);
  return api.create(principal, key, await keyedJson(ctx, api, principal, IDEMPOTENCY_ROUTES.create, key));
};

export const readEnvelope: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  return api.read(principalOf(ctx), pathId(ctx, 'envelope_id'));
};

export const uploadDocument: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const key = idempotencyKeyOf(ctx);
  const expectedVersion = ifMatchOf(ctx);
  // The media type is checked here (415), before any body byte is read.
  const body = ctx.pdf();
  return api.upload({ principal, envelopeId, key, expectedVersion, body, logger: ctx.logger });
};

export const prepareEnvelope: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const key = idempotencyKeyOf(ctx);
  return api.prepare(principal, envelopeId, key, await keyedJson(ctx, api, principal, IDEMPOTENCY_ROUTES.prepare, key));
};

export const readRecipientPreview: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  return api.preview(principalOf(ctx), pathId(ctx, 'envelope_id'));
};

export const confirmSend: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const key = idempotencyKeyOf(ctx);
  requireHuman(principal);
  return api.confirmSend(principal, envelopeId, key, await keyedJson(ctx, api, principal, IDEMPOTENCY_ROUTES.confirmSend, key));
};

export const sendEnvelope: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const key = idempotencyKeyOf(ctx);
  return api.send(principal, envelopeId, key, await keyedJson(ctx, api, principal, IDEMPOTENCY_ROUTES.send, key));
};

export const voidEnvelope: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const key = idempotencyKeyOf(ctx);
  requireHuman(principal);
  return api.void(principal, envelopeId, key, await keyedJson(ctx, api, principal, IDEMPOTENCY_ROUTES.void, key));
};

export const reissueEnvelope: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const key = idempotencyKeyOf(ctx);
  requireHuman(principal);
  return api.reissue(principal, envelopeId, key, await keyedJson(ctx, api, principal, IDEMPOTENCY_ROUTES.reissue, key));
};

export const resendInvitation: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const recipientId = pathId(ctx, 'recipient_id');
  const key = idempotencyKeyOf(ctx);
  requireHuman(principal);
  return api.resend(principal, envelopeId, recipientId, key, await keyedJson(ctx, api, principal, RESEND_ROUTE, key));
};

/** The T034 operations and their handlers. */
export const ENVELOPE_HANDLERS: Readonly<Partial<Record<OperationId, RouteHandler>>> = Object.freeze({
  createEnvelope,
  readEnvelope,
  uploadDocument,
  prepareEnvelope,
  readRecipientPreview,
  confirmSend,
  sendEnvelope,
  voidEnvelope,
  reissueEnvelope,
  resendInvitation,
});
