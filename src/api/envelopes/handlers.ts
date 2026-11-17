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
// The EnvelopeApi is app-scoped: the server stores one under ENVELOPE_API in its locals, and a
// request that finds none is a 500 (fail closed). ENVELOPE_HANDLERS is installed into a route
// registry by withEnvelopeHandlers() (src/api/routes.ts); production wiring is T031's US1
// composition slot (row WIRE-US1).

import type { OperationId } from '../auth/matrix.ts';
import { HttpError, type RequestContext, type RouteHandler } from '../../server/types.ts';
import { ENVELOPE_API, EnvelopeApi } from './api.ts';
import { idempotencyKeyOf, ifMatchOf, jsonBody, pathId, principalOf } from './request.ts';

/** The app's EnvelopeApi, or a 500 when the server was started without one. */
export function envelopeApiOf(ctx: RequestContext): EnvelopeApi {
  const api = ctx.locals.get(ENVELOPE_API);
  if (!(api instanceof EnvelopeApi)) throw new HttpError(500, 'internal');
  return api;
}

export const createEnvelope: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const key = idempotencyKeyOf(ctx);
  return api.create(principal, key, await jsonBody(ctx));
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
  return api.prepare(principal, envelopeId, key, await jsonBody(ctx));
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
  return api.confirmSend(principal, envelopeId, key, await jsonBody(ctx));
};

export const sendEnvelope: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const key = idempotencyKeyOf(ctx);
  return api.send(principal, envelopeId, key, await jsonBody(ctx));
};

export const voidEnvelope: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const key = idempotencyKeyOf(ctx);
  return api.void(principal, envelopeId, key, await jsonBody(ctx));
};

export const reissueEnvelope: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const key = idempotencyKeyOf(ctx);
  return api.reissue(principal, envelopeId, key, await jsonBody(ctx));
};

export const resendInvitation: RouteHandler = async (ctx) => {
  const api = envelopeApiOf(ctx);
  const principal = principalOf(ctx);
  const envelopeId = pathId(ctx, 'envelope_id');
  const recipientId = pathId(ctx, 'recipient_id');
  const key = idempotencyKeyOf(ctx);
  return api.resend(principal, envelopeId, recipientId, key, await jsonBody(ctx));
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
