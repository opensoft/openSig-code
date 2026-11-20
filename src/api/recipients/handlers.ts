// SPDX-License-Identifier: Apache-2.0
//
// Route handlers of the recipient ceremony (T008). The server has already
// applied its shared policy (src/server/app.ts): routing, the Origin allowlist
// on every mutating request (browser routes must send an allowlisted Origin),
// a 401 for any Authorization header on a recipient route, and body limits.
//
//   requestChallenge        POST   /v1/recipient-session/challenges  202 {status: accepted}, always
//   createRecipientSession  POST   /v1/recipient-session             201 RecipientSessionState + Set-Cookie
//   readRecipientSession    GET    /v1/recipient-session             200 RecipientSessionState
//   readRecipientDocument   GET    /v1/recipient-session/document    200 exact frozen PDF bytes, inline
//   readRecipientManifest   GET    /v1/recipient-session/manifest    200 exact canonical manifest bytes
//   endRecipientSession     DELETE /v1/recipient-session             204, cookie cleared (CSRF)
//
// requestChallenge answers before any per-invitation work starts: the ceremony
// validates and rate-limits, schedules the rest for after the response, and the
// handler returns the 202 (data-model.md, "Generic 202 (A-010)").
//
// HEAD is served as GET without a body, and a prefetch is served without moving
// the session's last_seen_at. The ceremony is app-scoped: the server stores one
// RecipientCeremony under RECIPIENT_CEREMONY in its locals, and a request that
// finds none is a 500 (fail closed). The client address keys the rate limits;
// no forwarding header is trusted.

import { clearedSessionCookie, sessionCookie, withRecipientMutation, withRecipientSession, type AuthorityLookup } from '../auth/recipient-session.ts';
import type { OperationId } from '../auth/matrix.ts';
import { HttpError, type RequestContext, type RouteHandler } from '../../server/types.ts';
import { RecipientCeremony } from './ceremony.ts';

/** The server locals key of the app's RecipientCeremony. */
export const RECIPIENT_CEREMONY = 'opensig.recipient-ceremony';

/** The app's ceremony, or a 500 when the server was started without one. */
export function ceremonyOf(ctx: RequestContext): RecipientCeremony {
  const ceremony = ctx.locals.get(RECIPIENT_CEREMONY);
  if (!(ceremony instanceof RecipientCeremony)) throw new HttpError(500, 'internal');
  return ceremony;
}

/** The session authority for the recipient scheme wrappers. */
export const ceremonyAuthority: AuthorityLookup = (ctx) => ceremonyOf(ctx);

function clientAddress(ctx: RequestContext): string {
  return ctx.request.socket.remoteAddress ?? 'unknown';
}

export const requestChallenge: RouteHandler = async (ctx) => {
  const ceremony = ceremonyOf(ctx);
  const body = await ctx.json();
  ceremony.requestChallenge(body, clientAddress(ctx), ctx.correlationId);
  return { status: 202, json: { status: 'accepted' } };
};

export const createRecipientSession: RouteHandler = async (ctx) => {
  const ceremony = ceremonyOf(ctx);
  const body = await ctx.json();
  const created = ceremony.createSession(body, clientAddress(ctx));
  return { status: 201, json: created.state, headers: { 'set-cookie': sessionCookie(created.value) } };
};

export const readRecipientSession: RouteHandler = withRecipientSession(ceremonyAuthority, async (ctx, session) => ({
  status: 200,
  json: ceremonyOf(ctx).readState(session),
}));

export const readRecipientDocument: RouteHandler = withRecipientSession(ceremonyAuthority, async (ctx, session) => ({
  status: 200,
  body: ceremonyOf(ctx).readDocument(session),
  contentType: 'application/pdf',
  headers: { 'content-disposition': 'inline' },
}));

export const readRecipientManifest: RouteHandler = withRecipientSession(ceremonyAuthority, async (ctx, session) => ({
  status: 200,
  body: ceremonyOf(ctx).readManifest(session),
  contentType: 'application/json',
}));

export const endRecipientSession: RouteHandler = withRecipientMutation(ceremonyAuthority, async (ctx, session) => {
  ceremonyOf(ctx).endSession(session);
  return { status: 204, headers: { 'set-cookie': clearedSessionCookie() } };
});

/** The T008 operations and their handlers. */
export const CEREMONY_HANDLERS: Readonly<Partial<Record<OperationId, RouteHandler>>> = Object.freeze({
  requestChallenge,
  createRecipientSession,
  readRecipientSession,
  endRecipientSession,
  readRecipientDocument,
  readRecipientManifest,
});
