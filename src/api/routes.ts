// SPDX-License-Identifier: Apache-2.0
//
// Route registry (T031). One entry per contract operation (spec leg contracts/http-api.yaml,
// draft 0.2.1), with the HTTP method, the path template, the request body kind and the
// task that implements the handler. The server (src/server/app.ts) applies the shared
// policy to every route before any handler runs:
// - routing, with path parameters matching ^[A-Za-z0-9_-]{16,64}$ (others are 404);
// - the Origin allowlist;
// - operator authentication and the role-by-operation matrix (src/api/auth, T005);
// - body limits.
// A route whose handler is still null answers 501 after those checks.
//
// The contract registry (CONTRACT_ROUTES) carries `handler: null` for every operation. ROUTES,
// the registry the server serves (src/server/main.ts), is set from the handler maps the owning
// tasks export (A-010 row WIRE-US1, T031's US1 composition slot):
//   ROUTES = withApprovalHandlers(withEnvelopeHandlers(withRecipientHandlers(CONTRACT_ROUTES)))
// - T008 RECIPIENT_HANDLERS: requestChallenge, createRecipientSession, readRecipientSession,
//   endRecipientSession, readRecipientDocument and readRecipientManifest, plus guard-only
//   entries (the recipient session and CSRF guard, then 501) for approval and decline;
// - T034 ENVELOPE_HANDLERS: createEnvelope, readEnvelope, uploadDocument, prepareEnvelope,
//   readRecipientPreview, confirmSend, sendEnvelope, voidEnvelope, reissueEnvelope and
//   resendInvitation;
// - T010 APPROVAL_HANDLERS: approveAsHuman and declineAsRecipient, installed last, over T008's
//   guard-only entries (A-010 request #24, ruling (7)).
// Every other route keeps `handler: null` and answers the uniform 501 until its owner lands
// (T038 retryFinalization, T016 artifacts, T019 webhooks); openReviewShell (GET /sign) is
// served by src/server/static.ts (T035) when that module exists. No handler exists outside
// this registry: each map names only registry operations, and the server dispatches only
// through the registry it is given (T031 SEC-04, as amended by § Rulings D1).
//
// T016 ARTIFACT_HANDLERS (readVerification, downloadFinalPdf and downloadPackage) is exported
// here with withArtifactHandlers(), and ROUTES does not install it (row ARTIFACT-ROUTES;
// request #46). Its handlers need an ArtifactApi under ARTIFACT_API in the server locals.
// The T031 US2 composition slot, after T016 and T038, composes one in src/server/main.ts,
// installs this map and T038's retry handler, and amends SEC-04 and SEC-05. Until then the
// three routes keep the uniform 501, so T031's errors test and T034's SC002-26 world are
// unchanged. T016 tests through its own world: withArtifactHandlers(ROUTES), plus an
// ArtifactApi in its locals.
//
// The handlers find their app-scoped dependencies in the server locals: the T008
// RecipientCeremony under RECIPIENT_CEREMONY, the T034 EnvelopeApi under ENVELOPE_API and the
// T010 ApprovalApi under APPROVAL_API. src/server/main.ts composes them once per process and
// installs the same instances into every listener's app; a request whose app has none is a
// 500 (fail closed). withRecipientHandlers() and its peers stay exported so each owner tests
// through its own map (T008, T034, T010 and T016 worlds).

import { ARTIFACT_HANDLERS } from './artifacts/handlers.ts';
import { withRecipientMutation } from './auth/recipient-session.ts';
import type { OperationId } from './auth/matrix.ts';
import { ENVELOPE_HANDLERS } from './envelopes/handlers.ts';
import { approveAsHuman } from './recipients/approval.ts';
import { declineAsRecipient } from './recipients/decline.ts';
import { CEREMONY_HANDLERS, ceremonyAuthority } from './recipients/handlers.ts';
import type { RouteHandler } from '../server/types.ts';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';
export type BodyKind = 'none' | 'json' | 'pdf';

export interface RouteDefinition {
  readonly operationId: OperationId;
  readonly method: HttpMethod;
  /** Contract path template, for example /v1/envelopes/{envelope_id}. */
  readonly path: string;
  readonly body: BodyKind;
  /** Task that implements the handler. */
  readonly owner: string;
  readonly handler: RouteHandler | null;
}

function route(operationId: OperationId, method: HttpMethod, path: string, body: BodyKind, owner: string, handler: RouteHandler | null = null): RouteDefinition {
  return Object.freeze({ operationId, method, path, body, owner, handler });
}

/** One entry per contract operation, every handler null: the registry before any map is installed. */
export const CONTRACT_ROUTES: readonly RouteDefinition[] = Object.freeze([
  route('createEnvelope', 'POST', '/v1/envelopes', 'json', 'T034'),
  route('readEnvelope', 'GET', '/v1/envelopes/{envelope_id}', 'none', 'T034'),
  route('uploadDocument', 'PUT', '/v1/envelopes/{envelope_id}/document', 'pdf', 'T034'),
  route('prepareEnvelope', 'POST', '/v1/envelopes/{envelope_id}/prepare', 'json', 'T034'),
  route('readRecipientPreview', 'GET', '/v1/envelopes/{envelope_id}/preview', 'none', 'T034'),
  route('confirmSend', 'POST', '/v1/envelopes/{envelope_id}/send-confirmations', 'json', 'T034'),
  route('sendEnvelope', 'POST', '/v1/envelopes/{envelope_id}/send', 'json', 'T034'),
  route('voidEnvelope', 'POST', '/v1/envelopes/{envelope_id}/void', 'json', 'T034'),
  route('reissueEnvelope', 'POST', '/v1/envelopes/{envelope_id}/reissue', 'json', 'T034'),
  route('resendInvitation', 'POST', '/v1/envelopes/{envelope_id}/recipients/{recipient_id}/resend-invitation', 'json', 'T034'),
  route('retryFinalization', 'POST', '/v1/envelopes/{envelope_id}/finalization/retry', 'json', 'T038'),
  route('readVerification', 'GET', '/v1/envelopes/{envelope_id}/verification', 'none', 'T016'),
  route('downloadFinalPdf', 'GET', '/v1/envelopes/{envelope_id}/final-pdf', 'none', 'T016'),
  route('downloadPackage', 'GET', '/v1/envelopes/{envelope_id}/package', 'none', 'T016'),
  route('createWebhookRegistration', 'POST', '/v1/webhook-registrations', 'json', 'T019'),
  route('readWebhookRegistration', 'GET', '/v1/webhook-registrations/{registration_id}', 'none', 'T019'),
  route('disableWebhookRegistration', 'DELETE', '/v1/webhook-registrations/{registration_id}', 'none', 'T019'),
  route('rotateWebhookKey', 'POST', '/v1/webhook-registrations/{registration_id}/keys', 'json', 'T019'),
  route('revokeWebhookKey', 'DELETE', '/v1/webhook-registrations/{registration_id}/keys/{key_id}', 'none', 'T019'),
  route('openReviewShell', 'GET', '/sign', 'none', 'T035'),
  route('requestChallenge', 'POST', '/v1/recipient-session/challenges', 'json', 'T008'),
  route('createRecipientSession', 'POST', '/v1/recipient-session', 'json', 'T008'),
  route('readRecipientSession', 'GET', '/v1/recipient-session', 'none', 'T008'),
  route('endRecipientSession', 'DELETE', '/v1/recipient-session', 'none', 'T008'),
  route('readRecipientDocument', 'GET', '/v1/recipient-session/document', 'none', 'T008'),
  route('readRecipientManifest', 'GET', '/v1/recipient-session/manifest', 'none', 'T008'),
  route('approveAsHuman', 'POST', '/v1/recipient-session/approval', 'json', 'T010'),
  route('declineAsRecipient', 'POST', '/v1/recipient-session/decline', 'json', 'T010'),
]);

/**
 * The recipient routes' handlers (T008). Approval and decline get the recipient session and
 * CSRF guard only (a live session, then its X-CSRF-Token, else 401 or 403 csrf_failed, then
 * 501); ROUTES installs T010's APPROVAL_HANDLERS over them.
 */
export const RECIPIENT_HANDLERS: Readonly<Partial<Record<OperationId, RouteHandler>>> = Object.freeze({
  ...CEREMONY_HANDLERS,
  approveAsHuman: withRecipientMutation(ceremonyAuthority, null),
  declineAsRecipient: withRecipientMutation(ceremonyAuthority, null),
});

/** `routes` with the recipient routes' handlers installed (every other route unchanged). */
export function withRecipientHandlers(routes: readonly RouteDefinition[] = ROUTES): readonly RouteDefinition[] {
  return Object.freeze(
    routes.map((definition) => {
      const handler = RECIPIENT_HANDLERS[definition.operationId];
      return handler === undefined ? definition : Object.freeze({ ...definition, handler });
    }),
  );
}

/**
 * T010's handler map: approval and decline. Any operator or service credential is 401, then
 * the recipient session and CSRF guard (a live session, then its X-CSRF-Token, else 401 or
 * 403 csrf_failed), then the approval or decline.
 */
export const APPROVAL_HANDLERS: Readonly<Partial<Record<OperationId, RouteHandler>>> = Object.freeze({
  approveAsHuman,
  declineAsRecipient,
});

/** `routes` with T010's approval and decline handlers installed (every other route unchanged). */
export function withApprovalHandlers(routes: readonly RouteDefinition[] = ROUTES): readonly RouteDefinition[] {
  return Object.freeze(
    routes.map((definition) => {
      const handler = APPROVAL_HANDLERS[definition.operationId];
      return handler === undefined ? definition : Object.freeze({ ...definition, handler });
    }),
  );
}

export { ENVELOPE_HANDLERS };

/** `routes` with the operator envelope routes' handlers installed (every other route unchanged). */
export function withEnvelopeHandlers(routes: readonly RouteDefinition[] = ROUTES): readonly RouteDefinition[] {
  return Object.freeze(
    routes.map((definition) => {
      const handler = ENVELOPE_HANDLERS[definition.operationId];
      return handler === undefined ? definition : Object.freeze({ ...definition, handler });
    }),
  );
}

export { ARTIFACT_HANDLERS };

/**
 * `routes` with T016's artifact handlers installed (every other route unchanged). Not yet part
 * of ROUTES: see the header comment.
 */
export function withArtifactHandlers(routes: readonly RouteDefinition[] = ROUTES): readonly RouteDefinition[] {
  return Object.freeze(
    routes.map((definition) => {
      const handler = ARTIFACT_HANDLERS[definition.operationId];
      return handler === undefined ? definition : Object.freeze({ ...definition, handler });
    }),
  );
}

/**
 * The registry the server serves (WIRE-US1): the contract registry with T008's, T034's and
 * T010's handler maps installed, in that order, so T010's approval and decline replace T008's
 * guard-only entries. Frozen, like every entry.
 */
export const ROUTES: readonly RouteDefinition[] = withApprovalHandlers(withEnvelopeHandlers(withRecipientHandlers(CONTRACT_ROUTES)));
