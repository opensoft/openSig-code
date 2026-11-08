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
// Owning tasks replace `handler: null` with their implementation in this file:
//   T034 envelope operations, T038 retryFinalization, T016 artifacts, T019 webhooks,
//   T008 recipient session, challenge, document and manifest, T010 approval and decline.
// openReviewShell (GET /sign) is served by src/server/static.ts (T035) when that module
// exists; see src/server/main.ts.

import type { OperationId } from './auth/matrix.ts';
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

export const ROUTES: readonly RouteDefinition[] = Object.freeze([
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
