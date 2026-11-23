// SPDX-License-Identifier: Apache-2.0
//
// Role-by-operation matrix (T005). This module mirrors the contract's
// x-opensig-role-matrix (spec leg contracts/http-api.yaml, draft 0.2) operation by
// operation, in contract order; T034 asserts it equal to the vendored contract.
//
// authorize() is the operator-side decision:
// - operator operations need a principal holding one of the listed roles AND every listed
//   scope (no principal: 401; principal without role or scope: 403);
// - recipient operations accept only the recipient session scheme (T008), so an operator
//   bearer is never sufficient there: 401 (SC002-17, SC002-18);
// - anonymous operations need no principal.

import type { OperatorPrincipal } from './operator.ts';

export type MatrixRole = 'sender' | 'tenant_admin' | 'service' | 'recipient' | 'anonymous';

export interface MatrixEntry {
  readonly roles: readonly MatrixRole[];
  readonly scopes: readonly string[];
}

const entry = (roles: MatrixRole[], scopes: string[]): MatrixEntry => Object.freeze({ roles: Object.freeze(roles), scopes: Object.freeze(scopes) });

export const ROLE_MATRIX = Object.freeze({
  createEnvelope: entry(['sender', 'service'], ['envelopes:write']),
  readEnvelope: entry(['sender', 'tenant_admin', 'service'], ['envelopes:read']),
  uploadDocument: entry(['sender', 'service'], ['envelopes:write']),
  prepareEnvelope: entry(['sender', 'service'], ['envelopes:write']),
  readRecipientPreview: entry(['sender', 'tenant_admin', 'service'], ['envelopes:read']),
  confirmSend: entry(['sender', 'tenant_admin'], ['envelopes:confirm-send']),
  sendEnvelope: entry(['sender', 'service'], ['envelopes:send']),
  voidEnvelope: entry(['sender', 'tenant_admin'], ['envelopes:void']),
  reissueEnvelope: entry(['sender', 'tenant_admin'], ['envelopes:write']),
  resendInvitation: entry(['sender', 'tenant_admin'], ['envelopes:send']),
  retryFinalization: entry(['tenant_admin'], ['finalization:retry']),
  readVerification: entry(['sender', 'tenant_admin', 'service'], ['artifacts:read']),
  downloadFinalPdf: entry(['sender', 'tenant_admin', 'service'], ['artifacts:read']),
  downloadPackage: entry(['sender', 'tenant_admin', 'service'], ['artifacts:read']),
  createWebhookRegistration: entry(['tenant_admin'], ['webhooks:admin']),
  readWebhookRegistration: entry(['tenant_admin'], ['webhooks:admin']),
  disableWebhookRegistration: entry(['tenant_admin'], ['webhooks:admin']),
  rotateWebhookKey: entry(['tenant_admin'], ['webhooks:admin']),
  revokeWebhookKey: entry(['tenant_admin'], ['webhooks:admin']),
  openReviewShell: entry(['anonymous'], []),
  requestChallenge: entry(['anonymous'], []),
  createRecipientSession: entry(['anonymous'], []),
  readRecipientSession: entry(['recipient'], []),
  endRecipientSession: entry(['recipient'], []),
  readRecipientDocument: entry(['recipient'], []),
  readRecipientManifest: entry(['recipient'], []),
  approveAsHuman: entry(['recipient'], []),
  declineAsRecipient: entry(['recipient'], []),
});

export type OperationId = keyof typeof ROLE_MATRIX;

export type Scheme = 'operator' | 'recipient' | 'anonymous';

export type AuthorizationResult = { ok: true } | { ok: false; status: 401 | 403; code: 'unauthenticated' | 'forbidden' };

function lookup(operationId: string): MatrixEntry {
  if (!Object.hasOwn(ROLE_MATRIX, operationId)) throw new TypeError(`unknown operation: ${operationId}`);
  return ROLE_MATRIX[operationId as OperationId];
}

/** The authentication scheme an operation accepts. */
export function operationScheme(operationId: string): Scheme {
  const { roles } = lookup(operationId);
  if (roles.includes('anonymous')) return 'anonymous';
  if (roles.includes('recipient')) return 'recipient';
  return 'operator';
}

/** Decide an operator request. Throws TypeError for an unknown operation id. */
export function authorize(operationId: string, principal: OperatorPrincipal | null): AuthorizationResult {
  const required = lookup(operationId);
  const scheme = operationScheme(operationId);
  if (scheme === 'anonymous') return { ok: true };
  if (scheme === 'recipient' || principal === null) return { ok: false, status: 401, code: 'unauthenticated' };
  const hasRole = principal.roles.some((role) => required.roles.includes(role));
  const hasScopes = required.scopes.every((scope) => principal.scopes.includes(scope));
  if (!hasRole || !hasScopes) return { ok: false, status: 403, code: 'forbidden' };
  return { ok: true };
}
