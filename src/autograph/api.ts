// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// The recipient operations of contract 0.2.3 that the review shell drives, as the T031 US1
// composition (row WIRE-US1) serves them through the T008 and T010 handlers:
//   requestChallenge        POST   /v1/recipient-session/challenges   202 Accepted (generic)
//   createRecipientSession  POST   /v1/recipient-session              201 RecipientSessionState + session cookie
//   readRecipientSession    GET    /v1/recipient-session              200 RecipientSessionState
//   endRecipientSession     DELETE /v1/recipient-session              204 (X-CSRF-Token)
//   readRecipientDocument   GET    /v1/recipient-session/document     200 exact frozen PDF bytes
//   readRecipientManifest   GET    /v1/recipient-session/manifest     200 canonical manifest bytes
//   approveAsHuman          POST   /v1/recipient-session/approval     200 ApprovalReceipt (X-CSRF-Token)
//   declineAsRecipient      POST   /v1/recipient-session/decline      200 DeclineOutcome (X-CSRF-Token)
// Same origin only: the session cookie (__Host-opensig_rs; HttpOnly, so never visible here)
// goes with credentials 'same-origin', the browser adds the Origin the server checks, and the
// CSRF token from the session state goes in X-CSRF-Token. No request ever carries a token in
// a URL. Errors come back as the uniform contract Error body; only its `code` is used.

import type { ApprovalBody, ApprovalReceipt, DeclineBody, SessionState } from './types.js';

export const SESSION_PATH = '/v1/recipient-session';
export const CHALLENGE_PATH = '/v1/recipient-session/challenges';
export const DOCUMENT_PATH = '/v1/recipient-session/document';
export const MANIFEST_PATH = '/v1/recipient-session/manifest';
export const APPROVAL_PATH = '/v1/recipient-session/approval';
export const DECLINE_PATH = '/v1/recipient-session/decline';

export type ApiResult<T> = { readonly ok: true; readonly status: number; readonly value: T } | { readonly ok: false; readonly status: number; readonly code: string };

type Expect = 'json' | 'bytes' | 'none';

async function errorCode(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (typeof body === 'object' && body !== null && 'code' in body && typeof body.code === 'string' && /^[a-z_]{1,40}$/.test(body.code)) return body.code;
  } catch {
    // Not a contract Error body.
  }
  return 'unknown';
}

async function call<T>(method: string, path: string, expect: Expect, options: { readonly json?: unknown; readonly csrf?: string } = {}): Promise<ApiResult<T>> {
  const headers: Record<string, string> = { accept: expect === 'bytes' ? '*/*' : 'application/json' };
  if (options.json !== undefined) headers['content-type'] = 'application/json';
  if (options.csrf !== undefined) headers['x-csrf-token'] = options.csrf;
  let response: Response;
  try {
    response = await window.fetch(path, {
      method,
      headers,
      body: options.json === undefined ? null : JSON.stringify(options.json),
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    });
  } catch {
    return { ok: false, status: 0, code: 'network' };
  }
  if (!response.ok) return { ok: false, status: response.status, code: await errorCode(response) };
  try {
    if (expect === 'json') return { ok: true, status: response.status, value: (await response.json()) as T };
    if (expect === 'bytes') return { ok: true, status: response.status, value: (await response.arrayBuffer()) as T };
    return { ok: true, status: response.status, value: null as T };
  } catch {
    return { ok: false, status: response.status, code: 'unreadable' };
  }
}

export interface RecipientApi {
  requestChallenge(invitation: string): Promise<ApiResult<null>>;
  createSession(invitation: string, code: string): Promise<ApiResult<SessionState>>;
  readSession(): Promise<ApiResult<SessionState>>;
  endSession(csrf: string): Promise<ApiResult<null>>;
  document(): Promise<ApiResult<ArrayBuffer>>;
  manifest(): Promise<ApiResult<ArrayBuffer>>;
  approve(csrf: string, body: ApprovalBody): Promise<ApiResult<ApprovalReceipt>>;
  decline(csrf: string, body: DeclineBody): Promise<ApiResult<{ readonly envelope_state: 'declined' }>>;
}

export const recipientApi: RecipientApi = {
  requestChallenge: (invitation) => call<null>('POST', CHALLENGE_PATH, 'none', { json: { invitation } }),
  createSession: (invitation, code) => call<SessionState>('POST', SESSION_PATH, 'json', { json: { invitation, code } }),
  readSession: () => call<SessionState>('GET', SESSION_PATH, 'json'),
  endSession: (csrf) => call<null>('DELETE', SESSION_PATH, 'none', { csrf }),
  document: () => call<ArrayBuffer>('GET', DOCUMENT_PATH, 'bytes'),
  manifest: () => call<ArrayBuffer>('GET', MANIFEST_PATH, 'bytes'),
  approve: (csrf, body) => call<ApprovalReceipt>('POST', APPROVAL_PATH, 'json', { json: body, csrf }),
  decline: (csrf, body) => call<{ readonly envelope_state: 'declined' }>('POST', DECLINE_PATH, 'json', { json: body, csrf }),
};
