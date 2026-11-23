// SPDX-License-Identifier: Apache-2.0
//
// Request bodies of the anonymous recipient operations (T008), checked against
// the vendored contract schemas: ChallengeRequest {invitation} and
// SessionCreate {invitation, code}, with additionalProperties false. A
// violation is 400 invalid_request whose details name the member, never its
// value. The server (src/server/body.ts) has already enforced the media type,
// the 256 KiB limit and valid JSON.

import { HttpError } from '../../server/types.ts';

/** ChallengeRequest.invitation and SessionCreate.invitation: base64url, 43 to 128 characters. */
export const INVITATION_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;
/** SessionCreate.code, exactly as the contract states it. */
export const SESSION_CODE_PATTERN = /^[0-9A-HJ-NP-Z]{10}$/;

function invalid(field: string, code: string): HttpError {
  return new HttpError(400, 'invalid_request', { details: [{ field, code }] });
}

function record(body: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw invalid('', 'invalid_type');
  for (const key of Object.keys(body)) if (!allowed.includes(key)) throw invalid(key.slice(0, 100), 'unknown_property');
  return body as Record<string, unknown>;
}

function invitation(value: unknown): string {
  if (value === undefined) throw invalid('invitation', 'required');
  if (typeof value !== 'string' || !INVITATION_PATTERN.test(value)) throw invalid('invitation', 'invalid_format');
  return value;
}

/** requestChallenge body: the invitation read from the URL fragment. */
export function checkChallengeRequest(body: unknown): string {
  return invitation(record(body, ['invitation'])['invitation']);
}

/** createRecipientSession body: the invitation and the mailed code. */
export function checkSessionCreate(body: unknown): { readonly invitation: string; readonly code: string } {
  const input = record(body, ['invitation', 'code']);
  const token = invitation(input['invitation']);
  const code = input['code'];
  if (code === undefined) throw invalid('code', 'required');
  if (typeof code !== 'string' || !SESSION_CODE_PATTERN.test(code)) throw invalid('code', 'invalid_format');
  return { invitation: token, code };
}
