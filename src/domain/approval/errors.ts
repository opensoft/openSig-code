// SPDX-License-Identifier: Apache-2.0
//
// Approval and decline errors (T010). Each carries the contract's Error code
// (contracts/http-api.json, components.schemas.Error) and the HTTP status the
// contract declares for it on approveAsHuman and declineAsRecipient, so the
// handlers map them without a second table. Messages are generic: they never
// carry a capability value, a field value, another envelope's facts or another
// tenant's facts. Details name a member, never its value.

export type ApprovalErrorCode =
  | 'invalid_request'
  | 'unauthenticated'
  | 'version_conflict'
  | 'state_conflict'
  | 'order_conflict'
  | 'digest_mismatch'
  | 'consent_mismatch'
  | 'unsupported_characters'
  | 'internal';

const STATUS: Readonly<Record<ApprovalErrorCode, number>> = Object.freeze({
  invalid_request: 400,
  unauthenticated: 401,
  version_conflict: 409,
  state_conflict: 409,
  order_conflict: 409,
  digest_mismatch: 409,
  consent_mismatch: 409,
  unsupported_characters: 422,
  internal: 500,
});

export interface ApprovalErrorDetail {
  readonly field: string;
  readonly code: string;
}

export class ApprovalError extends Error {
  readonly code: ApprovalErrorCode;
  readonly status: number;
  readonly details: readonly ApprovalErrorDetail[];
  /**
   * True when the request was refused because the envelope's expires_at had
   * passed before the reservation. The service then commits that expiry in its
   * own transaction (T007 ruling: advanceOnApproval refuses an expired envelope
   * inside the caller's transaction; T010 commits the expiry separately).
   */
  readonly expired: boolean;

  constructor(code: ApprovalErrorCode, message: string, details: readonly ApprovalErrorDetail[] = [], options: { readonly expired?: boolean } = {}) {
    super(message);
    this.name = 'ApprovalError';
    this.code = code;
    this.status = STATUS[code];
    this.details = Object.freeze(details.slice(0, 20).map((detail) => Object.freeze({ field: detail.field.slice(0, 100), code: detail.code.slice(0, 60) })));
    this.expired = options.expired === true;
  }
}

/** 400 invalid_request naming the member and the rule it broke. */
export function invalid(field: string, code: string): ApprovalError {
  return new ApprovalError('invalid_request', 'the request is invalid', [{ field, code }]);
}
