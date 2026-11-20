// SPDX-License-Identifier: Apache-2.0
//
// Envelope domain errors. Each carries the contract's Error code
// (contracts/http-api.json, components.schemas.Error) and the HTTP status the
// contract declares for it, so the operator handlers (T034) map them without
// a second table. Messages are generic: they never carry capability values,
// other tenants' facts or document content.

export type EnvelopeErrorCode =
  | 'invalid_request'
  | 'forbidden'
  | 'not_found'
  | 'version_conflict'
  | 'state_conflict'
  | 'order_conflict'
  | 'idempotency_conflict'
  | 'confirmation_required'
  | 'confirmation_invalid'
  | 'digest_mismatch'
  | 'field_out_of_bounds'
  | 'internal';

const STATUS: Readonly<Record<EnvelopeErrorCode, number>> = Object.freeze({
  invalid_request: 400,
  forbidden: 403,
  not_found: 404,
  version_conflict: 409,
  state_conflict: 409,
  order_conflict: 409,
  idempotency_conflict: 409,
  confirmation_required: 409,
  confirmation_invalid: 409,
  digest_mismatch: 409,
  field_out_of_bounds: 422,
  internal: 500,
});

export interface ErrorDetail {
  readonly field: string;
  readonly code: string;
}

export class EnvelopeError extends Error {
  readonly code: EnvelopeErrorCode;
  readonly status: number;
  readonly details: readonly ErrorDetail[];

  constructor(code: EnvelopeErrorCode, message: string, details: readonly ErrorDetail[] = []) {
    super(message);
    this.name = 'EnvelopeError';
    this.code = code;
    this.status = STATUS[code];
    this.details = Object.freeze(details.slice(0, 20));
  }
}

export function invalid(field: string, code: string, message = 'the request is invalid'): EnvelopeError {
  return new EnvelopeError('invalid_request', message, [{ field, code }]);
}
