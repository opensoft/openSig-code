// SPDX-License-Identifier: Apache-2.0
//
// Finalization errors (T038).
//
// - FinalizationError carries the contract's Error code, the HTTP status the
//   contract declares for it (contracts/http-api.yaml, retryFinalization: 400,
//   404, 409) and the contract ErrorDetail list, so the retry handler maps it
//   without a second table. The attempt ceiling is 409
//   finalization_not_retryable with detail { field: 'envelope', code:
//   'attempt_ceiling' } (A-010, request #59 (4)).
// - PublishRefused is the publish compare-and-set's refusal. It is thrown
//   inside the publish transaction, so the transaction rolls back and nothing
//   is written. It never reaches HTTP. The runner (src/jobs/finalize.ts)
//   treats fence, state, version and checkpoint as a lost attempt (no state
//   change of its own), and records blob as the retryable step failure
//   publish_refused.blob-missing under its still-held lease.
// Messages are generic: no document value, key material or capability value.

export type FinalizationErrorCode = 'invalid_request' | 'not_found' | 'version_conflict' | 'idempotency_conflict' | 'finalization_not_retryable' | 'internal';

const STATUS: Readonly<Record<FinalizationErrorCode, number>> = Object.freeze({
  invalid_request: 400,
  not_found: 404,
  version_conflict: 409,
  idempotency_conflict: 409,
  finalization_not_retryable: 409,
  internal: 500,
});

export interface FinalizationErrorDetail {
  readonly field: string;
  readonly code: string;
}

/** The detail of a retry refused at the 100-attempt ceiling (request #59 (4)). */
export const ATTEMPT_CEILING_DETAIL: FinalizationErrorDetail = Object.freeze({ field: 'envelope', code: 'attempt_ceiling' });

export class FinalizationError extends Error {
  readonly code: FinalizationErrorCode;
  readonly status: number;
  readonly details: readonly FinalizationErrorDetail[];

  constructor(code: FinalizationErrorCode, message: string, details: readonly FinalizationErrorDetail[] = []) {
    super(message);
    this.name = 'FinalizationError';
    this.code = code;
    this.status = STATUS[code];
    this.details = Object.freeze(details.map((detail) => Object.freeze({ field: detail.field, code: detail.code })));
  }
}

/**
 * Why a publish wrote nothing:
 * - fence: the job is not running under this attempt's token and owner with
 *   an unexpired lease (stale token, reclaimed or superseded lease);
 * - state: the envelope is not finalizing;
 * - version: the envelope is not at the version the attempt worked against;
 * - checkpoint: the receipt head is not the envelope's completion checkpoint;
 * - blob: a blob the artifact references is not stored intact.
 */
export type PublishRefusalReason = 'fence' | 'state' | 'version' | 'checkpoint' | 'blob';

export class PublishRefused extends Error {
  readonly reason: PublishRefusalReason;

  constructor(reason: PublishRefusalReason) {
    super(`finalization publish refused: ${reason}`);
    this.name = 'PublishRefused';
    this.reason = reason;
  }
}
