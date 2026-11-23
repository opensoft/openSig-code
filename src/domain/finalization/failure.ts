// SPDX-License-Identifier: Apache-2.0
//
// Failure classification for a finalization attempt (T038; data-model.md
// § Transitions and races, item 3; A-010 requests #43, #44, #57, #59 (6) and
// #62 (2)).
//
// - A failure is retryable within the job's bounded attempts unless it is
//   marked non-retryable, which moves the job to `failed` at once.
// - T036's ComposeError and T037's SealError each carry `code`, `reason` and
//   `retryable`. The component's own flag decides; T038 never restates their
//   reason tables. So a compose refusal with `retryable: false` fails the job
//   at once, and T037's retryable reasons (crashes, signals, the timeout, a
//   broken reply, `aborted`, every `key-*` reason and `worker-spawn-failed`)
//   follow the bounded retry.
// - T016's PackageError carries `code` and `retryable: false` (equal inputs
//   fail the same way, and a retry reuses the anchor and the checkpoint), so
//   it fails the job at once as `package_refused.<code>`.
// - T038's own steps throw StepFailure with the same three fields:
//   - the verify step (request #59 (6), #62 (2)): a verdict outside the
//     invariant, or an exception the verifier reports, is not retryable,
//     because T014 is deterministic over the same bytes and a retry reuses
//     the anchor; a wall-time cap breach or a verification worker that dies
//     is retryable;
//   - a manifest that cannot be rebuilt from the stored records is a broken
//     invariant, not retryable.
// - A store-time BlobTooLargeError (T028) is not retryable: under the
//   sealed-PDF bound it cannot occur, so it marks a broken invariant.
// - last_error_code is `<code>.<reason>`, each part a short lowercase
//   identifier, and never a message, detail or any value taken from the
//   document. Anything else is recorded as a fixed code.

import { BlobTooLargeError } from '../../storage/blobs/index.ts';
import { StorageBusyError } from '../../storage/db/index.ts';
import { MAX_ERROR_CODE_LENGTH } from '../../storage/repositories/jobs.ts';

export type FailureStage = 'lease' | 'anchor' | 'compose' | 'manifest' | 'seal' | 'verify' | 'store' | 'package' | 'publish';

export interface FailureVerdict {
  readonly retryable: boolean;
  readonly errorCode: string;
}

/** The code recorded when a code or reason is not a short identifier. */
export const UNRECOGNIZED_ERROR_CODE = 'internal.unrecognized';

const PART = /^[a-z][a-z0-9_-]{0,39}$/;
const COMPONENT_STAGES: ReadonlySet<FailureStage> = new Set<FailureStage>(['compose', 'seal']);

/** A failure of one of T038's own steps; `code` and `reason` are fixed identifiers. */
export class StepFailure extends Error {
  readonly code: string;
  readonly reason: string;
  readonly retryable: boolean;

  constructor(code: string, reason: string, retryable: boolean) {
    super(`finalization step failed: ${code}.${reason}`);
    this.name = 'StepFailure';
    this.code = code;
    this.reason = reason;
    this.retryable = retryable;
  }
}

/** `<code>.<reason>` when both are short lowercase identifiers and the whole fits the contract; otherwise a fixed code. */
export function errorCodeOf(code: unknown, reason: unknown): string {
  if (typeof code === 'string' && typeof reason === 'string' && PART.test(code) && PART.test(reason)) {
    const joined = `${code}.${reason}`;
    if (joined.length <= MAX_ERROR_CODE_LENGTH) return joined;
  }
  return UNRECOGNIZED_ERROR_CODE;
}

function componentFlag(error: unknown): { readonly code: unknown; readonly reason: unknown; readonly retryable: boolean } | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const fields = error as { readonly code?: unknown; readonly reason?: unknown; readonly retryable?: unknown };
  if (typeof fields.retryable !== 'boolean') return undefined;
  return { code: fields.code, reason: fields.reason, retryable: fields.retryable };
}

/** Classify what an attempt's `stage` threw. */
export function classifyFailure(stage: FailureStage, error: unknown): FailureVerdict {
  if (error instanceof StepFailure) return { retryable: error.retryable, errorCode: errorCodeOf(error.code, error.reason) };
  if (error instanceof BlobTooLargeError) return { retryable: false, errorCode: `blob_too_large.${stage}` };
  if (COMPONENT_STAGES.has(stage)) {
    const flagged = componentFlag(error);
    if (flagged !== undefined) return { retryable: flagged.retryable, errorCode: errorCodeOf(flagged.code, flagged.reason) };
  }
  if (stage === 'package') {
    // T016's PackageError carries its own flag (never retryable: equal inputs fail the same way) and a code.
    const flagged = componentFlag(error);
    if (flagged !== undefined) return { retryable: flagged.retryable, errorCode: errorCodeOf('package_refused', flagged.code) };
  }
  if (error instanceof StorageBusyError) return { retryable: true, errorCode: `storage_busy.${stage}` };
  return { retryable: true, errorCode: `internal.${stage}` };
}
