// SPDX-License-Identifier: Apache-2.0
//
// Seal failures (T037). Every failure of sealComposedPdf() is a SealError with
// a fixed `code`, a `reason` from the closed list below and a `retryable` flag,
// the same shape T038 already handles for T036's ComposeError (request #43,
// Q8; data-model.md § Transitions and races, item 3).
//
// - Retryable (the T037 line, request #44): a worker crash (a signal or a
//   non-zero exit), the wall-time kill, a broken result frame, a failed spawn,
//   an abort (T038 aborts on lease loss), and every key-* reason, because T038
//   opens the key file again for each attempt.
// - Not retryable (request #44): length-mismatch, certificate-invalid, the
//   placeholder, /ByteRange and input faults, the document bound, and
//   worker-isolation: they repeat for the same inputs, or mean a deployment
//   defect that must fail closed.
//
// No message carries a path, PEM text, key bytes, child output or any value
// from the document: each message is a constant chosen by `reason`, the child
// can send only a reason from REASONS, and errors carry no `cause`.
// T038 writes `${code}:${reason}` to last_error_code (at most 60 characters,
// contracts/http-api.yaml SigningJob); the longest is 43.

import type { SealKeyErrorCode } from '../keys/index.ts';

export const SEAL_ERROR_CODE = 'seal_failed';

const KEY_CODES = [
  'source-refused',
  'key-material-in-environment',
  'key-material-in-argv',
  'path-not-absolute',
  'descriptor-invalid',
  'symlink-refused',
  'unopenable',
  'not-regular-file',
  'wrong-owner',
  'mode-too-open',
  'size-out-of-bounds',
  'changed-while-read',
  'encrypted-key-refused',
  'key-unreadable',
  'not-rsa',
  'wrong-modulus',
  'wrong-exponent',
] as const satisfies readonly SealKeyErrorCode[];

type KeyReason = `key-${(typeof KEY_CODES)[number]}`;

export type SealFailureReason =
  | 'worker-crashed'
  | 'worker-timeout'
  | 'worker-protocol'
  | 'worker-spawn-failed'
  | 'worker-isolation'
  | 'aborted'
  | KeyReason
  | 'key-certificate-mismatch'
  | 'key-signer-failed'
  | 'certificate-invalid'
  | 'input-invalid'
  | 'document-too-large'
  | 'placeholder-invalid'
  | 'byte-range-mismatch'
  | 'length-mismatch';

const RETRYABLE_FIXED: readonly SealFailureReason[] = ['worker-crashed', 'worker-timeout', 'worker-protocol', 'worker-spawn-failed', 'aborted', 'key-certificate-mismatch'];

const MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  'worker-crashed': 'the sealing worker ended without a complete result',
  'worker-timeout': 'the sealing worker exceeded its time limit and was stopped',
  'worker-protocol': 'the sealing worker returned a malformed or inconsistent result',
  'worker-spawn-failed': 'the sealing worker could not be started',
  'worker-isolation': 'the sealing worker refused to run outside its isolation profile',
  aborted: 'the seal was aborted and the sealing worker was stopped',
  'key-certificate-mismatch': 'the seal key does not match the signer certificate',
  'key-signer-failed': 'the seal key did not produce a valid signature',
  'certificate-invalid': 'the signer certificate is not usable for the seal',
  'input-invalid': 'the seal request is malformed',
  'document-too-large': 'the composed document exceeds MAX_SEALED_PDF_BYTES',
  'placeholder-invalid': 'the signature placeholder is not an unfilled placeholder at the stated offsets',
  'byte-range-mismatch': 'the /ByteRange written in the document differs from the stated byte range',
  'length-mismatch': 'the CMS length differs from the placeholder length',
});

/** Every reason a SealError can carry; the child's reply is checked against it. */
export const REASONS: ReadonlySet<string> = new Set<string>([...Object.keys(MESSAGES), ...KEY_CODES.map((code) => `key-${code}`)]);

export function isRetryable(reason: SealFailureReason): boolean {
  return reason.startsWith('key-') || RETRYABLE_FIXED.includes(reason);
}

export class SealError extends Error {
  readonly code: typeof SEAL_ERROR_CODE;
  readonly reason: SealFailureReason;
  readonly retryable: boolean;

  constructor(reason: SealFailureReason) {
    const known = REASONS.has(reason) ? reason : 'worker-protocol';
    super(MESSAGES[known] ?? 'the seal key was refused by key custody');
    this.name = 'SealError';
    this.code = SEAL_ERROR_CODE;
    this.reason = known as SealFailureReason;
    this.retryable = isRetryable(this.reason);
  }
}

/** The reason for a T013 SealKeyError code (unknown codes become worker-protocol). */
export function keyReason(code: string): SealFailureReason {
  return (KEY_CODES as readonly string[]).includes(code) ? (`key-${code}` as SealFailureReason) : 'worker-protocol';
}
