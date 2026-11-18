// SPDX-License-Identifier: Apache-2.0
//
// The verifier's one thrown error: a refused configuration. Inputs under test
// never throw; they come back as verdicts. A caller's options (anchors, the
// expected digests, the validation time) are checked first, and a malformed one
// is refused here, so that no bad configuration can end in `trusted` (row
// T012-ANCHORS, the product side). The message carries the code only, never a
// value from the caller.

export const CONFIG_ERROR_CODES = [
  'options-invalid',
  'input-invalid',
  'anchors-invalid',
  'expected-artifact-digest-invalid',
  'expected-approval-evidence-digest-invalid',
  'validation-time-invalid',
] as const;

export type ConfigErrorCode = (typeof CONFIG_ERROR_CODES)[number];

export class VerifierConfigError extends Error {
  readonly code: ConfigErrorCode;

  constructor(code: ConfigErrorCode) {
    super(code);
    this.name = 'VerifierConfigError';
    this.code = code;
  }
}
