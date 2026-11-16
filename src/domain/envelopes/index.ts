// SPDX-License-Identifier: Apache-2.0
//
// Public surface of the envelope domain (T007): the state machine, freeze at
// prepare, send rules, idempotent mutations and the contract views.

export { EnvelopeError, type EnvelopeErrorCode, type ErrorDetail } from './errors.ts';
export {
  buildFieldManifest,
  FIELD_MANIFEST_SCHEMA,
  recipientsDigest,
  recipientsPreview,
  type DigestRecipient,
  type FieldManifest,
  type FrozenManifest,
  type ManifestField,
} from './manifest.ts';
export {
  CONFIRMATION_TTL_MS,
  confirmationExpiry,
  confirmationProblems,
  confirmationRequired,
  type ConfirmationProblem,
  type ConfirmationTarget,
} from './send.ts';
export {
  EnvelopeService,
  ROUTES,
  type ApprovalAdvance,
  type ApprovalOutcome,
  type EnvelopeChange,
  type EnvelopeOperation,
  type EnvelopeServiceOptions,
  type MutationResult,
  type OperatorRequest,
} from './service.ts';
export {
  APPROVING_STATES,
  canTransition,
  ENVELOPE_STATES,
  FULLY_APPROVED_STATES,
  isFullyApproved,
  isTerminal,
  PRE_RESERVATION_STATES,
  RECIPIENT_STATUSES,
  REISSUABLE_STATES,
  stateAfterApproval,
  TERMINAL_STATES,
  TRANSITIONS,
  turnAfter,
  type EnvelopeState,
  type RecipientStatus,
} from './states.ts';
export {
  DEFAULT_EXPIRY_MS,
  MAX_EXPIRY_MS,
  type Actor,
  type DocumentInput,
  type EnvelopeCreateInput,
  type FieldInput,
  type PageGeometry,
  type PrepareInput,
  type Rect,
  type SendConfirmationInput,
  type SendInput,
  type Source,
  type VersionInput,
  type VoidInput,
} from './validation.ts';
export { envelopeView, previewView, sendConfirmationView } from './views.ts';
