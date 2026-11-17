// SPDX-License-Identifier: Apache-2.0
//
// Public surface of approval and decline (T010): the request rules (typed
// field values, stroke caps, integer coordinates, the 15,000-point budget,
// WinAnsi typed text), the approval record and its digests, the receipt, and
// the service that records an approval or a decline through the envelope's one
// compare-and-set path, reserving finalization with the last approval.

export { ApprovalError, invalid, type ApprovalErrorCode, type ApprovalErrorDetail } from './errors.ts';
export {
  APPROVAL_ASSURANCE,
  APPROVAL_REQUEST_SCHEMA,
  approvalRequestDigest,
  buildApproval,
  dateValuesOf,
  fieldValueJson,
  fieldValuesDigest,
  receiptView,
  serverDate,
  type ApprovalRecipient,
  type ApprovalRecordInput,
  type BuiltApproval,
  type DateValue,
  type ReceiptInput,
} from './record.ts';
export {
  ApprovalService,
  FINALIZATION_MAX_ATTEMPTS,
  type ApprovalResult,
  type ApprovalServiceOptions,
  type ApprovalSession,
  type DeclineResult,
} from './service.ts';
export {
  checkApprovalRequest,
  checkDeclineRequest,
  CONSENT_VERSION_PATTERN,
  DECLINE_REASONS,
  DIGEST_PATTERN,
  FIELD_KEY_PATTERN,
  MALFORMED_BODY,
  MAX_COORDINATE,
  MAX_FIELD_VALUES,
  MAX_POINTS_PER_APPROVAL,
  MAX_POINTS_PER_STROKE,
  MAX_POINTS_PER_VALUE,
  MAX_STROKES_PER_VALUE,
  MAX_TYPED_TEXT_LENGTH,
  MIN_POINTS_PER_STROKE,
  type ApprovalRequest,
  type DateFieldValue,
  type DeclineReason,
  type DeclineRequest,
  type DrawnSignatureValue,
  type FieldValue,
  type Point,
  type TypedSignatureValue,
} from './values.ts';
export { expiryAnnouncer, type EnvelopeChangeListener } from './events.ts';
export { isWinAnsiCodePoint, isWinAnsiText, WINANSI_HIGH_CODE_POINTS } from './winansi.ts';
