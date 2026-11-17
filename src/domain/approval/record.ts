// SPDX-License-Identifier: Apache-2.0
//
// The Approval record, its digests and the receipt (T010; data-model.md
// § Entities, Approval; contract ApprovalRecord and ApprovalReceipt). Every
// digest goes through the project's single canonicalizer
// (src/domain/canonical/, RFC 8785).
//
// - field values: the checked values (values.ts), sorted by key, exactly as the
//   contract's FieldValue shapes: drawn {key, type, mode, strokes}, typed
//   {key, type, mode, text} and date {key, type}. They are stored as the RFC 8785
//   text of that array (approvals.field_values_json).
// - date values: the server fills every date field from the server's UTC time
//   at approval, as YYYY-MM-DD; the client never sends one. They are derived
//   from the approval's server_time and its date keys, so they need no column.
// - field_values_digest = SHA-256(RFC 8785({field_values, date_values})): it
//   binds the server-filled dates as well as the values the recipient gave.
// - the record is the contract's ApprovalRecord without approval_digest:
//   {approval_id, recipient {id, ordinal, role, email}, assurance {method,
//   level}, consent_version, consent_text_digest, document_digest,
//   manifest_digest, prior_approval_digest, field_values, date_values,
//   field_values_digest, server_time}, and approval_digest =
//   SHA-256(RFC 8785(record)) (data-model.md: SHA-256(JCS(record without
//   approval_digest))). prior_approval_digest is null for ordinal 1 and the
//   approval_digest of ordinal 1 for ordinal 2, so the approvals chain in
//   recipient order (the sequential approval digests; migration 0003's
//   approvals_sequence trigger enforces the same link).
// - the receipt is the contract's ApprovalReceipt. Its exact RFC 8785 bytes are
//   stored with the approval (approval_receipts, migration 0017), so an exact
//   retry returns the original receipt byte for byte, also after the envelope
//   has moved on.

import { canonicalDigest, type JsonValue } from '../../domain/canonical/index.ts';
import type { FieldValue } from './values.ts';

export const APPROVAL_ASSURANCE = Object.freeze({ method: 'mailbox-challenge', level: 'mailbox-control' } as const);

/** The request digest's schema label: an exact retry is the same request of the same recipient. */
export const APPROVAL_REQUEST_SCHEMA = 'opensig.approval-request/1';

export interface DateValue {
  readonly key: string;
  readonly value: string;
}

export interface ApprovalRecipient {
  readonly id: string;
  readonly ordinal: number;
  readonly role: string;
  readonly email: string;
}

export interface ApprovalRecordInput {
  readonly approvalId: string;
  readonly recipient: ApprovalRecipient;
  readonly consentVersion: string;
  readonly consentTextDigest: string;
  readonly documentDigest: string;
  readonly manifestDigest: string;
  readonly priorApprovalDigest: string | null;
  readonly fieldValues: readonly FieldValue[];
  readonly serverTime: string;
}

export interface BuiltApproval {
  /** The contract FieldValue array, sorted by key. */
  readonly fieldValues: JsonValue[];
  readonly dateValues: readonly DateValue[];
  readonly fieldValuesDigest: string;
  /** The ApprovalRecord without approval_digest: the digest preimage. */
  readonly record: JsonValue;
  readonly approvalDigest: string;
}

/** The UTC calendar date (YYYY-MM-DD) of an unsigned server time in toISOString() form. */
export function serverDate(serverTime: string): string {
  const ms = Date.parse(serverTime);
  if (!Number.isFinite(ms)) throw new TypeError('server time is not a date-time');
  return new Date(ms).toISOString().slice(0, 10);
}

/** One contract FieldValue as plain JSON data. */
export function fieldValueJson(value: FieldValue): JsonValue {
  if (value.type === 'date') return { key: value.key, type: 'date' };
  if (value.mode === 'typed') return { key: value.key, type: 'signature', mode: 'typed', text: value.text };
  return { key: value.key, type: 'signature', mode: 'drawn', strokes: value.strokes.map((stroke) => stroke.map((point) => [point[0], point[1]])) };
}

/** The server-filled value of every date field, sorted by key. */
export function dateValuesOf(fieldValues: readonly FieldValue[], serverTime: string): DateValue[] {
  const date = serverDate(serverTime);
  return fieldValues
    .filter((value) => value.type === 'date')
    .map((value) => ({ key: value.key, value: date }))
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

function dateValuesJson(dateValues: readonly DateValue[]): JsonValue[] {
  return dateValues.map((entry) => ({ key: entry.key, value: entry.value }));
}

/** field_values_digest: SHA-256 of the RFC 8785 form of {field_values, date_values}. */
export function fieldValuesDigest(fieldValues: readonly JsonValue[], dateValues: readonly DateValue[]): string {
  return canonicalDigest({ field_values: [...fieldValues], date_values: dateValuesJson(dateValues) });
}

/** Build the approval's values, record and approval_digest. */
export function buildApproval(input: ApprovalRecordInput): BuiltApproval {
  const sorted = [...input.fieldValues].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  const fieldValues = sorted.map(fieldValueJson);
  const dateValues = dateValuesOf(sorted, input.serverTime);
  const valuesDigest = fieldValuesDigest(fieldValues, dateValues);
  const record: JsonValue = {
    approval_id: input.approvalId,
    recipient: { id: input.recipient.id, ordinal: input.recipient.ordinal, role: input.recipient.role, email: input.recipient.email },
    assurance: { method: APPROVAL_ASSURANCE.method, level: APPROVAL_ASSURANCE.level },
    consent_version: input.consentVersion,
    consent_text_digest: input.consentTextDigest,
    document_digest: input.documentDigest,
    manifest_digest: input.manifestDigest,
    prior_approval_digest: input.priorApprovalDigest,
    field_values: fieldValues,
    date_values: dateValuesJson(dateValues),
    field_values_digest: valuesDigest,
    server_time: input.serverTime,
  };
  return { fieldValues, dateValues, fieldValuesDigest: valuesDigest, record, approvalDigest: canonicalDigest(record) };
}

/**
 * The digest that tells an exact retry from a changed one: the recipient and
 * every member of the checked request, the values sorted by key. Two requests
 * that differ only in member order or whitespace are the same request.
 */
export function approvalRequestDigest(recipientId: string, request: {
  readonly expectedVersion: number;
  readonly documentDigest: string;
  readonly manifestDigest: string;
  readonly priorApprovalDigest: string | null;
  readonly consentVersion: string;
  readonly consentTextDigest: string;
  readonly fieldValues: readonly FieldValue[];
}): string {
  return canonicalDigest({
    schema: APPROVAL_REQUEST_SCHEMA,
    recipient_id: recipientId,
    expected_version: request.expectedVersion,
    document_digest: request.documentDigest,
    manifest_digest: request.manifestDigest,
    prior_approval_digest: request.priorApprovalDigest,
    consent_version: request.consentVersion,
    consent_text_digest: request.consentTextDigest,
    consent: true,
    field_values: [...request.fieldValues].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0)).map(fieldValueJson),
  });
}

export interface ReceiptInput {
  readonly approvalId: string;
  readonly approvalDigest: string;
  readonly recipientId: string;
  readonly envelopeVersion: number;
  readonly envelopeState: 'in-progress' | 'finalizing';
  readonly dateValues: readonly DateValue[];
  readonly serverTime: string;
}

/** The contract ApprovalReceipt. */
export function receiptView(input: ReceiptInput): JsonValue {
  return {
    approval_id: input.approvalId,
    approval_digest: input.approvalDigest,
    recipient_id: input.recipientId,
    envelope_version: input.envelopeVersion,
    envelope_state: input.envelopeState,
    date_values: dateValuesJson(input.dateValues),
    server_time: input.serverTime,
  };
}
