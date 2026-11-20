// SPDX-License-Identifier: Apache-2.0
//
// Approval repository (T010): approvals, their receipts and the finalization
// reservation, through the tenant-scoped store only (every statement is
// filtered to the store's tenant). Writes need the caller's transaction
// (Database.transaction, BEGIN IMMEDIATE), the same one in which the envelope's
// compare-and-set moves it (src/storage/repositories/envelopes.ts,
// compareAndSetEnvelope), so an approval, its receipt and a reservation commit
// with the transition they belong to, or not at all.
//
// - approvals (migration 0003): immutable; one per recipient; the consent
//   version and digest must be those of the referenced consent text, and the
//   prior approval digest must follow the recipient order (0003 triggers).
// - approval_receipts (migration 0017): the exact bytes of the receipt the
//   recipient received and the digest of the request that produced it, one per
//   approval and per recipient. Immutable: no update, no delete, and no insert
//   that repeats a key or a stored rowid, so no receipt is ever replaced. A
//   stored receipt is checked against its digest before it is replayed.
// - signing_jobs (migration 0004): the finalization reservation. The
//   transaction that moves the envelope into finalizing (the last required
//   approval) inserts the envelope's SigningJob with reserved_version, the
//   version that transition wrote, and status pending (data-model.md
//   § Entities, SigningJob; T007 ruling: T010, not T007, inserts it). The
//   finalization runner (T038) leases and runs it.

import { createHash } from 'node:crypto';

import type { Row, TenantStore } from '../db/index.ts';
import { StorageUsageError } from '../db/index.ts';

/** The largest receipt a row keeps; migration 0017 enforces the same bound. */
export const MAX_RECEIPT_BYTES = 16_384;

export interface NewApproval {
  readonly id: string;
  readonly envelopeId: string;
  readonly recipientId: string;
  readonly documentDigest: string;
  readonly manifestDigest: string;
  readonly priorApprovalDigest: string | null;
  readonly consentTextId: string;
  readonly consentVersion: string;
  readonly consentTextDigest: string;
  /** The RFC 8785 text of the contract FieldValue array. */
  readonly fieldValuesJson: string;
  readonly fieldValuesDigest: string;
  readonly serverTime: string;
  readonly approvalDigest: string;
}

export interface ApprovalRow extends NewApproval {
  readonly assuranceMethod: string;
  readonly assuranceLevel: string;
}

export interface NewReceipt {
  readonly approvalId: string;
  readonly envelopeId: string;
  readonly recipientId: string;
  readonly requestDigest: string;
  /** The exact RFC 8785 bytes of the ApprovalReceipt sent to the recipient. */
  readonly body: Uint8Array;
  readonly createdAt: string;
}

export interface ReceiptRecord extends NewReceipt {
  readonly body: Buffer;
}

export interface NewReservation {
  readonly envelopeId: string;
  /** The envelope version written by the transition into finalizing. */
  readonly reservedVersion: number;
  readonly maxAttempts: number;
  readonly now: string;
}

const DIGEST = /^[0-9a-f]{64}$/;

function stored(table: string, column: string): StorageUsageError {
  return new StorageUsageError(`${table}.${column} holds an unexpected value`);
}

function str(row: Row, table: string, column: string): string {
  const value = row[column];
  if (typeof value !== 'string') throw stored(table, column);
  return value;
}

function optStr(row: Row, table: string, column: string): string | null {
  const value = row[column];
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') throw stored(table, column);
  return value;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

// ------------------------------------------------------------------ approvals

export function insertApproval(store: TenantStore, approval: NewApproval): void {
  store.insert('approvals', {
    id: approval.id,
    envelope_id: approval.envelopeId,
    recipient_id: approval.recipientId,
    document_digest: approval.documentDigest,
    manifest_digest: approval.manifestDigest,
    prior_approval_digest: approval.priorApprovalDigest,
    consent_text_id: approval.consentTextId,
    consent_version: approval.consentVersion,
    consent_text_digest: approval.consentTextDigest,
    field_values_json: approval.fieldValuesJson,
    field_values_digest: approval.fieldValuesDigest,
    assurance_method: 'mailbox-challenge',
    assurance_level: 'mailbox-control',
    server_time: approval.serverTime,
    approval_digest: approval.approvalDigest,
  });
}

function approvalFromRow(row: Row): ApprovalRow {
  return {
    id: str(row, 'approvals', 'id'),
    envelopeId: str(row, 'approvals', 'envelope_id'),
    recipientId: str(row, 'approvals', 'recipient_id'),
    documentDigest: str(row, 'approvals', 'document_digest'),
    manifestDigest: str(row, 'approvals', 'manifest_digest'),
    priorApprovalDigest: optStr(row, 'approvals', 'prior_approval_digest'),
    consentTextId: str(row, 'approvals', 'consent_text_id'),
    consentVersion: str(row, 'approvals', 'consent_version'),
    consentTextDigest: str(row, 'approvals', 'consent_text_digest'),
    fieldValuesJson: str(row, 'approvals', 'field_values_json'),
    fieldValuesDigest: str(row, 'approvals', 'field_values_digest'),
    assuranceMethod: str(row, 'approvals', 'assurance_method'),
    assuranceLevel: str(row, 'approvals', 'assurance_level'),
    serverTime: str(row, 'approvals', 'server_time'),
    approvalDigest: str(row, 'approvals', 'approval_digest'),
  };
}

/** The recipient's approval, if any (one per recipient, 0003). */
export function getApprovalOf(store: TenantStore, recipientId: string): ApprovalRow | undefined {
  const row = store.get('approvals', { recipient_id: recipientId });
  return row === undefined ? undefined : approvalFromRow(row);
}

// ------------------------------------------------------------------- receipts

/** Store the receipt of a new approval, in the approval's own transaction. */
export function insertApprovalReceipt(store: TenantStore, receipt: NewReceipt): void {
  if (!DIGEST.test(receipt.requestDigest)) throw new StorageUsageError('approval request digest is malformed');
  if (!(receipt.body instanceof Uint8Array) || receipt.body.byteLength < 2 || receipt.body.byteLength > MAX_RECEIPT_BYTES) {
    throw new StorageUsageError(`an approval receipt must hold 2..${MAX_RECEIPT_BYTES} bytes`);
  }
  store.insert('approval_receipts', {
    approval_id: receipt.approvalId,
    envelope_id: receipt.envelopeId,
    recipient_id: receipt.recipientId,
    request_digest: receipt.requestDigest,
    receipt_body: receipt.body,
    receipt_digest: sha256Hex(receipt.body),
    created_at: receipt.createdAt,
  });
}

/** The recipient's receipt (checked against its stored digest), if any. */
export function getApprovalReceiptOf(store: TenantStore, recipientId: string): ReceiptRecord | undefined {
  const row = store.get('approval_receipts', { recipient_id: recipientId });
  if (row === undefined) return undefined;
  const body = row['receipt_body'];
  if (!(body instanceof Uint8Array)) throw stored('approval_receipts', 'receipt_body');
  const bytes = Buffer.from(body);
  if (sha256Hex(bytes) !== str(row, 'approval_receipts', 'receipt_digest')) {
    throw new StorageUsageError('the stored approval receipt does not match its digest');
  }
  return {
    approvalId: str(row, 'approval_receipts', 'approval_id'),
    envelopeId: str(row, 'approval_receipts', 'envelope_id'),
    recipientId: str(row, 'approval_receipts', 'recipient_id'),
    requestDigest: str(row, 'approval_receipts', 'request_digest'),
    body: bytes,
    createdAt: str(row, 'approval_receipts', 'created_at'),
  };
}

// ------------------------------------------------------ finalization reservation

/**
 * Reserve finalization: insert the envelope's SigningJob (pending, no attempt
 * yet, reserved_version = the version of the transition into finalizing). It
 * must run in the transaction whose compare-and-set made that transition; the
 * primary key (tenant, envelope) admits one job per envelope.
 */
export function insertFinalizationReservation(store: TenantStore, reservation: NewReservation): void {
  if (!Number.isSafeInteger(reservation.reservedVersion) || reservation.reservedVersion < 1) {
    throw new StorageUsageError('the reserved version must be a positive integer');
  }
  if (!Number.isSafeInteger(reservation.maxAttempts) || reservation.maxAttempts < 1 || reservation.maxAttempts > 100) {
    throw new StorageUsageError('max attempts must be an integer in 1..100');
  }
  store.insert('signing_jobs', {
    envelope_id: reservation.envelopeId,
    reserved_version: reservation.reservedVersion,
    status: 'pending',
    attempt_count: 0,
    max_attempts: reservation.maxAttempts,
    created_at: reservation.now,
    updated_at: reservation.now,
  });
}

/** The reserved version of the envelope's SigningJob, or null when finalization is not reserved. */
export function reservedVersionOf(store: TenantStore, envelopeId: string): number | null {
  const row = store.get('signing_jobs', { envelope_id: envelopeId });
  if (row === undefined) return null;
  const value = row['reserved_version'];
  const n = typeof value === 'bigint' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isSafeInteger(n)) throw stored('signing_jobs', 'reserved_version');
  return n;
}
