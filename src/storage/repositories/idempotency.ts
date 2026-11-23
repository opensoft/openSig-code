// SPDX-License-Identifier: Apache-2.0
//
// Idempotency records (T007; data-model.md § Entities, IdempotencyRecord,
// ratified in A-010; contract parameter Idempotency-Key). A record is scoped by
// tenant (the store), route, principal and key. It holds the SHA-256 of the
// RFC 8785 form of the request and the response status, so the same key with
// the same request replays the original result and a changed request is
// detected. Request and body digests go through the single canonical module,
// src/domain/canonical/index.ts.
//
// response_body (migration 0011) has two explicit modes:
// - body: the exact response bytes the client received (the RFC 8785 form of
//   the response) and their SHA-256. At most 256 KiB: a larger body throws
//   IdempotencyBodyTooLarge, which fails the caller's transaction; it is never
//   truncated. Operator responses carry no capability value, so nothing is
//   stored that the response did not carry.
// - withheld: no body and no body digest, for a route whose response reveals a
//   one-time secret (webhook key issuance, T019). Its replay can never reveal
//   the secret again; the route rules the replay status.
//
// Records live 24 hours. An expired record is no longer a replay: the caller
// deletes it and runs the request anew. purgeExpiredIdempotencyRecords deletes
// expired records in bounded batches. They are operational data, not evidence,
// so a purge writes no DisposalRecord and no audit event. Records are inserted
// in the transaction of the mutation they describe and are otherwise immutable
// (schema trigger of 0004).

import { createHash } from 'node:crypto';

import { canonicalBytes, canonicalDigest, type JsonValue } from '../../domain/canonical/index.ts';
import type { Row, TenantStore } from '../db/index.ts';
import { StorageError, StorageUsageError } from '../db/index.ts';

export const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
/** The largest response body a record keeps: 256 KiB. */
export const MAX_IDEMPOTENCY_BODY_BYTES = 256 * 1024;
/** How long a record lives: 24 hours. */
export const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;
/** The default and the largest number of records one purge call deletes. */
export const DEFAULT_PURGE_BATCH = 500;
export const MAX_PURGE_BATCH = 1000;

const ROUTE_PATTERN = /^[A-Za-z0-9_.:/{}-]{1,100}$/;
const DIGEST = /^[0-9a-f]{64}$/;

/** A response body over the replay limit: the mutation's transaction must fail, never store a truncated body. */
export class IdempotencyBodyTooLarge extends StorageError {
  readonly bytes: number;

  constructor(bytes: number, limit: number) {
    super('idempotency_body_too_large', `the response body (${bytes} bytes) exceeds the ${limit}-byte idempotency limit`);
    this.bytes = bytes;
  }
}

export interface IdempotencyPrincipal {
  readonly kind: 'human-operator' | 'service';
  readonly ref: string;
}

export interface IdempotencyRecord {
  readonly route: string;
  readonly principal: IdempotencyPrincipal;
  readonly key: string;
  readonly requestDigest: string;
  readonly responseStatus: number;
  readonly responseBody: Uint8Array | null;
  readonly responseBodyDigest: string | null;
  readonly resourceId: string | null;
  readonly createdAt: string;
}

/** What a record keeps of the response: its exact body, or (for a one-time secret) nothing. */
export type RecordedResponseInput = { readonly kind: 'body'; readonly body: JsonValue } | { readonly kind: 'withheld' };

export type RecordedResponse = { readonly kind: 'body'; readonly bytes: Buffer } | { readonly kind: 'withheld' };

export interface NewIdempotencyRecord {
  readonly route: string;
  readonly principal: IdempotencyPrincipal;
  readonly key: string;
  readonly requestDigest: string;
  readonly responseStatus: number;
  readonly response: RecordedResponseInput;
  readonly resourceId: string | null;
  readonly createdAt: string;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function checkScope(route: string, key: string): void {
  if (typeof route !== 'string' || !ROUTE_PATTERN.test(route)) throw new StorageUsageError('idempotency route is malformed');
  if (typeof key !== 'string' || !IDEMPOTENCY_KEY_PATTERN.test(key)) throw new StorageUsageError('idempotency key is malformed');
}

function checkLimit(limit: number): number {
  if (!Number.isSafeInteger(limit) || limit < 2 || limit > MAX_IDEMPOTENCY_BODY_BYTES) {
    throw new StorageUsageError(`the idempotency body limit must be an integer in 2..${MAX_IDEMPOTENCY_BODY_BYTES}`);
  }
  return limit;
}

/** The digest that binds a key to its request: SHA-256 of the request's RFC 8785 form. */
export function idempotencyRequestDigest(request: JsonValue): string {
  return canonicalDigest(request);
}

/** True once the record has lived 24 hours; it is then no longer a replay. */
export function isIdempotencyRecordExpired(record: IdempotencyRecord, now: Date): boolean {
  return Date.parse(record.createdAt) + IDEMPOTENCY_TTL_MS <= now.getTime();
}

function recordFromRow(row: Row): IdempotencyRecord {
  const text = (column: string): string => {
    const value = row[column];
    if (typeof value !== 'string') throw new StorageUsageError(`idempotency_records.${column} holds an unexpected value`);
    return value;
  };
  const optional = (column: string): string | null => (row[column] === null ? null : text(column));
  const body = row['response_body'];
  if (body !== null && !(body instanceof Uint8Array)) throw new StorageUsageError('idempotency_records.response_body holds an unexpected value');
  const kind = text('principal_kind');
  if (kind !== 'human-operator' && kind !== 'service') throw new StorageUsageError('idempotency_records.principal_kind holds an unexpected value');
  return {
    route: text('route'),
    principal: { kind, ref: text('principal_ref') },
    key: text('key'),
    requestDigest: text('request_digest'),
    responseStatus: Number(row['response_status']),
    responseBody: body,
    responseBodyDigest: optional('response_body_digest'),
    resourceId: optional('resource_id'),
    createdAt: text('created_at'),
  };
}

export function findIdempotencyRecord(store: TenantStore, route: string, principalRef: string, key: string): IdempotencyRecord | undefined {
  checkScope(route, key);
  const row = store.get('idempotency_records', { route, principal_ref: principalRef, key });
  return row === undefined ? undefined : recordFromRow(row);
}

/**
 * Insert the record of a successful mutation, in that mutation's transaction.
 * In body mode, returns the exact response bytes stored (the RFC 8785 form of
 * the body) and throws IdempotencyBodyTooLarge past `maxBodyBytes` (at most,
 * and by default, 256 KiB). In withheld mode, stores no body and returns null.
 */
export function insertIdempotencyRecord(store: TenantStore, record: NewIdempotencyRecord, maxBodyBytes = MAX_IDEMPOTENCY_BODY_BYTES): Buffer | null {
  checkScope(record.route, record.key);
  const limit = checkLimit(maxBodyBytes);
  if (!DIGEST.test(record.requestDigest)) throw new StorageUsageError('idempotency request digest is malformed');
  let body: Buffer | null = null;
  if (record.response.kind === 'body') {
    body = canonicalBytes(record.response.body);
    if (body.length > limit) throw new IdempotencyBodyTooLarge(body.length, limit);
  } else if (record.response.kind !== 'withheld') {
    throw new StorageUsageError('the recorded response must be a body or withheld');
  }
  store.insert('idempotency_records', {
    route: record.route,
    principal_kind: record.principal.kind,
    principal_ref: record.principal.ref,
    key: record.key,
    request_digest: record.requestDigest,
    response_status: record.responseStatus,
    response_body: body,
    response_body_digest: body === null ? null : sha256Hex(body),
    resource_id: record.resourceId,
    created_at: record.createdAt,
  });
  return body;
}

/** What a record replays: its exact stored bytes (checked against their digest), or withheld. */
export function recordedResponse(record: IdempotencyRecord): RecordedResponse {
  if (record.responseBody === null && record.responseBodyDigest === null) return { kind: 'withheld' };
  if (record.responseBody === null || record.responseBodyDigest === null) {
    throw new StorageUsageError('the idempotency record holds a body without its digest, or a digest without its body');
  }
  const bytes = Buffer.from(record.responseBody);
  if (sha256Hex(bytes) !== record.responseBodyDigest) {
    throw new StorageUsageError('the stored idempotency response does not match its digest');
  }
  return { kind: 'body', bytes };
}

/** Delete one record (an expired one, before its key is used again). */
export function deleteIdempotencyRecord(store: TenantStore, record: IdempotencyRecord): void {
  const changed = store.delete('idempotency_records', { route: record.route, principal_ref: record.principal.ref, key: record.key });
  if (changed !== 1) throw new StorageUsageError(`idempotency record delete changed ${changed} rows, expected exactly one`);
}

/**
 * Delete at most `batchSize` of the tenant's expired records (oldest first) in
 * the caller's transaction; returns how many were deleted. Call again until it
 * returns fewer than `batchSize`. Writes nothing else: no DisposalRecord, no
 * audit event.
 */
export function purgeExpiredIdempotencyRecords(store: TenantStore, now: Date, batchSize = DEFAULT_PURGE_BATCH): number {
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > MAX_PURGE_BATCH) {
    throw new StorageUsageError(`the purge batch size must be an integer in 1..${MAX_PURGE_BATCH}`);
  }
  const cutoff = new Date(now.getTime() - IDEMPOTENCY_TTL_MS).toISOString();
  const rows = store.list('idempotency_records', { created_at: { op: '<=', value: cutoff } }, { orderBy: [['created_at', 'asc']], limit: batchSize });
  for (const row of rows) deleteIdempotencyRecord(store, recordFromRow(row));
  return rows.length;
}
