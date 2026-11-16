// SPDX-License-Identifier: Apache-2.0
//
// Idempotency records (T007; data-model.md § Entities, IdempotencyRecord;
// contract parameter Idempotency-Key). A record is scoped by tenant (the
// store), route, principal and key. It holds the SHA-256 of the RFC 8785 form
// of the request, and the response status, exact body bytes and their digest,
// so the same key with the same request replays the original result and a
// changed request is detected. Request and body digests go through the single
// canonical module, src/domain/canonical/index.ts.
//
// Records are inserted in the transaction of the mutation they describe and
// are immutable (schema trigger of 0004); the body column is added by 0011.

import { createHash } from 'node:crypto';

import { canonicalBytes, canonicalDigest, type JsonValue } from '../../domain/canonical/index.ts';
import type { Row, TenantStore } from '../db/index.ts';
import { StorageUsageError } from '../db/index.ts';

export const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const ROUTE_PATTERN = /^[A-Za-z0-9_.:/{}-]{1,100}$/;
const DIGEST = /^[0-9a-f]{64}$/;

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

export interface NewIdempotencyRecord {
  readonly route: string;
  readonly principal: IdempotencyPrincipal;
  readonly key: string;
  readonly requestDigest: string;
  readonly responseStatus: number;
  readonly responseBody: JsonValue;
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

/** The digest that binds a key to its request: SHA-256 of the request's RFC 8785 form. */
export function idempotencyRequestDigest(request: JsonValue): string {
  return canonicalDigest(request);
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
 * Returns the exact response bytes stored (the RFC 8785 form of the body).
 */
export function insertIdempotencyRecord(store: TenantStore, record: NewIdempotencyRecord): Buffer {
  checkScope(record.route, record.key);
  if (!DIGEST.test(record.requestDigest)) throw new StorageUsageError('idempotency request digest is malformed');
  const body = canonicalBytes(record.responseBody);
  store.insert('idempotency_records', {
    route: record.route,
    principal_kind: record.principal.kind,
    principal_ref: record.principal.ref,
    key: record.key,
    request_digest: record.requestDigest,
    response_status: record.responseStatus,
    response_body: body,
    response_body_digest: sha256Hex(body),
    resource_id: record.resourceId,
    created_at: record.createdAt,
  });
  return body;
}

/** The stored response bytes of a record, checked against their stored digest. */
export function storedResponseBody(record: IdempotencyRecord): Buffer {
  if (record.responseBody === null || record.responseBodyDigest === null) {
    throw new StorageUsageError('the idempotency record holds no response body to replay');
  }
  const body = Buffer.from(record.responseBody);
  if (sha256Hex(body) !== record.responseBodyDigest) {
    throw new StorageUsageError('the stored idempotency response does not match its digest');
  }
  return body;
}
