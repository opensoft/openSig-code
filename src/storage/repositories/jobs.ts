// SPDX-License-Identifier: Apache-2.0
//
// SigningJob lease, fencing and retry (T038; data-model.md § Entities,
// SigningJob, and § Transitions and races, items 2 and 3; migrations 0004 and
// 0018). Reads and writes go through the tenant-scoped store only. Every write
// needs the caller's Database.transaction (BEGIN IMMEDIATE) and is one
// TenantStore.compareAndSet on the job's own version, with the condition that
// makes the write legal in its WHERE clause. A write that is no longer legal
// matches no row, changes nothing and reports it; it never throws half-done.
//
// The lease predicate (leaseFence) is the one test of "this attempt still owns
// the job": status running, the attempt's fencing token, its lease owner, and a
// lease that has not expired at the transaction's instant. Renewal, failure
// recording and the publish transaction's job completion all use it, so an
// attempt that lost its lease (expired, reclaimed or superseded) writes
// nothing at all.
//
// Bounds (0004): attempt_count only grows (signing_jobs_monotonic), never
// exceeds max_attempts, and max_attempts stays in 1..100. The fencing token is
// the attempt_count at lease grant. A retry from `failed` at the limit raises
// max_attempts by update (A-010, request #28); it never touches attempt_count.
// last_error_code holds a code only: the contract's 60-character limit is
// enforced here, because 0004 allows 64 (row P13).
//
// The fence is strict (request #59 (11)): a lease holds only while
// lease_expires_at is later than now, and a reclaim needs it at or before now,
// so both never hold at the same instant.
//
// FinalizationAttemptBlob records (migration 0019, table
// finalization_attempt_blobs): an attempt records each blob ref in its own
// transaction, fenced by its lease, before it writes the blob
// (recordAttemptBlob). attemptCollectable() is the one collectability rule of
// data-model.md (not the published attempt, its lease ended, plus the 24-hour
// grace); T038's orphan collector selects with it and T029's
// reference-protection predicate protects with it (request #59 (7)).

import type { Row, TenantStore, Where } from '../db/index.ts';
import { StorageUsageError } from '../db/index.ts';
import { getEnvelope } from './envelopes.ts';

export type JobStatus = 'pending' | 'running' | 'retryable' | 'failed' | 'succeeded';
export const JOB_STATUSES: readonly JobStatus[] = Object.freeze(['pending', 'running', 'retryable', 'failed', 'succeeded']);

/** 0004: CHECK (max_attempts BETWEEN 1 AND 100). */
export const MAX_ATTEMPTS_CEILING = 100;
/** How many attempts one operator retry from `failed` at the limit adds (request #28; see the report's question). */
export const RETRY_RAISE = 1;
/** Contract FinalizationStatus.last_error_code maxLength (0004 allows 64; row P13). */
export const MAX_ERROR_CODE_LENGTH = 60;
export const DEFAULT_LEASE_MS = 120_000;
export const MIN_LEASE_MS = 1_000;
export const MAX_LEASE_MS = 3_600_000;
/** Bounded exponential retry_at: base, doubling per attempt, capped. */
export const RETRY_BASE_MS = 30_000;
export const RETRY_CAP_MS = 3_600_000;
/** The code a reclaimed (expired) lease records. */
export const LEASE_EXPIRED_ERROR_CODE = 'lease_expired.reclaimed';
export const MAX_JOB_LIST = 1_000;

const ERROR_CODE = /^[a-z0-9_.-]+$/;
const LEASE_OWNER = /^[A-Za-z0-9_.:-]{1,100}$/;

export interface JobRow {
  readonly envelopeId: string;
  readonly reservedVersion: number;
  readonly status: JobStatus;
  readonly attemptCount: number;
  readonly maxAttempts: number;
  readonly leaseOwner: string | null;
  readonly leaseExpiresAt: string | null;
  readonly fencingToken: number | null;
  readonly retryAt: string | null;
  readonly lastErrorCode: string | null;
  readonly version: number;
  readonly updatedAt: string;
}

/** What an attempt holds after a lease grant: the three values the fence compares. */
export interface LeaseHolder {
  readonly envelopeId: string;
  readonly fencingToken: number;
  readonly leaseOwner: string;
}

export interface LeaseGrant extends LeaseHolder {
  /** The envelope version written by the reservation; the publish compares against it. */
  readonly reservedVersion: number;
  readonly leaseExpiresAt: string;
  readonly attemptCount: number;
  readonly maxAttempts: number;
}

export interface LeaseOptions {
  readonly owner: string;
  readonly now: Date;
  readonly leaseMs?: number;
}

export type FailureOutcome = 'retryable' | 'failed' | 'lease-lost';
export type ReclaimOutcome = 'retryable' | 'failed' | 'not-expired';

export type RetryRefusal = 'not-reserved' | 'not-retryable' | 'attempt-ceiling' | 'conflict';
export type RetryOutcome =
  | { readonly kind: 'scheduled'; readonly from: 'retryable' | 'failed'; readonly maxAttempts: number; readonly retryAt: string }
  | { readonly kind: 'refused'; readonly reason: RetryRefusal };

function stored(column: string): StorageUsageError {
  return new StorageUsageError(`signing_jobs.${column} holds an unexpected value`);
}

function text(row: Row, column: string): string {
  const value = row[column];
  if (typeof value !== 'string') throw stored(column);
  return value;
}

function optText(row: Row, column: string): string | null {
  const value = row[column];
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') throw stored(column);
  return value;
}

function integer(row: Row, column: string): number {
  const value = row[column];
  const n = typeof value === 'bigint' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isSafeInteger(n)) throw stored(column);
  return n;
}

function optInteger(row: Row, column: string): number | null {
  const value = row[column];
  if (value === null || value === undefined) return null;
  return integer(row, column);
}

function isJobStatus(value: unknown): value is JobStatus {
  return typeof value === 'string' && (JOB_STATUSES as readonly string[]).includes(value);
}

function iso(now: Date): string {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new StorageUsageError('the job clock returned an invalid date');
  return now.toISOString();
}

function leaseMsOf(value: number | undefined): number {
  const ms = value ?? DEFAULT_LEASE_MS;
  if (!Number.isSafeInteger(ms) || ms < MIN_LEASE_MS || ms > MAX_LEASE_MS) {
    throw new StorageUsageError(`a lease lasts an integer ${MIN_LEASE_MS}..${MAX_LEASE_MS} ms`);
  }
  return ms;
}

function checkOwner(owner: unknown): string {
  if (typeof owner !== 'string' || !LEASE_OWNER.test(owner)) throw new StorageUsageError('a lease owner is 1..100 characters of [A-Za-z0-9_.:-]');
  return owner;
}

function checkLimit(limit: number): number {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_JOB_LIST) throw new StorageUsageError(`a job list limit is an integer in 1..${MAX_JOB_LIST}`);
  return limit;
}

/** Refuse a last_error_code the contract would not carry (charset of 0004, length of the contract). */
export function checkErrorCode(code: unknown): string {
  if (typeof code !== 'string' || code.length < 1 || code.length > MAX_ERROR_CODE_LENGTH || !ERROR_CODE.test(code)) {
    throw new StorageUsageError(`last_error_code must be 1..${MAX_ERROR_CODE_LENGTH} characters of [a-z0-9_.-]`);
  }
  return code;
}

/** The bounded exponential delay before the next attempt, after `attemptCount` attempts. */
export function retryDelayMs(attemptCount: number): number {
  const exponent = Math.min(Math.max(attemptCount - 1, 0), 20);
  return Math.min(RETRY_BASE_MS * 2 ** exponent, RETRY_CAP_MS);
}

function retryAtAfter(now: Date, attemptCount: number): string {
  return iso(new Date(now.getTime() + retryDelayMs(attemptCount)));
}

function jobFromRow(row: Row): JobRow {
  const status = row['status'];
  if (!isJobStatus(status)) throw stored('status');
  return {
    envelopeId: text(row, 'envelope_id'),
    reservedVersion: integer(row, 'reserved_version'),
    status,
    attemptCount: integer(row, 'attempt_count'),
    maxAttempts: integer(row, 'max_attempts'),
    leaseOwner: optText(row, 'lease_owner'),
    leaseExpiresAt: optText(row, 'lease_expires_at'),
    fencingToken: optInteger(row, 'fencing_token'),
    retryAt: optText(row, 'retry_at'),
    lastErrorCode: optText(row, 'last_error_code'),
    version: integer(row, 'version'),
    updatedAt: text(row, 'updated_at'),
  };
}

/** The envelope's SigningJob, every column, or undefined when finalization is not reserved. */
export function readJob(store: TenantStore, envelopeId: string): JobRow | undefined {
  const row = store.get('signing_jobs', { envelope_id: envelopeId });
  return row === undefined ? undefined : jobFromRow(row);
}

/**
 * The lease predicate: the job is running under this attempt's fencing token
 * and owner, and the lease has not expired at `now`. Used as the WHERE clause
 * of every write an attempt makes to its job.
 */
export function leaseFence(holder: LeaseHolder, now: string): Where {
  return {
    envelope_id: holder.envelopeId,
    status: 'running',
    fencing_token: holder.fencingToken,
    lease_owner: holder.leaseOwner,
    lease_expires_at: { op: '>', value: now },
  };
}

/**
 * Grant a lease on a claimable job: pending, or retryable and due, with an
 * attempt left, for an envelope still finalizing at its reserved version. The
 * grant increments attempt_count and makes it the fencing token. Returns null
 * when the job is not claimable or another writer moved it first.
 */
export function grantLease(store: TenantStore, envelopeId: string, options: LeaseOptions): LeaseGrant | null {
  const owner = checkOwner(options.owner);
  const leaseMs = leaseMsOf(options.leaseMs);
  const at = iso(options.now);
  const job = readJob(store, envelopeId);
  if (job === undefined) return null;
  const due = job.status === 'pending' || (job.status === 'retryable' && (job.retryAt === null || job.retryAt <= at));
  if (!due || job.attemptCount >= job.maxAttempts) return null;
  const envelope = getEnvelope(store, envelopeId);
  if (envelope === undefined || envelope.state !== 'finalizing' || envelope.version !== job.reservedVersion) return null;
  const attempt = job.attemptCount + 1;
  const leaseExpiresAt = iso(new Date(options.now.getTime() + leaseMs));
  const granted = store.compareAndSet(
    'signing_jobs',
    { envelope_id: envelopeId, status: job.status, attempt_count: job.attemptCount },
    job.version,
    {
      status: 'running',
      attempt_count: attempt,
      fencing_token: attempt,
      lease_owner: owner,
      lease_expires_at: leaseExpiresAt,
      retry_at: null,
      updated_at: at,
    },
  );
  if (!granted) return null;
  return {
    envelopeId,
    fencingToken: attempt,
    leaseOwner: owner,
    reservedVersion: job.reservedVersion,
    leaseExpiresAt,
    attemptCount: attempt,
    maxAttempts: job.maxAttempts,
  };
}

/** Extend a held lease to now + leaseMs; returns the new expiry. Null means the lease is lost: nothing was written. */
export function renewLease(store: TenantStore, holder: LeaseHolder, options: { readonly now: Date; readonly leaseMs?: number }): string | null {
  const leaseMs = leaseMsOf(options.leaseMs);
  const at = iso(options.now);
  const job = readJob(store, holder.envelopeId);
  if (job === undefined) return null;
  const leaseExpiresAt = iso(new Date(options.now.getTime() + leaseMs));
  const renewed = store.compareAndSet('signing_jobs', leaseFence(holder, at), job.version, { lease_expires_at: leaseExpiresAt, updated_at: at });
  return renewed ? leaseExpiresAt : null;
}

/**
 * Record a failed attempt under its lease: `retryable` with a bounded
 * exponential retry_at while an attempt is left and the failure is
 * retryable, otherwise `failed`. The lease is released. 'lease-lost' means
 * the attempt no longer owns the job and nothing was written.
 */
export function recordAttemptFailure(
  store: TenantStore,
  holder: LeaseHolder,
  failure: { readonly now: Date; readonly retryable: boolean; readonly errorCode: string },
): FailureOutcome {
  const errorCode = checkErrorCode(failure.errorCode);
  const at = iso(failure.now);
  const job = readJob(store, holder.envelopeId);
  if (job === undefined) return 'lease-lost';
  const status = failure.retryable === true && job.attemptCount < job.maxAttempts ? 'retryable' : 'failed';
  const recorded = store.compareAndSet('signing_jobs', leaseFence(holder, at), job.version, {
    status,
    retry_at: status === 'retryable' ? retryAtAfter(failure.now, job.attemptCount) : null,
    last_error_code: errorCode,
    lease_owner: null,
    lease_expires_at: null,
    updated_at: at,
  });
  return recorded ? status : 'lease-lost';
}

/** Complete the job under its lease (the publish transaction's job step). False: lease lost, nothing written. */
export function completeJob(store: TenantStore, holder: LeaseHolder, now: Date): boolean {
  const at = iso(now);
  const job = readJob(store, holder.envelopeId);
  if (job === undefined) return false;
  return store.compareAndSet('signing_jobs', leaseFence(holder, at), job.version, {
    status: 'succeeded',
    retry_at: null,
    lease_owner: null,
    lease_expires_at: null,
    updated_at: at,
  });
}

/**
 * Reclaim a running job whose lease expired at or before `now` (a crashed or
 * stalled attempt): `retryable` with a bounded retry_at while an attempt is
 * left, otherwise `failed`. The fencing token stays (0004 never lets it move
 * back or become null), so the old attempt's fence no longer holds.
 */
export function reclaimExpiredLease(store: TenantStore, envelopeId: string, now: Date): ReclaimOutcome {
  const at = iso(now);
  const job = readJob(store, envelopeId);
  if (job === undefined || job.status !== 'running' || job.leaseExpiresAt === null || job.leaseExpiresAt > at) return 'not-expired';
  const status = job.attemptCount < job.maxAttempts ? 'retryable' : 'failed';
  const reclaimed = store.compareAndSet(
    'signing_jobs',
    { envelope_id: envelopeId, status: 'running', fencing_token: job.fencingToken, lease_expires_at: { op: '<=', value: at } },
    job.version,
    {
      status,
      retry_at: status === 'retryable' ? retryAtAfter(now, job.attemptCount) : null,
      last_error_code: LEASE_EXPIRED_ERROR_CODE,
      lease_owner: null,
      lease_expires_at: null,
      updated_at: at,
    },
  );
  return reclaimed ? status : 'not-expired';
}

/**
 * The job half of retryFinalization: allowed only from `retryable` or
 * `failed` (data-model.md § Transitions and races, item 3). The job becomes
 * `retryable`, due now. From `failed` at the attempt limit, max_attempts is
 * raised by RETRY_RAISE within 0004's 1..100 (request #28); at 100 the retry
 * is refused. attempt_count is never written.
 */
export function retryJob(store: TenantStore, envelopeId: string, now: Date): RetryOutcome {
  const at = iso(now);
  const job = readJob(store, envelopeId);
  if (job === undefined) return { kind: 'refused', reason: 'not-reserved' };
  const from = job.status;
  if (from !== 'retryable' && from !== 'failed') return { kind: 'refused', reason: 'not-retryable' };
  let maxAttempts = job.maxAttempts;
  if (job.attemptCount >= job.maxAttempts) {
    if (job.attemptCount + RETRY_RAISE > MAX_ATTEMPTS_CEILING) return { kind: 'refused', reason: 'attempt-ceiling' };
    maxAttempts = job.attemptCount + RETRY_RAISE;
  }
  const scheduled = store.compareAndSet(
    'signing_jobs',
    { envelope_id: envelopeId, status: from, attempt_count: job.attemptCount },
    job.version,
    { status: 'retryable', max_attempts: maxAttempts, retry_at: at, updated_at: at },
  );
  if (!scheduled) return { kind: 'refused', reason: 'conflict' };
  return { kind: 'scheduled', from, maxAttempts, retryAt: at };
}

/** Envelope ids of claimable jobs: pending, then retryable and due (bounded). */
export function listClaimableJobs(store: TenantStore, now: Date, limit: number): string[] {
  const at = iso(now);
  const max = checkLimit(limit);
  const pending = store.list('signing_jobs', { status: 'pending' }, { orderBy: [['updated_at', 'asc']], limit: max });
  const due = store.list('signing_jobs', { status: 'retryable', retry_at: { op: '<=', value: at } }, { orderBy: [['retry_at', 'asc']], limit: max });
  return [...pending, ...due].slice(0, max).map((row) => text(row, 'envelope_id'));
}

/** Envelope ids of running jobs whose lease expired at or before `now` (bounded). */
export function listExpiredLeases(store: TenantStore, now: Date, limit: number): string[] {
  const at = iso(now);
  const max = checkLimit(limit);
  return store
    .list('signing_jobs', { status: 'running', lease_expires_at: { op: '<=', value: at } }, { orderBy: [['lease_expires_at', 'asc']], limit: max })
    .map((row) => text(row, 'envelope_id'));
}

// ------------------------------------------------- FinalizationAttemptBlob

export type AttemptBlobRole = 'composed' | 'sealed' | 'evidence' | 'package';
export const ATTEMPT_BLOB_ROLES: readonly AttemptBlobRole[] = Object.freeze(['composed', 'sealed', 'evidence', 'package']);
/** data-model.md § Entities, FinalizationAttemptBlob: 24 hours after the attempt's lease ended. */
export const ATTEMPT_GRACE_MS = 24 * 60 * 60 * 1000;

const BLOB_REF = /^tenants\/([A-Za-z0-9_-]{16,64})\/sha256\/[0-9a-f]{64}$/;

export interface AttemptBlobRecord {
  readonly envelopeId: string;
  readonly fencingToken: number;
  readonly blobRef: string;
  readonly role: AttemptBlobRole;
  readonly recordedAt: string;
}

function attemptBlobFromRow(row: Row): AttemptBlobRecord {
  const role = row['role'];
  if (typeof role !== 'string' || !(ATTEMPT_BLOB_ROLES as readonly string[]).includes(role)) throw stored('role');
  return {
    envelopeId: text(row, 'envelope_id'),
    fencingToken: integer(row, 'fencing_token'),
    blobRef: text(row, 'blob_ref'),
    role: role as AttemptBlobRole,
    recordedAt: text(row, 'recorded_at'),
  };
}

/** True while `holder` owns the job at `now` (the lease predicate, read inside the caller's transaction). */
export function leaseHeld(store: TenantStore, holder: LeaseHolder, now: Date): boolean {
  const at = iso(now);
  const job = readJob(store, holder.envelopeId);
  return (
    job !== undefined &&
    job.status === 'running' &&
    job.fencingToken === holder.fencingToken &&
    job.leaseOwner === holder.leaseOwner &&
    job.leaseExpiresAt !== null &&
    job.leaseExpiresAt > at
  );
}

/**
 * Record a blob ref the attempt is about to write, in the caller's transaction,
 * before the write (data-model.md § Entities, FinalizationAttemptBlob).
 * Fenced: false means the lease is lost and nothing was written. A ref the
 * same attempt already recorded is not recorded again.
 */
export function recordAttemptBlob(
  store: TenantStore,
  holder: LeaseHolder,
  blob: { readonly blobRef: string; readonly role: AttemptBlobRole; readonly now: Date },
): boolean {
  const match = BLOB_REF.exec(blob.blobRef);
  if (match === null || match[1] !== store.tenantId) throw new StorageUsageError('an attempt blob ref must be this tenant’s tenants/<tenant>/sha256/<digest>');
  if (!(ATTEMPT_BLOB_ROLES as readonly string[]).includes(blob.role)) throw new StorageUsageError('an attempt blob role is composed, sealed, evidence or package');
  if (!leaseHeld(store, holder, blob.now)) return false;
  const key = { envelope_id: holder.envelopeId, fencing_token: holder.fencingToken, blob_ref: blob.blobRef };
  if (store.get('finalization_attempt_blobs', key) !== undefined) return true;
  store.insert('finalization_attempt_blobs', { ...key, role: blob.role, recorded_at: iso(blob.now) });
  return true;
}

/** Every attempt record of an envelope, oldest first (keyset iteration; never truncated). */
export function listAttemptBlobs(store: TenantStore, envelopeId: string): AttemptBlobRecord[] {
  const records: AttemptBlobRecord[] = [];
  for (const row of store.iterate('finalization_attempt_blobs', { envelope_id: envelopeId }, { orderBy: [['recorded_at', 'asc']] })) {
    records.push(attemptBlobFromRow(row));
  }
  return records;
}

/** Every attempt record of a ref, across the tenant's envelopes (index finalization_attempt_blobs_ref). */
export function attemptBlobsOfRef(store: TenantStore, blobRef: string): AttemptBlobRecord[] {
  const records: AttemptBlobRecord[] = [];
  for (const row of store.iterate('finalization_attempt_blobs', { blob_ref: blobRef })) records.push(attemptBlobFromRow(row));
  return records;
}

/**
 * The one collectability rule (data-model.md § Entities,
 * FinalizationAttemptBlob; request #59 (7)): an attempt's records are
 * collectable only when the attempt is not the published one, its lease has
 * ended, and 24 hours have passed since. For the job's current running
 * attempt the lease ends at lease_expires_at. Any other attempt ended no later
 * than the job's updated_at (its failure, its reclaim, or the grant that
 * superseded it), so that time is a conservative bound. Without a job row
 * nothing is collectable.
 */
export function attemptCollectable(store: TenantStore, envelopeId: string, fencingToken: number, now: Date): boolean {
  const at = iso(now);
  const job = readJob(store, envelopeId);
  if (job === undefined) return false;
  if (store.count('final_artifacts', { envelope_id: envelopeId, fencing_token: fencingToken }) > 0) return false;
  let ended: string;
  if (job.status === 'running' && job.fencingToken === fencingToken) {
    if (job.leaseExpiresAt === null || job.leaseExpiresAt > at) return false;
    ended = job.leaseExpiresAt;
  } else {
    ended = job.updatedAt;
  }
  return Date.parse(ended) + ATTEMPT_GRACE_MS <= now.getTime();
}
