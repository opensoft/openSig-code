// SPDX-License-Identifier: Apache-2.0
//
// The expiry sweeper (T010; data-model.md § Envelope states, expired, and
// § Entities, IdempotencyRecord; A-010 rows IDEMP-B3 and T008-F5).
//
// One run, at one instant of the injected clock, for every tenant in the
// tenant registry:
// 1. Envelope expiry. Every envelope before the finalization reservation
//    (draft, prepared, sent, in-progress) whose expires_at has passed is
//    expired through EnvelopeService.expireIfDue (T007), one envelope per
//    BEGIN IMMEDIATE transaction. expireIfDue re-reads the envelope and
//    compares and sets it through the same path as approval, decline and void
//    (compareAndSetEnvelope), so an envelope that a concurrent request has
//    meanwhile moved on (finalizing, declined, voided or already expired) is
//    left alone; exactly one of them wins. The expiry closes the recipients
//    still pending or invited and revokes every outstanding invitation and
//    session (the envelope service). The sweeper's envelope service reports
//    each expiry, inside its transaction, to the recipient ceremony's listener
//    (which records what was revoked in the audit chain) and then announces it
//    as envelope.expired in the outbox (expiryAnnouncer; T007 writes no such
//    event), exactly once (A-010, request #24, ruling (6)). Until a run reaches
//    it, a session of an envelope past its expiry stays readable and shows the
//    turn as closed, and approval is already refused at the deadline (row
//    T008-F5); this run closes that gap.
// 2. The idempotency purge (row IDEMP-B3, N2). A record is deleted exactly
//    when T007's replay-expiry predicate (isIdempotencyRecordExpired: created_at
//    + 24 h <= now) says it is no longer a replay, so a purge never deletes a
//    record a replay would still honour (ruling (9)). Candidates are read
//    oldest first, at most `purgeBatch` per transaction; each is deleted
//    through the T007 repository only if that predicate holds for it. A purge
//    writes no DisposalRecord and no audit event: these records are
//    operational data, not evidence.
// Both steps work in bounded batches: due envelopes are read `expiryBatch` at a
// time (oldest expiry first), and each tenant gets at most `maxBatches`
// batches of each kind per run. A run that stops at that bound reports
// complete: false, and the next run continues where it stopped. No step holds
// the write lock for more than one batch.
//
// ExpirySweeper schedules runs on an interval (never two at once). The
// production composition (T031's US1 slot, row WIRE-US1) starts it.

import { expiryAnnouncer, type EnvelopeChangeListener } from '../domain/approval/events.ts';
import { EnvelopeService } from '../domain/envelopes/service.ts';
import { PRE_RESERVATION_STATES } from '../domain/envelopes/states.ts';
import type { Database, TenantStore } from '../storage/db/index.ts';
import {
  DEFAULT_PURGE_BATCH,
  IDEMPOTENCY_TTL_MS,
  MAX_PURGE_BATCH,
  deleteIdempotencyRecord,
  findIdempotencyRecord,
  isIdempotencyRecordExpired,
} from '../storage/repositories/idempotency.ts';

export const DEFAULT_EXPIRY_BATCH = 100;
export const MAX_EXPIRY_BATCH = 1000;
/** Batches of each kind per tenant per run. */
export const DEFAULT_MAX_BATCHES = 100;
export const DEFAULT_SWEEP_INTERVAL_MS = 60_000;

export interface ExpirySweepOptions {
  readonly db: Database;
  /** The recipient ceremony's onEnvelopeChange: it records what each expiry revoked. */
  readonly onEnvelopeChange: EnvelopeChangeListener;
  readonly clock: () => Date;
  /** Due envelopes read per batch (1..1000, default 100). */
  readonly expiryBatch?: number;
  /** Idempotency records deleted per transaction (1..MAX_PURGE_BATCH, default DEFAULT_PURGE_BATCH). */
  readonly purgeBatch?: number;
  /** Batches of each kind per tenant per run (1..10000, default 100). */
  readonly maxBatches?: number;
}

export interface ExpirySweepReport {
  /** The run's instant (unsigned server time). */
  readonly at: string;
  readonly tenants: number;
  readonly expired: number;
  readonly purged: number;
  /** False when a tenant reached maxBatches with work left; the next run continues. */
  readonly complete: boolean;
}

function bounded(value: number | undefined, fallback: number, max: number, name: string): number {
  const n = value ?? fallback;
  if (!Number.isSafeInteger(n) || n < 1 || n > max) throw new TypeError(`${name} must be an integer in 1..${max}`);
  return n;
}

interface Settings {
  readonly db: Database;
  readonly envelopes: EnvelopeService;
  readonly clock: () => Date;
  readonly expiryBatch: number;
  readonly purgeBatch: number;
  readonly maxBatches: number;
}

function settings(options: ExpirySweepOptions): Settings {
  if (typeof options?.clock !== 'function') throw new TypeError('the expiry sweeper needs an injected clock');
  if (typeof options.db?.transaction !== 'function' || typeof options.db.listTenantIds !== 'function') throw new TypeError('the expiry sweeper needs the database');
  if (typeof options.onEnvelopeChange !== 'function') throw new TypeError('the expiry sweeper needs the recipient ceremony’s change listener');
  return {
    db: options.db,
    envelopes: new EnvelopeService({ db: options.db, clock: options.clock, onChange: expiryAnnouncer(options.db, options.clock, options.onEnvelopeChange) }),
    clock: options.clock,
    expiryBatch: bounded(options.expiryBatch, DEFAULT_EXPIRY_BATCH, MAX_EXPIRY_BATCH, 'expiryBatch'),
    purgeBatch: bounded(options.purgeBatch, DEFAULT_PURGE_BATCH, MAX_PURGE_BATCH, 'purgeBatch'),
    maxBatches: bounded(options.maxBatches, DEFAULT_MAX_BATCHES, 10_000, 'maxBatches'),
  };
}

/** Expire the tenant's due envelopes, in batches; returns how many it expired and whether it finished. */
function expireTenant(s: Settings, tenantId: string, iso: string): { expired: number; complete: boolean } {
  let expired = 0;
  for (let batch = 0; batch < s.maxBatches; batch += 1) {
    const due = s.db.transaction(() =>
      s.db
        .forTenant(tenantId)
        .list(
          'envelopes',
          { state: { op: 'in', values: [...PRE_RESERVATION_STATES] }, expires_at: { op: '<=', value: iso } },
          { orderBy: [['expires_at', 'asc'], ['id', 'asc']], limit: s.expiryBatch },
        )
        .map((row) => String(row['id'])),
    );
    let moved = 0;
    for (const envelopeId of due) {
      // Re-read and compare-and-set inside its own transaction: a concurrent winner is left alone.
      if (s.envelopes.expireIfDue(tenantId, envelopeId)) moved += 1;
    }
    expired += moved;
    if (due.length < s.expiryBatch) return { expired, complete: true };
    // A full batch that expired nothing was moved on by concurrent requests; the next read sees that.
  }
  return { expired, complete: false };
}

/**
 * One purge batch in the caller's transaction: the oldest `limit` candidates (created at or
 * before now - 24 h), each deleted only when T007's replay-expiry predicate holds for it.
 */
function purgeBatch(store: TenantStore, now: Date, limit: number): { listed: number; deleted: number } {
  const cutoff = new Date(now.getTime() - IDEMPOTENCY_TTL_MS).toISOString();
  const rows = store.list('idempotency_records', { created_at: { op: '<=', value: cutoff } }, { orderBy: [['created_at', 'asc']], limit });
  let deleted = 0;
  for (const row of rows) {
    const record = findIdempotencyRecord(store, String(row['route']), String(row['principal_ref']), String(row['key']));
    if (record === undefined || !isIdempotencyRecordExpired(record, now)) continue;
    deleteIdempotencyRecord(store, record);
    deleted += 1;
  }
  return { listed: rows.length, deleted };
}

/** Purge the tenant's idempotency records that are no longer a replay, in batches. */
function purgeTenant(s: Settings, tenantId: string, now: Date): { purged: number; complete: boolean } {
  let purged = 0;
  for (let batch = 0; batch < s.maxBatches; batch += 1) {
    const { listed, deleted } = s.db.transaction(() => purgeBatch(s.db.forTenant(tenantId), now, s.purgeBatch));
    purged += deleted;
    // A candidate the predicate keeps would be listed again: stop there rather than loop.
    if (deleted < listed) return { purged, complete: false };
    if (listed < s.purgeBatch) return { purged, complete: true };
  }
  return { purged, complete: false };
}

/** One sweep over every tenant: envelope expiry, then the idempotency purge. */
export function runExpirySweep(options: ExpirySweepOptions): ExpirySweepReport {
  const s = settings(options);
  const now = s.clock();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('the expiry sweeper clock returned an invalid date');
  const iso = now.toISOString();
  const tenants = s.db.listTenantIds();
  let expired = 0;
  let purged = 0;
  let complete = true;
  for (const tenantId of tenants) {
    const expiry = expireTenant(s, tenantId, iso);
    expired += expiry.expired;
    const purge = purgeTenant(s, tenantId, now);
    purged += purge.purged;
    complete = complete && expiry.complete && purge.complete;
  }
  return Object.freeze({ at: iso, tenants: tenants.length, expired, purged, complete });
}

export interface ExpirySweeperOptions extends ExpirySweepOptions {
  /** Called with each scheduled run's report. */
  readonly onReport?: (report: ExpirySweepReport) => void;
  /** Called when a scheduled run throws; the next interval runs again. */
  readonly onError?: (error: unknown) => void;
}

/** Runs the sweep on an interval, one run at a time. */
export class ExpirySweeper {
  readonly #options: ExpirySweeperOptions;
  #timer: NodeJS.Timeout | null = null;
  #running = false;

  constructor(options: ExpirySweeperOptions) {
    settings(options);
    this.#options = options;
  }

  /** One run now (also used by tests with an injected clock). */
  runOnce(): ExpirySweepReport {
    if (this.#running) throw new Error('an expiry sweep is already running');
    this.#running = true;
    try {
      return runExpirySweep(this.#options);
    } finally {
      this.#running = false;
    }
  }

  /** Start scheduled runs every `intervalMs` (the timer does not keep the process alive). */
  start(intervalMs: number = DEFAULT_SWEEP_INTERVAL_MS): void {
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 1000) throw new TypeError('the sweep interval must be at least 1000 ms');
    if (this.#timer !== null) return;
    this.#timer = setInterval(() => {
      if (this.#running) return;
      try {
        const report = this.runOnce();
        this.#options.onReport?.(report);
      } catch (error) {
        this.#options.onError?.(error);
      }
    }, intervalMs);
    this.#timer.unref();
  }

  stop(): void {
    if (this.#timer !== null) clearInterval(this.#timer);
    this.#timer = null;
  }
}
