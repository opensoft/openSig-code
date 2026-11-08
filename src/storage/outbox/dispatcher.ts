// SPDX-License-Identifier: Apache-2.0
//
// At-least-once outbox delivery with a stable event_id.
//
// For each due event the dispatcher first claims it in its own transaction
// (attempts + 1, last_attempt_at, and next_attempt_at pushed out by the claim
// window, so a concurrent or restarted dispatcher does not pick it up while
// the attempt is in flight). It then calls the injected deliver() with the
// stored payload bytes, which carry the event_id fixed at insertion. Success
// records acknowledged_at. Failure schedules a bounded exponential retry, or
// abandons the event (next_attempt_at NULL, last_error_code kept) once it is
// not retryable, reaches maxAttempts or passes the retry horizon. A crash
// after delivery but before acknowledgement leads to a redelivery of the same
// event_id and bytes once the claim window has passed; consumers deduplicate
// on event_id.

import type { Database } from '../db/connection.ts';
import { StorageUsageError } from '../db/errors.ts';
import type { Row } from '../db/tenant-store.ts';

export interface DeliveryAttempt {
  readonly tenantId: string;
  readonly eventId: string;
  readonly type: string;
  readonly envelopeId: string;
  /** 1 for the first attempt. */
  readonly attempt: number;
  /** The exact stored payload bytes (canonical WebhookEvent JSON). */
  readonly body: Buffer;
}

export type DeliveryResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly errorCode: string; readonly retryable?: boolean };

export interface DispatcherOptions {
  readonly db: Database;
  readonly clock: () => Date;
  readonly deliver: (attempt: DeliveryAttempt) => Promise<DeliveryResult>;
  /** First retry delay (default 30 s); doubles per attempt up to maxDelayMs. */
  readonly baseDelayMs?: number;
  readonly maxDelayMs?: number;
  /** No retry is scheduled later than this after the event was created (default 72 h). */
  readonly horizonMs?: number;
  readonly maxAttempts?: number;
  /** How long a claimed attempt keeps the event from other dispatchers (default 60 s). */
  readonly claimMs?: number;
  readonly batchSize?: number;
}

export interface DispatchSummary {
  readonly delivered: readonly string[];
  readonly retrying: readonly string[];
  readonly abandoned: readonly string[];
}

export const RETRY_HORIZON_MS = 72 * 60 * 60 * 1000;
const ERROR_CODE = /^[a-z0-9_.-]{1,64}$/;

function positive(value: number | undefined, fallback: number, name: string): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1) throw new StorageUsageError(`${name} must be a positive integer`);
  return result;
}

export class OutboxDispatcher {
  readonly #db: Database;
  readonly #clock: () => Date;
  readonly #deliver: DispatcherOptions['deliver'];
  readonly #baseDelayMs: number;
  readonly #maxDelayMs: number;
  readonly #horizonMs: number;
  readonly #maxAttempts: number;
  readonly #claimMs: number;
  readonly #batchSize: number;

  constructor(options: DispatcherOptions) {
    if (typeof options?.clock !== 'function' || typeof options.deliver !== 'function') {
      throw new StorageUsageError('the dispatcher needs an injected clock and deliver function');
    }
    this.#db = options.db;
    this.#clock = options.clock;
    this.#deliver = options.deliver;
    this.#baseDelayMs = positive(options.baseDelayMs, 30_000, 'baseDelayMs');
    this.#maxDelayMs = positive(options.maxDelayMs, 3_600_000, 'maxDelayMs');
    this.#horizonMs = positive(options.horizonMs, RETRY_HORIZON_MS, 'horizonMs');
    this.#maxAttempts = positive(options.maxAttempts, 25, 'maxAttempts');
    this.#claimMs = positive(options.claimMs, 60_000, 'claimMs');
    this.#batchSize = positive(options.batchSize, 50, 'batchSize');
  }

  #now(): number {
    const now = this.#clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new StorageUsageError('the dispatcher clock returned an invalid date');
    return now.getTime();
  }

  /** Unacknowledged events that are due now, oldest first. */
  due(tenantId: string): Row[] {
    const store = this.#db.forTenant(tenantId);
    const now = new Date(this.#now()).toISOString();
    const fresh = store.list('outbox_events', { acknowledged_at: null, attempts: 0 });
    const retries = store.list('outbox_events', { acknowledged_at: null, next_attempt_at: { op: '<=', value: now } });
    const byId = new Map([...fresh, ...retries].map((row) => [String(row['event_id']), row]));
    return [...byId.values()]
      .sort((a, b) => String(a['created_at']).localeCompare(String(b['created_at'])) || String(a['event_id']).localeCompare(String(b['event_id'])))
      .slice(0, this.#batchSize);
  }

  /** Events that will not be retried: unacknowledged, attempted, with no next attempt. */
  abandoned(tenantId: string): Row[] {
    return this.#db
      .forTenant(tenantId)
      .list('outbox_events', { acknowledged_at: null, next_attempt_at: null, attempts: { op: '>', value: 0 } }, { orderBy: [['created_at', 'asc']] });
  }

  /** Claim an event for one attempt; returns the attempt number, or undefined if no longer due. */
  #claim(tenantId: string, eventId: string): { readonly attempt: number; readonly row: Row } | undefined {
    return this.#db.transaction(() => {
      const store = this.#db.forTenant(tenantId);
      const row = store.get('outbox_events', { event_id: eventId });
      if (row === undefined || row['acknowledged_at'] !== null) return undefined;
      const now = this.#now();
      const attempts = Number(row['attempts']);
      const next = row['next_attempt_at'];
      const isDue = attempts === 0 ? next === null : typeof next === 'string' && next <= new Date(now).toISOString();
      if (!isDue) return undefined;
      store.update('outbox_events', { event_id: eventId }, {
        attempts: attempts + 1,
        last_attempt_at: new Date(now).toISOString(),
        next_attempt_at: new Date(now + this.#claimMs).toISOString(),
      });
      return { attempt: attempts + 1, row };
    });
  }

  #settle(tenantId: string, eventId: string, attempt: number, createdAt: string, result: DeliveryResult): 'delivered' | 'retrying' | 'abandoned' {
    return this.#db.transaction(() => {
      const store = this.#db.forTenant(tenantId);
      const current = store.get('outbox_events', { event_id: eventId });
      // Another attempt took over after this claim expired: leave its state alone.
      if (current === undefined || current['acknowledged_at'] !== null) return 'delivered';
      if (Number(current['attempts']) !== attempt) return 'retrying';
      const now = this.#now();
      if (result.ok) {
        store.update('outbox_events', { event_id: eventId }, { acknowledged_at: new Date(now).toISOString(), next_attempt_at: null, last_error_code: null });
        return 'delivered';
      }
      const errorCode = ERROR_CODE.test(result.errorCode) ? result.errorCode : 'delivery_failed';
      const delay = Math.min(this.#maxDelayMs, this.#baseDelayMs * 2 ** Math.min(attempt - 1, 30));
      const nextAt = now + delay;
      const pastHorizon = nextAt > Date.parse(createdAt) + this.#horizonMs;
      if (result.retryable === false || attempt >= this.#maxAttempts || pastHorizon) {
        store.update('outbox_events', { event_id: eventId }, { next_attempt_at: null, last_error_code: errorCode });
        return 'abandoned';
      }
      store.update('outbox_events', { event_id: eventId }, { next_attempt_at: new Date(nextAt).toISOString(), last_error_code: errorCode });
      return 'retrying';
    });
  }

  /** Attempt every due event of the tenant once. */
  async dispatch(tenantId: string): Promise<DispatchSummary> {
    const summary = { delivered: [] as string[], retrying: [] as string[], abandoned: [] as string[] };
    for (const candidate of this.due(tenantId)) {
      const eventId = String(candidate['event_id']);
      const claimed = this.#claim(tenantId, eventId);
      if (claimed === undefined) continue;
      const attempt: DeliveryAttempt = {
        tenantId,
        eventId,
        type: String(claimed.row['type']),
        envelopeId: String(claimed.row['envelope_id']),
        attempt: claimed.attempt,
        body: Buffer.from(String(claimed.row['payload_json']), 'utf8'),
      };
      let result: DeliveryResult;
      try {
        result = await this.#deliver(attempt);
      } catch {
        result = { ok: false, errorCode: 'delivery_exception', retryable: true };
      }
      if (typeof result !== 'object' || result === null) result = { ok: false, errorCode: 'delivery_invalid_result', retryable: true };
      const outcome = this.#settle(tenantId, eventId, claimed.attempt, String(claimed.row['created_at']), result);
      summary[outcome].push(eventId);
    }
    return summary;
  }
}
