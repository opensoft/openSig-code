// SPDX-License-Identifier: Apache-2.0
//
// The lease keeper of one finalization attempt (T038; data-model.md
// § Transitions and races, item 2; the T037 line: "T038 aborts on lease
// loss").
//
// - Renewal. About every leaseMs / 3, and always before the local deadline,
//   the keeper runs the caller's renewal: a fenced renewLease
//   (src/storage/repositories/jobs.ts) in its own BEGIN IMMEDIATE
//   transaction, returning the new lease_expires_at or null.
// - Loss. The lease is lost when a renewal matches no row (the fence failed:
//   the lease expired and was reclaimed, or another attempt holds the job),
//   or when the local clock reaches the last known expiry minus a safety
//   margin without a successful renewal (for example while another
//   connection keeps the write lock). A renewal that throws is not a loss by
//   itself; the deadline decides.
// - On loss the keeper aborts its signal, which the attempt passes to T037's
//   sealComposedPdf (an abort kills the worker child and rejects with the
//   retryable reason `aborted`), and checkHeld() throws LeaseLost before
//   every later step. A lost attempt writes nothing more: no failure record,
//   no checkpoint, no publication. Safety never rests on this timing: every
//   write of the attempt carries the lease predicate in its WHERE clause.

export type LeaseLossCause = 'fenced' | 'deadline';

export class LeaseLost extends Error {
  readonly lossCause: LeaseLossCause;

  constructor(lossCause: LeaseLossCause) {
    super(`finalization lease lost: ${lossCause}`);
    this.name = 'LeaseLost';
    this.lossCause = lossCause;
  }
}

export interface LeaseTimers {
  readonly setTimeout: (callback: () => void, ms: number) => unknown;
  readonly clearTimeout: (handle: unknown) => void;
}

export interface LeaseKeeperOptions {
  /** One fenced renewal: the new lease_expires_at, or null when the fence no longer holds. */
  readonly renew: () => string | null;
  /** lease_expires_at from the grant. */
  readonly leaseExpiresAt: string;
  readonly leaseMs: number;
  readonly clock: () => Date;
  /** Timer seam (default: unref'd global timers). */
  readonly timers?: LeaseTimers;
}

const DEFAULT_TIMERS: LeaseTimers = Object.freeze({
  setTimeout(callback: () => void, ms: number): unknown {
    const handle = setTimeout(callback, ms);
    handle.unref();
    return handle;
  },
  clearTimeout(handle: unknown): void {
    clearTimeout(handle as ReturnType<typeof setTimeout>);
  },
});

export class LeaseKeeper {
  readonly #controller = new AbortController();
  readonly #renew: () => string | null;
  readonly #clock: () => Date;
  readonly #timers: LeaseTimers;
  readonly #interval: number;
  readonly #margin: number;
  #expiresAt: number;
  #handle: unknown = undefined;
  #lossCause: LeaseLossCause | null = null;
  #stopped = false;

  constructor(options: LeaseKeeperOptions) {
    if (typeof options?.renew !== 'function' || typeof options.clock !== 'function') throw new TypeError('the lease keeper needs a renewal and a clock');
    if (!Number.isSafeInteger(options.leaseMs) || options.leaseMs < 3) throw new TypeError('the lease length must be a positive integer of ms');
    const expiresAt = Date.parse(options.leaseExpiresAt);
    if (Number.isNaN(expiresAt)) throw new TypeError('the lease expiry must be a server time');
    this.#renew = options.renew;
    this.#clock = options.clock;
    this.#timers = options.timers ?? DEFAULT_TIMERS;
    this.#interval = Math.floor(options.leaseMs / 3);
    this.#margin = Math.floor(options.leaseMs / 10);
    this.#expiresAt = expiresAt;
  }

  /** Aborted when the lease is lost; pass it to sealComposedPdf. */
  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  get lossCause(): LeaseLossCause | null {
    return this.#lossCause;
  }

  start(): void {
    this.#schedule();
  }

  stop(): void {
    this.#stopped = true;
    if (this.#handle !== undefined) this.#timers.clearTimeout(this.#handle);
    this.#handle = undefined;
  }

  /** Throws LeaseLost when the lease is lost or its local deadline has passed. */
  checkHeld(): void {
    if (this.#lossCause === null && this.#pastDeadline()) this.#lose('deadline');
    if (this.#lossCause !== null) throw new LeaseLost(this.#lossCause);
  }

  /** One renewal step; the timer runs it. */
  tick(): void {
    this.#handle = undefined;
    if (this.#stopped || this.#lossCause !== null) return;
    if (this.#pastDeadline()) {
      this.#lose('deadline');
      return;
    }
    let renewed: string | null;
    try {
      renewed = this.#renew();
    } catch {
      this.#schedule();
      return;
    }
    const next = renewed === null ? Number.NaN : Date.parse(renewed);
    if (Number.isNaN(next)) {
      this.#lose('fenced');
      return;
    }
    this.#expiresAt = next;
    this.#schedule();
  }

  #pastDeadline(): boolean {
    return this.#clock().getTime() >= this.#expiresAt - this.#margin;
  }

  #schedule(): void {
    if (this.#stopped || this.#lossCause !== null) return;
    const untilDeadline = this.#expiresAt - this.#margin - this.#clock().getTime();
    this.#handle = this.#timers.setTimeout(() => this.tick(), Math.max(1, Math.min(this.#interval, untilDeadline)));
  }

  #lose(cause: LeaseLossCause): void {
    this.#lossCause = cause;
    this.stop();
    this.#controller.abort(new LeaseLost(cause));
  }
}
