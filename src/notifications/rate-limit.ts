// SPDX-License-Identifier: Apache-2.0
//
// Per-tenant notification rate limit (T032): a sliding window of at most `limit` accepted
// sends per `windowMs`. Every audience counts against the same tenant budget. A refused
// request consumes nothing. State is in memory and bounded: one timestamp per accepted
// send inside the window, and idle tenants are dropped.

export interface RateLimitOptions {
  /** Accepted sends per window, 1..100000. */
  readonly limit: number;
  /** Window length in milliseconds, 1 s .. 24 h. */
  readonly windowMs: number;
}

export const DEFAULT_TENANT_RATE_LIMIT: RateLimitOptions = Object.freeze({ limit: 100, windowMs: 10 * 60 * 1000 });

export type RateDecision = { readonly ok: true } | { readonly ok: false; readonly retryAfterMs: number };

export interface TenantRateLimiter {
  /** Record one send for `tenantId` when the budget allows it. */
  take(tenantId: string): RateDecision;
}

const SWEEP_THRESHOLD = 1024;

export function validRateLimit(options: RateLimitOptions): boolean {
  return (
    Number.isSafeInteger(options.limit) &&
    options.limit >= 1 &&
    options.limit <= 100_000 &&
    Number.isSafeInteger(options.windowMs) &&
    options.windowMs >= 1000 &&
    options.windowMs <= 24 * 60 * 60 * 1000
  );
}

export function createTenantRateLimiter(options: RateLimitOptions, now: () => number): TenantRateLimiter {
  if (!validRateLimit(options)) throw new RangeError('rate limit must be 1..100000 sends per 1 s .. 24 h window');
  const { limit, windowMs } = options;
  const windows = new Map<string, number[]>();

  const prune = (stamps: number[], at: number): void => {
    let drop = 0;
    while (drop < stamps.length && (stamps[drop] ?? 0) <= at - windowMs) drop += 1;
    if (drop > 0) stamps.splice(0, drop);
  };

  return {
    take(tenantId) {
      const at = now();
      if (windows.size > SWEEP_THRESHOLD) {
        for (const [tenant, stamps] of windows) {
          prune(stamps, at);
          if (stamps.length === 0) windows.delete(tenant);
        }
      }
      let stamps = windows.get(tenantId);
      if (stamps === undefined) {
        stamps = [];
        windows.set(tenantId, stamps);
      }
      prune(stamps, at);
      if (stamps.length >= limit) {
        const oldest = stamps[0] ?? at;
        return { ok: false, retryAfterMs: Math.max(1, oldest + windowMs - at) };
      }
      stamps.push(at);
      return { ok: true };
    },
  };
}
