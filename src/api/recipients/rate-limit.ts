// SPDX-License-Identifier: Apache-2.0
//
// Sliding-window request limits of the recipient ceremony (T008; contract
// requestChallenge: "rate-limited per invitation and per client address";
// createRecipientSession: 429 when rate-limited).
//
// A limiter counts accepted requests per key over the last `windowMs`; a
// refused request takes no budget. Keys are client addresses, or the SHA-256 of
// the presented invitation whether or not it names an invitation, so a limit
// answers the same for a valid and an unknown token and reveals nothing. State
// is per process, which is the single-instance pilot's deployment; the key
// count is bounded and the oldest key is dropped first.

export interface WindowLimit {
  readonly limit: number;
  readonly windowMs: number;
}

export type LimitDecision = { readonly ok: true } | { readonly ok: false; readonly retryAfterMs: number };

export interface WindowLimiter {
  /** Whether `key` may make one more request now; records nothing. */
  check(key: string): LimitDecision;
  /** Count one accepted request for `key`. */
  record(key: string): void;
  /** check(), and record() when allowed. */
  take(key: string): LimitDecision;
}

export const MAX_LIMITER_KEYS = 10_000;

export function validWindowLimit(value: unknown): value is WindowLimit {
  if (typeof value !== 'object' || value === null) return false;
  const { limit, windowMs } = value as Record<string, unknown>;
  return (
    typeof limit === 'number' && Number.isSafeInteger(limit) && limit >= 1 && limit <= 1_000_000 &&
    typeof windowMs === 'number' && Number.isSafeInteger(windowMs) && windowMs >= 1 && windowMs <= 86_400_000
  );
}

export function createWindowLimiter(rule: WindowLimit, now: () => number, maxKeys = MAX_LIMITER_KEYS): WindowLimiter {
  if (!validWindowLimit(rule)) throw new TypeError('a window limit needs an integer limit and window');
  const windows = new Map<string, number[]>();
  const recent = (key: string, at: number): number[] => (windows.get(key) ?? []).filter((stamp) => stamp > at - rule.windowMs);
  const check = (key: string): LimitDecision => {
    const at = now();
    const stamps = recent(key, at);
    if (stamps.length < rule.limit) return { ok: true };
    return { ok: false, retryAfterMs: Math.max(1, (stamps[0] as number) + rule.windowMs - at) };
  };
  const record = (key: string): void => {
    const at = now();
    const stamps = recent(key, at);
    stamps.push(at);
    windows.delete(key);
    windows.set(key, stamps);
    while (windows.size > maxKeys) {
      const oldest = windows.keys().next().value;
      if (oldest === undefined) break;
      windows.delete(oldest);
    }
  };
  return Object.freeze({
    check,
    record,
    take(key: string): LimitDecision {
      const decision = check(key);
      if (decision.ok) record(key);
      return decision;
    },
  });
}
