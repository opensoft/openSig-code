// SPDX-License-Identifier: Apache-2.0
//
// Per-tenant cap on in-flight uploads (A-010 LBR4-1; row "EA-01 sizing"; test EA-01).
//
// The isolated parse service (T033, src/pdf/service.ts) reads a streamed upload only under
// one of MAX_CONCURRENT_BODY_READS body-read permits, and refuses at once (429
// body-read-capacity) when every permit is held. The server's body timing (T031, SEC-10)
// lets an honest upload keep its permit for up to 640 s (10 MiB at the 16 KiB/s minimum
// rate), so one tenant could otherwise hold every permit for that long and starve every
// other tenant.
//
// uploadDocument therefore takes one of this tenant's upload slots before it hands the body
// to the parse service, and holds it until the upload's handler is done (accepted, refused,
// failed or aborted). A tenant holds at most UPLOADS_PER_TENANT slots: at most half of the
// parse service's body-read permits, and at least 1. The number is derived from T033's
// exported permit count, never copied. A further upload from a tenant at its cap is refused
// at once, before any body byte is read and before it can take a body-read permit (429
// rate_limited, detail upload-capacity). So one tenant can hold at most half of the permits,
// and another tenant's upload can always take one of the rest.
//
// The counts are process-wide, like the body-read permits they share out: every app in the
// process (the public listener and the Hermes relay) draws on the same parse service, so the
// cap must hold across them. uploadCapacity() is a read-only view for monitoring and tests.

import { MAX_CONCURRENT_BODY_READS } from '../../pdf/service.ts';

/** Uploads one tenant may have in flight: at most half of T033's body-read permits, and at least 1. */
export const UPLOADS_PER_TENANT: number = Math.max(1, Math.floor(MAX_CONCURRENT_BODY_READS / 2));

/** In-flight uploads per tenant; a tenant with none has no entry. */
const inFlight = new Map<string, number>();

export interface UploadSlot {
  /** Give the slot back; idempotent. */
  release(): void;
}

/** Take one of `tenantId`'s upload slots, or null when the tenant already holds UPLOADS_PER_TENANT. */
export function acquireUploadSlot(tenantId: string): UploadSlot | null {
  const held = inFlight.get(tenantId) ?? 0;
  if (held >= UPLOADS_PER_TENANT) return null;
  inFlight.set(tenantId, held + 1);
  let released = false;
  return Object.freeze({
    release(): void {
      if (released) return;
      released = true;
      const left = (inFlight.get(tenantId) ?? 1) - 1;
      if (left > 0) inFlight.set(tenantId, left);
      else inFlight.delete(tenantId);
    },
  });
}

/** Read-only: the upload slots `tenantId` holds now, and the cap. */
export function uploadCapacity(tenantId: string): { readonly held: number; readonly max: number } {
  return Object.freeze({ held: inFlight.get(tenantId) ?? 0, max: UPLOADS_PER_TENANT });
}

/** Read-only: upload slots held across every tenant (0 when the process is idle). */
export function uploadsInFlight(): number {
  let total = 0;
  for (const held of inFlight.values()) total += held;
  return total;
}
