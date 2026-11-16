// SPDX-License-Identifier: Apache-2.0
//
// Send rules (contract § Sending and human confirmation; data-model.md
// § Entities, SendConfirmation). An envelope created by a service principal
// is sent only with a SendConfirmation that:
// - a human operator of the tenant made (never a service principal);
// - names this envelope, its current version and its current document,
//   manifest and recipients digests;
// - is unconsumed and unexpired (24 hours, or the envelope's expiry if
//   earlier);
// - is consumed by the send that uses it (single use).
// A human-created envelope needs no confirmation (send_confirmation.required
// is true exactly when created_by.kind is service).

import type { SendConfirmationRecord } from '../../storage/repositories/envelopes.ts';
import type { Actor } from './validation.ts';

export const CONFIRMATION_TTL_MS = 24 * 60 * 60 * 1000;

export function confirmationRequired(createdBy: Actor): boolean {
  return createdBy.kind === 'service';
}

/** A confirmation expires 24 hours after it is made or at the envelope's expiry, whichever is first. */
export function confirmationExpiry(now: Date, envelopeExpiresAt: string): string {
  const day = now.getTime() + CONFIRMATION_TTL_MS;
  return new Date(Math.min(day, Date.parse(envelopeExpiresAt))).toISOString();
}

export interface ConfirmationTarget {
  readonly envelopeId: string;
  readonly version: number;
  readonly documentDigest: string;
  readonly manifestDigest: string;
  readonly recipientsDigest: string;
}

export type ConfirmationProblem = 'other-envelope' | 'not-human' | 'consumed' | 'expired' | 'stale-version' | 'digest-mismatch';

/** Why a confirmation cannot authorize this send; empty when it can. */
export function confirmationProblems(confirmation: SendConfirmationRecord, target: ConfirmationTarget, now: Date): ConfirmationProblem[] {
  const problems: ConfirmationProblem[] = [];
  if (confirmation.envelopeId !== target.envelopeId) problems.push('other-envelope');
  if (confirmation.confirmedBy.kind !== 'human-operator') problems.push('not-human');
  if (confirmation.consumedAt !== null) problems.push('consumed');
  if (Date.parse(confirmation.expiresAt) <= now.getTime()) problems.push('expired');
  if (confirmation.envelopeVersion !== target.version) problems.push('stale-version');
  if (
    confirmation.documentDigest !== target.documentDigest ||
    confirmation.manifestDigest !== target.manifestDigest ||
    confirmation.recipientsDigest !== target.recipientsDigest
  ) {
    problems.push('digest-mismatch');
  }
  return problems;
}
