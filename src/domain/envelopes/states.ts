// SPDX-License-Identifier: Apache-2.0
//
// The envelope state machine (data-model.md § Envelope states and the "fully
// approved" mapping, transition graph ruled in A-010). Migration 0010 enforces
// the same graph in the schema on every UPDATE that changes state; this module
// is what domain code consults before it writes.

export const ENVELOPE_STATES = Object.freeze([
  'draft',
  'prepared',
  'sent',
  'in-progress',
  'finalizing',
  'completed',
  'declined',
  'expired',
  'voided',
] as const);

export type EnvelopeState = (typeof ENVELOPE_STATES)[number];

export const RECIPIENT_STATUSES = Object.freeze(['pending', 'invited', 'approved', 'declined', 'expired', 'revoked'] as const);

export type RecipientStatus = (typeof RECIPIENT_STATUSES)[number];

/** The only legal transitions. An update that keeps the state is not a transition. */
export const TRANSITIONS: Readonly<Record<EnvelopeState, readonly EnvelopeState[]>> = Object.freeze({
  draft: Object.freeze(['prepared', 'voided', 'expired'] as const),
  prepared: Object.freeze(['sent', 'voided', 'expired'] as const),
  sent: Object.freeze(['in-progress', 'finalizing', 'declined', 'voided', 'expired'] as const),
  'in-progress': Object.freeze(['finalizing', 'declined', 'voided', 'expired'] as const),
  finalizing: Object.freeze(['completed'] as const),
  completed: Object.freeze([] as const),
  declined: Object.freeze([] as const),
  expired: Object.freeze([] as const),
  voided: Object.freeze([] as const),
});

export const TERMINAL_STATES: readonly EnvelopeState[] = Object.freeze(['completed', 'declined', 'expired', 'voided'] as const);

/** States before the finalization reservation: void, decline and expiry can still win. */
export const PRE_RESERVATION_STATES: readonly EnvelopeState[] = Object.freeze(['draft', 'prepared', 'sent', 'in-progress'] as const);

/** States in which recipients may still approve. */
export const APPROVING_STATES: readonly EnvelopeState[] = Object.freeze(['sent', 'in-progress'] as const);

/** "Fully approved" is approvals_complete = true, which holds exactly in these states. */
export const FULLY_APPROVED_STATES: readonly EnvelopeState[] = Object.freeze(['finalizing', 'completed'] as const);

/** States from which a reissue may start. */
export const REISSUABLE_STATES: readonly EnvelopeState[] = Object.freeze(['declined', 'expired', 'voided'] as const);

export function isEnvelopeState(value: unknown): value is EnvelopeState {
  return typeof value === 'string' && (ENVELOPE_STATES as readonly string[]).includes(value);
}

export function isRecipientStatus(value: unknown): value is RecipientStatus {
  return typeof value === 'string' && (RECIPIENT_STATUSES as readonly string[]).includes(value);
}

export function canTransition(from: EnvelopeState, to: EnvelopeState): boolean {
  return TRANSITIONS[from].includes(to);
}

export function isTerminal(state: EnvelopeState): boolean {
  return TERMINAL_STATES.includes(state);
}

export function isFullyApproved(state: EnvelopeState): boolean {
  return FULLY_APPROVED_STATES.includes(state);
}

/**
 * The state an approval moves the envelope to. The last required approval
 * makes it fully approved (finalizing, approvals_complete = true): for one
 * recipient that is sent -> finalizing directly, never through in-progress.
 * The first approval of two moves it to in-progress.
 */
export function stateAfterApproval(recipientsCount: number, ordinal: number): EnvelopeState {
  if (!Number.isInteger(recipientsCount) || recipientsCount < 1 || recipientsCount > 2) {
    throw new RangeError('recipients count must be 1 or 2');
  }
  if (!Number.isInteger(ordinal) || ordinal < 1 || ordinal > recipientsCount) {
    throw new RangeError('ordinal must be in 1..recipients count');
  }
  return ordinal === recipientsCount ? 'finalizing' : 'in-progress';
}

/** The ordinal whose turn it is: the first one not yet approved, given approvals so far. */
export function turnAfter(approvedOrdinals: readonly number[], recipientsCount: number): number | null {
  for (let ordinal = 1; ordinal <= recipientsCount; ordinal += 1) {
    if (!approvedOrdinals.includes(ordinal)) return ordinal;
  }
  return null;
}
