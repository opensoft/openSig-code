// SPDX-License-Identifier: Apache-2.0
//
// The recipient's view of the envelope (T008; contract RecipientSessionState).
// It returns every approval input: the session-bound document summary and
// manifest digest, this recipient's fields only, the prior approval digest,
// the exact consent text with its version and digest, the assurance statement,
// the organization-seal notice, the CSRF token, the turn and the idle expiry.
// It never carries another recipient's identity or capability, an invitation,
// a challenge code or the session value.

import type { JsonValue } from '../../domain/canonical/index.ts';
import { ASSURANCE, SEAL_NOTICE, consentView, type ConsentText } from '../../domain/consent/index.ts';
import { APPROVING_STATES, turnAfter, type EnvelopeState } from '../../domain/envelopes/states.ts';
import type { EnvelopeRecord, FieldRecord, RecipientRecord, RevisionRecord } from '../../storage/repositories/envelopes.ts';

export type Turn = 'yours' | 'waiting-for-prior' | 'done' | 'closed';

/** States in which a recipient session can exist: invitations are issued at send. */
export const SESSION_ENVELOPE_STATES: readonly EnvelopeState[] = Object.freeze(['sent', 'in-progress', 'finalizing', 'completed', 'declined', 'expired', 'voided'] as const);

/** The recipient's address with the local part masked: first and last character only. */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf('@');
  if (at < 1) return '***';
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  const masked = local.length <= 2 ? `${local[0] ?? ''}***` : `${local[0] ?? ''}***${local[local.length - 1] ?? ''}`;
  return `${masked}@${domain}`.slice(0, 254);
}

/**
 * Whose turn it is, from this recipient's side:
 * - done: this recipient has approved;
 * - closed: the envelope no longer takes approvals (finalizing or terminal, or
 *   past its expiry), or this recipient's participation ended;
 * - yours: this recipient is invited and is the first not yet approved;
 * - waiting-for-prior: an earlier recipient must approve first.
 */
export function turnOf(envelope: EnvelopeRecord, recipients: readonly RecipientRecord[], recipient: RecipientRecord, now: Date): Turn {
  if (recipient.status === 'approved') return 'done';
  if (!APPROVING_STATES.includes(envelope.state) || Date.parse(envelope.expiresAt) <= now.getTime()) return 'closed';
  if (recipient.status === 'pending') return 'waiting-for-prior';
  if (recipient.status !== 'invited') return 'closed';
  const turn = turnAfter(
    recipients.filter((entry) => entry.status === 'approved').map((entry) => entry.ordinal),
    envelope.recipientsCount,
  );
  return turn === recipient.ordinal ? 'yours' : 'waiting-for-prior';
}

export interface SessionStateInput {
  readonly envelope: EnvelopeRecord;
  readonly recipients: readonly RecipientRecord[];
  readonly recipient: RecipientRecord;
  readonly revision: RevisionRecord;
  readonly manifestDigest: string;
  readonly fields: readonly FieldRecord[];
  readonly consent: ConsentText;
  readonly csrfToken: string;
  readonly sessionExpiresAt: string;
  readonly now: Date;
}

/** RecipientSessionState for the session's own recipient. */
export function sessionStateView(input: SessionStateInput): JsonValue {
  const { envelope, recipient } = input;
  const prior = recipient.ordinal === 1 ? null : (input.recipients.find((entry) => entry.ordinal === recipient.ordinal - 1)?.approvalDigest ?? null);
  return {
    envelope_id: envelope.id,
    envelope_version: envelope.version,
    envelope_state: envelope.state,
    recipient: {
      id: recipient.id,
      ordinal: recipient.ordinal,
      role: recipient.role,
      email_masked: maskEmail(recipient.email),
      status: recipient.status,
    },
    turn: turnOf(envelope, input.recipients, recipient, input.now),
    document: {
      digest: input.revision.contentDigest,
      bytes: input.revision.bytes,
      pages: input.revision.pages.map((page) => ({ number: page.number, width: page.width, height: page.height, rotate: page.rotate })),
    },
    manifest_digest: input.manifestDigest,
    fields: input.fields
      .filter((field) => field.recipientId === recipient.id)
      .map((field) => ({
        key: field.key,
        recipient_id: field.recipientId,
        recipient_ordinal: field.recipientOrdinal,
        page: field.page,
        type: field.type,
        rect: { x: field.rect.x, y: field.rect.y, width: field.rect.width, height: field.rect.height },
      })),
    prior_approval_digest: prior,
    consent: { ...consentView(input.consent) },
    assurance: { method: ASSURANCE.method, level: ASSURANCE.level, statement: ASSURANCE.statement },
    seal_notice: SEAL_NOTICE,
    csrf_token: input.csrfToken,
    session_expires_at: input.sessionExpiresAt,
  };
}
