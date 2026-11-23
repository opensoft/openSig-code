// SPDX-License-Identifier: Apache-2.0
//
// Consent text and the recipient notices (T008; data-model.md § Entities,
// ConsentText; spec.md clarification on consent evidence).
//
// - A ConsentText is immutable and versioned: version ^[a-z0-9.-]{1,40}$, the
//   exact UTF-8 wording (at most 20,000 characters) and text_digest, the
//   lowercase hex SHA-256 of exactly those UTF-8 bytes. A new wording is a new
//   version. The tenant's consent text in force is tenants.consent_text_id.
// - The recipient session (readRecipientSession) returns the exact wording with
//   its version and digest, so an approval can bind both (T010 compares them
//   with consentMatches) and the package can reproduce what was shown.
// - The assurance statement and the organization-seal notice are fixed texts:
//   the mailbox challenge records mailbox control only, never legal identity or
//   representative authority, and the final document is sealed by the
//   organization's certificate, not by a personal certificate.

import { createHash, timingSafeEqual } from 'node:crypto';

export const CONSENT_VERSION_PATTERN = /^[a-z0-9.-]{1,40}$/;
export const MAX_CONSENT_TEXT_LENGTH = 20_000;
const DIGEST = /^[0-9a-f]{64}$/;

export interface ConsentText {
  readonly id: string;
  readonly version: string;
  readonly locale: string;
  readonly text: string;
  readonly textDigest: string;
  readonly effectiveFrom: string;
}

/** The contract ConsentText view: {version, text_digest, text}. */
export interface ConsentView {
  readonly version: string;
  readonly text_digest: string;
  readonly text: string;
}

export class ConsentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConsentError';
  }
}

/** SHA-256 (lowercase hex) of the exact UTF-8 bytes of `text`. */
export function consentTextDigest(text: string): string {
  if (typeof text !== 'string') throw new ConsentError('consent text must be a string');
  return createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

/**
 * Check a stored consent text before it is shown: the version and length rules
 * hold and the digest is the digest of the exact wording. A mismatch means the
 * stored record cannot be trusted as consent evidence, so it is refused.
 */
export function checkConsentText(consent: ConsentText): ConsentText {
  if (!CONSENT_VERSION_PATTERN.test(consent.version)) throw new ConsentError('consent version is malformed');
  const length = [...consent.text].length;
  if (length < 1 || length > MAX_CONSENT_TEXT_LENGTH) throw new ConsentError('consent text length is out of range');
  if (!DIGEST.test(consent.textDigest) || consentTextDigest(consent.text) !== consent.textDigest) {
    throw new ConsentError('consent text digest does not match its wording');
  }
  return consent;
}

export function consentView(consent: ConsentText): ConsentView {
  return { version: consent.version, text_digest: consent.textDigest, text: consent.text };
}

/**
 * True when a presented consent version and text digest are exactly those of
 * `consent` (the approval binding; T010 answers 409 consent_mismatch otherwise).
 */
export function consentMatches(consent: ConsentText, version: unknown, textDigest: unknown): boolean {
  if (typeof version !== 'string' || typeof textDigest !== 'string' || !DIGEST.test(textDigest)) return false;
  if (version !== consent.version) return false;
  return timingSafeEqual(Buffer.from(textDigest, 'ascii'), Buffer.from(consent.textDigest, 'ascii'));
}

/** RecipientSessionState.assurance: what the mailbox challenge does and does not establish. */
export const ASSURANCE = Object.freeze({
  method: 'mailbox-challenge',
  level: 'mailbox-control',
  statement:
    'You confirmed control of this mailbox with a one-time code. That records mailbox control only: ' +
    'it does not verify your legal identity or any authority to act for an organization.',
} as const);

/** RecipientSessionState.seal_notice: the organization seal is not a personal certificate signature. */
export const SEAL_NOTICE =
  'After every required approval, the final document is sealed with the organization’s certificate. ' +
  'It is not signed with a personal certificate. Until that seal is applied and verified, the document is not completed.';
