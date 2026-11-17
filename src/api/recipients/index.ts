// SPDX-License-Identifier: Apache-2.0
//
// Public surface of the recipient ceremony (T008). Typical wiring:
//
//   const ceremony = new RecipientCeremony({ db, blobs, notifier, clock,
//     challengeKey: loadChallengeKey({ path }) });   // or { fd }: never env or argv
//   const envelopes = new EnvelopeService({ db, clock, onChange: ceremony.onEnvelopeChange });
//   app.locals.set(RECIPIENT_CEREMONY, ceremony);
//   await ceremony.run(() => envelopes.send(request, id, input));  // mails after the commit
//   ...
//   await ceremony.drain();  // at shutdown: requestChallenge work still running after its 202
//
// The route handlers are installed by src/api/routes.ts (withRecipientHandlers).

export {
  CHALLENGE_TTL_MS,
  DEFAULT_CEREMONY_LIMITS,
  INVITATION_TTL_MS,
  InvitationMail,
  RecipientCeremony,
  type CeremonyLimits,
  type ChallengeWorkStats,
  type CreatedSession,
  type DeliveryReport,
  type RecipientCeremonyOptions,
  type WorkScheduler,
} from './ceremony.ts';
export {
  CHALLENGE_CODE_LENGTH,
  CHALLENGE_CODE_PATTERN,
  ChallengeKeyError,
  CROCKFORD_ALPHABET,
  loadChallengeKey,
  MAX_CHALLENGE_KEY_BYTES,
  MIN_CHALLENGE_KEY_BYTES,
  newChallengeCode,
  newInvitationToken,
  type ChallengeKey,
  type ChallengeKeySource,
} from './codes.ts';
export { CEREMONY_HANDLERS, ceremonyAuthority, ceremonyOf, RECIPIENT_CEREMONY } from './handlers.ts';
export { createWindowLimiter, type LimitDecision, type WindowLimit, type WindowLimiter } from './rate-limit.ts';
export { checkChallengeRequest, checkSessionCreate, INVITATION_PATTERN, SESSION_CODE_PATTERN } from './validation.ts';
export { maskEmail, SESSION_ENVELOPE_STATES, sessionStateView, turnOf, type Turn } from './views.ts';
