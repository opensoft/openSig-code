-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0013 (T008; A-008 P16): the recipient-ceremony
-- counters and markers only move forward, and every recipient session keeps one
-- CSRF secret for its whole life (data-model.md § Entities: Invitation,
-- Challenge, RecipientSession). Conventions: see 0001.
--
-- 0003 left these columns writable in any direction:
-- - invitations.expires_at belongs to the invitation's binding: it is fixed at
--   issue, as the earlier of sent_at + 7 days and the envelope's expiry. It
--   never moves. An extension would revive an invitation past its lifetime;
--   an invitation ends early only through revoked_at, which 0003 makes final.
-- - invitations.cumulative_wrong_codes never decreases, so the lockout after
--   20 wrong codes per invitation cannot be undone (0003's CHECK still demands
--   revoked_at once the count reaches 20).
-- - challenges.attempts never decreases, so the lock after 5 attempts cannot be
--   undone.
-- - challenges.superseded_at, once set, is final, as consumed_at is in 0003.
-- - Invitation and challenge rows are never deleted: deleting one and inserting
--   it again would reset its counters.
-- - recipient_sessions.csrf_secret is required on every new row and never
--   changes: the session's CSRF token is derived from it on every read.
--
-- Every trigger here is an AFTER trigger, as in 0010: NOT NULL, CHECK and
-- UNIQUE constraints are checked first, so a write that breaks a 0003
-- constraint still fails with that constraint, and a write that passes them and
-- breaks a rule below is then aborted with no change.

CREATE TRIGGER invitations_expiry_fixed AFTER UPDATE OF expires_at ON invitations
WHEN NEW.expires_at IS NOT OLD.expires_at
BEGIN
  SELECT RAISE(ABORT, 'invitations expires_at is fixed at issue');
END;

CREATE TRIGGER invitations_wrong_codes_monotonic AFTER UPDATE OF cumulative_wrong_codes ON invitations
WHEN NEW.cumulative_wrong_codes < OLD.cumulative_wrong_codes
BEGIN
  SELECT RAISE(ABORT, 'invitations cumulative_wrong_codes never decreases');
END;

CREATE TRIGGER invitations_retained AFTER DELETE ON invitations
BEGIN
  SELECT RAISE(ABORT, 'invitations rows are retained');
END;

CREATE TRIGGER challenges_attempts_monotonic AFTER UPDATE OF attempts ON challenges
WHEN NEW.attempts < OLD.attempts
BEGIN
  SELECT RAISE(ABORT, 'challenges attempts never decreases');
END;

CREATE TRIGGER challenges_supersession_final AFTER UPDATE OF superseded_at ON challenges
WHEN OLD.superseded_at IS NOT NULL AND NEW.superseded_at IS NOT OLD.superseded_at
BEGIN
  SELECT RAISE(ABORT, 'challenges supersession is final');
END;

CREATE TRIGGER challenges_retained AFTER DELETE ON challenges
BEGIN
  SELECT RAISE(ABORT, 'challenges rows are retained');
END;

CREATE TRIGGER recipient_sessions_csrf_required AFTER INSERT ON recipient_sessions
WHEN NEW.csrf_secret IS NULL
BEGIN
  SELECT RAISE(ABORT, 'recipient_sessions csrf_secret is required');
END;

CREATE TRIGGER recipient_sessions_csrf_immutable AFTER UPDATE OF csrf_secret ON recipient_sessions
WHEN NEW.csrf_secret IS NOT OLD.csrf_secret
BEGIN
  SELECT RAISE(ABORT, 'recipient_sessions csrf_secret is immutable');
END;
