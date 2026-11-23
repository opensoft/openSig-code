-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0014 (T008 follow-up; A-010 review finding F3):
-- no recipient-ceremony row is ever replaced. Conventions: see 0001.
--
-- INSERT OR REPLACE (and REPLACE, or an INSERT whose conflict clause is
-- REPLACE) resolves a uniqueness conflict by deleting the row that holds the
-- key and inserting the new one. With recursive triggers off, the default,
-- that implicit delete fires no delete trigger, and the new row is checked by
-- no update trigger. So it would get past 0003 and 0013 and could reset what
-- they keep final or monotonic: the wrong-code count, challenge attempts (a
-- locked challenge), supersession, revocation and the CSRF secret.
--
-- Each trigger here refuses an insert whose key already exists, before
-- conflict resolution runs, so no conflict clause can replace the row. The
-- keys are every uniqueness constraint 0003 declares on the table:
-- - the composite primary key (tenant_id, id), on all three tables;
-- - invitations' global UNIQUE (token_hash) and recipient_sessions' global
--   UNIQUE (value_hash). A fresh id with a hash that already exists, in the
--   same tenant or in another one, would otherwise replace (delete) the row
--   holding that hash.
--
-- These are BEFORE INSERT triggers, unlike 0013's: a conflicting insert must
-- be refused before SQLite resolves the conflict. A plain duplicate insert is
-- therefore refused by the trigger rather than by the 0003 constraint. A new
-- row with new keys inserts as before, and existing rows change only through
-- UPDATE, under the 0003 and 0013 triggers.

CREATE TRIGGER invitations_key_exists BEFORE INSERT ON invitations
WHEN EXISTS (
  SELECT 1 FROM invitations WHERE (tenant_id = NEW.tenant_id AND id = NEW.id) OR token_hash = NEW.token_hash
)
BEGIN
  SELECT RAISE(ABORT, 'invitations key exists: an invitation row is never replaced');
END;

CREATE TRIGGER challenges_key_exists BEFORE INSERT ON challenges
WHEN EXISTS (
  SELECT 1 FROM challenges WHERE tenant_id = NEW.tenant_id AND id = NEW.id
)
BEGIN
  SELECT RAISE(ABORT, 'challenges key exists: a challenge row is never replaced');
END;

CREATE TRIGGER recipient_sessions_key_exists BEFORE INSERT ON recipient_sessions
WHEN EXISTS (
  SELECT 1 FROM recipient_sessions WHERE (tenant_id = NEW.tenant_id AND id = NEW.id) OR value_hash = NEW.value_hash
)
BEGIN
  SELECT RAISE(ABORT, 'recipient_sessions key exists: a session row is never replaced');
END;
