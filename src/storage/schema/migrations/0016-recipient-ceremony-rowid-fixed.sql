-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0016 (T008 follow-up; A-010 ROWID-CER): no
-- recipient-ceremony row is replaced, moved or removed through its hidden
-- rowid, and no recipient session is deleted. Conventions: see 0001.
--
-- invitations, challenges and recipient_sessions are rowid tables with text
-- keys, so every row also has a hidden integer rowid, one column spelled rowid,
-- _rowid_ or oid, which is unique as well. 0014 refuses an insert whose key
-- exists, yet a raw writer could still reset a row past 0003, 0013 and 0014:
-- - INSERT OR REPLACE naming an existing row's rowid with a new key: the rowid
--   conflict deletes that row (with recursive triggers off, the default, no
--   delete trigger fires), and an insert of the old key then recreates it with
--   its wrong-code count, attempts, supersession, revocation or CSRF secret
--   reset. Foreign keys do not stop it: they are off on a new connection, a
--   deferred check is satisfied again by the re-insert, and nothing references
--   a challenge or a session;
-- - UPDATE OR REPLACE moving another row onto the victim's rowid, which
--   deletes the victim the same way;
-- - DELETE of a recipient session and an insert of it again (0013 already
--   refuses deletes on invitations and challenges).
-- No production code names a rowid: the store inserts declared columns only
-- and reads rowid only for paging. Production updates never change a key, and
-- no production path deletes a session.
--
-- On each of the three tables:
-- - <table>_rowid_exists (BEFORE INSERT, beside 0014's <table>_key_exists):
--   an insert whose rowid equals an existing row's is refused before conflict
--   resolution, whatever its conflict clause. When an insert names no rowid,
--   SQLite leaves NEW.rowid undefined in a BEFORE INSERT trigger (it is -1 in
--   practice); no stored row can have a rowid of 0 or less (next trigger), so
--   that value matches no row. A runtime that changed it to a value that
--   matched would refuse ordinary inserts: that fails closed, and CH-08's
--   ordinary insert makes it fail loudly.
-- - <table>_rowid_positive (AFTER INSERT, where NEW.rowid is the stored
--   value): a rowid of 0 or less is refused.
-- - <table>_rowid_key_fixed (BEFORE UPDATE): an update that changes the rowid
--   or a key column is refused before conflict resolution, so UPDATE OR
--   REPLACE can take neither another row's rowid nor its key. The key columns
--   are those of every uniqueness constraint 0003 declares: tenant_id and id,
--   and the global token_hash on invitations and value_hash on
--   recipient_sessions. (0003's bound-column triggers also refuse naming a key
--   column in an update; this trigger covers the rowid and holds on its own.)
-- And recipient_sessions_retained (BEFORE DELETE): a session row is never
-- deleted; a session ends through revoked_at, which 0003 makes final.
--
-- A duplicate key still surfaces as a trigger constraint (0014), and the app
-- reports storage_constraint. A task that must erase ceremony data amends
-- these triggers by an appended migration.

CREATE TRIGGER invitations_rowid_exists BEFORE INSERT ON invitations
WHEN EXISTS (SELECT 1 FROM invitations WHERE rowid = NEW.rowid)
BEGIN
  SELECT RAISE(ABORT, 'invitations rowid exists: a row is never replaced through its rowid');
END;

CREATE TRIGGER invitations_rowid_positive AFTER INSERT ON invitations
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'invitations rowid must be positive');
END;

CREATE TRIGGER invitations_rowid_key_fixed BEFORE UPDATE ON invitations
WHEN NEW.rowid IS NOT OLD.rowid
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.id IS NOT OLD.id
  OR NEW.token_hash IS NOT OLD.token_hash
BEGIN
  SELECT RAISE(ABORT, 'invitations rowid and key never change');
END;

CREATE TRIGGER challenges_rowid_exists BEFORE INSERT ON challenges
WHEN EXISTS (SELECT 1 FROM challenges WHERE rowid = NEW.rowid)
BEGIN
  SELECT RAISE(ABORT, 'challenges rowid exists: a row is never replaced through its rowid');
END;

CREATE TRIGGER challenges_rowid_positive AFTER INSERT ON challenges
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'challenges rowid must be positive');
END;

CREATE TRIGGER challenges_rowid_key_fixed BEFORE UPDATE ON challenges
WHEN NEW.rowid IS NOT OLD.rowid
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.id IS NOT OLD.id
BEGIN
  SELECT RAISE(ABORT, 'challenges rowid and key never change');
END;

CREATE TRIGGER recipient_sessions_rowid_exists BEFORE INSERT ON recipient_sessions
WHEN EXISTS (SELECT 1 FROM recipient_sessions WHERE rowid = NEW.rowid)
BEGIN
  SELECT RAISE(ABORT, 'recipient_sessions rowid exists: a row is never replaced through its rowid');
END;

CREATE TRIGGER recipient_sessions_rowid_positive AFTER INSERT ON recipient_sessions
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'recipient_sessions rowid must be positive');
END;

CREATE TRIGGER recipient_sessions_rowid_key_fixed BEFORE UPDATE ON recipient_sessions
WHEN NEW.rowid IS NOT OLD.rowid
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.id IS NOT OLD.id
  OR NEW.value_hash IS NOT OLD.value_hash
BEGIN
  SELECT RAISE(ABORT, 'recipient_sessions rowid and key never change');
END;

CREATE TRIGGER recipient_sessions_retained BEFORE DELETE ON recipient_sessions
BEGIN
  SELECT RAISE(ABORT, 'recipient_sessions rows are retained');
END;
