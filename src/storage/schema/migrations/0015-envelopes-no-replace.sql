-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0015 (T007 slot; A-010 REPLACE-ENV and ROWID-ENV):
-- no envelope row is ever replaced, re-keyed or deleted. Conventions: see 0001.
--
-- The 0010 guards on envelopes (the version step, the state graph and the
-- frozen columns) are UPDATE triggers. A conflict clause of REPLACE resolves a
-- uniqueness conflict by deleting the row that holds the key, and with
-- recursive triggers off, the default, that implicit delete fires no delete
-- trigger; the new row is checked by no update trigger. A plain DELETE fires no
-- update trigger either. Either way an envelope could be rolled back: its state
-- (a sent or completed envelope back to draft), its version, or its frozen base
-- revision, manifest and recipients digests. Foreign keys do not stop it: the
-- replacing row carries the same key, and with deferred foreign keys a delete
-- and a re-insert in one transaction satisfy every referencing row again.
--
-- An envelope is a rowid table (0002), so its hidden rowid is a uniqueness key
-- too: an insert naming an existing rowid (spelled rowid, _rowid_ or oid) with a
-- new key, or an update moving a row onto another row's rowid, replaces that
-- other row. The four triggers below close every route:
-- - envelopes_key_exists (BEFORE INSERT): a new row whose key (tenant_id, id) or
--   rowid already exists is refused before conflict resolution. When the insert
--   names no rowid, SQLite leaves NEW.rowid undefined (the runtime reports -1);
--   no stored rowid is 0 or less (next trigger), so that value matches no row
--   and an ordinary insert proceeds. Were a runtime ever to report an existing
--   rowid there, the insert would be refused: the check fails closed.
-- - envelopes_rowid_positive (AFTER INSERT): a stored rowid of 0 or less is
--   refused. In an AFTER INSERT trigger NEW.rowid is the rowid actually stored.
-- - envelopes_key_fixed (BEFORE UPDATE): an update that changes the rowid or the
--   key is refused before conflict resolution, so UPDATE OR REPLACE cannot take
--   another row's rowid or key and delete that row.
-- - envelopes_no_delete (BEFORE DELETE): a plain delete is refused. Envelopes are
--   never deleted (retention disposes of blobs, never of envelope rows).
--
-- A plain duplicate insert is therefore refused by envelopes_key_exists rather
-- than by the primary key; the store reports either as storage_constraint. A new
-- envelope (a new id, or the same id in another tenant) inserts as before, and
-- an existing envelope changes only through UPDATE, under the 0010 triggers.
-- This migration adds no envelopes column, so envelopes_version_step is
-- unchanged (data-model.md § Transitions and races, item 1).

CREATE TRIGGER envelopes_key_exists BEFORE INSERT ON envelopes
WHEN EXISTS (
  SELECT 1 FROM envelopes WHERE (tenant_id = NEW.tenant_id AND id = NEW.id) OR rowid = NEW.rowid
)
BEGIN
  SELECT RAISE(ABORT, 'envelopes key exists: an envelope row is never replaced');
END;

CREATE TRIGGER envelopes_rowid_positive AFTER INSERT ON envelopes
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'envelopes rowid must be positive');
END;

CREATE TRIGGER envelopes_key_fixed BEFORE UPDATE ON envelopes
WHEN NEW.rowid IS NOT OLD.rowid OR NEW.tenant_id IS NOT OLD.tenant_id OR NEW.id IS NOT OLD.id
BEGIN
  SELECT RAISE(ABORT, 'envelopes key and rowid never change');
END;

CREATE TRIGGER envelopes_no_delete BEFORE DELETE ON envelopes
BEGIN
  SELECT RAISE(ABORT, 'envelopes rows are never deleted');
END;
