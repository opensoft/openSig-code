-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0018 (T010 follow-up; A-010 ROWID-APJ): no
-- approval and no SigningJob is replaced by key, moved through its hidden
-- rowid, re-keyed or deleted. Conventions: see 0001.
--
-- approvals (0003) and signing_jobs (0004) are rowid tables with text keys,
-- the class 0015 (envelopes), 0016 (the ceremony rows) and 0017 (approval
-- receipts) closed. Their earlier guards are UPDATE and DELETE triggers:
-- approvals_immutable_update and approvals_immutable_delete (0003), and
-- signing_jobs_monotonic and signing_jobs_immutable_delete (0004). A conflict
-- clause of REPLACE resolves a uniqueness conflict by deleting the row that
-- holds the key, and with recursive triggers off, the default, that implicit
-- delete fires no delete trigger; the new row is checked by no update trigger.
-- So a raw writer could:
-- - INSERT OR REPLACE (or REPLACE) an approval by its key (tenant_id, id), its
--   recipient (tenant_id, recipient_id) or its four-column key, swapping the
--   approval's evidence: the consent and sequence triggers of 0003 check only
--   the new row;
-- - INSERT OR REPLACE a SigningJob by (tenant_id, envelope_id) after a lease
--   was granted, resetting its attempt_count, fencing token and lease, which
--   signing_jobs_monotonic (an UPDATE trigger) keeps from moving backward;
-- - do either through the hidden rowid (spelled rowid, _rowid_ or oid): an
--   insert naming an existing row's rowid with a new key deletes that row, and
--   a re-insert of the old key then recreates it;
-- - move a SigningJob onto another job's rowid with UPDATE OR REPLACE, which
--   deletes that job: signing_jobs_monotonic does not look at the rowid.
-- Foreign keys do not stop it: they are off on a new connection, a deferred
-- check is satisfied again by the re-insert, and nothing references these
-- rows except the approval receipts (0017, whose insert-time check a deferred
-- re-insert satisfies again).
--
-- The guards, in the 0015-0017 pattern:
-- - approvals_key_exists and signing_jobs_key_exists (BEFORE INSERT): an
--   insert whose key or rowid already exists is refused before conflict
--   resolution, whatever its conflict clause. The approvals keys are every
--   uniqueness constraint 0003 declares: (tenant_id, id), (tenant_id,
--   recipient_id), and (tenant_id, envelope_id, recipient_id, id), which
--   contains the first and so cannot conflict without it. The signing_jobs key
--   is its primary key (tenant_id, envelope_id). When an insert names no rowid,
--   SQLite leaves NEW.rowid undefined in a BEFORE INSERT trigger (-1 in
--   practice); no stored rowid is 0 or less (next trigger), so that value
--   matches no row and an ordinary insert proceeds. A runtime that changed it
--   to a matching value would refuse ordinary inserts: that fails closed, and
--   the approval and reservation of every approval test make it fail loudly.
-- - approvals_rowid_positive and signing_jobs_rowid_positive (AFTER INSERT,
--   where NEW.rowid is the stored value): a rowid of 0 or less is refused.
-- - signing_jobs_rowid_key_fixed (BEFORE UPDATE): an update that changes the
--   rowid or the key is refused before conflict resolution, so UPDATE OR
--   REPLACE can take neither another job's rowid nor its key. (0004's
--   signing_jobs_monotonic also refuses a key change; this trigger covers the
--   rowid and holds on its own.) Every other column stays writable: the
--   finalization runner's and the operator retry's updates of status,
--   attempt_count, fencing_token, lease_owner, lease_expires_at, retry_at,
--   last_error_code, max_attempts, version and updated_at are unchanged, under
--   0004's CHECKs and signing_jobs_monotonic.
-- Nothing more is needed for update and delete: approvals_immutable_update
-- (0003) refuses every update of an approval, its rowid included, before
-- conflict resolution, and approvals_immutable_delete (0003) and
-- signing_jobs_immutable_delete (0004) refuse a plain delete.
--
-- No production path names a rowid, re-keys either table or deletes from it:
-- the store inserts declared columns only, reads rowid only for paging, and
-- refuses an update of tenant_id. A plain duplicate insert therefore surfaces
-- as a trigger constraint rather than a uniqueness or primary-key constraint;
-- the store reports either as storage_constraint. A new approval or a new
-- reservation inserts as before.

CREATE TRIGGER approvals_key_exists BEFORE INSERT ON approvals
WHEN EXISTS (
  SELECT 1 FROM approvals
  WHERE (tenant_id = NEW.tenant_id AND (id = NEW.id OR recipient_id = NEW.recipient_id))
    OR rowid = NEW.rowid
)
BEGIN
  SELECT RAISE(ABORT, 'approvals key exists: an approval is never replaced');
END;

CREATE TRIGGER approvals_rowid_positive AFTER INSERT ON approvals
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'approvals rowid must be positive');
END;

CREATE TRIGGER signing_jobs_key_exists BEFORE INSERT ON signing_jobs
WHEN EXISTS (
  SELECT 1 FROM signing_jobs
  WHERE (tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id) OR rowid = NEW.rowid
)
BEGIN
  SELECT RAISE(ABORT, 'signing_jobs key exists: a reservation is never replaced');
END;

CREATE TRIGGER signing_jobs_rowid_positive AFTER INSERT ON signing_jobs
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'signing_jobs rowid must be positive');
END;

CREATE TRIGGER signing_jobs_rowid_key_fixed BEFORE UPDATE ON signing_jobs
WHEN NEW.rowid IS NOT OLD.rowid
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.envelope_id IS NOT OLD.envelope_id
BEGIN
  SELECT RAISE(ABORT, 'signing_jobs rowid and key never change');
END;
