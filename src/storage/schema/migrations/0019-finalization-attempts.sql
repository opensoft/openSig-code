-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0019 (T038; A-010 request #59, rulings (2), (3)
-- and (10)): the approval-evidence digest of a final artifact, the
-- FinalizationAttemptBlob table, and no-replace guards. Conventions: see 0001.
--
-- (2) final_artifacts.approval_evidence_digest (data-model.md § Entities,
--     FinalArtifact; FEN-07). ALTER TABLE cannot add a NOT NULL column without
--     a default, so the column is nullable and a BEFORE INSERT trigger
--     requires 64 lowercase hex digits on every new row. A BEFORE UPDATE OF
--     trigger makes it immutable like 0005's columns. No artifact row exists
--     before T038, so nothing is backfilled. 0005's own triggers are left
--     byte-identical: these are new triggers beside them.
-- (3) finalization_attempt_blobs (data-model.md § Entities,
--     FinalizationAttemptBlob): one row per blob an attempt writes, recorded
--     in its own transaction before the blob write. Roles: composed, sealed,
--     evidence and package. Rows are immutable: never updated, never deleted.
-- (10) No-replace guards (FEN-09), in the 0014, 0015 and 0018 pattern. A
--     REPLACE conflict clause deletes the row holding a key without firing
--     its delete trigger while recursive triggers are off (the default; no
--     code enables them), so 0005's and 0007's immutability triggers do not
--     stop an INSERT OR REPLACE. Each guarded table gets:
--     - <table>_key_exists (BEFORE INSERT): an insert whose unique key or
--       rowid already exists is refused before conflict resolution, whatever
--       its conflict clause. NEW.rowid is undefined (-1 in practice) when an
--       insert names none, and no stored rowid is 0 or less, so an ordinary
--       insert proceeds;
--     - <table>_rowid_positive (AFTER INSERT): a stored rowid of 0 or less is
--       refused;
--     - <table>_rowid_key_fixed (BEFORE UPDATE), where an update is otherwise
--       allowed: the rowid and the key never change, so UPDATE OR REPLACE can
--       take neither another row's rowid nor its key. verification_reports and
--       finalization_attempt_blobs refuse every update already.
--     A plain duplicate insert therefore surfaces as a trigger constraint
--     rather than a uniqueness or primary-key constraint; the store reports
--     either as storage_constraint.

-- (2) -------------------------------------------------------------------------

ALTER TABLE final_artifacts ADD COLUMN approval_evidence_digest TEXT
  CHECK (length(approval_evidence_digest) = 64 AND approval_evidence_digest NOT GLOB '*[^0-9a-f]*');

CREATE TRIGGER final_artifacts_evidence_required BEFORE INSERT ON final_artifacts
WHEN NEW.approval_evidence_digest IS NULL
  OR length(NEW.approval_evidence_digest) <> 64
  OR NEW.approval_evidence_digest GLOB '*[^0-9a-f]*'
BEGIN
  SELECT RAISE(ABORT, 'final_artifacts approval_evidence_digest must be 64 lowercase hex digits');
END;

CREATE TRIGGER final_artifacts_evidence_immutable BEFORE UPDATE OF approval_evidence_digest ON final_artifacts
BEGIN
  SELECT RAISE(ABORT, 'final_artifacts rows are immutable');
END;

-- (3) -------------------------------------------------------------------------

CREATE TABLE finalization_attempt_blobs (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  envelope_id TEXT NOT NULL,
  -- The attempt: its fencing token.
  fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
  blob_ref TEXT NOT NULL CHECK (
    substr(blob_ref, 1, length(tenant_id) + 16) = 'tenants/' || tenant_id || '/sha256/'
    AND length(blob_ref) = length(tenant_id) + 80
    AND substr(blob_ref, length(tenant_id) + 17) NOT GLOB '*[^0-9a-f]*'
  ),
  role TEXT NOT NULL CHECK (role IN ('composed', 'sealed', 'evidence', 'package')),
  recorded_at TEXT NOT NULL
    CHECK (recorded_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, envelope_id, fencing_token, blob_ref),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id)
) STRICT;

-- The reference-protection lookup by ref (T029's predicate, request #59 (7)).
CREATE INDEX finalization_attempt_blobs_ref ON finalization_attempt_blobs (tenant_id, blob_ref);

CREATE TRIGGER finalization_attempt_blobs_immutable_update BEFORE UPDATE ON finalization_attempt_blobs
BEGIN
  SELECT RAISE(ABORT, 'finalization_attempt_blobs rows are immutable');
END;

CREATE TRIGGER finalization_attempt_blobs_immutable_delete BEFORE DELETE ON finalization_attempt_blobs
BEGIN
  SELECT RAISE(ABORT, 'finalization_attempt_blobs rows are immutable');
END;

-- (10) ------------------------------------------------------------------------

CREATE TRIGGER final_artifacts_key_exists BEFORE INSERT ON final_artifacts
WHEN EXISTS (
  SELECT 1 FROM final_artifacts
  WHERE (tenant_id = NEW.tenant_id AND (artifact_id = NEW.artifact_id OR envelope_id = NEW.envelope_id))
    OR rowid = NEW.rowid
)
BEGIN
  SELECT RAISE(ABORT, 'final_artifacts key exists: a final artifact is never replaced');
END;

CREATE TRIGGER final_artifacts_rowid_positive AFTER INSERT ON final_artifacts
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'final_artifacts rowid must be positive');
END;

-- 0005 refuses updates of every identity column but not of the rowid, and
-- still allows the one package update.
CREATE TRIGGER final_artifacts_rowid_key_fixed BEFORE UPDATE ON final_artifacts
WHEN NEW.rowid IS NOT OLD.rowid
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.artifact_id IS NOT OLD.artifact_id
  OR NEW.envelope_id IS NOT OLD.envelope_id
BEGIN
  SELECT RAISE(ABORT, 'final_artifacts rowid and key never change');
END;

CREATE TRIGGER verification_reports_key_exists BEFORE INSERT ON verification_reports
WHEN EXISTS (
  SELECT 1 FROM verification_reports
  WHERE (tenant_id = NEW.tenant_id AND id = NEW.id) OR rowid = NEW.rowid
)
BEGIN
  SELECT RAISE(ABORT, 'verification_reports key exists: a verification report is never replaced');
END;

CREATE TRIGGER verification_reports_rowid_positive AFTER INSERT ON verification_reports
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'verification_reports rowid must be positive');
END;

-- outbox_events' unique keys: event_id (across tenants), (tenant_id,
-- event_id), and the one envelope.completed event per envelope (0007's
-- partial unique index), whose REPLACE would delete the published event.
CREATE TRIGGER outbox_events_key_exists BEFORE INSERT ON outbox_events
WHEN EXISTS (
  SELECT 1 FROM outbox_events
  WHERE event_id = NEW.event_id
    OR rowid = NEW.rowid
    OR (NEW.type = 'envelope.completed' AND type = 'envelope.completed' AND tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id)
)
BEGIN
  SELECT RAISE(ABORT, 'outbox_events key exists: an outbox event is never replaced');
END;

CREATE TRIGGER outbox_events_rowid_positive AFTER INSERT ON outbox_events
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'outbox_events rowid must be positive');
END;

-- 0007 refuses updates of the identity and payload columns; delivery updates
-- (attempts, last_attempt_at, next_attempt_at, acknowledged_at,
-- last_error_code) stay allowed.
CREATE TRIGGER outbox_events_rowid_key_fixed BEFORE UPDATE ON outbox_events
WHEN NEW.rowid IS NOT OLD.rowid
BEGIN
  SELECT RAISE(ABORT, 'outbox_events rowid never changes');
END;

CREATE TRIGGER finalization_attempt_blobs_key_exists BEFORE INSERT ON finalization_attempt_blobs
WHEN EXISTS (
  SELECT 1 FROM finalization_attempt_blobs
  WHERE (tenant_id = NEW.tenant_id AND envelope_id = NEW.envelope_id AND fencing_token = NEW.fencing_token AND blob_ref = NEW.blob_ref)
    OR rowid = NEW.rowid
)
BEGIN
  SELECT RAISE(ABORT, 'finalization_attempt_blobs key exists: an attempt record is never replaced');
END;

CREATE TRIGGER finalization_attempt_blobs_rowid_positive AFTER INSERT ON finalization_attempt_blobs
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'finalization_attempt_blobs rowid must be positive');
END;
