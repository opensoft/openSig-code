-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0008 (T003, A-008 P03): DisposalRecord kind.
-- Conventions: see 0001.
--
-- Two writers produce DisposalRecords: retention (T029) and the orphan
-- collector for abandoned finalization-attempt blobs (T038). Only a
-- 'retention' record ends an envelope's retention; an 'orphan-collection'
-- record never does, so the retention run filters on kind. Every new record
-- must state its kind: there is no default, and an insert without one is
-- refused. Records written before this migration came from retention, the
-- only writer then, so they are backfilled as 'retention'.
--
-- The backfill briefly replaces the immutability trigger of 0006 with an
-- identical one, inside this migration's transaction.

ALTER TABLE disposal_records ADD COLUMN kind TEXT CHECK (kind IN ('retention', 'orphan-collection'));

DROP TRIGGER disposal_records_immutable_update;

UPDATE disposal_records SET kind = 'retention';

CREATE TRIGGER disposal_records_immutable_update BEFORE UPDATE ON disposal_records
BEGIN
  SELECT RAISE(ABORT, 'disposal_records rows are immutable');
END;

CREATE TRIGGER disposal_records_kind_required BEFORE INSERT ON disposal_records
WHEN NEW.kind IS NULL
BEGIN
  SELECT RAISE(ABORT, 'disposal_records.kind is required: retention or orphan-collection');
END;

CREATE INDEX disposal_records_kind ON disposal_records (tenant_id, kind, envelope_id);
