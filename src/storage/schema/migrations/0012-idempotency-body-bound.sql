-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0012 (T007; A-010 IDEMP-B1): the schema enforces
-- the 256 KiB bound of idempotency_records.response_body (data-model.md
-- § Entities, IdempotencyRecord), so no insert path can exceed it.
-- Conventions: see 0001.
--
-- 0011 bounds the column at 1 MiB; the idempotency repository refuses a body
-- over 262,144 bytes before it inserts (and fails the mutation with 500
-- internal). These triggers make the same bound hold for every writer, on
-- insert and on any update of the column. A NULL body (the withheld mode for
-- one-time secrets) passes. The bound counts bytes whatever the value's
-- storage class: length() counts characters for TEXT, so the value is cast to
-- BLOB before it is measured.

CREATE TRIGGER idempotency_records_body_bound_insert BEFORE INSERT ON idempotency_records
WHEN NEW.response_body IS NOT NULL AND length(CAST(NEW.response_body AS BLOB)) > 262144
BEGIN
  SELECT RAISE(ABORT, 'idempotency_records response_body exceeds 262144 bytes');
END;

CREATE TRIGGER idempotency_records_body_bound_update BEFORE UPDATE OF response_body ON idempotency_records
WHEN NEW.response_body IS NOT NULL AND length(CAST(NEW.response_body AS BLOB)) > 262144
BEGIN
  SELECT RAISE(ABORT, 'idempotency_records response_body exceeds 262144 bytes');
END;
