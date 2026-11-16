-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0011 (T007): the response body of an idempotency
-- record. Conventions: see 0001.
--
-- The same Idempotency-Key with the same request replays the original status
-- and body (contract parameter Idempotency-Key). 0004 kept only the body's
-- digest, from which the body cannot be rebuilt once the resource has moved
-- on. Each new record now also keeps the exact response bytes, the RFC 8785
-- form of the response body; response_body_digest stays their SHA-256, which
-- src/storage/repositories/idempotency.ts checks before replaying. Rows stay
-- immutable through the update trigger of 0004.

ALTER TABLE idempotency_records ADD COLUMN response_body BLOB
  CHECK (response_body IS NULL OR length(response_body) BETWEEN 2 AND 1048576);

CREATE TRIGGER idempotency_records_body_digest BEFORE INSERT ON idempotency_records
WHEN NEW.response_body IS NOT NULL AND NEW.response_body_digest IS NULL
BEGIN
  SELECT RAISE(ABORT, 'idempotency_records response_body needs its response_body_digest');
END;
