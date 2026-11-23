-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0017 (T010): the receipt of each approval.
-- Conventions: see 0001.
--
-- approveAsHuman answers an exact retry with the original receipt and a changed
-- retry with 409 (contract Approval and ApprovalReceipt;
-- contracts/sessions-events-adapters.md § Recipient ceremony). The receipt
-- carries the envelope version and state the approval wrote, which the
-- approvals row of 0003 does not keep and which move on afterwards, so the
-- receipt's exact bytes are kept here, beside the SHA-256 of the request that
-- produced them (src/domain/approval/record.ts, approvalRequestDigest). A row
-- is written in the approval's own transaction, with the approval, the
-- envelope's compare-and-set and any finalization reservation. These rows are
-- part of the approval evidence, so they are never changed or removed.
--
-- approval_receipts is a rowid table with text keys, like the stored evidence
-- of 0015 and 0016, and resists the same routes (A-010 rows REPLACE-ENV,
-- ROWID-ENV and ROWID-CER):
-- - approval_receipts_key_exists (BEFORE INSERT): an insert whose key
--   (tenant_id, approval_id), whose recipient (tenant_id, recipient_id) or
--   whose rowid already exists is refused before conflict resolution, whatever
--   its conflict clause, so INSERT OR REPLACE can replace no receipt by key and
--   none through its hidden rowid (spelled rowid, _rowid_ or oid). With
--   recursive triggers off, the default, the delete that REPLACE would perform
--   fires no delete trigger, which is why the insert itself is refused. When an
--   insert names no rowid, NEW.rowid is undefined in a BEFORE INSERT trigger
--   (-1 in practice); no stored rowid is 0 or less (next trigger), so that
--   value matches no row and an ordinary insert proceeds. A runtime that
--   changed it to a matching value would refuse ordinary inserts: that fails
--   closed, and the ordinary-insert test makes it fail loudly.
-- - approval_receipts_rowid_positive (AFTER INSERT, where NEW.rowid is the
--   stored value): a rowid of 0 or less is refused.
-- - approval_receipts_immutable_update (BEFORE UPDATE): every update is
--   refused before conflict resolution, so neither a column, the key, nor the
--   rowid changes, and UPDATE OR REPLACE can take no other row's key or rowid.
-- - approval_receipts_immutable_delete (BEFORE DELETE): a plain delete is
--   refused.
-- A duplicate key therefore surfaces as a trigger constraint, and the app
-- reports storage_constraint. The foreign key binds each receipt to its own
-- approval: the same tenant, envelope, recipient and approval id.

CREATE TABLE approval_receipts (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  approval_id TEXT NOT NULL CHECK (length(approval_id) BETWEEN 16 AND 64 AND approval_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  -- SHA-256 of the RFC 8785 form of the checked request (recipient included).
  request_digest TEXT NOT NULL CHECK (length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
  -- The exact RFC 8785 bytes of the ApprovalReceipt the recipient received.
  receipt_body BLOB NOT NULL CHECK (typeof(receipt_body) = 'blob' AND length(receipt_body) BETWEEN 2 AND 16384),
  -- SHA-256 of receipt_body, checked before a replay.
  receipt_digest TEXT NOT NULL CHECK (length(receipt_digest) = 64 AND receipt_digest NOT GLOB '*[^0-9a-f]*'),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, approval_id),
  UNIQUE (tenant_id, recipient_id),
  FOREIGN KEY (tenant_id, envelope_id, recipient_id, approval_id) REFERENCES approvals (tenant_id, envelope_id, recipient_id, id)
) STRICT;

CREATE TRIGGER approval_receipts_key_exists BEFORE INSERT ON approval_receipts
WHEN EXISTS (
  SELECT 1 FROM approval_receipts
  WHERE (tenant_id = NEW.tenant_id AND (approval_id = NEW.approval_id OR recipient_id = NEW.recipient_id))
    OR rowid = NEW.rowid
)
BEGIN
  SELECT RAISE(ABORT, 'approval_receipts key exists: a receipt is never replaced');
END;

CREATE TRIGGER approval_receipts_rowid_positive AFTER INSERT ON approval_receipts
WHEN NEW.rowid <= 0
BEGIN
  SELECT RAISE(ABORT, 'approval_receipts rowid must be positive');
END;

CREATE TRIGGER approval_receipts_immutable_update BEFORE UPDATE ON approval_receipts
BEGIN
  SELECT RAISE(ABORT, 'approval_receipts rows are immutable');
END;

CREATE TRIGGER approval_receipts_immutable_delete BEFORE DELETE ON approval_receipts
BEGIN
  SELECT RAISE(ABORT, 'approval_receipts rows are immutable');
END;
