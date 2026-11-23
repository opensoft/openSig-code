-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0010 (T007; A-008 P04, A-010 rulings): freeze
-- recipients and field definitions once the envelope leaves draft, move the
-- envelope version only by exactly one on every change of state or content,
-- and enforce the envelope transition graph on every UPDATE that changes state
-- (data-model.md § Envelope states and § Transitions and races, item 1).
-- Inserts are not governed by the graph. Conventions: see 0001.
--
-- Every trigger here is an AFTER trigger. SQLite checks NOT NULL, CHECK and
-- UNIQUE before AFTER triggers run, so a write that breaks a T003 constraint
-- still fails with that constraint; a write that passes them and breaks a
-- rule below is then aborted, and the statement leaves no change.

-- The version moves only by exactly one. A change of state or of any content
-- column needs that step; only updated_at may change on its own.
CREATE TRIGGER envelopes_version_step AFTER UPDATE ON envelopes
WHEN NEW.version IS NOT OLD.version + 1 AND (
  NEW.version IS NOT OLD.version
  OR NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.id IS NOT OLD.id
  OR NEW.source_app IS NOT OLD.source_app
  OR NEW.source_record IS NOT OLD.source_record
  OR NEW.source_version IS NOT OLD.source_version
  OR NEW.state IS NOT OLD.state
  OR NEW.created_by_kind IS NOT OLD.created_by_kind
  OR NEW.created_by_ref IS NOT OLD.created_by_ref
  OR NEW.expires_at IS NOT OLD.expires_at
  OR NEW.recipients_count IS NOT OLD.recipients_count
  OR NEW.base_revision_id IS NOT OLD.base_revision_id
  OR NEW.manifest_digest IS NOT OLD.manifest_digest
  OR NEW.recipients_digest IS NOT OLD.recipients_digest
  OR NEW.approvals_complete IS NOT OLD.approvals_complete
  OR NEW.reissue_of IS NOT OLD.reissue_of
  OR NEW.reissued_as IS NOT OLD.reissued_as
  OR NEW.created_at IS NOT OLD.created_at
)
BEGIN
  SELECT RAISE(ABORT, 'envelopes version must be old + 1 on every change of state or content');
END;

-- The transition graph. completed, declined, expired and voided are terminal;
-- an update that keeps the state is not a transition.
CREATE TRIGGER envelopes_state_graph AFTER UPDATE OF state ON envelopes
WHEN NEW.state IS NOT OLD.state AND NOT (
  (OLD.state = 'draft' AND NEW.state IN ('prepared', 'voided', 'expired'))
  OR (OLD.state = 'prepared' AND NEW.state IN ('sent', 'voided', 'expired'))
  OR (OLD.state = 'sent' AND NEW.state IN ('in-progress', 'finalizing', 'declined', 'voided', 'expired'))
  OR (OLD.state = 'in-progress' AND NEW.state IN ('finalizing', 'declined', 'expired', 'voided'))
  OR (OLD.state = 'finalizing' AND NEW.state = 'completed')
)
BEGIN
  SELECT RAISE(ABORT, 'envelopes state transition is not in the state graph');
END;

-- Identity and origin never change; the frozen content never changes once the
-- envelope has left draft; reissued_as is recorded once.
CREATE TRIGGER envelopes_frozen_columns AFTER UPDATE ON envelopes
WHEN NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.id IS NOT OLD.id
  OR NEW.source_app IS NOT OLD.source_app
  OR NEW.source_record IS NOT OLD.source_record
  OR NEW.source_version IS NOT OLD.source_version
  OR NEW.created_by_kind IS NOT OLD.created_by_kind
  OR NEW.created_by_ref IS NOT OLD.created_by_ref
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.reissue_of IS NOT OLD.reissue_of
  OR (OLD.reissued_as IS NOT NULL AND NEW.reissued_as IS NOT OLD.reissued_as)
  OR (OLD.state <> 'draft' AND (
    NEW.expires_at IS NOT OLD.expires_at
    OR NEW.recipients_count IS NOT OLD.recipients_count
    OR NEW.base_revision_id IS NOT OLD.base_revision_id
    OR NEW.manifest_digest IS NOT OLD.manifest_digest
    OR NEW.recipients_digest IS NOT OLD.recipients_digest
  ))
BEGIN
  SELECT RAISE(ABORT, 'envelopes identity, origin and prepared content are frozen');
END;

-- Recipients: rows are added, removed or re-bound only while the envelope is a
-- draft. Status progress (status, invited_at, approved_at, approval_id,
-- updated_at) stays possible after draft.
CREATE TRIGGER recipients_frozen_insert AFTER INSERT ON recipients
WHEN (SELECT e.state FROM envelopes e WHERE e.tenant_id = NEW.tenant_id AND e.id = NEW.envelope_id) <> 'draft'
BEGIN
  SELECT RAISE(ABORT, 'recipients are frozen once the envelope leaves draft');
END;

CREATE TRIGGER recipients_frozen_delete AFTER DELETE ON recipients
WHEN (SELECT e.state FROM envelopes e WHERE e.tenant_id = OLD.tenant_id AND e.id = OLD.envelope_id) <> 'draft'
BEGIN
  SELECT RAISE(ABORT, 'recipients are frozen once the envelope leaves draft');
END;

CREATE TRIGGER recipients_frozen_binding AFTER UPDATE ON recipients
WHEN (
  NEW.tenant_id IS NOT OLD.tenant_id
  OR NEW.id IS NOT OLD.id
  OR NEW.envelope_id IS NOT OLD.envelope_id
  OR NEW.ordinal IS NOT OLD.ordinal
  OR NEW.email IS NOT OLD.email
  OR NEW.role IS NOT OLD.role
  OR NEW.created_at IS NOT OLD.created_at
) AND (
  (SELECT e.state FROM envelopes e WHERE e.tenant_id = OLD.tenant_id AND e.id = OLD.envelope_id) <> 'draft'
  OR (SELECT e.state FROM envelopes e WHERE e.tenant_id = NEW.tenant_id AND e.id = NEW.envelope_id) <> 'draft'
)
BEGIN
  SELECT RAISE(ABORT, 'recipients are frozen once the envelope leaves draft');
END;

-- Field definitions: no insert, update or delete once the envelope leaves draft.
CREATE TRIGGER field_definitions_frozen_insert AFTER INSERT ON field_definitions
WHEN (SELECT e.state FROM envelopes e WHERE e.tenant_id = NEW.tenant_id AND e.id = NEW.envelope_id) <> 'draft'
BEGIN
  SELECT RAISE(ABORT, 'field definitions are frozen once the envelope leaves draft');
END;

CREATE TRIGGER field_definitions_frozen_update AFTER UPDATE ON field_definitions
WHEN (SELECT e.state FROM envelopes e WHERE e.tenant_id = OLD.tenant_id AND e.id = OLD.envelope_id) <> 'draft'
  OR (SELECT e.state FROM envelopes e WHERE e.tenant_id = NEW.tenant_id AND e.id = NEW.envelope_id) <> 'draft'
BEGIN
  SELECT RAISE(ABORT, 'field definitions are frozen once the envelope leaves draft');
END;

CREATE TRIGGER field_definitions_frozen_delete AFTER DELETE ON field_definitions
WHEN (SELECT e.state FROM envelopes e WHERE e.tenant_id = OLD.tenant_id AND e.id = OLD.envelope_id) <> 'draft'
BEGIN
  SELECT RAISE(ABORT, 'field definitions are frozen once the envelope leaves draft');
END;
