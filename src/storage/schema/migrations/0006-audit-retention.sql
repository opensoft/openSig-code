-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0006 (T003): AuditEvent, AuditCheckpoint and
-- DisposalRecord. Conventions: see 0001.
--
-- The audit chain is tamper-evident, not tamper-proof. These triggers make the
-- append path the only write path for a connection that keeps the schema; a
-- test that simulates tampering must drop them explicitly.

CREATE TABLE audit_events (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  seq INTEGER NOT NULL CHECK (seq >= 1),
  type TEXT NOT NULL CHECK (
    length(type) BETWEEN 2 AND 61 AND substr(type, 1, 1) BETWEEN 'a' AND 'z' AND type NOT GLOB '*[^a-z0-9_.-]*'
  ),
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('human-operator', 'service', 'recipient', 'system')),
  actor_ref TEXT NOT NULL CHECK (length(actor_ref) BETWEEN 1 AND 100),
  server_time TEXT NOT NULL
    CHECK (server_time GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  envelope_id TEXT,
  subject_digest TEXT CHECK (length(subject_digest) = 64 AND subject_digest NOT GLOB '*[^0-9a-f]*'),
  -- Redacted metadata: never capability values, codes, keys or PDF content.
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json) AND json_type(metadata_json) = 'object'),
  prev_digest TEXT CHECK (length(prev_digest) = 64 AND prev_digest NOT GLOB '*[^0-9a-f]*'),
  -- SHA-256 of the RFC 8785 event without event_digest.
  event_digest TEXT NOT NULL CHECK (length(event_digest) = 64 AND event_digest NOT GLOB '*[^0-9a-f]*'),
  PRIMARY KEY (tenant_id, seq),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id),
  CHECK (seq = 1 OR prev_digest IS NOT NULL)
) STRICT;

CREATE INDEX audit_events_envelope ON audit_events (tenant_id, envelope_id, seq);

-- Each tenant chain grows by exactly one event, linked to the previous digest.
CREATE TRIGGER audit_events_chain BEFORE INSERT ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events seq must extend the tenant chain by one')
  WHERE NEW.seq <> (SELECT coalesce(max(seq), 0) + 1 FROM audit_events WHERE tenant_id = NEW.tenant_id);
  SELECT RAISE(ABORT, 'audit_events prev_digest must equal the previous event_digest')
  WHERE NEW.seq > 1 AND NEW.prev_digest IS NOT (
    SELECT event_digest FROM audit_events WHERE tenant_id = NEW.tenant_id AND seq = NEW.seq - 1
  );
END;

CREATE TRIGGER audit_events_append_only_update BEFORE UPDATE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events rows are append-only');
END;

CREATE TRIGGER audit_events_append_only_delete BEFORE DELETE ON audit_events
BEGIN
  SELECT RAISE(ABORT, 'audit_events rows are append-only');
END;

CREATE TABLE audit_checkpoints (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  seq INTEGER NOT NULL CHECK (seq >= 1),
  kind TEXT NOT NULL CHECK (kind IN ('cadence', 'completion')),
  event_digest TEXT NOT NULL CHECK (length(event_digest) = 64 AND event_digest NOT GLOB '*[^0-9a-f]*'),
  envelope_id TEXT,
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  FOREIGN KEY (tenant_id, seq) REFERENCES audit_events (tenant_id, seq),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id),
  CHECK ((kind = 'completion') = (envelope_id IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX audit_checkpoints_cadence ON audit_checkpoints (tenant_id, seq) WHERE kind = 'cadence';
CREATE UNIQUE INDEX audit_checkpoints_completion ON audit_checkpoints (tenant_id, envelope_id) WHERE kind = 'completion';

-- A checkpoint records the digest the chain actually holds at its seq.
CREATE TRIGGER audit_checkpoints_digest BEFORE INSERT ON audit_checkpoints
WHEN NEW.event_digest IS NOT (
  SELECT event_digest FROM audit_events WHERE tenant_id = NEW.tenant_id AND seq = NEW.seq
)
BEGIN
  SELECT RAISE(ABORT, 'audit_checkpoints event_digest must equal the chain digest at seq');
END;

CREATE TRIGGER audit_checkpoints_append_only_update BEFORE UPDATE ON audit_checkpoints
BEGIN
  SELECT RAISE(ABORT, 'audit_checkpoints rows are append-only');
END;

CREATE TRIGGER audit_checkpoints_append_only_delete BEFORE DELETE ON audit_checkpoints
BEGIN
  SELECT RAISE(ABORT, 'audit_checkpoints rows are append-only');
END;

CREATE TABLE disposal_records (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  retained_artifact_digests_json TEXT NOT NULL
    CHECK (json_valid(retained_artifact_digests_json) AND json_type(retained_artifact_digests_json) = 'array'),
  disposed_blob_refs_json TEXT NOT NULL
    CHECK (json_valid(disposed_blob_refs_json) AND json_type(disposed_blob_refs_json) = 'array'),
  policy_ref TEXT NOT NULL CHECK (length(policy_ref) BETWEEN 1 AND 200),
  server_time TEXT NOT NULL
    CHECK (server_time GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id)
) STRICT;

CREATE INDEX disposal_records_envelope ON disposal_records (tenant_id, envelope_id);

CREATE TRIGGER disposal_records_immutable_update BEFORE UPDATE ON disposal_records
BEGIN
  SELECT RAISE(ABORT, 'disposal_records rows are immutable');
END;

CREATE TRIGGER disposal_records_immutable_delete BEFORE DELETE ON disposal_records
BEGIN
  SELECT RAISE(ABORT, 'disposal_records rows are immutable');
END;
