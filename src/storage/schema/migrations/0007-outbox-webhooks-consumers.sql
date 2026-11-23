-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0007 (T003): OutboxEvent, WebhookRegistration,
-- WebhookKey and ConsumerAttachment. Conventions: see 0001.

CREATE TABLE outbox_events (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  -- Stable across delivery retries.
  event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) BETWEEN 16 AND 64 AND event_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  envelope_version INTEGER NOT NULL CHECK (envelope_version >= 1),
  type TEXT NOT NULL CHECK (
    length(type) BETWEEN 2 AND 61 AND substr(type, 1, 1) BETWEEN 'a' AND 'z' AND type NOT GLOB '*[^a-z0-9_.-]*'
  ),
  schema_version TEXT NOT NULL CHECK (length(schema_version) BETWEEN 1 AND 20),
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json) AND json_type(payload_json) = 'object'),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_attempt_at TEXT
    CHECK (last_attempt_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  next_attempt_at TEXT
    CHECK (next_attempt_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  acknowledged_at TEXT
    CHECK (acknowledged_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  last_error_code TEXT CHECK (length(last_error_code) BETWEEN 1 AND 64 AND last_error_code NOT GLOB '*[^a-z0-9_.-]*'),
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id)
) STRICT;

CREATE INDEX outbox_events_pending ON outbox_events (tenant_id, acknowledged_at, next_attempt_at);

-- Completion publishes exactly one event per envelope.
CREATE UNIQUE INDEX outbox_events_one_completion ON outbox_events (tenant_id, envelope_id)
  WHERE type = 'envelope.completed';

CREATE TRIGGER outbox_events_identity BEFORE UPDATE OF
  tenant_id, event_id, envelope_id, envelope_version, type, schema_version, payload_json, created_at
ON outbox_events
BEGIN
  SELECT RAISE(ABORT, 'outbox_events identity and payload are immutable');
END;

CREATE TRIGGER outbox_events_attempts_forward BEFORE UPDATE OF attempts ON outbox_events
WHEN NEW.attempts < OLD.attempts
BEGIN
  SELECT RAISE(ABORT, 'outbox_events attempts never move backward');
END;

CREATE TRIGGER outbox_events_immutable_delete BEFORE DELETE ON outbox_events
BEGIN
  SELECT RAISE(ABORT, 'outbox_events rows are never deleted');
END;

CREATE TABLE webhook_registrations (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  url TEXT NOT NULL CHECK (length(url) BETWEEN 9 AND 2048 AND substr(url, 1, 8) = 'https://'),
  event_types_json TEXT NOT NULL CHECK (json_valid(event_types_json) AND json_type(event_types_json) = 'array'),
  description TEXT CHECK (length(description) <= 200),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_by_ref TEXT NOT NULL CHECK (length(created_by_ref) BETWEEN 1 AND 100),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  updated_at TEXT NOT NULL
    CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, id),
  CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE webhook_keys (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 16 AND 64 AND key_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  registration_id TEXT NOT NULL,
  -- The secret encrypted under a server key loaded from a 0600 file; the
  -- plaintext is shown once and never stored.
  secret_ciphertext BLOB NOT NULL CHECK (length(secret_ciphertext) BETWEEN 16 AND 1024),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  expires_at TEXT
    CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  revoked_at TEXT
    CHECK (revoked_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, key_id),
  FOREIGN KEY (tenant_id, registration_id) REFERENCES webhook_registrations (tenant_id, id),
  CHECK (expires_at IS NULL OR expires_at > created_at)
) STRICT;

CREATE INDEX webhook_keys_registration ON webhook_keys (tenant_id, registration_id);

-- At most 2 active keys per registration, judged at the new key's created_at.
CREATE TRIGGER webhook_keys_active_limit BEFORE INSERT ON webhook_keys
WHEN (
  SELECT count(*) FROM webhook_keys k
  WHERE k.tenant_id = NEW.tenant_id AND k.registration_id = NEW.registration_id
    AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > NEW.created_at)
) >= 2
BEGIN
  SELECT RAISE(ABORT, 'webhook_keys allows at most 2 active keys per registration');
END;

CREATE TRIGGER webhook_keys_bound_columns BEFORE UPDATE OF
  tenant_id, key_id, registration_id, secret_ciphertext, created_at
ON webhook_keys
BEGIN
  SELECT RAISE(ABORT, 'webhook_keys binding columns are immutable');
END;

CREATE TRIGGER webhook_keys_revocation_final BEFORE UPDATE OF revoked_at ON webhook_keys
WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at
BEGIN
  SELECT RAISE(ABORT, 'webhook_keys revocation is final');
END;

CREATE TABLE consumer_attachments (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  consumer TEXT NOT NULL CHECK (consumer IN ('openchart', 'openpractice')),
  source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 200),
  source_version TEXT NOT NULL CHECK (length(source_version) BETWEEN 1 AND 100),
  envelope_id TEXT NOT NULL CHECK (length(envelope_id) BETWEEN 16 AND 64 AND envelope_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  artifact_id TEXT NOT NULL CHECK (length(artifact_id) BETWEEN 16 AND 64 AND artifact_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64 AND artifact_digest NOT GLOB '*[^0-9a-f]*'),
  attached_at TEXT NOT NULL
    CHECK (attached_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  -- A duplicate attachment is a no-op, never a second row.
  PRIMARY KEY (tenant_id, consumer, source_id, source_version, artifact_id)
) STRICT;
