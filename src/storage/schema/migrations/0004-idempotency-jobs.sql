-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0004 (T003): IdempotencyRecord and SigningJob.
-- Conventions: see 0001.

CREATE TABLE idempotency_records (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  route TEXT NOT NULL CHECK (length(route) BETWEEN 1 AND 100 AND route NOT GLOB '*[^A-Za-z0-9_.:/{}-]*'),
  principal_kind TEXT NOT NULL CHECK (principal_kind IN ('human-operator', 'service')),
  principal_ref TEXT NOT NULL CHECK (length(principal_ref) BETWEEN 1 AND 100),
  key TEXT NOT NULL CHECK (length(key) BETWEEN 16 AND 128 AND key NOT GLOB '*[^A-Za-z0-9_-]*'),
  request_digest TEXT NOT NULL CHECK (length(request_digest) = 64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
  response_status INTEGER NOT NULL CHECK (response_status BETWEEN 100 AND 599),
  response_body_digest TEXT
    CHECK (length(response_body_digest) = 64 AND response_body_digest NOT GLOB '*[^0-9a-f]*'),
  -- The resource the original request created or changed (for example the
  -- envelope of createEnvelope), so a replay can return the original result.
  resource_id TEXT CHECK (length(resource_id) BETWEEN 16 AND 64 AND resource_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, route, principal_ref, key)
) STRICT;

CREATE TRIGGER idempotency_records_immutable_update BEFORE UPDATE ON idempotency_records
BEGIN
  SELECT RAISE(ABORT, 'idempotency_records rows are immutable');
END;

CREATE TABLE signing_jobs (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  envelope_id TEXT NOT NULL,
  reserved_version INTEGER NOT NULL CHECK (reserved_version >= 1),
  status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'retryable', 'failed', 'succeeded')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
  lease_owner TEXT CHECK (length(lease_owner) BETWEEN 1 AND 100),
  lease_expires_at TEXT
    CHECK (lease_expires_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  -- The attempt_count at lease grant.
  fencing_token INTEGER,
  retry_at TEXT
    CHECK (retry_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  -- An error code only: never a secret, key material or a stack trace.
  last_error_code TEXT CHECK (length(last_error_code) BETWEEN 1 AND 64 AND last_error_code NOT GLOB '*[^a-z0-9_.-]*'),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  updated_at TEXT NOT NULL
    CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, envelope_id),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id),
  CHECK (attempt_count <= max_attempts),
  CHECK (fencing_token IS NULL OR (fencing_token >= 1 AND fencing_token <= attempt_count)),
  CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL)),
  CHECK (status <> 'running' OR (lease_owner IS NOT NULL AND fencing_token IS NOT NULL)),
  CHECK (updated_at >= created_at)
) STRICT;

CREATE INDEX signing_jobs_status ON signing_jobs (tenant_id, status, retry_at);

-- Attempts and fencing tokens only move forward, and the reservation is fixed.
CREATE TRIGGER signing_jobs_monotonic BEFORE UPDATE ON signing_jobs
WHEN NEW.attempt_count < OLD.attempt_count
  OR (OLD.fencing_token IS NOT NULL AND (NEW.fencing_token IS NULL OR NEW.fencing_token < OLD.fencing_token))
  OR NEW.reserved_version IS NOT OLD.reserved_version
  OR NEW.envelope_id IS NOT OLD.envelope_id
  OR NEW.tenant_id IS NOT OLD.tenant_id
BEGIN
  SELECT RAISE(ABORT, 'signing_jobs attempts, fencing tokens and reservation never move backward');
END;

CREATE TRIGGER signing_jobs_immutable_delete BEFORE DELETE ON signing_jobs
BEGIN
  SELECT RAISE(ABORT, 'signing_jobs rows are never deleted');
END;
