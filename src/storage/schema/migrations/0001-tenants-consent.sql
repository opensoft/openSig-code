-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0001 (T003): Tenant and ConsentText.
--
-- Migrations are append-only. tests/storage/ pins the SHA-256 of every T003
-- migration file, so a schema change is a new numbered file, never an edit.
--
-- Column conventions used by every migration:
--   identifiers   TEXT matching ^[A-Za-z0-9_-]{16,64}$
--   digests       TEXT, lowercase hex SHA-256 (64 characters)
--   timestamps    TEXT, UTC, Date.prototype.toISOString() form
--                 (YYYY-MM-DDTHH:MM:SS.sssZ), so text order is time order;
--                 these are unsigned server times
--   tenant_id     on every row; child rows reference parents through
--                 composite (tenant_id, ...) foreign keys, so a row can never
--                 point at another tenant's row

CREATE TABLE tenants (
  tenant_id TEXT NOT NULL PRIMARY KEY
    CHECK (length(tenant_id) BETWEEN 16 AND 64 AND tenant_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  oidc_issuer TEXT NOT NULL CHECK (length(oidc_issuer) BETWEEN 1 AND 2048),
  oidc_audience TEXT NOT NULL CHECK (length(oidc_audience) BETWEEN 1 AND 2048),
  role_claim TEXT NOT NULL CHECK (length(role_claim) BETWEEN 1 AND 200),
  role_map_json TEXT NOT NULL CHECK (json_valid(role_map_json) AND json_type(role_map_json) = 'object'),
  principal_kind_claim TEXT NOT NULL CHECK (length(principal_kind_claim) BETWEEN 1 AND 200),
  principal_kind_map_json TEXT
    CHECK (json_valid(principal_kind_map_json) AND json_type(principal_kind_map_json) = 'object'),
  allowed_roles_json TEXT NOT NULL CHECK (json_valid(allowed_roles_json) AND json_type(allowed_roles_json) = 'array'),
  consent_text_id TEXT,
  -- NULL means retain: nothing is disposed while retention is unset.
  retention_json TEXT CHECK (json_valid(retention_json) AND json_type(retention_json) = 'object'),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  updated_at TEXT NOT NULL
    CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  CHECK (updated_at >= created_at),
  FOREIGN KEY (tenant_id, consent_text_id) REFERENCES consent_texts (tenant_id, id)
) STRICT;

CREATE TABLE consent_texts (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  version TEXT NOT NULL CHECK (length(version) BETWEEN 1 AND 40 AND version NOT GLOB '*[^a-z0-9.-]*'),
  locale TEXT NOT NULL CHECK (length(locale) BETWEEN 2 AND 35 AND locale NOT GLOB '*[^A-Za-z0-9-]*'),
  text TEXT NOT NULL CHECK (length(text) BETWEEN 1 AND 20000),
  text_digest TEXT NOT NULL CHECK (length(text_digest) = 64 AND text_digest NOT GLOB '*[^0-9a-f]*'),
  effective_from TEXT NOT NULL
    CHECK (effective_from GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, version, locale)
) STRICT;

-- A new wording is a new version: consent texts are never changed or removed.
CREATE TRIGGER consent_texts_immutable_update BEFORE UPDATE ON consent_texts
BEGIN
  SELECT RAISE(ABORT, 'consent_texts rows are immutable');
END;

CREATE TRIGGER consent_texts_immutable_delete BEFORE DELETE ON consent_texts
BEGIN
  SELECT RAISE(ABORT, 'consent_texts rows are immutable');
END;
