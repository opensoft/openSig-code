-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0002 (T003): Envelope, DocumentRevision,
-- Recipient, FieldDefinition and FieldManifest. Conventions: see 0001.

CREATE TABLE envelopes (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  source_app TEXT NOT NULL CHECK (source_app IN ('hermes', 'openchart', 'openpractice', 'manual')),
  source_record TEXT NOT NULL CHECK (length(source_record) BETWEEN 1 AND 200),
  source_version TEXT NOT NULL CHECK (length(source_version) BETWEEN 1 AND 100),
  state TEXT NOT NULL CHECK (state IN (
    'draft', 'prepared', 'sent', 'in-progress', 'finalizing', 'completed', 'declined', 'expired', 'voided'
  )),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_by_kind TEXT NOT NULL CHECK (created_by_kind IN ('human-operator', 'service')),
  created_by_ref TEXT NOT NULL CHECK (length(created_by_ref) BETWEEN 1 AND 100),
  expires_at TEXT NOT NULL
    CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  recipients_count INTEGER NOT NULL CHECK (recipients_count BETWEEN 1 AND 2),
  base_revision_id TEXT,
  manifest_digest TEXT CHECK (length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  recipients_digest TEXT CHECK (length(recipients_digest) = 64 AND recipients_digest NOT GLOB '*[^0-9a-f]*'),
  approvals_complete INTEGER NOT NULL DEFAULT 0 CHECK (approvals_complete IN (0, 1)),
  reissue_of TEXT,
  reissued_as TEXT,
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  updated_at TEXT NOT NULL
    CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, id),
  -- The base revision must be a revision of this same envelope.
  FOREIGN KEY (tenant_id, id, base_revision_id) REFERENCES document_revisions (tenant_id, envelope_id, id),
  FOREIGN KEY (tenant_id, reissue_of) REFERENCES envelopes (tenant_id, id),
  FOREIGN KEY (tenant_id, reissued_as) REFERENCES envelopes (tenant_id, id),
  CHECK (expires_at > created_at),
  CHECK (updated_at >= created_at),
  CHECK (reissue_of IS NULL OR reissue_of <> id),
  CHECK (reissued_as IS NULL OR reissued_as <> id),
  -- "Fully approved" is approvals_complete = 1, which holds exactly in
  -- finalizing and completed.
  CHECK ((approvals_complete = 1) = (state IN ('finalizing', 'completed'))),
  -- Prepare freezes the document, the field manifest and the recipients.
  CHECK (
    state NOT IN ('prepared', 'sent', 'in-progress', 'finalizing', 'completed')
    OR (base_revision_id IS NOT NULL AND manifest_digest IS NOT NULL AND recipients_digest IS NOT NULL)
  )
) STRICT;

CREATE INDEX envelopes_state ON envelopes (tenant_id, state);

CREATE TABLE document_revisions (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  -- content_digest is the API's document_digest.
  content_digest TEXT NOT NULL CHECK (length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'),
  -- The tenant-namespaced, content-addressed blob key of exactly these bytes.
  blob_ref TEXT NOT NULL CHECK (blob_ref = 'tenants/' || tenant_id || '/sha256/' || content_digest),
  bytes INTEGER NOT NULL CHECK (bytes BETWEEN 1 AND 10485760),
  pages INTEGER NOT NULL CHECK (pages BETWEEN 1 AND 50),
  page_geometry_json TEXT NOT NULL CHECK (json_valid(page_geometry_json) AND json_type(page_geometry_json) = 'array'),
  parse_report_json TEXT NOT NULL CHECK (json_valid(parse_report_json) AND json_type(parse_report_json) = 'object'),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  frozen_at TEXT
    CHECK (frozen_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, envelope_id, id),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id),
  CHECK (frozen_at IS NULL OR frozen_at >= created_at)
) STRICT;

-- A revision is immutable once prepare has frozen it.
CREATE TRIGGER document_revisions_frozen_update BEFORE UPDATE ON document_revisions
WHEN OLD.frozen_at IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'document_revisions rows are immutable after prepare');
END;

CREATE TRIGGER document_revisions_frozen_delete BEFORE DELETE ON document_revisions
WHEN OLD.frozen_at IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'document_revisions rows are immutable after prepare');
END;

CREATE TABLE recipients (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK (ordinal IN (1, 2)),
  email TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 254 AND instr(email, '@') > 1),
  role TEXT NOT NULL CHECK (length(role) BETWEEN 1 AND 80),
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'invited', 'approved', 'declined', 'expired', 'revoked')),
  invited_at TEXT
    CHECK (invited_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  approved_at TEXT
    CHECK (approved_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  approval_id TEXT,
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  updated_at TEXT NOT NULL
    CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, envelope_id, ordinal),
  UNIQUE (tenant_id, envelope_id, id),
  UNIQUE (tenant_id, envelope_id, id, ordinal),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id),
  -- The recorded approval must be this recipient's own approval.
  FOREIGN KEY (tenant_id, envelope_id, id, approval_id) REFERENCES approvals (tenant_id, envelope_id, recipient_id, id),
  CHECK (updated_at >= created_at),
  CHECK (status <> 'approved' OR (approved_at IS NOT NULL AND approval_id IS NOT NULL))
) STRICT;

CREATE TABLE field_definitions (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  envelope_id TEXT NOT NULL,
  key TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 40 AND key NOT GLOB '*[^a-z0-9_-]*'),
  revision_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  recipient_ordinal INTEGER NOT NULL CHECK (recipient_ordinal IN (1, 2)),
  page INTEGER NOT NULL CHECK (page BETWEEN 1 AND 50),
  type TEXT NOT NULL CHECK (type IN ('signature', 'date')),
  -- Normalized to the displayed page: origin top-left, y downward, inside [0,1].
  rect_x REAL NOT NULL,
  rect_y REAL NOT NULL,
  rect_width REAL NOT NULL,
  rect_height REAL NOT NULL,
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, envelope_id, key),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id),
  FOREIGN KEY (tenant_id, envelope_id, revision_id) REFERENCES document_revisions (tenant_id, envelope_id, id),
  FOREIGN KEY (tenant_id, envelope_id, recipient_id, recipient_ordinal)
    REFERENCES recipients (tenant_id, envelope_id, id, ordinal),
  CHECK (
    rect_x >= 0 AND rect_y >= 0 AND rect_width > 0 AND rect_height > 0
    AND rect_x + rect_width <= 1 AND rect_y + rect_height <= 1
  )
) STRICT;

CREATE TABLE field_manifests (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  envelope_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  schema TEXT NOT NULL CHECK (length(schema) BETWEEN 1 AND 100),
  -- SHA-256 of canonical_bytes, the RFC 8785 form frozen at prepare.
  manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) BETWEEN 2 AND 1048576),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, envelope_id),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id),
  FOREIGN KEY (tenant_id, envelope_id, revision_id) REFERENCES document_revisions (tenant_id, envelope_id, id)
) STRICT;

CREATE TRIGGER field_manifests_immutable_update BEFORE UPDATE ON field_manifests
BEGIN
  SELECT RAISE(ABORT, 'field_manifests rows are immutable');
END;

CREATE TRIGGER field_manifests_immutable_delete BEFORE DELETE ON field_manifests
BEGIN
  SELECT RAISE(ABORT, 'field_manifests rows are immutable');
END;
