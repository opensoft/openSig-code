-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0003 (T003): SendConfirmation, Invitation,
-- Challenge, RecipientSession and Approval. Conventions: see 0001.
--
-- Capability values are never stored: invitations keep a token hash, sessions a
-- value hash, challenges an HMAC of the code.

CREATE TABLE send_confirmations (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  authorization_reference TEXT NOT NULL
    CHECK (length(authorization_reference) BETWEEN 16 AND 64 AND authorization_reference NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  envelope_version INTEGER NOT NULL CHECK (envelope_version >= 1),
  document_digest TEXT NOT NULL CHECK (length(document_digest) = 64 AND document_digest NOT GLOB '*[^0-9a-f]*'),
  manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  recipients_digest TEXT NOT NULL CHECK (length(recipients_digest) = 64 AND recipients_digest NOT GLOB '*[^0-9a-f]*'),
  -- Creation by a service principal is impossible.
  confirmed_by_kind TEXT NOT NULL CHECK (confirmed_by_kind = 'human-operator'),
  confirmed_by_ref TEXT NOT NULL CHECK (length(confirmed_by_ref) BETWEEN 1 AND 100),
  confirmed_at TEXT NOT NULL
    CHECK (confirmed_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  expires_at TEXT NOT NULL
    CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  consumed_at TEXT
    CHECK (consumed_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, authorization_reference),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id),
  CHECK (expires_at > confirmed_at)
) STRICT;

CREATE INDEX send_confirmations_envelope ON send_confirmations (tenant_id, envelope_id);

-- Single use: only consumed_at may change, and only once.
CREATE TRIGGER send_confirmations_bound_columns BEFORE UPDATE OF
  tenant_id, authorization_reference, envelope_id, envelope_version, document_digest, manifest_digest,
  recipients_digest, confirmed_by_kind, confirmed_by_ref, confirmed_at, expires_at
ON send_confirmations
BEGIN
  SELECT RAISE(ABORT, 'send_confirmations binding columns are immutable');
END;

CREATE TRIGGER send_confirmations_single_use BEFORE UPDATE OF consumed_at ON send_confirmations
WHEN OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
BEGIN
  SELECT RAISE(ABORT, 'send_confirmations are single use');
END;

CREATE TRIGGER send_confirmations_immutable_delete BEFORE DELETE ON send_confirmations
BEGIN
  SELECT RAISE(ABORT, 'send_confirmations rows are immutable');
END;

CREATE TABLE invitations (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  -- Hash of the raw token (at least 256 bits, mailed only). Unique across
  -- tenants because the presented token is what resolves the tenant.
  token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
  sent_at TEXT NOT NULL
    CHECK (sent_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  expires_at TEXT NOT NULL
    CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  revoked_at TEXT
    CHECK (revoked_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  cumulative_wrong_codes INTEGER NOT NULL DEFAULT 0 CHECK (cumulative_wrong_codes BETWEEN 0 AND 20),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, envelope_id, recipient_id) REFERENCES recipients (tenant_id, envelope_id, id),
  FOREIGN KEY (tenant_id, envelope_id, revision_id) REFERENCES document_revisions (tenant_id, envelope_id, id),
  CHECK (expires_at > sent_at),
  -- Twenty wrong codes revoke the invitation.
  CHECK (cumulative_wrong_codes < 20 OR revoked_at IS NOT NULL)
) STRICT;

CREATE INDEX invitations_recipient ON invitations (tenant_id, envelope_id, recipient_id);

CREATE TRIGGER invitations_bound_columns BEFORE UPDATE OF
  tenant_id, id, envelope_id, recipient_id, revision_id, manifest_digest, token_hash, sent_at
ON invitations
BEGIN
  SELECT RAISE(ABORT, 'invitations binding columns are immutable');
END;

CREATE TRIGGER invitations_revocation_final BEFORE UPDATE OF revoked_at ON invitations
WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at
BEGIN
  SELECT RAISE(ABORT, 'invitations revocation is final');
END;

CREATE TABLE challenges (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  invitation_id TEXT NOT NULL,
  -- HMAC-SHA256 of the code under a server key loaded from a 0600 file.
  code_hmac TEXT NOT NULL CHECK (length(code_hmac) = 64 AND code_hmac NOT GLOB '*[^0-9a-f]*'),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  expires_at TEXT NOT NULL
    CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  -- At most 5 attempts; the fifth wrong attempt locks the challenge.
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  consumed_at TEXT
    CHECK (consumed_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  superseded_at TEXT
    CHECK (superseded_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, invitation_id) REFERENCES invitations (tenant_id, id),
  CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX challenges_invitation ON challenges (tenant_id, invitation_id);

CREATE TRIGGER challenges_bound_columns BEFORE UPDATE OF
  tenant_id, id, invitation_id, code_hmac, created_at, expires_at
ON challenges
BEGIN
  SELECT RAISE(ABORT, 'challenges binding columns are immutable');
END;

CREATE TRIGGER challenges_single_use BEFORE UPDATE OF consumed_at ON challenges
WHEN OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS NOT OLD.consumed_at
BEGIN
  SELECT RAISE(ABORT, 'challenges are single use');
END;

CREATE TABLE recipient_sessions (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  -- Hash of the session value; the raw value exists only in the cookie.
  value_hash TEXT NOT NULL UNIQUE CHECK (length(value_hash) = 64 AND value_hash NOT GLOB '*[^0-9a-f]*'),
  envelope_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  csrf_secret BLOB CHECK (length(csrf_secret) BETWEEN 16 AND 64),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  last_seen_at TEXT NOT NULL
    CHECK (last_seen_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  revoked_at TEXT
    CHECK (revoked_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, envelope_id, recipient_id) REFERENCES recipients (tenant_id, envelope_id, id),
  FOREIGN KEY (tenant_id, envelope_id, revision_id) REFERENCES document_revisions (tenant_id, envelope_id, id),
  CHECK (last_seen_at >= created_at)
) STRICT;

CREATE INDEX recipient_sessions_recipient ON recipient_sessions (tenant_id, envelope_id, recipient_id);

CREATE TRIGGER recipient_sessions_bound_columns BEFORE UPDATE OF
  tenant_id, id, value_hash, envelope_id, recipient_id, revision_id, manifest_digest, created_at
ON recipient_sessions
BEGIN
  SELECT RAISE(ABORT, 'recipient_sessions binding columns are immutable');
END;

CREATE TRIGGER recipient_sessions_revocation_final BEFORE UPDATE OF revoked_at ON recipient_sessions
WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at
BEGIN
  SELECT RAISE(ABORT, 'recipient_sessions revocation is final');
END;

CREATE TABLE approvals (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  recipient_id TEXT NOT NULL,
  document_digest TEXT NOT NULL CHECK (length(document_digest) = 64 AND document_digest NOT GLOB '*[^0-9a-f]*'),
  manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
  prior_approval_digest TEXT
    CHECK (length(prior_approval_digest) = 64 AND prior_approval_digest NOT GLOB '*[^0-9a-f]*'),
  consent_text_id TEXT NOT NULL,
  consent_version TEXT NOT NULL,
  consent_text_digest TEXT NOT NULL,
  field_values_json TEXT NOT NULL CHECK (json_valid(field_values_json) AND json_type(field_values_json) = 'array'),
  field_values_digest TEXT NOT NULL
    CHECK (length(field_values_digest) = 64 AND field_values_digest NOT GLOB '*[^0-9a-f]*'),
  assurance_method TEXT NOT NULL CHECK (assurance_method = 'mailbox-challenge'),
  assurance_level TEXT NOT NULL CHECK (assurance_level = 'mailbox-control'),
  server_time TEXT NOT NULL
    CHECK (server_time GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  -- SHA-256 of the RFC 8785 record without approval_digest.
  approval_digest TEXT NOT NULL CHECK (length(approval_digest) = 64 AND approval_digest NOT GLOB '*[^0-9a-f]*'),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, recipient_id),
  UNIQUE (tenant_id, envelope_id, recipient_id, id),
  FOREIGN KEY (tenant_id, envelope_id, recipient_id) REFERENCES recipients (tenant_id, envelope_id, id),
  FOREIGN KEY (tenant_id, consent_text_id) REFERENCES consent_texts (tenant_id, id)
) STRICT;

-- The stored consent version and digest must be those of the referenced text.
CREATE TRIGGER approvals_consent_binding BEFORE INSERT ON approvals
WHEN NOT EXISTS (
  SELECT 1 FROM consent_texts c
  WHERE c.tenant_id = NEW.tenant_id AND c.id = NEW.consent_text_id
    AND c.version = NEW.consent_version AND c.text_digest = NEW.consent_text_digest
)
BEGIN
  SELECT RAISE(ABORT, 'approvals consent version and digest must match the consent text');
END;

-- Sequential approval digests: ordinal 1 has no prior; ordinal 2 names the
-- approval_digest of ordinal 1 of the same envelope, which must already exist.
CREATE TRIGGER approvals_sequence BEFORE INSERT ON approvals
WHEN CASE (
  SELECT r.ordinal FROM recipients r
  WHERE r.tenant_id = NEW.tenant_id AND r.envelope_id = NEW.envelope_id AND r.id = NEW.recipient_id
)
  WHEN 1 THEN NEW.prior_approval_digest IS NOT NULL
  ELSE NEW.prior_approval_digest IS NOT (
    SELECT a.approval_digest FROM approvals a
    JOIN recipients r ON r.tenant_id = a.tenant_id AND r.envelope_id = a.envelope_id AND r.id = a.recipient_id
    WHERE a.tenant_id = NEW.tenant_id AND a.envelope_id = NEW.envelope_id AND r.ordinal = 1
  ) OR NEW.prior_approval_digest IS NULL
END
BEGIN
  SELECT RAISE(ABORT, 'approvals prior_approval_digest must follow the recipient order');
END;

CREATE TRIGGER approvals_immutable_update BEFORE UPDATE ON approvals
BEGIN
  SELECT RAISE(ABORT, 'approvals rows are immutable');
END;

CREATE TRIGGER approvals_immutable_delete BEFORE DELETE ON approvals
BEGIN
  SELECT RAISE(ABORT, 'approvals rows are immutable');
END;
