-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0005 (T003): FinalArtifact, VerificationReport and
-- AnchorReceipt. Conventions: see 0001.

CREATE TABLE final_artifacts (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  artifact_id TEXT NOT NULL CHECK (length(artifact_id) BETWEEN 16 AND 64 AND artifact_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  -- SHA-256 of final.pdf.
  artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64 AND artifact_digest NOT GLOB '*[^0-9a-f]*'),
  -- SHA-256 of the package ZIP; set once when the package is assembled.
  package_digest TEXT CHECK (length(package_digest) = 64 AND package_digest NOT GLOB '*[^0-9a-f]*'),
  approved_composition_digest TEXT NOT NULL
    CHECK (length(approved_composition_digest) = 64 AND approved_composition_digest NOT GLOB '*[^0-9a-f]*'),
  pdf_blob_ref TEXT NOT NULL CHECK (pdf_blob_ref = 'tenants/' || tenant_id || '/sha256/' || artifact_digest),
  evidence_blob_ref TEXT NOT NULL CHECK (
    substr(evidence_blob_ref, 1, length(tenant_id) + 16) = 'tenants/' || tenant_id || '/sha256/'
    AND length(evidence_blob_ref) = length(tenant_id) + 80
    AND substr(evidence_blob_ref, length(tenant_id) + 17) NOT GLOB '*[^0-9a-f]*'
  ),
  package_blob_ref TEXT CHECK (package_blob_ref = 'tenants/' || tenant_id || '/sha256/' || package_digest),
  signer_certificate_sha256 TEXT NOT NULL
    CHECK (length(signer_certificate_sha256) = 64 AND signer_certificate_sha256 NOT GLOB '*[^0-9a-f]*'),
  development_certificate INTEGER NOT NULL CHECK (development_certificate IN (0, 1)),
  verifier_name TEXT NOT NULL CHECK (length(verifier_name) BETWEEN 1 AND 100),
  verifier_version TEXT NOT NULL CHECK (length(verifier_version) BETWEEN 1 AND 50),
  verification_json TEXT NOT NULL CHECK (json_valid(verification_json) AND json_type(verification_json) = 'object'),
  -- The fencing token of the publishing attempt.
  fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
  completed_at TEXT NOT NULL
    CHECK (completed_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, artifact_id),
  -- One artifact per envelope.
  UNIQUE (tenant_id, envelope_id),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id),
  CHECK ((package_digest IS NULL) = (package_blob_ref IS NULL))
) STRICT;

-- Publication is fenced: the artifact must carry the job's current token.
CREATE TRIGGER final_artifacts_fencing BEFORE INSERT ON final_artifacts
WHEN NOT EXISTS (
  SELECT 1 FROM signing_jobs j
  WHERE j.tenant_id = NEW.tenant_id AND j.envelope_id = NEW.envelope_id AND j.fencing_token = NEW.fencing_token
)
BEGIN
  SELECT RAISE(ABORT, 'final_artifacts fencing token is not the current signing job token');
END;

-- Completed evidence is immutable. The only permitted change is recording the
-- package digest and blob once.
CREATE TRIGGER final_artifacts_immutable_update BEFORE UPDATE OF
  tenant_id, artifact_id, envelope_id, artifact_digest, approved_composition_digest, pdf_blob_ref,
  evidence_blob_ref, signer_certificate_sha256, development_certificate, verifier_name, verifier_version,
  verification_json, fencing_token, completed_at
ON final_artifacts
BEGIN
  SELECT RAISE(ABORT, 'final_artifacts rows are immutable');
END;

CREATE TRIGGER final_artifacts_package_once BEFORE UPDATE OF package_digest, package_blob_ref ON final_artifacts
WHEN OLD.package_digest IS NOT NULL OR OLD.package_blob_ref IS NOT NULL
BEGIN
  SELECT RAISE(ABORT, 'final_artifacts package is recorded once');
END;

CREATE TRIGGER final_artifacts_immutable_delete BEFORE DELETE ON final_artifacts
BEGIN
  SELECT RAISE(ABORT, 'final_artifacts rows are immutable');
END;

CREATE TABLE verification_reports (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64 AND artifact_digest NOT GLOB '*[^0-9a-f]*'),
  integrity TEXT NOT NULL CHECK (integrity IN ('valid', 'invalid', 'indeterminate')),
  trust TEXT NOT NULL CHECK (trust IN ('trusted', 'untrusted', 'indeterminate')),
  trust_anchor_ref TEXT CHECK (length(trust_anchor_ref) BETWEEN 1 AND 200),
  revision_coverage TEXT NOT NULL CHECK (revision_coverage IN ('complete', 'incomplete', 'indeterminate')),
  seal_type TEXT NOT NULL CHECK (seal_type = 'organization'),
  signer_certificate_sha256 TEXT
    CHECK (length(signer_certificate_sha256) = 64 AND signer_certificate_sha256 NOT GLOB '*[^0-9a-f]*'),
  timestamp_status TEXT NOT NULL DEFAULT 'absent'
    CHECK (timestamp_status IN ('trusted', 'absent', 'invalid', 'indeterminate')),
  revocation_status TEXT NOT NULL DEFAULT 'not-checked'
    CHECK (revocation_status IN ('good', 'revoked', 'unknown', 'not-checked')),
  verifier_name TEXT NOT NULL CHECK (length(verifier_name) BETWEEN 1 AND 100),
  verifier_version TEXT NOT NULL CHECK (length(verifier_version) BETWEEN 1 AND 50),
  verified_at TEXT NOT NULL
    CHECK (verified_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  checks_json TEXT NOT NULL CHECK (json_valid(checks_json) AND json_type(checks_json) = 'array'),
  -- The exact report bytes as produced by src/verifier/.
  report_bytes BLOB CHECK (length(report_bytes) BETWEEN 2 AND 1048576),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id)
) STRICT;

CREATE INDEX verification_reports_artifact ON verification_reports (tenant_id, artifact_digest);

CREATE TRIGGER verification_reports_immutable_update BEFORE UPDATE ON verification_reports
BEGIN
  SELECT RAISE(ABORT, 'verification_reports rows are immutable');
END;

CREATE TRIGGER verification_reports_immutable_delete BEFORE DELETE ON verification_reports
BEGIN
  SELECT RAISE(ABORT, 'verification_reports rows are immutable');
END;

CREATE TABLE anchor_receipts (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  id TEXT NOT NULL CHECK (length(id) BETWEEN 16 AND 64 AND id NOT GLOB '*[^A-Za-z0-9_-]*'),
  envelope_id TEXT NOT NULL,
  artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 64 AND artifact_digest NOT GLOB '*[^0-9a-f]*'),
  -- Only the disabled and fake adapters exist; a fake receipt never carries a
  -- real transaction identifier or network proof.
  adapter TEXT NOT NULL CHECK (adapter IN ('disabled', 'fake')),
  schema TEXT NOT NULL CHECK (length(schema) BETWEEN 1 AND 100),
  status TEXT NOT NULL CHECK (length(status) BETWEEN 1 AND 40 AND status NOT GLOB '*[^a-z0-9_-]*'),
  fake INTEGER NOT NULL CHECK (fake IN (0, 1)),
  receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json) AND json_type(receipt_json) = 'object'),
  created_at TEXT NOT NULL
    CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9].[0-9][0-9][0-9]Z'),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id),
  CHECK ((adapter = 'fake') = (fake = 1)),
  CHECK (adapter <> 'disabled' OR status = 'disabled')
) STRICT;

CREATE INDEX anchor_receipts_envelope ON anchor_receipts (tenant_id, envelope_id);
