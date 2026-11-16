-- SPDX-License-Identifier: Apache-2.0
--
-- openSig storage migration 0009 (T003, A-010 T30R3-1): blob-reference
-- lookups. Conventions: see 0001.
--
-- A disposal re-checks, inside its BEGIN IMMEDIATE transaction, whether any
-- row of the tenant still references each candidate blob (T029's
-- reference-protection predicate): document_revisions by blob_ref, and
-- final_artifacts by each of its blob-reference columns. These indexes make
-- every such lookup an index search, never a table scan, so the write lock
-- is held only for indexed lookups.

CREATE INDEX document_revisions_blob_ref ON document_revisions (tenant_id, blob_ref);

CREATE INDEX final_artifacts_pdf_blob_ref ON final_artifacts (tenant_id, pdf_blob_ref);

CREATE INDEX final_artifacts_evidence_blob_ref ON final_artifacts (tenant_id, evidence_blob_ref);

CREATE INDEX final_artifacts_package_blob_ref ON final_artifacts (tenant_id, package_blob_ref);
