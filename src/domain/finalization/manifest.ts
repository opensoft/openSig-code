// SPDX-License-Identifier: Apache-2.0
//
// The pre-seal approval manifest and its approval_evidence_digest (T038;
// A-008 S1; data-model.md § Entities, FinalArtifact; contract
// ApprovalManifest; FEN-07).
//
// Order (request #61 (4)): the seal anchor, then the composition, then this
// manifest, then the seal. The manifest carries every ApprovalManifest member
// except final_pdf_digest, which only exists after the seal:
// approval_evidence_digest = SHA-256 of its RFC 8785 form, computed by the
// project's one canonical module, and passed to T037's seal unchanged.
//
// Every member is read from stored, frozen rows:
// - the envelope's source, its id and its version (the reserved version: the
//   only version fixed before the seal, see the report's question Q5);
// - the frozen revision (digest, bytes, displayed pages) and the frozen field
//   manifest's exact canonical bytes, with manifest_digest;
// - each approval in recipient order, rebuilt as the contract ApprovalRecord
//   from its stored row and checked against its stored approval_digest, then
//   its stored field_values_digest checked against T010's fieldValuesDigest
//   of the stored values and the server-day dates (A-010 request #85 (1), row
//   FV-DIGEST); a mismatch is a broken invariant (StepFailure
//   manifest_invalid.approval-digest or .field-values-digest, not
//   retryable), never repaired;
// - each consent text the approvals reference, once, in approval order;
// - approved_composition_digest (T036's ComposedRevision.digest), the seal's
//   signer certificate digest and development flag, and the seal anchor's seq
//   and event digest.

import { canonicalDigest, parseJson, type JsonValue } from '../../domain/canonical/index.ts';
import type { TenantStore } from '../../storage/db/index.ts';
import { getApprovalOf } from '../../storage/repositories/approvals.ts';
import { getEnvelope, getManifest, getRevision, listRecipients } from '../../storage/repositories/envelopes.ts';
import { fieldValuesDigest, serverDate, type DateValue } from '../approval/index.ts';
import { StepFailure } from './failure.ts';

export const APPROVAL_MANIFEST_SCHEMA = 'opensig.approval-manifest/1';

export interface PreSealManifestInput {
  readonly envelopeId: string;
  readonly anchor: { readonly seq: number; readonly digest: string };
  readonly approvedCompositionDigest: string;
  readonly seal: { readonly signerCertificateSha256: string; readonly developmentCertificate: boolean };
}

export interface PreSealManifest {
  /** approval-manifest.json without final_pdf_digest. */
  readonly manifest: { readonly [key: string]: JsonValue };
  readonly approvalEvidenceDigest: string;
}

function broken(reason: string): StepFailure {
  return new StepFailure('manifest_invalid', reason, false);
}

function parsed(text: string, reason: string): JsonValue {
  try {
    return parseJson(text);
  } catch {
    throw broken(reason);
  }
}

/** The frozen inputs of the seal, read once per attempt: T036's request members and the manifest's stored members. */
export interface SealRecords {
  readonly envelopeId: string;
  readonly envelopeVersion: number;
  readonly source: JsonValue;
  readonly document: { readonly blobRef: string; readonly summary: JsonValue };
  /** The frozen field manifest (T036's FieldManifestInput shape) and its digest. */
  readonly fieldManifest: JsonValue;
  readonly manifestDigest: string;
  /** Contract ApprovalRecords in recipient order, each checked against its stored approval_digest and field_values_digest. */
  readonly approvals: readonly { readonly [key: string]: JsonValue }[];
  readonly consentTexts: readonly JsonValue[];
}

/** Build the pre-seal manifest and its digest from the stored rows (reads only). */
export function buildPreSealManifest(records: SealRecords, input: PreSealManifestInput): PreSealManifest {
  const manifest: { [key: string]: JsonValue } = {
    schema: APPROVAL_MANIFEST_SCHEMA,
    envelope_id: records.envelopeId,
    envelope_version: records.envelopeVersion,
    source: records.source,
    document: records.document.summary,
    field_manifest: records.fieldManifest,
    manifest_digest: records.manifestDigest,
    consent_texts: [...records.consentTexts],
    approvals: [...records.approvals],
    approved_composition_digest: input.approvedCompositionDigest,
    seal: { type: 'organization', signer_certificate_sha256: input.seal.signerCertificateSha256, development_certificate: input.seal.developmentCertificate },
    seal_audit_anchor: { seq: input.anchor.seq, event_digest: input.anchor.digest },
  };
  return { manifest, approvalEvidenceDigest: canonicalDigest(manifest) };
}

/** Read and check the frozen seal inputs of a finalizing envelope (reads only). */
export function readSealRecords(store: TenantStore, envelopeId: string): SealRecords {
  const envelope = getEnvelope(store, envelopeId);
  if (envelope === undefined || envelope.state !== 'finalizing' || envelope.baseRevisionId === null || envelope.manifestDigest === null) throw broken('envelope');
  const revision = getRevision(store, envelope.id, envelope.baseRevisionId);
  if (revision === undefined) throw broken('revision');
  const fieldManifest = getManifest(store, envelope.id);
  if (fieldManifest === undefined || fieldManifest.digest !== envelope.manifestDigest) throw broken('field-manifest');

  const approvals: { [key: string]: JsonValue }[] = [];
  const consentIds: string[] = [];
  for (const recipient of listRecipients(store, envelope.id).sort((a, b) => a.ordinal - b.ordinal)) {
    const approval = getApprovalOf(store, recipient.id);
    if (approval === undefined) throw broken('approval-missing');
    const fieldValues = parsed(approval.fieldValuesJson, 'field-values');
    if (!Array.isArray(fieldValues)) throw broken('field-values');
    const date = serverDate(approval.serverTime);
    const dates: DateValue[] = fieldValues
      .filter((value): value is { readonly [key: string]: JsonValue } => typeof value === 'object' && value !== null && !Array.isArray(value) && value['type'] === 'date')
      .map((value) => String(value['key']))
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
      .map((key) => ({ key, value: date }));
    const dateValues: JsonValue[] = dates.map(({ key, value }) => ({ key, value }));
    const record: { [key: string]: JsonValue } = {
      approval_id: approval.id,
      recipient: { id: recipient.id, ordinal: recipient.ordinal, role: recipient.role, email: recipient.email },
      assurance: { method: approval.assuranceMethod, level: approval.assuranceLevel },
      consent_version: approval.consentVersion,
      consent_text_digest: approval.consentTextDigest,
      document_digest: approval.documentDigest,
      manifest_digest: approval.manifestDigest,
      prior_approval_digest: approval.priorApprovalDigest,
      field_values: fieldValues,
      date_values: dateValues,
      field_values_digest: approval.fieldValuesDigest,
      server_time: approval.serverTime,
    };
    if (canonicalDigest(record) !== approval.approvalDigest) throw broken('approval-digest');
    // FV-DIGEST (request #85 (1)): the stored digest must be T010's digest of the stored values and their dates.
    if (fieldValuesDigest(fieldValues, dates) !== approval.fieldValuesDigest) throw broken('field-values-digest');
    approvals.push({ ...record, approval_digest: approval.approvalDigest });
    if (!consentIds.includes(approval.consentTextId)) consentIds.push(approval.consentTextId);
  }
  if (approvals.length < 1 || approvals.length > 2) throw broken('approvals');

  const consentTexts: JsonValue[] = consentIds.map((id) => {
    const row = store.get('consent_texts', { id });
    if (row === undefined) throw broken('consent-text');
    return { version: String(row['version']), text_digest: String(row['text_digest']), text: String(row['text']) };
  });

  return {
    envelopeId: envelope.id,
    envelopeVersion: envelope.version,
    source: { app: envelope.source.app, record: envelope.source.record, version: envelope.source.version },
    document: { blobRef: revision.blobRef, summary: { digest: revision.contentDigest, bytes: revision.bytes, pages: parsed(revision.pageGeometryJson, 'pages') } },
    fieldManifest: parsed(Buffer.from(fieldManifest.bytes).toString('utf8'), 'field-manifest'),
    manifestDigest: envelope.manifestDigest,
    approvals,
    consentTexts,
  };
}
