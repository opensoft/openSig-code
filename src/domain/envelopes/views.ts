// SPDX-License-Identifier: Apache-2.0
//
// Contract views (contracts/http-api.json: Envelope, RecipientPreview,
// SendConfirmation). A view never carries a capability value: no invitation,
// challenge code, session value or CSRF token is ever read here.

import type { JsonValue } from '../../domain/canonical/index.ts';
import type { EnvelopeAggregate, SendConfirmationRecord } from '../../storage/repositories/envelopes.ts';
import { confirmationRequired } from './send.ts';
import type { Actor } from './validation.ts';

/** anchor_status until T021 wires the anchoring adapters. */
const ANCHOR_STATUS = 'disabled';

const INTEGRITY = new Set(['valid', 'invalid', 'indeterminate']);
const TRUST = new Set(['trusted', 'untrusted', 'indeterminate']);

function documentView(aggregate: EnvelopeAggregate): JsonValue {
  const revision = aggregate.revision;
  if (revision === null) return null;
  return {
    digest: revision.contentDigest,
    bytes: revision.bytes,
    pages: revision.pages.map((page) => ({ number: page.number, width: page.width, height: page.height, rotate: page.rotate })),
  };
}

function fieldsView(aggregate: EnvelopeAggregate): JsonValue[] {
  return aggregate.fields.map((field) => ({
    key: field.key,
    recipient_id: field.recipientId,
    recipient_ordinal: field.recipientOrdinal,
    page: field.page,
    type: field.type,
    rect: { x: field.rect.x, y: field.rect.y, width: field.rect.width, height: field.rect.height },
  }));
}

function recipientsView(aggregate: EnvelopeAggregate): JsonValue[] {
  return aggregate.recipients.map((recipient) => ({
    id: recipient.id,
    ordinal: recipient.ordinal,
    role: recipient.role,
    email: recipient.email,
    status: recipient.status,
    invited_at: recipient.invitedAt,
    approved_at: recipient.approvedAt,
    approval_digest: recipient.approvalDigest,
  }));
}

function finalizationView(aggregate: EnvelopeAggregate): JsonValue {
  const job = aggregate.job;
  if (job === null) return null;
  return {
    job_status: job.status,
    attempts: job.attemptCount,
    max_attempts: job.maxAttempts,
    retry_at: job.retryAt,
    last_error_code: job.lastErrorCode,
  };
}

function artifactView(aggregate: EnvelopeAggregate): JsonValue {
  const artifact = aggregate.artifact;
  if (artifact === null || artifact.packageDigest === null) return null;
  let verification: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(artifact.verificationJson);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) verification = parsed as Record<string, unknown>;
  } catch {
    verification = {};
  }
  const integrity = typeof verification['integrity'] === 'string' && INTEGRITY.has(verification['integrity']) ? verification['integrity'] : 'indeterminate';
  const trust = typeof verification['trust'] === 'string' && TRUST.has(verification['trust']) ? verification['trust'] : 'indeterminate';
  return {
    artifact_id: artifact.artifactId,
    artifact_digest: artifact.artifactDigest,
    package_digest: artifact.packageDigest,
    integrity,
    trust,
    completed_at: artifact.completedAt,
  };
}

/** The operator view (contract Envelope). `openReference` is the current usable confirmation, if any. */
export function envelopeView(aggregate: EnvelopeAggregate, openReference: string | null): JsonValue {
  const envelope = aggregate.envelope;
  return {
    id: envelope.id,
    version: envelope.version,
    state: envelope.state,
    created_by: { kind: envelope.createdBy.kind, ref: envelope.createdBy.ref },
    source: { app: envelope.source.app, record: envelope.source.record, version: envelope.source.version },
    expires_at: envelope.expiresAt,
    reissue_of: envelope.reissueOf,
    reissued_as: envelope.reissuedAs,
    document: documentView(aggregate),
    manifest_digest: envelope.manifestDigest,
    fields: fieldsView(aggregate),
    recipients: recipientsView(aggregate),
    approvals_complete: envelope.approvalsComplete,
    send_confirmation: { required: confirmationRequired(envelope.createdBy), authorization_reference: openReference },
    finalization: finalizationView(aggregate),
    artifact: artifactView(aggregate),
    anchor_status: ANCHOR_STATUS,
    created_at: envelope.createdAt,
    updated_at: envelope.updatedAt,
  };
}

/**
 * What a human confirms before sending (contract RecipientPreview); only for a
 * prepared envelope. requires_human_confirmation applies the send rule to the
 * reading principal: true when the envelope is service-created or the reader
 * is a service (A-010 IDEMP-B2). The envelope view's send_confirmation.required
 * keeps the contract's creator rule.
 */
export function previewView(aggregate: EnvelopeAggregate, reader: Actor): JsonValue {
  const envelope = aggregate.envelope;
  return {
    envelope_id: envelope.id,
    version: envelope.version,
    state: 'prepared',
    created_by: { kind: envelope.createdBy.kind, ref: envelope.createdBy.ref },
    source: { app: envelope.source.app, record: envelope.source.record, version: envelope.source.version },
    document: documentView(aggregate),
    manifest_digest: envelope.manifestDigest,
    recipients_digest: envelope.recipientsDigest,
    recipients: recipientsView(aggregate),
    fields: fieldsView(aggregate),
    requires_human_confirmation: confirmationRequired(envelope.createdBy, reader),
  };
}

export function sendConfirmationView(confirmation: SendConfirmationRecord): JsonValue {
  return {
    authorization_reference: confirmation.authorizationReference,
    envelope_id: confirmation.envelopeId,
    envelope_version: confirmation.envelopeVersion,
    document_digest: confirmation.documentDigest,
    manifest_digest: confirmation.manifestDigest,
    recipients_digest: confirmation.recipientsDigest,
    confirmed_by: { kind: confirmation.confirmedBy.kind, ref: confirmation.confirmedBy.ref },
    confirmed_at: confirmation.confirmedAt,
    expires_at: confirmation.expiresAt,
  };
}
