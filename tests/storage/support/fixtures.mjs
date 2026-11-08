// SPDX-License-Identifier: Apache-2.0
//
// Shared helpers for the storage tests (T003). Every value is synthetic and
// generated at run time: identifiers are random, addresses use example.test,
// digests hash fixed labels, and secret-shaped columns get random bytes.

import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openDatabase } from '../../../src/storage/db/index.ts';
import { appendRestricted } from '../../../src/storage/db/restricted-writer.ts';

export const BASE_TIME = Date.UTC(2026, 10, 8, 10, 0, 0);

/** Unsigned server time, `minutes` after the fixed base, in toISOString() form. */
export function ts(minutes = 0) {
  return new Date(BASE_TIME + minutes * 60_000).toISOString();
}

/** A synthetic opaque identifier (16..64 characters of [A-Za-z0-9_-]). */
export function sid(prefix) {
  return `${prefix}-${randomBytes(12).toString('base64url')}`;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

/** A lowercase hex digest of a fixed label. */
export function hex(label) {
  return sha256(`opensig-test:${label}`);
}

export function blobRef(tenantId, digest) {
  return `tenants/${tenantId}/sha256/${digest}`;
}

export function makeScratch() {
  const dirs = [];
  return {
    dir(prefix = 'opensig-storage-') {
      const dir = mkdtempSync(join(tmpdir(), prefix));
      dirs.push(dir);
      return dir;
    },
    cleanup() {
      for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** Open a fresh database in a scratch directory, migrated unless told otherwise. */
export function openTemp(scratch, { busyTimeoutMs = 2_000, migrate = true } = {}) {
  const dir = scratch.dir();
  const path = join(dir, 'opensig.db');
  const db = openDatabase({ path, busyTimeoutMs });
  if (migrate) db.migrate();
  return { db, dir, path };
}

export function tenantRow(now = ts(0)) {
  return {
    oidc_issuer: 'https://issuer.example.test',
    oidc_audience: 'opensig-api',
    role_claim: 'roles',
    role_map_json: JSON.stringify({ 'opensig-sender': 'sender', 'opensig-admin': 'tenant_admin' }),
    principal_kind_claim: 'principal_kind',
    allowed_roles_json: JSON.stringify(['sender', 'tenant_admin', 'service']),
    created_at: now,
    updated_at: now,
  };
}

export function createTenant(db, tenantId) {
  db.transaction(() => db.forTenant(tenantId).insert('tenants', tenantRow()));
}

export function envelopeRow(id, overrides = {}) {
  return {
    id,
    source_app: 'manual',
    source_record: 'record-1',
    source_version: 'v1',
    state: 'draft',
    created_by_kind: 'human-operator',
    created_by_ref: 'operator-1',
    expires_at: ts(7 * 24 * 60),
    recipients_count: 2,
    created_at: ts(1),
    updated_at: ts(1),
    ...overrides,
  };
}

export function auditEvent(seq, prevDigest, overrides = {}) {
  return {
    seq,
    type: 'envelope.created',
    actor_kind: 'human-operator',
    actor_ref: 'operator-1',
    server_time: ts(seq),
    metadata_json: '{}',
    prev_digest: prevDigest,
    event_digest: hex(`event-${seq}-${prevDigest ?? 'genesis'}-${overrides.type ?? ''}`),
    ...overrides,
  };
}

/**
 * Build one tenant's complete synthetic graph through the tenant-scoped helpers:
 * a two-recipient envelope taken from draft to completed, plus a row in every
 * table of the schema. Returns the identifiers and digests used.
 */
export function seedGraph(db, tenantId) {
  const store = db.forTenant(tenantId);
  const g = {
    tenantId,
    consentId: sid('consent'),
    env: sid('env'),
    rev: sid('rev'),
    r1: sid('rcpt'),
    r2: sid('rcpt'),
    authRef: sid('auth'),
    inv: sid('inv'),
    ch: sid('chal'),
    ses: sid('sess'),
    a1: sid('appr'),
    a2: sid('appr'),
    vr: sid('vrep'),
    art: sid('art'),
    anchor: sid('anch'),
    disposal: sid('disp'),
    reg: sid('hook'),
    keyId: sid('hkey'),
    eventId: sid('evt'),
    idemKey: sid('idempotency'),
    docDigest: hex('document'),
    artDigest: hex('final-pdf'),
    tokenHash: sha256(randomBytes(32)),
    sessionHash: sha256(randomBytes(32)),
    recipientsDigest: hex('recipients'),
    consentText: 'Synthetic consent wording used by storage tests.',
  };
  g.consentDigest = sha256(g.consentText);
  const manifest = Buffer.from(
    JSON.stringify({ document_digest: g.docDigest, envelope_id: g.env, fields: [], schema: 'opensig.field-manifest/1' }),
  );
  g.manifestDigest = sha256(manifest);
  g.approvalDigest1 = hex('approval-1');
  g.approvalDigest2 = hex('approval-2');

  db.transaction(() => {
    store.insert('tenants', tenantRow());
    store.insert('consent_texts', {
      id: g.consentId,
      version: '2026.11',
      locale: 'en',
      text: g.consentText,
      text_digest: g.consentDigest,
      effective_from: ts(0),
      created_at: ts(0),
    });
    store.compareAndSet('tenants', {}, 1, { consent_text_id: g.consentId, updated_at: ts(1) });

    store.insert('envelopes', envelopeRow(g.env));
    store.insert('document_revisions', {
      id: g.rev,
      envelope_id: g.env,
      content_digest: g.docDigest,
      blob_ref: blobRef(tenantId, g.docDigest),
      bytes: 2048,
      pages: 2,
      page_geometry_json: JSON.stringify([
        { number: 1, width: 612, height: 792, rotate: 0 },
        { number: 2, width: 792, height: 612, rotate: 90 },
      ]),
      parse_report_json: JSON.stringify({ encrypted: false, signatures: 0 }),
      created_at: ts(2),
    });
    for (const [id, ordinal] of [
      [g.r1, 1],
      [g.r2, 2],
    ]) {
      store.insert('recipients', {
        id,
        envelope_id: g.env,
        ordinal,
        email: `recipient-${ordinal}@example.test`,
        role: 'approver',
        status: 'pending',
        created_at: ts(2),
        updated_at: ts(2),
      });
    }
    const field = (key, recipientId, ordinal, type, y) => ({
      envelope_id: g.env,
      key,
      revision_id: g.rev,
      recipient_id: recipientId,
      recipient_ordinal: ordinal,
      page: 1,
      type,
      rect_x: 0.1,
      rect_y: y,
      rect_width: 0.3,
      rect_height: 0.05,
      created_at: ts(3),
    });
    store.insert('field_definitions', field('sig-1', g.r1, 1, 'signature', 0.6));
    store.insert('field_definitions', field('date-1', g.r1, 1, 'date', 0.7));
    store.insert('field_definitions', field('sig-2', g.r2, 2, 'signature', 0.8));
    store.insert('field_manifests', {
      envelope_id: g.env,
      revision_id: g.rev,
      schema: 'opensig.field-manifest/1',
      manifest_digest: g.manifestDigest,
      canonical_bytes: manifest,
      created_at: ts(4),
    });
    store.update('document_revisions', { id: g.rev }, { frozen_at: ts(4) });
    store.compareAndSet('envelopes', { id: g.env }, 1, {
      state: 'prepared',
      base_revision_id: g.rev,
      manifest_digest: g.manifestDigest,
      recipients_digest: g.recipientsDigest,
      updated_at: ts(4),
    });

    store.insert('send_confirmations', {
      authorization_reference: g.authRef,
      envelope_id: g.env,
      envelope_version: 2,
      document_digest: g.docDigest,
      manifest_digest: g.manifestDigest,
      recipients_digest: g.recipientsDigest,
      confirmed_by_kind: 'human-operator',
      confirmed_by_ref: 'operator-1',
      confirmed_at: ts(5),
      expires_at: ts(5 + 24 * 60),
    });
    store.update('send_confirmations', { authorization_reference: g.authRef }, { consumed_at: ts(6) });
    store.compareAndSet('envelopes', { id: g.env }, 2, { state: 'sent', updated_at: ts(6) });
    store.update('recipients', { id: g.r1 }, { status: 'invited', invited_at: ts(6), updated_at: ts(6) });
    store.insert('invitations', {
      id: g.inv,
      envelope_id: g.env,
      recipient_id: g.r1,
      revision_id: g.rev,
      manifest_digest: g.manifestDigest,
      token_hash: g.tokenHash,
      sent_at: ts(6),
      expires_at: ts(6 + 7 * 24 * 60),
    });
    store.insert('challenges', {
      id: g.ch,
      invitation_id: g.inv,
      code_hmac: hex('challenge-code'),
      created_at: ts(7),
      expires_at: ts(17),
    });
    store.update('challenges', { id: g.ch }, { attempts: 1, consumed_at: ts(8) });
    store.insert('recipient_sessions', {
      id: g.ses,
      value_hash: g.sessionHash,
      envelope_id: g.env,
      recipient_id: g.r1,
      revision_id: g.rev,
      manifest_digest: g.manifestDigest,
      csrf_secret: randomBytes(32),
      created_at: ts(8),
      last_seen_at: ts(8),
    });

    const approval = (id, recipientId, prior, digest, minute) => ({
      id,
      envelope_id: g.env,
      recipient_id: recipientId,
      document_digest: g.docDigest,
      manifest_digest: g.manifestDigest,
      prior_approval_digest: prior,
      consent_text_id: g.consentId,
      consent_version: '2026.11',
      consent_text_digest: g.consentDigest,
      field_values_json: JSON.stringify([{ key: 'sig-1', type: 'signature', mode: 'typed', text: 'Synthetic Signer' }]),
      field_values_digest: hex(`field-values-${id}`),
      assurance_method: 'mailbox-challenge',
      assurance_level: 'mailbox-control',
      server_time: ts(minute),
      approval_digest: digest,
    });
    store.insert('approvals', approval(g.a1, g.r1, null, g.approvalDigest1, 9));
    store.update('recipients', { id: g.r1 }, { status: 'approved', approved_at: ts(9), approval_id: g.a1, updated_at: ts(9) });
    store.compareAndSet('envelopes', { id: g.env }, 3, { state: 'in-progress', updated_at: ts(9) });
    store.update('recipients', { id: g.r2 }, { status: 'invited', invited_at: ts(9), updated_at: ts(9) });
    store.insert('approvals', approval(g.a2, g.r2, g.approvalDigest1, g.approvalDigest2, 10));
    store.update('recipients', { id: g.r2 }, { status: 'approved', approved_at: ts(10), approval_id: g.a2, updated_at: ts(10) });
    store.compareAndSet('envelopes', { id: g.env }, 4, { state: 'finalizing', approvals_complete: 1, updated_at: ts(10) });

    store.insert('idempotency_records', {
      route: 'createEnvelope',
      principal_kind: 'human-operator',
      principal_ref: 'operator-1',
      key: g.idemKey,
      request_digest: hex('request'),
      response_status: 201,
      response_body_digest: hex('response'),
      resource_id: g.env,
      created_at: ts(1),
    });
    store.insert('signing_jobs', {
      envelope_id: g.env,
      reserved_version: 5,
      status: 'pending',
      max_attempts: 5,
      created_at: ts(10),
      updated_at: ts(10),
    });
    store.compareAndSet('signing_jobs', { envelope_id: g.env }, 1, {
      status: 'running',
      attempt_count: 1,
      fencing_token: 1,
      lease_owner: 'runner-1',
      lease_expires_at: ts(16),
      updated_at: ts(11),
    });
    store.insert('verification_reports', {
      id: g.vr,
      envelope_id: g.env,
      artifact_digest: g.artDigest,
      integrity: 'valid',
      trust: 'untrusted',
      revision_coverage: 'complete',
      seal_type: 'organization',
      signer_certificate_sha256: hex('certificate'),
      verifier_name: 'opensig-verifier',
      verifier_version: '0.0.0',
      verified_at: ts(12),
      checks_json: JSON.stringify([{ name: 'byte-range', result: 'pass' }]),
    });
    store.insert('final_artifacts', {
      artifact_id: g.art,
      envelope_id: g.env,
      artifact_digest: g.artDigest,
      approved_composition_digest: hex('composition'),
      pdf_blob_ref: blobRef(tenantId, g.artDigest),
      evidence_blob_ref: blobRef(tenantId, hex('evidence')),
      signer_certificate_sha256: hex('certificate'),
      development_certificate: 1,
      verifier_name: 'opensig-verifier',
      verifier_version: '0.0.0',
      verification_json: JSON.stringify({ integrity: 'valid', trust: 'untrusted' }),
      fencing_token: 1,
      completed_at: ts(13),
    });
    store.compareAndSet('signing_jobs', { envelope_id: g.env }, 2, {
      status: 'succeeded',
      lease_owner: null,
      lease_expires_at: null,
      updated_at: ts(13),
    });
    store.compareAndSet('envelopes', { id: g.env }, 5, { state: 'completed', updated_at: ts(13) });
    store.insert('outbox_events', {
      event_id: g.eventId,
      envelope_id: g.env,
      envelope_version: 6,
      type: 'envelope.completed',
      schema_version: '1',
      payload_json: JSON.stringify({ event_id: g.eventId, envelope_id: g.env, artifact_digest: g.artDigest }),
      created_at: ts(13),
    });

    const e1 = auditEvent(1, null);
    const e2 = auditEvent(2, e1.event_digest, { envelope_id: g.env, type: 'envelope.sent' });
    const e3 = auditEvent(3, e2.event_digest, {
      envelope_id: g.env,
      type: 'envelope.completed',
      subject_digest: g.artDigest,
    });
    for (const event of [e1, e2, e3]) appendRestricted(store, 'audit_events', event);
    appendRestricted(store, 'audit_checkpoints', {
      seq: 3,
      kind: 'completion',
      event_digest: e3.event_digest,
      envelope_id: g.env,
      created_at: ts(13),
    });
    g.auditDigests = [e1.event_digest, e2.event_digest, e3.event_digest];

    store.insert('anchor_receipts', {
      id: g.anchor,
      envelope_id: g.env,
      artifact_digest: g.artDigest,
      adapter: 'disabled',
      schema: 'opensig.anchor-receipt/1',
      status: 'disabled',
      fake: 0,
      receipt_json: JSON.stringify({ status: 'disabled' }),
      created_at: ts(14),
    });
    store.insert('disposal_records', {
      id: g.disposal,
      envelope_id: g.env,
      retained_artifact_digests_json: JSON.stringify([g.artDigest]),
      disposed_blob_refs_json: JSON.stringify([]),
      policy_ref: 'synthetic-retention-policy',
      server_time: ts(15),
    });
    store.insert('webhook_registrations', {
      id: g.reg,
      url: 'https://hooks.example.test/opensig',
      event_types_json: JSON.stringify(['envelope.completed']),
      status: 'active',
      created_by_ref: 'admin-1',
      created_at: ts(1),
      updated_at: ts(1),
    });
    store.insert('webhook_keys', {
      key_id: g.keyId,
      registration_id: g.reg,
      secret_ciphertext: randomBytes(48),
      created_at: ts(1),
    });
    store.insert('consumer_attachments', {
      consumer: 'openchart',
      source_id: 'record-1',
      source_version: 'v1',
      envelope_id: g.env,
      artifact_id: g.art,
      artifact_digest: g.artDigest,
      attached_at: ts(16),
    });
  });
  return g;
}
