// SPDX-License-Identifier: Apache-2.0
//
// Test-only world for the completion tests (T038). Every value is synthetic
// and generated at run time: identifiers are random, digests hash fixed
// labels, blob bytes are labelled filler, addresses use example.test, and time
// comes from an injected clock that starts at a fixed instant. Each world
// lives in its own owner-only mkdtemp directory with a migrated database and a
// blob store, and close() removes that directory.
//
// The envelope reaches `finalizing` only through legal transitions (draft 1,
// prepared 2, sent 3, finalizing 4), and the reservation is inserted through
// T010's insertFinalizationReservation, as the last approval does.
// seedSealable() also stores a frozen document blob, a frozen field manifest,
// one recipient, a consent text and that recipient's approval, built with
// T010's buildApproval, so the runner can read real seal records.
//
// assembleAttempt() stands in for the steps before publication: T029's audit
// writer for the seal anchor and the completion checkpoint, T028's blob store
// for synthetic PDF, evidence and package bytes, and a synthetic contract
// VerificationReport (the shape of T014's buildVerificationReport).

import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { buildApproval } from '../../../src/domain/approval/record.ts';
import { canonicalBytes, canonicalize } from '../../../src/domain/canonical/index.ts';
import { AuditWriter } from '../../../src/storage/audit/index.ts';
import { openBlobStore } from '../../../src/storage/blobs/index.ts';
import { openDatabase } from '../../../src/storage/db/index.ts';
import { insertApproval, insertFinalizationReservation } from '../../../src/storage/repositories/approvals.ts';
import { getCompletionCheckpoint } from '../../../src/storage/repositories/artifacts.ts';
import { compareAndSetEnvelope, insertEnvelope, insertManifest, insertRecipient } from '../../../src/storage/repositories/envelopes.ts';

export const BASE_TIME = Date.UTC(2026, 10, 8, 10, 0, 0);
export const RESERVED_VERSION = 4;

export function sid(prefix) {
  return `${prefix}-${randomBytes(12).toString('base64url')}`;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

/** A lowercase hex digest of a fixed label. */
export function hex(label) {
  return sha256(`opensig-completion-test:${label}`);
}

/** Labelled synthetic bytes (never a real document). */
export function syntheticBytes(label, size = 256) {
  const bytes = Buffer.alloc(size, 0x2e);
  bytes.write(`synthetic:${label}:`, 0, 'latin1');
  return bytes;
}

/** A settable clock; `now()` returns a fresh Date. */
export function makeClock(start = BASE_TIME) {
  let current = start;
  return {
    now: () => new Date(current),
    iso: () => new Date(current).toISOString(),
    advance(ms) {
      current += ms;
      return new Date(current);
    },
  };
}

function tenantRow(now) {
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

export function makeWorld() {
  const dir = mkdtempSync(join(tmpdir(), 'opensig-completion-'));
  const dbPath = join(dir, 'opensig.db');
  const blobRoot = join(dir, 'blobs');
  mkdirSync(blobRoot, { mode: 0o700 });
  const db = openDatabase({ path: dbPath, busyTimeoutMs: 5_000 });
  db.migrate();
  const clock = makeClock();
  const audit = new AuditWriter(db, { clock: clock.now });
  const blobs = openBlobStore({ root: blobRoot });
  const tenantId = sid('tenant');
  db.transaction(() => db.forTenant(tenantId).insert('tenants', tenantRow(clock.iso())));
  return {
    dir,
    dbPath,
    blobRoot,
    db,
    clock,
    audit,
    blobs,
    tenantId,
    store: db.forTenant(tenantId),
    context: () => ({ db, audit, tenantId, clock: clock.now }),
    close() {
      db.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function walkToFinalizing(store, envelopeId, revisionId, manifestDigest, now) {
  const steps = [
    { state: 'prepared', baseRevisionId: revisionId, manifestDigest, recipientsDigest: hex(`recipients-${envelopeId}`) },
    { state: 'sent' },
    { state: 'finalizing', approvalsComplete: true },
  ];
  steps.forEach((step, index) => {
    if (!compareAndSetEnvelope(store, envelopeId, index + 1, { ...step, updatedAt: now })) throw new Error(`seed: the ${step.state} step lost its compare-and-set (envelope ${envelopeId})`);
  });
}

function draftEnvelope(world, envelopeId, now) {
  insertEnvelope(world.store, {
    id: envelopeId,
    source: { app: 'manual', record: 'record-1', version: 'v1' },
    createdBy: { kind: 'human-operator', ref: 'operator-1' },
    expiresAt: new Date(BASE_TIME + 7 * 24 * 3_600_000).toISOString(),
    recipientsCount: 1,
    reissueOf: null,
    now,
  });
}

function revisionRow(world, envelopeId, revisionId, digest, bytes, now) {
  return {
    id: revisionId,
    envelope_id: envelopeId,
    content_digest: digest,
    blob_ref: `tenants/${world.tenantId}/sha256/${digest}`,
    bytes,
    pages: 1,
    page_geometry_json: JSON.stringify([{ number: 1, width: 612, height: 792, rotate: 0 }]),
    parse_report_json: JSON.stringify({ encrypted: false, signatures: 0 }),
    created_at: now,
  };
}

/** A one-recipient envelope walked legally to finalizing, with its reservation (no approval rows). */
export function seedFinalizing(world, { maxAttempts = 5 } = {}) {
  const { db, store, clock } = world;
  const envelopeId = sid('env');
  const revisionId = sid('rev');
  const now = clock.iso();
  db.transaction(() => {
    draftEnvelope(world, envelopeId, now);
    const documentDigest = hex(`document-${envelopeId}`);
    store.insert('document_revisions', revisionRow(world, envelopeId, revisionId, documentDigest, 2048, now));
    walkToFinalizing(store, envelopeId, revisionId, hex(`manifest-${envelopeId}`), now);
    insertFinalizationReservation(store, { envelopeId, reservedVersion: RESERVED_VERSION, maxAttempts, now });
  });
  return { envelopeId, reservedVersion: RESERVED_VERSION };
}

/** A finalizing envelope with real seal records: document blob, field manifest, recipient, consent text and approval. */
export function seedSealable(world, { maxAttempts = 5 } = {}) {
  const { db, store, clock, blobs, tenantId } = world;
  const envelopeId = sid('env');
  const revisionId = sid('rev');
  const recipientId = sid('rcp');
  const consentId = sid('cons');
  const now = clock.iso();
  const document = blobs.put(tenantId, syntheticBytes(`document-${envelopeId}`, 2048));
  const fieldManifest = {
    schema: 'opensig.field-manifest/1',
    envelope_id: envelopeId,
    document_digest: document.digest,
    fields: [{ key: 'sig-1', recipient_id: recipientId, recipient_ordinal: 1, page: 1, type: 'signature', rect: { x: 0.1, y: 0.1, width: 0.3, height: 0.1 } }],
  };
  const manifestBytes = canonicalBytes(fieldManifest);
  const manifestDigest = sha256(manifestBytes);
  const consentText = 'Synthetic consent wording for tests.';
  const consentDigest = sha256(Buffer.from(consentText, 'utf8'));
  db.transaction(() => {
    draftEnvelope(world, envelopeId, now);
    store.insert('document_revisions', revisionRow(world, envelopeId, revisionId, document.digest, 2048, now));
    insertRecipient(store, { id: recipientId, envelopeId, ordinal: 1, email: 'recipient-1@example.test', role: 'approver', now });
    store.insert('consent_texts', { id: consentId, version: 'v1', locale: 'en', text: consentText, text_digest: consentDigest, effective_from: now, created_at: now });
    insertManifest(store, envelopeId, { revisionId, schema: 'opensig.field-manifest/1', digest: manifestDigest, bytes: manifestBytes }, now);
    walkToFinalizing(store, envelopeId, revisionId, manifestDigest, now);
    const approvalId = sid('appr');
    const built = buildApproval({
      approvalId,
      recipient: { id: recipientId, ordinal: 1, role: 'approver', email: 'recipient-1@example.test' },
      consentVersion: 'v1',
      consentTextDigest: consentDigest,
      documentDigest: document.digest,
      manifestDigest,
      priorApprovalDigest: null,
      fieldValues: [{ key: 'sig-1', type: 'signature', mode: 'typed', text: 'Synthetic Signer' }],
      serverTime: now,
    });
    insertApproval(store, {
      id: approvalId,
      envelopeId,
      recipientId,
      documentDigest: document.digest,
      manifestDigest,
      priorApprovalDigest: null,
      consentTextId: consentId,
      consentVersion: 'v1',
      consentTextDigest: consentDigest,
      fieldValuesJson: canonicalize(built.fieldValues),
      fieldValuesDigest: built.fieldValuesDigest,
      serverTime: now,
      approvalDigest: built.approvalDigest,
    });
    insertFinalizationReservation(store, { envelopeId, reservedVersion: RESERVED_VERSION, maxAttempts, now });
  });
  return { envelopeId, reservedVersion: RESERVED_VERSION, recipientId, documentDigest: document.digest, manifestDigest };
}

/** A synthetic contract VerificationReport for the given digests, as RFC 8785 bytes. */
export function reportBytesFor({ artifactDigest, approvalEvidenceDigest, verifiedAt, integrity = 'valid', coverage = 'complete', evidenceCheck = 'pass' }) {
  return canonicalBytes({
    schema: 'opensig.verification/1',
    artifact_digest: artifactDigest,
    integrity,
    trust: 'untrusted',
    trust_anchor_ref: null,
    revision_coverage: coverage,
    seal_type: 'organization',
    signer_certificate_sha256: hex('certificate'),
    approval_evidence_digest: approvalEvidenceDigest,
    timestamp_status: 'absent',
    revocation_status: 'not-checked',
    verifier: { name: 'opensig-product-verifier', version: '0.1.0' },
    verified_at: verifiedAt,
    checks: [
      { id: 'artifact-digest', result: 'pass' },
      { id: 'approval-evidence-digest', result: evidenceCheck },
    ],
  });
}

/**
 * The pre-publication steps of one attempt, with landed APIs only: the seal
 * anchor (once per envelope), synthetic stored blobs, the completion
 * checkpoint (once per envelope; a later attempt reuses it) and a report.
 */
export function assembleAttempt(world, envelopeId, label = 'attempt') {
  const { db, audit, blobs, tenantId, store } = world;
  const pdf = blobs.put(tenantId, syntheticBytes(`pdf-${envelopeId}-${label}`));
  const evidence = blobs.put(tenantId, syntheticBytes(`evidence-${envelopeId}-${label}`));
  const pack = blobs.put(tenantId, syntheticBytes(`package-${envelopeId}-${label}`));
  const head = db.transaction(() => {
    if (store.count('audit_events', { envelope_id: envelopeId, type: 'envelope.seal_started' }) === 0) {
      audit.append(tenantId, { type: 'envelope.seal_started', actor: { kind: 'system', ref: 'finalization-runner' }, envelopeId, metadata: { attempt: 1 } });
    }
    const existing = getCompletionCheckpoint(store, envelopeId);
    if (existing !== undefined) return existing;
    const written = audit.checkpointCompletion(tenantId, envelopeId);
    return { seq: written.seq, digest: written.digest };
  });
  const approvalEvidenceDigest = hex(`evidence-digest-${envelopeId}`);
  return {
    receiptHead: head,
    verificationReportId: sid('vrep'),
    reportBytes: reportBytesFor({ artifactDigest: pdf.digest, approvalEvidenceDigest, verifiedAt: world.clock.iso() }),
    artifact: {
      artifactId: sid('art'),
      artifactDigest: pdf.digest,
      packageDigest: pack.digest,
      approvedCompositionDigest: hex(`composition-${envelopeId}`),
      evidenceDigest: evidence.digest,
      approvalEvidenceDigest,
      developmentCertificate: true,
    },
  };
}

/** One line of the discriminating values of a snapshot, for assertion messages (request #70 (6)): ids, states and counts. */
export function describe(snap) {
  const job = snap.job ?? {};
  return [
    `envelope ${snap.envelope?.id} ${snap.envelope?.state} v${snap.envelope?.version}`,
    `job ${job.status} attempts ${job.attempt_count}/${job.max_attempts} attempt-no ${job.fencing_token} owner ${job.lease_owner} error ${job.last_error_code}`,
    `artifacts ${snap.artifacts.length}`,
    `reports ${snap.reports}`,
    `outbox ${snap.outbox.length}`,
    `attempt-records ${snap.attemptBlobs}`,
    `events ${snap.events}`,
    `checkpoints ${snap.checkpoints}`,
  ].join('; ');
}

/** Every row the publish or a failure may touch, for before/after equality. */
export function snapshot(world, envelopeId) {
  const { store } = world;
  return {
    envelope: store.get('envelopes', { id: envelopeId }),
    job: store.get('signing_jobs', { envelope_id: envelopeId }),
    artifacts: store.list('final_artifacts', { envelope_id: envelopeId }),
    reports: store.count('verification_reports', { envelope_id: envelopeId }),
    outbox: store.list('outbox_events', { envelope_id: envelopeId }),
    attemptBlobs: store.count('finalization_attempt_blobs', { envelope_id: envelopeId }),
    events: store.count('audit_events'),
    checkpoints: store.count('audit_checkpoints'),
  };
}
