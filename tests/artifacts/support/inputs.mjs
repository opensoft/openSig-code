// SPDX-License-Identifier: Apache-2.0
//
// T016 test support: package-builder inputs. Everything is synthetic and generated at run
// time; the scratch database is removed afterwards.
// - Storage-seeded chain (chainWorld). A migrated SQLite database (T003) holds one tenant,
//   the envelope under test and a second envelope. The tenant chain is written through
//   T029's AuditWriter, and the envelope's events are read back as T038 will read them:
//   eventFromRow() of each row, plus the row's stored event_digest.
// - Manifest and report (packageInput). A contract-shaped pre-seal ApprovalManifest (no
//   final_pdf_digest; T038's has not landed, so its shape is the contract's) and a report
//   shaped as T014's buildVerificationReport() emits it: T014's CHECK_IDS, in order, and its
//   VERIFIER. The report is passed as bytes, as T038 stores them in
//   verification_reports.report_bytes. Here they are its jcs.mjs form; T016 treats them
//   as opaque. `report` keeps the object so a test can edit it and call reserialize().
//   Every digest the fixture computes itself uses the test-local RFC 8785 serializer
//   (jcs.mjs), never src/domain/canonical/: manifest_digest, approval digests, field-value
//   digests and the evidence digest.
// - In-memory chains (memoryChain). Events built here with their digests from jcs.mjs, for
//   shapes the writer would refuse: the worst-case record, and receipts past the budget.
// The consent wording carries a non-ASCII character, so a string length and a UTF-8 byte
// length differ.

import { AuditWriter, eventFromRow } from '../../../src/storage/audit/index.ts';
import { CHECK_IDS, VERIFIER } from '../../../src/verifier/index.ts';
import { BASE_TIME, createTenant, envelopeRow, hex, makeScratch, openTemp, sid, ts } from '../../storage/support/fixtures.mjs';
import { jcsBytes, jcsDigest, sha256Hex } from './jcs.mjs';

export { hex, sid, ts };

export const CONSENT_VERSION = '2026.11-synthetic';
export const CONSENT_TEXT = 'I have reviewed this synthetic document and I approve it as shown — synthetic wording.';

/** A clock that advances one second per call from the fixed base time. */
export function steppingClock(start = BASE_TIME) {
  let now = start;
  return () => new Date((now += 1000));
}

/** Synthetic PDF-shaped bytes of exactly `size` bytes (at least 64): a header, filler, and an end marker. */
export function syntheticPdf(label, size = 4096) {
  const header = Buffer.from(`%PDF-1.7\n% synthetic sealed document ${label}\n`, 'latin1');
  const trailer = Buffer.from('\n%%EOF\n', 'latin1');
  if (size < header.length + trailer.length) throw new Error('syntheticPdf: size too small');
  return Buffer.concat([header, Buffer.alloc(size - header.length - trailer.length, 0x30), trailer]);
}

/**
 * The storage-seeded chain. Tenant chain order (seq):
 *   1 recipient.invited (E)            2 recipient.invited (other envelope)
 *   3 recipient.challenge_verified (E) 4 recipient.session_created (E)
 *   5 recipient.approved (E)           6 envelope.seal_started (E): the seal audit anchor
 *   7 recipient.capabilities_revoked (other envelope): the chain head; then the completion
 *     checkpoint at that head
 *   8 recipient.capabilities_revoked (E): after the head, so never in the receipt
 * `events` holds every event of E, seq 8 included, as T038 might read them.
 */
export function chainWorld() {
  const scratch = makeScratch();
  const { db } = openTemp(scratch);
  const tenantId = sid('tenant');
  createTenant(db, tenantId);
  const store = db.forTenant(tenantId);
  const envelopeId = sid('env');
  const otherId = sid('env');
  db.transaction(() => {
    store.insert('envelopes', envelopeRow(envelopeId));
    store.insert('envelopes', envelopeRow(otherId));
  });
  const audit = new AuditWriter(db, { clock: steppingClock() });
  const operator = { kind: 'human-operator', ref: 'operator-1' };
  const system = { kind: 'system', ref: 'recipient-ceremony' };
  const recipientId = sid('rcp');
  const recipient = { kind: 'recipient', ref: recipientId };
  const append = (envelope, type, actor, metadata) =>
    db.transaction(() => audit.append(tenantId, { type, actor, envelopeId: envelope, subjectDigest: hex(`manifest-${envelope}`), metadata }));

  append(envelopeId, 'recipient.invited', operator, { invitation_id: sid('inv'), recipient_id: recipientId, ordinal: 1, envelope_version: 3 });
  append(otherId, 'recipient.invited', operator, { invitation_id: sid('inv'), recipient_id: sid('rcp'), ordinal: 1, envelope_version: 3 });
  append(envelopeId, 'recipient.challenge_verified', recipient, { challenge_id: sid('chl'), invitation_id: sid('inv'), attempt: 1 });
  append(envelopeId, 'recipient.session_created', recipient, { session_id: sid('ses'), recipient_id: recipientId });
  append(envelopeId, 'recipient.approved', recipient, { approval_id: sid('apr'), recipient_id: recipientId, ordinal: 1, envelope_version: 4 });
  const anchor = append(envelopeId, 'envelope.seal_started', { kind: 'system', ref: 'finalizer' }, { attempt: 1, envelope_version: 4 });
  append(otherId, 'recipient.capabilities_revoked', system, { scope: 'void', envelope_version: 5 });
  const checkpoint = db.transaction(() => audit.checkpointCompletion(tenantId, envelopeId));
  append(envelopeId, 'recipient.capabilities_revoked', system, { scope: 'session-end', envelope_version: 5 });

  const read = (envelope) =>
    [...store.iterate('audit_events', { envelope_id: envelope }, { orderBy: [['seq', 'asc']] })].map((row) => ({
      event: eventFromRow(row),
      eventDigest: String(row['event_digest']),
    }));
  const events = read(envelopeId);
  return {
    db,
    scratch,
    tenantId,
    envelopeId,
    otherId,
    /** The other envelope's events, each with a valid stored digest. */
    otherEvents: read(otherId),
    anchor: { seq: anchor.seq, digest: anchor.digest },
    chainHead: { seq: checkpoint.seq, digest: checkpoint.digest },
    checkpoint,
    events,
    close() {
      db.close();
      scratch.cleanup();
    },
  };
}

/**
 * A complete, consistent PackageInput over `chain`: `approvals` (1 or 2) approvals of
 * one shared consent text, and a report whose artifact, signer and evidence digests are
 * those of `pdf` and the manifest.
 */
export function packageInput(chain, { pdf = syntheticPdf(chain.envelopeId), approvals = 1, artifactId = sid('art') } = {}) {
  const envelopeId = chain.envelopeId;
  const documentDigest = hex(`document-${envelopeId}`);
  const recipients = [
    { id: sid('rcp'), ordinal: 1, role: 'approver', email: 'signer.one@example.test' },
    { id: sid('rcp'), ordinal: 2, role: 'countersigner', email: 'signer.two@example.test' },
  ].slice(0, approvals);
  const fieldManifest = {
    schema: 'opensig.field-manifest/1',
    envelope_id: envelopeId,
    document_digest: documentDigest,
    fields: recipients.map((recipient, index) => ({
      key: `sig-${index + 1}`,
      recipient_id: recipient.id,
      recipient_ordinal: recipient.ordinal,
      page: 1,
      type: 'signature',
      rect: { x: 0.1, y: 0.1 + 0.2 * index, width: 0.3, height: 0.1 },
    })),
  };
  const manifestDigest = jcsDigest(fieldManifest);
  const consentDigest = sha256Hex(Buffer.from(CONSENT_TEXT, 'utf8'));
  let prior = null;
  const records = recipients.map((recipient, index) => {
    const fieldValues = [{ key: `sig-${index + 1}`, type: 'signature', mode: 'typed', text: `Synthetic Signer ${index + 1}` }];
    const dateValues = [];
    const body = {
      approval_id: sid('apr'),
      recipient,
      assurance: { method: 'mailbox-challenge', level: 'mailbox-control' },
      consent_version: CONSENT_VERSION,
      consent_text_digest: consentDigest,
      document_digest: documentDigest,
      manifest_digest: manifestDigest,
      prior_approval_digest: prior,
      field_values: fieldValues,
      date_values: dateValues,
      field_values_digest: jcsDigest({ field_values: fieldValues, date_values: dateValues }),
      server_time: ts(20 + index),
    };
    const approval = { ...body, approval_digest: jcsDigest(body) };
    prior = approval.approval_digest;
    return approval;
  });
  const signer = hex('synthetic-signer-certificate');
  const approvalManifest = {
    schema: 'opensig.approval-manifest/1',
    envelope_id: envelopeId,
    envelope_version: 5,
    source: { app: 'manual', record: 'record-1', version: 'v1' },
    document: { digest: documentDigest, bytes: 2048, pages: [{ number: 1, width: 612, height: 792, rotate: 0 }] },
    field_manifest: fieldManifest,
    manifest_digest: manifestDigest,
    consent_texts: [{ version: CONSENT_VERSION, text_digest: consentDigest, text: CONSENT_TEXT }],
    approvals: records,
    approved_composition_digest: hex(`composition-${envelopeId}`),
    seal: { type: 'organization', signer_certificate_sha256: signer, development_certificate: true },
    seal_audit_anchor: { seq: chain.anchor.seq, event_digest: chain.anchor.digest },
  };
  // A development certificate: integrity valid and trust untrusted, so the trust-anchors
  // check fails while every other check passes (trust is not part of the verdict).
  const report = {
    schema: 'opensig.verification/1',
    artifact_digest: sha256Hex(pdf),
    integrity: 'valid',
    trust: 'untrusted',
    trust_anchor_ref: null,
    revision_coverage: 'complete',
    seal_type: 'organization',
    signer_certificate_sha256: signer,
    approval_evidence_digest: jcsDigest(approvalManifest),
    timestamp_status: 'absent',
    revocation_status: 'not-checked',
    verifier: { name: VERIFIER.name, version: VERIFIER.version },
    verified_at: ts(30),
    checks: CHECK_IDS.map((id) => (id === 'trust-anchors' ? { id, result: 'fail' } : { id, result: 'pass' })),
  };
  return {
    tenantId: chain.tenantId,
    envelopeId,
    artifactId,
    finalPdf: pdf,
    approvalManifest,
    events: chain.events,
    chainHead: chain.chainHead,
    checkpoint: chain.checkpoint,
    verification: jcsBytes(report),
    report,
  };
}

/** Serialize `input.report` again into `input.verification` after a test edits it. */
export function reserialize(input) {
  input.verification = jcsBytes(input.report);
  return input;
}

/** The digest preimage of an AuditEvent, built here member by member from the contract's AuditEventRecord. */
export function preimageOf(event) {
  return {
    schema: 'opensig.audit-event/1',
    tenant_id: event.tenantId,
    seq: event.seq,
    type: event.type,
    actor: { kind: event.actor.kind, ref: event.actor.ref },
    server_time: event.serverTime,
    envelope_id: event.envelopeId,
    subject_digest: event.subjectDigest,
    metadata: event.metadata,
    prev_digest: event.prevDigest,
  };
}

/**
 * An in-memory tenant chain of `count` events of `envelopeId`, seq 1..count, linked by
 * prev_digest, with digests from jcs.mjs. `shape(seq)` may override any AuditEvent member.
 * Returns { events, chainHead, checkpoint, anchor }, where the anchor is the last event.
 */
export function memoryChain(tenantId, envelopeId, count, shape = () => ({})) {
  const events = [];
  let prev = null;
  for (let seq = 1; seq <= count; seq += 1) {
    const event = {
      tenantId,
      seq,
      type: 'recipient.session_created',
      actor: { kind: 'recipient', ref: `recipient-${seq}` },
      serverTime: new Date(BASE_TIME + seq * 1000).toISOString(),
      envelopeId,
      subjectDigest: hex(`subject-${seq}`),
      metadata: { session_id: `session-${seq}` },
      prevDigest: prev,
      ...shape(seq),
    };
    const eventDigest = jcsDigest(preimageOf(event));
    events.push({ event, eventDigest });
    prev = eventDigest;
  }
  const last = events[events.length - 1];
  const head = { seq: last.event.seq, digest: last.eventDigest };
  return { events, chainHead: head, checkpoint: { ...head, created_at: ts(60) }, anchor: head };
}
