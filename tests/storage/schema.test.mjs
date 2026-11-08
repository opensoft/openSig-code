// SPDX-License-Identifier: Apache-2.0
//
// Schema coverage and integrity (T003): every data-model entity is persisted,
// every table carries tenant_id with composite tenant foreign keys, and the
// data-model constraints, immutability rules and audit-chain linkage hold in
// the schema itself.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';

import { StorageConstraintError, StorageUsageError } from '../../src/storage/db/index.ts';
import { appendRestricted } from '../../src/storage/db/restricted-writer.ts';
import { DERIVED_ENTITIES, entityTables, SYSTEM_TABLES, TABLES } from '../../src/storage/schema/entities.ts';
import {
  auditEvent,
  blobRef,
  createTenant,
  envelopeRow,
  hex,
  makeScratch,
  openTemp,
  seedGraph,
  sha256,
  sid,
  ts,
} from './support/fixtures.mjs';

// The entity rows of data-model.md (revision 2026-11-08, M4), in order.
const DATA_MODEL_ENTITIES = Object.freeze([
  'Tenant',
  'Principal',
  'Envelope',
  'DocumentRevision',
  'FieldDefinition',
  'FieldManifest',
  'Recipient',
  'ConsentText',
  'SendConfirmation',
  'Invitation',
  'Challenge',
  'RecipientSession',
  'Approval',
  'IdempotencyRecord',
  'SigningJob',
  'FinalArtifact',
  'VerificationReport',
  'AuditEvent',
  'AuditCheckpoint',
  'OutboxEvent',
  'WebhookRegistration / WebhookKey',
  'ConsumerAttachment',
  'AnchorReceipt',
  'DisposalRecord',
]);

const IMMUTABLE_TABLES = Object.freeze([
  'consent_texts',
  'field_manifests',
  'approvals',
  'verification_reports',
  'audit_events',
  'audit_checkpoints',
  'disposal_records',
]);

const scratch = makeScratch();
after(() => scratch.cleanup());

function constraintError(kinds, pattern) {
  const allowed = [].concat(kinds);
  return (error) =>
    error instanceof StorageConstraintError &&
    allowed.includes(error.constraint) &&
    (pattern === undefined || pattern.test(error.message));
}

function rejects(db, fn, kinds, pattern) {
  assert.throws(() => db.transaction(fn), constraintError(kinds, pattern));
}

function rawTriggerAbort(raw, sql, ...params) {
  assert.throws(
    () => raw.prepare(sql).run(...params),
    (error) => error.code === 'ERR_SQLITE_ERROR' && error.errcode === 1811,
    sql,
  );
}

/** A fresh two-recipient draft envelope with a revision, for focused cases. */
function draftEnvelope(store, tenantId) {
  const ids = { env: sid('env'), rev: sid('rev'), r1: sid('rcpt'), r2: sid('rcpt'), digest: hex(`doc-${randomBytes(4).toString('hex')}`) };
  store.insert('envelopes', envelopeRow(ids.env));
  store.insert('document_revisions', {
    id: ids.rev,
    envelope_id: ids.env,
    content_digest: ids.digest,
    blob_ref: blobRef(tenantId, ids.digest),
    bytes: 100,
    pages: 1,
    page_geometry_json: '[]',
    parse_report_json: '{}',
    created_at: ts(2),
  });
  for (const [id, ordinal] of [
    [ids.r1, 1],
    [ids.r2, 2],
  ]) {
    store.insert('recipients', {
      id,
      envelope_id: ids.env,
      ordinal,
      email: `recipient-${ordinal}@example.test`,
      role: 'approver',
      created_at: ts(2),
      updated_at: ts(2),
    });
  }
  return ids;
}

function approvalRow(g, ids, recipientId, prior, overrides = {}) {
  return {
    id: sid('appr'),
    envelope_id: ids.env,
    recipient_id: recipientId,
    document_digest: ids.digest,
    manifest_digest: hex('manifest'),
    prior_approval_digest: prior,
    consent_text_id: g.consentId,
    consent_version: '2026.11',
    consent_text_digest: g.consentDigest,
    field_values_json: '[]',
    field_values_digest: hex('field-values'),
    assurance_method: 'mailbox-challenge',
    assurance_level: 'mailbox-control',
    server_time: ts(20),
    approval_digest: hex(`approval-${recipientId}`),
    ...overrides,
  };
}

test('[DB-11] every data-model entity is persisted, and every table is STRICT with tenant_id and tenant-carrying foreign keys', () => {
  const map = entityTables();
  assert.deepEqual([...map.keys()].sort(), [...DATA_MODEL_ENTITIES].sort(), 'the entity map names exactly the data-model entities');
  for (const entity of DATA_MODEL_ENTITIES) {
    if (Object.hasOwn(DERIVED_ENTITIES, entity)) {
      assert.deepEqual(map.get(entity), [], `${entity} is derived, not stored`);
    } else {
      assert.ok((map.get(entity) ?? []).length > 0, `${entity} has a table`);
    }
  }
  assert.deepEqual(Object.keys(DERIVED_ENTITIES), ['Principal']);

  const { db, path } = openTemp(scratch);
  db.close();
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    const tables = raw
      .prepare(`SELECT name, strict FROM pragma_table_list WHERE schema = 'main' AND type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
      .all();
    assert.deepEqual(
      tables.map((row) => row.name),
      [...Object.keys(TABLES), ...SYSTEM_TABLES].sort(),
      'the migrated schema and the table policy map agree',
    );
    for (const { name, strict } of tables) {
      assert.equal(strict, 1, `${name} is STRICT`);
      if (SYSTEM_TABLES.includes(name)) continue;
      const tenantColumn = raw.prepare(`SELECT "notnull" AS nn, pk FROM pragma_table_info(?) WHERE name = 'tenant_id'`).get(name);
      assert.ok(tenantColumn, `${name} has tenant_id`);
      assert.equal(tenantColumn.nn === 1 || tenantColumn.pk > 0, true, `${name}.tenant_id is required`);
      const keys = raw.prepare(`SELECT id, "table" AS parent, "from" AS source, "to" AS target FROM pragma_foreign_key_list(?)`).all(name);
      const groups = new Map();
      for (const key of keys) groups.set(key.id, [...(groups.get(key.id) ?? []), key]);
      if (name !== 'tenants') {
        assert.ok(
          [...groups.values()].some((group) => group.length === 1 && group[0].parent === 'tenants' && group[0].source === 'tenant_id'),
          `${name}.tenant_id references tenants`,
        );
      }
      for (const group of groups.values()) {
        assert.ok(
          group.some((key) => key.source === 'tenant_id' && key.target === 'tenant_id'),
          `${name} -> ${group[0].parent}: every foreign key carries tenant_id`,
        );
      }
    }
    for (const [table, policy] of Object.entries(TABLES)) {
      if (policy.capabilityColumn === undefined) continue;
      const unique = raw
        .prepare(`SELECT il.name FROM pragma_index_list(?) il WHERE il."unique" = 1`)
        .all(table)
        .some((index) => {
          const columns = raw.prepare('SELECT name FROM pragma_index_info(?)').all(index.name).map((row) => row.name);
          return columns.length === 1 && columns[0] === policy.capabilityColumn;
        });
      assert.ok(unique, `${table}.${policy.capabilityColumn} is unique`);
    }
    assert.deepEqual(
      Object.entries(TABLES)
        .filter(([, policy]) => policy.writer === 'restricted')
        .map(([table]) => table)
        .sort(),
      ['audit_checkpoints', 'audit_events'],
    );
  } finally {
    raw.close();
  }
});

test('[DB-12] a complete synthetic tenant graph from draft to completed writes every table and passes foreign key checks', () => {
  const { db, path } = openTemp(scratch);
  try {
    const tenant = sid('tenant');
    const g = seedGraph(db, tenant);
    const store = db.forTenant(tenant);
    for (const table of Object.keys(TABLES)) assert.ok(store.count(table) >= 1, `${table} has a row`);
    const envelope = store.get('envelopes', { id: g.env });
    assert.equal(envelope?.state, 'completed');
    assert.equal(envelope?.version, 6);
    assert.equal(envelope?.approvals_complete, 1);
    assert.deepEqual(
      store.list('recipients', { envelope_id: g.env }, { orderBy: [['ordinal', 'asc']] }).map((row) => [row.ordinal, row.status]),
      [
        [1, 'approved'],
        [2, 'approved'],
      ],
    );
    const manifestBytes = store.get('field_manifests', { envelope_id: g.env })?.canonical_bytes;
    assert.ok(manifestBytes instanceof Uint8Array);
    assert.equal(sha256(manifestBytes), g.manifestDigest, 'the frozen canonical bytes round-trip exactly');
  } finally {
    db.close();
  }
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    assert.deepEqual(raw.prepare('PRAGMA foreign_key_check').all(), []);
    assert.equal(raw.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
  } finally {
    raw.close();
  }
});

test('[DB-13] composite foreign keys and blob keys keep every reference inside one tenant and one envelope', () => {
  const { db } = openTemp(scratch);
  try {
    const tenantA = sid('tenant');
    const tenantB = sid('tenant');
    const g = seedGraph(db, tenantA);
    createTenant(db, tenantB);
    const a = db.forTenant(tenantA);
    const b = db.forTenant(tenantB);

    rejects(
      db,
      () =>
        b.insert('recipients', {
          id: sid('rcpt'),
          envelope_id: g.env,
          ordinal: 1,
          email: 'recipient-1@example.test',
          role: 'approver',
          created_at: ts(2),
          updated_at: ts(2),
        }),
      'foreign-key',
    );
    const bEnvelope = sid('env');
    db.transaction(() => b.insert('envelopes', envelopeRow(bEnvelope)));
    rejects(
      db,
      () =>
        b.insert('document_revisions', {
          id: sid('rev'),
          envelope_id: bEnvelope,
          content_digest: g.docDigest,
          blob_ref: blobRef(tenantA, g.docDigest),
          bytes: 10,
          pages: 1,
          page_geometry_json: '[]',
          parse_report_json: '{}',
          created_at: ts(2),
        }),
      'check',
      /blob_ref/,
    );
    rejects(db, () => b.insert('approvals', approvalRow(g, { env: bEnvelope, digest: g.docDigest }, g.r1, null)), ['foreign-key', 'trigger']);
    rejects(db, () => b.compareAndSet('tenants', {}, 1, { consent_text_id: g.consentId, updated_at: ts(2) }), 'foreign-key');

    // Inside one tenant, references stay inside one envelope.
    let other;
    db.transaction(() => {
      other = draftEnvelope(a, tenantA);
    });
    rejects(
      db,
      () =>
        a.insert('field_definitions', {
          envelope_id: other.env,
          key: 'sig-x',
          revision_id: other.rev,
          recipient_id: g.r1,
          recipient_ordinal: 1,
          page: 1,
          type: 'signature',
          rect_x: 0.1,
          rect_y: 0.1,
          rect_width: 0.2,
          rect_height: 0.1,
          created_at: ts(3),
        }),
      'foreign-key',
    );
    rejects(
      db,
      () =>
        a.insert('field_definitions', {
          envelope_id: other.env,
          key: 'sig-y',
          revision_id: other.rev,
          recipient_id: other.r1,
          recipient_ordinal: 2,
          page: 1,
          type: 'signature',
          rect_x: 0.1,
          rect_y: 0.1,
          rect_width: 0.2,
          rect_height: 0.1,
          created_at: ts(3),
        }),
      'foreign-key',
    );
    rejects(
      db,
      () =>
        a.insert('invitations', {
          id: sid('inv'),
          envelope_id: other.env,
          recipient_id: other.r1,
          revision_id: g.rev,
          manifest_digest: g.manifestDigest,
          token_hash: hex(`token-${randomBytes(4).toString('hex')}`),
          sent_at: ts(6),
          expires_at: ts(60),
        }),
      'foreign-key',
    );
    rejects(db, () => a.compareAndSet('envelopes', { id: other.env }, 1, { base_revision_id: g.rev, updated_at: ts(3) }), 'foreign-key');
  } finally {
    db.close();
  }
});

test('[DB-14] data-model constraints are enforced by the schema', () => {
  const { db } = openTemp(scratch);
  try {
    const tenant = sid('tenant');
    const g = seedGraph(db, tenant);
    const s = db.forTenant(tenant);

    rejects(db, () => s.insert('envelopes', envelopeRow(sid('env'), { state: 'approved' })), 'check');
    rejects(db, () => s.insert('envelopes', envelopeRow('short-id')), 'check');
    rejects(db, () => s.insert('envelopes', envelopeRow(sid('env'), { recipients_count: 3 })), 'check');
    rejects(db, () => s.insert('envelopes', envelopeRow(sid('env'), { recipients_count: 'two' })), 'datatype');
    rejects(db, () => s.insert('envelopes', envelopeRow(sid('env'), { approvals_complete: 1 })), 'check', /approvals_complete/);
    rejects(db, () => s.insert('envelopes', envelopeRow(sid('env'), { state: 'prepared' })), 'check', /base_revision_id/);
    rejects(db, () => s.insert('envelopes', envelopeRow(sid('env'), { expires_at: '2026-11-15T10:00:00.000+01:00' })), 'check');
    rejects(db, () => s.insert('envelopes', envelopeRow(sid('env'), { expires_at: ts(0) })), 'check', /expires_at > created_at/);
    rejects(db, () => s.insert('envelopes', envelopeRow(sid('env'), { created_by_kind: 'recipient' })), 'check');
    rejects(db, () => s.compareAndSet('envelopes', { id: g.env }, 6, { approvals_complete: 0, updated_at: ts(20) }), 'check');

    rejects(
      db,
      () =>
        s.insert('recipients', {
          id: sid('rcpt'),
          envelope_id: g.env,
          ordinal: 2,
          email: 'recipient-3@example.test',
          role: 'approver',
          created_at: ts(2),
          updated_at: ts(2),
        }),
      'unique',
    );
    rejects(
      db,
      () =>
        s.insert('send_confirmations', {
          authorization_reference: sid('auth'),
          envelope_id: g.env,
          envelope_version: 2,
          document_digest: g.docDigest,
          manifest_digest: g.manifestDigest,
          recipients_digest: g.recipientsDigest,
          confirmed_by_kind: 'service',
          confirmed_by_ref: 'hermes-service',
          confirmed_at: ts(5),
          expires_at: ts(60),
        }),
      'check',
      /human-operator/,
    );
    rejects(db, () => s.insert('approvals', approvalRow(g, { env: g.env, digest: g.docDigest }, g.r1, null)), 'unique');
    rejects(
      db,
      () => s.insert('signing_jobs', { envelope_id: g.env, reserved_version: 5, status: 'pending', max_attempts: 3, created_at: ts(1), updated_at: ts(1) }),
      'primary-key',
    );
    rejects(
      db,
      () =>
        s.insert('final_artifacts', {
          artifact_id: sid('art'),
          envelope_id: g.env,
          artifact_digest: hex('second-pdf'),
          approved_composition_digest: hex('composition'),
          pdf_blob_ref: blobRef(tenant, hex('second-pdf')),
          evidence_blob_ref: blobRef(tenant, hex('evidence')),
          signer_certificate_sha256: hex('certificate'),
          development_certificate: 1,
          verifier_name: 'opensig-verifier',
          verifier_version: '0.0.0',
          verification_json: '{}',
          fencing_token: 1,
          completed_at: ts(30),
        }),
      'unique',
    );
    const outbox = (eventId, type) => ({
      event_id: eventId,
      envelope_id: g.env,
      envelope_version: 6,
      type,
      schema_version: '1',
      payload_json: '{}',
      created_at: ts(30),
    });
    rejects(db, () => s.insert('outbox_events', outbox(sid('evt'), 'envelope.completed')), 'unique', /outbox_events/);
    rejects(db, () => s.insert('outbox_events', outbox(g.eventId, 'envelope.sent')), ['unique', 'primary-key']);
    db.transaction(() => s.insert('outbox_events', outbox(sid('evt'), 'envelope.sent')));

    rejects(
      db,
      () =>
        s.insert('field_definitions', {
          envelope_id: g.env,
          key: 'sig-wide',
          revision_id: g.rev,
          recipient_id: g.r1,
          recipient_ordinal: 1,
          page: 1,
          type: 'signature',
          rect_x: 0.8,
          rect_y: 0.1,
          rect_width: 0.3,
          rect_height: 0.1,
          created_at: ts(3),
        }),
      'check',
      /rect_x/,
    );
    rejects(db, () => s.update('invitations', { id: g.inv }, { cumulative_wrong_codes: 20 }), 'check', /cumulative_wrong_codes/);
    db.transaction(() => s.update('invitations', { id: g.inv }, { cumulative_wrong_codes: 20, revoked_at: ts(30) }));
    rejects(db, () => s.update('challenges', { id: g.ch }, { attempts: 6 }), 'check');
    rejects(db, () => s.insert('consent_texts', {
      id: sid('consent'),
      version: 'V1',
      locale: 'en',
      text: 'x',
      text_digest: hex('x'),
      effective_from: ts(0),
      created_at: ts(0),
    }), 'check');
    rejects(db, () => s.update('envelopes', { id: g.env }, { manifest_digest: hex('upper').toUpperCase() }), 'check');

    const key = () => ({ key_id: sid('hkey'), registration_id: g.reg, secret_ciphertext: randomBytes(48), created_at: ts(2) });
    db.transaction(() => s.insert('webhook_keys', key()));
    rejects(db, () => s.insert('webhook_keys', key()), 'trigger', /at most 2 active keys/);
    db.transaction(() => s.update('webhook_keys', { key_id: g.keyId }, { revoked_at: ts(3) }));
    db.transaction(() => s.insert('webhook_keys', key()));
  } finally {
    db.close();
  }
});

test('[DB-15] immutable, single-use, frozen and fenced rows are protected by the helpers and by schema triggers', () => {
  const { db, path } = openTemp(scratch);
  const raw = new DatabaseSync(path);
  try {
    const tenant = sid('tenant');
    const g = seedGraph(db, tenant);
    const s = db.forTenant(tenant);

    for (const table of IMMUTABLE_TABLES) {
      assert.throws(() => db.transaction(() => s.update(table, { tenant_id: tenant }, {})), StorageUsageError);
      assert.throws(() => db.transaction(() => s.delete(table, { rowid: 1 })), /immutable/, `${table} delete refused`);
      assert.throws(() => db.transaction(() => s.compareAndSet(table, { rowid: 1 }, 1, {})), /immutable/, `${table} CAS refused`);
      rawTriggerAbort(raw, `UPDATE "${table}" SET tenant_id = tenant_id WHERE tenant_id = ?`, tenant);
      rawTriggerAbort(raw, `DELETE FROM "${table}" WHERE tenant_id = ?`, tenant);
    }

    rejects(db, () => s.update('document_revisions', { id: g.rev }, { pages: 3 }), 'trigger', /after prepare/);
    rejects(db, () => s.delete('document_revisions', { id: g.rev }), 'trigger');
    let draft;
    db.transaction(() => {
      draft = draftEnvelope(s, tenant);
      s.update('document_revisions', { id: draft.rev }, { pages: 2 });
    });

    rejects(db, () => s.update('send_confirmations', { authorization_reference: g.authRef }, { consumed_at: ts(40) }), 'trigger', /single use/);
    rejects(db, () => s.update('send_confirmations', { authorization_reference: g.authRef }, { envelope_version: 3 }), 'trigger');
    rejects(db, () => s.delete('send_confirmations', { authorization_reference: g.authRef }), 'trigger');

    rejects(db, () => s.update('final_artifacts', { artifact_id: g.art }, { artifact_digest: hex('other') }), 'trigger');
    db.transaction(() =>
      s.update('final_artifacts', { artifact_id: g.art }, { package_digest: hex('package'), package_blob_ref: blobRef(tenant, hex('package')) }),
    );
    rejects(
      db,
      () => s.update('final_artifacts', { artifact_id: g.art }, { package_digest: hex('package-2'), package_blob_ref: blobRef(tenant, hex('package-2')) }),
      'trigger',
      /recorded once/,
    );
    rejects(db, () => s.delete('final_artifacts', { artifact_id: g.art }), 'trigger');

    db.transaction(() =>
      s.insert('signing_jobs', {
        envelope_id: draft.env,
        reserved_version: 1,
        status: 'running',
        attempt_count: 2,
        max_attempts: 5,
        fencing_token: 2,
        lease_owner: 'runner-2',
        lease_expires_at: ts(50),
        created_at: ts(40),
        updated_at: ts(40),
      }),
    );
    const artifact = (fencingToken) => ({
      artifact_id: sid('art'),
      envelope_id: draft.env,
      artifact_digest: hex('draft-pdf'),
      approved_composition_digest: hex('composition'),
      pdf_blob_ref: blobRef(tenant, hex('draft-pdf')),
      evidence_blob_ref: blobRef(tenant, hex('evidence')),
      signer_certificate_sha256: hex('certificate'),
      development_certificate: 1,
      verifier_name: 'opensig-verifier',
      verifier_version: '0.0.0',
      verification_json: '{}',
      fencing_token: fencingToken,
      completed_at: ts(45),
    });
    rejects(db, () => s.insert('final_artifacts', artifact(1)), 'trigger', /fencing token/);
    rejects(db, () => s.update('signing_jobs', { envelope_id: draft.env }, { attempt_count: 1, fencing_token: 1 }), 'trigger');
    rejects(db, () => s.update('signing_jobs', { envelope_id: draft.env }, { reserved_version: 2 }), 'trigger');
    rejects(db, () => s.delete('signing_jobs', { envelope_id: draft.env }), 'trigger');
    db.transaction(() => s.insert('final_artifacts', artifact(2)));

    rejects(db, () => s.update('outbox_events', { event_id: g.eventId }, { payload_json: '{"changed":true}' }), 'trigger');
    db.transaction(() => s.update('outbox_events', { event_id: g.eventId }, { attempts: 2, acknowledged_at: ts(50) }));
    rejects(db, () => s.update('outbox_events', { event_id: g.eventId }, { attempts: 1 }), 'trigger');
    rejects(db, () => s.delete('outbox_events', { event_id: g.eventId }), 'trigger');

    rejects(db, () => s.update('invitations', { id: g.inv }, { token_hash: hex('another-token') }), 'trigger');
    db.transaction(() => s.update('invitations', { id: g.inv }, { revoked_at: ts(50) }));
    rejects(db, () => s.update('invitations', { id: g.inv }, { revoked_at: null }), 'trigger', /final/);
    rejects(db, () => s.update('recipient_sessions', { id: g.ses }, { value_hash: hex('another-session') }), 'trigger');
    rejects(db, () => s.update('challenges', { id: g.ch }, { consumed_at: ts(51) }), 'trigger', /single use/);
  } finally {
    raw.close();
    db.close();
  }
});

test('[DB-16] the audit chain, checkpoints, approval order and consent binding are enforced on insert', () => {
  const { db, path } = openTemp(scratch);
  const raw = new DatabaseSync(path);
  try {
    const tenantA = sid('tenant');
    const tenantB = sid('tenant');
    const g = seedGraph(db, tenantA);
    createTenant(db, tenantB);
    const a = db.forTenant(tenantA);
    const b = db.forTenant(tenantB);
    const head = g.auditDigests[2];

    assert.throws(() => db.transaction(() => a.insert('audit_events', auditEvent(4, head))), (error) => error instanceof StorageUsageError && /restricted writer/.test(error.message));
    assert.throws(() => db.transaction(() => appendRestricted(a, 'envelopes', envelopeRow(sid('env')))), /not a restricted table/);
    rejects(db, () => appendRestricted(a, 'audit_events', auditEvent(5, head)), 'trigger', /extend the tenant chain/);
    rejects(db, () => appendRestricted(a, 'audit_events', auditEvent(3, g.auditDigests[1])), ['trigger', 'primary-key']);
    rejects(db, () => appendRestricted(a, 'audit_events', auditEvent(4, hex('not-the-head'))), 'trigger', /previous event_digest/);
    rejects(db, () => appendRestricted(a, 'audit_events', auditEvent(4, null)), ['check', 'trigger']);
    const fourth = auditEvent(4, head);
    db.transaction(() => appendRestricted(a, 'audit_events', fourth));
    db.transaction(() => appendRestricted(b, 'audit_events', auditEvent(1, null)));
    assert.equal(b.count('audit_events'), 1, 'each tenant has its own chain');
    assert.equal(a.count('audit_events'), 4);

    rejects(db, () => appendRestricted(a, 'audit_checkpoints', { seq: 4, kind: 'cadence', event_digest: head, created_at: ts(40) }), 'trigger', /chain digest/);
    db.transaction(() => appendRestricted(a, 'audit_checkpoints', { seq: 4, kind: 'cadence', event_digest: fourth.event_digest, created_at: ts(40) }));
    rejects(db, () => appendRestricted(a, 'audit_checkpoints', { seq: 4, kind: 'cadence', event_digest: fourth.event_digest, created_at: ts(41) }), 'unique');
    rejects(db, () => appendRestricted(a, 'audit_checkpoints', { seq: 4, kind: 'completion', event_digest: fourth.event_digest, created_at: ts(41) }), 'check');
    rawTriggerAbort(raw, 'UPDATE audit_events SET metadata_json = ? WHERE tenant_id = ? AND seq = 2', '{"edited":true}', tenantA);
    rawTriggerAbort(raw, 'DELETE FROM audit_events WHERE tenant_id = ? AND seq = 4', tenantA);

    let ids;
    db.transaction(() => {
      ids = draftEnvelope(a, tenantA);
    });
    rejects(db, () => a.insert('approvals', approvalRow(g, ids, ids.r2, hex('anything'))), 'trigger', /recipient order/);
    rejects(db, () => a.insert('approvals', approvalRow(g, ids, ids.r1, hex('a-prior'))), 'trigger', /recipient order/);
    rejects(db, () => a.insert('approvals', approvalRow(g, ids, ids.r1, null, { consent_text_digest: hex('other-wording') })), 'trigger', /consent/);
    rejects(db, () => a.insert('approvals', approvalRow(g, ids, ids.r1, null, { consent_version: '2026.12' })), 'trigger', /consent/);
    const first = approvalRow(g, ids, ids.r1, null);
    db.transaction(() => a.insert('approvals', first));
    rejects(db, () => a.insert('approvals', approvalRow(g, ids, ids.r2, null)), 'trigger', /recipient order/);
    rejects(db, () => a.insert('approvals', approvalRow(g, ids, ids.r2, hex('wrong-prior'))), 'trigger', /recipient order/);
    db.transaction(() => a.insert('approvals', approvalRow(g, ids, ids.r2, first.approval_digest)));
  } finally {
    raw.close();
    db.close();
  }
});
