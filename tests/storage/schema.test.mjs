// SPDX-License-Identifier: Apache-2.0
//
// Schema coverage and integrity (T003): every data-model entity is persisted,
// every table carries tenant_id with composite tenant foreign keys, and the
// data-model constraints, immutability rules and audit-chain linkage hold in
// the schema itself.

import { AssertionError } from 'node:assert';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { openDatabase, StorageConstraintError, StorageUsageError, TenantStore } from '../../src/storage/db/index.ts';
import { claimRestrictedInsert } from '../../src/storage/db/tenant-store.ts';
import { DERIVED_ENTITIES, entityTables, SYSTEM_TABLES, TABLES } from '../../src/storage/schema/entities.ts';
import { loadMigrations } from '../../src/storage/schema/migrations.ts';
import {
  appendAudit,
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

// The entity rows of data-model.md (revision 2026-11-08, M4, with the
// FinalizationAttemptBlob row added by spec f5f5711), in order.
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
  'FinalizationAttemptBlob',
  'DisposalRecord',
]);

// Entities whose tables T003 creates. Later tasks add tables for the rest
// (FinalizationAttemptBlob: T038) through appended migrations.
const T003_ENTITIES = Object.freeze(DATA_MODEL_ENTITIES.filter((entity) => entity !== 'FinalizationAttemptBlob'));

// The tables T003's migrations create. DB-12 writes a row into each of these;
// tables appended by later tasks are checked structurally by DB-11 only.
const T003_TABLES = Object.freeze([
  'tenants',
  'consent_texts',
  'envelopes',
  'document_revisions',
  'recipients',
  'field_definitions',
  'field_manifests',
  'send_confirmations',
  'invitations',
  'challenges',
  'recipient_sessions',
  'approvals',
  'idempotency_records',
  'signing_jobs',
  'final_artifacts',
  'verification_reports',
  'audit_events',
  'audit_checkpoints',
  'outbox_events',
  'webhook_registrations',
  'webhook_keys',
  'consumer_attachments',
  'anchor_receipts',
  'disposal_records',
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

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '..', '..');

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

/** Entity-map checks: only data-model entities, every T003 entity persisted. */
function checkEntityMap(map, derived) {
  for (const entity of map.keys()) assert.ok(DATA_MODEL_ENTITIES.includes(entity), `${entity} is a data-model entity`);
  for (const entity of T003_ENTITIES) {
    if (Object.hasOwn(derived, entity)) {
      assert.deepEqual(map.get(entity), [], `${entity} is derived, not stored`);
    } else {
      assert.ok((map.get(entity) ?? []).length > 0, `${entity} has a table`);
    }
  }
  assert.deepEqual(Object.keys(derived), ['Principal']);
}

/**
 * Structural invariants of every table of a migrated database against a table
 * policy map: the schema and the map agree, every table is STRICT, carries a
 * required tenant_id referencing tenants, and every foreign key carries
 * tenant_id; capability columns are unique; only the audit tables are
 * restricted.
 */
function checkTableInvariants(raw, policies) {
  const tables = raw
    .prepare(`SELECT name, strict FROM pragma_table_list WHERE schema = 'main' AND type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
    .all();
  assert.deepEqual(
    tables.map((row) => row.name),
    [...Object.keys(policies), ...SYSTEM_TABLES].sort(),
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
  for (const [table, policy] of Object.entries(policies)) {
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
    Object.entries(policies)
      .filter(([, policy]) => policy.writer === 'restricted')
      .map(([table]) => table)
      .sort(),
    ['audit_checkpoints', 'audit_events'],
  );
}

test('[DB-11] every data-model entity is persisted, and every table is STRICT with tenant_id and tenant-carrying foreign keys', () => {
  checkEntityMap(entityTables(), DERIVED_ENTITIES);
  for (const table of T003_TABLES) assert.ok(Object.hasOwn(TABLES, table), `${table} has a policy`);
  const { db, path } = openTemp(scratch);
  db.close();
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    checkTableInvariants(raw, TABLES);
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
    for (const table of T003_TABLES) assert.ok(store.count(table) >= 1, `${table} has a row`);
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
    assert.throws(() => db.transaction(() => appendAudit(a, 'envelopes', envelopeRow(sid('env')))), /not a restricted table/);
    rejects(db, () => appendAudit(a, 'audit_events', auditEvent(5, head)), 'trigger', /extend the tenant chain/);
    rejects(db, () => appendAudit(a, 'audit_events', auditEvent(3, g.auditDigests[1])), ['trigger', 'primary-key']);
    rejects(db, () => appendAudit(a, 'audit_events', auditEvent(4, hex('not-the-head'))), 'trigger', /previous event_digest/);
    rejects(db, () => appendAudit(a, 'audit_events', auditEvent(4, null)), ['check', 'trigger']);
    const fourth = auditEvent(4, head);
    db.transaction(() => appendAudit(a, 'audit_events', fourth));
    db.transaction(() => appendAudit(b, 'audit_events', auditEvent(1, null)));
    assert.equal(b.count('audit_events'), 1, 'each tenant has its own chain');
    assert.equal(a.count('audit_events'), 4);

    rejects(db, () => appendAudit(a, 'audit_checkpoints', { seq: 4, kind: 'cadence', event_digest: head, created_at: ts(40) }), 'trigger', /chain digest/);
    db.transaction(() => appendAudit(a, 'audit_checkpoints', { seq: 4, kind: 'cadence', event_digest: fourth.event_digest, created_at: ts(40) }));
    rejects(db, () => appendAudit(a, 'audit_checkpoints', { seq: 4, kind: 'cadence', event_digest: fourth.event_digest, created_at: ts(41) }), 'unique');
    rejects(db, () => appendAudit(a, 'audit_checkpoints', { seq: 4, kind: 'completion', event_digest: fourth.event_digest, created_at: ts(41) }), 'check');
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

// A probe table shaped like a later task's appended table (here like T038's
// FinalizationAttemptBlob). Its name is one no task will use, so this test
// keeps working after the real table is appended.
const APPENDED_TABLE = 'appended_probe_blobs';
const APPENDED_TABLE_SQL = `CREATE TABLE ${APPENDED_TABLE} (
  tenant_id TEXT NOT NULL REFERENCES tenants (tenant_id),
  envelope_id TEXT NOT NULL,
  fencing_token INTEGER NOT NULL CHECK (fencing_token >= 1),
  blob_ref TEXT NOT NULL CHECK (substr(blob_ref, 1, length(tenant_id) + 16) = 'tenants/' || tenant_id || '/sha256/'),
  role TEXT NOT NULL CHECK (role IN ('composed', 'sealed', 'evidence')),
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, envelope_id, fencing_token, blob_ref),
  FOREIGN KEY (tenant_id, envelope_id) REFERENCES envelopes (tenant_id, id)
) STRICT;
`;

/** Migrate a fresh database with the code's migrations plus one appended file. */
function migrateWithAppended(name, sql) {
  const dir = scratch.dir();
  const migrations = join(dir, 'migrations');
  mkdirSync(migrations);
  const real = loadMigrations();
  for (const migration of real) writeFileSync(join(migrations, migration.name), migration.sql);
  writeFileSync(join(migrations, `${String(real.length + 1).padStart(4, '0')}-${name}.sql`), sql);
  const path = join(dir, 'appended.db');
  const db = openDatabase({ path });
  db.migrate(loadMigrations(migrations));
  return { db, path };
}

test('[DB-22] a table appended by a later task passes DB-11 and DB-12, and the structural checks still bite', () => {
  const { db, path } = migrateWithAppended('appended-probe-blobs', APPENDED_TABLE_SQL);
  try {
    const tenant = sid('tenant');
    seedGraph(db, tenant);
    const store = db.forTenant(tenant);
    for (const table of T003_TABLES) assert.ok(store.count(table) >= 1, `${table} has a row`);
  } finally {
    db.close();
  }
  const extended = { ...TABLES, [APPENDED_TABLE]: { entity: 'FinalizationAttemptBlob', mutability: 'immutable', writer: 'store' } };
  const map = new Map(entityTables());
  map.set('FinalizationAttemptBlob', [...(map.get('FinalizationAttemptBlob') ?? []), APPENDED_TABLE]);
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    checkTableInvariants(raw, extended);
    checkEntityMap(map, DERIVED_ENTITIES);
    assert.equal(raw.prepare(`SELECT count(*) AS n FROM ${APPENDED_TABLE}`).get().n, 0, 'an appended table may be empty');
    assert.throws(() => checkTableInvariants(raw, TABLES), AssertionError, 'an appended table without a policy is caught');
    const unknown = new Map(map);
    unknown.set('MadeUpEntity', [APPENDED_TABLE]);
    assert.throws(() => checkEntityMap(unknown, DERIVED_ENTITIES), AssertionError, 'an entity outside data-model.md is caught');
  } finally {
    raw.close();
  }

  const unscoped = migrateWithAppended('unscoped-notes', 'CREATE TABLE unscoped_notes (id TEXT NOT NULL PRIMARY KEY, note TEXT) STRICT;\n');
  unscoped.db.close();
  const rawUnscoped = new DatabaseSync(unscoped.path, { readOnly: true });
  try {
    assert.throws(
      () => checkTableInvariants(rawUnscoped, { ...TABLES, unscoped_notes: { entity: 'Tenant', mutability: 'mutable', writer: 'store' } }),
      (error) => error instanceof AssertionError && /unscoped_notes has tenant_id/.test(error.message),
    );
  } finally {
    rawUnscoped.close();
  }
});

test('[DB-23] the restricted insert is handed out exactly once by claimRestrictedInsert() and is reachable no other way', async () => {
  const tenantStoreModule = await import('../../src/storage/db/tenant-store.ts');
  assert.deepEqual(
    Object.keys(tenantStoreModule).sort(),
    ['MAX_LIST_LIMIT', 'TENANT_ID_PATTERN', 'TenantStore', 'claimRestrictedInsert'],
    'tenant-store exports the one-shot claim and no restricted insert function',
  );
  const indexModule = await import('../../src/storage/db/index.ts');
  assert.deepEqual(Object.keys(indexModule).filter((name) => /restrict|claim/i.test(name)), [], 'the storage index re-exports no restricted path');
  assert.deepEqual(
    [...Object.getOwnPropertyNames(TenantStore.prototype), ...Object.getOwnPropertyNames(TenantStore)].filter((name) => /restrict|claim/i.test(name)),
    [],
    'no TenantStore member exposes the restricted path',
  );
  assert.equal(existsSync(join(REPO_ROOT, 'src', 'storage', 'db', 'restricted-writer.ts')), false, 'no shared restricted-writer module remains');

  // A fresh process: the first claim returns a working insert for the audit
  // tables only, and every later claim throws.
  const child = spawnSync(process.execPath, [join(HERE, 'support', 'restricted-claim-child.mjs')], { cwd: REPO_ROOT, encoding: 'utf8', timeout: 60_000 });
  assert.equal(child.status, 0, child.stderr);
  const claimed = JSON.parse(child.stdout.trim().split('\n').at(-1));
  assert.equal(claimed.first, 'function');
  assert.match(claimed.second, /^storage_usage: .*already been claimed/);
  assert.match(claimed.third, /^storage_usage: .*already been claimed/);
  assert.equal(claimed.appended, 1, 'the claimed insert appends to the audit chain');
  assert.match(claimed.nonRestricted, /^storage_usage: envelopes is not a restricted table/);

  // This process: once the claim is held (here by the storage fixtures), any
  // further claim throws, and the generic insert still refuses audit tables.
  const { db } = openTemp(scratch);
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const store = db.forTenant(tenant);
    db.transaction(() => appendAudit(store, 'audit_events', auditEvent(1, null)));
    assert.throws(() => claimRestrictedInsert(), (error) => error instanceof StorageUsageError && /already been claimed/.test(error.message));
    assert.throws(() => db.transaction(() => store.insert('audit_events', auditEvent(2, hex('any')))), /restricted writer/);
    assert.equal(store.count('audit_events'), 1);
  } finally {
    db.close();
  }
});

test('[DB-26] an appended migration gives DisposalRecord a required kind (retention or orphan-collection) that retention can filter on', () => {
  const migrations = loadMigrations();
  const kindMigration = migrations.find((entry) => entry.name === '0008-disposal-record-kind.sql');
  assert.ok(kindMigration, 'migration 0008 adds the kind');
  assert.equal(kindMigration.version, 8, 'it is appended after the T003 baseline (0001..0007)');

  // A database migrated to the baseline holds a record written before the
  // kind existed; 0008 backfills it as 'retention' (its only writer then).
  const dir = scratch.dir();
  const migrationDir = (name, count) => {
    const target = join(dir, name);
    mkdirSync(target);
    for (const entry of migrations.slice(0, count)) writeFileSync(join(target, entry.name), entry.sql);
    return target;
  };
  const baselineDir = migrationDir('baseline', 7);
  const kindDir = migrationDir('through-0008', 8);
  const path = join(dir, 'kind.db');
  const db = openDatabase({ path });
  const raw = new DatabaseSync(path);
  try {
    db.migrate(loadMigrations(baselineDir));
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const store = db.forTenant(tenant);
    const envA = sid('env');
    const envB = sid('env');
    const record = (id, envelopeId, extra = {}) => ({
      id,
      envelope_id: envelopeId,
      retained_artifact_digests_json: '[]',
      disposed_blob_refs_json: '[]',
      policy_ref: 'synthetic-policy',
      server_time: ts(30),
      ...extra,
    });
    const legacy = sid('disp');
    db.transaction(() => {
      store.insert('envelopes', envelopeRow(envA));
      store.insert('envelopes', envelopeRow(envB));
      store.insert('disposal_records', record(legacy, envA));
    });
    assert.throws(() => db.transaction(() => store.insert('disposal_records', record(sid('disp'), envA, { kind: 'retention' }))), StorageUsageError, 'no kind column before 0008');

    assert.deepEqual(db.migrate(loadMigrations(kindDir)).applied, [8]);
    const column = raw.prepare(`SELECT type, dflt_value FROM pragma_table_info('disposal_records') WHERE name = 'kind'`).get();
    assert.deepEqual({ ...column }, { type: 'TEXT', dflt_value: null }, 'kind has no default');
    assert.equal(store.get('disposal_records', { id: legacy })?.kind, 'retention', 'a pre-0008 record is backfilled as retention');
    const immutableSql = (name) => raw.prepare(`SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?`).get(name)?.sql;
    assert.equal(
      immutableSql('disposal_records_immutable_update'),
      /CREATE TRIGGER disposal_records_immutable_update[\s\S]*?END/.exec(migrations[5].sql)?.[0],
      'the immutability trigger is restored exactly as 0006 defined it',
    );

    const orphan = sid('disp');
    db.transaction(() => {
      store.insert('disposal_records', record(orphan, envB, { kind: 'orphan-collection' }));
      store.insert('disposal_records', record(sid('disp'), envB, { kind: 'retention' }));
    });
    rejects(db, () => store.insert('disposal_records', record(sid('disp'), envB, { kind: 'archive' })), 'check');
    rejects(db, () => store.insert('disposal_records', record(sid('disp'), envB, { kind: null })), 'trigger', /kind is required/);
    rejects(db, () => store.insert('disposal_records', record(sid('disp'), envB)), 'trigger', /kind is required/);
    assert.deepEqual(
      store.list('disposal_records', { kind: 'retention' }, { orderBy: [['envelope_id', 'asc']] }).map((row) => row.envelope_id).sort(),
      [envA, envB].sort(),
      'retention filters records by kind',
    );
    assert.deepEqual(store.list('disposal_records', { kind: 'orphan-collection' }).map((row) => row.id), [orphan]);
    rawTriggerAbort(raw, `UPDATE disposal_records SET kind = 'retention' WHERE tenant_id = ? AND id = ?`, tenant, orphan);
    const index = raw.prepare(`SELECT name FROM pragma_index_list('disposal_records') WHERE name = 'disposal_records_kind'`).get();
    assert.ok(index, 'kind lookups are indexed');
    assert.deepEqual(raw.prepare('PRAGMA foreign_key_check').all(), []);
  } finally {
    raw.close();
    db.close();
  }
});
