// SPDX-License-Identifier: Apache-2.0
//
// Envelope lifecycle (T007): create, freeze at prepare through the single
// canonical module, and the version semantics ruled in spec 12de9e8
// (data-model.md § Transitions and races, item 1).

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { canonicalBytes, canonicalDigest, parseJson } from '../../../src/domain/canonical/index.ts';
import { FIELD_MANIFEST_SCHEMA } from '../../../src/domain/envelopes/index.ts';
import {
  BASE_TIME,
  contractErrors,
  createInput,
  documentInput,
  fieldsFor,
  HUMAN,
  makeScratch,
  preparedEnvelope,
  rejectsWith,
  req,
  SERVICE,
  setup,
  sha256,
} from './support.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

const DAY = 24 * 60 * 60 * 1000;
const ID = /^[A-Za-z0-9_-]{16,64}$/;

function row(ctx, table, where) {
  return ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).get(table, where));
}

function count(ctx, table, where = {}) {
  return ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).count(table, where));
}

test('[ST-03] create inserts a draft at version 1 with server-generated ids, ordered recipients and the expiry bounds', () => {
  const ctx = setup(scratch);
  try {
    const created = ctx.service.create(req(ctx.tenant), createInput(1));
    assert.equal(created.status, 201);
    assert.equal(created.replayed, false);
    const view = created.body;
    assert.match(view.id, ID);
    assert.equal(view.state, 'draft');
    assert.equal(view.version, 1);
    assert.deepEqual(view.created_by, HUMAN);
    assert.equal(view.expires_at, new Date(BASE_TIME + 7 * DAY).toISOString(), 'default expiry is created_at + 7 days');
    assert.equal(view.created_at, new Date(BASE_TIME).toISOString());
    assert.deepEqual([view.document, view.manifest_digest, view.fields, view.approvals_complete], [null, null, [], false]);
    assert.deepEqual(view.send_confirmation, { required: false, authorization_reference: null });
    assert.deepEqual(view.recipients.map((r) => [r.ordinal, r.status, r.invited_at, r.approved_at, r.approval_digest]), [[1, 'pending', null, null, null]]);
    assert.match(view.recipients[0].id, ID);
    assert.deepEqual(contractErrors('Envelope', view), [], 'the created view conforms to the contract');
    assert.deepEqual(created.bytes, canonicalBytes(view), 'the response bytes are the canonical body');
    const stored = row(ctx, 'envelopes', { id: view.id });
    assert.deepEqual([stored.state, stored.version], ['draft', 1]);

    const reversed = createInput(2);
    const two = ctx.service.create(req(ctx.tenant, SERVICE), { ...reversed, recipients: [...reversed.recipients].reverse() }).body;
    assert.deepEqual(two.recipients.map((r) => r.ordinal), [1, 2], 'recipients come back in ordinal order');
    assert.notEqual(two.recipients[0].id, two.recipients[1].id);
    assert.deepEqual(two.send_confirmation, { required: true, authorization_reference: null }, 'a service-created envelope needs human send confirmation');
    assert.deepEqual(two.created_by, SERVICE);

    const bound = ctx.service.create(req(ctx.tenant), createInput(1, { expires_at: new Date(BASE_TIME + 30 * DAY).toISOString() })).body;
    assert.equal(bound.expires_at, new Date(BASE_TIME + 30 * DAY).toISOString(), 'expires_at may be created_at + 30 days');
    const offset = ctx.service.create(req(ctx.tenant), createInput(1, { expires_at: '2026-11-10T12:00:00+02:00' })).body;
    assert.equal(offset.expires_at, '2026-11-10T10:00:00.000Z', 'expiry is stored as UTC');
  } finally {
    ctx.db.close();
  }
});

test('[ST-03] create refuses the ordinal rule, the expiry bounds and unknown properties, and writes nothing when it refuses', () => {
  const ctx = setup(scratch);
  try {
    const one = createInput(1);
    const two = createInput(2);
    const refused = [
      ['duplicate ordinals', { ...two, recipients: [two.recipients[0], { ...two.recipients[1], ordinal: 1 }] }],
      ['a gap: one recipient with ordinal 2', { ...one, recipients: [{ ...one.recipients[0], ordinal: 2 }] }],
      ['three recipients', { ...two, recipients: [...two.recipients, { email: 'signer.three@example.test', role: 'witness', ordinal: 2 }] }],
      ['no recipients', { ...one, recipients: [] }],
      ['a tenant in the body', { ...one, tenant_id: 'tenant-from-the-body-0001' }],
      ['an unknown source app', { ...one, source: { ...one.source, app: 'mail' } }],
      ['expiry past 30 days', createInput(1, { expires_at: new Date(BASE_TIME + 30 * DAY + 1).toISOString() })],
      ['expiry in the past', createInput(1, { expires_at: new Date(BASE_TIME - 1000).toISOString() })],
      ['expiry not a date-time', createInput(1, { expires_at: 'next week' })],
      ['a malformed address', { ...one, recipients: [{ ...one.recipients[0], email: 'no-at-sign' }] }],
    ];
    for (const [label, input] of refused) {
      const error = rejectsWith(() => ctx.service.create(req(ctx.tenant), input), 'invalid_request', 400);
      assert.ok(error.details.length > 0, `${label}: the refusal names a field`);
    }
    assert.equal(count(ctx, 'envelopes'), 0, 'no refused create left an envelope');
    assert.equal(count(ctx, 'recipients'), 0);
  } finally {
    ctx.db.close();
  }
});

test('[ST-04] prepare freezes the document, the field definitions, the RFC 8785 field manifest and the recipients digest, computed by src/domain/canonical/', () => {
  const ctx = setup(scratch);
  try {
    const created = ctx.service.create(req(ctx.tenant), createInput(2)).body;
    const document = documentInput(2);
    const uploaded = ctx.service.uploadDocument(req(ctx.tenant), created.id, 1, document).body;
    assert.deepEqual(uploaded.document, { digest: document.digest, bytes: document.bytes, pages: document.pages });
    rejectsWith(() => ctx.service.preview(req(ctx.tenant), created.id), 'state_conflict', 409);

    const fields = fieldsFor(2).reverse();
    const prepared = ctx.service.prepare(req(ctx.tenant), created.id, { expected_version: uploaded.version, fields }).body;
    assert.equal(prepared.state, 'prepared');
    assert.equal(prepared.version, 3, 'create 1, upload 2, prepare 3');
    assert.deepEqual(contractErrors('Envelope', prepared), []);

    const recipientIds = new Map(prepared.recipients.map((r) => [r.ordinal, r.id]));
    const expectedFields = [...fields]
      .sort((a, b) => (a.key < b.key ? -1 : 1))
      .map((f) => ({ key: f.key, recipient_id: recipientIds.get(f.recipient_ordinal), recipient_ordinal: f.recipient_ordinal, page: f.page, type: f.type, rect: f.rect }));
    assert.deepEqual(prepared.fields, expectedFields, 'field definitions are frozen in key order with server recipient ids');
    const expectedManifest = { schema: FIELD_MANIFEST_SCHEMA, envelope_id: created.id, document_digest: document.digest, fields: expectedFields };

    const manifestRow = row(ctx, 'field_manifests', { envelope_id: created.id });
    const bytes = Buffer.from(manifestRow.canonical_bytes);
    assert.deepEqual(bytes, canonicalBytes(expectedManifest), 'the frozen bytes are the canonical module’s RFC 8785 form of the manifest');
    assert.deepEqual(parseJson(bytes.toString('utf8')), expectedManifest);
    assert.equal(sha256(bytes), prepared.manifest_digest, 'manifest_digest = SHA-256 of the frozen bytes');
    assert.equal(canonicalDigest(expectedManifest), prepared.manifest_digest);
    assert.equal(manifestRow.manifest_digest, prepared.manifest_digest);

    const preview = ctx.service.preview(req(ctx.tenant, SERVICE), created.id);
    assert.deepEqual(contractErrors('RecipientPreview', preview), [], 'the preview conforms to the contract');
    const recipients = [...createInput(2).recipients].map((r) => ({ ordinal: r.ordinal, role: r.role, email: r.email }));
    assert.equal(preview.recipients_digest, canonicalDigest(recipients), 'recipients_digest = SHA-256 of canonical [{ordinal, role, email}] in ordinal order');
    assert.equal(row(ctx, 'envelopes', { id: created.id }).recipients_digest, preview.recipients_digest);
    assert.equal(preview.manifest_digest, prepared.manifest_digest);
    assert.equal(preview.requires_human_confirmation, false);
    assert.equal(preview.version, prepared.version, 'a preview read leaves the version');

    const revision = row(ctx, 'document_revisions', { envelope_id: created.id });
    assert.equal(revision.frozen_at, ctx.time.now.toISOString(), 'the revision is frozen at prepare');
    assert.equal(revision.content_digest, document.digest);

    rejectsWith(() => ctx.service.uploadDocument(req(ctx.tenant), created.id, prepared.version, documentInput(1)), 'state_conflict', 409);
    rejectsWith(() => ctx.service.prepare(req(ctx.tenant), created.id, { expected_version: prepared.version, fields: fieldsFor(2) }), 'state_conflict', 409);
    assert.equal(ctx.service.read(req(ctx.tenant), created.id).version, prepared.version, 'edits after prepare are refused and change nothing');
  } finally {
    ctx.db.close();
  }
});

test('[ST-04] prepare refuses fields outside the document or page (field_out_of_bounds), broken field rules (invalid_request) and a missing document, freezing nothing', () => {
  const ctx = setup(scratch);
  try {
    const bare = ctx.service.create(req(ctx.tenant), createInput(1)).body;
    rejectsWith(() => ctx.service.prepare(req(ctx.tenant), bare.id, { expected_version: 1, fields: fieldsFor(1) }), 'state_conflict', 409);

    const two = ctx.service.create(req(ctx.tenant), createInput(2)).body;
    const uploaded = ctx.service.uploadDocument(req(ctx.tenant), two.id, two.version, documentInput(1)).body;
    const base = fieldsFor(2);
    const withField = (index, patch) => base.map((field, i) => (i === index ? { ...field, ...patch } : field));
    const cases = [
      ['x + width above 1', withField(0, { rect: { x: 0.8, y: 0.1, width: 0.3, height: 0.1 } }), 'field_out_of_bounds', 422],
      ['y + height above 1', withField(0, { rect: { x: 0.1, y: 0.95, width: 0.2, height: 0.1 } }), 'field_out_of_bounds', 422],
      ['a page the document does not have', withField(1, { page: 2 }), 'field_out_of_bounds', 422],
      ['duplicate keys', withField(1, { key: 'sig_1' }), 'invalid_request', 400],
      ['an upper-case key', withField(0, { key: 'Sig_1' }), 'invalid_request', 400],
      ['a recipient without a signature field', base.filter((field) => field.key !== 'sig_2'), 'invalid_request', 400],
      ['no fields', [], 'invalid_request', 400],
      ['an unknown field type', withField(1, { type: 'initials' }), 'invalid_request', 400],
    ];
    for (const [label, fields, code, status] of cases) {
      const error = rejectsWith(() => ctx.service.prepare(req(ctx.tenant), two.id, { expected_version: uploaded.version, fields }), code, status);
      assert.ok(error.details.length > 0, `${label}: the refusal names a field`);
    }
    const one = ctx.service.create(req(ctx.tenant), createInput(1)).body;
    const oneUploaded = ctx.service.uploadDocument(req(ctx.tenant), one.id, 1, documentInput(1)).body;
    rejectsWith(() => ctx.service.prepare(req(ctx.tenant), one.id, { expected_version: oneUploaded.version, fields: fieldsFor(2) }), 'invalid_request', 400);

    const after = ctx.service.read(req(ctx.tenant), two.id);
    assert.deepEqual([after.state, after.version, after.manifest_digest, after.fields], ['draft', uploaded.version, null, []], 'nothing was frozen');
    assert.equal(count(ctx, 'field_definitions'), 0);
    assert.equal(count(ctx, 'field_manifests'), 0);
    assert.equal(row(ctx, 'document_revisions', { envelope_id: two.id }).frozen_at, null);
  } finally {
    ctx.db.close();
  }
});

test('[ST-05] the version starts at 1 and moves by exactly 1 per successful upload, prepare and send; refusals, reads, confirmations and a failing hook leave it', () => {
  let failOn;
  const ctx = setup(scratch, {
    onChange: (change) => {
      if (change.operation === failOn) throw new Error('synthetic failure inside the mutation');
    },
  });
  try {
    const versionOf = (id) => row(ctx, 'envelopes', { id }).version;
    const created = ctx.service.create(req(ctx.tenant, SERVICE), createInput(1)).body;
    assert.equal(created.version, 1);
    const first = ctx.service.uploadDocument(req(ctx.tenant, SERVICE), created.id, 1, documentInput(1)).body;
    assert.equal(first.version, 2, 'upload adds 1');

    rejectsWith(() => ctx.service.uploadDocument(req(ctx.tenant, SERVICE), created.id, 1, documentInput(1)), 'version_conflict', 409);
    rejectsWith(() => ctx.service.uploadDocument(req(ctx.tenant, SERVICE), created.id, 3, documentInput(1)), 'version_conflict', 409);
    assert.equal(versionOf(created.id), 2, 'a stale or future expected version changes nothing');

    failOn = 'upload';
    assert.throws(() => ctx.service.uploadDocument(req(ctx.tenant, SERVICE), created.id, 2, documentInput(1)), /synthetic failure/);
    failOn = undefined;
    assert.equal(versionOf(created.id), 2, 'a failure inside the transaction rolls the upload back');
    assert.equal(count(ctx, 'document_revisions', { envelope_id: created.id }), 1);

    const replacement = documentInput(1, 'replacement');
    const second = ctx.service.uploadDocument(req(ctx.tenant, SERVICE), created.id, 2, replacement).body;
    assert.equal(second.version, 3, 'a replacing upload adds 1');
    assert.equal(second.document.digest, replacement.digest);

    const prepared = ctx.service.prepare(req(ctx.tenant, SERVICE), created.id, { expected_version: 3, fields: fieldsFor(1) }).body;
    assert.equal(prepared.version, 4, 'prepare adds 1');
    assert.equal(ctx.service.read(req(ctx.tenant), created.id).version, 4, 'a read leaves it');
    const preview = ctx.service.preview(req(ctx.tenant), created.id);
    const confirmation = ctx.service.confirmSend(req(ctx.tenant, HUMAN), created.id, {
      expected_version: 4,
      document_digest: preview.document.digest,
      manifest_digest: preview.manifest_digest,
      recipients_digest: preview.recipients_digest,
    }).body;
    assert.equal(versionOf(created.id), 4, 'a send confirmation changes neither state nor content, so it leaves the version');
    assert.equal(confirmation.envelope_version, 4);

    rejectsWith(() => ctx.service.send(req(ctx.tenant, SERVICE), created.id, { expected_version: 3, authorization_reference: confirmation.authorization_reference }), 'version_conflict', 409);
    const sent = ctx.service.send(req(ctx.tenant, SERVICE), created.id, { expected_version: 4, authorization_reference: confirmation.authorization_reference }).body;
    assert.equal(sent.version, 5, 'send adds 1');
    assert.equal(versionOf(created.id), 5);
    assert.deepEqual(
      ctx.changes.map((change) => [change.operation, change.version]),
      [['create', 1], ['upload', 2], ['upload', 3], ['upload', 3], ['prepare', 4], ['confirm-send', 4], ['send', 5]],
      'each committed change reports the version it wrote; the rolled-back upload was reported inside its transaction, then undone',
    );
  } finally {
    ctx.db.close();
  }
});
