// SPDX-License-Identifier: Apache-2.0
//
// Void, expiry, reissue and tenant isolation (T007): void and expiry win only
// before the finalization reservation and revoke outstanding capabilities;
// reissue starts a linked draft that copies source, recipients and document,
// never approvals; another tenant's envelope is uniformly not found.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, test } from 'node:test';

import { compareAndSetEnvelope, setRecipientProgress } from '../../../src/storage/repositories/envelopes.ts';
import {
  approve,
  contractErrors,
  createInput,
  documentInput,
  fieldsFor,
  hex,
  HUMAN,
  insertConsent,
  makeScratch,
  preparedEnvelope,
  rejectsWith,
  req,
  sentEnvelope,
  SERVICE,
  setup,
  sid,
} from './support.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

const HOUR = 60 * 60 * 1000;

function get(ctx, table, where, tenant = ctx.tenant) {
  return ctx.db.transaction(() => ctx.db.forTenant(tenant).get(table, where));
}

/** Synthetic outstanding capabilities of recipient 1: an invitation and a session (hashes of random labels only). */
function insertCapabilities(ctx, envelope) {
  const now = ctx.time.now.toISOString();
  const recipient = envelope.recipients[0];
  const revision = get(ctx, 'document_revisions', { envelope_id: envelope.id, content_digest: envelope.document.digest });
  const ids = { invitation: sid('inv'), session: sid('ses') };
  ctx.db.transaction(() => {
    const store = ctx.db.forTenant(ctx.tenant);
    store.insert('invitations', {
      id: ids.invitation,
      envelope_id: envelope.id,
      recipient_id: recipient.id,
      revision_id: revision.id,
      manifest_digest: envelope.manifest_digest,
      token_hash: hex(`invitation-${randomBytes(8).toString('hex')}`),
      sent_at: now,
      expires_at: new Date(ctx.time.now.getTime() + 7 * 24 * HOUR).toISOString(),
    });
    store.insert('recipient_sessions', {
      id: ids.session,
      value_hash: hex(`session-${randomBytes(8).toString('hex')}`),
      envelope_id: envelope.id,
      recipient_id: recipient.id,
      revision_id: revision.id,
      manifest_digest: envelope.manifest_digest,
      csrf_secret: randomBytes(32),
      created_at: now,
      last_seen_at: now,
    });
  });
  return ids;
}

const VOID = (version) => ({ expected_version: version, reason_code: 'sender-cancelled' });

test('[ST-08] void (human operators only) wins before the reservation, revokes recipients, invitations and sessions, and is refused after reservation', () => {
  const ctx = setup(scratch);
  try {
    const draft = ctx.service.create(req(ctx.tenant), createInput(1)).body;
    const voidedDraft = ctx.service.void(req(ctx.tenant), draft.id, VOID(1)).body;
    assert.deepEqual([voidedDraft.state, voidedDraft.version], ['voided', 2]);
    assert.deepEqual(voidedDraft.recipients.map((r) => r.status), ['revoked']);
    assert.deepEqual(contractErrors('Envelope', voidedDraft), []);

    const sent = sentEnvelope(ctx);
    const ids = insertCapabilities(ctx, sent);
    rejectsWith(() => ctx.service.void(req(ctx.tenant, SERVICE), sent.id, VOID(sent.version)), 'forbidden', 403);
    rejectsWith(() => ctx.service.void(req(ctx.tenant), sent.id, VOID(sent.version - 1)), 'version_conflict', 409);
    rejectsWith(() => ctx.service.void(req(ctx.tenant), sent.id, { expected_version: sent.version, reason_code: 'bored' }), 'invalid_request', 400);
    const voided = ctx.service.void(req(ctx.tenant), sent.id, VOID(sent.version)).body;
    assert.deepEqual([voided.state, voided.version], ['voided', sent.version + 1]);
    assert.deepEqual(voided.recipients.map((r) => r.status), ['revoked']);
    const now = ctx.time.now.toISOString();
    assert.equal(get(ctx, 'invitations', { id: ids.invitation }).revoked_at, now, 'the outstanding invitation is revoked');
    assert.equal(get(ctx, 'recipient_sessions', { id: ids.session }).revoked_at, now, 'the outstanding session is revoked');
    rejectsWith(() => ctx.service.void(req(ctx.tenant), sent.id, VOID(voided.version)), 'state_conflict', 409);

    const consent = insertConsent(ctx.db, ctx.tenant);
    const reserved = sentEnvelope(ctx);
    approve(ctx, reserved, reserved.recipients[0], consent);
    const finalizing = ctx.service.read(req(ctx.tenant), reserved.id);
    assert.equal(finalizing.state, 'finalizing');
    rejectsWith(() => ctx.service.void(req(ctx.tenant), reserved.id, VOID(finalizing.version)), 'state_conflict', 409);
    assert.deepEqual(
      [ctx.service.read(req(ctx.tenant), reserved.id).state, ctx.service.read(req(ctx.tenant), reserved.id).version],
      ['finalizing', finalizing.version],
      'after reservation void changes nothing',
    );
  } finally {
    ctx.db.close();
  }
});

test('[ST-08] a request that finds expires_at passed before reservation expires the envelope and is refused; the sweeper step expires only what is due', () => {
  const ctx = setup(scratch);
  try {
    const soon = (ms) => createInput(1, { expires_at: new Date(ctx.time.now.getTime() + ms).toISOString() });
    const draft = ctx.service.create(req(ctx.tenant), soon(HOUR)).body;
    const sent = (() => {
      const created = ctx.service.create(req(ctx.tenant), soon(HOUR)).body;
      ctx.service.uploadDocument(req(ctx.tenant), created.id, 1, documentInput(1));
      ctx.service.prepare(req(ctx.tenant), created.id, { expected_version: 2, fields: fieldsFor(1) });
      return ctx.service.send(req(ctx.tenant), created.id, { expected_version: 3 }).body;
    })();
    const ids = insertCapabilities(ctx, sent);
    const lasting = ctx.service.create(req(ctx.tenant), createInput(1)).body;
    const consent = insertConsent(ctx.db, ctx.tenant);
    const reserved = (() => {
      const created = ctx.service.create(req(ctx.tenant), soon(HOUR)).body;
      ctx.service.uploadDocument(req(ctx.tenant), created.id, 1, documentInput(1));
      ctx.service.prepare(req(ctx.tenant), created.id, { expected_version: 2, fields: fieldsFor(1) });
      const view = ctx.service.send(req(ctx.tenant), created.id, { expected_version: 3 }).body;
      approve(ctx, view, view.recipients[0], consent);
      return view;
    })();

    ctx.time.advance(2 * HOUR);
    rejectsWith(() => ctx.service.uploadDocument(req(ctx.tenant), draft.id, 1, documentInput(1)), 'state_conflict', 409);
    const expired = ctx.service.read(req(ctx.tenant), draft.id);
    assert.deepEqual([expired.state, expired.version], ['expired', 2], 'the expiry is committed although the request is refused');
    assert.deepEqual(expired.recipients.map((r) => r.status), ['expired']);
    const expiry = ctx.changes.at(-1);
    assert.deepEqual([expiry.operation, expiry.from, expiry.to, expiry.actor], ['expire', 'draft', 'expired', null]);

    assert.equal(ctx.service.expireIfDue(ctx.tenant, sent.id), true);
    const sweptView = ctx.service.read(req(ctx.tenant), sent.id);
    assert.deepEqual([sweptView.state, sweptView.version], ['expired', sent.version + 1]);
    assert.deepEqual(sweptView.recipients.map((r) => r.status), ['expired']);
    assert.equal(get(ctx, 'invitations', { id: ids.invitation }).revoked_at, ctx.time.now.toISOString(), 'expiry revokes the invitation');
    assert.equal(get(ctx, 'recipient_sessions', { id: ids.session }).revoked_at, ctx.time.now.toISOString(), 'and the session');
    assert.equal(ctx.service.expireIfDue(ctx.tenant, sent.id), false, 'already expired');
    assert.equal(ctx.service.expireIfDue(ctx.tenant, lasting.id), false, 'not due');
    assert.equal(ctx.service.expireIfDue(ctx.tenant, reserved.id), false, 'after reservation, expiry no longer wins');
    assert.equal(ctx.service.read(req(ctx.tenant), reserved.id).state, 'finalizing');
  } finally {
    ctx.db.close();
  }
});

test('[ST-08] reissue (human operators only) inserts a linked draft that copies source, recipients and document but never approvals or fields', () => {
  const ctx = setup(scratch);
  try {
    const prepared = preparedEnvelope(ctx, { recipients: 2 });
    const voided = ctx.service.void(req(ctx.tenant), prepared.id, VOID(prepared.version)).body;
    rejectsWith(() => ctx.service.reissue(req(ctx.tenant, SERVICE), prepared.id, { expected_version: voided.version }), 'forbidden', 403);
    rejectsWith(() => ctx.service.reissue(req(ctx.tenant), prepared.id, { expected_version: voided.version - 1 }), 'version_conflict', 409);
    const reissued = ctx.service.reissue(req(ctx.tenant), prepared.id, { expected_version: voided.version });
    assert.equal(reissued.status, 201);
    const fresh = reissued.body;
    assert.deepEqual(contractErrors('Envelope', fresh), []);
    assert.equal(fresh.reissue_of, prepared.id);
    assert.equal(fresh.state, 'draft');
    assert.equal(fresh.version, 2, 'inserted as draft at version 1, then the copied document attached as an upload (+1)');
    assert.deepEqual(fresh.document, prepared.document, 'the document is copied');
    assert.deepEqual(fresh.source, prepared.source);
    assert.deepEqual(fresh.created_by, HUMAN);
    assert.deepEqual([fresh.fields, fresh.manifest_digest, fresh.approvals_complete], [[], null, false], 'fields and freeze are not copied');
    assert.deepEqual(fresh.recipients.map((r) => [r.ordinal, r.role, r.email, r.status]), prepared.recipients.map((r) => [r.ordinal, r.role, r.email, 'pending']));
    for (const [index, recipient] of fresh.recipients.entries()) assert.notEqual(recipient.id, prepared.recipients[index].id, 'new recipient ids');
    const prior = ctx.service.read(req(ctx.tenant), prepared.id);
    assert.deepEqual([prior.state, prior.version, prior.reissued_as], ['voided', voided.version + 1, fresh.id]);

    rejectsWith(() => ctx.service.reissue(req(ctx.tenant), prepared.id, { expected_version: prior.version }), 'state_conflict', 409);
    const live = preparedEnvelope(ctx);
    rejectsWith(() => ctx.service.reissue(req(ctx.tenant), live.id, { expected_version: live.version }), 'state_conflict', 409);

    // A declined envelope with an approval: the reissue copies no approval.
    const consent = insertConsent(ctx.db, ctx.tenant);
    const sent = sentEnvelope(ctx, { recipients: 2 });
    approve(ctx, sent, sent.recipients[0], consent);
    const progressing = ctx.service.read(req(ctx.tenant), sent.id);
    ctx.db.transaction(() => {
      const store = ctx.db.forTenant(ctx.tenant);
      const now = ctx.time.now.toISOString();
      setRecipientProgress(store, progressing.recipients[1].id, { status: 'declined', updatedAt: now });
      assert.equal(compareAndSetEnvelope(store, sent.id, progressing.version, { state: 'declined', updatedAt: now }), true);
    });
    const declined = ctx.service.read(req(ctx.tenant), sent.id);
    assert.equal(declined.state, 'declined');
    const again = ctx.service.reissue(req(ctx.tenant), sent.id, { expected_version: declined.version }).body;
    assert.deepEqual(again.recipients.map((r) => [r.status, r.approval_digest, r.approved_at]), [['pending', null, null], ['pending', null, null]]);
    assert.equal(ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).count('approvals', { envelope_id: again.id })), 0, 'no approval is copied');
    assert.equal(ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).count('approvals', { envelope_id: sent.id })), 1, 'the prior approval stays');

    const bare = ctx.service.create(req(ctx.tenant), createInput(1)).body;
    const bareVoided = ctx.service.void(req(ctx.tenant), bare.id, VOID(1)).body;
    const bareAgain = ctx.service.reissue(req(ctx.tenant), bare.id, { expected_version: bareVoided.version }).body;
    assert.deepEqual([bareAgain.version, bareAgain.document], [1, null], 'without a document the reissue stays at version 1');
  } finally {
    ctx.db.close();
  }
});

test('[ST-08] another tenant’s envelope is uniformly not found for every operation, and a malformed id is invalid_request', () => {
  const ctx = setup(scratch, { tenants: 2 });
  try {
    const [a, b] = ctx.tenants;
    const prepared = preparedEnvelope(ctx);
    const id = prepared.id;
    const v = prepared.version;
    const preview = ctx.service.preview(req(a), id);
    const confirm = { expected_version: v, document_digest: preview.document.digest, manifest_digest: preview.manifest_digest, recipients_digest: preview.recipients_digest };
    const operations = [
      ['read', () => ctx.service.read(req(b), id)],
      ['preview', () => ctx.service.preview(req(b), id)],
      ['upload', () => ctx.service.uploadDocument(req(b), id, v, documentInput(1))],
      ['prepare', () => ctx.service.prepare(req(b), id, { expected_version: v, fields: fieldsFor(1) })],
      ['confirmSend', () => ctx.service.confirmSend(req(b), id, confirm)],
      ['send', () => ctx.service.send(req(b), id, { expected_version: v })],
      ['void', () => ctx.service.void(req(b), id, VOID(v))],
      ['reissue', () => ctx.service.reissue(req(b), id, { expected_version: v })],
      ['expireIfDue', () => ctx.service.expireIfDue(b, id)],
    ];
    for (const [label, operation] of operations) {
      const error = rejectsWith(operation, 'not_found', 404);
      assert.equal(error.message, 'the envelope was not found', `${label}: the same generic message`);
    }
    const unchanged = ctx.service.read(req(a), id);
    assert.deepEqual([unchanged.state, unchanged.version], ['prepared', v], 'tenant A’s envelope is untouched');
    rejectsWith(() => ctx.service.read(req(a), 'short-id'), 'invalid_request', 400);
    rejectsWith(() => ctx.service.void(req(a), 'not/an/id-000000000', VOID(v)), 'invalid_request', 400);
  } finally {
    ctx.db.close();
  }
});
