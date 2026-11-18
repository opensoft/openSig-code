// SPDX-License-Identifier: Apache-2.0
//
// Shared helpers for the envelope domain tests (T007). Every value is
// synthetic and generated at run time: identifiers are random, addresses use
// example.test, digests hash fixed labels, and no capability value exists.

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import { EnvelopeError, EnvelopeService } from '../../../src/domain/envelopes/index.ts';
import { StorageConstraintError } from '../../../src/storage/db/index.ts';
import { loadVendoredContract } from '../../contract/envelopes/lib/contract.mjs';
import { validate } from '../../contract/envelopes/lib/schema.mjs';
import { BASE_TIME, createTenant, envelopeRow, hex, makeScratch, openTemp, sid, ts } from '../../storage/support/fixtures.mjs';

export { BASE_TIME, createTenant, envelopeRow, hex, makeScratch, openTemp, sid, ts };

/** The ruled graph, written out independently of the module under test (spec ce4b55a). */
export const RULED_GRAPH = Object.freeze({
  draft: ['prepared', 'voided', 'expired'],
  prepared: ['sent', 'voided', 'expired'],
  sent: ['in-progress', 'finalizing', 'declined', 'voided', 'expired'],
  'in-progress': ['finalizing', 'declined', 'voided', 'expired'],
  finalizing: ['completed'],
  completed: [],
  declined: [],
  expired: [],
  voided: [],
});

export const HUMAN = Object.freeze({ kind: 'human-operator', ref: 'operator-1' });
export const OTHER_HUMAN = Object.freeze({ kind: 'human-operator', ref: 'operator-2' });
export const SERVICE = Object.freeze({ kind: 'service', ref: 'hermes-service' });

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** A clock the test moves: { clock, advance(ms), set(ms) }. */
export function testClock(start = BASE_TIME) {
  const state = { now: start };
  return {
    clock: () => new Date(state.now),
    advance(ms) {
      state.now += ms;
    },
    get now() {
      return new Date(state.now);
    },
  };
}

/**
 * A migrated database with one tenant and an envelope service on a test clock.
 * `busyTimeoutMs` overrides the scratch database's bounded wait for the write lock.
 */
export function setup(scratch, { onChange, tenants = 1, busyTimeoutMs } = {}) {
  const { db, path } = openTemp(scratch, busyTimeoutMs === undefined ? {} : { busyTimeoutMs });
  const ids = [];
  for (let i = 0; i < tenants; i += 1) {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    ids.push(tenant);
  }
  const time = testClock();
  const changes = [];
  const service = new EnvelopeService({
    db,
    clock: time.clock,
    onChange: (change, store) => {
      changes.push(change);
      onChange?.(change, store);
    },
  });
  return { db, path, tenant: ids[0], tenants: ids, time, service, changes };
}

export function req(tenantId, actor = HUMAN, idempotency) {
  return idempotency === undefined ? { tenantId, actor } : { tenantId, actor, idempotency };
}

export function createInput(recipients = 1, overrides = {}) {
  const list = [{ email: 'signer.one@example.test', role: 'approver', ordinal: 1 }];
  if (recipients === 2) list.push({ email: 'signer.two@example.test', role: 'countersigner', ordinal: 2 });
  return { source: { app: 'manual', record: 'synthetic-record-0001', version: 'v1' }, recipients: list, ...overrides };
}

export function documentInput(pages = 1, label = 'document') {
  return {
    digest: hex(`${label}-${randomBytes(4).toString('hex')}`),
    bytes: 2048,
    pages: Array.from({ length: pages }, (_, index) => ({ number: index + 1, width: 612, height: 792, rotate: index % 2 === 0 ? 0 : 90 })),
    parseReport: { pages, network_sandbox: 'netns+fs-enforced (local)' },
  };
}

export function fieldsFor(recipients = 1) {
  const fields = [
    { key: 'sig_1', recipient_ordinal: 1, page: 1, type: 'signature', rect: { x: 0.1, y: 0.8, width: 0.3, height: 0.08 } },
    { key: 'date_1', recipient_ordinal: 1, page: 1, type: 'date', rect: { x: 0.45, y: 0.8, width: 0.2, height: 0.05 } },
  ];
  if (recipients === 2) fields.push({ key: 'sig_2', recipient_ordinal: 2, page: 1, type: 'signature', rect: { x: 0.1, y: 0.9, width: 0.3, height: 0.08 } });
  return fields;
}

/** Create (as `creator`), upload and prepare; returns the prepared view. */
export function preparedEnvelope(ctx, { recipients = 1, creator = HUMAN, pages = 1 } = {}) {
  const created = ctx.service.create(req(ctx.tenant, creator), createInput(recipients)).body;
  const uploaded = ctx.service.uploadDocument(req(ctx.tenant, creator), created.id, created.version, documentInput(pages)).body;
  return ctx.service.prepare(req(ctx.tenant, creator), created.id, { expected_version: uploaded.version, fields: fieldsFor(recipients) }).body;
}

/** A human-created envelope taken to sent. */
export function sentEnvelope(ctx, { recipients = 1 } = {}) {
  const prepared = preparedEnvelope(ctx, { recipients });
  return ctx.service.send(req(ctx.tenant, HUMAN), prepared.id, { expected_version: prepared.version }).body;
}

/** Assert that `fn` throws an EnvelopeError with `code` (and its contract status). */
export function rejectsWith(fn, code, status) {
  let caught;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  assert.ok(caught instanceof EnvelopeError, `expected an EnvelopeError ${code}, got ${caught === undefined ? 'no error' : caught}`);
  assert.equal(caught.code, code);
  if (status !== undefined) assert.equal(caught.status, status);
  return caught;
}

/** Assert that `fn`, run in a transaction, is refused by a schema trigger whose message matches `pattern`. */
export function refusedByTrigger(db, fn, pattern, label) {
  assert.throws(
    () => db.transaction(fn),
    (error) => error instanceof StorageConstraintError && error.constraint === 'trigger' && pattern.test(error.message),
    label,
  );
}

let contract;
/** Validate a view against a schema of the vendored contract; returns the error list. */
export function contractErrors(schemaName, value) {
  contract ??= loadVendoredContract().doc;
  const schema = contract.components.schemas[schemaName];
  assert.ok(schema, `the contract defines ${schemaName}`);
  return validate(contract, schema, value);
}

/** A raw connection to the same database file (triggers intact, as any writer would have). */
export function rawConnection(path) {
  return new DatabaseSync(path);
}

/** A consent text of the tenant, for synthetic approvals. */
export function insertConsent(db, tenant) {
  const text = 'I approve this synthetic document.';
  const consent = { id: sid('consent'), version: '2026.11', digest: sha256(Buffer.from(text, 'utf8')) };
  db.transaction(() =>
    db.forTenant(tenant).insert('consent_texts', {
      id: consent.id,
      version: consent.version,
      locale: 'en',
      text,
      text_digest: consent.digest,
      effective_from: ts(0),
      created_at: ts(0),
    }),
  );
  return consent;
}

/** A synthetic Approval row (T010 writes real ones); returns { id, digest }. */
export function insertApproval(store, { envelope, recipientId, consent, prior = null, serverTime }) {
  const id = sid('appr');
  const digest = hex(`approval-${id}`);
  store.insert('approvals', {
    id,
    envelope_id: envelope.id,
    recipient_id: recipientId,
    document_digest: envelope.document.digest,
    manifest_digest: envelope.manifest_digest,
    prior_approval_digest: prior,
    consent_text_id: consent.id,
    consent_version: consent.version,
    consent_text_digest: consent.digest,
    field_values_json: '[]',
    field_values_digest: hex(`field-values-${id}`),
    assurance_method: 'mailbox-challenge',
    assurance_level: 'mailbox-control',
    server_time: serverTime,
    approval_digest: digest,
  });
  return { id, digest };
}

/** Approve as `recipient` (insert the Approval, then advance the state machine) in one transaction. */
export function approve(ctx, envelope, recipient, consent, prior = null) {
  return ctx.db.transaction(() => {
    const store = ctx.db.forTenant(ctx.tenant);
    const approval = insertApproval(store, { envelope, recipientId: recipient.id, consent, prior, serverTime: ctx.time.now.toISOString() });
    const outcome = ctx.service.advanceOnApproval(store, { envelopeId: envelope.id, expectedVersion: envelope.version, recipientId: recipient.id, approvalId: approval.id });
    return { approval, outcome };
  });
}

/**
 * Advance without inserting an Approval: the domain's own turn and state checks
 * refuse before any write, so this proves them independently of the schema's
 * approval-order trigger.
 */
export function advanceOnly(ctx, envelope, recipient) {
  return ctx.db.transaction(() =>
    ctx.service.advanceOnApproval(ctx.db.forTenant(ctx.tenant), {
      envelopeId: envelope.id,
      expectedVersion: envelope.version,
      recipientId: recipient.id,
      approvalId: sid('appr'),
    }),
  );
}
