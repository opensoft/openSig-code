// SPDX-License-Identifier: Apache-2.0
//
// Idempotency records (T007): scoped by tenant, route, principal and key; the
// same request replays the stored status and bytes; a changed request is
// idempotency_conflict (contract parameter Idempotency-Key).

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { idempotencyRequestDigest } from '../../../src/storage/repositories/idempotency.ts';
import { createInput, documentInput, HUMAN, makeScratch, OTHER_HUMAN, refusedByTrigger, rejectsWith, req, setup, sha256 } from './support.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

function count(ctx, table, where = {}) {
  return ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).count(table, where));
}

function record(ctx, route, principalRef, key) {
  return ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).get('idempotency_records', { route, principal_ref: principalRef, key }));
}

test('[ST-06] the same Idempotency-Key with the same request replays the stored status and bytes, with no second mutation, version change or change event', () => {
  const ctx = setup(scratch);
  try {
    const key = 'create-key-000000000001';
    const input = createInput(1);
    const first = ctx.service.create(req(ctx.tenant, HUMAN, { key, request: input }), input);
    const events = ctx.changes.length;
    const replay = ctx.service.create(req(ctx.tenant, HUMAN, { key, request: input }), input);
    assert.equal(replay.replayed, true);
    assert.equal(replay.status, 201);
    assert.deepEqual(replay.bytes, first.bytes, 'the exact original bytes');
    assert.deepEqual(replay.body, first.body);
    assert.equal(count(ctx, 'envelopes'), 1, 'no second envelope');
    assert.equal(ctx.changes.length, events, 'no second change event');

    const stored = record(ctx, 'createEnvelope', HUMAN.ref, key);
    assert.equal(stored.principal_kind, 'human-operator');
    assert.equal(stored.request_digest, idempotencyRequestDigest({ route: 'createEnvelope', target: null, request: input }), 'request digest = SHA-256 of the RFC 8785 request');
    assert.equal(stored.response_status, 201);
    assert.deepEqual(Buffer.from(stored.response_body), first.bytes);
    assert.equal(stored.response_body_digest, sha256(first.bytes));
    assert.equal(stored.resource_id, first.body.id);

    const id = first.body.id;
    const uploadKey = 'upload-key-000000000001';
    const document = documentInput(1);
    const uploadRequest = { if_match: '"1"', document_digest: document.digest };
    const uploaded = ctx.service.uploadDocument(req(ctx.tenant, HUMAN, { key: uploadKey, request: uploadRequest }), id, 1, document);
    assert.equal(uploaded.body.version, 2);
    const uploadReplay = ctx.service.uploadDocument(req(ctx.tenant, HUMAN, { key: uploadKey, request: uploadRequest }), id, 1, document);
    assert.equal(uploadReplay.replayed, true);
    assert.deepEqual(uploadReplay.bytes, uploaded.bytes);
    assert.equal(ctx.service.read(req(ctx.tenant), id).version, 2, 'a replay leaves the version');
    assert.equal(count(ctx, 'document_revisions', { envelope_id: id }), 1, 'no second revision');

    const later = ctx.service.create(req(ctx.tenant, HUMAN, { key, request: input }), input);
    assert.equal(later.body.version, 1, 'the replay is the original result, not the envelope as it is now');
  } finally {
    ctx.db.close();
  }
});

test('[ST-06] a changed request under the same key is idempotency_conflict; keys are scoped by route, principal and target; refused requests record nothing', () => {
  const ctx = setup(scratch);
  try {
    const key = 'shared-key-000000000001';
    const input = createInput(1);
    const first = ctx.service.create(req(ctx.tenant, HUMAN, { key, request: input }), input).body;
    const changed = createInput(2);
    rejectsWith(() => ctx.service.create(req(ctx.tenant, HUMAN, { key, request: changed }), changed), 'idempotency_conflict', 409);
    assert.equal(count(ctx, 'envelopes'), 1, 'the changed request made no envelope');

    const other = ctx.service.create(req(ctx.tenant, OTHER_HUMAN, { key, request: input }), input);
    assert.equal(other.replayed, false, 'another principal with the same key is a separate scope');
    assert.notEqual(other.body.id, first.id);
    rejectsWith(
      () => ctx.service.create(req(ctx.tenant, { kind: 'service', ref: HUMAN.ref }, { key, request: input }), input),
      'idempotency_conflict',
      409,
    );

    const document = documentInput(1);
    const uploaded = ctx.service.uploadDocument(req(ctx.tenant, HUMAN, { key, request: { document: document.digest } }), first.id, 1, document);
    assert.equal(uploaded.replayed, false, 'the same key on another route is a separate scope');
    const second = ctx.service.create(req(ctx.tenant), createInput(1)).body;
    rejectsWith(
      () => ctx.service.uploadDocument(req(ctx.tenant, HUMAN, { key, request: { document: document.digest } }), second.id, 1, document),
      'idempotency_conflict',
      409,
    );
    assert.equal(ctx.service.read(req(ctx.tenant), second.id).version, 1, 'the same key and route on another envelope changes nothing');

    const records = count(ctx, 'idempotency_records');
    const stale = { expected_version: 1, fields: [] };
    for (let attempt = 0; attempt < 2; attempt += 1) {
      rejectsWith(() => ctx.service.prepare(req(ctx.tenant, HUMAN, { key: 'prepare-key-00000000001', request: stale }), first.id, stale), 'version_conflict', 409);
    }
    assert.equal(count(ctx, 'idempotency_records'), records, 'a refused request records nothing, so its retry runs again and is refused again');
    rejectsWith(() => ctx.service.create(req(ctx.tenant, HUMAN, { key: 'too-short', request: input }), input), 'invalid_request', 400);
    refusedByTrigger(
      ctx.db,
      () =>
        ctx.db.forTenant(ctx.tenant).insert('idempotency_records', {
          route: 'createEnvelope',
          principal_kind: 'human-operator',
          principal_ref: HUMAN.ref,
          key: 'body-without-digest-01',
          request_digest: sha256(Buffer.from('request')),
          response_status: 201,
          response_body: Buffer.from('{}'),
          created_at: ctx.time.now.toISOString(),
        }),
      /response_body_digest/,
      'a stored body always carries its digest (0011)',
    );
  } finally {
    ctx.db.close();
  }
});
