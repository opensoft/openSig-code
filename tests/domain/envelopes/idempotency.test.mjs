// SPDX-License-Identifier: Apache-2.0
//
// Idempotency records (T007): scoped by tenant, route, principal and key; the
// same request replays the stored status and bytes; a changed request is
// idempotency_conflict (contract parameter Idempotency-Key). ST-13 proves the
// ratified response_body rules (data-model.md § IdempotencyRecord, A-010):
// byte-identical replay after the envelope has moved on, the 256 KiB bound
// that fails the transaction, the no-body mode for one-time secrets, and the
// 24-hour lifetime with a bounded purge that writes no DisposalRecord. The
// schema enforces the same bound for every writer (migration 0012, A-010
// IDEMP-B1).

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { EnvelopeService } from '../../../src/domain/envelopes/index.ts';
import { StorageUsageError } from '../../../src/storage/db/index.ts';
import {
  findIdempotencyRecord,
  IDEMPOTENCY_TTL_MS,
  IdempotencyBodyTooLarge,
  idempotencyRequestDigest,
  insertIdempotencyRecord,
  MAX_IDEMPOTENCY_BODY_BYTES,
  purgeExpiredIdempotencyRecords,
  recordedResponse,
} from '../../../src/storage/repositories/idempotency.ts';
import {
  createInput,
  documentInput,
  fieldsFor,
  hex,
  HUMAN,
  makeScratch,
  OTHER_HUMAN,
  rawConnection,
  refusedByTrigger,
  rejectsWith,
  req,
  setup,
  sha256,
} from './support.mjs';

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

// The ruled bounds, written out independently of the module under test.
const KIB = 1024;
const BODY_LIMIT = 256 * KIB;
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

function rows(ctx, table, where = {}) {
  return ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).list(table, where, { limit: 1000 }));
}

/** A record of the repository's own route space, with a body whose RFC 8785 form is exactly `size` bytes. */
function sizedRecord(ctx, key, size) {
  const body = { pad: 'a'.repeat(size - '{"pad":""}'.length) };
  return {
    route: 'syntheticRoute',
    principal: HUMAN,
    key,
    requestDigest: hex(`request-${key}`),
    responseStatus: 200,
    response: { kind: 'body', body },
    resourceId: null,
    createdAt: ctx.time.now.toISOString(),
  };
}

test('[ST-13] an exact replay after the envelope has moved on returns the stored status and byte-identical body, with no second mutation', () => {
  const ctx = setup(scratch);
  try {
    const created = ctx.service.create(req(ctx.tenant), createInput(1)).body;
    ctx.service.uploadDocument(req(ctx.tenant), created.id, 1, documentInput(1));
    const prepareKey = 'prepare-key-moved-on-001';
    const prepareRequest = { expected_version: 2, fields: fieldsFor(1) };
    const prepared = ctx.service.prepare(req(ctx.tenant, HUMAN, { key: prepareKey, request: prepareRequest }), created.id, prepareRequest);
    assert.equal(prepared.body.state, 'prepared');
    assert.equal(prepared.body.version, 3);

    const sendKey = 'send-key-moved-on-000001';
    const sendRequest = { expected_version: 3 };
    const sent = ctx.service.send(req(ctx.tenant, HUMAN, { key: sendKey, request: sendRequest }), created.id, sendRequest);
    assert.equal(sent.body.version, 4);
    const voided = ctx.service.void(req(ctx.tenant), created.id, { expected_version: 4, reason_code: 'sender-cancelled' }).body;
    assert.equal(voided.state, 'voided');
    assert.equal(voided.version, 5);

    const before = {
      envelope: rows(ctx, 'envelopes', { id: created.id }),
      recipients: rows(ctx, 'recipients', { envelope_id: created.id }),
      manifests: rows(ctx, 'field_manifests', { envelope_id: created.id }).length,
      fields: rows(ctx, 'field_definitions', { envelope_id: created.id }).length,
      records: rows(ctx, 'idempotency_records').length,
      changes: ctx.changes.length,
    };
    for (const [label, original, replay] of [
      ['prepare', prepared, () => ctx.service.prepare(req(ctx.tenant, HUMAN, { key: prepareKey, request: prepareRequest }), created.id, prepareRequest)],
      ['send', sent, () => ctx.service.send(req(ctx.tenant, HUMAN, { key: sendKey, request: sendRequest }), created.id, sendRequest)],
    ]) {
      const again = replay();
      assert.equal(again.replayed, true, `${label}: a replay`);
      assert.equal(again.status, original.status, `${label}: the stored status`);
      assert.equal(Buffer.compare(again.bytes, original.bytes), 0, `${label}: byte-identical to the original response`);
      assert.deepEqual(again.body, original.body);
      assert.notEqual(again.body.state, 'voided', `${label}: the original result, not the envelope as it is now`);
    }
    assert.deepEqual(rows(ctx, 'envelopes', { id: created.id }), before.envelope, 'no second mutation: the envelope row is unchanged (voided, version 5)');
    assert.deepEqual(rows(ctx, 'recipients', { envelope_id: created.id }), before.recipients, 'no recipient change');
    assert.equal(rows(ctx, 'field_manifests', { envelope_id: created.id }).length, before.manifests, 'no second manifest');
    assert.equal(rows(ctx, 'field_definitions', { envelope_id: created.id }).length, before.fields, 'no second field set');
    assert.equal(rows(ctx, 'idempotency_records').length, before.records, 'no second record');
    assert.equal(ctx.changes.length, before.changes, 'no change event');

    const stored = rows(ctx, 'idempotency_records', { route: 'prepareEnvelope', key: prepareKey })[0];
    assert.equal(Buffer.compare(Buffer.from(stored.response_body), prepared.bytes), 0, 'the record keeps exactly the bytes the client received');
    assert.equal(stored.response_body_digest, sha256(prepared.bytes));
    const record = ctx.db.transaction(() => findIdempotencyRecord(ctx.db.forTenant(ctx.tenant), 'prepareEnvelope', HUMAN.ref, prepareKey));
    assert.throws(() => recordedResponse({ ...record, responseBody: Buffer.from('{}') }), StorageUsageError, 'a body that no longer matches its digest is never replayed');
    assert.throws(() => recordedResponse({ ...record, responseBody: null }), StorageUsageError, 'a digest without its body is never read as the no-body mode');
  } finally {
    ctx.db.close();
  }
});

test('[ST-13] a response body over 256 KiB fails the transaction and is never truncated; a body of exactly 256 KiB is kept byte for byte', () => {
  const ctx = setup(scratch);
  try {
    assert.equal(MAX_IDEMPOTENCY_BODY_BYTES, BODY_LIMIT, 'the bound is 256 KiB');
    const atLimit = sizedRecord(ctx, 'body-at-limit-0000001', BODY_LIMIT);
    const kept = ctx.db.transaction(() => insertIdempotencyRecord(ctx.db.forTenant(ctx.tenant), atLimit));
    assert.equal(kept.length, BODY_LIMIT);
    const read = ctx.db.transaction(() => findIdempotencyRecord(ctx.db.forTenant(ctx.tenant), 'syntheticRoute', HUMAN.ref, 'body-at-limit-0000001'));
    const replayed = recordedResponse(read);
    assert.equal(replayed.kind, 'body');
    assert.equal(Buffer.compare(replayed.bytes, kept), 0, 'the replay returns the full stored body');

    const records = rows(ctx, 'idempotency_records').length;
    let caught;
    try {
      ctx.db.transaction(() => {
        const store = ctx.db.forTenant(ctx.tenant);
        insertIdempotencyRecord(store, sizedRecord(ctx, 'same-transaction-00001', 64));
        insertIdempotencyRecord(store, sizedRecord(ctx, 'body-over-limit-000001', BODY_LIMIT + 1));
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught instanceof IdempotencyBodyTooLarge, `expected IdempotencyBodyTooLarge, got ${caught}`);
    assert.equal(caught.code, 'idempotency_body_too_large');
    assert.equal(caught.bytes, BODY_LIMIT + 1);
    assert.equal(rows(ctx, 'idempotency_records').length, records, 'the whole transaction rolled back: neither record exists, and no truncated body');
    assert.throws(
      () => ctx.db.transaction(() => insertIdempotencyRecord(ctx.db.forTenant(ctx.tenant), sizedRecord(ctx, 'raised-limit-00000001', 64), BODY_LIMIT + 1)),
      StorageUsageError,
      'a caller can never raise the bound',
    );

    // Through the service: the oversized response fails the mutation with 500 internal and rolls it back.
    assert.throws(() => new EnvelopeService({ db: ctx.db, clock: ctx.time.clock, idempotencyBodyLimit: BODY_LIMIT + 1 }), TypeError, 'the service option can only lower the bound');
    const bounded = new EnvelopeService({ db: ctx.db, clock: ctx.time.clock, idempotencyBodyLimit: 64 });
    const envelopes = rows(ctx, 'envelopes').length;
    const input = createInput(1);
    const key = 'oversized-create-00001';
    rejectsWith(() => bounded.create(req(ctx.tenant, HUMAN, { key, request: input }), input), 'internal', 500);
    assert.equal(rows(ctx, 'envelopes').length, envelopes, 'the create rolled back with its record');
    assert.equal(rows(ctx, 'idempotency_records', { key }).length, 0, 'no record, so nothing truncated is ever replayed');

    const draft = ctx.service.create(req(ctx.tenant), input).body;
    const document = documentInput(1);
    const uploadKey = 'oversized-upload-00001';
    rejectsWith(() => bounded.uploadDocument(req(ctx.tenant, HUMAN, { key: uploadKey, request: { document: document.digest } }), draft.id, 1, document), 'internal', 500);
    assert.equal(ctx.service.read(req(ctx.tenant), draft.id).version, 1, 'the upload rolled back: the version is unchanged');
    assert.equal(rows(ctx, 'document_revisions', { envelope_id: draft.id }).length, 0, 'no revision');
    assert.equal(bounded.create(req(ctx.tenant), input).status, 201, 'without a key no record is kept, so the bound does not apply');
    const retried = ctx.service.create(req(ctx.tenant, HUMAN, { key, request: input }), input);
    assert.equal(retried.replayed, false, 'the failed request recorded nothing, so its retry runs as new');
  } finally {
    ctx.db.close();
  }
});

test('[ST-13] a route that reveals a one-time secret stores no body: the no-body mode keeps neither body nor digest and never replays a body', () => {
  const ctx = setup(scratch);
  try {
    const withheld = {
      route: 'createWebhookKey',
      principal: HUMAN,
      key: 'one-time-secret-000001',
      requestDigest: hex('webhook-key-request'),
      responseStatus: 201,
      response: { kind: 'withheld' },
      resourceId: null,
      createdAt: ctx.time.now.toISOString(),
    };
    assert.equal(ctx.db.transaction(() => insertIdempotencyRecord(ctx.db.forTenant(ctx.tenant), withheld)), null, 'nothing is returned as stored bytes');
    const [row] = rows(ctx, 'idempotency_records', { key: withheld.key });
    assert.equal(row.response_body, null, 'no body');
    assert.equal(row.response_body_digest, null, 'no body digest either');
    assert.equal(row.response_status, 201, 'the status is kept for the route to rule its replay');
    const record = ctx.db.transaction(() => findIdempotencyRecord(ctx.db.forTenant(ctx.tenant), withheld.route, HUMAN.ref, withheld.key));
    assert.deepEqual(recordedResponse(record), { kind: 'withheld' });
    assert.throws(
      () => ctx.db.transaction(() => insertIdempotencyRecord(ctx.db.forTenant(ctx.tenant), { ...withheld, key: 'unknown-mode-00000001', response: { kind: 'partial' } })),
      StorageUsageError,
      'the mode is explicit: a body or withheld, nothing else',
    );

    // Envelope responses carry no one-time secret: a withheld record on an envelope route is refused as internal, never answered.
    const input = createInput(1);
    const key = 'withheld-envelope-0001';
    ctx.db.transaction(() =>
      insertIdempotencyRecord(ctx.db.forTenant(ctx.tenant), {
        ...withheld,
        route: 'createEnvelope',
        key,
        requestDigest: idempotencyRequestDigest({ route: 'createEnvelope', target: null, request: input }),
      }),
    );
    rejectsWith(() => ctx.service.create(req(ctx.tenant, HUMAN, { key, request: input }), input), 'internal', 500);
    assert.equal(rows(ctx, 'envelopes').length, 0, 'no envelope was made');
    assert.equal(ctx.changes.length, 0, 'no change event');
  } finally {
    ctx.db.close();
  }
});

test('[ST-13] records live 24 hours: expired records are purged in bounded batches with no DisposalRecord, after which the same key and request is a new request', () => {
  const ctx = setup(scratch);
  try {
    assert.equal(IDEMPOTENCY_TTL_MS, DAY, 'the lifetime is 24 hours');
    const input = createInput(1);
    const keys = Array.from({ length: 5 }, (_, index) => `purge-key-${String(index).padStart(12, '0')}`);
    const originals = keys.map((key) => ctx.service.create(req(ctx.tenant, HUMAN, { key, request: input }), input));
    ctx.time.advance(12 * HOUR);
    const youngKey = 'young-key-000000000001';
    const young = ctx.service.create(req(ctx.tenant, HUMAN, { key: youngKey, request: input }), input);
    ctx.time.advance(12 * HOUR - 1);

    const purge = (batchSize) => ctx.db.transaction(() => purgeExpiredIdempotencyRecords(ctx.db.forTenant(ctx.tenant), ctx.time.now, batchSize));
    assert.equal(purge(2), 0, 'one millisecond short of 24 hours, nothing is expired');
    const early = ctx.service.create(req(ctx.tenant, HUMAN, { key: keys[0], request: input }), input);
    assert.equal(early.replayed, true, 'and the same request is still a replay');
    assert.equal(Buffer.compare(early.bytes, originals[0].bytes), 0);

    ctx.time.advance(1);
    const disposals = rows(ctx, 'disposal_records').length;
    const audit = rows(ctx, 'audit_events').length;
    assert.deepEqual([purge(2), purge(2), purge(2), purge(2)], [2, 2, 1, 0], 'at 24 hours the five old records go, at most two per batch');
    assert.deepEqual(
      rows(ctx, 'idempotency_records').map((row) => row.key),
      [youngKey],
      'the record younger than 24 hours stays',
    );
    assert.equal(rows(ctx, 'disposal_records').length, disposals, 'a purge writes no DisposalRecord');
    assert.equal(rows(ctx, 'audit_events').length, audit, 'and no audit event');
    for (const size of [0, 1001, 1.5]) {
      assert.throws(() => purge(size), StorageUsageError, `batch size ${size} is refused: every purge is bounded`);
    }

    const envelopes = rows(ctx, 'envelopes').length;
    const repeat = ctx.service.create(req(ctx.tenant, HUMAN, { key: keys[0], request: input }), input);
    assert.equal(repeat.replayed, false, 'after the purge the same key and request is a new request');
    assert.notEqual(repeat.body.id, originals[0].body.id);
    assert.equal(rows(ctx, 'envelopes').length, envelopes + 1, 'which makes a new envelope');
    const renewed = rows(ctx, 'idempotency_records', { key: keys[0] });
    assert.equal(renewed.length, 1);
    assert.equal(renewed[0].created_at, ctx.time.now.toISOString(), 'with a fresh 24-hour record');

    // A record past 24 hours that no purge has reached yet is not a replay either.
    ctx.time.advance(12 * HOUR);
    const changed = createInput(2);
    const late = ctx.service.create(req(ctx.tenant, HUMAN, { key: youngKey, request: changed }), changed);
    assert.equal(late.replayed, false, 'an expired, unpurged record neither replays nor conflicts');
    assert.notEqual(late.body.id, young.body.id);
    const replaced = rows(ctx, 'idempotency_records', { key: youngKey });
    assert.equal(replaced.length, 1, 'the expired record is replaced');
    assert.equal(replaced[0].request_digest, idempotencyRequestDigest({ route: 'createEnvelope', target: null, request: changed }));
  } finally {
    ctx.db.close();
  }
});

// SQLite extended result codes: a RAISE(ABORT) in a trigger, and a STRICT table's type check.
const SQLITE_CONSTRAINT_TRIGGER = 1811;
const SQLITE_CONSTRAINT_DATATYPE = 3091;

function thrown(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

test('[ST-13] the schema bounds response_body at 256 KiB for every writer (migration 0012): direct writes past 262,144 bytes are refused, on insert and on update', () => {
  const ctx = setup(scratch);
  const raw = rawConnection(ctx.path);
  try {
    const values = (key, body) => ({
      route: 'syntheticRoute',
      principal_kind: 'human-operator',
      principal_ref: HUMAN.ref,
      key,
      request_digest: hex(`request-${key}`),
      response_status: 200,
      response_body: body,
      response_body_digest: body === null ? null : sha256(Buffer.from(body)),
      created_at: ctx.time.now.toISOString(),
    });
    const stored = (key) => raw.prepare('SELECT length(response_body) AS bytes, typeof(response_body) AS type FROM idempotency_records WHERE key = ?').get(key);

    // A direct store insert (TenantStore, no repository) of 262,145 bytes: refused by the 0012 trigger.
    refusedByTrigger(
      ctx.db,
      () => ctx.db.forTenant(ctx.tenant).insert('idempotency_records', values('store-over-limit-00001', Buffer.alloc(BODY_LIMIT + 1, 0x61))),
      /response_body exceeds 262144 bytes/,
      'a direct store insert of 262,145 bytes is refused',
    );
    assert.equal(stored('store-over-limit-00001'), undefined);

    // Raw SQL on a second connection, bypassing the repository and the store.
    const insert = raw.prepare(
      'INSERT INTO idempotency_records (tenant_id, route, principal_kind, principal_ref, key, request_digest, response_status, response_body, response_body_digest, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    );
    const rawInsert = (key, body) => {
      const v = values(key, body);
      insert.run(ctx.tenant, v.route, v.principal_kind, v.principal_ref, v.key, v.request_digest, v.response_status, v.response_body, v.response_body_digest, v.created_at);
    };
    const over = thrown(() => rawInsert('raw-over-limit-000001', Buffer.alloc(BODY_LIMIT + 1, 0x61)));
    assert.equal(over?.errcode, SQLITE_CONSTRAINT_TRIGGER, `262,145 bytes: ${over}`);
    assert.match(over.message, /response_body exceeds 262144 bytes/);
    assert.equal(stored('raw-over-limit-000001'), undefined, 'nothing stored, nothing truncated');
    rawInsert('raw-at-limit-00000001', Buffer.alloc(BODY_LIMIT, 0x61));
    assert.deepEqual({ ...stored('raw-at-limit-00000001') }, { bytes: BODY_LIMIT, type: 'blob' }, 'exactly 262,144 bytes is accepted, whole');
    raw.prepare('INSERT INTO idempotency_records (tenant_id, route, principal_kind, principal_ref, key, request_digest, response_status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
      ctx.tenant,
      'syntheticRoute',
      'human-operator',
      HUMAN.ref,
      'raw-withheld-00000001',
      hex('request-withheld'),
      201,
      ctx.time.now.toISOString(),
    );
    assert.deepEqual({ ...stored('raw-withheld-00000001') }, { bytes: null, type: 'null' }, 'a NULL body (the withheld mode) passes');

    // TEXT: at most 262,144 characters but more than 262,144 bytes (87,382 three-byte characters).
    const text = '€'.repeat(87_382);
    assert.equal(text.length, 87_382);
    assert.equal(Buffer.byteLength(text, 'utf8'), 262_146);
    const textRefusal = thrown(() => rawInsert('raw-text-over-bytes01', text));
    assert.ok(
      textRefusal?.errcode === SQLITE_CONSTRAINT_DATATYPE || textRefusal?.errcode === SQLITE_CONSTRAINT_TRIGGER,
      `a TEXT body over 262,144 bytes is refused (${textRefusal?.errcode} ${textRefusal?.message})`,
    );
    assert.equal(stored('raw-text-over-bytes01'), undefined);
    // The table is STRICT, so its type check refuses any TEXT body first; the 0012 condition
    // itself counts bytes, not characters, as its stored SQL shows when evaluated on the value.
    assert.equal(raw.prepare("SELECT strict FROM pragma_table_list WHERE name = 'idempotency_records'").get().strict, 1);
    const condition = (name) => {
      const sql = raw.prepare("SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?").get(name)?.sql;
      assert.ok(sql, `trigger ${name} exists`);
      const when = /\bWHEN\b([\s\S]*?)\bBEGIN\b/i.exec(sql)?.[1];
      assert.ok(when, `trigger ${name} has a WHEN condition`);
      return raw.prepare(`SELECT (${when.replaceAll('NEW.response_body', '?1')}) AS fires`);
    };
    for (const name of ['idempotency_records_body_bound_insert', 'idempotency_records_body_bound_update']) {
      const fires = condition(name);
      assert.equal(raw.prepare('SELECT length(?) AS characters').get(text).characters, 87_382, 'a character count would let this value pass');
      assert.equal(fires.get(text).fires, 1, `${name}: fires on 87,382 characters of 262,146 bytes`);
      assert.equal(fires.get('a'.repeat(BODY_LIMIT)).fires, 0, `${name}: 262,144 one-byte characters pass`);
      assert.equal(fires.get(Buffer.alloc(BODY_LIMIT + 1)).fires, 1, `${name}: fires on 262,145 bytes`);
      assert.equal(fires.get(Buffer.alloc(BODY_LIMIT)).fires, 0, `${name}: 262,144 bytes pass`);
      assert.equal(fires.get(null).fires, 0, `${name}: NULL passes`);
    }

    // UPDATE: rows are immutable (0004), and 0012 bounds the column on update too. With 0004
    // present, an oversized update is answered first by 0012's update trigger, not by 0004 (both
    // abort with errcode 1811, so the first assertion holds whichever answers). Once 0004's
    // trigger is dropped on this scratch store, only 0012 can refuse, and its message is asserted.
    const update = raw.prepare('UPDATE idempotency_records SET response_body = ? WHERE key = ?');
    const updateOver = thrown(() => update.run(Buffer.alloc(BODY_LIMIT + 1, 0x62), 'raw-at-limit-00000001'));
    assert.equal(updateOver?.errcode, SQLITE_CONSTRAINT_TRIGGER, `an update to 262,145 bytes is refused: ${updateOver}`);
    raw.exec('DROP TRIGGER idempotency_records_immutable_update');
    const updateOnlyBound = thrown(() => update.run(Buffer.alloc(BODY_LIMIT + 1, 0x62), 'raw-at-limit-00000001'));
    assert.equal(updateOnlyBound?.errcode, SQLITE_CONSTRAINT_TRIGGER, `${updateOnlyBound}`);
    assert.match(updateOnlyBound.message, /response_body exceeds 262144 bytes/, 'the 0012 update trigger refuses 262,145 bytes');
    assert.deepEqual({ ...stored('raw-at-limit-00000001') }, { bytes: BODY_LIMIT, type: 'blob' }, 'the stored body is unchanged');
    update.run(Buffer.alloc(BODY_LIMIT, 0x62), 'raw-at-limit-00000001');
    assert.equal(raw.prepare('SELECT response_body FROM idempotency_records WHERE key = ?').get('raw-at-limit-00000001').response_body[0], 0x62, 'an update to exactly 262,144 bytes passes the bound');
  } finally {
    raw.close();
    ctx.db.close();
  }
});
