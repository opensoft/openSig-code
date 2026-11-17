// SPDX-License-Identifier: Apache-2.0
//
// The appended P04 migration (T007; A-008 P04, A-010 rulings) enforced by the
// schema itself, below the domain: recipients and field definitions freeze
// once the envelope leaves draft (ST-09), the version moves only by exactly
// one and every change of state or content needs that step (ST-10), every
// UPDATE that changes state follows the transition graph (ST-11), and inserts
// are not governed by the graph while the domain inserts only draft at
// version 1 (ST-12).

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { StorageConstraintError } from '../../../src/storage/db/index.ts';
import { loadMigrations } from '../../../src/storage/schema/migrations.ts';
import {
  createInput,
  envelopeRow,
  hex,
  makeScratch,
  preparedEnvelope,
  rawConnection,
  refusedByTrigger,
  rejectsWith,
  req,
  RULED_GRAPH,
  setup,
  sid,
  ts,
} from './support.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

/** Migrations appended by T007; their digests are pinned, so they too can only be followed, never edited. */
const PINNED_T007_MIGRATIONS = Object.freeze([
  { version: 10, name: '0010-envelope-freeze-version-graph.sql', sha256: 'b52503d539f794ecfddd44d2c9638a78fa16268bfd5c5f369aa072086aeca57d' },
  { version: 11, name: '0011-idempotency-response-body.sql', sha256: 'adf11be692fe9ef40b0484334696f85c4ea5001431e7ce71d4beab3d77737c1c' },
  { version: 12, name: '0012-idempotency-body-bound.sql', sha256: '3d5460527f5e7595122194567c79bf3cd8327002dcf403854431761a8ddf332c' },
]);

const STATES = Object.keys(RULED_GRAPH);
const FULLY_APPROVED = ['finalizing', 'completed'];
const LEGAL_WALKS = Object.freeze({
  draft: [],
  prepared: ['prepared'],
  sent: ['prepared', 'sent'],
  'in-progress': ['prepared', 'sent', 'in-progress'],
  finalizing: ['prepared', 'sent', 'finalizing'],
  completed: ['prepared', 'sent', 'finalizing', 'completed'],
  declined: ['prepared', 'sent', 'declined'],
  expired: ['expired'],
  voided: ['voided'],
});
const ROLLBACK = Symbol('rollback');
const GRAPH = /not in the state graph/;
const VERSION = /version must be old \+ 1/;
const FROZEN = /frozen/;

/** A storage-level envelope with an (unfrozen) revision, walked to `state` by legal compare-and-sets. */
function envelopeIn(db, tenant, state) {
  const store = db.forTenant(tenant);
  const id = sid('env');
  const revision = sid('rev');
  const content = { base_revision_id: revision, manifest_digest: hex(`manifest-${id}`), recipients_digest: hex(`recipients-${id}`) };
  db.transaction(() => {
    store.insert('envelopes', envelopeRow(id));
    store.insert('document_revisions', {
      id: revision,
      envelope_id: id,
      content_digest: hex(`document-${id}`),
      blob_ref: `tenants/${tenant}/sha256/${hex(`document-${id}`)}`,
      bytes: 2048,
      pages: 1,
      page_geometry_json: '[]',
      parse_report_json: '{}',
      created_at: ts(1),
    });
    LEGAL_WALKS[state].forEach((step, index) => {
      const values = { state: step, updated_at: ts(2 + index), ...(index === 0 ? content : {}), ...(step === 'finalizing' ? { approvals_complete: 1 } : {}) };
      assert.equal(store.compareAndSet('envelopes', { id }, index + 1, values), true, `walk ${state}: ${step}`);
    });
  });
  return { id, revision, content, version: LEGAL_WALKS[state].length + 1 };
}

/** Run `fn` in a transaction that always rolls back; returns 'ok', or the constraint error message. */
function attempt(db, fn) {
  let outcome;
  try {
    db.transaction(() => {
      outcome = fn() === false ? 'cas-lost' : 'ok';
      throw ROLLBACK;
    });
  } catch (error) {
    if (error === ROLLBACK) return outcome;
    if (error instanceof StorageConstraintError) return `${error.constraint}: ${error.message}`;
    throw error;
  }
  throw new Error('unreachable');
}

function rawRefuses(path, sql, params, pattern) {
  const raw = rawConnection(path);
  try {
    assert.throws(() => raw.prepare(sql).run(...params), (error) => pattern.test(String(error.message)), sql);
  } finally {
    raw.close();
  }
}

function rawRun(path, sql, params) {
  const raw = rawConnection(path);
  try {
    return raw.prepare(sql).run(...params).changes;
  } finally {
    raw.close();
  }
}

test('[ST-09] recipients and field definitions freeze once the envelope leaves draft; status progress stays possible; prepared content and identity are frozen', () => {
  const ctx = setup(scratch);
  try {
    const { db, tenant } = ctx;
    const store = db.forTenant(tenant);
    const recipientRow = (envelopeId, ordinal) => ({ id: sid('rcpt'), envelope_id: envelopeId, ordinal, email: `signer-${ordinal}@example.test`, role: 'approver', created_at: ts(1), updated_at: ts(1) });

    // While draft, recipients and fields are editable.
    const draft = envelopeIn(db, tenant, 'draft');
    const r1 = recipientRow(draft.id, 1);
    db.transaction(() => store.insert('recipients', r1));
    const field = { envelope_id: draft.id, key: 'sig_1', revision_id: draft.revision, recipient_id: r1.id, recipient_ordinal: 1, page: 1, type: 'signature', rect_x: 0.1, rect_y: 0.1, rect_width: 0.2, rect_height: 0.1, created_at: ts(1) };
    for (const [label, fn] of [
      ['insert a recipient', () => store.insert('recipients', recipientRow(draft.id, 2))],
      ['re-address a recipient', () => store.update('recipients', { id: r1.id }, { email: 'changed@example.test', role: 'witness' })],
      ['remove a recipient', () => store.delete('recipients', { id: r1.id })],
      ['insert a field', () => store.insert('field_definitions', field)],
    ]) assert.equal(attempt(db, fn), 'ok', `draft: ${label}`);
    db.transaction(() => store.insert('field_definitions', field));
    assert.equal(attempt(db, () => store.update('field_definitions', { envelope_id: draft.id, key: 'sig_1' }, { rect_x: 0.2 })), 'ok', 'draft: move a field');
    assert.equal(attempt(db, () => store.delete('field_definitions', { envelope_id: draft.id, key: 'sig_1' })), 'ok', 'draft: remove a field');

    // After prepare (through the domain), they are frozen.
    const prepared = preparedEnvelope(ctx, { recipients: 1 });
    const recipient = prepared.recipients[0];
    const preparedRevision = db.transaction(() => store.get('field_definitions', { envelope_id: prepared.id, key: 'sig_1' }).revision_id);
    const frozen = [
      ['insert a recipient', () => store.insert('recipients', recipientRow(prepared.id, 2))],
      ['remove a recipient', () => store.delete('recipients', { id: recipient.id })],
      ['change a recipient email', () => store.update('recipients', { id: recipient.id }, { email: 'changed@example.test' })],
      ['change a recipient role', () => store.update('recipients', { id: recipient.id }, { role: 'witness' })],
      ['change a recipient ordinal', () => store.update('recipients', { id: recipient.id }, { ordinal: 2 })],
      ['insert a field', () => store.insert('field_definitions', { ...field, envelope_id: prepared.id, key: 'sig_extra', revision_id: preparedRevision, recipient_id: recipient.id })],
      ['move a field', () => store.update('field_definitions', { envelope_id: prepared.id, key: 'sig_1' }, { rect_x: 0.2 })],
      ['retype a field', () => store.update('field_definitions', { envelope_id: prepared.id, key: 'date_1' }, { type: 'signature' })],
      ['remove a field', () => store.delete('field_definitions', { envelope_id: prepared.id, key: 'date_1' })],
    ];
    for (const [label, fn] of frozen) refusedByTrigger(db, fn, FROZEN, label);
    assert.equal(attempt(db, () => store.update('recipients', { id: recipient.id }, { status: 'revoked', updated_at: ts(30) })), 'ok', 'status progress is not a binding change');

    const envelopeVersion = () => db.transaction(() => store.get('envelopes', { id: prepared.id }).version);
    const v = envelopeVersion();
    const otherRevision = sid('rev');
    db.transaction(() =>
      store.insert('document_revisions', { id: otherRevision, envelope_id: prepared.id, content_digest: hex('other'), blob_ref: `tenants/${tenant}/sha256/${hex('other')}`, bytes: 10, pages: 1, page_geometry_json: '[]', parse_report_json: '{}', created_at: ts(1) }),
    );
    for (const [label, values] of [
      ['manifest_digest', { manifest_digest: hex('another-manifest') }],
      ['recipients_digest', { recipients_digest: hex('another-recipients') }],
      ['base_revision_id', { base_revision_id: otherRevision }],
      ['recipients_count', { recipients_count: 2 }],
      ['expires_at', { expires_at: ts(60 * 24 * 3) }],
    ]) refusedByTrigger(db, () => store.compareAndSet('envelopes', { id: prepared.id }, v, { ...values, updated_at: ts(40) }), FROZEN, `prepared ${label}`);
    for (const [label, values] of [
      ['source_record', { source_record: 'another-record' }],
      ['created_by_ref', { created_by_ref: 'someone-else' }],
      ['created_at', { created_at: ts(0) }],
    ]) refusedByTrigger(db, () => store.compareAndSet('envelopes', { id: draft.id }, draft.version, { ...values, updated_at: ts(40) }), FROZEN, `draft identity ${label}`);
    assert.equal(envelopeVersion(), v, 'every refused change left the version');

    const voided = envelopeIn(db, tenant, 'voided');
    const successor = envelopeIn(db, tenant, 'draft');
    const later = envelopeIn(db, tenant, 'draft');
    db.transaction(() => assert.equal(store.compareAndSet('envelopes', { id: voided.id }, voided.version, { reissued_as: successor.id, updated_at: ts(50) }), true));
    refusedByTrigger(db, () => store.compareAndSet('envelopes', { id: voided.id }, voided.version + 1, { reissued_as: later.id, updated_at: ts(51) }), FROZEN, 'reissued_as is recorded once');
  } finally {
    ctx.db.close();
  }
});

test('[ST-10] the version moves only by exactly one, every column but updated_at needs that step, and updated_at alone may keep it (DB-28 unchanged)', () => {
  const ctx = setup(scratch);
  try {
    const { db, tenant, path } = ctx;
    const store = db.forTenant(tenant);
    const draft = envelopeIn(db, tenant, 'draft');
    const prepared = envelopeIn(db, tenant, 'prepared');
    const get = (id) => db.transaction(() => store.get('envelopes', { id }));

    db.transaction(() => assert.equal(store.update('envelopes', { id: prepared.id }, { updated_at: ts(30) }), 1));
    assert.equal(get(prepared.id).version, prepared.version, 'updated_at alone keeps the version');
    db.transaction(() => assert.equal(store.compareAndSet('envelopes', { id: prepared.id }, prepared.version, { updated_at: ts(31) }), true));
    assert.equal(get(prepared.id).version, prepared.version + 1, 'or takes exactly one step');

    for (const [label, values] of [
      ['state', { state: 'voided' }],
      ['expires_at', { expires_at: ts(60 * 24 * 2) }],
      ['manifest_digest', { manifest_digest: hex('m') }],
      ['recipients_digest', { recipients_digest: hex('r') }],
      ['recipients_count', { recipients_count: 1 }],
    ]) {
      refusedByTrigger(db, () => store.update('envelopes', { id: draft.id }, { ...values, updated_at: ts(32) }), VERSION, `${label} without the step`);
      assert.equal(attempt(db, () => store.compareAndSet('envelopes', { id: draft.id }, draft.version, { ...values, updated_at: ts(32) })), 'ok', `${label} with the step`);
    }

    const v = get(draft.id).version;
    rawRefuses(path, 'UPDATE envelopes SET version = version + 2 WHERE tenant_id = ? AND id = ?', [tenant, draft.id], VERSION);
    rawRefuses(path, 'UPDATE envelopes SET version = version - 1 WHERE tenant_id = ? AND id = ?', [tenant, prepared.id], VERSION);
    assert.equal(get(prepared.id).version, prepared.version + 1, 'a backward step (above the T003 floor of 1) is refused by the step rule');
    rawRefuses(path, 'UPDATE envelopes SET version = 1, state = ? WHERE tenant_id = ? AND id = ?', ['voided', tenant, prepared.id], /version must be old \+ 1|not in the state graph/);
    rawRefuses(path, "UPDATE envelopes SET expires_at = ? WHERE tenant_id = ? AND id = ?", [ts(60 * 24 * 3), tenant, draft.id], VERSION);
    assert.equal(get(draft.id).version, v, 'raw writers are held to the same rule');
    assert.equal(rawRun(path, 'UPDATE envelopes SET version = version + 1 WHERE tenant_id = ? AND id = ?', [tenant, draft.id]), 1, 'a single step alone is allowed');

    // The rule names every column of envelopes except version and updated_at.
    const raw = rawConnection(path);
    try {
      const columns = raw.prepare("SELECT name FROM pragma_table_info('envelopes')").all().map((row) => row.name);
      const sql = raw.prepare("SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = 'envelopes_version_step'").get().sql;
      for (const column of columns.filter((name) => name !== 'version' && name !== 'updated_at')) {
        assert.ok(sql.includes(`NEW.${column} IS NOT OLD.${column}`), `${column} counts as state or content`);
      }
      assert.equal(sql.includes('NEW.updated_at'), false, 'updated_at alone never needs the step');
    } finally {
      raw.close();
    }
  } finally {
    ctx.db.close();
  }
});

test('[ST-11] every UPDATE that changes state follows exactly the transition graph: all 16 legal transitions pass and all 56 others are refused', () => {
  const ctx = setup(scratch);
  try {
    const { db, tenant } = ctx;
    const store = db.forTenant(tenant);
    let legal = 0;
    let refused = 0;
    for (const from of STATES) {
      const envelope = envelopeIn(db, tenant, from);
      for (const to of STATES.filter((state) => state !== from)) {
        // Keep the T003 CHECKs satisfied so that only the graph can decide.
        const values = { state: to, approvals_complete: FULLY_APPROVED.includes(to) ? 1 : 0, updated_at: ts(60), ...(from === 'draft' ? envelope.content : {}) };
        const outcome = attempt(db, () => store.compareAndSet('envelopes', { id: envelope.id }, envelope.version, values));
        if (RULED_GRAPH[from].includes(to)) {
          assert.equal(outcome, 'ok', `${from} -> ${to} is legal`);
          legal += 1;
        } else {
          assert.match(outcome, /^trigger: /, `${from} -> ${to} is refused by the schema`);
          assert.match(outcome, GRAPH, `${from} -> ${to} is refused by the graph`);
          refused += 1;
        }
      }
      for (const values of [{ updated_at: ts(61) }, { state: from, updated_at: ts(61) }]) {
        assert.equal(attempt(db, () => store.compareAndSet('envelopes', { id: envelope.id }, envelope.version, values)), 'ok', `${from}: an update that keeps the state is not a transition`);
      }
    }
    assert.deepEqual([legal, refused], [16, 56]);
  } finally {
    ctx.db.close();
  }
});

test('[ST-11] the proven P04 defect is refused: a completed envelope with an artifact cannot be set to voided, at its version or reset to version 1', () => {
  const ctx = setup(scratch);
  try {
    const { db, tenant, path } = ctx;
    const store = db.forTenant(tenant);
    const completed = envelopeIn(db, tenant, 'completed');
    refusedByTrigger(db, () => store.compareAndSet('envelopes', { id: completed.id }, completed.version, { state: 'voided', approvals_complete: 0, updated_at: ts(70) }), GRAPH);
    rawRefuses(path, 'UPDATE envelopes SET state = ?, approvals_complete = 0, version = 1 WHERE tenant_id = ? AND id = ?', ['voided', tenant, completed.id], /version must be old \+ 1|not in the state graph/);
    refusedByTrigger(db, () => store.update('envelopes', { id: completed.id }, { state: 'voided', approvals_complete: 0 }), /version must be old \+ 1|not in the state graph/);
    const row = db.transaction(() => store.get('envelopes', { id: completed.id }));
    assert.deepEqual([row.state, row.version], ['completed', completed.version]);
  } finally {
    ctx.db.close();
  }
});

test('[ST-12] the graph does not govern inserts, while domain create and reissue insert only draft at version 1', () => {
  const ctx = setup(scratch);
  try {
    const { db, tenant, path, service } = ctx;
    const store = db.forTenant(tenant);
    rawRun(
      path,
      "CREATE TRIGGER st12_insert_shape BEFORE INSERT ON envelopes WHEN NEW.state <> 'draft' OR NEW.version <> 1 BEGIN SELECT RAISE(ABORT, 'st12: an insert that is not draft at version 1'); END",
      [],
    );
    refusedByTrigger(db, () => store.insert('envelopes', envelopeRow(sid('env'), { state: 'voided' })), /st12/, 'the probe trigger bites');

    const one = service.create(req(tenant), createInput(1)).body;
    const two = service.create(req(tenant), createInput(2)).body;
    assert.deepEqual([one.state, one.version, two.state, two.version], ['draft', 1, 'draft', 1]);
    const prepared = preparedEnvelope(ctx, { recipients: 2 });
    const voided = service.void(req(tenant), prepared.id, { expected_version: prepared.version, reason_code: 'superseded' }).body;
    const reissued = service.reissue(req(tenant), prepared.id, { expected_version: voided.version }).body;
    assert.equal(reissued.reissue_of, prepared.id, 'the reissue inserted its draft while the probe trigger was armed');
    const bare = service.create(req(tenant), createInput(1)).body;
    const bareVoided = service.void(req(tenant), bare.id, { expected_version: 1, reason_code: 'other' }).body;
    assert.equal(service.reissue(req(tenant), bare.id, { expected_version: bareVoided.version }).body.version, 1);

    rawRun(path, 'DROP TRIGGER st12_insert_shape', []);
    for (const state of ['voided', 'declined', 'expired']) {
      assert.equal(attempt(db, () => store.insert('envelopes', envelopeRow(sid('env'), { state, updated_at: ts(5) }))), 'ok', `a storage insert in ${state} is not governed by the graph`);
    }
    rejectsWith(() => service.create(req(tenant), { ...createInput(1), state: 'voided' }), 'invalid_request', 400);
  } finally {
    ctx.db.close();
  }
});

test('[ST-12] migrations 0010, 0011 and 0012 are appended after the T003 set and pinned by SHA-256', () => {
  const migrations = loadMigrations();
  for (const pinned of PINNED_T007_MIGRATIONS) {
    const actual = migrations[pinned.version - 1];
    assert.ok(actual, `migration ${pinned.version} exists`);
    assert.deepEqual({ version: actual.version, name: actual.name, sha256: actual.sha256 }, pinned, `migration ${pinned.version} is unchanged: append a new one instead`);
  }
  const ctx = setup(scratch);
  try {
    const raw = rawConnection(ctx.path);
    try {
      const applied = raw.prepare('SELECT version, name, sha256 FROM schema_migrations WHERE version >= 10 ORDER BY version').all().map((row) => ({ ...row }));
      assert.deepEqual(applied.slice(0, PINNED_T007_MIGRATIONS.length), PINNED_T007_MIGRATIONS.map((entry) => ({ ...entry })));
      const triggers = raw.prepare("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND sql LIKE '%AFTER%' AND name LIKE 'envelopes_%' ORDER BY name").all().map((row) => row.name);
      assert.deepEqual(triggers, ['envelopes_frozen_columns', 'envelopes_state_graph', 'envelopes_version_step']);
    } finally {
      raw.close();
    }
  } finally {
    ctx.db.close();
  }
});
