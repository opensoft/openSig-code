// SPDX-License-Identifier: Apache-2.0
//
// Per-tenant audit hash chain (T029): AC-01 chain digest, AC-02 row-edit
// detection, AC-03 truncated-tail detection, AC-04 checkpoint cadence.
// Tampering is simulated through a raw connection that drops the T003
// append-only triggers, as an attacker with file access could.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { canonicalBytes, canonicalDigest, canonicalize } from '../../src/domain/canonical/index.ts';
import { StorageConstraintError, StorageUsageError } from '../../src/storage/db/index.ts';
import {
  AUDIT_EVENT_SCHEMA,
  AuditWriter,
  CHECKPOINT_INTERVAL,
  envelopeAuditRecords,
  eventDigest,
  eventFromRow,
  verifyChain,
} from '../../src/storage/audit/index.ts';
import { makeScratch } from '../storage/support/fixtures.mjs';
import { addEnvelope, createTenant, environment, hex, rawConnection, sid } from './support/chain.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

const operator = { kind: 'human-operator', ref: 'operator-1' };

function appendMany(db, audit, tenant, count, input = {}) {
  const results = [];
  db.transaction(() => {
    for (let i = 0; i < count; i += 1) {
      results.push(audit.append(tenant, { type: 'envelope.updated', actor: operator, metadata: { step: i }, ...input }));
    }
  });
  return results;
}

function rows(db, tenant) {
  return db.forTenant(tenant).list('audit_events', {}, { orderBy: [['seq', 'asc']] });
}

test('[AC-01] each event digest is SHA-256 of the RFC 8785 event without event_digest, chained per tenant', () => {
  const { db } = environment(scratch);
  try {
    const tenantA = sid('tenant');
    const tenantB = sid('tenant');
    createTenant(db, tenantA);
    createTenant(db, tenantB);
    const envelope = addEnvelope(db, tenantA);
    const audit = new AuditWriter(db, { clock: (() => {
      let second = 0;
      return () => new Date(Date.UTC(2026, 10, 8, 12, 0, (second += 1)));
    })() });

    const appended = [];
    db.transaction(() => {
      appended.push(audit.append(tenantA, { type: 'envelope.created', actor: operator, envelopeId: envelope, metadata: { recipients: 2 } }));
      appended.push(audit.append(tenantA, { type: 'envelope.sent', actor: { kind: 'service', ref: 'hermes-adapter' }, envelopeId: envelope }));
      appended.push(
        audit.append(tenantA, {
          type: 'artifact.read',
          actor: { kind: 'recipient', ref: 'recipient-1' },
          subjectDigest: hex('artifact'),
          metadata: { error_code: 'none', key_id: 'k1', nested: { list: [1, 'two', null] } },
        }),
      );
    });
    db.transaction(() => audit.append(tenantB, { type: 'tenant.configured', actor: { kind: 'system', ref: 'bootstrap' } }));

    const stored = rows(db, tenantA);
    assert.deepEqual(stored.map((row) => row.seq), [1, 2, 3]);
    const expectedInputs = [
      {
        schema: AUDIT_EVENT_SCHEMA,
        tenant_id: tenantA,
        seq: 1,
        type: 'envelope.created',
        actor: operator,
        server_time: '2026-11-08T12:00:01.000Z',
        envelope_id: envelope,
        subject_digest: null,
        metadata: { recipients: 2 },
        prev_digest: null,
      },
      {
        schema: AUDIT_EVENT_SCHEMA,
        tenant_id: tenantA,
        seq: 2,
        type: 'envelope.sent',
        actor: { kind: 'service', ref: 'hermes-adapter' },
        server_time: '2026-11-08T12:00:02.000Z',
        envelope_id: envelope,
        subject_digest: null,
        metadata: {},
        prev_digest: stored[0].event_digest,
      },
      {
        schema: AUDIT_EVENT_SCHEMA,
        tenant_id: tenantA,
        seq: 3,
        type: 'artifact.read',
        actor: { kind: 'recipient', ref: 'recipient-1' },
        server_time: '2026-11-08T12:00:03.000Z',
        envelope_id: null,
        subject_digest: hex('artifact'),
        metadata: { error_code: 'none', key_id: 'k1', nested: { list: [1, 'two', null] } },
        prev_digest: stored[1].event_digest,
      },
    ];
    stored.forEach((row, index) => {
      const input = expectedInputs[index];
      assert.equal(row.event_digest, canonicalDigest(input), `seq ${row.seq} digest`);
      assert.equal(row.event_digest, eventDigest(eventFromRow(row)));
      assert.equal(row.metadata_json, canonicalize(input.metadata), 'metadata is stored in canonical form');
      assert.equal(appended[index].digest, row.event_digest);
      assert.equal(appended[index].prevDigest, input.prev_digest);
    });
    assert.ok(canonicalBytes(expectedInputs[0]).toString('utf8').startsWith('{"actor":{"kind":"human-operator","ref":"operator-1"},"envelope_id":'));

    const b = rows(db, tenantB);
    assert.equal(b.length, 1);
    assert.equal(b[0].seq, 1, 'each tenant has its own chain');
    assert.equal(b[0].prev_digest, null);
    for (const tenant of [tenantA, tenantB]) assert.equal(verifyChain(db, tenant).ok, true);
    assert.deepEqual(verifyChain(db, tenantA).head, { seq: 3, digest: stored[2].event_digest });
    assert.deepEqual(audit.head(tenantA), { seq: 3, digest: stored[2].event_digest });

    const records = envelopeAuditRecords(db, tenantA, envelope);
    assert.equal(records.length, 2);
    assert.deepEqual(Object.keys(records[0]).sort(), ['actor', 'event_digest', 'prev_digest', 'seq', 'server_time', 'subject_digest', 'type']);

    assert.throws(() => audit.append(tenantA, { type: 'envelope.updated', actor: operator }), (error) => error instanceof StorageUsageError && /inside Database.transaction/.test(error.message));
    const refused = [
      { type: 'Bad Type', actor: operator },
      { type: 'envelope.updated', actor: { kind: 'admin', ref: 'x' } },
      { type: 'envelope.updated', actor: { kind: 'system', ref: '' } },
      { type: 'envelope.updated', actor: operator, envelopeId: 'short' },
      { type: 'envelope.updated', actor: operator, subjectDigest: 'ABC' },
      { type: 'envelope.updated', actor: operator, metadata: [] },
      { type: 'envelope.updated', actor: operator, metadata: { invitation_token: 'x' } },
      { type: 'envelope.updated', actor: operator, metadata: { challengeCode: 'x' } },
      { type: 'envelope.updated', actor: operator, metadata: { recipient_email: 'recipient-1@example.test' } },
      { type: 'envelope.updated', actor: operator, metadata: { signing_key: 'x' } },
      { type: 'envelope.updated', actor: operator, metadata: { nested: { session_cookie: 'x' } } },
      { type: 'envelope.updated', actor: operator, metadata: { pdf_bytes: 'x' } },
      { type: 'envelope.updated', actor: operator, metadata: { note: 'x'.repeat(201) } },
      { type: 'envelope.updated', actor: operator, metadata: { note: '-----BEGIN CERTIFICATE-----' } },
      { type: 'envelope.updated', actor: operator, metadata: { a: { b: { c: { d: { e: 1 } } } } } },
    ];
    for (const input of refused) {
      assert.throws(() => db.transaction(() => audit.append(tenantA, input)), StorageUsageError, JSON.stringify(input).slice(0, 80));
    }
    assert.equal(rows(db, tenantA).length, 3, 'refused appends wrote nothing');
    assert.throws(() => new AuditWriter(db, {}), /injected clock/);
  } finally {
    db.close();
  }
});

test('[AC-02] editing any stored event is detected: digest mismatch, broken link, moved envelope, rewritten head', () => {
  const { db, path, audit } = environment(scratch);
  const raw = rawConnection(path);
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const envelope = addEnvelope(db, tenant);
    appendMany(db, audit, tenant, 6, { envelopeId: envelope });
    assert.equal(verifyChain(db, tenant).ok, true);

    raw.exec('DROP TRIGGER audit_events_append_only_update');
    raw.prepare('UPDATE audit_events SET metadata_json = ? WHERE tenant_id = ? AND seq = 3').run('{"step":99}', tenant);
    let report = verifyChain(db, tenant);
    assert.equal(report.ok, false);
    assert.deepEqual(report.problems.map((problem) => [problem.kind, problem.seq]), [['digest-mismatch', 3]]);

    // A consistent rewrite of seq 3 (recomputed digest) breaks the link to seq 4.
    const edited = eventFromRow(raw.prepare('SELECT * FROM audit_events WHERE tenant_id = ? AND seq = 3').get(tenant));
    raw.prepare('UPDATE audit_events SET event_digest = ? WHERE tenant_id = ? AND seq = 3').run(eventDigest(edited), tenant);
    report = verifyChain(db, tenant);
    assert.deepEqual(report.problems.map((problem) => [problem.kind, problem.seq]), [['link-break', 4]]);

    // Moving an event to another envelope changes its digest input.
    const tenant2 = sid('tenant');
    createTenant(db, tenant2);
    const own = addEnvelope(db, tenant2);
    const other = addEnvelope(db, tenant2);
    appendMany(db, audit, tenant2, 3, { envelopeId: own });
    raw.prepare('UPDATE audit_events SET envelope_id = ? WHERE tenant_id = ? AND seq = 2').run(other, tenant2);
    assert.deepEqual(verifyChain(db, tenant2).problems.map((problem) => [problem.kind, problem.seq]), [['digest-mismatch', 2]]);

    // Rewriting the head consistently is caught by the completion checkpoint
    // and by the head recorded outside the database.
    const tenant3 = sid('tenant');
    createTenant(db, tenant3);
    const env3 = addEnvelope(db, tenant3);
    appendMany(db, audit, tenant3, 4, { envelopeId: env3 });
    db.transaction(() => audit.checkpointCompletion(tenant3, env3));
    const head3 = verifyChain(db, tenant3).head;
    const last = eventFromRow(raw.prepare('SELECT * FROM audit_events WHERE tenant_id = ? AND seq = 4').get(tenant3));
    const forged = { ...last, metadata: { step: 'forged' } };
    raw
      .prepare('UPDATE audit_events SET metadata_json = ?, event_digest = ? WHERE tenant_id = ? AND seq = 4')
      .run(canonicalize(forged.metadata), eventDigest(forged), tenant3);
    report = verifyChain(db, tenant3, { expectedHead: head3 });
    assert.deepEqual(
      report.problems.map((problem) => problem.kind).sort(),
      ['checkpoint-mismatch', 'head-mismatch'],
    );
  } finally {
    raw.close();
    db.close();
  }
});

test('[AC-03] a truncated tail is detected against checkpoints and against a recorded head', () => {
  const { db, path, audit } = environment(scratch);
  const raw = rawConnection(path);
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const envelope = addEnvelope(db, tenant);
    appendMany(db, audit, tenant, 7, { envelopeId: envelope });
    const completion = db.transaction(() => audit.checkpointCompletion(tenant, envelope));
    assert.equal(completion.seq, 7);
    const recorded = { seq: completion.seq, digest: completion.digest };

    raw.exec('DROP TRIGGER audit_events_append_only_delete');
    raw.prepare('DELETE FROM audit_events WHERE tenant_id = ? AND seq >= 6').run(tenant);
    let report = verifyChain(db, tenant);
    assert.equal(report.ok, false);
    assert.equal(report.head.seq, 5);
    assert.deepEqual(report.problems.map((problem) => [problem.kind, problem.seq]), [['truncated', 7]]);
    report = verifyChain(db, tenant, { expectedHead: recorded });
    assert.deepEqual(report.problems.map((problem) => problem.kind), ['truncated', 'truncated']);

    // Without a checkpoint past the cut, only the externally recorded head reveals it.
    const tenantB = sid('tenant');
    createTenant(db, tenantB);
    appendMany(db, audit, tenantB, 4);
    const headB = verifyChain(db, tenantB).head;
    raw.prepare('DELETE FROM audit_events WHERE tenant_id = ? AND seq = 4').run(tenantB);
    assert.equal(verifyChain(db, tenantB).ok, true, 'a clean cut at the tail is invisible from inside the database');
    assert.deepEqual(verifyChain(db, tenantB, { expectedHead: headB }).problems.map((problem) => [problem.kind, problem.seq]), [['truncated', 4]]);

    // A row removed from the middle is a sequence gap.
    const tenantC = sid('tenant');
    createTenant(db, tenantC);
    appendMany(db, audit, tenantC, 5);
    raw.prepare('DELETE FROM audit_events WHERE tenant_id = ? AND seq = 3').run(tenantC);
    assert.deepEqual(verifyChain(db, tenantC).problems.map((problem) => [problem.kind, problem.seq]), [['seq-gap', 4]]);

    // An empty chain with a recorded head is truncated, not ok.
    const tenantD = sid('tenant');
    createTenant(db, tenantD);
    assert.deepEqual(verifyChain(db, tenantD, { expectedHead: headB }).problems.map((problem) => problem.kind), ['truncated']);
    assert.deepEqual(verifyChain(db, tenantD), { ok: true, events: 0, checkpoints: 0, head: null, problems: [] });
  } finally {
    raw.close();
    db.close();
  }
});

test('[AC-04] a cadence checkpoint is written every 100 events and a completion checkpoint at each completion', () => {
  const { db, audit } = environment(scratch);
  try {
    assert.equal(CHECKPOINT_INTERVAL, 100);
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const envelope = addEnvelope(db, tenant);
    const appended = [...appendMany(db, audit, tenant, 150), ...appendMany(db, audit, tenant, 100)];
    assert.deepEqual(
      appended.filter((event) => event.checkpointed).map((event) => event.seq),
      [100, 200],
    );
    const store = db.forTenant(tenant);
    const cadence = store.list('audit_checkpoints', { kind: 'cadence' }, { orderBy: [['seq', 'asc']] });
    assert.deepEqual(cadence.map((row) => row.seq), [100, 200]);
    for (const checkpoint of cadence) {
      assert.equal(checkpoint.event_digest, appended[checkpoint.seq - 1].digest);
      assert.equal(checkpoint.envelope_id, null);
    }

    const completion = db.transaction(() => {
      audit.append(tenant, { type: 'envelope.completed', actor: { kind: 'system', ref: 'finalizer' }, envelopeId: envelope, subjectDigest: hex('final-pdf') });
      return audit.checkpointCompletion(tenant, envelope);
    });
    assert.equal(completion.seq, 251);
    assert.equal(completion.digest, audit.head(tenant).digest);
    const stored = store.get('audit_checkpoints', { kind: 'completion' });
    assert.deepEqual([stored.seq, stored.envelope_id, stored.event_digest, stored.created_at], [251, envelope, completion.digest, completion.created_at]);
    assert.throws(
      () => db.transaction(() => audit.checkpointCompletion(tenant, envelope)),
      (error) => error instanceof StorageConstraintError && error.constraint === 'unique',
      'one completion checkpoint per envelope',
    );
    assert.throws(() => audit.checkpointCompletion(tenant, envelope), /inside Database.transaction/);
    const empty = sid('tenant');
    createTenant(db, empty);
    const emptyEnvelope = addEnvelope(db, empty);
    assert.throws(() => db.transaction(() => audit.checkpointCompletion(empty, emptyEnvelope)), /at least one audit event/);

    const report = verifyChain(db, tenant);
    assert.equal(report.ok, true);
    assert.equal(report.events, 251);
    assert.equal(report.checkpoints, 3);
  } finally {
    db.close();
  }
});
