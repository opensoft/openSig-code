// SPDX-License-Identifier: Apache-2.0
//
// Tenant-filtered query helpers (T003): every read and write is filtered to
// the store's tenant by the storage layer, identifiers are checked against the
// schema, compare-and-set owns the version column, and the only unscoped
// lookups are the tenant registry and capability-hash resolution.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { StorageUsageError, TenantStore } from '../../src/storage/db/index.ts';
import { createTenant, envelopeRow, hex, makeScratch, openTemp, seedGraph, sid, ts } from './support/fixtures.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

function twoTenants() {
  const { db } = openTemp(scratch);
  const tenantA = sid('tenant');
  const tenantB = sid('tenant');
  const ga = seedGraph(db, tenantA);
  const gb = seedGraph(db, tenantB);
  return { db, tenantA, tenantB, ga, gb, a: db.forTenant(tenantA), b: db.forTenant(tenantB) };
}

const usage = (pattern) => (error) => error instanceof StorageUsageError && (pattern === undefined || pattern.test(error.message));

test('[DB-17] reads and writes through a tenant store never reach another tenant', () => {
  const { db, tenantA, tenantB, ga, gb, a, b } = twoTenants();
  try {
    assert.ok(a instanceof TenantStore);
    assert.equal(a.tenantId, tenantA);
    for (const table of ['envelopes', 'recipients', 'approvals', 'audit_events', 'outbox_events', 'tenants']) {
      const rows = a.list(table);
      assert.ok(rows.length > 0, `${table} has tenant A rows`);
      assert.ok(rows.every((row) => row.tenant_id === tenantA), `${table} lists only tenant A`);
      assert.equal(a.count(table), b.count(table), `${table} counts are per tenant`);
    }
    assert.equal(a.get('envelopes', { id: gb.env }), undefined, "tenant B's envelope is invisible to tenant A");
    assert.equal(a.get('approvals', { id: gb.a1 }), undefined);
    assert.equal(a.count('recipients', { envelope_id: gb.env }), 0);
    assert.equal(a.list('envelopes', { id: { op: 'in', values: [ga.env, gb.env] } }).length, 1);

    db.transaction(() => {
      assert.equal(a.update('recipients', { id: gb.r1 }, { role: 'changed-by-a' }), 0);
      assert.equal(a.compareAndSet('envelopes', { id: gb.env }, 6, { updated_at: ts(30) }), false);
      assert.equal(a.delete('consumer_attachments', { envelope_id: gb.env }), 0);
      assert.equal(a.update('webhook_registrations', { id: gb.reg }, { status: 'disabled' }), 0);
    });
    assert.equal(b.get('recipients', { id: gb.r1 })?.role, 'approver');
    assert.equal(b.get('envelopes', { id: gb.env })?.version, 6);
    assert.equal(b.count('consumer_attachments'), 1);
    assert.equal(b.get('webhook_registrations', { id: gb.reg })?.status, 'active');
    assert.equal(b.get('tenants', {})?.tenant_id, tenantB, 'the tenant row itself is reached only by its own store');
  } finally {
    db.close();
  }
});

test('[DB-18] tenant_id is supplied by the storage layer and cannot be set, filtered or spoofed by callers', () => {
  const { db, tenantA, tenantB, ga, a, b } = twoTenants();
  try {
    assert.throws(() => db.transaction(() => a.insert('envelopes', { ...envelopeRow(sid('env')), tenant_id: tenantB })), usage(/tenant_id is set by the storage layer/));
    assert.throws(() => db.transaction(() => a.update('envelopes', { id: ga.env }, { tenant_id: tenantB })), usage(/tenant_id/));
    assert.throws(() => a.list('envelopes', { tenant_id: tenantB }), usage(/tenant filter/));
    assert.throws(() => a.get('envelopes', { tenant_id: { op: '<>', value: tenantA } }), usage(/tenant filter/));
    assert.equal(b.count('envelopes', { id: ga.env }), 0);
    for (const bad of ['', 'short', 'x'.repeat(65), 'tenant/../other-xx', 'tenant id with spaces', null, undefined, 42]) {
      assert.throws(() => db.forTenant(bad), usage(/tenant id/), `tenant id ${String(bad)}`);
    }
    const id = sid('env');
    db.transaction(() => a.insert('envelopes', envelopeRow(id)));
    assert.equal(a.get('envelopes', { id })?.tenant_id, tenantA);
  } finally {
    db.close();
  }
});

test('[DB-19] table names, column names, operators, values and narrowing are checked before any SQL runs', () => {
  const { db, ga, a } = twoTenants();
  try {
    for (const table of ['no_such_table', 'schema_migrations', 'sqlite_schema', 'envelopes; DROP TABLE envelopes', 'Envelopes', '__proto__', 'constructor']) {
      assert.throws(() => a.list(table), usage(/unknown table/), table);
    }
    for (const column of ['no_such_column', 'id" OR 1=1 --', 'rowid', '__proto__']) {
      assert.throws(() => a.list('envelopes', { [column]: 'x' }), usage(/unknown column/), column);
      assert.throws(() => db.transaction(() => a.insert('envelopes', { ...envelopeRow(sid('env')), [column]: 'x' })), usage(/unknown column/), column);
    }
    assert.throws(() => a.list('envelopes', {}, { orderBy: [['id; DROP TABLE envelopes', 'asc']] }), usage(/unknown column/));
    assert.throws(() => a.list('envelopes', {}, { orderBy: [['id', 'sideways']] }), usage(/asc or desc/));
    assert.throws(() => a.list('envelopes', { version: { op: 'LIKE', value: '%' } }), usage(/unsupported operator/));
    assert.throws(() => a.list('envelopes', { id: { op: 'in', values: [] } }), usage(/"in" needs/));
    for (const limit of [0, -1, 1.5, 10_001]) assert.throws(() => a.list('envelopes', {}, { limit }), usage(/limit/));
    for (const value of [undefined, true, Number.NaN, Number.POSITIVE_INFINITY, { nested: 1 }, ['x']]) {
      assert.throws(() => a.list('envelopes', { source_record: value }), StorageUsageError, String(value));
    }

    assert.throws(() => db.transaction(() => a.update('envelopes', {}, { source_record: 'all-rows' })), usage(/non-empty where/));
    assert.throws(() => db.transaction(() => a.delete('recipients', {})), usage(/non-empty where/));
    assert.throws(() => db.transaction(() => a.compareAndSet('envelopes', {}, 1, {})), usage(/non-empty where/));
    assert.throws(() => db.transaction(() => a.update('envelopes', { id: ga.env }, {})), usage(/sets no columns/));
    db.transaction(() => assert.equal(a.update('tenants', {}, { retention_json: null }), 1, 'the tenant row is keyed by tenant_id alone'));

    assert.throws(() => a.get('recipients', { envelope_id: ga.env }), usage(/more than one row/));
    assert.equal(a.get('recipients', { envelope_id: ga.env, ordinal: 2 })?.id, ga.r2);
    assert.deepEqual(
      a.list('recipients', { envelope_id: ga.env, invited_at: { op: 'is-not-null' } }, { orderBy: [['ordinal', 'desc']], limit: 1 }).map((row) => row.ordinal),
      [2],
    );
    assert.equal(a.count('signing_jobs', { lease_owner: null }), 1);
    assert.equal(a.count('signing_jobs', { lease_owner: { op: 'is-null' } }), 1);
    assert.equal(a.count('audit_events', { seq: { op: '>=', value: 2 } }), 2);
    assert.equal(a.count('envelopes', { expires_at: { op: '>', value: ts(0) } }), 1, 'fixed-width UTC timestamps compare in time order');
  } finally {
    db.close();
  }
});

test('[DB-20] compareAndSet updates one row only at the expected version and owns the version column', () => {
  const { db, ga, a } = twoTenants();
  try {
    db.transaction(() => {
      assert.equal(a.compareAndSet('envelopes', { id: ga.env }, 5, { updated_at: ts(30) }), false, 'stale version');
      assert.equal(a.compareAndSet('envelopes', { id: ga.env }, 6, { updated_at: ts(30) }), true);
      assert.equal(a.compareAndSet('envelopes', { id: ga.env }, 6, { updated_at: ts(31) }), false, 'the version moved on');
    });
    const row = a.get('envelopes', { id: ga.env });
    assert.equal(row?.version, 7);
    assert.equal(row?.updated_at, ts(30));

    assert.throws(() => db.transaction(() => a.compareAndSet('envelopes', { id: ga.env }, 7, { version: 1 })), usage(/owns the version column/));
    assert.throws(() => db.transaction(() => a.compareAndSet('envelopes', { id: ga.env, version: 7 }, 7, {})), usage(/owns the version column/));
    assert.throws(() => db.transaction(() => a.compareAndSet('envelopes', { id: ga.env }, 0, {})), usage(/positive integer/));
    assert.throws(() => db.transaction(() => a.compareAndSet('recipients', { id: ga.r1 }, 1, { role: 'x' })), usage(/no version column/));
    db.transaction(() =>
      a.insert('webhook_registrations', {
        id: sid('hook'),
        url: 'https://hooks.example.test/second',
        event_types_json: '["envelope.completed"]',
        created_by_ref: 'admin-1',
        created_at: ts(1),
        updated_at: ts(1),
      }),
    );
    assert.throws(
      () => db.transaction(() => a.compareAndSet('webhook_registrations', { status: 'active' }, 1, { description: 'both' })),
      usage(/more than one row/),
    );
    assert.deepEqual(
      a.list('webhook_registrations').map((registration) => [registration.version, registration.description]),
      [
        [1, null],
        [1, null],
      ],
      'the ambiguous compare-and-set was rolled back',
    );
  } finally {
    db.close();
  }
});

test('[DB-21] the only unscoped lookups are the tenant registry and capability-hash resolution', () => {
  const { db, tenantA, tenantB, ga, gb } = twoTenants();
  try {
    assert.deepEqual(db.listTenantIds(), [tenantA, tenantB].sort());
    assert.deepEqual(db.resolveCapability('invitations', ga.tokenHash), { tenantId: tenantA, id: ga.inv });
    assert.deepEqual(db.resolveCapability('invitations', gb.tokenHash), { tenantId: tenantB, id: gb.inv });
    assert.deepEqual(db.resolveCapability('recipient_sessions', gb.sessionHash), { tenantId: tenantB, id: gb.ses });
    assert.equal(db.resolveCapability('invitations', hex('unknown-token')), undefined);
    assert.equal(db.resolveCapability('invitations', ga.sessionHash), undefined, 'a session hash is not an invitation token');
    for (const table of ['envelopes', 'challenges', 'webhook_keys', 'no_such_table', 'schema_migrations']) {
      assert.throws(() => db.resolveCapability(table, ga.tokenHash), usage(/no capability column/), table);
    }
    for (const hash of ['', ga.tokenHash.toUpperCase(), ga.tokenHash.slice(1), `${ga.tokenHash}0`, null]) {
      assert.throws(() => db.resolveCapability('invitations', hash), usage(/capability hash/));
    }
    const extra = sid('tenant');
    createTenant(db, extra);
    assert.equal(db.listTenantIds().length, 3);
  } finally {
    db.close();
  }
});
