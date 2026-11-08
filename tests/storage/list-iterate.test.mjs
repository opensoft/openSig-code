// SPDX-License-Identifier: Apache-2.0
//
// Bounded reads (T003, A-008): TenantStore.list() never truncates silently,
// it throws StorageLimitError past MAX_LIST_LIMIT, and iterate() walks any
// number of rows in keyset pages with a stable order. All data is synthetic.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { MAX_LIST_LIMIT, StorageLimitError, StorageUsageError } from '../../src/storage/db/index.ts';
import { createTenant, envelopeRow, makeScratch, openTemp, sid, ts } from './support/fixtures.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

/** Insert `count` envelopes; `shape(i)` overrides columns of the i-th row. */
function insertEnvelopes(db, store, count, shape = () => ({})) {
  const ids = [];
  db.transaction(() => {
    for (let i = 0; i < count; i += 1) {
      const id = `env-${String(i).padStart(6, '0')}-${sid('x').slice(2, 10)}`;
      store.insert('envelopes', envelopeRow(id, shape(i)));
      ids.push(id);
    }
  });
  return ids;
}

test('[DB-24] list() past MAX_LIST_LIMIT matches throws StorageLimitError instead of truncating; an explicit limit still caps', () => {
  const { db } = openTemp(scratch);
  try {
    const tenant = sid('tenant');
    const other = sid('tenant');
    createTenant(db, tenant);
    createTenant(db, other);
    const store = db.forTenant(tenant);
    insertEnvelopes(db, store, MAX_LIST_LIMIT);
    insertEnvelopes(db, db.forTenant(other), 5);
    assert.equal(store.list('envelopes').length, MAX_LIST_LIMIT, 'exactly the cap is returned whole');

    insertEnvelopes(db, store, 1, () => ({ state: 'voided' }));
    assert.equal(store.count('envelopes'), MAX_LIST_LIMIT + 1);
    const limited = (error) => error instanceof StorageLimitError && error.code === 'storage_limit' && /more than 10000 rows; use iterate\(\)/.test(error.message);
    assert.throws(() => store.list('envelopes'), limited, 'one row past the cap fails loudly');
    assert.throws(() => store.list('envelopes', {}, { orderBy: [['id', 'asc']] }), limited, 'with an order too');
    assert.throws(() => store.list('envelopes', { source_app: 'manual' }), limited, 'and with a filter that still matches too many');

    assert.equal(store.list('envelopes', {}, { limit: MAX_LIST_LIMIT }).length, MAX_LIST_LIMIT, 'an explicit limit is a deliberate cap');
    assert.equal(store.list('envelopes', {}, { limit: 3, orderBy: [['id', 'asc']] }).length, 3);
    assert.deepEqual(store.list('envelopes', { state: 'voided' }).map((row) => row.state), ['voided'], 'a narrow filter is fine');
    assert.throws(() => store.list('envelopes', {}, { limit: MAX_LIST_LIMIT + 1 }), StorageUsageError);
    assert.equal([...store.iterate('envelopes')].length, MAX_LIST_LIMIT + 1, 'iterate() reads them all');
  } finally {
    db.close();
  }
});

test('[DB-25] iterate() yields every row exactly once in a stable order, across page boundaries and equal sort keys', () => {
  const { db } = openTemp(scratch);
  try {
    const tenant = sid('tenant');
    const other = sid('tenant');
    createTenant(db, tenant);
    createTenant(db, other);
    const store = db.forTenant(tenant);
    // 53 rows over three states and five update times: long runs of equal keys.
    const states = ['draft', 'declined', 'voided'];
    const ids = insertEnvelopes(db, store, 53, (i) => ({ state: states[i % 3], created_at: ts(0), updated_at: ts(i % 5) }));
    insertEnvelopes(db, db.forTenant(other), 7, () => ({ state: 'declined' }));
    const expected = [...ids].sort();

    const collect = (where, options) => [...store.iterate('envelopes', where, options)];
    const orders = [
      [],
      [['state', 'asc']],
      [['updated_at', 'desc']],
      [['state', 'desc'], ['updated_at', 'asc']],
      [['updated_at', 'asc'], ['state', 'desc'], ['id', 'asc']],
    ];
    for (const orderBy of orders) {
      const reference = collect({}, { orderBy, pageSize: 1000 }).map((row) => row.id);
      assert.deepEqual([...reference].sort(), expected, `${JSON.stringify(orderBy)}: one page holds every row once`);
      for (const pageSize of [1, 2, 3, 7, 52, 53, 54]) {
        const rows = collect({}, { orderBy, pageSize });
        const seen = rows.map((row) => row.id);
        assert.equal(new Set(seen).size, seen.length, `${JSON.stringify(orderBy)} page ${pageSize}: no row twice`);
        assert.deepEqual(seen, reference, `${JSON.stringify(orderBy)} page ${pageSize}: same rows in the same order`);
        assert.ok(rows.every((row) => !Object.hasOwn(row, '__keyset_rowid')), 'the keyset column is not returned');
      }
      const rows = collect({}, { orderBy, pageSize: 1000 });
      for (let i = 1; i < rows.length; i += 1) {
        for (const [column, direction] of orderBy) {
          const prev = rows[i - 1][column];
          const next = rows[i][column];
          if (prev === next) continue;
          assert.ok(direction === 'asc' ? prev < next : prev > next, `${column} ${direction} order holds`);
          break;
        }
      }
    }

    const filtered = collect({ state: 'declined', updated_at: { op: '<=', value: ts(2) } }, { orderBy: [['updated_at', 'asc']], pageSize: 2 });
    assert.ok(filtered.length > 2);
    assert.ok(filtered.every((row) => row.state === 'declined' && row.updated_at <= ts(2) && row.tenant_id === tenant), 'filters and tenant scope hold on every page');
    assert.deepEqual(collect({ state: 'completed' }), [], 'no match yields nothing');

    // Bad calls fail where they are made, before any page is read.
    assert.throws(() => store.iterate('envelopes', {}, { orderBy: [['reissue_of', 'asc']] }), (error) => error instanceof StorageUsageError && /NOT NULL/.test(error.message), 'a nullable order column is refused');
    assert.throws(() => store.iterate('envelopes', {}, { pageSize: 0 }), StorageUsageError);
    assert.throws(() => store.iterate('envelopes', {}, { pageSize: MAX_LIST_LIMIT + 1 }), StorageUsageError);
    assert.throws(() => store.iterate('envelopes', {}, { orderBy: [['no_such_column', 'asc']] }), StorageUsageError);
    assert.throws(() => store.iterate('envelopes', {}, { orderBy: [['state', 'sideways']] }), StorageUsageError);
    assert.throws(() => store.iterate('envelopes', { tenant_id: other }), StorageUsageError, 'callers cannot widen the tenant scope');
  } finally {
    db.close();
  }
});
