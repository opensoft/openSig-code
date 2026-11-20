// SPDX-License-Identifier: Apache-2.0
//
// Blob-reference lookups (T003, A-010 T30R3-1): DB-29 an appended migration
// indexes document_revisions(tenant_id, blob_ref) and (tenant_id, <column>)
// for every blob-reference column of final_artifacts; the reference check a
// disposal runs inside BEGIN IMMEDIATE is an index search, never a scan; and
// the write-lock hold time of a disposal of 10,001 revisions is measured.

import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { after, mock, test } from 'node:test';

import { AuditWriter } from '../../src/storage/audit/index.ts';
import { openBlobStore } from '../../src/storage/blobs/index.ts';
import { MAX_LIST_LIMIT } from '../../src/storage/db/index.ts';
import * as retention from '../../src/storage/retention/index.ts';
import { loadMigrations } from '../../src/storage/schema/migrations.ts';
import { BASE_TIME, blobRef, createTenant, envelopeRow, hex, makeScratch, openTemp, sid, ts } from './support/fixtures.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

test('[DB-29] an appended migration indexes every blob-reference lookup by tenant: the disposal reference check is an index search, never a scan, and its write lock at 10,001 revisions is measured', (t) => {
  const migration = loadMigrations().find((entry) => entry.name === '0009-blob-ref-indexes.sql');
  assert.ok(migration, 'migration 0009 adds the blob-reference indexes');
  assert.equal(migration.version, 9, 'it is appended after 0008; earlier migrations are untouched (DB-06)');

  const { db, path } = openTemp(scratch);
  const raw = new DatabaseSync(path, { readOnly: true });
  try {
    // The indexes exist, for document_revisions.blob_ref and for every blob-reference column of final_artifacts.
    const artifactColumns = raw
      .prepare(`SELECT name FROM pragma_table_info('final_artifacts') WHERE name LIKE '%blob_ref'`)
      .all()
      .map((row) => row.name)
      .sort();
    assert.deepEqual(artifactColumns, ['evidence_blob_ref', 'package_blob_ref', 'pdf_blob_ref']);
    const indexedBy = (table, column) =>
      raw
        .prepare('SELECT name FROM pragma_index_list(?)')
        .all(table)
        .some((index) => {
          const columns = raw.prepare('SELECT name FROM pragma_index_info(?) ORDER BY seqno').all(index.name).map((row) => row.name);
          return columns.length === 2 && columns[0] === 'tenant_id' && columns[1] === column;
        });
    const lookups = [['document_revisions', 'blob_ref'], ...artifactColumns.map((column) => ['final_artifacts', column])];
    for (const [table, column] of lookups) assert.ok(indexedBy(table, column), `${table}(tenant_id, ${column}) is indexed`);

    // The query plan of the lookups the disposal's reference check runs (the
    // statements T029's ReferenceProtection prepares, captured as prepared).
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const prepared = [];
    const prepare = DatabaseSync.prototype.prepare;
    mock.method(DatabaseSync.prototype, 'prepare', function (sql, ...rest) {
      prepared.push(sql);
      return prepare.call(this, sql, ...rest);
    });
    try {
      assert.equal(new retention.ReferenceProtection(db.forTenant(tenant)).referenced(blobRef(tenant, hex('db29-probe'))), false);
    } finally {
      mock.restoreAll();
    }
    const statements = prepared.filter((sql) => /FROM "(document_revisions|final_artifacts)"/.test(sql));
    assert.equal(statements.length, lookups.length, 'one lookup per blob-reference column');
    for (const sql of statements) {
      const plan = raw.prepare(`EXPLAIN QUERY PLAN ${sql}`).all().map((row) => row.detail);
      assert.ok(
        plan.some((detail) => /^SEARCH (document_revisions|final_artifacts) USING (COVERING )?INDEX \S+ \(tenant_id=\? AND \w*blob_ref=\?/.test(detail)),
        `an index search on (tenant_id, blob ref): ${sql}\n${plan.join('\n')}`,
      );
      assert.equal(plan.some((detail) => /^SCAN /.test(detail)), false, `never a scan: ${plan.join(' | ')}`);
      assert.equal(plan.some((detail) => /TEMP B-TREE/.test(detail)), false, `no sort: ${plan.join(' | ')}`);
    }

    // The write lock a disposal of 10,001 revisions holds (BEGIN IMMEDIATE to COMMIT).
    const store = db.forTenant(tenant);
    db.transaction(() => store.update('tenants', {}, { retention_json: JSON.stringify({ policy_ref: 'synthetic-db29', dispose_after_days: 1 }) }));
    const envelope = sid('env');
    const count = MAX_LIST_LIMIT + 1;
    db.transaction(() => {
      store.insert('envelopes', envelopeRow(envelope, { state: 'declined', updated_at: ts(5) }));
      for (let i = 0; i < count; i += 1) {
        const digest = hex(`db29-revision-${i}`);
        store.insert('document_revisions', {
          id: `rev_${String(i).padStart(12, '0')}`,
          envelope_id: envelope,
          content_digest: digest,
          blob_ref: blobRef(tenant, digest),
          bytes: 64,
          pages: 1,
          page_geometry_json: '[]',
          parse_report_json: '{}',
          created_at: ts(2),
        });
      }
    });
    const blobRoot = join(dirname(path), 'blobs');
    mkdirSync(blobRoot, { mode: 0o700 });
    const holds = [];
    const transaction = db.transaction.bind(db);
    db.transaction = (fn) => {
      const started = performance.now();
      try {
        return transaction(fn);
      } finally {
        holds.push(performance.now() - started);
      }
    };
    const clock = () => new Date(BASE_TIME + 2 * 86_400_000);
    const run = new retention.RetentionService({ db, blobs: openBlobStore({ root: blobRoot }), audit: new AuditWriter(db, { clock }), clock }).run(tenant);
    delete db.transaction;
    assert.deepEqual(run.disposals.map((disposal) => [disposal.envelopeId, disposal.disposedBlobRefs.length]), [[envelope, count]]);
    assert.ok(holds.length >= 1, 'the disposal ran in a transaction');
    const hold = Math.max(...holds);
    t.diagnostic(`DB-29 write-lock hold of one disposal of ${count} revisions: ${Math.round(hold)} ms (BEGIN IMMEDIATE to COMMIT)`);
    assert.ok(hold < 30_000, `the disposal holds the write lock for indexed lookups only (${Math.round(hold)} ms)`);
  } finally {
    raw.close();
    db.close();
  }
});
