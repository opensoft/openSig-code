// SPDX-License-Identifier: Apache-2.0
//
// Migration 0019's guards (T038; A-010 request #59 (2), (3) and (10); FEN-07
// storage half and FEN-09). SQLite's REPLACE conflict resolution deletes the
// row holding a key without firing its delete trigger, so 0019 refuses every
// insert whose key or rowid exists, whatever its conflict clause, and keeps
// rowids and keys fixed on update. The approval-evidence digest is required
// on insert and immutable. A raw connection plays the attacker; every refused
// statement leaves the stored row byte for byte. Synthetic data only.

import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

import { recordBlob } from '../../src/domain/finalization/index.ts';
import { StorageConstraintError } from '../../src/storage/db/index.ts';
import { holderOf, lease, publish } from './support/steps.mjs';
import { assembleAttempt, makeWorld, seedFinalizing, sha256, sid, syntheticBytes } from './support/world.mjs';

const TRIGGER_ABORT = 1811; // SQLITE_CONSTRAINT_TRIGGER

function published(world) {
  const { envelopeId } = seedFinalizing(world);
  const grant = lease(world, envelopeId, 'runner-a');
  const bytes = syntheticBytes('fen09-composed');
  const attemptRef = `tenants/${world.tenantId}/sha256/${sha256(bytes)}`;
  assert.equal(recordBlob(world.context(), holderOf(grant), attemptRef, 'composed'), true);
  const assembled = assembleAttempt(world, envelopeId);
  const publication = publish(world, grant, assembled);
  return { envelopeId, grant, attemptRef, publication, reportId: assembled.verificationReportId };
}

/** Every stored row of `table` with its rowid, for byte-for-byte comparison. */
function rowsOf(raw, table) {
  return raw.prepare(`SELECT rowid AS stored_rowid, * FROM ${table} ORDER BY rowid`).all();
}

function refusedByTrigger(raw, sql, params, pattern) {
  let caught;
  try {
    raw.prepare(sql).run(...params);
  } catch (error) {
    caught = error;
  }
  const seen = caught === undefined ? 'no error' : `${caught.code} ${caught.errcode}: ${String(caught.message).slice(0, 160)}`;
  assert.ok(caught?.code === 'ERR_SQLITE_ERROR' && caught.errcode === TRIGGER_ABORT && pattern.test(caught.message), `${sql} → ${seen}`);
}

/** The rows' rowids and count, for assertion messages. */
const rowids = (rows) => `${rows.length} row(s), rowids [${rows.map((row) => row.stored_rowid).join(',')}]`;

/** The stored rows of `table` are exactly `before`; the message carries both sides' rowids. */
function sameRows(raw, table, before, label) {
  const after = rowsOf(raw, table);
  assert.deepEqual(after, before, `${label}: ${table} before ${rowids(before)}, after ${rowids(after)}`);
}

/** Copy one stored row into a temp table, change `changes`, and try to put it back with `verb`. */
function replay(raw, table, where, params, changes, verb) {
  raw.exec('DROP TABLE IF EXISTS temp.replayed');
  // No bound parameter in DDL: an empty copy of the shape, then the row.
  raw.exec(`CREATE TEMP TABLE replayed AS SELECT * FROM main.${table} WHERE 0`);
  raw.prepare(`INSERT INTO temp.replayed SELECT * FROM main.${table} WHERE ${where}`).run(...params);
  for (const [column, value] of Object.entries(changes)) raw.prepare(`UPDATE temp.replayed SET ${column} = ?`).run(value);
  return `${verb} INTO main.${table} SELECT * FROM temp.replayed`;
}

test('[FEN-09] INSERT OR REPLACE, REPLACE and a plain duplicate cannot take a stored key on the four guarded tables', () => {
  const world = makeWorld();
  try {
    const { envelopeId, attemptRef, publication, reportId } = published(world);
    const raw = new DatabaseSync(world.dbPath);
    try {
      raw.exec('PRAGMA busy_timeout = 5000');
      const cases = [
        ['final_artifacts', 'envelope_id = ?', [envelopeId], {}, /final_artifacts key exists/],
        ['final_artifacts', 'envelope_id = ?', [envelopeId], { artifact_id: sid('art') }, /final_artifacts key exists/],
        ['verification_reports', 'id = ?', [reportId], {}, /verification_reports key exists/],
        ['outbox_events', 'event_id = ?', [publication.outboxEventId], {}, /outbox_events key exists/],
        // A second envelope.completed under a new event id would REPLACE the published one (0007's partial unique index).
        ['outbox_events', 'event_id = ?', [publication.outboxEventId], { event_id: sid('evt') }, /outbox_events key exists/],
        ['finalization_attempt_blobs', 'blob_ref = ?', [attemptRef], { role: 'package' }, /finalization_attempt_blobs key exists/],
      ];
      for (const [table, where, params, changes, pattern] of cases) {
        const before = rowsOf(raw, table);
        for (const verb of ['INSERT OR REPLACE', 'REPLACE', 'INSERT OR IGNORE', 'INSERT']) {
          refusedByTrigger(raw, replay(raw, table, where, params, changes, verb), [], pattern);
          sameRows(raw, table, before, `${verb} with ${JSON.stringify(changes)}`);
        }
      }
      // A rowid takeover: an insert naming a stored rowid under a new key.
      const [stored] = rowsOf(raw, 'finalization_attempt_blobs');
      const before = rowsOf(raw, 'finalization_attempt_blobs');
      refusedByTrigger(
        raw,
        'INSERT OR REPLACE INTO finalization_attempt_blobs (rowid, tenant_id, envelope_id, fencing_token, blob_ref, role, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [stored.stored_rowid, world.tenantId, envelopeId, 1, `tenants/${world.tenantId}/sha256/${sha256('fen09-other')}`, 'sealed', stored.recorded_at],
        /finalization_attempt_blobs key exists/,
      );
      sameRows(raw, 'finalization_attempt_blobs', before, `a takeover of rowid ${stored.stored_rowid}`);
      // Updates never move a rowid or a key.
      for (const [table, sql, pattern] of [
        ['final_artifacts', 'UPDATE OR REPLACE final_artifacts SET rowid = rowid + 1000', /final_artifacts rowid and key never change/],
        ['outbox_events', 'UPDATE OR REPLACE outbox_events SET rowid = rowid + 1000', /outbox_events rowid never changes/],
        ['verification_reports', 'UPDATE OR REPLACE verification_reports SET rowid = rowid + 1000', /verification_reports rows are immutable/],
        ['finalization_attempt_blobs', 'UPDATE OR REPLACE finalization_attempt_blobs SET rowid = rowid + 1000', /finalization_attempt_blobs rows are immutable/],
      ]) {
        const rows = rowsOf(raw, table);
        refusedByTrigger(raw, sql, [], pattern);
        sameRows(raw, table, rows, 'an UPDATE OR REPLACE of the rowid');
      }
      refusedByTrigger(raw, 'DELETE FROM finalization_attempt_blobs', [], /finalization_attempt_blobs rows are immutable/);
      raw.exec('DROP TABLE IF EXISTS temp.replayed');
    } finally {
      raw.close();
    }
    // Through the store, a duplicate surfaces as a trigger constraint.
    assert.throws(
      () => world.db.transaction(() => world.store.insert('finalization_attempt_blobs', { envelope_id: envelopeId, fencing_token: 1, blob_ref: attemptRef, role: 'composed', recorded_at: world.clock.iso() })),
      (error) => error instanceof StorageConstraintError && error.constraint === 'trigger',
    );
  } finally {
    world.close();
  }
});

test('[FEN-07] final_artifacts.approval_evidence_digest is required on insert, 64 lowercase hex digits, and immutable', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = published(world);
    const raw = new DatabaseSync(world.dbPath);
    try {
      raw.exec('PRAGMA busy_timeout = 5000');
      const before = rowsOf(raw, 'final_artifacts');
      assert.match(before[0].approval_evidence_digest, /^[0-9a-f]{64}$/);
      refusedByTrigger(raw, 'UPDATE final_artifacts SET approval_evidence_digest = ?', ['f'.repeat(64)], /final_artifacts rows are immutable/);
      refusedByTrigger(raw, 'UPDATE final_artifacts SET approval_evidence_digest = NULL', [], /final_artifacts rows are immutable/);
      sameRows(raw, 'final_artifacts', before, 'an update of approval_evidence_digest');
      // A second envelope leased at token 1, so 0005's fencing trigger and the key guard pass and only the digest decides.
      const second = seedFinalizing(world).envelopeId;
      lease(world, second, 'runner-b');
      const copy = (digest) => {
        raw.exec('DROP TABLE IF EXISTS temp.replayed');
        raw.exec('CREATE TEMP TABLE replayed AS SELECT * FROM main.final_artifacts WHERE 0');
        raw.prepare('INSERT INTO temp.replayed SELECT * FROM main.final_artifacts WHERE envelope_id = ?').run(envelopeId);
        raw.prepare('UPDATE temp.replayed SET envelope_id = ?, artifact_id = ?, approval_evidence_digest = ?').run(second, sid('art'), digest);
        return 'INSERT INTO main.final_artifacts SELECT * FROM temp.replayed';
      };
      for (const digest of [null, 'F'.repeat(64), 'f'.repeat(63), `${'f'.repeat(63)}g`]) {
        refusedByTrigger(raw, copy(digest), [], /final_artifacts approval_evidence_digest must be 64 lowercase hex digits/);
      }
      sameRows(raw, 'final_artifacts', before, 'inserts with a missing or malformed digest');
      // The positive control: the same row with a well-formed digest is accepted.
      raw.prepare(copy('e'.repeat(64))).run();
      const accepted = rowsOf(raw, 'final_artifacts');
      assert.equal(accepted.length, before.length + 1, `the well-formed copy is accepted: ${rowids(before)} → ${rowids(accepted)}`);
      raw.exec('DROP TABLE IF EXISTS temp.replayed');
    } finally {
      raw.close();
    }
  } finally {
    world.close();
  }
});
