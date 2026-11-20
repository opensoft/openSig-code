// SPDX-License-Identifier: Apache-2.0
//
// Reads take no write lock (T007; A-010 row READ-LOCK-ENV, request #30;
// data-model.md § Persistence: a request path that only reads opens no
// transaction). node:sqlite is synchronous, so a read that waited for the
// write lock would stall the whole process for up to the busy timeout and
// then fail busy. ST-17 holds the write lock on a second connection to the
// same database file (BEGIN IMMEDIATE) and shows that `read` and `preview`,
// the calls behind readEnvelope and readRecipientPreview, answer at once with
// the views they give when nothing holds the lock, and that their refusals do
// too. A short busy timeout keeps a regression (a read in a transaction) to
// one bounded wait, which then fails busy; the lock is released in `finally`.

import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { after, test } from 'node:test';

import {
  createInput,
  HUMAN,
  makeScratch,
  preparedEnvelope,
  rawConnection,
  rejectsWith,
  req,
  SERVICE,
  setup,
  sid,
} from './support.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

/** The scratch database's bounded wait for the write lock: short, so a read that waits fails fast. */
const LOCK_WAIT_MS = 1_000;

/** True when a fresh connection that never waits cannot take the write lock: another connection holds it. */
function writeLockHeldElsewhere(path) {
  const probe = new DatabaseSync(path, { timeout: 0 });
  try {
    probe.exec('BEGIN IMMEDIATE');
    probe.exec('ROLLBACK');
    return false;
  } catch (error) {
    if (/database is locked/.test(String(error?.message))) return true;
    throw error;
  } finally {
    probe.close();
  }
}

/** Run `fn`, returning its result (or thrown error) and how long it took, in ms. */
function timed(fn) {
  const started = performance.now();
  try {
    return { value: fn(), error: undefined, ms: performance.now() - started };
  } catch (error) {
    return { value: undefined, error, ms: performance.now() - started };
  }
}

function answered(label, outcome) {
  assert.equal(outcome.error, undefined, `${label} answered while another connection held the write lock (got ${outcome.error})`);
  return outcome.value;
}

test('[ST-17] read and preview take no write lock: while another connection holds it, each answers at once with its unlocked view, its refusals do too, and nothing is written (A-010 READ-LOCK-ENV, request #30)', (t) => {
  const ctx = setup(scratch, { busyTimeoutMs: LOCK_WAIT_MS });
  try {
    const prepared = preparedEnvelope(ctx);
    const draft = ctx.service.create(req(ctx.tenant, HUMAN), createInput()).body;
    // The views when nothing holds the lock.
    const unlockedRead = ctx.service.read(req(ctx.tenant, HUMAN), prepared.id);
    const unlockedPreview = ctx.service.preview(req(ctx.tenant, SERVICE), prepared.id);
    const changes = ctx.changes.length;
    const busy = ctx.db.busyTimeoutMs;
    assert.equal(busy, LOCK_WAIT_MS, 'the service connection waits at most the short busy timeout');
    assert.equal(writeLockHeldElsewhere(ctx.path), false, 'before the window, nothing holds the write lock');

    // A second connection on the same database file holds the write lock for the whole window.
    const locker = rawConnection(ctx.path);
    let read;
    let preview;
    let missing;
    let notPrepared;
    let heldThroughout;
    try {
      locker.exec('BEGIN IMMEDIATE');
      read = timed(() => ctx.service.read(req(ctx.tenant, HUMAN), prepared.id));
      preview = timed(() => ctx.service.preview(req(ctx.tenant, SERVICE), prepared.id));
      missing = timed(() => ctx.service.read(req(ctx.tenant, HUMAN), sid('missing')));
      notPrepared = timed(() => ctx.service.preview(req(ctx.tenant, HUMAN), draft.id));
      // Still held at the end of the window, so every call above ran under it.
      heldThroughout = writeLockHeldElsewhere(ctx.path);
    } finally {
      if (locker.isTransaction) locker.exec('ROLLBACK');
      locker.close();
    }
    t.diagnostic(
      `under a held write lock: read ${Math.round(read.ms)} ms, preview ${Math.round(preview.ms)} ms, ` +
        `not_found ${Math.round(missing.ms)} ms, state_conflict ${Math.round(notPrepared.ms)} ms (busy timeout ${busy} ms)`,
    );

    assert.equal(heldThroughout, true, 'the other connection held the write lock throughout the window');
    assert.deepEqual(answered('read', read), unlockedRead, 'read under the held lock gives the unlocked view');
    assert.deepEqual(answered('preview', preview), unlockedPreview, 'preview under the held lock gives the unlocked view');
    rejectsWith(() => {
      throw missing.error;
    }, 'not_found', 404);
    rejectsWith(() => {
      throw notPrepared.error;
    }, 'state_conflict', 409);
    for (const [label, outcome] of [
      ['read', read],
      ['preview', preview],
      ['the not_found read', missing],
      ['the state_conflict preview', notPrepared],
    ]) {
      assert.ok(outcome.ms < busy / 2, `${label} answered at once: ${Math.round(outcome.ms)} ms, against a busy timeout of ${busy} ms`);
    }

    assert.equal(ctx.db.inTransaction, false, 'no read left a transaction open');
    assert.equal(ctx.changes.length, changes, 'no read reported a change');
    assert.deepEqual(ctx.service.read(req(ctx.tenant, HUMAN), prepared.id), unlockedRead, 'the envelope is unchanged, at the same version');
    assert.equal(writeLockHeldElsewhere(ctx.path), false, 'after the window, the write lock is free again');
  } finally {
    ctx.db.close();
  }
});
