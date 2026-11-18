// SPDX-License-Identifier: Apache-2.0
//
// T008 recipient ceremony: calls that only read take no write lock (A-010 row
// READ-LOCK-CER, request #30; data-model.md § Persistence: a request path that
// only reads opens no transaction). node:sqlite is synchronous, so a read that
// waited for the write lock would stall the whole process, every listener
// included, for up to the busy timeout and then fail busy. CH-09 holds the
// write lock on a second connection to the same database file (BEGIN
// IMMEDIATE) and shows that readState, readDocument, readManifest and a
// session lookup that does not refresh each answer at once with what they give
// when nothing holds the lock, and that the prefetched session routes, which
// use only those calls, answer 200 at once with the same bytes and write
// nothing. Moving last_seen_at (a lookup that refreshes) is a write and still
// takes the lock; SC002-25 shows GET and HEAD still move it. A short busy
// timeout keeps a regression (a read in a transaction) to bounded waits that
// then fail busy; the lock is released in `finally`.

import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

import { COOKIE, createWorld, openSession, readAs, sentEnvelope } from './support.mjs';

/** The world database's bounded wait for the write lock: short, so a read that waits fails fast. */
const LOCK_WAIT_MS = 1_000;

const SESSION_ROUTES = Object.freeze(['/v1/recipient-session', '/v1/recipient-session/document', '/v1/recipient-session/manifest']);
const PREFETCH = Object.freeze({ 'sec-purpose': 'prefetch' });

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

test('[CH-09] ceremony calls that only read take no write lock: while another connection holds it, readState, readDocument, readManifest and a lookup that does not refresh each answer at once, the prefetched session routes answer 200 at once, and nothing is written (A-010 READ-LOCK-CER, request #30)', async (t) => {
  const world = await createWorld({ busyTimeoutMs: LOCK_WAIT_MS });
  try {
    const { pdf, token } = await sentEnvelope(world);
    const { session: value } = await openSession(world, token);
    const request = { headers: { cookie: `${COOKIE}=${value}` } };
    const session = world.ceremony.authenticate(request, { refresh: false });
    assert.ok(session !== null, 'premise: the session is live');

    // What each call and route gives when nothing holds the lock.
    const unlocked = {
      lookup: session,
      state: world.ceremony.readState(session),
      document: world.ceremony.readDocument(session),
      manifest: world.ceremony.readManifest(session),
    };
    assert.ok(unlocked.document.equals(pdf), 'premise: readDocument gives the frozen bytes');
    const unlockedRoutes = new Map();
    for (const path of SESSION_ROUTES) {
      const response = await readAs(world, value, path, { headers: PREFETCH });
      assert.equal(response.status, 200, `premise: prefetch ${path} is 200 with no lock held`);
      unlockedRoutes.set(path, response.bytes);
    }
    const rows = world.snapshot();
    const busy = world.db.busyTimeoutMs;
    assert.equal(busy, LOCK_WAIT_MS, 'the ceremony connection waits at most the short busy timeout');
    assert.equal(writeLockHeldElsewhere(world.path), false, 'before the window, nothing holds the write lock');

    // A second connection on the same database file holds the write lock for the whole window.
    const locker = new DatabaseSync(world.path);
    let calls;
    const fetched = [];
    let heldThroughout;
    try {
      locker.exec('BEGIN IMMEDIATE');
      calls = {
        lookup: timed(() => world.ceremony.authenticate(request, { refresh: false })),
        state: timed(() => world.ceremony.readState(session)),
        document: timed(() => world.ceremony.readDocument(session)),
        manifest: timed(() => world.ceremony.readManifest(session)),
      };
      for (const path of SESSION_ROUTES) {
        const started = performance.now();
        const response = await readAs(world, value, path, { headers: PREFETCH });
        fetched.push({ path, response, ms: performance.now() - started });
      }
      // Still held at the end of the window, so every call and request above ran under it.
      heldThroughout = writeLockHeldElsewhere(world.path);
    } finally {
      if (locker.isTransaction) locker.exec('ROLLBACK');
      locker.close();
    }
    t.diagnostic(
      `under a held write lock: ${Object.entries(calls)
        .map(([name, outcome]) => `${name} ${Math.round(outcome.ms)} ms`)
        .join(', ')}; ${fetched.map(({ path, ms }) => `prefetch ${path} ${Math.round(ms)} ms`).join(', ')} (busy timeout ${busy} ms)`,
    );

    assert.equal(heldThroughout, true, 'the other connection held the write lock throughout the window');
    for (const [name, outcome] of Object.entries(calls)) {
      assert.equal(outcome.error, undefined, `${name} answered while another connection held the write lock (got ${outcome.error})`);
      assert.ok(outcome.ms < busy / 2, `${name} answered at once: ${Math.round(outcome.ms)} ms, against a busy timeout of ${busy} ms`);
    }
    assert.deepEqual(calls.lookup.value, unlocked.lookup, 'the lookup that does not refresh gives the same session, last_seen_at unmoved');
    assert.deepEqual(calls.state.value, unlocked.state, 'readState gives the unlocked state');
    assert.ok(Buffer.isBuffer(calls.document.value) && calls.document.value.equals(unlocked.document), 'readDocument gives the exact frozen bytes');
    assert.ok(Buffer.isBuffer(calls.manifest.value) && calls.manifest.value.equals(unlocked.manifest), 'readManifest gives the exact manifest bytes');
    for (const { path, response, ms } of fetched) {
      assert.equal(response.status, 200, `prefetch ${path} is 200 while another connection holds the write lock (got ${response.status} ${response.json?.code ?? ''})`);
      assert.ok(response.bytes.equals(unlockedRoutes.get(path)), `prefetch ${path} gives the unlocked bytes`);
      // Any wait for the lock lasts at least the busy timeout, because the lock is held throughout.
      assert.ok(ms < busy, `prefetch ${path} answered without waiting for the lock: ${Math.round(ms)} ms, against a busy timeout of ${busy} ms`);
    }

    assert.equal(world.db.inTransaction, false, 'no read left a transaction open');
    assert.deepEqual(world.snapshot(), rows, 'nothing was written, not even last_seen_at');
    assert.equal(writeLockHeldElsewhere(world.path), false, 'after the window, the write lock is free again');
  } finally {
    await world.close();
  }
});
