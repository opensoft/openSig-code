// SPDX-License-Identifier: Apache-2.0
//
// Test-only steps shared by the completion tests (T038): lease an attempt,
// let its lease expire and be reclaimed so another attempt takes over,
// publish through the real publish transaction, record a failure and run an
// operator retry through the real domain operations.

import assert from 'node:assert/strict';

import { failAttempt, PublishRefused, publishFinalization, reclaimLease, retryFinalization } from '../../../src/domain/finalization/index.ts';
import { DEFAULT_LEASE_MS, grantLease, retryDelayMs } from '../../../src/storage/repositories/jobs.ts';
import { describe, snapshot } from './world.mjs';

/** The envelope's rows equal `before`; the message carries both sides' discriminating values. */
export function assertUnchanged(world, envelopeId, before, label) {
  const after = snapshot(world, envelopeId);
  assert.deepEqual(after, before, `${label}: before [${describe(before)}] after [${describe(after)}]`);
}

/** Grant `owner` the lease at the world's current instant. */
export function lease(world, envelopeId, owner) {
  const grant = world.db.transaction(() => grantLease(world.store, envelopeId, { owner, now: world.clock.now() }));
  assert.ok(grant, `${owner} is granted the lease on ${envelopeId}`);
  return grant;
}

export function holderOf(grant) {
  return { envelopeId: grant.envelopeId, fencingToken: grant.fencingToken, leaseOwner: grant.leaseOwner };
}

/** Let `stale`'s lease expire, reclaim it, wait out the retry delay, and lease the job to `owner`. */
export function takeOver(world, stale, owner) {
  world.clock.advance(DEFAULT_LEASE_MS + 1_000);
  const reclaimed = reclaimLease(world.context(), stale.envelopeId);
  assert.equal(reclaimed, 'retryable', `the expired lease of token ${stale.fencingToken} is reclaimed (got ${reclaimed})`);
  world.clock.advance(retryDelayMs(stale.attemptCount) + 1_000);
  const grant = lease(world, stale.envelopeId, owner);
  assert.equal(grant.fencingToken, stale.fencingToken + 1, `the new attempt holds token ${stale.fencingToken + 1} (got ${grant.fencingToken})`);
  return grant;
}

/** Publish `assembled` under `grant` through the real publish transaction. */
export function publish(world, grant, assembled, overrides = {}) {
  const { options, ...input } = overrides;
  return publishFinalization(
    world.db,
    {
      tenantId: world.tenantId,
      holder: holderOf(grant),
      expectedEnvelopeVersion: grant.reservedVersion,
      receiptHead: assembled.receiptHead,
      verificationReportId: assembled.verificationReportId,
      reportBytes: assembled.reportBytes,
      artifact: assembled.artifact,
      ...input,
    },
    { clock: world.clock.now, audit: world.audit, blobs: world.blobs, ...options },
  );
}

export function refusedWith(reason) {
  return (error) => error instanceof PublishRefused && error.reason === reason;
}

/** Record a failure of `grant`'s attempt through the domain (announces a move into failed). */
export function fail(world, grant, retryable, errorCode) {
  return failAttempt(world.context(), holderOf(grant), { retryable, errorCode });
}

/** An operator retry through the domain operation (actor: a synthetic human operator). */
export function retry(world, envelopeId, expectedVersion, key = `retry-key-${envelopeId}`.slice(0, 64)) {
  return retryFinalization(
    world.db,
    world.audit,
    { tenantId: world.tenantId, envelopeId, actor: { kind: 'human-operator', ref: 'admin-1' }, idempotency: { key, request: { expected_version: expectedVersion } } },
    { clock: world.clock.now },
  );
}

/** The envelope's audit events of `type`. */
export function eventsOf(world, envelopeId, type) {
  return world.store.list('audit_events', { envelope_id: envelopeId, type }, { orderBy: [['seq', 'asc']] });
}

/** The envelope's outbox events of `type`. */
export function outboxOf(world, envelopeId, type) {
  return world.store.list('outbox_events', { envelope_id: envelopeId, type });
}
