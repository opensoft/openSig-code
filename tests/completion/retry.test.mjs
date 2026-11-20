// SPDX-License-Identifier: Apache-2.0
//
// Retry rules (T038; data-model.md § Transitions and races, item 3; FEN-03;
// A-010 requests #28, #43, #44, #57, #59 (4), (6), (8), (9) and #62 (2)).
// Synthetic data in a migrated temporary database, with an injected clock.

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';

import { PackageError } from '../../src/artifacts/package.ts';
import { SealError } from '../../src/cryptograph/worker/index.ts';
import {
  acceptReport,
  classifyFailure,
  errorCodeOf,
  FinalizationError,
  LeaseLost,
  runVerification,
  StepFailure,
  UNRECOGNIZED_ERROR_CODE,
} from '../../src/domain/finalization/index.ts';
import { BlobTooLargeError } from '../../src/storage/blobs/index.ts';
import { grantLease, retryDelayMs } from '../../src/storage/repositories/jobs.ts';
import { assertUnchanged, eventsOf, fail, lease, outboxOf, publish, retry } from './support/steps.mjs';
import { assembleAttempt, hex, makeWorld, reportBytesFor, RESERVED_VERSION, seedFinalizing, sid, snapshot } from './support/world.mjs';

const conflict = (code, detail) => (error) =>
  error instanceof FinalizationError && error.code === code && error.status === 409 && JSON.stringify(error.details) === JSON.stringify(detail === undefined ? [] : [detail]);

const bodyOf = (result) => JSON.parse(result.bytes.toString('utf8'));
const verdictOf = (error) => (error instanceof Error ? `${error.name} ${error.code}.${error.reason} retryable=${error.retryable}` : String(error));

test('[FEN-03] a retry is refused from pending, running and succeeded, for a stale version and an unknown envelope, writing nothing', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world);
    const records = () => world.store.count('idempotency_records');
    let before = snapshot(world, envelopeId);
    assert.throws(() => retry(world, envelopeId, RESERVED_VERSION), conflict('finalization_not_retryable'), `pending ${envelopeId}`);
    assertUnchanged(world, envelopeId, before, 'a retry from pending wrote nothing');
    const grant = lease(world, envelopeId, 'runner-a');
    before = snapshot(world, envelopeId);
    assert.throws(() => retry(world, envelopeId, RESERVED_VERSION), conflict('finalization_not_retryable'), `running attempt ${grant.fencingToken}`);
    assert.throws(() => retry(world, envelopeId, RESERVED_VERSION + 1, 'retry-key-stale-version'), conflict('version_conflict'));
    assert.throws(() => retry(world, sid('env'), 1, 'retry-key-unknown-envelope'), (error) => error instanceof FinalizationError && error.code === 'not_found' && error.status === 404);
    assertUnchanged(world, envelopeId, before, 'retries while running, at a stale version and for an unknown envelope wrote nothing');
    publish(world, grant, assembleAttempt(world, envelopeId));
    before = snapshot(world, envelopeId);
    assert.throws(() => retry(world, envelopeId, RESERVED_VERSION + 1, 'retry-key-after-success'), conflict('finalization_not_retryable'), `succeeded at v${before.envelope.version}`);
    assertUnchanged(world, envelopeId, before, 'a retry after success wrote nothing');
    assert.equal(records(), 0, `a refused retry stores no idempotency record (got ${records()})`);
  } finally {
    world.close();
  }
});

test('[FEN-03] attempts are bounded; the move into failed is announced once; a retry from failed at the limit raises max_attempts by exactly one and is audited', () => {
  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world, { maxAttempts: 2 });
    const first = lease(world, envelopeId, 'runner-a');
    const firstOutcome = fail(world, first, true, 'seal_failed.worker-spawn-failed');
    assert.equal(firstOutcome, 'retryable', `attempt 1 of 2, retryable: ${firstOutcome}`);
    let job = snapshot(world, envelopeId).job;
    const retryAt = new Date(world.clock.now().getTime() + retryDelayMs(1)).toISOString();
    assert.equal(job.retry_at, retryAt, `bounded exponential retry_at ${job.retry_at}, expected ${retryAt}`);
    const quietOutbox = outboxOf(world, envelopeId, 'envelope.finalization_failed').length;
    const quietAudit = eventsOf(world, envelopeId, 'envelope.finalization_failed').length;
    assert.deepEqual([quietOutbox, quietAudit], [0, 0], `a retryable failure emits no outbox event (${quietOutbox}) and no audit event (${quietAudit})`);

    world.clock.advance(retryDelayMs(1));
    const second = lease(world, envelopeId, 'runner-b');
    const secondOutcome = fail(world, second, true, 'seal_failed.timeout');
    assert.equal(secondOutcome, 'failed', `attempt 2 of 2 leaves none: ${secondOutcome}`);
    job = snapshot(world, envelopeId).job;
    assert.deepEqual([job.status, job.attempt_count, job.max_attempts, job.retry_at], ['failed', 2, 2, null], `job ${job.status} ${job.attempt_count}/${job.max_attempts} retry_at ${job.retry_at}`);
    const failedEvents = outboxOf(world, envelopeId, 'envelope.finalization_failed');
    assert.equal(failedEvents.length, 1, `one finalization_failed outbox event (got ${failedEvents.length})`);
    assert.equal(failedEvents[0].envelope_version, RESERVED_VERSION, `announcing v${failedEvents[0].envelope_version}, the unchanged v${RESERVED_VERSION}`);
    const failedAudit = eventsOf(world, envelopeId, 'envelope.finalization_failed');
    assert.equal(failedAudit.length, 1, `and one audit event (got ${failedAudit.length})`);
    assert.deepEqual(JSON.parse(failedAudit[0].metadata_json), { attempt: 2, error_code: 'seal_failed.timeout' }, `metadata ${failedAudit[0].metadata_json}`);
    const claim = world.db.transaction(() => grantLease(world.store, envelopeId, { owner: 'runner-c', now: world.clock.now() }));
    assert.equal(claim, null, `a failed job is not claimable (got ${JSON.stringify(claim)})`);

    const result = retry(world, envelopeId, RESERVED_VERSION);
    assert.equal(result.status, 202, `status ${result.status}`);
    const body = bodyOf(result);
    assert.equal(body.finalization.job_status, 'retryable', `job_status ${body.finalization.job_status}`);
    assert.deepEqual(
      [body.finalization.attempts, body.finalization.max_attempts],
      [2, 3],
      `max_attempts rises by exactly one: attempts ${body.finalization.attempts}, max ${body.finalization.max_attempts}`,
    );
    const after = snapshot(world, envelopeId);
    assert.deepEqual(
      [after.job.status, after.job.attempt_count, after.job.max_attempts, after.job.fencing_token],
      ['retryable', 2, 3, 2],
      `job ${after.job.status} ${after.job.attempt_count}/${after.job.max_attempts}, attempt ${after.job.fencing_token}`,
    );
    assert.equal(after.envelope.version, RESERVED_VERSION, `the retry leaves the envelope at v${after.envelope.version}, the reserved v${RESERVED_VERSION}`);
    const retried = eventsOf(world, envelopeId, 'envelope.finalization_retried');
    assert.equal(retried.length, 1, `retried events ${retried.length}`);
    assert.deepEqual([retried[0].actor_kind, retried[0].actor_ref], ['human-operator', 'admin-1'], `the actor is ${retried[0].actor_kind} ${retried[0].actor_ref}`);
    assert.deepEqual(JSON.parse(retried[0].metadata_json), { envelope_version: RESERVED_VERSION, attempt_count: 2, max_attempts: 3 }, `metadata ${retried[0].metadata_json}`);

    const replay = retry(world, envelopeId, RESERVED_VERSION);
    assert.equal(replay.replayed, true, `replayed ${replay.replayed}`);
    assert.ok(replay.bytes.equals(result.bytes), `an exact replay returns the original ${result.bytes.length} bytes (got ${replay.bytes.length})`);
    assertUnchanged(world, envelopeId, after, 'the replay writes nothing');
    const retriedAgain = eventsOf(world, envelopeId, 'envelope.finalization_retried').length;
    assert.equal(retriedAgain, 1, `retried events after the replay ${retriedAgain}`);
    assert.throws(() => retry(world, envelopeId, RESERVED_VERSION + 1), (error) => error instanceof FinalizationError && error.code === 'idempotency_conflict');
    const third = lease(world, envelopeId, 'runner-c');
    assert.equal(third.fencingToken, 3, `the third attempt's number ${third.fencingToken}`);

    // Below the limit nothing is raised: a non-retryable failure, then a retry from failed, then one from retryable.
    const other = seedFinalizing(world, { maxAttempts: 5 });
    const refused = fail(world, lease(world, other.envelopeId, 'runner-d'), false, 'unsupported_pdf.report-invalid');
    assert.equal(refused, 'failed', `a non-retryable failure: ${refused}`);
    const announced = outboxOf(world, other.envelopeId, 'envelope.finalization_failed').length;
    assert.equal(announced, 1, `a non-retryable failure is announced once (got ${announced})`);
    const fromFailed = bodyOf(retry(world, other.envelopeId, RESERVED_VERSION)).finalization.max_attempts;
    assert.equal(fromFailed, 5, `below the limit max_attempts stays 5 (got ${fromFailed})`);
    const again = fail(world, lease(world, other.envelopeId, 'runner-e'), true, 'seal_failed.timeout');
    assert.equal(again, 'retryable', `attempt 2 of 5, retryable: ${again}`);
    const fromRetryable = bodyOf(retry(world, other.envelopeId, RESERVED_VERSION, 'retry-key-from-retryable')).finalization.max_attempts;
    assert.equal(fromRetryable, 5, `a retry from retryable raises nothing (got ${fromRetryable})`);
  } finally {
    world.close();
  }
});

test('[FEN-03] max_attempts never passes 100: at 99 the retry raises to 100, at 100 it answers attempt_ceiling and writes nothing', () => {
  const world = makeWorld();
  try {
    const exhausted = (attempts) => {
      const { envelopeId } = seedFinalizing(world, { maxAttempts: attempts });
      // Test-only premise: the job used every attempt and failed (0004 admits this row; attempts only grow).
      world.db.transaction(() =>
        world.store.update('signing_jobs', { envelope_id: envelopeId }, { attempt_count: attempts, fencing_token: attempts, status: 'failed', last_error_code: 'seal_failed.timeout' }),
      );
      return envelopeId;
    };
    const atNinetyNine = exhausted(99);
    const raised = bodyOf(retry(world, atNinetyNine, RESERVED_VERSION)).finalization.max_attempts;
    assert.equal(raised, 100, `99 of 99 rises to ${raised}`);
    const atHundred = exhausted(100);
    const before = snapshot(world, atHundred);
    assert.throws(() => retry(world, atHundred, RESERVED_VERSION), conflict('finalization_not_retryable', { field: 'envelope', code: 'attempt_ceiling' }));
    assertUnchanged(world, atHundred, before, 'the ceiling refusal wrote nothing');
    assert.deepEqual([before.job.attempt_count, before.job.max_attempts], [100, 100], `premise: ${before.job.attempt_count}/${before.job.max_attempts}`);
  } finally {
    world.close();
  }
});

const fakeWorker = (behave) => (spawned) => {
  const worker = new EventEmitter();
  worker.terminate = () => undefined;
  setImmediate(() => behave(worker, spawned));
  return worker;
};

const verifyJob = () => ({
  bytes: Buffer.from('synthetic non-pdf bytes'),
  anchors: [],
  expectedArtifactDigest: hex('pdf'),
  expectedApprovalEvidenceDigest: hex('evidence'),
  validationTime: new Date(0).toISOString(),
});

test('[FEN-03] failures follow their component’s flag; a T014 refusal or exception fails at once; a cap breach or a dead worker is retryable; last_error_code holds only a code and reason', async () => {
  const spawnFailed = new SealError('worker-spawn-failed');
  assert.deepEqual(
    [spawnFailed.code, spawnFailed.reason, spawnFailed.retryable],
    ['seal_failed', 'worker-spawn-failed', true],
    `premise: T037's landed classification is ${verdictOf(spawnFailed)}`,
  );
  assert.deepEqual(classifyFailure('seal', spawnFailed), { retryable: true, errorCode: 'seal_failed.worker-spawn-failed' });
  const refusal = Object.assign(new Error('synthetic title words from a document'), { code: 'unsupported_pdf', reason: 'report-invalid', detail: 'composition_too_large', retryable: false });
  assert.deepEqual(classifyFailure('compose', refusal), { retryable: false, errorCode: 'unsupported_pdf.report-invalid' });
  assert.equal(classifyFailure('compose', { code: 'internal', reason: 'Synthetic Deed Title', retryable: false }).errorCode, UNRECOGNIZED_ERROR_CODE);
  const long = errorCodeOf('a'.repeat(30), 'b'.repeat(30));
  assert.equal(long, UNRECOGNIZED_ERROR_CODE, `a 61-character code and reason is recorded as ${long}`);
  assert.deepEqual(classifyFailure('store', new BlobTooLargeError('synthetic')), { retryable: false, errorCode: 'blob_too_large.store' });
  // T016's refusal carries retryable: false; equal inputs fail the same way.
  assert.deepEqual(classifyFailure('package', new PackageError('cross-link', 'synthetic')), { retryable: false, errorCode: 'package_refused.cross-link' });
  assert.deepEqual(classifyFailure('package', new Error('synthetic')), { retryable: true, errorCode: 'internal.package' });

  // The verify step's verdicts (request #59 (6), #62 (2)).
  const job = verifyJob();
  const report = (overrides) => reportBytesFor({ artifactDigest: hex('pdf'), approvalEvidenceDigest: hex('evidence'), verifiedAt: job.validationTime, ...overrides });
  const accepted = acceptReport(report({}), job);
  assert.ok(accepted.length > 0, `the invariant holds for a matching report (${accepted.length} bytes)`);
  for (const [overrides, check] of [
    [{ integrity: 'invalid' }, 'integrity'],
    [{ coverage: 'incomplete' }, 'coverage'],
    [{ artifactDigest: hex('other') }, 'artifact-digest'],
    [{ evidenceCheck: 'fail' }, 'approval-evidence'],
  ]) {
    assert.throws(() => acceptReport(report(overrides), job), (error) => error instanceof StepFailure && !error.retryable && error.reason === check, `refused on ${check}`);
  }
  const outcome = (options) => runVerification(job, options).then(() => 'resolved', (error) => error);
  const timeout = await outcome({ capMs: 5, spawn: fakeWorker(() => undefined) });
  assert.deepEqual([timeout.code, timeout.reason, timeout.retryable], ['verification_timeout', 'cap', true], `cap breach: ${verdictOf(timeout)}`);
  const died = await outcome({ spawn: fakeWorker((worker) => worker.emit('exit', 1)) });
  assert.deepEqual([died.code, died.reason, died.retryable], ['verification_worker', 'died', true], `dead worker: ${verdictOf(died)}`);
  const thrown = await outcome({ spawn: fakeWorker((worker) => worker.emit('message', { kind: 'exception', code: 'anchors-invalid' })) });
  assert.deepEqual([thrown.code, thrown.reason, thrown.retryable], ['verification_error', 'anchors-invalid', false], `verifier exception: ${verdictOf(thrown)}`);
  const unavailable = await outcome({ spawn: fakeWorker((worker) => worker.emit('message', { kind: 'refused', field: 'approval_evidence_digest' })) });
  assert.deepEqual([unavailable.code, unavailable.reason, unavailable.retryable], ['verification_refused', 'report-unavailable', false], `no report: ${verdictOf(unavailable)}`);
  const controller = new AbortController();
  const aborted = outcome({ signal: controller.signal, spawn: fakeWorker(() => undefined) });
  controller.abort(new LeaseLost('fenced'));
  const abortOutcome = await aborted;
  assert.ok(abortOutcome instanceof LeaseLost, `the lease keeper's abort ends the verification (got ${verdictOf(abortOutcome)})`);

  const world = makeWorld();
  try {
    const { envelopeId } = seedFinalizing(world, { maxAttempts: 5 });
    const verdict = classifyFailure('verify', new StepFailure('verification_refused', 'integrity', false));
    const recorded = fail(world, lease(world, envelopeId, 'runner-a'), verdict.retryable, verdict.errorCode);
    assert.equal(recorded, 'failed', `a T014 refusal fails the job at once (got ${recorded} for ${verdict.errorCode})`);
    const stored = snapshot(world, envelopeId).job;
    assert.deepEqual([stored.last_error_code, stored.attempt_count], ['verification_refused.integrity', 1], `stored ${stored.last_error_code} after ${stored.attempt_count} attempt(s)`);
    assert.match(stored.last_error_code, /^[a-z0-9_.-]{1,60}$/);
  } finally {
    world.close();
  }
});

test('[FEN-03] the verify step runs T014 in a real worker thread from its .ts entry under the pinned node, and its verdict on non-PDF bytes is not retried', async () => {
  // No spawn seam: verify.ts starts node:worker_threads on verify-worker.ts (type stripping). A worker that
  // failed to load would surface as verification_worker.died (retryable); T014's verdict is a non-retryable failure.
  const real = await runVerification(verifyJob()).then(() => 'resolved', (error) => error);
  assert.ok(
    real instanceof StepFailure && real.retryable === false && ['verification_refused', 'verification_error'].includes(real.code),
    `node ${process.version}: the real worker answered ${verdictOf(real)}`,
  );
});
