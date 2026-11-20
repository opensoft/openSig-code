// SPDX-License-Identifier: Apache-2.0
//
// The verify step (T038; A-010 requests #59 (6) and #62 (2)). T014 runs in a
// worker thread (verify-worker.ts), so request handling and lease renewal
// continue during it. The lease keeper's abort ends it (the worker is
// terminated). A wall-time cap of at least 120 s is a fail-closed safety net,
// not a verdict.
//
// Outcomes:
// - the report bytes, when T014's report shows the invariant: integrity
//   `valid`, revision_coverage `complete`, the artifact digest equal to the
//   sealed bytes' digest, the approval-evidence digest equal to the
//   manifest's, and both checks `pass` (trust is not required: a development
//   certificate is `untrusted`);
// - StepFailure verification_refused.<check>, not retryable: a verdict
//   outside the invariant, or no contract report (request #59 (6));
// - StepFailure verification_error.<code>, not retryable: an exception the
//   verifier reports;
// - StepFailure verification_timeout.cap or verification_worker.died,
//   retryable: the cap breached, or the worker died before answering;
// - the abort's reason (LeaseLost), when the lease was lost: the attempt
//   writes nothing more.

import { Worker } from 'node:worker_threads';

import { FinalArtifactInvalid, readReport } from '../../storage/repositories/artifacts.ts';
import { StepFailure } from './failure.ts';
import { LeaseLost } from './lease.ts';
import type { VerifyJob, VerifyMessage } from './verify-worker.ts';

/** The fail-closed wall-time cap (request #62 (2): at least 120 s). */
export const VERIFY_WALL_CAP_MS = 120_000;

export interface VerifyWorker {
  on(event: string, listener: (...args: never[]) => void): unknown;
  terminate(): unknown;
}

export interface VerifyOptions {
  readonly signal?: AbortSignal;
  /** At least VERIFY_WALL_CAP_MS in production; tests may lower it. */
  readonly capMs?: number;
  /** Worker seam (default: a worker thread running verify-worker.ts). */
  readonly spawn?: (job: VerifyJob) => VerifyWorker;
}

const ENTRY = new URL('./verify-worker.ts', import.meta.url);
const CODE = /^[a-z][a-z0-9_-]{0,39}$/;

function defaultSpawn(job: VerifyJob): VerifyWorker {
  return new Worker(ENTRY, { workerData: job });
}

function refused(check: string): StepFailure {
  return new StepFailure('verification_refused', check, false);
}

/** Check T014's report bytes against the completion invariant; returns them unchanged. */
export function acceptReport(bytes: Uint8Array, job: VerifyJob): Uint8Array {
  let report: ReturnType<typeof readReport>;
  try {
    report = readReport(bytes);
  } catch (error) {
    if (error instanceof FinalArtifactInvalid) throw refused('report-invalid');
    throw error;
  }
  if (report.integrity !== 'valid') throw refused('integrity');
  if (report.revisionCoverage !== 'complete') throw refused('coverage');
  if (report.artifactDigest !== job.expectedArtifactDigest) throw refused('artifact-digest');
  if (report.approvalEvidenceDigest !== job.expectedApprovalEvidenceDigest) throw refused('approval-evidence');
  const result = (id: string): unknown => {
    const check = report.checks.find((entry) => typeof entry === 'object' && entry !== null && (entry as { readonly id?: unknown }).id === id);
    return check === undefined ? undefined : (check as { readonly result?: unknown }).result;
  };
  if (result('artifact-digest') !== 'pass') throw refused('artifact-digest');
  if (result('approval-evidence-digest') !== 'pass') throw refused('approval-evidence');
  return bytes;
}

function settle(message: unknown, job: VerifyJob): Uint8Array {
  const reply = message as VerifyMessage;
  if (typeof reply !== 'object' || reply === null) throw new StepFailure('verification_worker', 'died', true);
  if (reply.kind === 'report' && reply.bytes instanceof Uint8Array) return acceptReport(reply.bytes, job);
  if (reply.kind === 'refused') throw refused('report-unavailable');
  if (reply.kind === 'exception') throw new StepFailure('verification_error', typeof reply.code === 'string' && CODE.test(reply.code) ? reply.code : 'unexpected', false);
  throw new StepFailure('verification_worker', 'died', true);
}

/** Run T014 off the event loop under the cap and the lease keeper's signal. */
export function runVerification(job: VerifyJob, options: VerifyOptions = {}): Promise<Uint8Array> {
  const capMs = options.capMs ?? VERIFY_WALL_CAP_MS;
  if (!Number.isSafeInteger(capMs) || capMs < 1) throw new TypeError('the verification cap must be a positive integer of ms');
  const signal = options.signal;
  if (signal?.aborted === true) return Promise.reject(signal.reason ?? new LeaseLost('fenced'));
  return new Promise<Uint8Array>((resolve, reject) => {
    const worker = (options.spawn ?? defaultSpawn)(job);
    let done = false;
    const finish = (outcome: () => Uint8Array): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      void worker.terminate();
      try {
        resolve(outcome());
      } catch (error) {
        reject(error);
      }
    };
    const onAbort = (): void => {
      finish(() => {
        throw signal?.reason ?? new LeaseLost('fenced');
      });
    };
    const timer = setTimeout(() => {
      finish(() => {
        throw new StepFailure('verification_timeout', 'cap', true);
      });
    }, capMs);
    signal?.addEventListener('abort', onAbort, { once: true });
    worker.on('message', (message: unknown) => finish(() => settle(message, job)));
    worker.on('error', () =>
      finish(() => {
        throw new StepFailure('verification_worker', 'died', true);
      }),
    );
    worker.on('exit', () =>
      finish(() => {
        throw new StepFailure('verification_worker', 'died', true);
      }),
    );
  });
}
