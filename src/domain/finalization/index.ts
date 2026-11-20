// SPDX-License-Identifier: Apache-2.0
//
// Verified durable completion (T038): the domain half of the finalization
// runner (src/jobs/finalize.ts). The verification worker entry
// (verify-worker.ts) is loaded only as a worker thread, never from here.

export { ATTEMPT_CEILING_DETAIL, FinalizationError, PublishRefused, type FinalizationErrorCode, type FinalizationErrorDetail, type PublishRefusalReason } from './errors.ts';
export { classifyFailure, errorCodeOf, StepFailure, UNRECOGNIZED_ERROR_CODE, type FailureStage, type FailureVerdict } from './failure.ts';
export { LeaseKeeper, LeaseLost, type LeaseKeeperOptions, type LeaseLossCause, type LeaseTimers } from './lease.ts';
export { APPROVAL_MANIFEST_SCHEMA, buildPreSealManifest, readSealRecords, type PreSealManifest, type PreSealManifestInput, type SealRecords } from './manifest.ts';
export { FINALIZATION_ACTOR_REF, publishFinalization, type Publication, type PublishInput, type PublishOptions, type ReceiptHead } from './publish.ts';
export { FINALIZATION_RETRIED, RETRY_ROUTE, RETRY_STATUS, retryFinalization, type RetryActor, type RetryRequest, type RetryResult } from './retry.ts';
export {
  failAttempt,
  FINALIZATION_FAILED,
  reclaimLease,
  recordBlob,
  SEAL_STARTED,
  writeCompletionCheckpoint,
  writeSealAnchor,
  type SealAnchor,
  type StepContext,
} from './transitions.ts';
export { acceptReport, runVerification, VERIFY_WALL_CAP_MS, type VerifyOptions, type VerifyWorker } from './verify.ts';
