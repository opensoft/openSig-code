// SPDX-License-Identifier: Apache-2.0
//
// Retention and disposal (T029). BlobDisposer is the one disposal path, shared
// by retention and the orphan collector (T038).

export { MAX_RETENTION_DAYS, parseRetentionPolicy, RetentionPolicyError, type RetentionPolicy, type RetentionScope } from './policy.ts';
export {
  BlobDisposer,
  DISPOSAL_KINDS,
  DISPOSAL_RECORD_SCHEMA,
  RETENTION_BATCH_SIZE,
  RetentionService,
  TERMINAL_STATES,
  type BlobDisposerOptions,
  type DisposalKind,
  type DisposalOutcome,
  type DisposalRequest,
  type RetentionRun,
  type RetentionServiceOptions,
} from './service.ts';
