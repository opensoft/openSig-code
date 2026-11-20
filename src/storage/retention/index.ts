// SPDX-License-Identifier: Apache-2.0
//
// Retention and disposal (T029). BlobDisposer is the one disposal path, shared
// by retention and the orphan collector (T038). ReferenceProtection is the one
// reference-protection predicate, shared by the disposer and backup (T030).

export { MAX_RETENTION_DAYS, parseRetentionPolicy, RetentionPolicyError, type RetentionPolicy, type RetentionScope } from './policy.ts';
export {
  BLOB_REFERENCE_COLUMNS,
  BlobDisposer,
  DISPOSAL_KINDS,
  DISPOSAL_RECORD_SCHEMA,
  ReferenceProtection,
  RETENTION_BATCH_SIZE,
  RetentionService,
  TERMINAL_STATES,
  type BlobDisposerOptions,
  type DisposalContext,
  type DisposalKind,
  type DisposalOutcome,
  type DisposalRequest,
  type ProtectionOptions,
  type ReferenceKind,
  type RetentionRun,
  type RetentionServiceOptions,
} from './service.ts';
