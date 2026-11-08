// SPDX-License-Identifier: Apache-2.0
//
// Retention and disposal (T029).

export { MAX_RETENTION_DAYS, parseRetentionPolicy, RetentionPolicyError, type RetentionPolicy, type RetentionScope } from './policy.ts';
export {
  DISPOSAL_RECORD_SCHEMA,
  RetentionService,
  TERMINAL_STATES,
  type DisposalOutcome,
  type RetentionRun,
  type RetentionServiceOptions,
} from './service.ts';
