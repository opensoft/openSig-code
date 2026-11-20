// SPDX-License-Identifier: Apache-2.0
//
// Per-tenant audit hash chain (T029).

export {
  ACTOR_KINDS,
  AUDIT_EVENT_SCHEMA,
  digestInput,
  eventDigest,
  eventFromRow,
  recordFromRow,
  type ActorKind,
  type AuditActor,
  type AuditEvent,
  type AuditEventRecord,
} from './event.ts';
export { envelopeAuditRecords, verifyChain, type ChainProblem, type ChainProblemKind, type ChainReport, type VerifyOptions } from './verify.ts';
export {
  AuditWriter,
  CHECKPOINT_INTERVAL,
  MAX_METADATA_BYTES,
  MAX_METADATA_STRING,
  type AppendedAuditEvent,
  type AuditEventInput,
  type AuditHead,
  type AuditWriterOptions,
  type CompletionCheckpoint,
} from './writer.ts';
