// SPDX-License-Identifier: Apache-2.0
//
// The publish transaction (T038; data-model.md § Envelope states, completed,
// and § Transitions and races, item 2; A-008 P04; A-010 S4 and request #59).
//
// One BEGIN IMMEDIATE transaction, statements in this order (request #59):
// 1. The job fence and completion: signing_jobs moves running -> succeeded
//    only WHERE status = 'running' AND fencing_token = <token> AND
//    lease_owner = <owner> AND lease_expires_at > <now> (strict, request #59
//    (11)) AND version = <read>. No row: PublishRefused('fence'). FEN-05.
// 2. The envelope: it must be finalizing (PublishRefused('state')), and
//    envelopes moves finalizing -> completed only WHERE version = the
//    reserved version the attempt worked against (PublishRefused('version')).
// 3. The receipt head: the envelope's completion checkpoint, written once at
//    package assembly (T029), must be the head the package's receipt ends at
//    (PublishRefused('checkpoint')).
// 4. The FinalArtifact insert, with package_digest, the package blob ref and
//    approval_evidence_digest; 0005's fencing trigger re-checks the token.
// 5. Exactly one verification_reports row, whose report_bytes are T014's
//    exact report bytes; final_artifacts.verification_json holds the same
//    report (request #59 (9)).
// 6. The `envelope.completed` audit event, which follows the receipt's head.
// 7. The `envelope.completed` outbox event (T030), announcing the version
//    written in step 2; 0007 and 0019 admit one per envelope.
// Every refusal is thrown inside the transaction callback, so it rolls back:
// a stale token, a stale version or a wrong state writes nothing, and a
// refused attempt writes no verification_reports row. The callback is
// synchronous, so no other code of this process runs between BEGIN and
// COMMIT, and WAL readers on other connections see none of it before COMMIT.
// A refused attempt's blobs stay unreferenced by any final artifact, so they
// stay collectable (data-model.md § Entities, FinalizationAttemptBlob).
//
// Before BEGIN, with no await in between, the values are checked against the
// contract (row P13), the report is checked to describe exactly this artifact,
// and every blob the artifact references is confirmed stored intact; after
// COMMIT the artifact row protects those blobs from disposal.

import type { AuditWriter } from '../../storage/audit/index.ts';
import type { BlobStore } from '../../storage/blobs/index.ts';
import type { Database } from '../../storage/db/index.ts';
import { enqueueOutboxEvent } from '../../storage/outbox/index.ts';
import {
  FinalArtifactInvalid,
  getCompletionCheckpoint,
  insertFinalArtifact,
  insertVerificationReport,
  readReport,
  validateFinalArtifact,
  type NewFinalArtifact,
} from '../../storage/repositories/artifacts.ts';
import { compareAndSetEnvelope, getEnvelope } from '../../storage/repositories/envelopes.ts';
import { completeJob, type LeaseHolder } from '../../storage/repositories/jobs.ts';
import { PublishRefused } from './errors.ts';
import { FINALIZATION_ACTOR_REF } from './transitions.ts';

export { FINALIZATION_ACTOR_REF };

const DIGEST = /^[0-9a-f]{64}$/;

export interface ReceiptHead {
  readonly seq: number;
  readonly digest: string;
}

export interface PublishInput {
  readonly tenantId: string;
  readonly holder: LeaseHolder;
  /** The reserved version (the envelope version written on entering finalizing). */
  readonly expectedEnvelopeVersion: number;
  /** The chain head the package's audit receipt ends at. */
  readonly receiptHead: ReceiptHead;
  /** The verification_reports row id. */
  readonly verificationReportId: string;
  /** T014's exact report bytes (the verify step's output). */
  readonly reportBytes: Uint8Array;
  readonly artifact: Omit<NewFinalArtifact, 'envelopeId' | 'fencingToken' | 'completedAt' | 'verificationJson' | 'verifierName' | 'verifierVersion' | 'signerCertificateSha256'>;
}

export interface PublishOptions {
  readonly clock: () => Date;
  readonly audit: AuditWriter;
  readonly blobs: BlobStore;
  /** Outbox event id source (default: T030's random id). */
  readonly newEventId?: () => string;
}

export interface Publication {
  readonly envelopeId: string;
  readonly artifactId: string;
  readonly artifactDigest: string;
  readonly packageDigest: string;
  /** The envelope version the publish wrote (reserved version + 1). */
  readonly envelopeVersion: number;
  readonly outboxEventId: string;
  readonly completedEventSeq: number;
  readonly completedAt: string;
}

function checkInput(input: PublishInput): void {
  if (typeof input !== 'object' || input === null) throw new TypeError('a publish input is required');
  if (!Number.isSafeInteger(input.expectedEnvelopeVersion) || input.expectedEnvelopeVersion < 1) {
    throw new TypeError('the expected envelope version must be a positive integer');
  }
  const head = input.receiptHead;
  if (typeof head !== 'object' || head === null || !Number.isSafeInteger(head.seq) || head.seq < 1 || typeof head.digest !== 'string' || !DIGEST.test(head.digest)) {
    throw new TypeError('the receipt head must be a chain seq and its event digest');
  }
}

/** Publish one verified, stored attempt (see the header). Throws PublishRefused when the attempt lost. */
export function publishFinalization(db: Database, input: PublishInput, options: PublishOptions): Publication {
  checkInput(input);
  const now = options.clock();
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('the publish clock returned an invalid date');
  const completedAt = now.toISOString();
  const { tenantId, holder } = input;
  const report = readReport(input.reportBytes);
  if (report.artifactDigest !== input.artifact.artifactDigest) throw new FinalArtifactInvalid('report.artifact_digest');
  if (report.approvalEvidenceDigest !== input.artifact.approvalEvidenceDigest) throw new FinalArtifactInvalid('report.approval_evidence_digest');
  const artifact: NewFinalArtifact = {
    ...input.artifact,
    envelopeId: holder.envelopeId,
    fencingToken: holder.fencingToken,
    completedAt,
    signerCertificateSha256: report.signerCertificateSha256,
    verifierName: report.verifierName,
    verifierVersion: report.verifierVersion,
    verificationJson: Buffer.from(input.reportBytes).toString('utf8'),
  };
  validateFinalArtifact(artifact);
  for (const digest of [artifact.artifactDigest, artifact.evidenceDigest, artifact.packageDigest]) {
    if (options.blobs.check(tenantId, digest) !== 'ok') throw new PublishRefused('blob');
  }
  const store = db.forTenant(tenantId);
  return db.transaction((): Publication => {
    if (!completeJob(store, holder, now)) throw new PublishRefused('fence');
    const envelope = getEnvelope(store, holder.envelopeId);
    if (envelope === undefined || envelope.state !== 'finalizing') throw new PublishRefused('state');
    if (!compareAndSetEnvelope(store, holder.envelopeId, input.expectedEnvelopeVersion, { state: 'completed', updatedAt: completedAt })) {
      throw new PublishRefused('version');
    }
    const checkpoint = getCompletionCheckpoint(store, holder.envelopeId);
    if (checkpoint === undefined || checkpoint.seq !== input.receiptHead.seq || checkpoint.digest !== input.receiptHead.digest) {
      throw new PublishRefused('checkpoint');
    }
    insertFinalArtifact(store, artifact);
    insertVerificationReport(store, { id: input.verificationReportId, envelopeId: holder.envelopeId, reportBytes: input.reportBytes });
    const completed = options.audit.append(tenantId, {
      type: 'envelope.completed',
      actor: { kind: 'system', ref: FINALIZATION_ACTOR_REF },
      envelopeId: holder.envelopeId,
      subjectDigest: artifact.artifactDigest,
      metadata: { artifact_id: artifact.artifactId, attempt: holder.fencingToken },
    });
    const envelopeVersion = input.expectedEnvelopeVersion + 1;
    const event = enqueueOutboxEvent(
      db,
      tenantId,
      { type: 'envelope.completed', envelopeId: holder.envelopeId, envelopeVersion, artifactId: artifact.artifactId, artifactDigest: artifact.artifactDigest },
      { clock: () => now, newId: options.newEventId },
    );
    return {
      envelopeId: holder.envelopeId,
      artifactId: artifact.artifactId,
      artifactDigest: artifact.artifactDigest,
      packageDigest: artifact.packageDigest,
      envelopeVersion,
      outboxEventId: event.eventId,
      completedEventSeq: completed.seq,
      completedAt,
    };
  });
}
