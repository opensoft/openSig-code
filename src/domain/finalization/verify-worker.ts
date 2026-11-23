// SPDX-License-Identifier: Apache-2.0
//
// The verification worker thread (T038; A-010 request #62 (2)). It runs
// T014's verifyPdf and buildVerificationReport over the sealed bytes, off the
// runner's event loop, and posts exactly one message back:
// - { kind: 'report', bytes }: the RFC 8785 bytes of the contract
//   VerificationReport, the exact bytes the publish stores and T016 serves;
// - { kind: 'refused', field }: T014 refused to emit a contract report;
// - { kind: 'exception', code }: verifyPdf threw (a VerifierConfigError code,
//   or 'unexpected').
// It returns only these values and never touches the database, the blob
// store, a key or the network. The parent ends it on lease loss or at the
// wall-time cap.

import { parentPort, workerData } from 'node:worker_threads';

import { canonicalBytes, type JsonValue } from '../../domain/canonical/index.ts';
import { buildVerificationReport, VerifierConfigError, verifyPdf } from '../../verifier/index.ts';

export interface VerifyJob {
  readonly bytes: Uint8Array;
  readonly anchors: readonly string[];
  readonly expectedArtifactDigest: string;
  readonly expectedApprovalEvidenceDigest: string;
  /** ISO time: T014's validationTime and the report's verified_at. */
  readonly validationTime: string;
}

export type VerifyMessage =
  | { readonly kind: 'report'; readonly bytes: Uint8Array }
  | { readonly kind: 'refused'; readonly field: string }
  | { readonly kind: 'exception'; readonly code: string };

function run(job: VerifyJob): VerifyMessage {
  try {
    const validationTime = new Date(job.validationTime);
    const outcome = verifyPdf(job.bytes, {
      anchors: job.anchors,
      expectedArtifactDigest: job.expectedArtifactDigest,
      expectedApprovalEvidenceDigest: job.expectedApprovalEvidenceDigest,
      validationTime,
    });
    const built = buildVerificationReport(outcome, { verifiedAt: validationTime });
    if (!built.ok) return { kind: 'refused', field: built.field };
    return { kind: 'report', bytes: canonicalBytes(built.report as unknown as JsonValue) };
  } catch (error) {
    return { kind: 'exception', code: error instanceof VerifierConfigError ? error.code : 'unexpected' };
  }
}

if (parentPort !== null) parentPort.postMessage(run(workerData as VerifyJob));
