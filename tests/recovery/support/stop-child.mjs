// SPDX-License-Identifier: Apache-2.0
//
// CONTINGENT (row RUNNER-STOP; the T038 slot recheck's surviving mutant S7). Included only if
// the orchestrator relays that ruling. Tests only.
//
// One runner pass in its own OS process that stops itself from inside the first attempt, at an
// await, as a shutdown does: the fake compose step calls the runner's stop()
// (src/jobs/finalize.ts:417-423 at 00b260f) and then returns its result. The keeper's abort
// (lease.ts:113-115, cause 'stopped') makes the next checkHeld() (finalize.ts:257) refuse, so the
// attempt ends 'lost' and writes nothing more (:210). runOnce must then reclaim and claim nothing
// on any later tenant (:360), and claim nothing more on this one (:179).
// Usage: node stop-child.mjs <job file>. The job file is as runner-child.mjs's; the clock is the
// one fixed instant it names. No fault hook flag is passed. Stdout: one
// {"event":"outcome","reclaimed":n,"attempts":[{"tenant":...,"outcome":...}],"stopCalls":n} line,
// or one {"event":"error",...} line and exit 1.

import { readFileSync, writeSync } from 'node:fs';

import { canonicalBytes } from '../../../src/domain/canonical/index.ts';
import { FinalizationRunner } from '../../../src/jobs/finalize.ts';
import { AuditWriter } from '../../../src/storage/audit/index.ts';
import { openBlobStore } from '../../../src/storage/blobs/index.ts';
import { openDatabase } from '../../../src/storage/db/index.ts';
import { reportBytesFor, sha256, syntheticBytes } from '../../completion/support/world.mjs';

const NEVER = Object.freeze({ setTimeout: () => 0, clearTimeout: () => undefined });

function emit(event) {
  writeSync(1, `${JSON.stringify(event)}\n`);
}

const jobPath = process.argv[2];
let db;
let runner;
let stopping = null;
let stopCalls = 0;
try {
  const job = JSON.parse(readFileSync(jobPath, 'utf8'));
  if (!Number.isSafeInteger(job.clockMs)) throw new TypeError('the job names no instant');
  const clock = () => new Date(job.clockMs);
  db = openDatabase({ path: job.dbPath, busyTimeoutMs: job.busyTimeoutMs });
  runner = new FinalizationRunner({
    db,
    audit: new AuditWriter(db, { clock }),
    blobs: openBlobStore({ root: job.blobRoot }),
    clock,
    owner: job.owner,
    leaseMs: job.leaseMs,
    seal: { keyFile: job.sealKeyFile, certificateDer: syntheticBytes('certificate-der', 64), developmentCertificate: true },
    anchors: [],
    buildPackage: (inputs) => {
      const bytes = canonicalBytes({ synthetic_package: true, checkpoint: inputs.checkpoint, events: inputs.events.length, pdf: sha256(inputs.finalPdf) });
      return { bytes, packageDigest: sha256(bytes), artifactDigest: sha256(inputs.finalPdf) };
    },
    ports: {
      compose: async (request) => {
        // The shutdown arrives while the first attempt awaits its composition.
        if (stopping === null) {
          stopCalls += 1;
          stopping = runner.stop();
        }
        const bytes = Buffer.concat([Buffer.from(request.document), Buffer.from(`synthetic composition at ${request.sealTime}`)]);
        return { bytes, digest: sha256(bytes), documentDigest: sha256(request.document), documentLength: request.document.length, byteRange: [0, 1, 2, 3], contents: { offset: 1, hexLength: 2 }, signedDataLength: 1, xrefKind: 'table' };
      },
      sealPdf: async (input) => {
        const bytes = Buffer.concat([Buffer.from(input.composed.bytes), Buffer.from(input.approvalEvidenceDigest)]);
        return { bytes, finalPdfDigest: sha256(bytes), signerCertificateSha256: sha256(input.certificateDer) };
      },
      verify: async (verifyJob) => reportBytesFor({ artifactDigest: verifyJob.expectedArtifactDigest, approvalEvidenceDigest: verifyJob.expectedApprovalEvidenceDigest, verifiedAt: verifyJob.validationTime }),
    },
    timers: NEVER,
  });
  const report = await runner.runOnce();
  await stopping;
  emit({ event: 'outcome', reclaimed: report.reclaimed, attempts: report.attempts.map((attempt) => ({ tenant: attempt.tenantId, outcome: attempt.outcome })), stopCalls });
} catch (error) {
  emit({ event: 'error', name: String(error?.name ?? 'Error'), code: typeof error?.code === 'string' ? error.code : null, message: String(error?.message ?? error).slice(0, 200) });
  process.exitCode = 1;
} finally {
  try {
    await runner?.stop();
  } finally {
    db?.close();
  }
}
