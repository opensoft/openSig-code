// SPDX-License-Identifier: Apache-2.0
//
// T015's child entry: one finalization runner pass in its own OS process, on the case's database
// file and blob store. Usage, from the harness only (support/process.mjs):
//   node runner-child.mjs <job file> [--opensig-test-fault-hook=<phase>:<release FIFO>]
// - The job file (0600, in the case's 0700 directory) names the database, the blob root, the
//   synthetic seal-key placeholder, the lease owner, the lease length, the busy timeout and the
//   ONE instant this process runs on. The clock enters only through T038's test entry, the
//   FinalizationRunner options (request #61 (8)); it never reads wall time.
// - The fault hook (src/domain/finalization/fault-hook.ts) reads the flag from this command line,
//   and only there. A malformed flag is refused here, before any attempt.
// - The pass is the runner's own runOnce (src/jobs/finalize.ts:353-372 at 00b260f): reclaim
//   strictly expired leases, then run each claimable job once. The child never calls start(), so
//   no interval timer exists; before the database closes it awaits the runner's stop()
//   (:417-423, row RUNNER-STOP), the order SEC-16 uses, which resolves at once here because no
//   attempt is in flight once runOnce has settled. onError (:118, row RUN-ERRORS) reports only
//   start()'s scheduled runs; this child's own catch reports a rejected runOnce as its
//   {"event":"error"} line and exit 1, which every case treats as a failure.
// - As in T038's runner tests (tests/completion/runner.test.mjs), only the CPU-bound components
//   are deterministic fakes behind the runner's ports (T036 compose, T037 seal, T014 verify, T016
//   package); every durable step is the runner's: the grant, the anchor, the attempt records, the
//   blob writes, the checkpoint, the publish, the failure and reclaim records. The timers never
//   fire, so the keeper never renews; with the fixed clock its deadline never passes either.
// Stdout: the hook's {"event":"fault-hook",...} line, if held, then one
// {"event":"outcome","reclaimed":n,"attempts":[...]} line; on an unexpected error one
// {"event":"error",...} line and exit 1. Every handled outcome exits 0. Nothing else is printed.

import { readFileSync, writeSync } from 'node:fs';

import { canonicalBytes } from '../../../src/domain/canonical/index.ts';
import { parseFaultHookFlag } from '../../../src/domain/finalization/fault-hook.ts';
import { FinalizationRunner } from '../../../src/jobs/finalize.ts';
import { AuditWriter } from '../../../src/storage/audit/index.ts';
import { openBlobStore } from '../../../src/storage/blobs/index.ts';
import { openDatabase } from '../../../src/storage/db/index.ts';
import { reportBytesFor, sha256, syntheticBytes } from '../../completion/support/world.mjs';

const NEVER = Object.freeze({ setTimeout: () => 0, clearTimeout: () => undefined });

function emit(event) {
  writeSync(1, `${JSON.stringify(event)}\n`);
}

const ports = Object.freeze({
  // Deterministic over the document and sealTime, as T036 is.
  compose: async (request) => {
    const bytes = Buffer.concat([Buffer.from(request.document), Buffer.from(`synthetic composition at ${request.sealTime}`)]);
    return { bytes, digest: sha256(bytes), documentDigest: sha256(request.document), documentLength: request.document.length, byteRange: [0, 1, 2, 3], contents: { offset: 1, hexLength: 2 }, signedDataLength: 1, xrefKind: 'table' };
  },
  // Deterministic over the composition and the evidence digest (the product CMS has no signingTime).
  sealPdf: async (input) => {
    const bytes = Buffer.concat([Buffer.from(input.composed.bytes), Buffer.from(input.approvalEvidenceDigest)]);
    return { bytes, finalPdfDigest: sha256(bytes), signerCertificateSha256: sha256(input.certificateDer) };
  },
  verify: async (job) => reportBytesFor({ artifactDigest: job.expectedArtifactDigest, approvalEvidenceDigest: job.expectedApprovalEvidenceDigest, verifiedAt: job.validationTime }),
});

/** Stands in for T016's buildPackage (its own suite covers it): deterministic over the same input. */
function buildPackage(inputs) {
  const bytes = canonicalBytes({ synthetic_package: true, checkpoint: inputs.checkpoint, events: inputs.events.length, pdf: sha256(inputs.finalPdf) });
  return { bytes, packageDigest: sha256(bytes), artifactDigest: sha256(inputs.finalPdf) };
}

const jobPath = process.argv[2];
let db;
let runner;
try {
  if (typeof jobPath !== 'string' || jobPath.startsWith('-')) throw new TypeError('usage: runner-child.mjs <job file> [fault hook flag]');
  parseFaultHookFlag(process.argv);
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
    buildPackage,
    ports,
    timers: NEVER,
  });
  const report = await runner.runOnce();
  emit({ event: 'outcome', reclaimed: report.reclaimed, attempts: report.attempts.map((attempt) => attempt.outcome) });
} catch (error) {
  emit({ event: 'error', name: String(error?.name ?? 'Error'), code: typeof error?.code === 'string' ? error.code : null, message: String(error?.message ?? error).slice(0, 200) });
  process.exitCode = 1;
} finally {
  try {
    // RUNNER-STOP: nothing may run against a closed database.
    await runner?.stop();
  } finally {
    db?.close();
  }
}
