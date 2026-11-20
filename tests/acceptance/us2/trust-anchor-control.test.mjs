// SPDX-License-Identifier: Apache-2.0
//
// T017 [US2-ANCHOR-CONTROL]: an extra ID. It is not one of us2-local's 12 required IDs, and the
// frozen runner never counts it among them: scripts/verify.mjs collects every passing "[ID]" into
// passed_case_ids, while only requiredCases decide cases found and missing.
//
// A-010 request #88 item 2 (N2), by the driver's word. It proves the composed runner's own anchor
// wiring, "the runner receives exactly the validated values" (the T031 line, request #81 (10)).
// Nothing else reaches that wiring:
// - T031's `server` mode cannot, because a real attempt needs T033's sandbox and `server` declares
//   none;
// - the ten SC001 flows cannot, because they expect `untrusted` against their unrelated anchor, as
//   a runner given no anchors would also produce;
// - [US2-TAMPER]'s seal-certificate control runs both checkers on bytes and never touches the
//   runner.
// The ten flows, SC005-01 and SC005-02 are unchanged by this file.
//
// - Its own composed server: harness.mjs startWorld with anchors 'seal-certificate'. It has its own
//   startServer, database, blobs (<data>/blobs), spool and seal pair, in this file's own process.
//   The seal pair is made as for every world: an RSA-3072 key and its self-signed development
//   certificate. The anchors file (OPENSIG_TRUST_ANCHORS_FILE) holds exactly that certificate's PEM
//   bytes, the matching anchor.
// - The trust path, by src/verifier/trust.ts evaluateTrust: a signer byte-identical to a
//   configured anchor is `trusted` with detail `anchor-direct`, and trust_anchor_ref is that
//   anchor's DER SHA-256. With no anchors the detail is `no-anchor-configured`, and trust is never
//   `trusted`.
// - One flow through the normal entry points:
//   - the sender's operator steps (create, upload through T033's parse, prepare, preview, confirm,
//     send);
//   - one recipient over the shell's three recipient routes (HTTP with the shell's Origin and CSRF
//     token, as SC005-02);
//   - T038's composed runner at its next tick, within the harness deadline
//     (COMPLETION_DEADLINE_MS).
// - The order precondition, the first thing the test does, before any server, browser or key
//   material starts (request #88: the control runs AFTER the SC005-02 burst). The frozen runner runs
//   expandGlobs(MODES['us2-local'].files) in that sorted order, one file at a time (executeFiles
//   awaits runFile, which returns only once the file's process has closed). This file is named
//   trust-anchor-control.test.mjs so that it sorts after concurrent.test.mjs (the SC005-02 burst),
//   flows.test.mjs (the ten flows and SC005-01) and static.test.mjs, and runs LAST.
//   assertRunsAfterBurst() computes that list with the runner's own exported expandGlobs and the
//   us2-local glob from MODES, read-only, and asserts that this file sorts strictly after the one
//   file declaring the SC005-02 test. If it does not, the extra flow never starts. [US2-STATIC]
//   checks the same order statically.
// - The composition precondition: the composition REPORTS the matching anchor to the runner
//   (composition.finalizationOptions, T031's self-report). Mutant M-R3 leaves that report unchanged,
//   so a failure after it isolates the runner's own wiring.
// - The assertion expected to kill M-R3 (the composed runner built with anchors: [] while the
//   reported options stay unchanged; M-R3 is run once, by T017's fresh recheck, request #88): the
//   STORED verification report must say `trusted` through `anchor-direct`, naming the seal
//   certificate. That report is the runner's own result, served by readVerification and byte-equal
//   to the package's verification.json.
// - Outside SC005: by the order above, the SC005-02 burst and the ten flows with SC005-01 have
//   finished, and their processes have closed, before this file starts. Nothing here enters
//   evidence.json's timing or flow_attempts, or flows.json. Its own record is anchor-control.json
//   beside them.
// - Stopped and reaped: the test closes the server and awaits it within CLOSE_DEADLINE_MS. close()
//   resolves only after:
//   - the runner's stop();
//   - every handler settled;
//   - the database closed.
//   The server's own log must then show the runner `stopped` and a `closed` record. That record
//   must faithfully report T033's historical ended-child count, with no stop past the cap. That
//   cumulative count may include benign cleanup after the launcher exits (request #17); it is
//   not a survivor count. After awaited close, parseCapacity must show no running or waiting parse.
//   T033 settles each parse only once its captured sandbox members have terminated.
// - It imports harness.mjs and, read-only, the frozen runner's scripts/verify.mjs (expandGlobs) and
//   scripts/verify-modes.mjs (MODES). None of them imports an oracle module, and verify.mjs runs its
//   main only as the entry file, so this file and its targeted run load in a tree without the
//   oracle's directory ([US2-STATIC] pins that).

import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { performance } from 'node:perf_hooks';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { expandGlobs } from '../../../scripts/verify.mjs';
import { MODES } from '../../../scripts/verify-modes.mjs';
import { parseCapacity, parseOrphans } from '../../../src/pdf/service.ts';
import { openPackage, recordAnchorControl, REPO, scrub, sha256, startWorld } from './harness.mjs';

const CASE = 'US2-ANCHOR-CONTROL';
const DOCUMENT = 'single-page.pdf';
const PAGE = 1;
/** The bound on closing the control's server, after its one flow completed. */
const CLOSE_DEADLINE_MS = 30_000;
/** A file declaring the SC005-02 test (built from pieces, so this file's own text never matches). */
const DECLARES_BURST = new RegExp(['\\btest\\(\\s*', "'\\[", 'SC005-02', '\\]'].join(''));

let world;

after(async () => {
  await world?.close();
});

/**
 * The order precondition (request #88): the frozen runner's own file list for us2-local, sorted
 * as it runs it, must put this file strictly after the one file that declares the SC005-02 test.
 * Returns the list and both indexes for the record.
 */
function assertRunsAfterBurst() {
  const self = relative(REPO, fileURLToPath(import.meta.url)).split(sep).join('/');
  const list = expandGlobs(REPO, MODES['us2-local'].files);
  const burst = list.filter((file) => DECLARES_BURST.test(readFileSync(join(REPO, file), 'utf8')));
  assert.equal(burst.length, 1, `exactly one us2-local file declares the SC005-02 test (found ${burst.length}: ${burst.join(', ') || 'none'}; the runner's sorted list: ${list.join(', ')})`);
  const order = { list, self, burst: burst[0], selfIndex: list.indexOf(self), burstIndex: list.indexOf(burst[0]) };
  assert.ok(
    order.selfIndex > order.burstIndex,
    `the frozen runner runs us2-local's files in this sorted order, one at a time: ${list.join(', ')}. ${self} (index ${order.selfIndex}) must sort strictly after ${order.burst} (index ${order.burstIndex}), the SC005-02 burst, so the extra flow starts only after it (request #88)`,
  );
  return order;
}

/** `promise`, or a failure naming `what` once `ms` have passed. */
async function within(promise, ms, what) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${what} did not settle within ${ms} ms`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** The server's own log records (JSON lines from its logSink). */
function logRecords(lines) {
  return lines.flatMap((line) => {
    try {
      return [JSON.parse(line)];
    } catch {
      return [];
    }
  });
}

test('[US2-ANCHOR-CONTROL] an extra control, never one of the 12 required IDs, run after the SC005-02 burst: on its own composed server whose anchors file holds the matching anchor (the development seal certificate), one flow through T038\'s composed runner completes and the stored verification report says trusted through anchor-direct; the server is then closed, awaited and reaped', async () => {
  // The order precondition first: nothing starts unless the runner runs this file after the burst.
  const order = assertRunsAfterBurst();
  world = await startWorld({ label: 'us2a', anchors: 'seal-certificate' });
  const seal = world.material.sealCertificateSha256;
  assert.deepEqual(
    { anchors: world.material.anchors, anchor: world.material.anchorCertificateSha256 },
    { anchors: 'seal-certificate', anchor: seal },
    `this world's anchors file holds the seal certificate ${seal} (found ${world.material.anchors}, ${world.material.anchorCertificateSha256})`,
  );
  // The composition precondition (T031's self-report; M-R3 leaves it unchanged): the composition
  // reports exactly the matching anchor as the runner's.
  const reported = world.running.composition.finalizationOptions?.anchors ?? [];
  const reportedSha256 = reported.map((pem) => sha256(new X509Certificate(pem).raw));
  assert.deepEqual(reportedSha256, [seal], `the composition reports exactly the matching anchor to the runner (reported: ${reportedSha256.join(', ') || 'none'}; the seal certificate ${seal})`);

  // One flow through the normal entry points, finalized by the composed runner.
  const to = world.address('anchor-control');
  const sent = await world.sentEnvelope({ flow: CASE, document: DOCUMENT, page: PAGE, recipients: [to] });
  const id = sent.id;
  const recipient = await world.recipientOverHttp(to, 'Anchor Control Recipient');
  const answer = await recipient.approve();
  assert.equal(answer.status, 200, `${CASE}: the approval answers 200, not ${answer.status} (${answer.json?.code ?? ''})`);
  assert.equal(answer.json.envelope_state, 'finalizing', `${CASE}: the approval moves envelope ${id} to finalizing (${answer.json.envelope_state})`);
  const waitStarted = performance.now();
  await world.awaitCompleted(id);
  const waitedMs = performance.now() - waitStarted;
  const { envelope, verification, pkg } = await world.retrieve(id, CASE);
  const report = verification.json;
  const opened = openPackage(pkg.bytes);
  const servedIsPackaged = opened.members['verification.json'].bytes.equals(verification.bytes);
  const trustCheck = Array.isArray(report?.checks) ? (report.checks.find((check) => check.id === 'trust-anchors') ?? null) : null;
  const observed = {
    trust: report?.trust ?? null,
    trust_check: trustCheck === null ? null : `${trustCheck.result}/${trustCheck.detail_code ?? '-'}`,
    trust_anchor_ref: report?.trust_anchor_ref ?? null,
  };

  // Stop the control's server now, bounded, so it is gone whatever the verdict.
  const closeStarted = performance.now();
  let closeError = null;
  try {
    await within(world.close(), CLOSE_DEADLINE_MS, `the ${CASE} server's close`);
  } catch (error) {
    closeError = error;
  }
  const closeMs = performance.now() - closeStarted;
  const capacityAfterClose = parseCapacity();
  const endedAfterClose = parseOrphans().orphans_ended;
  const records = logRecords(world.lines);
  const shutdown = records.find((record) => record.event === 'shutdown') ?? null;
  const closed = records.find((record) => record.event === 'closed') ?? null;
  const round = (ms) => Math.round(ms * 10) / 10;

  // Its own record, before the assertions, so a failing control is diagnosable.
  recordAnchorControl({
    case: CASE,
    scope: 'an extra control outside the 12 required IDs and outside SC005 (A-010 request #88 item 2, N2): one flow through the composed runner on its own server, whose anchors file holds the matching anchor',
    trust_path_expected: 'anchor-direct: the signer is byte-identical to the configured anchor (src/verifier/trust.ts evaluateTrust)',
    runner_order: { files: order.list, control_index: order.selfIndex, burst_file: order.burst, burst_index: order.burstIndex },
    seal_certificate_sha256: seal,
    reported_anchor_sha256: reportedSha256,
    stored_report: {
      ...observed,
      integrity: report?.integrity ?? null,
      revision_coverage: report?.revision_coverage ?? null,
      signer_certificate_sha256: report?.signer_certificate_sha256 ?? null,
      served_equals_packaged: servedIsPackaged,
    },
    artifact_summary: { integrity: envelope.artifact?.integrity ?? null, trust: envelope.artifact?.trust ?? null },
    finalization: { job_status: envelope.finalization?.job_status ?? null, attempts: envelope.finalization?.attempts ?? null },
    waited_for_completion_ms: round(waitedMs),
    server_close: {
      ms: round(closeMs),
      error: closeError === null ? null : scrub(closeError.message ?? closeError),
      runner: shutdown?.finalization ?? null,
      closed_logged: closed !== null,
      parse_orphans_ended: closed?.parse_orphans_ended ?? null,
      actual_parse_orphans_ended: endedAfterClose,
      parse_capacity_after_close: { running: capacityAfterClose.running, waiting: capacityAfterClose.waiting },
      parse_stops_past_cap: closed?.parse_stops_past_cap ?? null,
      run_failures_logged: records.filter((record) => record.event === 'finalization_run_failed').length,
    },
  });

  // The flow completed through the runner, and the report read is the one it stored.
  assert.deepEqual(
    { state: envelope.state, job: envelope.finalization?.job_status },
    { state: 'completed', job: 'succeeded' },
    `${CASE}: envelope ${id} is completed by the runner (state ${envelope.state}, job ${envelope.finalization?.job_status} after ${envelope.finalization?.attempts} attempt(s))`,
  );
  assert.equal(servedIsPackaged, true, `${CASE}: the served verification report (${sha256(verification.bytes)}) is the package's verification.json (${sha256(opened.members['verification.json'].bytes)}), the runner's stored result`);
  assert.equal(report?.signer_certificate_sha256, seal, `${CASE}: the seal's signer is the development certificate ${seal} (found ${report?.signer_certificate_sha256})`);
  assert.deepEqual({ integrity: report.integrity, revision_coverage: report.revision_coverage }, { integrity: 'valid', revision_coverage: 'complete' }, `${CASE}: integrity ${report.integrity}, coverage ${report.revision_coverage}`);

  // The assertion expected to kill M-R3 (run once by T017's fresh recheck, request #88): the runner
  // judged trust against the anchor the composition validated.
  assert.deepEqual(
    observed,
    { trust: 'trusted', trust_check: 'pass/anchor-direct', trust_anchor_ref: seal },
    `${CASE}: the runner's stored verification report for envelope ${id} says trust ${observed.trust}, trust-anchors ${observed.trust_check}, trust_anchor_ref ${observed.trust_anchor_ref}; the trust path for the matching anchor is anchor-direct (trusted, pass/anchor-direct, ${seal}). The composition reported ${reportedSha256.length} anchor(s) to the runner, so untrusted with no-anchor-configured means the runner was built without them (mutant M-R3)`,
  );
  assert.equal(envelope.artifact?.trust, 'trusted', `${CASE}: the stored artifact summary says trust ${envelope.artifact?.trust}`);

  // Stopped, awaited and reaped.
  assert.equal(closeError, null, `${CASE}: the server closed within ${CLOSE_DEADLINE_MS} ms (${closeError?.message ?? ''})`);
  assert.equal(shutdown?.finalization, 'stopped', `${CASE}: the server's shutdown record shows the runner stopped (${shutdown?.finalization ?? 'no shutdown record'})`);
  assert.ok(closed !== null, `${CASE}: the server logged closed, after the runner's stop, every handler and the database`);
  assert.deepEqual(
    { orphans: closed.parse_orphans_ended, past_cap: closed.parse_stops_past_cap },
    { orphans: endedAfterClose, past_cap: 0 },
    `${CASE}: the closed log reports the actual historical ended-child total ${endedAfterClose} (logged ${closed.parse_orphans_ended}), not live survivors, and no stop past the cap (${closed.parse_stops_past_cap})`,
  );
  assert.deepEqual(
    { running: capacityAfterClose.running, waiting: capacityAfterClose.waiting },
    { running: 0, waiting: 0 },
    `${CASE}: no parser work remains after awaited close (running ${capacityAfterClose.running}, waiting ${capacityAfterClose.waiting}; historical children ended ${endedAfterClose})`,
  );
});
