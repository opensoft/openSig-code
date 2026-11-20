// SPDX-License-Identifier: Apache-2.0
//
// T017 [SC005-02] (plan.md § Case catalogs SC-005: finalization max ≤ 60 s, n = 10 concurrent; the
// T017 line with A-010 request #78 (2) and (3)), labelled indicative-local and never a claim of
// SC-005, whose declared single-instance pilot hardware stays an OPEN gate. Its own world
// (harness.mjs), so it never shares a server with the ten SC001 flows.
//
// The workload is the bounded functional SC-005 workload the driver admitted (request #78 (3)):
// normal application entry points, the existing fixture agreement-multipage.pdf, resource and time
// bounds, and the host load recorded before and after. Nothing else is added:
// - ten one-recipient envelopes are prepared and sent one at a time, and each recipient opens a
//   session over HTTP (the shell's three recipient routes, with its Origin and CSRF token; no
//   browser, since this case measures finalization, not review) and reads the document, but does
//   not approve yet;
// - the ten final approvals are then sent in ONE burst, one request each. Each moves its envelope
//   into `finalizing` in the approval's own transaction (data-model.md);
// - finalization is the product's own: T038's runner at code 7257167, composed by the T031 US2 slot,
//   ticks every DEFAULT_RUN_INTERVAL_MS (15 s), claims at most 10 jobs per tenant per run and runs
//   them one attempt at a time. So the ten wait for the next tick and are then finalized in turn;
//   the 60 s maximum includes that queueing (request #78 (2));
// - a hard harness deadline bounds the wait (awaitAllCompleted): on expiry the case fails with each
//   envelope's state and job, and it never waits unbounded;
// - each finalization is timed from its last approval's server_time to its artifact's
//   completed_at, and the case asserts the maximum ≤ 60 s;
// - recorded, labelled indicative-local: every interval; the burst's spread; the peak overlap, as
//   two measured figures, neither asserted: envelopes in `finalizing` at once (from server_time to
//   completed_at), and attempts in progress at once (from each package receipt's
//   envelope.seal_started to completed_at); each envelope's PDF sizes (the base and final.pdf); the
//   attempts; the runner's interval; the host's CPU count; and the 1-minute load before and after
//   (spec.md SC-005: report hardware, PDF sizes and measurement separately). The evidence never
//   calls a peak below ten "ten concurrent finalizations".
// - each burst package is also opened: its four JSON members validate against the contract
//   (request #76 (3)), and its receipt shows no operator retry (request #78 (8)).

import assert from 'node:assert/strict';
import { availableParallelism, loadavg } from 'node:os';
import { after, before, test } from 'node:test';

import { DEFAULT_RUN_INTERVAL_MS } from '../../../src/jobs/finalize.ts';
import { bindOracleLabels, fixture, openPackage, recordEvidence, startWorld, summarize } from './harness.mjs';
import { oracleLabels } from './oracle.mjs';

const N = 10;
const DOCUMENT = 'agreement-multipage.pdf';
const PAGE = 3;
const BOUND_MS = 60_000;
/** The ten approvals count as one burst only if they enter `finalizing` within this spread. */
const BURST_SPREAD_MS = 10_000;
/** The hard harness deadline for the whole burst (request #78 (2)). */
const DEADLINE_MS = 180_000;
const SEAL_STARTED = 'envelope.seal_started';
const OPERATOR_RETRY_EVENT = 'envelope.finalization_retried';

let world;

before(async () => {
  // Request #78 (1): this file records evidence, so it binds the oracle's labels (harness.mjs imports no oracle).
  bindOracleLabels(oracleLabels);
  world = await startWorld({ label: 'us2c' });
});

after(async () => {
  await world?.close();
});

/** The largest number of [start, end] intervals open at one moment (an end before a start at a tie). */
function peakOverlap(starts, ends) {
  const moments = starts.flatMap((at, index) => [[at, 1], [ends[index], -1]]).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let open = 0;
  let peak = 0;
  for (const [, change] of moments) {
    open += change;
    peak = Math.max(peak, open);
  }
  return peak;
}

test('[SC005-02] indicative-local finalization timing: ten envelopes released in one burst, the slowest finalization within 60 s (SC-005 n = 10 concurrent envelopes); the overlaps are measured and recorded, never asserted; never a claim of SC-005', async () => {
  const { entry } = fixture(DOCUMENT);
  const held = [];
  for (let index = 0; index < N; index += 1) {
    const to = world.address(`burst-${index + 1}`);
    const sent = await world.sentEnvelope({ flow: `SC005-02 envelope ${index + 1}`, document: DOCUMENT, page: PAGE, recipients: [to] });
    held.push({ id: sent.id, recipient: await world.recipientOverHttp(to, `Burst Recipient ${index + 1}`) });
  }
  const ids = held.map(({ id }) => id);

  const loadBefore = loadavg()[0];
  const answers = await Promise.all(held.map(({ recipient }) => recipient.approve()));
  for (const [index, answer] of answers.entries()) {
    assert.equal(answer.status, 200, `envelope ${ids[index]}: its burst approval answers 200, not ${answer.status} (${answer.json?.code ?? ''})`);
    assert.equal(answer.json.envelope_state, 'finalizing', `envelope ${ids[index]}: its approval moves it to finalizing (${answer.json.envelope_state})`);
  }
  const seenAt = await world.awaitAllCompleted(ids, DEADLINE_MS);
  const loadAfter = loadavg()[0];

  // After the burst: each envelope and its package, read once (never navigation samples).
  const envelopes = [];
  const packages = [];
  for (const id of ids) {
    envelopes.push(await world.readEnvelope(id));
    const pkg = await world.operator({ path: `/v1/envelopes/${id}/package` });
    assert.equal(pkg.status, 200, `envelope ${id}: downloadPackage answers 200, not ${pkg.status}`);
    packages.push(openPackage(pkg.bytes));
  }

  const enteredAt = answers.map((answer) => Date.parse(answer.json.server_time));
  const completedAt = envelopes.map((envelope) => Date.parse(envelope.artifact?.completed_at ?? ''));
  const sealStartedAt = packages.map((opened) => Date.parse(opened.members['audit-receipt.json'].value.events?.find((event) => event.type === SEAL_STARTED)?.server_time ?? ''));
  const serverMs = completedAt.map((at, index) => at - enteredAt[index]);
  const clientMs = seenAt.map((at, index) => at - answers[index].receivedAtMs);
  const spread = Math.max(...enteredAt) - Math.min(...enteredAt);
  const round = (value) => Math.round(value * 100) / 100;
  const figures = {
    scope: 'indicative-local',
    envelopes_released_in_one_burst: N,
    bound_ms: BOUND_MS,
    runner_interval_ms: DEFAULT_RUN_INTERVAL_MS,
    intervals: ids.map((_, index) => ({
      envelope: index + 1,
      server_measured_ms: serverMs[index],
      waited_before_attempt_ms: sealStartedAt[index] - enteredAt[index],
      attempt_window_ms: completedAt[index] - sealStartedAt[index],
      client_observed_ms: round(clientMs[index]),
      base_pdf_bytes: entry.bytes,
      final_pdf_bytes: packages[index].entries.get('final.pdf')?.length ?? null,
      attempts: envelopes[index].finalization?.attempts ?? null,
    })),
    server_measured: summarize(serverMs),
    client_observed: summarize(clientMs),
    burst_spread_ms: spread,
    peak_envelopes_in_finalizing_at_once: peakOverlap(enteredAt, completedAt),
    peak_attempts_in_progress_at_once: peakOverlap(sealStartedAt, completedAt),
    peak_note: 'measured, not asserted: envelopes in finalizing at once (server_time to completed_at) and attempts in progress at once (envelope.seal_started to completed_at); the runner runs one attempt at a time, and no figure here is called ten concurrent finalizations',
    document: { file: DOCUMENT, pages: entry.pages.length },
    cpus: availableParallelism(),
    load_1m_before: round(loadBefore),
    load_1m_after: round(loadAfter),
    measured: 'server_measured = artifact completed_at minus the final approval server_time (the move into finalizing), queueing for the runner tick included; client_observed = first read of completed minus the approval answer, polled every 200 ms',
  };
  recordEvidence({ timing: { finalization: figures } });

  for (const [index, envelope] of envelopes.entries()) {
    const id = ids[index];
    assert.deepEqual(
      { state: envelope.state, job: envelope.finalization?.job_status, integrity: envelope.artifact?.integrity, trust: envelope.artifact?.trust },
      { state: 'completed', job: 'succeeded', integrity: 'valid', trust: 'untrusted' },
      `envelope ${id}: a supported, verified finalization (state ${envelope.state}, job ${envelope.finalization?.job_status} after ${envelope.finalization?.attempts} attempt(s), integrity ${envelope.artifact?.integrity}, trust ${envelope.artifact?.trust})`,
    );
    for (const member of Object.values(packages[index].members)) {
      assert.deepEqual(member.errors, [], `envelope ${id}: ${member.name} validates against the contract schema ${member.schema}; a failure is a finding against ${member.producer} (first errors: ${member.errors.slice(0, 5).join('; ')})`);
    }
    const retried = packages[index].members['audit-receipt.json'].value.events.filter((event) => event.type === OPERATOR_RETRY_EVENT).length;
    assert.equal(retried, 0, `envelope ${id}: no operator retry (${retried} found)`);
    assert.ok(Number.isFinite(serverMs[index]) && serverMs[index] >= 0, `envelope ${id}: its finalization time is measurable on the server's clock (${serverMs[index]} ms)`);
    assert.ok(Number.isFinite(sealStartedAt[index]), `envelope ${id}: its package receipt carries ${SEAL_STARTED}`);
  }
  assert.ok(spread <= BURST_SPREAD_MS, `the ten final approvals entered finalizing within one burst: spread ${spread} ms, at most ${BURST_SPREAD_MS} ms`);
  assert.ok(
    figures.server_measured.max_ms <= BOUND_MS,
    `the slowest of the ten burst finalizations took ${figures.server_measured.max_ms} ms on the server's clock, within ${BOUND_MS} ms (indicative-local; runner interval ${DEFAULT_RUN_INTERVAL_MS} ms; measured peaks ${figures.peak_envelopes_in_finalizing_at_once} in finalizing and ${figures.peak_attempts_in_progress_at_once} attempt(s) in progress, recorded, not asserted)`,
  );
  assert.ok(figures.client_observed.max_ms <= BOUND_MS, `as observed by the client, the slowest took ${figures.client_observed.max_ms} ms, within ${BOUND_MS} ms (indicative-local)`);
  recordEvidence({ case: 'SC005-02' });
});
