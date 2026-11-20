// SPDX-License-Identifier: Apache-2.0
//
// T015 per-case receipt. `recovery` declares no evidence labels (plan.md § Mode registry: "—";
// scripts/verify-modes.mjs registers none), so the evidence of a pass is the runner's own result:
// each case ID as the leading [ID] of a passing test (result.json passed_case_ids; cases 20/20).
// This record is a diagnostic beside it, never evidence of a pass, written whatever the verdict
// (the SEC16-PROBE precedent, tests/server/ceremony-work.test.mjs):
// - as a test diagnostic, `SC003-RECEIPT {...}`;
// - as `sc003/<case>.json` under the runner's output directory (OPENSIG_VERIFY_OUT; outside the
//   runner, the gitignored .verify-out/recovery/).
// It holds no host-absolute path, no PID, no capability value and no document byte: the case, the
// phase reached, each child's role and exit, the job and envelope counters, and I1..I10.

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { REPO } from './world.mjs';

const HOST_PATH = /(^|[\s"'=:(])(\/[^\s/]|~\/|[A-Za-z]:\\|file:)/;

export function newRecord(entry) {
  return { case: entry.id, group: entry.group, phase: entry.phase?.label ?? null, race: entry.race ?? null, phase_reached: null, children: [], job: null, envelope: null, counts: null, invariants: null, expectations: [], verdict: 'incomplete' };
}

/** The counters a receipt keeps from the state invariants.mjs read. */
export function counters(s) {
  return {
    job: { status: s.job.status, attempt_count: Number(s.job.attempt_count), max_attempts: Number(s.job.max_attempts), fencing_token: s.job.fencing_token === null ? null : Number(s.job.fencing_token), last_error_code: s.job.last_error_code },
    envelope: { state: s.envelope.state, version: Number(s.envelope.version) },
    counts: {
      artifacts: s.artifacts.length,
      completion_events: s.outbox.filter((row) => row.type === 'envelope.completed').length,
      failure_events: s.outbox.filter((row) => row.type === 'envelope.finalization_failed').length,
      verification_rows: s.reports.length,
      seal_anchors: s.audit.filter((row) => row.type === 'envelope.seal_started').length,
      completion_checkpoints: s.checkpoints.length,
      attempt_records: s.records.length,
    },
  };
}

/** Record the receipt whatever the verdict; a record that would name a host path is refused, not written. */
export function recordCase(t, record) {
  const text = JSON.stringify(record);
  if (HOST_PATH.test(text)) {
    t.diagnostic(`SC003-RECEIPT refused: the record of ${record.case} would name a host path`);
    return null;
  }
  t.diagnostic(`SC003-RECEIPT ${text}`);
  try {
    const dir = join(process.env.OPENSIG_VERIFY_OUT ?? join(REPO, '.verify-out', 'recovery'), 'sc003');
    mkdirSync(dir, { recursive: true });
    const file = join(dir, `${record.case}.json`);
    writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
    return file;
  } catch {
    // A diagnostic only: a failed write never changes the verdict.
    return null;
  }
}
