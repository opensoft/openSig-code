// SPDX-License-Identifier: Apache-2.0
//
// T015 extra case IDs, never required (plan.md § Case catalogs, SC-003; request #61 (7)):
// - REC-01: without the harness flag a run with every hook point compiled in behaves exactly as
//   an unhooked run, and a static check shows that the hook reads only that flag. Kills "the hook
//   active without the flag".
// - REC-02: the attempt limit. A crash at the last allowed attempt is reclaimed into failed once,
//   with one envelope.finalization_failed outbox event and one audit event (request #61 (5)); an
//   operator retry raises max_attempts by exactly one; a second retry before the next attempt
//   answers 202 and writes neither the job nor an audit event (request #80 (1), row RETRY-BOUND);
//   attempt_count never passes max_attempts. Kills "attempts past the bound", "a retry that
//   always audits" and "envelope.finalization_failed emitted twice".

import { test } from 'node:test';

import { entryById } from './support/catalog.mjs';
import { CASE_TIMEOUT_MS, runCase } from './support/scenario.mjs';

for (const id of ['REC-01', 'REC-02']) {
  test(`[${id}] ${entryById(id).title}`, { timeout: CASE_TIMEOUT_MS }, (t) => runCase(t, id));
}
