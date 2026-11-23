// SPDX-License-Identifier: Apache-2.0
//
// T015 SC003-01..SC003-08 (plan.md § Case catalogs, SC-003; request #61 (1), (2)): a SIGKILL at
// each phase, in order (reserve, compose, seal, verify, store PDF, store evidence, publish,
// outbox). Runner A runs in its own OS process with the explicit harness flag and is held at the
// phase's hook (src/domain/finalization/fault-hook.ts); the parent SIGKILLs A's recorded PID. A
// fresh runner reclaims at the strict lease expiry and the envelope is completed exactly once,
// in two children (request #79 (1)): B reclaims, and C, at the retry_at B wrote, takes the one
// further attempt in 01..07 (07 rolls back the uncommitted publish and reuses the anchor and the
// checkpoint); in 08 B finds the job succeeded and no C runs. I1..I10 hold after each case.
// Cases run serially, each bounded by its own timeout.

import { test } from 'node:test';

import { entryById } from './support/catalog.mjs';
import { CASE_TIMEOUT_MS, runCase } from './support/scenario.mjs';

for (const id of ['SC003-01', 'SC003-02', 'SC003-03', 'SC003-04', 'SC003-05', 'SC003-06', 'SC003-07', 'SC003-08']) {
  test(`[${id}] ${entryById(id).title}`, { timeout: CASE_TIMEOUT_MS }, (t) => runCase(t, id));
}
