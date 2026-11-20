// SPDX-License-Identifier: Apache-2.0
//
// T015 SC003-09..SC003-16 (plan.md § Case catalogs, SC-003; request #61 (1), (2)): the stale-lease
// races, a barrier at each phase in order. Runner A, in its own OS process with the explicit
// harness flag, is held at the phase's hook while its lease expires by the next runners' fixed
// clocks. A probe 1 ms before the expiry reclaims nothing; a second runner reclaims at the expiry
// (request #59 (11)). In 09..14 a third runner publishes attempt 2 and the released holder writes
// nothing, every write it attempts being fenced. In 15 the holder keeps the publish write lock,
// its fence held under that lock, so its commit stands and the queued runner writes nothing. In
// 16 the second runner finds the job succeeded and takes no attempt. I1..I10 hold after each case.

import { test } from 'node:test';

import { entryById } from './support/catalog.mjs';
import { CASE_TIMEOUT_MS, runCase } from './support/scenario.mjs';

for (const id of ['SC003-09', 'SC003-10', 'SC003-11', 'SC003-12', 'SC003-13', 'SC003-14', 'SC003-15', 'SC003-16']) {
  test(`[${id}] ${entryById(id).title}`, { timeout: CASE_TIMEOUT_MS }, (t) => runCase(t, id));
}
