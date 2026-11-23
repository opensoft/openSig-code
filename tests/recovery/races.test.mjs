// SPDX-License-Identifier: Apache-2.0
//
// T015 SC003-17..SC003-20 (plan.md § Case catalogs, SC-003): void at compose, decline at seal,
// expiry at store PDF and an operator retry at store evidence, each against a running
// finalization held at that hook in its own OS process. The void, decline and expiry racers are
// T010's landed race child, each its own OS process (request #61 (9)): the void and the decline
// carry the envelope's current version on a live session and are refused 409 state_conflict
// (request #79 (5)), and the sweep leaves the envelope. The operator retry is T038's retryFinalization: 409
// finalization_not_retryable. Each writes nothing; the finalization then completes once, never
// both completed and voided. I1..I10 hold after each case.

import { test } from 'node:test';

import { entryById } from './support/catalog.mjs';
import { CASE_TIMEOUT_MS, runCase } from './support/scenario.mjs';

for (const id of ['SC003-17', 'SC003-18', 'SC003-19', 'SC003-20']) {
  test(`[${id}] ${entryById(id).title}`, { timeout: CASE_TIMEOUT_MS }, (t) => runCase(t, id));
}
