// SPDX-License-Identifier: Apache-2.0
//
// Child driver for the PL-15 and PL-13 no-launcher branch (T033). It runs the unmodified
// parse service with the real process environment and no test seams, and prints one JSON
// line: the plan the service chose, the exact child command serviceCommand() builds for it,
// the worker entry, the outcome of parsing a small synthetic document (summary and full),
// and the outcome of an oversized body (as a buffer, and as a stream that counts how many
// chunks the service pulled from it). The tests start it either directly or inside an outer
// user and mount namespace in which no sandbox launcher can run (bwrap masked, user
// namespaces limited to zero).

import { realpathSync } from 'node:fs';

import { DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS } from '../../src/pdf/limits.ts';
import { parsePdf, parseServicePlan, serviceCommand, WORKER_ENTRY } from '../../src/pdf/service.ts';
import { basicObjects, classicPdf } from './pdf-builder.mjs';

const OVERSIZED = 10 * 1024 * 1024 + 1;
const summary = (outcome) =>
  outcome.ok
    ? { ok: true, status: 200, label: outcome.network_sandbox, report_label: outcome.report.network_sandbox }
    : { ok: false, status: outcome.status, code: outcome.code, reason: outcome.reason, label: outcome.network_sandbox };

const plan = await parseServicePlan();
const command = serviceCommand(plan, DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS);
const outcome = await parsePdf(classicPdf(basicObjects()));
const oversized = await parsePdf(Buffer.alloc(OVERSIZED));
let pulled = 0;
const stream = (async function* body() {
  pulled += 1;
  yield Buffer.alloc(OVERSIZED);
})();
const streamed = await parsePdf(stream);

process.stdout.write(
  `${JSON.stringify({
    plan: { mode: plan.mode, label: plan.network_sandbox, available: plan.probe.available, launcher: plan.probe.launcher },
    command: command === null ? null : { file: command.file, args: command.args },
    worker_entry: WORKER_ENTRY,
    worker_entry_real: realpathSync(WORKER_ENTRY),
    outcome: summary(outcome),
    full: outcome,
    oversized: summary(oversized),
    oversized_stream: { ...summary(streamed), pulled },
  })}\n`,
);
