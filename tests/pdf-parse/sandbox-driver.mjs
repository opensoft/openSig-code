// SPDX-License-Identifier: Apache-2.0
//
// Child driver for the PL-15 and PL-13 no-launcher branch (T033). It runs the unmodified
// parse service with the real process environment and no test seams, and prints one JSON
// line: the plan the service chose and the outcome of parsing a small synthetic document.
// The tests start it either directly or inside an outer user and mount namespace in which
// no sandbox launcher can run (bwrap masked, user namespaces limited to zero).

import { parsePdf, parseServicePlan } from '../../src/pdf/service.ts';
import { basicObjects, classicPdf } from './pdf-builder.mjs';

const plan = await parseServicePlan();
const outcome = await parsePdf(classicPdf(basicObjects()));
process.stdout.write(
  `${JSON.stringify({
    plan: { mode: plan.mode, label: plan.network_sandbox, available: plan.probe.available, launcher: plan.probe.launcher },
    outcome: outcome.ok
      ? { ok: true, status: 200, label: outcome.network_sandbox, report_label: outcome.report.network_sandbox }
      : { ok: false, status: outcome.status, code: outcome.code, reason: outcome.reason, label: outcome.network_sandbox },
  })}\n`,
);
