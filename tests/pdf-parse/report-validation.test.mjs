// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-17 (A-008 P09): the parent validates the child's report and never
// trusts it. Deliberately lying children (test-only entry modules written to a mkdtemp
// directory and launched exactly as the real worker is: same sandbox, permission flags and
// limits) report impossible page counts, sizes, rotations, boxes, isolation flags and byte
// counts; every such report is a fail-closed 500 service-failure. An honest copy of a real
// report passes, which shows the lying children run through the same path.

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import * as service from '../../src/pdf/service.ts';
import { fixtureBytes, sha256 } from './support.mjs';

const dir = mkdtempSync(join(tmpdir(), 'opensig-pl17-'));
after(() => rmSync(dir, { recursive: true, force: true }));
let children = 0;

/** A child entry that ignores its input and prints `text` as its one result line. */
function lyingChild(text) {
  children += 1;
  const entry = join(dir, `child-${children}.mjs`);
  writeFileSync(entry, `process.stdout.write(${JSON.stringify(`${text}\n`)});\n`, { mode: 0o600 });
  return entry;
}

const clone = (value) => JSON.parse(JSON.stringify(value));

test('[PL-17] a lying parse child is never trusted: impossible reports are fail-closed service failures', async () => {
  const input = fixtureBytes('single-page.pdf');
  const real = await service.parsePdf(input);
  assert.equal(real.ok, true, real.ok ? '' : real.detail);
  const honest = clone(real.report);
  delete honest.digest;
  delete honest.network_sandbox;
  const page = honest.pages[0];
  const forge = (mutate) => {
    const report = clone(honest);
    mutate(report);
    return JSON.stringify({ ok: true, report });
  };

  // Control: an honest copy of the real report, from a test child, is accepted unchanged.
  const control = await service.parsePdf(input, { workerEntry: lyingChild(JSON.stringify({ ok: true, report: honest })) });
  assert.equal(control.ok, true, control.ok ? '' : `${control.reason} ${control.detail}`);
  assert.equal(control.report.digest, sha256(input));
  assert.deepEqual(control.report.pages, honest.pages);
  assert.equal(control.network_sandbox, real.network_sandbox);

  const lies = {
    'zero pages': forge((r) => (r.pages = [])),
    '51 pages': forge((r) => (r.pages = Array.from({ length: 51 }, (_, i) => ({ ...page, number: i + 1 })))),
    'pages out of order': forge((r) => (r.pages[0].number = 2)),
    'zero width': forge((r) => (r.pages[0].width = 0)),
    'negative height': forge((r) => (r.pages[0].height = -page.height)),
    'non-numeric width': forge((r) => (r.pages[0].width = String(page.width))),
    'NaN width (serialized as null)': forge((r) => (r.pages[0].width = Number.NaN)),
    'infinite height': forge((r) => (r.pages[0].height = 1)).replace('"height":1,', '"height":1e999,'),
    'width that disagrees with the box': forge((r) => (r.pages[0].width = page.width - 1)),
    'rotate 45': forge((r) => (r.pages[0].rotate = 45)),
    'rotate -90': forge((r) => (r.pages[0].rotate = -90)),
    'rotate as a string': forge((r) => (r.pages[0].rotate = '0')),
    'crop box differing from the media box': forge((r) => {
      r.pages[0].crop_box = [10, 10, page.media_box[2] - 10, page.media_box[3] - 10];
      r.pages[0].width = page.media_box[2] - 20;
      r.pages[0].height = page.media_box[3] - 20;
    }),
    'media box without area': forge((r) => (r.pages[0].media_box = [0, 0, 0, 0])),
    'byte count one more than the input': forge((r) => (r.bytes = input.length + 1)),
    'byte count one less than the input': forge((r) => (r.bytes = input.length - 1)),
    'no byte count': forge((r) => delete r.bytes),
    'permission model reported off': forge((r) => (r.isolation.permission_model = false)),
    'fs-write reported granted': forge((r) => (r.isolation.fs_write = true)),
    'wrong schema': forge((r) => (r.schema = 'opensig.pdf.parse-report.v0')),
    'unknown rejection reason': JSON.stringify({ ok: false, reason: 'all-clear', detail: 'synthetic' }),
    'overlong rejection detail': JSON.stringify({ ok: false, reason: 'malformed', detail: 'x'.repeat(500) }),
    'non-JSON output': 'synthetic garbage',
  };
  const names = Object.keys(lies);
  const outcomes = await Promise.all(names.map((name) => service.parsePdf(input, { workerEntry: lyingChild(lies[name]) })));
  names.forEach((name, index) => {
    const outcome = outcomes[index];
    assert.equal(outcome.ok, false, `${name} must not be accepted`);
    assert.equal(outcome.status, 500, `${name}: ${outcome.status} ${outcome.reason} ${outcome.detail}`);
    assert.equal(outcome.code, 'internal', name);
    assert.equal(outcome.reason, 'service-failure', name);
    assert.match(outcome.detail, /invalid report|no valid result/, name);
    assert.equal(outcome.report, undefined, name);
  });

  // A well-formed rejection from the child is passed through as a 422.
  const rejection = await service.parsePdf(input, { workerEntry: lyingChild(JSON.stringify({ ok: false, reason: 'malformed', detail: 'synthetic' })) });
  assert.deepEqual([rejection.status, rejection.reason, rejection.detail], [422, 'malformed', 'synthetic']);

  // The page ceiling follows the configured limit as well as the FR-002 ceiling.
  const twoPages = JSON.parse(forge((r) => (r.pages = [page, { ...page, number: 2 }])));
  assert.notEqual(service.validateChildResult(twoPages, input.length, 2), null);
  assert.equal(service.validateChildResult(twoPages, input.length, 1), null);
});
