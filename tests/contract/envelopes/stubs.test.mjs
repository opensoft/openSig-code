// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006), kind harness: the manifest discriminates.
//   EC-STUB-ACCEPT-<FIXTURE>  accept-everything fails at least one case of the fixture,
//                             and fails every rejecting case on its status
//   EC-STUB-REJECT-<FIXTURE>  reject-everything fails at least one case of the fixture,
//                             fails every accepting case, and passes only cases that
//                             expect exactly 400 invalid_request
//   EC-13 arrangeThroughApi reaches each precondition with contract-valid requests only
// The stubs are non-conforming on purpose. These results are harness
// self-checks: never success-criterion evidence, never runtime acceptance.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { getOperation, loadVendoredContract, operationIndex, sha256Hex } from './lib/contract.mjs';
import { arrangeThroughApi, makeApiSubject, matchOperation, requestFindings, runManifest, summarize } from './lib/harness.mjs';
import { loadManifest } from './lib/manifest.mjs';
import { buildPdf, inspectPdf } from './lib/pdf.mjs';
import { acceptEverything, rejectEverything } from './lib/stubs.mjs';

const { doc } = loadVendoredContract();
const index = operationIndex(doc);
const manifest = loadManifest();
const env = { doc, index, manifest };

const runs = new Map();
function resultsFor(name) {
  if (!runs.has(name)) runs.set(name, runManifest(name === 'accept' ? acceptEverything(doc) : rejectEverything(), env));
  return runs.get(name);
}

const accepting = (c) => c.expect.status >= 200 && c.expect.status < 300;

for (const fixture of manifest.fixtures) {
  const label = fixture.category.toUpperCase();
  const cases = new Map(fixture.cases.map((c) => [c.id, c]));

  test(`[EC-STUB-ACCEPT-${label}] accept-everything fails at least one ${fixture.category} case`, async () => {
    const results = (await resultsFor('accept')).filter((r) => r.category === fixture.category);
    assert.equal(results.length, fixture.cases.length);
    for (const r of results) assert.equal(r.stage, 'verdict', `${r.id}: the stub reached the verdict`);
    const failed = results.filter((r) => !r.pass);
    assert.ok(failed.length >= 1, `accept-everything passed every ${fixture.category} case`);
    for (const r of results) {
      const c = cases.get(r.id);
      if (!accepting(c)) {
        assert.equal(r.pass, false, `${r.id}: accept-everything must fail a rejecting case`);
        assert.match(r.reasons[0], new RegExp(`^status 2\\d\\d, expected ${c.expect.status}$`), r.id);
      }
    }
    assert.equal(failed.length >= fixture.cases.filter((c) => !accepting(c)).length, true);
    assert.deepEqual(summarize(results)[fixture.category].cases, fixture.cases.length);
  });

  test(`[EC-STUB-REJECT-${label}] reject-everything fails at least one ${fixture.category} case`, async () => {
    const results = (await resultsFor('reject')).filter((r) => r.category === fixture.category);
    assert.equal(results.length, fixture.cases.length);
    for (const r of results) assert.equal(r.stage, 'verdict', `${r.id}: the stub reached the verdict`);
    assert.ok(results.some((r) => !r.pass), `reject-everything passed every ${fixture.category} case`);
    for (const r of results) {
      const c = cases.get(r.id);
      const sameOutcome = c.expect.status === 400 && c.expect.code === 'invalid_request' && (c.expect.detailCodes ?? []).length === 0;
      assert.equal(r.pass, sameOutcome, `${r.id}: reject-everything ${sameOutcome ? 'must pass' : 'must fail'} (${r.reasons.join('; ')})`);
      if (accepting(c)) assert.match(r.reasons[0], new RegExp(`^status 400, expected ${c.expect.status}$`), r.id);
    }
  });
}

test('[EC-13] arrangeThroughApi reaches each precondition with contract-valid requests only', async () => {
  const stub = acceptEverything(doc);
  for (const [name, given] of Object.entries(manifest.index.givens)) {
    const seen = [];
    const recording = async (request) => {
      const match = matchOperation(index, request.method, request.path);
      assert.ok(match, `${name}: ${request.method} ${request.path} is a contract operation`);
      assert.equal(match.entry.operationId, request.operationId);
      assert.deepEqual(requestFindings(doc, getOperation(index, request.operationId), request, match.pathValues), [], `${name}: ${request.operationId} request is contract-valid`);
      assert.ok(doc['x-opensig-role-matrix'][request.operationId].roles.includes(request.principal));
      if (request.operationId === 'uploadDocument') {
        assert.equal(sha256Hex(request.body), sha256Hex(buildPdf(given.document)));
        assert.deepEqual(inspectPdf(request.body).features, []);
      }
      seen.push(request.operationId);
      return stub.handle(request);
    };
    const arranged = await arrangeThroughApi(recording, given, index);
    const expectedSteps = ['createEnvelope', ...(given.document ? ['uploadDocument'] : []), ...(given.prepare ? ['prepareEnvelope'] : [])];
    assert.deepEqual(seen, expectedSteps, name);
    assert.equal(arranged.version, expectedSteps.length, `${name}: the version comes from the last response`);
    assert.match(arranged.envelope_id, /^[A-Za-z0-9_-]{16,64}$/);
  }
  // A subject built on handle() alone arranges through the API; a failing step surfaces as an arrange failure.
  const failing = makeApiSubject('reject-api', rejectEverything().handle, doc);
  await assert.rejects(failing.arrange(manifest.index.givens['draft-1']), /createEnvelope returned 400, expected 201/);
  const [result] = await runManifest(failing, env, { ids: ['EC-ENV-20'] });
  assert.deepEqual([result.pass, result.stage], [false, 'arrange']);
});
