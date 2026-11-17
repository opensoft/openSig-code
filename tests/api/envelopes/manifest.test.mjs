// SPDX-License-Identifier: Apache-2.0
//
// T034 consumes the T006 envelope conformance manifest with a count check
// (fixtures/synthetic/envelopes/README.md, "Consuming the manifest (T034)").
//
// Every manifest case is materialized by the T006 harness and sent, as the harness built it,
// to the real application through the real router: the case's principal (sender or service
// of tenant alpha) becomes a bearer token of the T005 authenticator, and arranged givens go
// through the operator API itself (makeApiSubject). Uploads are parsed by the real isolated
// parse service. The counts are frozen in the T006 harness (EC-04) and repeated here, so a
// manifest that gains or loses a case fails until this consumer is updated with it.
//
// EC-ENV-22 (a malformed envelope_id) expects T031's uniform 404 not_found, as amended by the
// T006 test-data follow-up of row T006-EC22 (request #16), which lands directly before T034.
// The router answers it before authentication, so the case reaches no T034 handler.
//
// Kind: harness. These results are never success-criterion evidence; T034's own cases are.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { loadVendoredContract, operationIndex } from '../../contract/envelopes/lib/contract.mjs';
import { makeApiSubject, runManifest, summarize } from '../../contract/envelopes/lib/harness.mjs';
import { loadManifest } from '../../contract/envelopes/lib/manifest.mjs';
import { bearer, call, createWorld } from './support.mjs';

let world;
before(async () => {
  world = await createWorld();
});
after(async () => {
  await world?.close();
});

/** The subject's transport: the harness request, plus the principal's credential, to the real server. */
async function handle(request) {
  const headers = { ...request.headers, authorization: `Bearer ${bearer('alpha', request.principal === 'service' ? 'service' : 'sender')}` };
  const response = await call(world.port, { method: request.method, path: request.path, headers, body: request.body ?? undefined, defaultType: false });
  return { status: response.status, headers: response.headers, body: response.bytes };
}

test('[EH-04] the T006 conformance manifest runs against the real handlers through the router: 72 cases in their four categories, every one passing (harness evidence only)', async (t) => {
  const vendored = loadVendoredContract();
  const manifest = loadManifest();
  assert.equal(manifest.index.contract.sha256, vendored.sha256, 'the manifest names the vendored contract');
  assert.equal(manifest.total, 72, 'the manifest total');
  const ec22 = manifest.cases.find((c) => c.id === 'EC-ENV-22');
  assert.deepEqual([ec22?.defect?.kind, ec22?.expect?.status, ec22?.expect?.code], ['path-parameter', 404, 'not_found'], 'EC-ENV-22 as amended by row T006-EC22 (request #16)');
  const results = await runManifest(makeApiSubject('opensig', handle, vendored.doc), { doc: vendored.doc, index: operationIndex(vendored.doc), manifest });
  assert.equal(results.length, 72, 'every case ran');
  const summary = summarize(results);
  assert.deepEqual(
    Object.fromEntries(Object.entries(summary).map(([category, counts]) => [category, counts.cases])),
    { envelope: 29, version: 17, 'upload-limit': 7, 'unsupported-pdf': 19 },
    'the frozen per-category counts',
  );
  t.diagnostic(`manifest: ${results.filter((result) => result.pass).length} of ${results.length} cases pass (harness only, never success-criterion evidence)`);
  assert.deepEqual(
    results.filter((result) => !result.pass).map((result) => ({ id: result.id, stage: result.stage, reasons: result.reasons })),
    [],
    'every manifest case passes',
  );
});
