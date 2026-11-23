// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006), kind harness: the vendored contract.
//   EC-01 contracts/http-api.json re-hashes to the sha256 in http-api.source.json
//   EC-02 the source record names the spec leg, a full commit and the contract path
//   EC-03 the vendored bytes are the OpenAPI 3.1 contract the manifest was derived from
// Harness checks only: never success-criterion evidence, never runtime acceptance.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { CONTRACT_FILE, CONTRACT_SOURCE_FILE, getOperation, operationIndex, REPO_ROOT } from './lib/contract.mjs';
import { loadManifest } from './lib/manifest.mjs';

const bytes = readFileSync(join(REPO_ROOT, CONTRACT_FILE));
const source = JSON.parse(readFileSync(join(REPO_ROOT, CONTRACT_SOURCE_FILE), 'utf8'));

test('[EC-01] the vendored contract re-hashes to the sha256 recorded in its source record', () => {
  const actual = createHash('sha256').update(bytes).digest('hex');
  assert.match(source.sha256, /^[0-9a-f]{64}$/);
  assert.equal(actual, source.sha256, 'contracts/http-api.json differs from the recorded digest; re-vendor byte-exact from the recorded commit');
  // A one-byte change must change the digest (the check is not vacuous).
  const altered = Buffer.from(bytes);
  altered[altered.length - 1] ^= 0x01;
  assert.notEqual(createHash('sha256').update(altered).digest('hex'), source.sha256);
});

test('[EC-02] the source record names the spec leg, a full commit and the contract path', () => {
  assert.deepEqual(Object.keys(source).sort(), ['commit', 'path', 'repo', 'sha256']);
  assert.equal(source.repo, 'opensoft/openSig-spec');
  assert.match(source.commit, /^[0-9a-f]{40}$/, 'commit must be a full 40-hex commit id');
  assert.equal(source.path, 'specs/001-corporate-signing-mvp/contracts/http-api.yaml');
});

test('[EC-03] the vendored bytes are the OpenAPI 3.1 contract the manifest was derived from', () => {
  const doc = JSON.parse(bytes.toString('utf8'));
  assert.equal(doc.openapi, '3.1.0');
  assert.equal(doc.info.license.identifier, 'Apache-2.0');
  const manifest = loadManifest();
  assert.equal(manifest.index.contract.sha256, source.sha256, 'the manifest was derived from a different contract; re-derive the manifest after re-vendoring');
  assert.equal(manifest.index.contract.info_version, doc.info.version);
  assert.equal(manifest.index.contract.file, CONTRACT_FILE);
  assert.equal(manifest.index.contract.source, CONTRACT_SOURCE_FILE);
  const index = operationIndex(doc);
  const used = new Set(manifest.cases.map((c) => c.request.operationId));
  for (const id of ['createEnvelope', 'uploadDocument', 'prepareEnvelope']) used.add(id); // arrangeThroughApi
  for (const operationId of used) {
    const entry = getOperation(index, operationId);
    assert.ok(entry.operation.responses, `${operationId} declares responses`);
  }
  assert.deepEqual([...used].sort(), ['createEnvelope', 'prepareEnvelope', 'readEnvelope', 'sendEnvelope', 'uploadDocument', 'voidEnvelope']);
});
