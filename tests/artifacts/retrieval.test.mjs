// SPDX-License-Identifier: Apache-2.0
//
// T016: artifact retrieval (readVerification, downloadFinalPdf and downloadPackage) through
// the real application. Cases:
// - SC002-09: the cross-tenant 404.
// - PK-04: exact bytes and ETags, 409 not_completed, roles, audited access and broken
//   invariants. The report is the verification_reports row's report_bytes, unchanged
//   (request #59 (9)). A broken invariant is a logged 500 internal, never 409 (request #46
//   (5)). Only a successful read is audited (request #46 (6)).
// - PK-03 (served side): no capability value in the package, the responses or the logs.
// The world (support/world.mjs) is T010's synthetic world plus an application with T016's
// handlers installed. Envelopes are driven through the real services and routes, and a
// completed artifact is published through the storage layer, as T038 will publish it. All
// content is synthetic; capability values stay in memory and never appear in a test name
// or an assertion message.

import assert from 'node:assert/strict';
import { rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, test } from 'node:test';

import { ACCESS_EVENT_TYPE, ArtifactApi, ArtifactInvariantError } from '../../src/api/artifacts/index.ts';
import { AuditWriter, verifyChain } from '../../src/storage/audit/index.ts';
import { readZip } from '../zip/reader.mjs';
import { sha256Hex } from './support/jcs.mjs';
import { sid } from './support/inputs.mjs';
import {
  ARTIFACT_PATHS,
  COOKIE,
  assertError,
  bearer,
  completedEnvelope,
  contractErrors,
  createArtifactWorld,
  envelopeIn,
  errorShape,
  finalizingEnvelope,
  publish,
  rowsOf,
  storedCapabilityDigests,
} from './support/world.mjs';

let world;
before(async () => {
  world = await createArtifactWorld();
});
after(async () => {
  await world?.close();
});

const OPERATIONS = Object.keys(ARTIFACT_PATHS);
const accessEvents = (envelopeId) => rowsOf(world, 'audit_events', envelopeId).filter((row) => row.type === ACCESS_EVENT_TYPE);
const allAccessEvents = () => world.rows('audit_events', 'WHERE type = ?', [ACCESS_EVENT_TYPE]);
const UNIFORM_HEADERS = ['content-type', 'content-length', 'cache-control', 'etag'];

function membersOf(zip) {
  return new Map(readZip(zip).entries.map((entry) => [entry.name, Buffer.from(entry.data)]));
}

// Request #70 (6): the frozen runner keeps only an assertion's message, so a comparison with
// a message of its own carries the compared non-secret values: statuses, counts, digests,
// header values and table digests. Bytes are shown as SHA-256 and length; capability
// values never appear in a message.
function same(actual, expected, what) {
  assert.equal(actual, expected, `${what}: ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}
function sameBytes(actual, expected, what) {
  const [a, b] = [Buffer.from(actual), Buffer.from(expected)];
  assert.ok(a.equals(b), `${what}: sha256 ${sha256Hex(a)} (${a.length} bytes), expected ${sha256Hex(b)} (${b.length} bytes)`);
}
/** The tables whose content digest differs between two world.snapshot() results. */
function changedTables(after, before) {
  return [...new Set([...Object.keys(after), ...Object.keys(before)])].filter((table) => after[table] !== before[table]).sort();
}

/** The artifact_invariant records the T016 application has logged, parsed. */
function invariantsLogged() {
  return world
    .artifactLog()
    .split('\n')
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line))
    .filter((record) => record.event === 'artifact_invariant');
}

/** A direct-call operator principal of `tenantId` (the server derives one per request). */
function principalOf(tenantId) {
  return { scheme: 'operator', tenant_id: tenantId, kind: 'human-operator', roles: ['sender'], scopes: ['artifacts:read'], ref: 'operator-artifacts', issuer: 'https://issuer.example.test', expires_at: 0 };
}

/** `read` throws an ArtifactInvariantError with `code`; the message names what it got. */
function throwsInvariant(read, code, what) {
  let caught;
  try {
    read();
  } catch (error) {
    caught = error;
  }
  const got = caught instanceof ArtifactInvariantError ? caught.code : caught === undefined ? 'no error' : caught.name;
  assert.ok(caught instanceof ArtifactInvariantError && caught.code === code, `${what}: ${got}, expected ${code}`);
}

/** GET `operation` on `id`: a 500 internal, its invariant logged with `code`, and no access event. */
async function assertInvariant(id, operation, code) {
  const accessBefore = accessEvents(id).length;
  const logged = invariantsLogged().length;
  assertError(await world.fetchArtifact(ARTIFACT_PATHS[operation](id)), 500, 'internal', `${operation}: ${code}`);
  // Request #70 (6): the compared values (counts, codes, operation names) are in each message.
  const records = invariantsLogged().slice(logged);
  assert.equal(records.length, 1, `${operation}: ${records.length} artifact_invariant records, expected 1`);
  const [record] = records;
  assert.equal(record.level, 'error', `${operation}: level ${record.level}, expected error`);
  assert.equal(record.operation, operation, `${operation}: logged operation ${record.operation}`);
  assert.equal(record.invariant, code, `${operation}: logged invariant ${record.invariant}, expected ${code}`);
  assert.equal(typeof record.correlation_id, 'string', `${operation}: correlation_id is ${typeof record.correlation_id}`);
  const accessAfter = accessEvents(id).length;
  assert.equal(accessAfter, accessBefore, `${operation} on ${id}: ${accessAfter} access events after a failed read, expected ${accessBefore}`);
}

test('[PK-04] a completed envelope serves its report, final.pdf and package as exact bytes, ETag the quoted digest, each access audited', async () => {
  const done = await completedEnvelope(world);
  const id = done.envelopeId;
  const members = membersOf(done.built.bytes);
  assert.equal(accessEvents(id).length, 0);

  const pdf = await world.fetchArtifact(ARTIFACT_PATHS.downloadFinalPdf(id));
  assert.equal(pdf.status, 200);
  assert.equal(pdf.headers['content-type'], 'application/pdf');
  sameBytes(pdf.bytes, done.pdf, 'final.pdf exact bytes');
  same(pdf.headers.etag, `"${sha256Hex(pdf.bytes)}"`, 'final.pdf ETag: the quoted digest of the served bytes');
  same(pdf.headers.etag, `"${done.built.artifactDigest}"`, 'final.pdf ETag: artifact_digest');

  const pkg = await world.fetchArtifact(ARTIFACT_PATHS.downloadPackage(id));
  assert.equal(pkg.status, 200);
  assert.equal(pkg.headers['content-type'], 'application/zip');
  sameBytes(pkg.bytes, done.built.bytes, 'the package exact bytes');
  assert.equal(pkg.headers.etag, `"${sha256Hex(pkg.bytes)}"`);
  same(pkg.headers.etag, `"${done.built.packageDigest}"`, 'package ETag: package_digest');

  const report = await world.fetchArtifact(ARTIFACT_PATHS.readVerification(id));
  assert.equal(report.status, 200);
  assert.match(report.headers['content-type'], /^application\/json/);
  const reportErrors = contractErrors('VerificationReport', report.json);
  assert.deepEqual(reportErrors, [], `a contract VerificationReport: ${JSON.stringify(reportErrors)}`);
  sameBytes(report.bytes, members.get('verification.json'), 'the report, against the package\'s verification.json');
  const reports = rowsOf(world, 'verification_reports', id);
  same(reports.length, 1, 'verification_reports rows');
  sameBytes(report.bytes, reports[0].report_bytes, 'the report, against the stored report_bytes');
  sameBytes(report.bytes, done.input.verification, 'the report, against the bytes the builder packaged');
  assert.equal(report.headers.etag, `"${sha256Hex(report.bytes)}"`);
  same(report.headers.etag, `"${done.built.members['verification.json'].sha256}"`, 'report ETag: its package-index digest');
  for (const response of [pdf, pkg, report]) assert.match(response.headers['cache-control'] ?? '', /no-store/);

  // One access event per successful read, in order, naming what was served.
  const events = accessEvents(id);
  assert.deepEqual(events.map((event) => JSON.parse(event.metadata_json).operation), ['downloadFinalPdf', 'downloadPackage', 'readVerification']);
  assert.deepEqual(events.map((event) => event.subject_digest), [done.built.artifactDigest, done.built.packageDigest, done.built.members['verification.json'].sha256]);
  for (const event of events) {
    assert.equal(event.actor_kind, 'human-operator');
    assert.ok(typeof event.actor_ref === 'string' && event.actor_ref.length > 0, `access event seq ${event.seq}: actor_ref is ${typeof event.actor_ref} of length ${event.actor_ref?.length}`);
    assert.equal(JSON.parse(event.metadata_json).artifact_id, done.input.artifactId);
  }

  // A tenant admin and a service principal read too; each read is audited with its actor kind.
  for (const [who, kind] of [['admin', 'human-operator'], ['service', 'service']]) {
    for (const operation of OPERATIONS) {
      const response = await world.fetchArtifact(ARTIFACT_PATHS[operation](id), { who });
      same(response.status, 200, `${operation} as ${who}: status`);
      assert.equal(accessEvents(id).at(-1).actor_kind, kind);
    }
  }
  assert.equal(accessEvents(id).length, 9);
  const chainCheck = verifyChain(world.db, world.tenantId('alpha'));
  assert.ok(chainCheck.ok, `the tenant chain stays valid: ${JSON.stringify(chainCheck).slice(0, 400)}`);

  // Access never changes what is served: the stored package and its ETag are stable.
  const again = await world.fetchArtifact(ARTIFACT_PATHS.downloadPackage(id));
  assert.equal(again.headers.etag, pkg.headers.etag);
  sameBytes(again.bytes, pkg.bytes, 'the package read again');
});

test('[PK-04] readVerification serves the stored report bytes unchanged, whatever their serialization, ETag their digest', async () => {
  const finalizing = await finalizingEnvelope(world);
  const done = publish(world, 'alpha', finalizing.envelopeId, { prettyReport: true });
  const stored = Buffer.from(done.input.verification);
  const compact = Buffer.from(JSON.stringify(JSON.parse(stored.toString('utf8'))), 'utf8');
  assert.equal(stored.equals(compact), false, `the stored bytes are not compact JSON: ${stored.length} vs ${compact.length} bytes`);
  const report = await world.fetchArtifact(ARTIFACT_PATHS.readVerification(finalizing.envelopeId));
  assert.equal(report.status, 200, `readVerification status ${report.status}`);
  assert.ok(report.bytes.equals(stored), `served unchanged: ${sha256Hex(report.bytes)}, expected ${sha256Hex(stored)}`);
  assert.equal(report.headers.etag, `"${sha256Hex(stored)}"`, `ETag ${report.headers.etag}, expected the stored bytes' digest`);
  const packaged = membersOf(done.built.bytes).get('verification.json');
  assert.ok(packaged.equals(stored), `the package carries the same bytes: ${sha256Hex(packaged)}`);
});

test('[PK-04] before completion every artifact operation is 409 not_completed, whatever the state, and writes nothing', async () => {
  const targets = [];
  for (const state of ['draft', 'prepared', 'sent', 'in-progress', 'finalizing']) targets.push([state, await envelopeIn(world, state)]);
  // A FinalArtifact row inserted while the envelope is still finalizing: the state decides.
  const early = await envelopeIn(world, 'finalizing');
  publish(world, 'alpha', early, { insertOnly: true });
  targets.push(['finalizing with an artifact row', early]);

  const snapshot = world.snapshot();
  const accessBefore = allAccessEvents().length;
  for (const [state, id] of targets) {
    for (const operation of OPERATIONS) {
      const response = await world.fetchArtifact(ARTIFACT_PATHS[operation](id));
      assertError(response, 409, 'not_completed', `${operation} on a ${state} envelope`);
      same(response.headers.etag, undefined, `${operation} on a ${state} envelope: ETag`);
    }
  }
  assert.deepEqual(changedTables(world.snapshot(), snapshot), [], 'tables changed by refused reads');
  same(allAccessEvents().length, accessBefore, 'access events after refused reads');
});

test('[PK-04] without an operator credential the routes answer 401 and write nothing', async () => {
  const done = await completedEnvelope(world);
  const accessBefore = allAccessEvents().length;
  const recipientCookie = done.capabilities[2];
  for (const operation of OPERATIONS) {
    const path = ARTIFACT_PATHS[operation](done.envelopeId);
    assertError(await world.fetchArtifact(path, { headers: {} }), 401, 'unauthenticated', `${operation} without a credential`);
    assertError(await world.fetchArtifact(path, { headers: { authorization: 'Bearer not-a-token' } }), 401, 'unauthenticated', `${operation} with a token that does not verify`);
    assertError(await world.fetchArtifact(path, { headers: { cookie: `${COOKIE}=${recipientCookie}` } }), 401, 'unauthenticated', `${operation} with a recipient session`);
  }
  assert.equal(allAccessEvents().length, accessBefore);
});

test('[PK-04] a missing or corrupt stored blob, or an access event that cannot be written, serves nothing; a broken invariant is a logged 500', async () => {
  const done = await completedEnvelope(world);
  const id = done.envelopeId;
  const tenantId = world.tenantId('alpha');

  // final.pdf's blob removed: 500, no bytes, no access event; the other operations still serve.
  same(world.blobs.dispose(tenantId, done.pdfBlob.digest), true, `final.pdf blob ${done.pdfBlob.digest} disposed`);
  await assertInvariant(id, 'downloadFinalPdf', 'blob-unreadable');
  assert.equal((await world.fetchArtifact(ARTIFACT_PATHS.readVerification(id))).status, 200);

  // The package's blob replaced by other bytes: the blob store's integrity check refuses it.
  const packagePath = join(world.blobRoot, done.packageBlob.ref);
  rmSync(packagePath);
  writeFileSync(packagePath, Buffer.from('synthetic replacement bytes'), { mode: 0o600 });
  await assertInvariant(id, 'downloadPackage', 'blob-unreadable');

  // A blob store that returns other bytes under the recorded ref: T016's own digest check.
  const lying = new ArtifactApi({ db: world.db, blobs: { readRef: () => Buffer.from('synthetic other bytes') }, clock: world.time.clock });
  const count = accessEvents(id).length;
  throwsInvariant(() => lying.downloadFinalPdf(principalOf(tenantId), id), 'digest-mismatch', 'downloadFinalPdf over other bytes');
  same(accessEvents(id).length, count, 'access events after the digest-mismatch read');

  // The log names the invariant only: no blob ref, no digest.
  const log = world.artifactLog();
  const logged = Object.entries({ pdfBlobRef: done.pdfBlob.ref, packageBlobRef: done.packageBlob.ref, artifactDigest: done.built.artifactDigest, packageDigest: done.built.packageDigest })
    .filter(([, value]) => log.includes(value))
    .map(([name]) => name);
  assert.deepEqual(logged, [], 'blob refs or digests found in the artifact log');

  // An access event that cannot be written: nothing is returned, and it is not an invariant.
  class FailingWriter extends AuditWriter {
    append() {
      throw new Error('synthetic audit failure');
    }
  }
  const api = new ArtifactApi({ db: world.db, blobs: world.blobs, clock: world.time.clock, audit: new FailingWriter(world.db, { clock: world.time.clock }) });
  let auditFailure;
  try {
    api.readVerification(principalOf(tenantId), id);
  } catch (error) {
    auditFailure = error;
  }
  const failure = auditFailure === undefined ? 'served' : `${auditFailure.name}: ${auditFailure.message}`;
  assert.ok(auditFailure !== undefined && !(auditFailure instanceof ArtifactInvariantError) && /synthetic audit failure/.test(auditFailure.message), `a failed access append: ${failure}, expected the audit failure itself`);
  assert.equal(accessEvents(id).length, count);
});

test('[PK-04] a completed artifact with no package or no usable report row is a logged 500 internal, never 409', async () => {
  const tenantId = world.tenantId('alpha');
  const store = world.store('alpha');

  // No package recorded: downloadPackage is 500; the PDF and the report still serve.
  const noPackage = (await finalizingEnvelope(world)).envelopeId;
  publish(world, 'alpha', noPackage, { withoutPackage: true });
  await assertInvariant(noPackage, 'downloadPackage', 'package-missing');
  throwsInvariant(() => world.artifactApi.downloadPackage(principalOf(tenantId), noPackage), 'package-missing', 'downloadPackage, direct call');
  for (const operation of ['downloadFinalPdf', 'readVerification']) same((await world.fetchArtifact(ARTIFACT_PATHS[operation](noPackage))).status, 200, `${operation} with no package: status`);

  // No verification_reports row: readVerification is 500; the PDF and the package still serve.
  const noReport = (await finalizingEnvelope(world)).envelopeId;
  const published = publish(world, 'alpha', noReport, { withoutReport: true });
  await assertInvariant(noReport, 'readVerification', 'report-missing');
  for (const operation of ['downloadFinalPdf', 'downloadPackage']) same((await world.fetchArtifact(ARTIFACT_PATHS[operation](noReport))).status, 200, `${operation} with no report row: status`);

  // A row whose bytes are not one JSON value: report-invalid.
  const row = (bytes) => {
    const report = published.input.report;
    return {
      id: sid('vrep'),
      envelope_id: noReport,
      artifact_digest: published.built.artifactDigest,
      integrity: report.integrity,
      trust: report.trust,
      revision_coverage: report.revision_coverage,
      seal_type: report.seal_type,
      verifier_name: report.verifier.name,
      verifier_version: report.verifier.version,
      verified_at: report.verified_at,
      checks_json: JSON.stringify(report.checks),
      report_bytes: bytes,
    };
  };
  world.db.transaction(() => store.insert('verification_reports', row(Buffer.from('synthetic, not JSON'))));
  await assertInvariant(noReport, 'readVerification', 'report-invalid');

  // Two rows for one artifact break T038's one-row publish: report-invalid as well.
  const done = await completedEnvelope(world);
  const report = done.input.report;
  world.db.transaction(() =>
    store.insert('verification_reports', {
      ...row(new Uint8Array(done.input.verification)),
      envelope_id: done.envelopeId,
      artifact_digest: done.built.artifactDigest,
      verified_at: report.verified_at,
    }),
  );
  await assertInvariant(done.envelopeId, 'readVerification', 'report-invalid');
});

test('[SC002-09] another tenant\'s verification and artifact reads are a uniform 404, completed or not, and write nothing', async () => {
  const done = await completedEnvelope(world, 'alpha');
  const pending = await envelopeIn(world, 'sent', 'alpha');
  const accessBefore = allAccessEvents().length;
  const snapshot = world.snapshot();
  for (const who of ['sender', 'admin', 'service']) {
    for (const operation of OPERATIONS) {
      for (const [what, target] of [['completed', done.envelopeId], ['sent', pending]]) {
        const cross = await world.fetchArtifact(ARTIFACT_PATHS[operation](target), { tenant: 'beta', who });
        const absent = await world.fetchArtifact(ARTIFACT_PATHS[operation](sid('env')), { tenant: 'beta', who });
        const label = `${operation} by beta ${who} on alpha's ${what} envelope`;
        assertError(cross, 404, 'not_found', label);
        assert.deepEqual(errorShape(cross), errorShape(absent), `${label}: body ${JSON.stringify(errorShape(cross))}, expected the never-existing envelope's ${JSON.stringify(errorShape(absent))}`);
        for (const name of UNIFORM_HEADERS) same(cross.headers[name], absent.headers[name], `${label}: header ${name}`);
      }
    }
  }
  same(allAccessEvents().length, accessBefore, 'access events in either tenant after cross-tenant reads');
  assert.deepEqual(changedTables(world.snapshot(), snapshot), [], 'tables changed by cross-tenant reads');
  // The control: alpha's own sender reads the same artifact.
  assert.equal((await world.fetchArtifact(ARTIFACT_PATHS.downloadPackage(done.envelopeId))).status, 200);
});

test('[PK-03] no capability value, stored capability digest or bearer token appears in the package, the served bytes or the logs', async () => {
  const done = await completedEnvelope(world);
  const id = done.envelopeId;
  const token = bearer('alpha', 'sender');
  const headers = { authorization: `Bearer ${token}` };
  const served = [];
  for (const operation of OPERATIONS) {
    const response = await world.fetchArtifact(ARTIFACT_PATHS[operation](id), { headers });
    assert.equal(response.status, 200);
    served.push(response.bytes);
  }
  const receipt = JSON.parse(membersOf(done.built.bytes).get('audit-receipt.json').toString('utf8'));
  const types = new Set(receipt.events.map((event) => event.type));
  for (const type of ['recipient.invited', 'recipient.challenge_verified', 'recipient.session_created', 'recipient.approved', 'envelope.seal_started']) {
    assert.ok(types.has(type), `the receipt carries the real ${type} event; it has ${JSON.stringify([...types])}`);
  }
  const secrets = [...done.capabilities, ...storedCapabilityDigests(world, 'alpha'), token];
  // Only counts and lengths are shown here, never a capability value.
  const shortValues = secrets.filter((value) => typeof value !== 'string' || value.length < 10).length;
  assert.ok(secrets.length >= 6 && shortValues === 0, `capability values: ${secrets.length} (at least 6), ${shortValues} not strings of at least 10 characters`);
  const haystacks = [Buffer.from(done.built.bytes), ...membersOf(done.built.bytes).values(), ...served, Buffer.from(world.artifactLog(), 'utf8'), Buffer.from(world.logText(), 'utf8')];
  for (const [index, secret] of secrets.entries()) {
    for (const form of [secret, Buffer.from(secret, 'utf8').toString('hex'), Buffer.from(secret, 'utf8').toString('base64url')]) {
      assert.ok(haystacks.every((haystack) => !haystack.includes(form)), `capability value ${index} appears nowhere`);
    }
  }
});
