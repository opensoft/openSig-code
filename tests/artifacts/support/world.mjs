// SPDX-License-Identifier: Apache-2.0
//
// T016 test support: the retrieval world. It extends T010's synthetic world
// (tests/approval/support.mjs) and replaces none of its production modules:
// - T010's world: two tenants (alpha and beta) with the real T005 authenticator, the T008
//   ceremony, the T034 EnvelopeApi and the T010 ApprovalApi, envelopes driven through the
//   real services and routes, and capability values read back from the mail spool and the
//   responses.
// - A second application serving T016's routes: withArtifactHandlers(world.routes), with a
//   real ArtifactApi in its locals beside T010's own, the same authenticator and Origin
//   allowlist, and its own loopback port and log capture.
// - publish(): completes an envelope as T038 will, through the storage layer only. In
//   order: the envelope.seal_started anchor and the completion checkpoint (T029 writer);
//   the package from T016's builder over the envelope's real events; the PDF, evidence and
//   package blobs (T028); then, in one transaction, the signing job's lease, the
//   FinalArtifact row, the one verification_reports row (request #59 (9)), the job's
//   success and the envelope's move to completed, each update by compare-and-set.
// - envelopeIn(): envelopes in each pre-completion state, through the same services.
// Capability values are kept in memory and never put in a test name or an assertion
// message.

import assert from 'node:assert/strict';

import { ARTIFACT_API, ArtifactApi } from '../../../src/api/artifacts/index.ts';
import { withArtifactHandlers } from '../../../src/api/routes.ts';
import { buildPackage } from '../../../src/artifacts/package.ts';
import { createApp, createAppServer } from '../../../src/server/app.ts';
import { loadServerConfig } from '../../../src/server/config.ts';
import { createLogger } from '../../../src/server/redact.ts';
import { AuditWriter, eventFromRow } from '../../../src/storage/audit/index.ts';
import * as approval from '../../approval/support.mjs';
import { jcs } from './jcs.mjs';
import { packageInput, sid, syntheticPdf } from './inputs.mjs';

export const { ORIGIN, COOKIE, TENANTS, bearer, call, assertError, errorShape, contractErrors, sentEnvelope, approvalBody, postApproval, approvedByFirst, codeOf, cookieOf, createInput, fieldsFor } = approval;

export const ARTIFACT_PATHS = Object.freeze({
  readVerification: (id) => `/v1/envelopes/${id}/verification`,
  downloadFinalPdf: (id) => `/v1/envelopes/${id}/final-pdf`,
  downloadPackage: (id) => `/v1/envelopes/${id}/package`,
});

/** The T010 world plus T016's application. */
export async function createArtifactWorld() {
  const world = await approval.createWorld();
  const lines = [];
  const logger = createLogger((line) => lines.push(line));
  const artifactApi = new ArtifactApi({ db: world.db, blobs: world.blobs, clock: world.time.clock });
  const routes = withArtifactHandlers(world.routes);
  const app = createApp({ routes, config: loadServerConfig({ OPENSIG_PORT: '0' }), logger, authenticator: world.authenticator, allowedOrigins: new Set([ORIGIN]) });
  for (const [key, value] of world.app.locals) app.locals.set(key, value);
  app.locals.set(ARTIFACT_API, artifactApi);
  const server = createAppServer(app);
  await new Promise((resolveListen) => server.listen({ host: '127.0.0.1', port: 0 }, resolveListen));
  const { port } = server.address();
  const closeT010 = world.close;
  return Object.assign(world, {
    artifactApi,
    artifactRoutes: routes,
    artifactPort: port,
    artifactLog: () => lines.join('\n'),
    /** GET a T016 route as `who` (sender, admin, service) of `tenant`, or with explicit headers. */
    fetchArtifact(path, { tenant = 'alpha', who = 'sender', headers } = {}) {
      return call(port, { path, headers: headers ?? { authorization: `Bearer ${bearer(tenant, who)}` } });
    },
    async close() {
      await new Promise((resolveClose) => {
        server.close(resolveClose);
        server.closeAllConnections();
      });
      await closeT010();
    },
  });
}

/** Rows of `table` for one envelope, as a reader of the database file sees them. */
export function rowsOf(world, table, envelopeId) {
  return world.rows(table, 'WHERE envelope_id = ?', [envelopeId]);
}

/**
 * Complete a `finalizing` envelope as T038 will (see the header). Returns the builder's
 * input and output and the stored blobs. The publish transaction follows T038's order: the
 * job's lease, the FinalArtifact row, the verification_reports row (report_bytes the exact
 * bytes the package carries; request #59 (9)), the job's success, then the envelope.
 * Broken states for PK-04, which no real publish leaves:
 * - `insertOnly`: the FinalArtifact row exists, but the envelope stays `finalizing`;
 * - `withoutPackage`: the row records no package;
 * - `withoutReport`: no verification_reports row.
 * With `prettyReport`, the stored and packaged report bytes are two-space JSON rather than
 * RFC 8785, so a test can tell bytes served unchanged from bytes serialized again.
 */
export function publish(world, tenant, envelopeId, { insertOnly = false, withoutPackage = false, withoutReport = false, prettyReport = false } = {}) {
  const tenantId = world.tenantId(tenant);
  const store = world.store(tenant);
  const envelope = store.get('envelopes', { id: envelopeId });
  assert.equal(envelope?.state, 'finalizing', `publish starts from a finalizing envelope: ${envelopeId} is ${envelope?.state}`);
  const audit = new AuditWriter(world.db, { clock: world.time.clock });
  const anchor = world.db.transaction(() =>
    audit.append(tenantId, { type: 'envelope.seal_started', actor: { kind: 'system', ref: 'finalizer' }, envelopeId, subjectDigest: String(envelope.manifest_digest), metadata: { attempt: 1 } }),
  );
  const checkpoint = world.db.transaction(() => audit.checkpointCompletion(tenantId, envelopeId));
  const events = [...store.iterate('audit_events', { envelope_id: envelopeId }, { orderBy: [['seq', 'asc']] })].map((row) => ({ event: eventFromRow(row), eventDigest: String(row['event_digest']) }));
  const pdf = syntheticPdf(envelopeId);
  const input = packageInput(
    { tenantId, envelopeId, anchor: { seq: anchor.seq, digest: anchor.digest }, chainHead: { seq: checkpoint.seq, digest: checkpoint.digest }, checkpoint, events },
    { pdf, artifactId: sid('art') },
  );
  if (prettyReport) input.verification = Buffer.from(JSON.stringify(input.report, null, 2), 'utf8');
  const built = buildPackage(input);
  const pdfBlob = world.blobs.put(tenantId, pdf);
  const evidenceBlob = world.blobs.put(tenantId, Buffer.from(jcs(input.approvalManifest), 'utf8'));
  const packageBlob = world.blobs.put(tenantId, built.bytes);
  const now = () => world.time.now.toISOString();
  world.db.transaction(() => {
    const job = store.get('signing_jobs', { envelope_id: envelopeId });
    assert.ok(job, `the last approval reserved the signing job of ${envelopeId}`);
    const leased = store.compareAndSet('signing_jobs', { envelope_id: envelopeId }, Number(job['version']), {
      status: 'running',
      attempt_count: 1,
      fencing_token: 1,
      lease_owner: 'runner-artifacts',
      lease_expires_at: new Date(world.time.now.getTime() + 60_000).toISOString(),
      updated_at: now(),
    });
    assert.ok(leased, `the job lease at version ${job['version']}`);
    const report = input.report;
    store.insert('final_artifacts', {
      artifact_id: input.artifactId,
      envelope_id: envelopeId,
      artifact_digest: built.artifactDigest,
      package_digest: withoutPackage ? null : built.packageDigest,
      approved_composition_digest: input.approvalManifest.approved_composition_digest,
      approval_evidence_digest: input.report.approval_evidence_digest,
      pdf_blob_ref: pdfBlob.ref,
      evidence_blob_ref: evidenceBlob.ref,
      package_blob_ref: withoutPackage ? null : packageBlob.ref,
      signer_certificate_sha256: input.approvalManifest.seal.signer_certificate_sha256,
      development_certificate: 1,
      verifier_name: report.verifier.name,
      verifier_version: report.verifier.version,
      verification_json: jcs(report),
      fencing_token: 1,
      completed_at: now(),
    });
    if (!withoutReport) {
      store.insert('verification_reports', {
        id: sid('vrep'),
        envelope_id: envelopeId,
        artifact_digest: built.artifactDigest,
        integrity: report.integrity,
        trust: report.trust,
        revision_coverage: report.revision_coverage,
        seal_type: report.seal_type,
        signer_certificate_sha256: report.signer_certificate_sha256,
        timestamp_status: report.timestamp_status,
        revocation_status: report.revocation_status,
        verifier_name: report.verifier.name,
        verifier_version: report.verifier.version,
        verified_at: report.verified_at,
        checks_json: JSON.stringify(report.checks),
        report_bytes: new Uint8Array(input.verification),
      });
    }
    if (insertOnly) return;
    const succeeded = store.compareAndSet('signing_jobs', { envelope_id: envelopeId }, Number(job['version']) + 1, { status: 'succeeded', lease_owner: null, lease_expires_at: null, updated_at: now() });
    assert.ok(succeeded, `the job's success at version ${Number(job['version']) + 1}`);
    const completed = store.compareAndSet('envelopes', { id: envelopeId }, Number(envelope.version), { state: 'completed', updated_at: now() });
    assert.ok(completed, `${envelopeId} to completed at version ${envelope.version}`);
  });
  return { input, built, pdf, pdfBlob, packageBlob, evidenceBlob };
}

/**
 * A one-recipient envelope approved through the real routes, so its chain holds real
 * ceremony and approval events. Returns { envelopeId, capabilities }, where capabilities
 * lists the raw invitation token, challenge code, session value and CSRF token.
 */
export async function finalizingEnvelope(world, tenant = 'alpha') {
  const { envelope, token } = await sentEnvelope(world, { tenant, recipients: 1 });
  const challenge = await world.http({ method: 'POST', path: '/v1/recipient-session/challenges', headers: { origin: ORIGIN }, body: { invitation: token } });
  assert.equal(challenge.status, 202);
  await world.ceremony.drain();
  const [mail] = world.takeMails('recipient_challenge', 'signer.one@example.test');
  assert.ok(mail, 'the challenge code is mailed');
  const code = codeOf(mail);
  const created = await world.http({ method: 'POST', path: '/v1/recipient-session', headers: { origin: ORIGIN }, body: { invitation: token, code } });
  assert.equal(created.status, 201);
  const session = { cookie: cookieOf(created), csrf: created.json.csrf_token, state: created.json };
  const approved = await postApproval(world, session, approvalBody(session.state));
  assert.equal(approved.status, 200, `the recipient approves: status ${approved.status} ${approved.json?.code ?? ''}`);
  assert.equal(world.store(tenant).get('envelopes', { id: envelope.id })?.state, 'finalizing');
  return { envelopeId: envelope.id, capabilities: [token, code, session.cookie, session.csrf] };
}

/** A completed envelope with its published artifact. */
export async function completedEnvelope(world, tenant = 'alpha') {
  const finalizing = await finalizingEnvelope(world, tenant);
  return { ...finalizing, ...publish(world, tenant, finalizing.envelopeId) };
}

/**
 * The page list T034's upload stores in the parse report, which T007's prepare reads as
 * its placement geometry (request #53; 8629a53): each page with its MediaBox and an equal
 * CropBox, sized so the displayed width and height follow under the page's rotation. The
 * same rule as T010's fixture (54e051a), which does not export it.
 */
function pageReport(pages) {
  return pages.map((page) => {
    const box = page.rotate % 180 === 0 ? [0, 0, page.width, page.height] : [0, 0, page.height, page.width];
    return { ...page, media_box: box, crop_box: [...box] };
  });
}

/** An envelope of `tenant` in `state` (draft, prepared, sent, in-progress or finalizing), through the real services. */
export async function envelopeIn(world, state, tenant = 'alpha') {
  const req = world.req(tenant);
  if (state === 'draft') return world.envelopes.create(req, createInput(1)).body.id;
  if (state === 'prepared') {
    const tenantId = world.tenantId(tenant);
    const pdf = approval.syntheticPdf(sid('doc'));
    const put = world.blobs.put(tenantId, pdf);
    const pages = [
      { number: 1, width: 612, height: 792, rotate: 0 },
      { number: 2, width: 612, height: 792, rotate: 90 },
    ];
    const created = world.envelopes.create(req, createInput(1)).body;
    const uploaded = world.envelopes.uploadDocument(req, created.id, created.version, {
      digest: put.digest,
      bytes: pdf.length,
      pages,
      parseReport: { pages: pageReport(pages), network_sandbox: 'netns+fs-enforced (local)' },
    }).body;
    return world.envelopes.prepare(req, created.id, { expected_version: uploaded.version, fields: fieldsFor(1) }).body.id;
  }
  if (state === 'sent') return (await sentEnvelope(world, { tenant, recipients: 1 })).envelope.id;
  if (state === 'in-progress') return (await approvedByFirst(world, { tenant, recipients: 2 })).envelope.id;
  if (state === 'finalizing') return (await finalizingEnvelope(world, tenant)).envelopeId;
  throw new Error(`envelopeIn: no path to ${state}`);
}

/** Every stored capability hash, HMAC and secret of `tenant`, as strings (invitations, challenges, sessions). */
export function storedCapabilityDigests(world, tenant) {
  const values = [];
  for (const table of ['invitations', 'challenges', 'recipient_sessions']) {
    for (const row of world.rows(table, 'WHERE tenant_id = ?', [world.tenantId(tenant)])) {
      for (const [name, value] of Object.entries(row)) {
        if (!/hash|hmac|secret/.test(name) || value === null) continue;
        values.push(value instanceof Uint8Array ? Buffer.from(value).toString('hex') : String(value));
      }
    }
  }
  return values;
}
