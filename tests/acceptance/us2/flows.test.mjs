// SPDX-License-Identifier: Apache-2.0
//
// T017: ten consecutive local flows (the T017 line; plan.md § Case catalogs SC-001 and SC-005;
// spec.md SC-001, SC-005 and US2; A-010 requests #48 C1, #56, #76 (3) and #78). One world
// (harness.mjs) and one locked Chromium (browser.mjs) serve the whole file, and the flows run one
// after another. No flow is rerun or replaced: a failed flow fails the run (request #78 (8)).
//
// [SC001-01]..[SC001-10]: one flow each, mixed one and two recipients, on table and cross-reference
// stream bases, rotated pages and a 50-page document (no hybrid base; request #78 (6)). A flow is:
// - the sender: create, upload (T033's sandboxed parse), prepare, preview, confirm and send;
// - each recipient in the browser: open the mailed link, code, review (the document checked),
//   one review reload, sign (typed or drawn), consent and approve; recipient 2 is invited only
//   after recipient 1's approval commits;
// - finalization by T038's runner, until the envelope is `completed`;
// - retrieval of final.pdf, verification.json and the package (T016's routes).
// Each flow shows:
// - request #76 (3), row T016-NOTES F3, first: each of the four JSON members validates against its
//   contract schema (ApprovalManifest, AuditReceipt, VerificationReport, PackageIndex) with the
//   test-local validator, imported read-only; a failure is a finding against the member's producer;
// - every approval's document_digest equals the SHA-256 of every response body the browser received
//   for the document (the shell's checked read and the viewer iframe), the session's digest, the
//   frozen fixture's digest, the stored approval row and the package manifest's approval record;
//   each packaged approval record's field_values_digest, date_values and approval_digest recompute
//   from data-model.md's preimage with T017's own serializer (row FV-DIGEST), and the second
//   approval binds the first;
// - finalization is T038's runner at code 7257167, composed by the T031 US2 slot: the flow waits,
//   with a bounded deadline, for the runner's next tick (DEFAULT_RUN_INTERVAL_MS, 15 s) to publish;
// - the product verification (the served verification.json): integrity `valid`, revision_coverage
//   `complete`, trust `untrusted` (judged against the configured unrelated anchor) for the
//   development certificate, and the approval-evidence check `pass`;
// - request #78 (1): T014's runBoth on the downloaded final.pdf, with the unrelated anchor, the
//   package index's final.pdf digest and the RFC 8785 digest of the packaged manifest without
//   final_pdf_digest (T017's own serializer). disagreements must be empty, and the product side is
//   accepted as the original;
// - the package: exactly five members, final.pdf and verification.json byte-equal to the downloads,
//   package-index.json's digests and sizes equal to the members, ETags equal to the digests;
// - request #78 (8): no operator retry (no envelope.finalization_retried event in the packaged
//   receipt); the attempts are recorded in evidence.json, so an automatic retry is visible.
// Each flow writes one flows.json entry (request #48 C1) before its assertions; the entry holds only
// the T017 line's fields.
// [SC005-01]: one combined p95 within 2 s over the status (readEnvelope), link-open and
// review-reload navigations of the ten flows; each kind's p95 and count recorded; indicative-local,
// never a claim of SC-005.
// [US2-TAMPER] (an extra ID, never required): SC001-01's final.pdf, copied, through runBoth each
// time: a byte changed inside each signed range gives integrity `invalid`, and an appended revision
// gives revision_coverage `incomplete`, with disagreements empty. Controls: the untouched copy is
// accepted, and with the seal certificate as the only anchor BOTH checkers say `trusted`
// (request #78 (7)).
// [US2-RECORD] (an extra ID): the flow record holds exactly the ten entries and the line's fields,
// and no secret, token, link or host path.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { verifyPdf, VERIFIER } from '../../../src/verifier/index.ts';
import { approveInBrowser, assertDocumentTransport, browserEvidence, captureDocument, closeAll, guardPages, launchLocked, openContext } from './browser.mjs';
import { approvalRecordDigests, assertRecordClean, bindOracleLabels, evidenceDigestOf, FLOW_FIELDS, flowRecord, openPackage, recordEvidence, recordFlow, sha256, startWorld, summarize } from './harness.mjs';
import { AGREEMENT_FIELDS, checkBoth, openWork, oracleLabels, oracleResultOf } from './oracle.mjs';
import { appendRevision, byteChangeInRange } from './tamper.mjs';

const PLANS = Object.freeze([
  Object.freeze({ document: 'agreement-multipage.pdf', page: 3, signatures: ['typed'] }),
  Object.freeze({ document: 'agreement-multipage.pdf', page: 3, signatures: ['drawn', 'typed'] }),
  Object.freeze({ document: 'agreement-xref-stream.pdf', page: 3, signatures: ['drawn'] }),
  Object.freeze({ document: 'agreement-xref-stream.pdf', page: 3, signatures: ['typed', 'drawn'] }),
  Object.freeze({ document: 'rotated-pages.pdf', page: 1, signatures: ['typed'] }),
  Object.freeze({ document: 'rotated-pages.pdf', page: 3, signatures: ['drawn', 'typed'] }),
  Object.freeze({ document: 'single-page.pdf', page: 1, signatures: ['drawn'] }),
  Object.freeze({ document: 'single-page.pdf', page: 1, signatures: ['typed', 'typed'] }),
  Object.freeze({ document: 'pages-50.pdf', page: 50, signatures: ['typed'] }),
  Object.freeze({ document: 'rotated-pages.pdf', page: 5, signatures: ['drawn', 'drawn'] }),
]);
const CASES = Object.freeze(PLANS.map((_, index) => `SC001-${String(index + 1).padStart(2, '0')}`));
/** A table-based flow: appendRevision needs a classic last section. */
const TAMPER_SOURCE = 'SC001-01';
const NAVIGATION_BOUND_MS = 2_000;
/** The operator retry's audit type (the T038 line); a flow with one does not count (request #78 (8)). */
const OPERATOR_RETRY_EVENT = 'envelope.finalization_retried';
/** The product side of an accepted original for the development certificate. */
const ACCEPTED = Object.freeze({ integrity: 'valid', trust: 'untrusted', revision_coverage: 'complete', artifact_match: true, approval_evidence: 'match', accepted_as_original: true });

let world;
let browser;
let locked;
let oracle;
/** caseId -> { id, pdf, base, expectedArtifactDigest, evidenceDigest } for every flow that passed. */
const completed = new Map();

before(async () => {
  // Request #78 (1): the labels are read at run time, and a missing member fails before any flow.
  bindOracleLabels(oracleLabels);
  world = await startWorld({ label: 'us2' });
  ({ browser, locked } = await launchLocked());
  oracle = openWork();
});

after(() => closeAll([() => oracle?.close(), () => browser?.close(), () => world?.close()]));

const productFields = (outcome) => ({
  integrity: outcome.integrity,
  trust: outcome.trust,
  revision_coverage: outcome.revision_coverage,
  artifact_match: outcome.artifact_match,
  approval_evidence: outcome.approval_evidence,
  accepted_as_original: outcome.accepted_as_original,
});

/** runBoth on `bytes` against `anchorPaths`, with the producer's expected digests. */
const both = (bytes, anchorPaths, expectedArtifactDigest, evidenceDigest) =>
  checkBoth(oracle, { verifyPdf, bytes, anchorPaths, expectedArtifactDigest, expectedApprovalEvidenceDigest: evidenceDigest });

async function runFlow(caseId, plan) {
  const recipients = plan.signatures.map((_, index) => world.address(`${caseId.toLowerCase()}-r${index + 1}`));
  const sent = await world.sentEnvelope({ flow: caseId, document: plan.document, page: plan.page, recipients });
  const id = sent.id;

  const turns = [];
  const pages = {};
  const closers = [];
  await guardPages({ caseId, section: `${caseId} recipients in the browser`, browser, pages, closers }, async () => {
    for (const [index, signature] of plan.signatures.entries()) {
      const ordinal = index + 1;
      const party = await openContext(browser);
      pages[`recipient${ordinal}`] = party.page;
      closers.unshift(party.close);
      const capture = await captureDocument(party.page, { origin: world.origin, caseId, recipient: ordinal });
      closers.unshift(() => capture.stop());
      const invitation = world.invitation(recipients[index]);
      const turn = await approveInBrowser(party, { world, invitation, to: recipients[index], ordinal, signature, flow: caseId });
      await capture.settle();
      turns.push({ ordinal, ...turn, received: [...capture.seen] });
      await world.readEnvelope(id, caseId);
    }
  });
  const last = turns.at(-1);
  assert.equal(last.receipt.envelope_state, 'finalizing', `${caseId}: the last approval moves envelope ${id} to finalizing (${last.receipt.envelope_state})`);

  await world.awaitCompleted(id);
  const { envelope, finalPdf, verification, pkg } = await world.retrieve(id, caseId);
  const pdf = finalPdf.bytes;
  const artifactDigest = sha256(pdf);
  const report = verification.json;
  const opened = openPackage(pkg.bytes);
  const manifest = opened.members['approval-manifest.json'].value;
  const index = opened.members['package-index.json'].value;
  // Request #78 (1): the expected digests come from the package, the producer's record.
  const expectedArtifactDigest = Array.isArray(index?.files) ? (index.files.find((file) => file.path === 'final.pdf')?.sha256 ?? null) : null;
  const evidenceDigest = evidenceDigestOf(manifest);
  let run = null;
  let runError = null;
  try {
    run = both(pdf, [world.material.anchorsFile], expectedArtifactDigest, evidenceDigest);
  } catch (error) {
    runError = error;
  }
  const evidenceCheck = Array.isArray(report?.checks) ? (report.checks.find((check) => check.id === 'approval-evidence-digest') ?? null) : null;
  const digestMatches = turns.map((turn) => turn.received.length > 0 && turn.received.every((seen) => seen.status === 200 && seen.sha256 === turn.body.document_digest));
  recordFlow(caseId, {
    recipients: plan.signatures.length,
    document_digest_match: digestMatches.length === plan.signatures.length && digestMatches.every(Boolean),
    product_verification: { integrity: report?.integrity ?? null, revision_coverage: report?.revision_coverage ?? null, trust: report?.trust ?? null, approval_evidence: evidenceCheck?.result ?? null },
    oracle: run === null ? null : oracleResultOf(run),
    package_digest: sha256(pkg.bytes),
  });
  recordEvidence({ flow_attempts: { [caseId]: { attempts: envelope.finalization?.attempts ?? null, job_status: envelope.finalization?.job_status ?? null } } });

  // Request #76 (3), row T016-NOTES F3: the first contract check of a package T038's runner built.
  // It runs before anything below reads a member, so a member that does not validate is reported
  // against its producer, never as a later TypeError.
  const { entries, members } = opened;
  for (const member of Object.values(members)) {
    assert.deepEqual(member.errors, [], `${caseId}: ${member.name} validates against the contract schema ${member.schema}; a failure is a finding against ${member.producer}, never repaired in T017 (first errors: ${member.errors.slice(0, 5).join('; ')})`);
    if (member.canonical) assert.equal(member.isCanonical, true, `${caseId}: ${member.name} is its own RFC 8785 form (${member.bytes.length} bytes)`);
  }

  // Request #78 (8): a flow that needed an operator retry does not count.
  const retried = members['audit-receipt.json'].value.events.filter((event) => event.type === OPERATOR_RETRY_EVENT).length;
  assert.equal(retried, 0, `${caseId}: envelope ${id} needed ${retried} operator retr${retried === 1 ? 'y' : 'ies'}, so it does not count for SC001 (finalization ${envelope.finalization?.attempts} attempt(s))`);

  // SC-001: every approval references the displayed revision, the bytes the browser received.
  const stored = world.rows('approvals', id);
  assert.equal(stored.length, plan.signatures.length, `${caseId}: the store holds ${plan.signatures.length} approval(s) for envelope ${id} (found ${stored.length})`);
  for (const turn of turns) {
    const who = `${caseId} recipient ${turn.ordinal}`;
    assertDocumentTransport(turn.received, who);
    for (const seen of turn.received) {
      assert.equal(seen.status, 200, `${who}: a ${seen.resourceType} response for the document answered ${seen.status ?? seen.error}`);
      assert.equal(seen.bytes, turn.state.document.bytes, who + ': every captured body has the session document length (received ' + seen.bytes + ', expected ' + turn.state.document.bytes + ')');
      assert.equal(seen.sha256, turn.body.document_digest, `${who}: the approval's document_digest ${turn.body.document_digest} equals the SHA-256 ${seen.sha256} of the ${seen.bytes} bytes the browser received (${seen.resourceType})`);
    }
    assert.equal(turn.body.document_digest, turn.state.document.digest, `${who}: the approval binds the session's document ${turn.state.document.digest}`);
    assert.equal(turn.body.document_digest, sent.entry.sha256, `${who}: the approval binds the frozen fixture ${plan.document} (${sent.entry.sha256})`);
    const row = stored.find((each) => each.recipient_id === turn.receipt.recipient_id);
    assert.ok(row, `${who}: the store holds the approval of recipient ${turn.receipt.recipient_id}`);
    assert.equal(row.document_digest, turn.body.document_digest, `${who}: the stored approval's document_digest ${row.document_digest} is the one the browser sent`);
    const recorded = manifest.approvals.find((each) => each.approval_id === turn.receipt.approval_id);
    assert.ok(recorded, `${who}: the package manifest records approval ${turn.receipt.approval_id}`);
    assert.equal(recorded.document_digest, turn.body.document_digest, `${who}: the manifest's approval record binds ${recorded.document_digest}`);
    assert.equal(recorded.approval_digest, turn.receipt.approval_digest, `${who}: the manifest's approval digest is the receipt's ${turn.receipt.approval_digest}`);
    // FV-DIGEST's preimage (data-model.md § Approval; request #85) on the real package, recomputed
    // by T017's own serializer: a second layer over T038's check before the seal anchor.
    const digests = approvalRecordDigests(recorded);
    assert.deepEqual(recorded.date_values, digests.dateValues, `${who}: date_values are the UTC dates of server_time ${recorded.server_time}, one per date field, by key (found ${JSON.stringify(recorded.date_values)})`);
    assert.equal(recorded.field_values_digest, digests.fieldValuesDigest, `${who}: field_values_digest ${recorded.field_values_digest} is the RFC 8785 digest ${digests.fieldValuesDigest} of {field_values, date_values}`);
    assert.equal(recorded.approval_digest, digests.approvalDigest, `${who}: approval_digest ${recorded.approval_digest} is the RFC 8785 digest ${digests.approvalDigest} of its record`);
  }
  assert.equal(manifest.approvals[0].prior_approval_digest, null, `${caseId}: the first approval has no prior (${manifest.approvals[0].prior_approval_digest})`);
  if (manifest.approvals.length === 2) {
    assert.equal(manifest.approvals[1].prior_approval_digest, manifest.approvals[0].approval_digest, `${caseId}: the second approval binds the first's digest ${manifest.approvals[0].approval_digest}`);
  }

  // Completion and retrieval (T038 publication, T016 routes).
  assert.equal(envelope.state, 'completed', `${caseId}: envelope ${id} is completed (${envelope.state})`);
  assert.equal(envelope.approvals_complete, true, `${caseId}: approvals_complete`);
  assert.equal(envelope.finalization?.job_status, 'succeeded', `${caseId}: finalization ${envelope.finalization?.job_status} after ${envelope.finalization?.attempts} attempt(s)`);
  assert.equal(expectedArtifactDigest, artifactDigest, `${caseId}: the package index's final.pdf digest ${expectedArtifactDigest} is the downloaded final.pdf's ${artifactDigest}`);
  assert.equal(envelope.artifact?.artifact_digest, artifactDigest, `${caseId}: the recorded artifact digest ${envelope.artifact?.artifact_digest} is the downloaded final.pdf's ${artifactDigest}`);
  assert.equal(finalPdf.headers.etag, `"${artifactDigest}"`, `${caseId}: downloadFinalPdf's ETag ${finalPdf.headers.etag} is its digest`);
  assert.match(finalPdf.headers['content-type'] ?? '', /^application\/pdf(?:;|$)/, `${caseId}: final.pdf is application/pdf`);
  assert.equal(envelope.artifact.package_digest, sha256(pkg.bytes), `${caseId}: the recorded package digest ${envelope.artifact.package_digest} is the downloaded package's ${sha256(pkg.bytes)}`);
  assert.equal(pkg.headers.etag, `"${sha256(pkg.bytes)}"`, `${caseId}: downloadPackage's ETag ${pkg.headers.etag} is its digest`);
  assert.equal(verification.headers.etag, `"${sha256(verification.bytes)}"`, `${caseId}: readVerification's ETag ${verification.headers.etag} is its digest`);
  assert.deepEqual({ integrity: envelope.artifact.integrity, trust: envelope.artifact.trust }, { integrity: 'valid', trust: 'untrusted' }, `${caseId}: the artifact summary says integrity ${envelope.artifact.integrity}, trust ${envelope.artifact.trust}`);

  // The product verification: the served report.
  assert.equal(report?.schema, 'opensig.verification/1', `${caseId}: verification.json is a VerificationReport (${report?.schema})`);
  assert.equal(report.artifact_digest, artifactDigest, `${caseId}: the report names artifact ${report.artifact_digest}, the downloaded ${artifactDigest}`);
  assert.deepEqual(
    { integrity: report.integrity, revision_coverage: report.revision_coverage, trust: report.trust, approval_evidence: evidenceCheck?.result ?? null },
    { integrity: 'valid', revision_coverage: 'complete', trust: 'untrusted', approval_evidence: 'pass' },
    `${caseId}: the product verification for the development certificate: integrity ${report.integrity}, coverage ${report.revision_coverage}, trust ${report.trust}, approval evidence ${evidenceCheck?.result}/${evidenceCheck?.detail_code ?? '-'}`,
  );
  const trustCheck = report.checks.find((check) => check.id === 'trust-anchors');
  assert.equal(trustCheck?.detail_code, 'no-path-to-anchor', `${caseId}: trust was judged against the configured unrelated anchor (${trustCheck?.result}/${trustCheck?.detail_code})`);
  assert.equal(report.trust_anchor_ref, null, `${caseId}: no trust anchor reference for an untrusted seal`);
  assert.equal(report.signer_certificate_sha256, world.material.sealCertificateSha256, `${caseId}: the seal's signer is the development certificate ${world.material.sealCertificateSha256}`);
  assert.equal(report.approval_evidence_digest, evidenceDigest, `${caseId}: the signed evidence digest ${report.approval_evidence_digest} is the RFC 8785 digest ${evidenceDigest} of the packaged manifest without final_pdf_digest`);
  assert.deepEqual({ seal: report.seal_type, timestamp: report.timestamp_status, revocation: report.revocation_status }, { seal: 'organization', timestamp: 'absent', revocation: 'not-checked' }, `${caseId}: seal ${report.seal_type}, timestamp ${report.timestamp_status}, revocation ${report.revocation_status}`);
  assert.deepEqual(report.verifier, { name: VERIFIER.name, version: VERIFIER.version }, `${caseId}: the report names the shipped verifier ${VERIFIER.name} ${VERIFIER.version}`);

  // The package (T016's builder as T038's runner called it); its members validated above.
  assert.ok(entries.get('final.pdf').equals(pdf), `${caseId}: the package's final.pdf (${sha256(entries.get('final.pdf'))}) is the downloaded final.pdf (${artifactDigest})`);
  assert.ok(members['verification.json'].bytes.equals(verification.bytes), `${caseId}: the package's verification.json (${sha256(members['verification.json'].bytes)}) is the served report (${sha256(verification.bytes)})`);
  assert.deepEqual({ envelope: index.envelope_id, artifact: index.artifact_id }, { envelope: id, artifact: envelope.artifact.artifact_id }, `${caseId}: package-index.json names envelope ${index.envelope_id} and artifact ${index.artifact_id}`);
  for (const file of index.files) {
    const bytes = entries.get(file.path);
    assert.ok(bytes, `${caseId}: package-index.json lists ${file.path}, and the package holds it`);
    assert.deepEqual({ sha256: sha256(bytes), bytes: bytes.length }, { sha256: file.sha256, bytes: file.bytes }, `${caseId}: ${file.path} has the indexed digest ${file.sha256} and size ${file.bytes}`);
  }
  assert.equal(manifest.envelope_id, id, `${caseId}: the manifest names envelope ${manifest.envelope_id}`);
  assert.equal(manifest.document.digest, sent.entry.sha256, `${caseId}: the manifest names the frozen document ${manifest.document.digest}`);
  assert.equal(manifest.final_pdf_digest, artifactDigest, `${caseId}: the manifest's final_pdf_digest ${manifest.final_pdf_digest} is final.pdf's`);
  assert.deepEqual(manifest.seal, { type: 'organization', signer_certificate_sha256: world.material.sealCertificateSha256, development_certificate: true }, `${caseId}: the manifest labels the development seal (${JSON.stringify(manifest.seal)})`);
  assert.equal(manifest.approvals.length, plan.signatures.length, `${caseId}: the manifest records ${manifest.approvals.length} approval(s)`);

  // Request #78 (1): the oracle and the product on the same bytes (T014's runBoth).
  if (runError !== null) throw runError;
  assert.deepEqual(run.diff, [], `${caseId}: the oracle and the product agree on ${AGREEMENT_FIELDS.join(', ')} (disagreements: ${JSON.stringify(run.diff)})`);
  assert.deepEqual(productFields(run.product), ACCEPTED, `${caseId}: the product, on the downloaded bytes, says ${JSON.stringify(productFields(run.product))}`);
  assert.equal(run.product.approval_evidence_digest, report.approval_evidence_digest, `${caseId}: runBoth's product side reads the served evidence digest ${run.product.approval_evidence_digest}`);
  assert.deepEqual(oracleResultOf(run), Object.fromEntries(AGREEMENT_FIELDS.map((field) => [field, run.product[field]])), `${caseId}: the recorded oracle result equals the product's on the agreement fields`);

  recordEvidence({ case: caseId, flows_recorded: Object.keys(flowRecord()).length, ...browserEvidence(browser, locked), openssl_version: world.material.opensslVersion });
  return { id, pdf, base: sent.bytes, expectedArtifactDigest, evidenceDigest };
}

for (const [index, plan] of PLANS.entries()) {
  const caseId = CASES[index];
  test(`[${caseId}] flow ${index + 1} of ten consecutive: ${plan.signatures.length} recipient(s) on ${plan.document}; each approval's document_digest is the SHA-256 of the bytes the browser received; one retrievable verified package (integrity valid, coverage complete, trust untrusted for the development certificate), the oracle agrees through runBoth, and the package's JSON members validate against the contract`, async () => {
    completed.set(caseId, await runFlow(caseId, plan));
  });
}

test('[SC005-01] indicative-local navigation timing over the ten flows: status, link-open and review-reload navigations, one combined p95 within 2 s, never a claim of SC-005', () => {
  assert.deepEqual([...completed.keys()], [...CASES], `all ten flows completed before the navigation figures are taken (completed: ${[...completed.keys()].join(', ') || 'none'})`);
  for (const [index, caseId] of CASES.entries()) {
    const recipients = PLANS[index].signatures.length;
    const mine = world.samples.filter((sample) => sample.flow === caseId);
    const count = (kind) => mine.filter((sample) => sample.kind === kind).length;
    assert.deepEqual(
      { status: count('status'), open: count('open-invitation'), reload: count('review-reload') },
      { status: recipients + 2, open: recipients, reload: recipients },
      `${caseId}: one status read after send, after each approval and after completion, and one link open and one review reload per recipient`,
    );
  }
  const of = (kind) => world.samples.filter((sample) => sample.kind === kind).map((sample) => sample.ms);
  const figures = {
    scope: 'indicative-local',
    bound_ms: NAVIGATION_BOUND_MS,
    combined: summarize(world.samples.map((sample) => sample.ms)),
    status: summarize(of('status')),
    link_open: summarize(of('open-invitation')),
    review_reload: summarize(of('review-reload')),
    measured: 'monotonic test clock; status = readEnvelope round trip; link_open = link open until the invitation step; review_reload = reload with the session held until the checked review step',
    excludes: 'authentication and mail (the challenge, the code entry and the session creation) are never timed, and package retrieval is never counted',
  };
  recordEvidence({ timing: { navigation: figures } });
  assert.ok(figures.combined.p95_ms <= NAVIGATION_BOUND_MS, `the combined navigation p95 ${figures.combined.p95_ms} ms over ${figures.combined.n} operations is within ${NAVIGATION_BOUND_MS} ms (indicative-local; status p95 ${figures.status.p95_ms} of ${figures.status.n}, link-open p95 ${figures.link_open.p95_ms} of ${figures.link_open.n}, review-reload p95 ${figures.review_reload.p95_ms} of ${figures.review_reload.n})`);
  recordEvidence({ case: 'SC005-01' });
});

test('[US2-TAMPER] on a completed flow output, through runBoth each time: a byte changed inside either signed range gives integrity invalid, an appended revision gives revision_coverage incomplete, and the oracle agrees; with the seal certificate as the only anchor both checkers say trusted', () => {
  const source = completed.get(TAMPER_SOURCE);
  assert.ok(source, `${TAMPER_SOURCE} completed, so a completed flow's final.pdf exists`);
  const retained = Buffer.from(source.pdf);
  const unrelated = [world.material.anchorsFile];
  const judge = (bytes, anchorPaths = unrelated) => both(bytes, anchorPaths, source.expectedArtifactDigest, source.evidenceDigest);
  const control = judge(Buffer.from(retained));
  const selfAnchored = judge(Buffer.from(retained), [world.material.sealCertFile]);
  const first = byteChangeInRange(retained, source.base, 'first');
  const second = byteChangeInRange(retained, source.base, 'second');
  const changedFirst = judge(first.bytes);
  const changedSecond = judge(second.bytes);
  const appended = judge(appendRevision(retained));
  const line = (run) => ({
    product_integrity: run.product.integrity,
    oracle_integrity: run.oracle.integrity,
    product_revision_coverage: run.product.revision_coverage,
    oracle_revision_coverage: run.oracle.revision_coverage,
    product_trust: run.product.trust,
    oracle_trust: run.oracle.trust,
    product_accepted: run.product.accepted_as_original,
    disagreements: run.diff.length,
  });
  recordEvidence({
    tamper: {
      source: TAMPER_SOURCE,
      control_untouched_copy: line(control),
      control_seal_certificate_as_only_anchor: line(selfAnchored),
      byte_change_first_range: { offset: first.offset, range: first.range, ...line(changedFirst) },
      byte_change_second_range: { offset: second.offset, range: second.range, ...line(changedSecond) },
      appended_revision: line(appended),
    },
  });

  for (const [name, run] of [['the untouched copy', control], ['the seal certificate as the only anchor', selfAnchored], ['a byte changed in the first signed range', changedFirst], ['a byte changed in the second signed range', changedSecond], ['an appended revision', appended]]) {
    assert.deepEqual(run.diff, [], `${name}: the oracle and the product agree (disagreements: ${JSON.stringify(run.diff)})`);
  }
  assert.deepEqual(productFields(control.product), ACCEPTED, `control: the untouched copy is accepted (${JSON.stringify(productFields(control.product))})`);
  assert.deepEqual(
    { product: selfAnchored.product.trust, oracle: selfAnchored.oracle.trust, anchor: selfAnchored.product.trust_anchor_ref },
    { product: 'trusted', oracle: 'trusted', anchor: world.material.sealCertificateSha256 },
    `control: with the seal certificate as the only anchor both checkers say trusted (product ${selfAnchored.product.trust}, oracle ${selfAnchored.oracle.trust}), so untrusted in the flows is a real verdict`,
  );
  for (const [name, run, at] of [['first', changedFirst, first], ['second', changedSecond, second]]) {
    assert.deepEqual(
      { product: run.product.integrity, oracle: run.oracle.integrity, accepted: run.product.accepted_as_original },
      { product: 'invalid', oracle: 'invalid', accepted: false },
      `a byte changed at ${at.offset} inside the ${name} signed range [${at.range}]: product ${run.product.integrity}, oracle ${run.oracle.integrity}`,
    );
  }
  assert.deepEqual(
    { product: [appended.product.integrity, appended.product.revision_coverage, appended.product.accepted_as_original], oracle: [appended.oracle.integrity, appended.oracle.revision_coverage] },
    { product: ['valid', 'incomplete', false], oracle: ['valid', 'incomplete'] },
    `an appended revision: product ${JSON.stringify(productFields(appended.product))}, oracle coverage ${appended.oracle.revision_coverage}`,
  );
  assert.equal(sha256(source.pdf), source.expectedArtifactDigest, `the retained original is unchanged (${source.expectedArtifactDigest})`);
  recordEvidence({ case: 'US2-TAMPER' });
});

test('[US2-RECORD] the flow record holds exactly the ten entries with the T017 line fields only, and no secret, token, link or host path', () => {
  const record = flowRecord();
  assert.deepEqual(Object.keys(record).sort(), [...CASES], `flows.json holds the ten flows (found ${Object.keys(record).join(', ') || 'none'})`);
  for (const caseId of CASES) {
    const entry = record[caseId];
    assert.deepEqual(Object.keys(entry), [...FLOW_FIELDS], `${caseId}: exactly the line's fields`);
    assert.ok(entry.recipients === 1 || entry.recipients === 2, `${caseId}: one or two recipients (${entry.recipients})`);
    assert.equal(typeof entry.document_digest_match, 'boolean', `${caseId}: the document_digest match is a boolean`);
    assert.deepEqual(Object.keys(entry.product_verification).sort(), ['approval_evidence', 'integrity', 'revision_coverage', 'trust'], `${caseId}: the product verification's four results`);
    assert.ok(entry.oracle !== null && typeof entry.oracle === 'object', `${caseId}: the oracle's result is recorded`);
    assert.deepEqual(Object.keys(entry.oracle), [...AGREEMENT_FIELDS], `${caseId}: the oracle's result on the agreement fields`);
    assert.match(entry.package_digest, /^[0-9a-f]{64}$/, `${caseId}: the package digest is 64 lowercase hex`);
  }
  const mix = CASES.map((caseId) => record[caseId].recipients);
  assert.ok(mix.includes(1) && mix.includes(2), `the ten flows mix one and two recipients (${mix.join(', ')})`);
  assertRecordClean(JSON.stringify(record, null, 2), 'flows.json');
});
