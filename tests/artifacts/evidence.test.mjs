// SPDX-License-Identifier: Apache-2.0
//
// T016: PK-06, the approval-evidence binding (A-008 S1). Recipient identities or consent
// wording are replaced in approval-manifest.json and package-index.json is recomputed. The
// package is then internally consistent, but the shipped verifier must report the evidence
// mismatch, because the seal commits the original manifest's digest.
//
// Bound to landed interfaces only, with no capability, child process or key file, under
// request #74 (Q2): the seal carries the approval-evidence attribute, the verdict comes from
// verifyPdf (never a stub), and nothing is imported from the oracle paths or from the
// product-seal and oracle helpers (checked below over the import closure):
// - the seal: T014's test-local sealed-PDF builder (tests/integrity/product/helpers/
//   cms-build.mjs sealSynthetic), whose CMS carries the approval-evidence attribute, signed
//   by a synthetic self-signed RSA-3072 certificate made in memory (cert-build.mjs). Like a
//   development certificate, it is untrusted against no anchors;
// - the verdict: T014's verifyPdf() and buildVerificationReport() (src/verifier/index.ts),
//   given the manifest digest the caller supplies (VB-03).
// The report's bytes stand in for T038's verification_reports.report_bytes: their jcs.mjs
// form, which T016 packages unchanged. Every digest here uses the test-local serializer
// (support/jcs.mjs).

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { after, before, test } from 'node:test';

import { buildPackage, PackageError } from '../../src/artifacts/package.ts';
import { writeZip } from '../../src/artifacts/zip.ts';
import { buildVerificationReport, verifyPdf } from '../../src/verifier/index.ts';
import { buildCertificate, rsaKeyPair } from '../integrity/product/helpers/cert-build.mjs';
import { sealSynthetic } from '../integrity/product/helpers/cms-build.mjs';
import { readZip } from '../zip/reader.mjs';
import { jcs, jcsBytes, jcsDigest, sha256Hex } from './support/jcs.mjs';
import { chainWorld, packageInput, syntheticPdf } from './support/inputs.mjs';

const AT = new Date(Date.UTC(2026, 10, 18, 9, 30, 0));
const DAY = 86_400_000;

let chain;
let signer;
before(() => {
  chain = chainWorld();
  signer = buildCertificate({
    commonName: 'T016 Development Seal (seal.example.test)',
    keyPair: rsaKeyPair(3072),
    serial: 0x1601,
    notBefore: new Date(AT.getTime() - DAY),
    notAfter: new Date(AT.getTime() + 30 * DAY),
  });
});
after(() => chain?.close());

const checkOf = (report, id) => report.checks.find((check) => check.id === id);

const HELPERS = new URL('../integrity/product/helpers/', import.meta.url);
const FORBIDDEN_MODULE = /\/oracle\/|\/helpers\/(?:oracle|product-seal)\.mjs$/;

/** The `from '...'` specifiers of one module's import and export statements. */
function specifiersOf(url) {
  return [...readFileSync(url, 'utf8').matchAll(/^\s*(?:import|export)\b[^'"]*?\bfrom\s+'([^']+)'/gm)].map((match) => match[1]);
}

/**
 * Request #74 (Q2): the sealer's import closure. Every module reached from cms-build.mjs and
 * cert-build.mjs imports only node: built-ins and modules beside it in helpers/, none of them
 * the oracle or product-seal helper; and this file imports neither. Returns the offenders.
 */
function sealerImportOffences() {
  const offences = [];
  const seen = new Set();
  const visit = (url) => {
    if (seen.has(url.href)) return;
    seen.add(url.href);
    for (const specifier of specifiersOf(url)) {
      if (specifier.startsWith('node:')) continue;
      const target = new URL(specifier, url);
      if (!specifier.startsWith('./') || !target.href.startsWith(HELPERS.href) || FORBIDDEN_MODULE.test(target.pathname)) {
        offences.push(`${url.pathname.split('/').pop()} -> ${specifier}`);
        continue;
      }
      visit(target);
    }
  };
  for (const name of ['cms-build.mjs', 'cert-build.mjs']) visit(new URL(name, HELPERS));
  for (const specifier of specifiersOf(new URL(import.meta.url))) {
    if (FORBIDDEN_MODULE.test(new URL(specifier, import.meta.url).pathname)) offences.push(`evidence.test.mjs -> ${specifier}`);
  }
  return { offences, modules: seen.size };
}

/** The evidence digest: the RFC 8785 SHA-256 of the manifest without final_pdf_digest, which the package adds. */
function preSealDigest(manifest) {
  const { final_pdf_digest: _excluded, ...preSeal } = manifest;
  return jcsDigest(preSeal);
}

// Request #70 (6): the runner keeps only an assertion's message, so each comparison puts
// its non-secret values (states, digests, codes) in the message.
function same(actual, expected, what) {
  assert.equal(actual, expected, `${what}: ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

/** `build` throws a PackageError with `code`; the message names the code it got. */
function refusedWith(build, code, what) {
  let caught;
  try {
    build();
  } catch (error) {
    caught = error;
  }
  const got = caught instanceof PackageError ? caught.code : caught === undefined ? 'no refusal' : caught.name;
  assert.ok(caught instanceof PackageError && caught.code === code, `${what}: ${got}, expected ${code}`);
}

/** T014's outcome and contract report for `pdf`, against the manifest digest the caller supplies. */
function verify(pdf, evidenceDigest) {
  const outcome = verifyPdf(pdf, { anchors: [], expectedArtifactDigest: sha256Hex(pdf), expectedApprovalEvidenceDigest: evidenceDigest, validationTime: AT });
  const built = buildVerificationReport(outcome, { verifiedAt: AT });
  assert.equal(built.ok, true, `T014 builds an in-contract report: ${built.ok ? 'ok' : `${built.code} ${built.field}`}`);
  return { outcome, report: built.report };
}

/** Replace approval-manifest.json, recompute package-index.json, re-zip: a consistent forgery. */
function forged(zip, edit) {
  const members = new Map(readZip(zip).entries.map((entry) => [entry.name, Buffer.from(entry.data)]));
  const manifest = JSON.parse(members.get('approval-manifest.json').toString('utf8'));
  edit(manifest);
  members.set('approval-manifest.json', jcsBytes(manifest));
  const index = JSON.parse(members.get('package-index.json').toString('utf8'));
  for (const file of index.files) {
    file.sha256 = sha256Hex(members.get(file.path));
    file.bytes = members.get(file.path).length;
  }
  members.set('package-index.json', jcsBytes(index));
  return { zip: writeZip([...members].map(([name, data]) => ({ name, data }))), manifest, members };
}

test('[PK-06] replaced recipient identity or consent wording, with package-index.json recomputed, is reported as an evidence mismatch', () => {
  // Q2's third condition, by reading the import statements (no module is loaded here).
  const closure = sealerImportOffences();
  assert.deepEqual(closure.offences, [], `the sealer's import closure (${closure.modules} modules): offending imports ${JSON.stringify(closure.offences)}`);

  // The pre-seal manifest names the signer, so the seal commits its digest.
  const draft = packageInput(chain, { pdf: syntheticPdf('placeholder') });
  draft.approvalManifest.seal.signer_certificate_sha256 = sha256Hex(signer.der);
  const evidence = preSealDigest(draft.approvalManifest);
  const pdf = sealSynthetic({ signer, variant: { evidence: Buffer.from(evidence, 'hex') } }).bytes;

  // The control: the original manifest matches, and the verdict T016 requires holds.
  const control = verify(pdf, evidence);
  same(control.report.integrity, 'valid', 'control integrity');
  same(control.report.revision_coverage, 'complete', 'control revision_coverage');
  same(control.report.trust, 'untrusted', 'control trust (a development-style certificate)');
  same(control.outcome.approval_evidence, 'match', 'control evidence state');
  same(control.report.approval_evidence_digest, evidence, 'control: the seal commits the manifest digest');
  same(control.report.signer_certificate_sha256, sha256Hex(signer.der), 'control signer certificate');
  same(checkOf(control.report, 'approval-evidence-digest')?.result, 'pass', 'control approval-evidence-digest check');
  same(checkOf(control.report, 'artifact-digest')?.result, 'pass', 'control artifact-digest check');

  const verification = jcsBytes(control.report);
  const built = buildPackage({ ...draft, finalPdf: pdf, verification });
  const packaged = new Map(readZip(built.bytes).entries.map((entry) => [entry.name, Buffer.from(entry.data)]));
  same(sha256Hex(packaged.get('verification.json')), sha256Hex(verification), 'the report bytes, packaged unchanged (digest)');
  same(preSealDigest(JSON.parse(packaged.get('approval-manifest.json').toString('utf8'))), evidence, 'control: the packaged manifest still has the sealed digest');

  const variants = {
    'a replaced recipient email': (manifest) => {
      manifest.approvals[0].recipient.email = 'someone.else@example.test';
    },
    'a replaced recipient role': (manifest) => {
      manifest.approvals[0].recipient.role = 'another-role';
    },
    'replaced consent wording, its digests and the approval chain recomputed': (manifest) => {
      const text = `${manifest.consent_texts[0].text} Altered.`;
      const digest = sha256Hex(Buffer.from(text, 'utf8'));
      manifest.consent_texts[0] = { ...manifest.consent_texts[0], text, text_digest: digest };
      let prior = null;
      for (const approval of manifest.approvals) {
        approval.consent_text_digest = digest;
        approval.prior_approval_digest = prior;
        const { approval_digest: _old, ...body } = approval;
        approval.approval_digest = jcsDigest(body);
        prior = approval.approval_digest;
      }
    },
  };
  for (const [what, edit] of Object.entries(variants)) {
    const forgery = forged(built.bytes, edit);
    // A holder checking only the index finds nothing wrong.
    const index = JSON.parse(forgery.members.get('package-index.json').toString('utf8'));
    for (const file of index.files) same(file.sha256, sha256Hex(forgery.members.get(file.path)), `${what}: the recomputed index entry for ${file.path}`);
    same(sha256Hex(forgery.members.get('approval-manifest.json')), sha256Hex(Buffer.from(jcs(forgery.manifest), 'utf8')), `${what}: the forged manifest is in RFC 8785 form`);
    // The verifier, given the forged manifest's digest, reports the mismatch.
    const forgedDigest = preSealDigest(forgery.manifest);
    assert.notEqual(forgedDigest, evidence, `${what}: the forged manifest has another digest: ${forgedDigest} vs ${evidence}`);
    const verdict = verify(forgery.members.get('final.pdf'), forgedDigest);
    same(verdict.report.integrity, 'valid', `${what}: integrity (the PDF itself is untouched)`);
    same(verdict.outcome.approval_evidence, 'mismatch', `${what}: the evidence state`);
    same(verdict.report.approval_evidence_digest, evidence, `${what}: the sealed digest is the original's`);
    same(checkOf(verdict.report, 'approval-evidence-digest')?.result, 'fail', `${what}: the approval-evidence-digest check`);
    // And T016 itself never packages either half of the forgery (request #46 (7)).
    refusedWith(() => buildPackage({ ...draft, approvalManifest: forgery.manifest, finalPdf: pdf, verification }), 'cross-link', `${what}: the original report against the forged manifest`);
    refusedWith(
      () => buildPackage({ ...draft, approvalManifest: forgery.manifest, finalPdf: pdf, verification: jcsBytes({ ...verdict.report, approval_evidence_digest: forgedDigest }) }),
      'verdict',
      `${what}: a mismatch report`,
    );
  }
});
