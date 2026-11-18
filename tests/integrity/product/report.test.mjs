// SPDX-License-Identifier: Apache-2.0
//
// VB-02 (P13): every report field stays within the contract limits. Reports are
// validated against the vendored contract's VerificationReport schema, read at
// test time, so a contract change is judged against the real schema. A report
// that cannot fill a field within the contract is refused, never emitted.
//
// Mutants killed here: a malformed or absent evidence digest emitted in the
// report; an overlong trust_anchor_ref, check id or detail code emitted;
// timestamp or revocation status invented; a report built without its schema
// tag or with an extra field.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import {
  buildVerificationReport,
  CHECK_IDS,
  DETAIL_CODES,
  REPORT_LIMITS,
  VERIFIER,
  verifyPdf,
} from '../../../src/verifier/index.ts';
import { testPki } from './helpers/cert-build.mjs';
import { sealSynthetic, sha256Hex } from './helpers/cms-build.mjs';
import { loadContractSchema, validate } from './helpers/schema.mjs';

const at = new Date();
const pki = testPki(at);
const { contract, schema } = loadContractSchema('VerificationReport');
const evidence = Buffer.alloc(32, 0x5a);

test('[VB-02] a report from a sealed artifact validates against the vendored VerificationReport schema', () => {
  for (const xref of ['table', 'stream-flate', 'hybrid']) {
    const { bytes } = sealSynthetic({ signer: pki.leaf, xref, variant: { evidence } });
    const outcome = verifyPdf(bytes, {
      anchors: [pki.ca.der],
      expectedArtifactDigest: sha256Hex(bytes),
      expectedApprovalEvidenceDigest: evidence.toString('hex'),
      validationTime: at,
    });
    const built = buildVerificationReport(outcome, { verifiedAt: at });
    assert.equal(built.ok, true, built.ok ? '' : `${built.code} ${built.field}`);
    assert.deepEqual(validate(schema, built.report, contract), [], xref);
    assert.equal(built.report.timestamp_status, 'absent');
    assert.equal(built.report.revocation_status, 'not-checked');
    assert.equal(built.report.seal_type, 'organization');
    assert.equal(built.report.approval_evidence_digest, evidence.toString('hex'));
    assert.equal(built.report.verified_at, at.toISOString());
    assert.equal(built.report.trust_anchor_ref, outcome.trust_anchor_ref);
  }
});

test('[VB-02] untrusted and invalid outcomes still produce in-contract reports when every field is known', () => {
  const self = sealSynthetic({ signer: pki.selfSigned, variant: { evidence } }).bytes;
  const untrusted = buildVerificationReport(verifyPdf(self, { anchors: [pki.ca.der], validationTime: at }), { verifiedAt: at });
  assert.equal(untrusted.ok, true);
  assert.equal(untrusted.report.trust, 'untrusted');
  assert.equal(untrusted.report.trust_anchor_ref, null);
  assert.deepEqual(validate(schema, untrusted.report, contract), []);
  const sealed = sealSynthetic({ signer: pki.leaf, variant: { evidence } });
  const tampered = Buffer.from(sealed.bytes);
  tampered[tampered.length - 3] ^= 0x01;
  const invalid = buildVerificationReport(verifyPdf(tampered, { anchors: [pki.ca.der], validationTime: at }), { verifiedAt: at });
  assert.equal(invalid.ok, true);
  assert.equal(invalid.report.integrity, 'invalid');
  assert.deepEqual(validate(schema, invalid.report, contract), []);
});

test('[VB-02] a field the contract requires but the input cannot supply refuses the report; nothing out of contract is emitted', () => {
  const noEvidence = sealSynthetic({ signer: pki.leaf }).bytes;
  const refusedAbsent = buildVerificationReport(verifyPdf(noEvidence, { anchors: [pki.ca.der], validationTime: at }), { verifiedAt: at });
  assert.deepEqual(refusedAbsent, { ok: false, code: 'report-field-unavailable', field: 'approval_evidence_digest' });
  const short = sealSynthetic({ signer: pki.leaf, variant: { evidence: Buffer.alloc(31, 1) } }).bytes;
  const malformedOutcome = verifyPdf(short, { anchors: [pki.ca.der], expectedApprovalEvidenceDigest: evidence.toString('hex'), validationTime: at });
  assert.equal(malformedOutcome.approval_evidence, 'malformed');
  assert.equal(buildVerificationReport(malformedOutcome, { verifiedAt: at }).ok, false);
  const good = verifyPdf(sealSynthetic({ signer: pki.leaf, variant: { evidence } }).bytes, { anchors: [pki.ca.der], validationTime: at });
  const longRef = { ...good, trust_anchor_ref: 'x'.repeat(REPORT_LIMITS.trustAnchorRef + 1) };
  assert.deepEqual(buildVerificationReport(longRef, { verifiedAt: at }), { ok: false, code: 'report-limit', field: 'trust_anchor_ref' });
  const longDetail = { ...good, checks: [{ id: 'byte-range', result: 'fail', detail: 'd'.repeat(REPORT_LIMITS.detailCode + 1) }] };
  assert.equal(buildVerificationReport(longDetail, { verifiedAt: at }).ok, false);
  assert.equal(buildVerificationReport(good, { verifiedAt: new Date(Number.NaN) }).ok, false);
  const noCms = verifyPdf(Buffer.from('%PDF-1.7\n%%EOF\n', 'latin1'), { validationTime: at });
  assert.deepEqual(buildVerificationReport(noCms, { verifiedAt: at }), { ok: false, code: 'report-field-unavailable', field: 'signer_certificate_sha256' });
});

test('[VB-02] every check id and detail code, and the verifier label, fit the contract limits', () => {
  for (const id of CHECK_IDS) assert.ok(id.length <= REPORT_LIMITS.checkId, id);
  for (const code of DETAIL_CODES) assert.ok(code.length <= REPORT_LIMITS.detailCode, code);
  assert.ok(VERIFIER.name.length <= REPORT_LIMITS.verifierName);
  assert.ok(VERIFIER.version.length <= REPORT_LIMITS.verifierVersion);
  const checks = schema.properties.checks.items.properties;
  assert.equal(checks.id.maxLength, REPORT_LIMITS.checkId, 'the limits mirror the vendored contract');
  assert.equal(checks.detail_code.maxLength, REPORT_LIMITS.detailCode);
  assert.equal(schema.properties.trust_anchor_ref.oneOf[0].maxLength, REPORT_LIMITS.trustAnchorRef);
  assert.equal(schema.properties.verifier.properties.name.maxLength, REPORT_LIMITS.verifierName);
  assert.equal(schema.properties.verifier.properties.version.maxLength, REPORT_LIMITS.verifierVersion);
});
