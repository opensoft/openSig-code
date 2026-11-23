// SPDX-License-Identifier: Apache-2.0
//
// verifyPdf: the shipped product verifier's entry point (T014).
//
// Verdict mapping (it must agree with the T012 oracle on every corpus case and
// every product-sealed output; check lists and detail codes may differ):
// - integrity is `valid` only when the signature dictionary, ByteRange, CMS
//   extraction, CMS structure, signer binding, messageDigest and signature
//   checks all pass. Any failed check makes it `invalid`. It is
//   `indeterminate` only when no check failed but one could not be evaluated
//   (an input past the size bound, several signatures or signers, or an
//   algorithm or key outside the accepted set). That never occurs on a corpus
//   case. /Contents padding is not part of integrity (OC-04).
// - trust is `indeterminate` unless integrity is `valid`, and is otherwise
//   `trusted` or `untrusted` against the configured anchors only.
// - revision_coverage is structural: `complete` when the structure and
//   ByteRange checks pass and the signed revision is the last, `incomplete`
//   when it is not the last, `indeterminate` otherwise.
// - artifact_match compares SHA-256 of the exact bytes with the supplied
//   digest (null when none is supplied).
// - approval_evidence compares the signed opensig-approval-evidence-digest
//   attribute with the supplied digest (VB-03): not-requested, match,
//   mismatch, absent, malformed, or indeterminate when the signed attributes
//   could not be read.
// - accepted_as_original needs integrity `valid`, coverage `complete`,
//   artifact_match exactly true, and evidence `match` or `not-requested`. It
//   ignores trust.
// signingTime and a missing signingCertificateV2 are profile checks
// (`signing-time-present`, `signing-certificate-v2-absent`), and a time-stamp
// token gives timestamp_status `indeterminate`; none changes integrity, trust
// or coverage (VB-09). Product-sealed output shows none of them.
//
// The outcome is T014's internal result (request #44): a value the input lacks
// is null, and agreement with the oracle compares this result. The contract
// VerificationReport is built from it only when every required field is
// contract-valid (buildVerificationReport), and is refused otherwise.
//
// The verifier is pure: no clock, no file, no network, no process. The caller
// supplies the anchors (T038, from OPENSIG_TRUST_ANCHORS_FILE), the expected
// digests (the caller's recorded artifact digest and manifest digest) and the
// validation time.

import { createHash } from 'node:crypto';
import {
  BYTE_RANGE_DETAILS,
  checkByteRange,
  CMS_EXTRACTION_DETAILS,
  CONTENTS_PADDING_DETAILS,
  extractCms,
  isHexStringToken,
  locateSignature,
  SIGNATURE_DICTIONARY_DETAILS,
  statedRanges,
} from './byte-range.ts';
import { CMS_DETAILS, evaluateCms, type CmsEvaluation, type Step } from './cms.ts';
import { VerifierConfigError } from './errors.ts';
import { VERIFIER_LIMITS } from './limits.ts';
import { readRevisionStructure, STRUCTURE_DETAILS } from './structure.ts';
import { evaluateTrust, parseAnchors, TRUST_DETAILS, type TrustAnchor } from './trust.ts';

export const CHECK_IDS = [
  'input-size',
  'revision-structure',
  'signature-dictionary',
  'byte-range',
  'cms-extraction',
  'contents-padding',
  'cms-structure',
  'signer-binding',
  'message-digest',
  'signature-value',
  'trust-anchors',
  'revision-coverage',
  'artifact-digest',
  'approval-evidence-digest',
  'profile-signing-time',
  'profile-signing-certificate-v2',
] as const;

export type CheckId = (typeof CHECK_IDS)[number];

export const EVIDENCE_STATES = ['not-requested', 'match', 'mismatch', 'absent', 'malformed', 'indeterminate'] as const;
export type EvidenceState = (typeof EVIDENCE_STATES)[number];

/** Every detail code a check can carry (each at most 60 characters; VB-02). */
export const DETAIL_CODES: readonly string[] = Object.freeze([
  'input-too-large',
  ...STRUCTURE_DETAILS,
  ...SIGNATURE_DICTIONARY_DETAILS,
  ...BYTE_RANGE_DETAILS,
  ...CMS_EXTRACTION_DETAILS,
  ...CONTENTS_PADDING_DETAILS,
  ...CMS_DETAILS,
  ...TRUST_DETAILS,
  'not-last-revision',
  'coverage-indeterminate',
  'artifact-digest-mismatch',
  ...EVIDENCE_STATES,
  'signing-time-present',
  'signing-certificate-v2-absent',
]);

export interface VerifierCheck {
  readonly id: CheckId;
  readonly result: 'pass' | 'fail' | 'not-run';
  readonly detail: string | null;
}

export interface VerifyOptions {
  /** Trust anchors as DER bytes or PEM text. Omitted means none. null or anything malformed is refused. */
  readonly anchors?: readonly (Uint8Array | string)[];
  /** Lowercase SHA-256 hex of the recorded artifact, or null. */
  readonly expectedArtifactDigest?: string | null;
  /** Lowercase SHA-256 hex of the approval manifest digest committed in the seal, or null (not requested). */
  readonly expectedApprovalEvidenceDigest?: string | null;
  /** The time certificates are judged at. Required: the verifier reads no clock. */
  readonly validationTime: Date;
}

export interface VerificationOutcome {
  readonly artifact_digest: string;
  readonly integrity: 'valid' | 'invalid' | 'indeterminate';
  readonly trust: 'trusted' | 'untrusted' | 'indeterminate';
  readonly trust_anchor_ref: string | null;
  readonly revision_coverage: 'complete' | 'incomplete' | 'indeterminate';
  readonly artifact_match: boolean | null;
  readonly approval_evidence: EvidenceState;
  /** Lowercase hex of a well-formed 32-byte approval-evidence attribute, else null. */
  readonly approval_evidence_digest: string | null;
  readonly accepted_as_original: boolean;
  readonly signed_revision: number | null;
  readonly revision_count: number | null;
  readonly signer_certificate_sha256: string | null;
  readonly timestamp_status: 'absent' | 'indeterminate';
  readonly revocation_status: 'not-checked';
  readonly checks: readonly VerifierCheck[];
}

interface Config {
  readonly anchors: readonly TrustAnchor[];
  readonly expectedArtifactDigest: string | null;
  readonly expectedApprovalEvidenceDigest: string | null;
  readonly validationTime: Date;
}

const OPTION_KEYS = new Set(['anchors', 'expectedArtifactDigest', 'expectedApprovalEvidenceDigest', 'validationTime']);
const HEX64 = /^[0-9a-f]{64}$/;

function readConfig(options: unknown): Config {
  if (typeof options !== 'object' || options === null || Array.isArray(options)) throw new VerifierConfigError('options-invalid');
  for (const key of Object.keys(options)) if (!OPTION_KEYS.has(key)) throw new VerifierConfigError('options-invalid');
  const o = options as Record<string, unknown>;
  const anchors = parseAnchors(o['anchors']);
  const expectedArtifactDigest = digestOption(o['expectedArtifactDigest'], 'expected-artifact-digest-invalid');
  const expectedApprovalEvidenceDigest = digestOption(
    o['expectedApprovalEvidenceDigest'],
    'expected-approval-evidence-digest-invalid',
  );
  const validationTime = o['validationTime'];
  if (!(validationTime instanceof Date) || !Number.isFinite(validationTime.getTime())) {
    throw new VerifierConfigError('validation-time-invalid');
  }
  return { anchors, expectedArtifactDigest, expectedApprovalEvidenceDigest, validationTime };
}

function digestOption(
  value: unknown,
  code: 'expected-artifact-digest-invalid' | 'expected-approval-evidence-digest-invalid',
): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !HEX64.test(value)) throw new VerifierConfigError(code);
  return value;
}

class Checks {
  private readonly entries = new Map<CheckId, VerifierCheck>();

  constructor() {
    for (const id of CHECK_IDS) this.entries.set(id, { id, result: 'not-run', detail: null });
  }

  set(id: CheckId, result: 'pass' | 'fail' | 'not-run', detail: string | null = null): void {
    this.entries.set(id, Object.freeze({ id, result, detail }));
  }

  step(id: CheckId, step: Step, detail: string | null): void {
    if (step === 'pass') this.set(id, 'pass');
    else if (step === 'not-run') this.set(id, 'not-run');
    else this.set(id, 'fail', detail);
  }

  list(): readonly VerifierCheck[] {
    return Object.freeze(CHECK_IDS.map((id): VerifierCheck => this.entries.get(id) ?? { id, result: 'not-run', detail: null }));
  }
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Verify one PDF. Throws VerifierConfigError only for refused options; a bad input is a verdict. */
export function verifyPdf(input: Uint8Array, options: VerifyOptions): VerificationOutcome {
  const config = readConfig(options);
  if (!(input instanceof Uint8Array)) throw new VerifierConfigError('input-invalid');
  const artifactDigest = sha256Hex(input);
  const artifactMatch = config.expectedArtifactDigest === null ? null : artifactDigest === config.expectedArtifactDigest;
  const checks = new Checks();
  checks.set(
    'artifact-digest',
    artifactMatch === null ? 'not-run' : artifactMatch ? 'pass' : 'fail',
    artifactMatch === false ? 'artifact-digest-mismatch' : null,
  );

  if (input.length > VERIFIER_LIMITS.maxInputBytes) {
    checks.set('input-size', 'fail', 'input-too-large');
    const evidence: EvidenceState = config.expectedApprovalEvidenceDigest === null ? 'not-requested' : 'indeterminate';
    checks.set('approval-evidence-digest', evidence === 'not-requested' ? 'not-run' : 'fail', evidence === 'not-requested' ? null : evidence);
    const tooLarge: VerificationOutcome = {
      artifact_digest: artifactDigest,
      integrity: 'indeterminate',
      trust: 'indeterminate',
      trust_anchor_ref: null,
      revision_coverage: 'indeterminate',
      artifact_match: artifactMatch,
      approval_evidence: evidence,
      approval_evidence_digest: null,
      accepted_as_original: false,
      signed_revision: null,
      revision_count: null,
      signer_certificate_sha256: null,
      timestamp_status: 'absent',
      revocation_status: 'not-checked',
      checks: checks.list(),
    };
    return Object.freeze(tooLarge);
  }
  checks.set('input-size', 'pass');

  // Revision structure.
  const structure = readRevisionStructure(input);
  checks.set('revision-structure', structure.ok ? 'pass' : 'fail', structure.ok ? null : structure.detail);

  // Signature dictionary, ByteRange, CMS.
  const located = locateSignature(input, structure);
  let dictionaryStep: Step;
  let byteRangeStep: Step = 'not-run';
  let extractionStep: Step = 'not-run';
  let signedRevision: number | null = null;
  let cms: CmsEvaluation | null = null;
  if (located.state === 'pass') {
    dictionaryStep = 'pass';
    const range = checkByteRange(input, located.field, structure);
    byteRangeStep = range.result;
    signedRevision = range.signedRevision;
    checks.set('byte-range', range.result, range.detail);
    const [o1, l1, o2] = located.field.range;
    if (isHexStringToken(input, o1 + l1, o2)) {
      const extraction = extractCms(input, o1 + l1, o2);
      extractionStep = extraction.result;
      checks.set('cms-extraction', extraction.result, extraction.detail);
      checks.set('contents-padding', extraction.padding, extraction.padding === 'fail' ? 'nonzero-padding' : null);
      const ranges = statedRanges(input, located.field);
      if (extraction.der !== null && ranges !== null) {
        const digest = createHash('sha256').update(ranges[0]).update(ranges[1]).digest();
        cms = evaluateCms(extraction.der, digest);
      }
    }
  } else {
    dictionaryStep = located.state === 'unsupported' ? 'unsupported' : 'fail';
  }
  checks.step('signature-dictionary', dictionaryStep, located.state === 'pass' ? null : located.detail);
  if (cms !== null) {
    checks.step('cms-structure', cms.structure, cms.structureDetail);
    checks.step('signer-binding', cms.binding, cms.bindingDetail);
    checks.step('message-digest', cms.messageDigest, 'message-digest-mismatch');
    checks.step('signature-value', cms.signature, cms.signatureDetail);
    if (cms.signingTimePresent !== null) {
      checks.set('profile-signing-time', cms.signingTimePresent ? 'fail' : 'pass', cms.signingTimePresent ? 'signing-time-present' : null);
    }
    if (cms.signingCertificateV2Present !== null) {
      checks.set(
        'profile-signing-certificate-v2',
        cms.signingCertificateV2Present ? 'pass' : 'fail',
        cms.signingCertificateV2Present ? null : 'signing-certificate-v2-absent',
      );
    }
  }

  // Integrity.
  const steps: Step[] = [
    dictionaryStep,
    byteRangeStep,
    extractionStep,
    cms?.structure ?? 'not-run',
    cms?.binding ?? 'not-run',
    cms?.messageDigest ?? 'not-run',
    cms?.signature ?? 'not-run',
  ];
  const integrity: VerificationOutcome['integrity'] = steps.includes('fail')
    ? 'invalid'
    : steps.every((s) => s === 'pass')
      ? 'valid'
      : 'indeterminate';

  // Trust.
  let trust: VerificationOutcome['trust'] = 'indeterminate';
  let trustAnchorRef: string | null = null;
  if (integrity === 'valid' && cms !== null && cms.signer !== null) {
    const judged = evaluateTrust(cms.signer, cms.certificates, config.anchors, config.validationTime);
    trust = judged.trusted ? 'trusted' : 'untrusted';
    trustAnchorRef = judged.anchorRef;
    checks.set('trust-anchors', judged.trusted ? 'pass' : 'fail', judged.detail);
  }

  // Coverage.
  let coverage: VerificationOutcome['revision_coverage'] = 'indeterminate';
  if (structure.ok && byteRangeStep === 'pass' && signedRevision !== null) {
    coverage = signedRevision === structure.revisions.length - 1 ? 'complete' : 'incomplete';
  }
  checks.set(
    'revision-coverage',
    coverage === 'complete' ? 'pass' : 'fail',
    coverage === 'complete' ? null : coverage === 'incomplete' ? 'not-last-revision' : 'coverage-indeterminate',
  );

  // Approval evidence (VB-03).
  const attribute = cms?.evidence ?? null;
  let evidence: EvidenceState;
  if (config.expectedApprovalEvidenceDigest === null) evidence = 'not-requested';
  else if (attribute === null) evidence = 'indeterminate';
  else if (attribute.state === 'absent') evidence = 'absent';
  else if (attribute.state === 'malformed') evidence = 'malformed';
  else evidence = attribute.hex === config.expectedApprovalEvidenceDigest ? 'match' : 'mismatch';
  checks.set(
    'approval-evidence-digest',
    evidence === 'not-requested' ? 'not-run' : evidence === 'match' ? 'pass' : 'fail',
    evidence === 'not-requested' || evidence === 'match' ? null : evidence,
  );
  // A value the input lacks is null (request #44): only a well-formed 32-byte attribute has a digest.
  const evidenceHex = attribute !== null && attribute.state === 'present' ? attribute.hex : null;

  const accepted =
    integrity === 'valid' &&
    coverage === 'complete' &&
    artifactMatch === true &&
    (evidence === 'match' || evidence === 'not-requested');

  const outcome: VerificationOutcome = {
    artifact_digest: artifactDigest,
    integrity,
    trust,
    trust_anchor_ref: trustAnchorRef,
    revision_coverage: coverage,
    artifact_match: artifactMatch,
    approval_evidence: evidence,
    approval_evidence_digest: evidenceHex,
    accepted_as_original: accepted,
    signed_revision: structure.ok ? signedRevision : null,
    revision_count: structure.ok ? structure.revisions.length : null,
    signer_certificate_sha256: cms?.signerDer ? sha256Hex(cms.signerDer) : null,
    timestamp_status: cms?.timestampTokenPresent ? 'indeterminate' : 'absent',
    revocation_status: 'not-checked',
    checks: checks.list(),
  };
  return Object.freeze(outcome);
}
