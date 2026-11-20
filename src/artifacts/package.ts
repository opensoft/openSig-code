// SPDX-License-Identifier: Apache-2.0
//
// The evidence package builder (T016; tasks.md T016 line, A-008 S1, A-010 S4 and requests
// #44, #46, #50 and #59; contract downloadPackage, PackageIndex, ApprovalManifest,
// AuditReceipt, AuditEventRecord (0.2.1) and VerificationReport). T038 calls it at package
// assembly: after verification and evidence storage, and after it writes the completion
// checkpoint (data-model.md § Transitions and races, item 2).
//
// buildPackage(input) is pure and deterministic. It reads no clock, no randomness, no file
// and no database, and equal inputs give equal bytes (PK-07). It returns a ZIP of exactly
// five members, written by T039's writeZip with the five fixed names and the package's
// own limits, including an inclusive entry limit of 5:
//   final.pdf               the sealed PDF bytes, unchanged;
//   approval-manifest.json  T038's pre-seal manifest unchanged, plus final_pdf_digest
//                           (A-008 S1: the only member the evidence digest excludes);
//   audit-receipt.json      every supplied event up to the supplied chain head, each as its
//                           full digest preimage from T029's digestInput() plus the stored
//                           event_digest, with that chain head and the completion
//                           checkpoint;
//   verification.json       the exact report_bytes of the envelope's one
//                           verification_reports row, which T038 serializes once at
//                           publish (requests #59 (9) and #74). They are never serialized
//                           again here and are not claimed to be RFC 8785. readVerification
//                           serves the same bytes, and its ETag equals this member's index
//                           digest (request #46 (4));
//   package-index.json      the SHA-256 and byte length of the other four members.
// The members the builder writes (approval-manifest.json, audit-receipt.json and
// package-index.json) are the RFC 8785 form of their objects (src/domain/canonical/), in
// UTF-8 with no trailing newline. package-index.json lists `files` in this module's own
// order (INDEX_ORDER). The ZIP orders entries by name bytes (T039), and the two orders need
// not match.
//
// Cross-links. Each is checked before any byte is written, and a mismatch is a
// PackageError:
// - final.pdf: sha256(final.pdf) is the artifact digest. It equals the report's
//   artifact_digest and the manifest's final_pdf_digest (added here, or checked when
//   supplied).
// - The evidence digest: the RFC 8785 SHA-256 of the manifest without final_pdf_digest
//   equals the report's approval_evidence_digest, the value of the signed CMS attribute.
// - The signer: the report's signer_certificate_sha256 equals the manifest's seal.
// - Inside the manifest: manifest_digest is the digest of field_manifest; the envelope and
//   document identifiers agree; approvals run in ordinal order, each bound to the document,
//   the field manifest and the prior approval; and each consent text matches its digest and
//   is the one an approval names.
// - The receipt: every event is of this tenant and this envelope, and its stored digest
//   equals the recomputed digest of its preimage. Events are taken in seq order, and only
//   those with seq at or below the chain head are kept. Consecutive seq values link by
//   prev_digest. The checkpoint is the chain head. The manifest's seal_audit_anchor is one
//   of the receipt's events.
// - The verdict, an invariant (request #46 (7)): integrity `valid`, revision_coverage
//   `complete`, the check approval-evidence-digest `pass` (T014's evidence state `match`),
//   and the check artifact-digest `pass` with the report's artifact_digest equal to
//   final.pdf's. Trust is not required, because a development certificate is `untrusted`.
//   The report's checks are T014's fixed list: each id one of CHECK_IDS, at most once.
//
// No capability value or key. Each JSON member is built only from contract-shaped inputs,
// and every object the builder checks has a closed set of members, so no member can carry
// a token or a code. Audit metadata is redacted when T029 writes it. As a last defence, a
// string carrying PEM armour in any JSON member is refused.
//
// The size bound (row SIZE-BOUND, request #44). The package is stored as one T028 blob of at
// most MAX_PACKAGE_BYTES (64 MiB). final.pdf is at most MAX_SEALED_PDF_BYTES (T036, 48 MiB).
// The other four members and the ZIP framing share the remaining 16 MiB under the budgets
// below. Each budget is enforced here as an invariant: a member over its budget is refused,
// never truncated. What keeps each member within its budget upstream:
// - approval-manifest.json (MAX_MANIFEST_BYTES, 1 MiB). At most 2 approvals, each holding
//   at most 20 field values within the contract 0.2.3 point budget (at most 256 KiB of
//   compact JSON). At most 2 consent texts (one per approval, checked here) of at most
//   20,000 characters, taken at the worst case of 6 bytes per character. A field manifest
//   of at most 20 fields, at most 50 pages, and bounded source, recipient and seal members.
//   The worst case is about 790,000 bytes.
// - verification.json (MAX_VERIFICATION_BYTES, 1 MiB): the stored report bytes, in whatever
//   form T038 serializes them once at publish (request #74). The budget is the bound of
//   verification_reports.report_bytes (migration 0005), so any bytes the row can hold are
//   packaged. T014's report has a contract bound on every member except `checks`; its
//   `checks` are T014's fixed CHECK_IDS (16 entries), each within REPORT_LIMITS (request
//   #46 (8): no contract maxItems). That is about 14,000 bytes in RFC 8785 form at the
//   worst case.
// - package-index.json (MAX_INDEX_BYTES, 4 KiB). Four fixed entries, under 700 bytes.
// - The ZIP framing: exactly ZIP_OVERHEAD_BYTES (570) for the five fixed names.
// - audit-receipt.json: the remainder, MAX_RECEIPT_BYTES. One record is at most
//   MAX_EVENT_RECORD_BYTES, from T029's write-time limits, so RECEIPT_EVENT_CAPACITY
//   (2,754) events always fit. Row EVENT-CAP bounds the events (requests #46 and #50).
//   T008's ENVELOPE_REPEATABLE_EVENT_CEILING (2,052) covers the repeatable actions and the
//   session ends after the cap. The sources that are never refused and are bounded per
//   envelope add at most 309: the send's invitation (1), the approvals (2) and recipient 2's
//   follow-up invitation (1), one terminal transition with a reissue (3), and finalization
//   at most 100 attempts × 3 events plus the anchor and envelope.completed (302; request
//   #59 (9)). The total is 2,361. PK-01 asserts the sum from its owners' exports. The claim
//   covers rows the fixed T008 code writes. An envelope whose rows predate it is not
//   claimed to fit, and its package is refused here (member-too-large).

import { createHash } from 'node:crypto';

import { MAX_SEALED_PDF_BYTES } from '../cryptograph/compose/bounds.ts';
import { CanonicalJsonError, canonicalDigest, canonicalize, parseJson, type JsonValue } from '../domain/canonical/index.ts';
import { digestInput, type AuditEvent } from '../storage/audit/event.ts';
import { CHECK_IDS, REPORT_LIMITS, REPORT_SCHEMA } from '../verifier/index.ts';
import { writeZip, type ZipLimits } from './zip.ts';

export type JsonRecord = { [key: string]: JsonValue };

/** The five fixed member names. */
export const PACKAGE_FILES = Object.freeze({
  finalPdf: 'final.pdf',
  approvalManifest: 'approval-manifest.json',
  auditReceipt: 'audit-receipt.json',
  verification: 'verification.json',
  packageIndex: 'package-index.json',
} as const);

export type PackageFileName = (typeof PACKAGE_FILES)[keyof typeof PACKAGE_FILES];
export type IndexedFileName = Exclude<PackageFileName, 'package-index.json'>;

/** package-index.json's `files` order, which is this module's own (request #43, Q3). */
export const INDEX_ORDER: readonly IndexedFileName[] = Object.freeze([
  PACKAGE_FILES.finalPdf,
  PACKAGE_FILES.approvalManifest,
  PACKAGE_FILES.auditReceipt,
  PACKAGE_FILES.verification,
]);

/** The package's entry limit, an inclusive maximum (request #44). */
export const PACKAGE_ENTRY_LIMIT = 5;

/** T028's per-blob limit (DEFAULT_MAX_BLOB_BYTES, inclusive), restated; PK-01 compares them. */
export const MAX_PACKAGE_BYTES = 67_108_864;

/** What the package leaves for the other four members and the ZIP framing: 16 MiB. */
export const MAX_NON_PDF_BYTES = MAX_PACKAGE_BYTES - MAX_SEALED_PDF_BYTES;

/**
 * T039's framing for the five fixed names: for each entry, a 30-byte local header and a
 * 46-byte central header, each followed by the name, plus one 22-byte end record. T039
 * writes no extra field, comment or data descriptor. That gives 570 bytes, which PK-01
 * measures.
 */
export const ZIP_OVERHEAD_BYTES = 22 + Object.values(PACKAGE_FILES).reduce((sum, name) => sum + 30 + 46 + 2 * name.length, 0);

export const MAX_MANIFEST_BYTES = 1_048_576;
/** The bound of verification_reports.report_bytes (migration 0005; request #74); PK-01 compares them. */
export const MAX_VERIFICATION_BYTES = 1_048_576;
export const MAX_INDEX_BYTES = 4_096;
/** The remainder of the 16 MiB: 14,675,398 bytes. */
export const MAX_RECEIPT_BYTES = MAX_NON_PDF_BYTES - MAX_MANIFEST_BYTES - MAX_VERIFICATION_BYTES - MAX_INDEX_BYTES - ZIP_OVERHEAD_BYTES;

/** T029's write-time limit on canonical audit metadata (MAX_METADATA_BYTES), restated; PK-01 compares them. */
export const AUDIT_METADATA_BYTES = 4_096;

/**
 * The largest RFC 8785 AuditEventRecord, with its separating comma: 5,328 bytes. Fixed
 * members and punctuation take 632 bytes. That assumes 64-character identifiers and
 * digests, a 16-digit seq, the 24-character server time (the schema's fixed form), a
 * 61-character type and the longest actor kind. The actor ref takes at most 600 bytes: 100
 * UTF-16 units at 6 bytes each, a control character being escaped as \u00XX. The metadata
 * takes at most AUDIT_METADATA_BYTES.
 */
export const MAX_EVENT_RECORD_BYTES = 5_328;

/**
 * The receipt's own members around an empty `events` array: at most 370 bytes, with a
 * 16-digit checkpoint seq. N records add at most N × MAX_EVENT_RECORD_BYTES, less one comma.
 */
export const RECEIPT_FRAME_BYTES = 370;

/** Events that always fit MAX_RECEIPT_BYTES at the worst-case record size: 2,754. */
export const RECEIPT_EVENT_CAPACITY = Math.floor((MAX_RECEIPT_BYTES - RECEIPT_FRAME_BYTES + 1) / MAX_EVENT_RECORD_BYTES);

/** The most report checks: T014's fixed CHECK_IDS (16; request #46 (8)). */
export const MAX_REPORT_CHECKS = CHECK_IDS.length;

/** The report checks the verdict reads (T014 CHECK_IDS). */
const EVIDENCE_CHECK = 'approval-evidence-digest';
const ARTIFACT_CHECK = 'artifact-digest';

/** The limits passed to T039's writeZip; each only lowers T039's ceilings. */
export const PACKAGE_ZIP_LIMITS: ZipLimits = Object.freeze({
  entryCountLimit: PACKAGE_ENTRY_LIMIT,
  entryBytesLimit: MAX_SEALED_PDF_BYTES,
  archiveBytesLimit: MAX_PACKAGE_BYTES,
});

export type PackageErrorCode =
  | 'input-invalid'
  | 'pdf-invalid'
  | 'cross-link'
  | 'receipt-invalid'
  | 'capability-leak'
  | 'verdict'
  | 'member-too-large';

/** A refusal. Equal inputs fail the same way, so no refusal is retryable. Messages name members, never values. */
export class PackageError extends Error {
  readonly code: PackageErrorCode;
  readonly retryable: false = false;

  constructor(code: PackageErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'PackageError';
    this.code = code;
  }
}

/** One audit event as T038 reads it: the T029 event model of its row and the row's stored event_digest. */
export interface ReceiptEventInput {
  readonly event: AuditEvent;
  readonly eventDigest: string;
}

/** The chain head at package assembly (T029 AuditHead). */
export interface ChainHead {
  readonly seq: number;
  readonly digest: string;
}

/** The completion checkpoint written at package assembly (T029 CompletionCheckpoint). */
export interface Checkpoint {
  readonly seq: number;
  readonly digest: string;
  readonly created_at: string;
}

export interface PackageInput {
  readonly tenantId: string;
  readonly envelopeId: string;
  /** The FinalArtifact's artifact_id. */
  readonly artifactId: string;
  /** The sealed PDF's exact bytes. */
  readonly finalPdf: Uint8Array;
  /** T038's pre-seal ApprovalManifest; final_pdf_digest may be absent, and if present must equal the PDF's digest. */
  readonly approvalManifest: JsonRecord;
  /** The envelope's audit events, in any order; those after the chain head are left out. */
  readonly events: readonly ReceiptEventInput[];
  readonly chainHead: ChainHead;
  readonly checkpoint: Checkpoint;
  /**
   * The exact bytes of T014's contract VerificationReport of final.pdf, as T038 serializes
   * them once and stores them in verification_reports.report_bytes (requests #59 (9) and
   * #74). They are packaged unchanged and parsed only to check the verdict and the
   * cross-links.
   */
  readonly verification: Uint8Array;
}

export interface MemberDigest {
  readonly sha256: string;
  readonly bytes: number;
}

export interface BuiltPackage {
  /** The ZIP's exact bytes, at most MAX_PACKAGE_BYTES. */
  readonly bytes: Uint8Array;
  /** SHA-256 of the ZIP: FinalArtifact.package_digest and downloadPackage's ETag. */
  readonly packageDigest: string;
  /** SHA-256 of final.pdf: FinalArtifact.artifact_digest and downloadFinalPdf's ETag. */
  readonly artifactDigest: string;
  /** SHA-256 of the RFC 8785 manifest without final_pdf_digest. */
  readonly approvalEvidenceDigest: string;
  /** Every member's digest and length, package-index.json included. */
  readonly members: Readonly<Record<PackageFileName, MemberDigest>>;
  /** The number of events in the receipt. */
  readonly receiptEvents: number;
}

// --- checks ---------------------------------------------------------------------------------

const ID = /^[A-Za-z0-9_-]{16,64}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const EVENT_TYPE = /^[a-z][a-z0-9_.-]{1,60}$/;
const SERVER_TIME = /^[0-9]{4}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/;
const DATE_TIME = /^[0-9]{4}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-6][0-9](?:\.[0-9]{1,9})?(?:Z|[+-][0-2][0-9]:[0-5][0-9])$/;
const ACTOR_KINDS: ReadonlySet<string> = new Set(['human-operator', 'service', 'recipient', 'system']);
const PDF_HEADER = Buffer.from('%PDF-', 'latin1');
const PEM_ARMOUR = '-----BEGIN';

function fail(code: PackageErrorCode, detail: string): never {
  throw new PackageError(code, detail);
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function record(value: unknown, what: string): JsonRecord {
  if (!isRecord(value)) fail('input-invalid', `${what} is not an object`);
  return value;
}

function list(value: unknown, what: string, min: number, max: number): readonly JsonValue[] {
  if (!Array.isArray(value) || value.length < min || value.length > max) fail('input-invalid', `${what} must list ${min} to ${max} items`);
  return value as readonly JsonValue[];
}

/** The object has every required member and no member outside required and optional. */
function members(value: JsonRecord, what: string, required: readonly string[], optional: readonly string[] = []): void {
  for (const name of required) if (!Object.hasOwn(value, name)) fail('input-invalid', `${what}.${name} is missing`);
  for (const name of Object.keys(value)) {
    if (!required.includes(name) && !optional.includes(name)) fail('input-invalid', `${what} has a member outside its contract schema`);
  }
}

function digest(value: unknown, what: string): string {
  if (typeof value !== 'string' || !DIGEST.test(value)) fail('input-invalid', `${what} is not a lowercase hex SHA-256`);
  return value;
}

function nullableDigest(value: unknown, what: string): string | null {
  return value === null ? null : digest(value, what);
}

function identifier(value: unknown, what: string): string {
  if (typeof value !== 'string' || !ID.test(value)) fail('input-invalid', `${what} is not an opaque identifier`);
  return value;
}

function integer(value: unknown, what: string, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) fail('input-invalid', `${what} must be an integer from ${min} to ${max}`);
  return value;
}

/** A string of min to max characters, counted as code points, as JSON Schema counts them. */
function text(value: unknown, what: string, min: number, max: number): string {
  if (typeof value !== 'string') fail('input-invalid', `${what} must be a string`);
  const length = [...value].length;
  if (length < min || length > max) fail('input-invalid', `${what} must be a string of ${min} to ${max} characters`);
  return value;
}

function oneOf<T extends string>(value: unknown, what: string, allowed: readonly T[]): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) fail('input-invalid', `${what} is not one of its contract values`);
  return value as T;
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * The RFC 8785 digest of a value the caller supplied, through the canonical module; a value
 * with no canonical form is refused. (Named so that JCS-06's canonicalizer-shape check, which
 * flags a definition starting with "jcs", does not take it for a second canonicalizer.)
 */
function digestOfValue(value: JsonValue, what: string): string {
  try {
    return canonicalDigest(value);
  } catch (error) {
    if (error instanceof CanonicalJsonError) fail('input-invalid', `${what} has no RFC 8785 form`);
    throw error;
  }
}

/** A member's exact bytes: its RFC 8785 form in UTF-8, refused above its budget. */
function memberBytes(value: JsonValue, what: string, budget: number): Uint8Array {
  let form: string;
  try {
    form = canonicalize(value);
  } catch (error) {
    if (error instanceof CanonicalJsonError) fail('input-invalid', `${what} has no RFC 8785 form`);
    throw error;
  }
  const bytes = Buffer.from(form, 'utf8');
  if (bytes.byteLength > budget) fail('member-too-large', `${what} has ${bytes.byteLength} bytes, over its bound of ${budget}`);
  return bytes;
}

/** Refuse PEM armour anywhere in a member, names included. */
function refuseKeyMaterial(value: JsonValue, what: string): void {
  const pending: JsonValue[] = [value];
  while (pending.length > 0) {
    const item = pending.pop() as JsonValue;
    if (typeof item === 'string') {
      if (item.includes(PEM_ARMOUR)) fail('capability-leak', `${what} holds PEM armour`);
    } else if (Array.isArray(item)) {
      pending.push(...item);
    } else if (isRecord(item)) {
      for (const [name, member] of Object.entries(item)) {
        if (name.includes(PEM_ARMOUR)) fail('capability-leak', `${what} holds PEM armour`);
        pending.push(member);
      }
    }
  }
}

// --- members --------------------------------------------------------------------------------

const MANIFEST_REQUIRED = [
  'schema',
  'envelope_id',
  'envelope_version',
  'source',
  'document',
  'field_manifest',
  'manifest_digest',
  'consent_texts',
  'approvals',
  'approved_composition_digest',
  'seal',
  'seal_audit_anchor',
] as const;

const APPROVAL_REQUIRED = [
  'approval_id',
  'recipient',
  'assurance',
  'consent_version',
  'consent_text_digest',
  'document_digest',
  'manifest_digest',
  'prior_approval_digest',
  'field_values',
  'date_values',
  'field_values_digest',
  'server_time',
  'approval_digest',
] as const;

interface CheckedManifest {
  /** The manifest without final_pdf_digest: the object the seal's evidence digest covers. */
  readonly preSeal: JsonRecord;
  readonly signerCertificate: string;
  readonly sealAnchor: ChainHead;
}

function checkManifest(input: unknown, envelopeId: string, artifactDigest: string): CheckedManifest {
  const manifest = record(input, 'approval-manifest');
  members(manifest, 'approval-manifest', MANIFEST_REQUIRED, ['final_pdf_digest']);
  if (manifest['schema'] !== 'opensig.approval-manifest/1') fail('input-invalid', 'approval-manifest.schema is not opensig.approval-manifest/1');
  if (identifier(manifest['envelope_id'], 'approval-manifest.envelope_id') !== envelopeId) fail('cross-link', 'approval-manifest names another envelope');
  integer(manifest['envelope_version'], 'approval-manifest.envelope_version', 1);
  if (Object.hasOwn(manifest, 'final_pdf_digest') && digest(manifest['final_pdf_digest'], 'approval-manifest.final_pdf_digest') !== artifactDigest) {
    fail('cross-link', 'approval-manifest.final_pdf_digest is not the digest of final.pdf');
  }
  digest(manifest['approved_composition_digest'], 'approval-manifest.approved_composition_digest');

  const source = record(manifest['source'], 'approval-manifest.source');
  members(source, 'approval-manifest.source', ['app', 'record', 'version']);
  const fieldManifest = record(manifest['field_manifest'], 'approval-manifest.field_manifest');
  members(fieldManifest, 'approval-manifest.field_manifest', ['schema', 'envelope_id', 'document_digest', 'fields']);
  list(fieldManifest['fields'], 'approval-manifest.field_manifest.fields', 1, 20);
  const document = record(manifest['document'], 'approval-manifest.document');
  members(document, 'approval-manifest.document', ['digest', 'bytes', 'pages']);
  list(document['pages'], 'approval-manifest.document.pages', 1, 50);
  const documentDigest = digest(document['digest'], 'approval-manifest.document.digest');
  if (fieldManifest['envelope_id'] !== envelopeId) fail('cross-link', 'the field manifest names another envelope');
  if (fieldManifest['document_digest'] !== documentDigest) fail('cross-link', 'the field manifest binds another document');
  const manifestDigest = digest(manifest['manifest_digest'], 'approval-manifest.manifest_digest');
  if (digestOfValue(fieldManifest, 'approval-manifest.field_manifest') !== manifestDigest) fail('cross-link', 'manifest_digest is not the digest of the field manifest');

  // Consent texts: each matches its digest, versions are distinct, and each is the text an
  // approval names, so there are at most as many texts as approvals.
  const consent = new Map<string, string>();
  for (const [index, item] of list(manifest['consent_texts'], 'approval-manifest.consent_texts', 1, 2).entries()) {
    const entry = record(item, `approval-manifest.consent_texts[${index}]`);
    members(entry, `approval-manifest.consent_texts[${index}]`, ['version', 'text_digest', 'text']);
    const version = text(entry['version'], `approval-manifest.consent_texts[${index}].version`, 1, 40);
    const wording = text(entry['text'], `approval-manifest.consent_texts[${index}].text`, 1, 20_000);
    const textDigest = digest(entry['text_digest'], `approval-manifest.consent_texts[${index}].text_digest`);
    if (sha256(Buffer.from(wording, 'utf8')) !== textDigest) fail('cross-link', `consent text ${index} does not match its digest`);
    if (consent.has(version)) fail('input-invalid', 'two consent texts share a version');
    consent.set(version, textDigest);
  }

  // Approvals, in ordinal order, each bound to the document, the field manifest, the prior
  // approval and a consent text of this manifest.
  const named = new Set<string>();
  let prior: string | null = null;
  for (const [index, item] of list(manifest['approvals'], 'approval-manifest.approvals', 1, 2).entries()) {
    const what = `approval-manifest.approvals[${index}]`;
    const approval = record(item, what);
    members(approval, what, APPROVAL_REQUIRED);
    list(approval['field_values'], `${what}.field_values`, 1, 20);
    list(approval['date_values'], `${what}.date_values`, 0, 20);
    const recipient = record(approval['recipient'], `${what}.recipient`);
    members(recipient, `${what}.recipient`, ['id', 'ordinal', 'role', 'email']);
    members(record(approval['assurance'], `${what}.assurance`), `${what}.assurance`, ['method', 'level']);
    if (integer(recipient['ordinal'], `${what}.recipient.ordinal`, 1, 2) !== index + 1) fail('cross-link', `${what} is out of ordinal order`);
    if (digest(approval['document_digest'], `${what}.document_digest`) !== documentDigest) fail('cross-link', `${what} binds another document`);
    if (digest(approval['manifest_digest'], `${what}.manifest_digest`) !== manifestDigest) fail('cross-link', `${what} binds another field manifest`);
    if (nullableDigest(approval['prior_approval_digest'], `${what}.prior_approval_digest`) !== prior) fail('cross-link', `${what} does not chain to the prior approval`);
    const version = text(approval['consent_version'], `${what}.consent_version`, 1, 40);
    if (consent.get(version) !== digest(approval['consent_text_digest'], `${what}.consent_text_digest`)) fail('cross-link', `${what} names a consent text the manifest does not carry`);
    named.add(version);
    prior = digest(approval['approval_digest'], `${what}.approval_digest`);
  }
  if (named.size !== consent.size) fail('cross-link', 'a consent text is named by no approval');

  const seal = record(manifest['seal'], 'approval-manifest.seal');
  members(seal, 'approval-manifest.seal', ['type', 'signer_certificate_sha256', 'development_certificate']);
  if (seal['type'] !== 'organization') fail('input-invalid', 'approval-manifest.seal.type is not organization');
  if (typeof seal['development_certificate'] !== 'boolean') fail('input-invalid', 'approval-manifest.seal.development_certificate is not a boolean');
  const signerCertificate = digest(seal['signer_certificate_sha256'], 'approval-manifest.seal.signer_certificate_sha256');

  const anchor = record(manifest['seal_audit_anchor'], 'approval-manifest.seal_audit_anchor');
  members(anchor, 'approval-manifest.seal_audit_anchor', ['seq', 'event_digest']);
  const sealAnchor = { seq: integer(anchor['seq'], 'approval-manifest.seal_audit_anchor.seq', 1), digest: digest(anchor['event_digest'], 'approval-manifest.seal_audit_anchor.event_digest') };

  const preSeal: JsonRecord = {};
  for (const [name, member] of Object.entries(manifest)) if (name !== 'final_pdf_digest') preSeal[name] = member;
  return { preSeal, signerCertificate, sealAnchor };
}

const REPORT_REQUIRED = [
  'schema',
  'artifact_digest',
  'integrity',
  'trust',
  'trust_anchor_ref',
  'revision_coverage',
  'seal_type',
  'signer_certificate_sha256',
  'approval_evidence_digest',
  'timestamp_status',
  'revocation_status',
  'verifier',
  'verified_at',
  'checks',
] as const;

/**
 * Parse the report's exact bytes (T029's strict parser), check its contract shape with
 * T014's own limits, its cross-links and the verdict. Returns the parsed report, which is
 * used for checks only; the bytes are packaged unchanged.
 */
function checkReport(bytes: unknown, artifactDigest: string, evidenceDigest: string, signerCertificate: string): JsonRecord {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0) fail('input-invalid', 'verification is not a byte array');
  if (bytes.byteLength > MAX_VERIFICATION_BYTES) fail('member-too-large', `verification.json has ${bytes.byteLength} bytes, over its bound of ${MAX_VERIFICATION_BYTES}`);
  let parsed: JsonValue;
  try {
    // ignoreBOM keeps a leading BOM in the text, where the strict parser refuses it.
    parsed = parseJson(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    fail('input-invalid', 'verification is not one JSON value in UTF-8');
  }
  const report = record(parsed, 'verification');
  members(report, 'verification', REPORT_REQUIRED);
  if (report['schema'] !== REPORT_SCHEMA) fail('input-invalid', `verification.schema is not ${REPORT_SCHEMA}`);
  if (digest(report['artifact_digest'], 'verification.artifact_digest') !== artifactDigest) fail('cross-link', 'the report verifies another artifact');
  if (digest(report['approval_evidence_digest'], 'verification.approval_evidence_digest') !== evidenceDigest) fail('cross-link', 'the sealed evidence digest is not the digest of the approval manifest');
  if (digest(report['signer_certificate_sha256'], 'verification.signer_certificate_sha256') !== signerCertificate) fail('cross-link', 'the report names another signer certificate');
  const integrity = oneOf(report['integrity'], 'verification.integrity', ['valid', 'invalid', 'indeterminate']);
  oneOf(report['trust'], 'verification.trust', ['trusted', 'untrusted', 'indeterminate']);
  if (report['trust_anchor_ref'] !== null) text(report['trust_anchor_ref'], 'verification.trust_anchor_ref', 0, REPORT_LIMITS.trustAnchorRef);
  const coverage = oneOf(report['revision_coverage'], 'verification.revision_coverage', ['complete', 'incomplete', 'indeterminate']);
  if (report['seal_type'] !== 'organization') fail('input-invalid', 'verification.seal_type is not organization');
  oneOf(report['timestamp_status'], 'verification.timestamp_status', ['trusted', 'absent', 'invalid', 'indeterminate']);
  oneOf(report['revocation_status'], 'verification.revocation_status', ['good', 'revoked', 'unknown', 'not-checked']);
  const verifier = record(report['verifier'], 'verification.verifier');
  members(verifier, 'verification.verifier', ['name', 'version']);
  text(verifier['name'], 'verification.verifier.name', 0, REPORT_LIMITS.verifierName);
  text(verifier['version'], 'verification.verifier.version', 0, REPORT_LIMITS.verifierVersion);
  if (typeof report['verified_at'] !== 'string' || !DATE_TIME.test(report['verified_at'])) fail('input-invalid', 'verification.verified_at is not a date-time');
  const results = new Map<string, string>();
  for (const [index, item] of list(report['checks'], 'verification.checks', 0, MAX_REPORT_CHECKS).entries()) {
    const check = record(item, `verification.checks[${index}]`);
    members(check, `verification.checks[${index}]`, ['id', 'result'], ['detail_code']);
    const id = oneOf(check['id'], `verification.checks[${index}].id`, CHECK_IDS);
    if (results.has(id)) fail('input-invalid', `verification.checks[${index}] repeats a check`);
    results.set(id, oneOf(check['result'], `verification.checks[${index}].result`, ['pass', 'fail', 'not-run']));
    if (Object.hasOwn(check, 'detail_code')) text(check['detail_code'], `verification.checks[${index}].detail_code`, 0, REPORT_LIMITS.detailCode);
  }
  // The verdict, an invariant (request #46 (7)); trust is not required.
  if (integrity !== 'valid') fail('verdict', 'the report\'s integrity is not valid');
  if (coverage !== 'complete') fail('verdict', 'the report\'s revision coverage is not complete');
  if (results.get(EVIDENCE_CHECK) !== 'pass') fail('verdict', 'the report\'s approval-evidence check is not a match');
  if (results.get(ARTIFACT_CHECK) !== 'pass') fail('verdict', 'the report\'s artifact-digest check did not pass');
  return report;
}

/** One receipt record: the event's full digest preimage (T029 digestInput) plus its stored digest. */
function receiptRecord(input: ReceiptEventInput, index: number, tenantId: string, envelopeId: string): JsonRecord {
  const what = `events[${index}]`;
  if (typeof input !== 'object' || input === null || typeof input.event !== 'object' || input.event === null) fail('receipt-invalid', `${what} is not an audit event`);
  if (typeof input.event.actor !== 'object' || input.event.actor === null) fail('receipt-invalid', `${what}.actor is not an object`);
  const stored = digest(input.eventDigest, `${what}.event_digest`);
  const preimage = digestInput(input.event);
  if (preimage['schema'] !== 'opensig.audit-event/1') fail('receipt-invalid', `${what} has another event schema`);
  if (preimage['tenant_id'] !== tenantId) fail('receipt-invalid', `${what} belongs to another tenant`);
  if (preimage['envelope_id'] !== envelopeId) fail('receipt-invalid', `${what} belongs to another envelope`);
  integer(preimage['seq'], `${what}.seq`, 1);
  if (typeof preimage['type'] !== 'string' || !EVENT_TYPE.test(preimage['type'])) fail('receipt-invalid', `${what}.type is malformed`);
  const actor = record(preimage['actor'], `${what}.actor`);
  if (typeof actor['kind'] !== 'string' || !ACTOR_KINDS.has(actor['kind'])) fail('receipt-invalid', `${what}.actor.kind is unknown`);
  text(actor['ref'], `${what}.actor.ref`, 1, 100);
  if (typeof preimage['server_time'] !== 'string' || !SERVER_TIME.test(preimage['server_time'])) fail('receipt-invalid', `${what}.server_time is malformed`);
  nullableDigest(preimage['subject_digest'], `${what}.subject_digest`);
  nullableDigest(preimage['prev_digest'], `${what}.prev_digest`);
  record(preimage['metadata'], `${what}.metadata`);
  if (digestOfValue(preimage, what) !== stored) fail('receipt-invalid', `${what}: the stored event_digest does not match its preimage`);
  return { ...preimage, event_digest: stored };
}

function buildReceipt(input: PackageInput, sealAnchor: ChainHead): { readonly receipt: JsonRecord; readonly events: number } {
  const head = { seq: integer(input.chainHead?.seq, 'chainHead.seq', 1), digest: digest(input.chainHead?.digest, 'chainHead.digest') };
  const checkpoint = record(input.checkpoint, 'checkpoint');
  members(checkpoint, 'checkpoint', ['seq', 'digest', 'created_at']);
  if (integer(checkpoint['seq'], 'checkpoint.seq', 1) !== head.seq || digest(checkpoint['digest'], 'checkpoint.digest') !== head.digest) {
    fail('cross-link', 'the completion checkpoint is not the chain head');
  }
  if (typeof checkpoint['created_at'] !== 'string' || !SERVER_TIME.test(checkpoint['created_at'])) fail('input-invalid', 'checkpoint.created_at is malformed');
  if (!Array.isArray(input.events)) fail('receipt-invalid', 'events must be an array');

  const records: JsonRecord[] = [];
  for (const [index, event] of input.events.entries()) {
    const entry = receiptRecord(event, index, input.tenantId, input.envelopeId);
    // Only events up to the chain head belong in the receipt (A-010, S4).
    if ((entry['seq'] as number) <= head.seq) records.push(entry);
  }
  records.sort((left, right) => (left['seq'] as number) - (right['seq'] as number));
  if (records.length === 0) fail('receipt-invalid', 'no event of the envelope precedes the chain head');
  for (let index = 0; index < records.length; index += 1) {
    const current = records[index] as JsonRecord;
    const seq = current['seq'] as number;
    if ((seq === 1) !== (current['prev_digest'] === null)) fail('receipt-invalid', 'only seq 1 of the tenant chain has no prev_digest');
    if (index === 0) continue;
    const previous = records[index - 1] as JsonRecord;
    if (previous['seq'] === seq) fail('receipt-invalid', 'two events share a seq');
    if ((previous['seq'] as number) + 1 === seq && current['prev_digest'] !== previous['event_digest']) fail('receipt-invalid', 'consecutive events do not link');
  }
  const last = records[records.length - 1] as JsonRecord;
  if (last['seq'] === head.seq && last['event_digest'] !== head.digest) fail('cross-link', 'the event at the chain head has another digest');
  if (!records.some((entry) => entry['seq'] === sealAnchor.seq && entry['event_digest'] === sealAnchor.digest)) {
    fail('cross-link', 'the seal audit anchor is not an event of the receipt');
  }
  return {
    receipt: {
      schema: 'opensig.audit-receipt/1',
      envelope_id: input.envelopeId,
      events: records,
      chain_head_digest: head.digest,
      checkpoint: { seq: head.seq, digest: head.digest, created_at: checkpoint['created_at'] },
    },
    events: records.length,
  };
}

// --- the builder ----------------------------------------------------------------------------

/**
 * Build the evidence package. Throws a PackageError for an input outside its contract shape,
 * a cross-link mismatch, a receipt that does not recompute, PEM armour in a member, or a
 * member over its bound. It never changes its inputs, and the result shares no memory with
 * them.
 */
export function buildPackage(input: PackageInput): BuiltPackage {
  if (typeof input !== 'object' || input === null) fail('input-invalid', 'the package input is required');
  const tenantId = identifier(input.tenantId, 'tenantId');
  const envelopeId = identifier(input.envelopeId, 'envelopeId');
  const artifactId = identifier(input.artifactId, 'artifactId');

  const pdf = input.finalPdf;
  if (!(pdf instanceof Uint8Array) || pdf.byteLength === 0) fail('pdf-invalid', 'final.pdf is empty');
  if (pdf.byteLength > MAX_SEALED_PDF_BYTES) fail('pdf-invalid', `final.pdf has ${pdf.byteLength} bytes, over MAX_SEALED_PDF_BYTES`);
  if (!PDF_HEADER.equals(pdf.subarray(0, PDF_HEADER.length))) fail('pdf-invalid', 'final.pdf does not start with a PDF header');
  const artifactDigest = sha256(pdf);

  const manifest = checkManifest(input.approvalManifest, envelopeId, artifactDigest);
  const approvalEvidenceDigest = digestOfValue(manifest.preSeal, 'approval-manifest');
  const report = checkReport(input.verification, artifactDigest, approvalEvidenceDigest, manifest.signerCertificate);
  const { receipt, events } = buildReceipt({ ...input, tenantId, envelopeId }, manifest.sealAnchor);
  const packaged: JsonRecord = { ...manifest.preSeal, final_pdf_digest: artifactDigest };

  for (const [name, value] of [
    [PACKAGE_FILES.approvalManifest, packaged],
    [PACKAGE_FILES.auditReceipt, receipt],
    [PACKAGE_FILES.verification, report],
  ] as const) {
    refuseKeyMaterial(value, name);
  }

  const data: Record<IndexedFileName, Uint8Array> = {
    // Not copied: writeZip copies every entry into its own output, and nothing runs between
    // the digest and the write.
    'final.pdf': pdf,
    'approval-manifest.json': memberBytes(packaged, PACKAGE_FILES.approvalManifest, MAX_MANIFEST_BYTES),
    'audit-receipt.json': memberBytes(receipt, PACKAGE_FILES.auditReceipt, MAX_RECEIPT_BYTES),
    // The stored report bytes exactly (request #59 (9)); checkReport bounded them.
    'verification.json': input.verification,
  };
  const files = INDEX_ORDER.map((name) => ({ path: name, sha256: sha256(data[name]), bytes: data[name].byteLength }));
  const indexBytes = memberBytes({ schema: 'opensig.package-index/1', envelope_id: envelopeId, artifact_id: artifactId, files }, PACKAGE_FILES.packageIndex, MAX_INDEX_BYTES);

  const bytes = writeZip(
    [
      { name: PACKAGE_FILES.finalPdf, data: data['final.pdf'] },
      { name: PACKAGE_FILES.approvalManifest, data: data['approval-manifest.json'] },
      { name: PACKAGE_FILES.auditReceipt, data: data['audit-receipt.json'] },
      { name: PACKAGE_FILES.verification, data: data['verification.json'] },
      { name: PACKAGE_FILES.packageIndex, data: indexBytes },
    ],
    PACKAGE_ZIP_LIMITS,
  );

  const digests = Object.fromEntries(files.map((file) => [file.path, { sha256: file.sha256, bytes: file.bytes }])) as Record<IndexedFileName, MemberDigest>;
  return Object.freeze({
    bytes,
    packageDigest: sha256(bytes),
    artifactDigest,
    approvalEvidenceDigest,
    members: Object.freeze({ ...digests, 'package-index.json': { sha256: sha256(indexBytes), bytes: indexBytes.byteLength } }),
    receiptEvents: events,
  });
}
