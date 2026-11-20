// SPDX-License-Identifier: Apache-2.0
//
// T016: the evidence package builder (src/artifacts/package.ts). Cases, per plan.md § Case
// catalogs (PK):
// - PK-01: exactly five members, each contract-valid; T039 called with the package limits;
//   the size bound, taken from its owners' exports, with the receipt budget covering T008's
//   ceiling plus the event sources that are never refused (requests #46 and #50).
// - PK-02: the digest cross-links and the verdict invariant, each refused when broken; a
//   two-approval package; every manifest and receipt link the builder checks, broken one at
//   a time; and each list cap at its owner's export, built at the cap and refused one above
//   (row T016-TESTS, request #76).
// - PK-03 (builder side): no key material and no slot outside the contract schemas.
// - PK-05: the receipt recomputes alone with the test-local RFC 8785 serializer.
// - PK-07: equal inputs give equal bytes.
// Rows are seeded through the storage layer (support/inputs.mjs chainWorld). Every digest
// this file computes uses support/jcs.mjs, never src/domain/canonical/. The package is read
// with T039's independent reader (tests/zip/reader.mjs), which imports nothing from src/.
// All content is synthetic. Key material is generated in memory at run time and never
// written.

import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { after, before, test } from 'node:test';

import { ENVELOPE_MAX_RECIPIENTS, ENVELOPE_REPEATABLE_EVENT_CEILING } from '../../src/api/recipients/index.ts';
import {
  AUDIT_METADATA_BYTES,
  INDEX_ORDER,
  MAX_EVENT_RECORD_BYTES,
  MAX_INDEX_BYTES,
  MAX_MANIFEST_BYTES,
  MAX_NON_PDF_BYTES,
  MAX_PACKAGE_BYTES,
  MAX_RECEIPT_BYTES,
  MAX_REPORT_CHECKS,
  MAX_VERIFICATION_BYTES,
  PACKAGE_FILES,
  PACKAGE_ZIP_LIMITS,
  PackageError,
  RECEIPT_EVENT_CAPACITY,
  RECEIPT_FRAME_BYTES,
  ZIP_OVERHEAD_BYTES,
  buildPackage,
} from '../../src/artifacts/package.ts';
import { writeZip } from '../../src/artifacts/zip.ts';
import { MAX_SEALED_PDF_BYTES } from '../../src/cryptograph/compose/bounds.ts';
import { MAX_CONSENT_TEXT_LENGTH } from '../../src/domain/consent/index.ts';
import { MAX_FIELDS, MAX_PAGES } from '../../src/domain/envelopes/validation.ts';
import {
  MAX_COORDINATE,
  MAX_FIELD_VALUES,
  MAX_POINTS_PER_APPROVAL,
  MAX_POINTS_PER_STROKE,
  MAX_POINTS_PER_VALUE,
  MAX_STROKES_PER_VALUE,
} from '../../src/domain/approval/index.ts';
import { MAX_METADATA_BYTES } from '../../src/storage/audit/index.ts';
import { DEFAULT_MAX_BLOB_BYTES } from '../../src/storage/blobs/index.ts';
import { CHECK_IDS, REPORT_LIMITS } from '../../src/verifier/index.ts';
import { loadVendoredContract } from '../contract/envelopes/lib/contract.mjs';
import { validate } from '../contract/envelopes/lib/schema.mjs';
import { readZip } from '../zip/reader.mjs';
import { jcs, jcsBytes, jcsDigest, sha256Hex } from './support/jcs.mjs';
import { chainWorld, hex, memoryChain, packageInput, preimageOf, reserialize, sid, syntheticPdf } from './support/inputs.mjs';

const contract = loadVendoredContract().doc;
const schemas = contract.components.schemas;
const schemaErrors = (name, value) => validate(contract, schemas[name], value);
const SOURCE = readFileSync(new URL('../../src/artifacts/package.ts', import.meta.url), 'utf8');
const JOBS_MIGRATION = readFileSync(new URL('../../src/storage/schema/migrations/0004-idempotency-jobs.sql', import.meta.url), 'utf8');
const ARTIFACTS_MIGRATION = readFileSync(new URL('../../src/storage/schema/migrations/0005-artifacts.sql', import.meta.url), 'utf8');

// Request #70 (6): the frozen runner keeps only an assertion's message, so every comparison
// with a message of its own carries the compared non-secret values (names, counts, sizes,
// digests) in that message. Bytes are shown as their SHA-256 and length, never as content.
const shown = (value) => (typeof value === 'string' ? value : JSON.stringify(value));
function same(actual, expected, what) {
  assert.equal(actual, expected, `${what}: ${shown(actual)}, expected ${shown(expected)}`);
}
function sameDeep(actual, expected, what) {
  assert.deepEqual(actual, expected, `${what}: ${shown(actual)}, expected ${shown(expected)}`);
}
function sameBytes(actual, expected, what) {
  const [a, b] = [Buffer.from(actual), Buffer.from(expected)];
  assert.ok(a.equals(b), `${what}: sha256 ${sha256Hex(a)} (${a.length} bytes), expected ${sha256Hex(b)} (${b.length} bytes)`);
}
function atMost(value, limit, what) {
  assert.ok(value <= limit, `${what}: ${value}, at most ${limit}`);
}

/**
 * ASSUMPTION (T038, not landed; request #59 (9)): finalization adds at most three audit
 * events per attempt (its terminal failure, the operator retry after it, the orphan
 * collection of its blobs), plus the seal anchor and envelope.completed once. Reconciled
 * against T038's export when T038 lands.
 */
const FINALIZATION_EVENTS_PER_ATTEMPT = 3;
const FINALIZATION_ONCE_EVENTS = 2;

let chain;
let base;
/** A consistent two-approval input over the same chain: two recipients, one shared consent text. */
let pair;
before(() => {
  chain = chainWorld();
  base = packageInput(chain);
  pair = packageInput(chain, { approvals: 2 });
});
after(() => chain?.close());

/** The package's members by name, read with the independent reader. */
function unzip(bytes) {
  return new Map(readZip(bytes).entries.map((entry) => [entry.name, Buffer.from(entry.data)]));
}

function member(bytes, name) {
  return JSON.parse(unzip(bytes).get(name).toString('utf8'));
}

/** Recompute the report's evidence digest after a manifest edit, so only the check under test can fail. */
function resealed(input) {
  const { final_pdf_digest: _excluded, ...preSeal } = input.approvalManifest;
  input.report.approval_evidence_digest = jcsDigest(preSeal);
  return reserialize(input);
}

/** A copy of `source` with `mutate` applied; manifest edits are resealed, report edits reserialized. */
function variantOf(source, mutate, { reseal = true } = {}) {
  const input = structuredClone(source);
  mutate(input);
  return reseal ? resealed(input) : reserialize(input);
}

/** A copy of the base input with `mutate` applied (see variantOf). */
function variant(mutate, options) {
  return variantOf(base, mutate, options);
}

/** After a field-manifest edit: manifest_digest and every approval's binding follow the edited field manifest. */
function refrozen(input) {
  const manifestDigest = jcsDigest(input.approvalManifest.field_manifest);
  input.approvalManifest.manifest_digest = manifestDigest;
  for (const approval of input.approvalManifest.approvals) approval.manifest_digest = manifestDigest;
  return input;
}

/** Replace consent text `index`'s wording; its digest and every approval naming its version follow. */
function reworded(input, index, text) {
  const entry = input.approvalManifest.consent_texts[index];
  entry.text = text;
  entry.text_digest = sha256Hex(Buffer.from(text, 'utf8'));
  for (const approval of input.approvalManifest.approvals) if (approval.consent_version === entry.version) approval.consent_text_digest = entry.text_digest;
  return input;
}

/**
 * The two-approval input with `count` approvals in ordinal order, each chained to the one
 * before (added approvals copy the first, with their own identifiers). With `ownTexts`, each
 * approval names its own consent text, so the manifest carries `count` texts.
 */
function approvalsOf(count, { ownTexts = false } = {}) {
  return variantOf(pair, (input) => {
    const manifest = input.approvalManifest;
    const [template] = manifest.approvals;
    const [wording] = manifest.consent_texts;
    const approvals = [];
    const texts = [];
    let prior = null;
    for (let index = 0; index < count; index += 1) {
      const approval = structuredClone(manifest.approvals[index] ?? { ...template, approval_id: sid('apr'), recipient: { ...template.recipient, id: sid('rcp'), ordinal: index + 1 }, approval_digest: hex(`approval-${index + 1}`) });
      approval.prior_approval_digest = prior;
      prior = approval.approval_digest;
      if (ownTexts) {
        const text = `${wording.text} (text ${index + 1})`;
        const entry = { version: `consent-${index + 1}`, text_digest: sha256Hex(Buffer.from(text, 'utf8')), text };
        texts.push(entry);
        approval.consent_version = entry.version;
        approval.consent_text_digest = entry.text_digest;
      }
      approvals.push(approval);
    }
    manifest.approvals = approvals;
    if (ownTexts) manifest.consent_texts = texts;
  });
}

/** The value at a builder path such as `approval-manifest.approvals[0].field_values`. */
function valueAt(manifest, path) {
  return path
    .replace(/^approval-manifest\./, '')
    .split('.')
    .reduce((value, part) => {
      const [, name, index] = /^([a-z_]+)(?:\[(\d+)\])?$/.exec(part) ?? [];
      const next = value?.[name];
      return index === undefined ? next : next?.[Number(index)];
    }, manifest);
}

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * buildPackage(input) refuses with `code` and a message matching `message`. Request #70 (6):
 * the assertion message carries what was thrown (a PackageError names members, never values).
 */
function assertRefused(input, code, message, what) {
  let caught;
  try {
    buildPackage(input);
  } catch (error) {
    caught = error;
  }
  const got = caught instanceof PackageError ? `${caught.code} "${caught.message}"` : caught === undefined ? 'built' : caught.name;
  assert.ok(caught instanceof PackageError && caught.code === code && message.test(caught.message), `${what}: ${got}, expected ${code} ${message}`);
}

/** A copy of a JSON value with every object's members inserted in reverse order. */
function reversedKeys(value) {
  if (Array.isArray(value)) return value.map(reversedKeys);
  if (value === null || typeof value !== 'object' || value instanceof Uint8Array) return value;
  return Object.fromEntries(Object.entries(value).reverse().map(([name, item]) => [name, reversedKeys(item)]));
}

const control = (length) => '\u0001'.repeat(length);
const longNumber = 0.0000012345678901234567;

/** The largest approval-manifest.json its owners allow, measured, never built. */
function worstManifest() {
  const fieldKey = (index) => `${'k'.repeat(38)}${String(index).padStart(2, '0')}`;
  const strokesPerValue = MAX_STROKES_PER_VALUE;
  const pointsPerStroke = Math.floor(MAX_POINTS_PER_APPROVAL / (MAX_FIELD_VALUES * strokesPerValue));
  assert.ok(
    pointsPerStroke >= 2 && pointsPerStroke <= MAX_POINTS_PER_STROKE && pointsPerStroke * strokesPerValue <= MAX_POINTS_PER_VALUE,
    `points per stroke ${pointsPerStroke} (2..${MAX_POINTS_PER_STROKE}), per value ${pointsPerStroke * strokesPerValue} (at most ${MAX_POINTS_PER_VALUE})`,
  );
  const drawn = (index) => ({
    key: fieldKey(index),
    type: 'signature',
    mode: 'drawn',
    strokes: Array.from({ length: strokesPerValue }, () => Array.from({ length: pointsPerStroke }, () => [MAX_COORDINATE, MAX_COORDINATE])),
  });
  const approvals = Array.from({ length: schemas.ApprovalManifest.properties.approvals.maxItems }, (_, index) => ({
    approval_id: 'A'.repeat(64),
    recipient: { id: 'R'.repeat(64), ordinal: index + 1, role: control(schemas.RecipientInput.properties.role.maxLength), email: control(schemas.RecipientInput.properties.email.maxLength) },
    assurance: { method: 'mailbox-challenge', level: 'mailbox-control' },
    consent_version: 'v'.repeat(40),
    consent_text_digest: 'f'.repeat(64),
    document_digest: 'f'.repeat(64),
    manifest_digest: 'f'.repeat(64),
    prior_approval_digest: 'f'.repeat(64),
    field_values: Array.from({ length: MAX_FIELD_VALUES }, (_, value) => drawn(value)),
    date_values: Array.from({ length: MAX_FIELD_VALUES }, (_, value) => ({ key: fieldKey(value), value: '2026-11-19' })),
    field_values_digest: 'f'.repeat(64),
    server_time: '2026-11-19T00:00:00.000Z',
    approval_digest: 'f'.repeat(64),
  }));
  return {
    schema: 'opensig.approval-manifest/1',
    envelope_id: 'E'.repeat(64),
    envelope_version: Number.MAX_SAFE_INTEGER,
    source: { app: 'openpractice', record: control(schemas.Source.properties.record.maxLength), version: control(schemas.Source.properties.version.maxLength) },
    document: {
      digest: 'f'.repeat(64),
      bytes: schemas.DocumentSummary.properties.bytes.maximum,
      pages: Array.from({ length: schemas.DocumentSummary.properties.pages.maxItems }, (_, index) => ({ number: index + 1, width: Number.MAX_VALUE, height: Number.MAX_VALUE, rotate: 270 })),
    },
    field_manifest: {
      schema: 'opensig.field-manifest/1',
      envelope_id: 'E'.repeat(64),
      document_digest: 'f'.repeat(64),
      fields: Array.from({ length: schemas.FieldManifest.properties.fields.maxItems }, (_, index) => ({
        key: fieldKey(index),
        recipient_id: 'R'.repeat(64),
        recipient_ordinal: 2,
        page: 50,
        type: 'signature',
        rect: { x: longNumber, y: longNumber, width: longNumber, height: longNumber },
      })),
    },
    manifest_digest: 'f'.repeat(64),
    consent_texts: approvals.map(() => ({ version: 'v'.repeat(40), text_digest: 'f'.repeat(64), text: control(schemas.ConsentText.properties.text.maxLength) })),
    approvals,
    approved_composition_digest: 'f'.repeat(64),
    seal: { type: 'organization', signer_certificate_sha256: 'f'.repeat(64), development_certificate: false },
    seal_audit_anchor: { seq: Number.MAX_SAFE_INTEGER, event_digest: 'f'.repeat(64) },
    final_pdf_digest: 'f'.repeat(64),
  };
}

test('[PK-01] the package holds exactly the five fixed members, each valid against its vendored contract schema', () => {
  const built = buildPackage(base);
  const { entries } = readZip(built.bytes);
  sameDeep(entries.map((entry) => entry.name), ['approval-manifest.json', 'audit-receipt.json', 'final.pdf', 'package-index.json', 'verification.json'], 'the five fixed names, in name-byte order');
  const members = unzip(built.bytes);
  sameBytes(members.get('final.pdf'), base.finalPdf, 'final.pdf is the sealed bytes, unchanged');
  sameBytes(members.get('verification.json'), base.verification, 'verification.json is the stored report bytes, unchanged');
  // However T038 serializes the report (requests #59 (9) and #74), its bytes are packaged
  // unchanged and never serialized again: here two-space JSON, which is not RFC 8785.
  const prettyBytes = Buffer.from(JSON.stringify(base.report, null, 2), 'utf8');
  const prettyMember = unzip(buildPackage({ ...base, verification: prettyBytes }).bytes).get('verification.json');
  sameBytes(prettyMember, prettyBytes, 'two-space report bytes, packaged unchanged');
  for (const [name, schema] of [
    ['approval-manifest.json', 'ApprovalManifest'],
    ['audit-receipt.json', 'AuditReceipt'],
    ['verification.json', 'VerificationReport'],
    ['package-index.json', 'PackageIndex'],
  ]) {
    sameDeep(schemaErrors(schema, JSON.parse(members.get(name).toString('utf8'))), [], `${name} is a contract ${schema}`);
  }
  for (const name of ['approval-manifest.json', 'audit-receipt.json', 'package-index.json']) {
    const bytes = members.get(name);
    sameBytes(bytes, Buffer.from(jcs(JSON.parse(bytes.toString('utf8'))), 'utf8'), `${name} is exactly its RFC 8785 form`);
  }
  for (const record of member(built.bytes, 'audit-receipt.json').events) sameDeep(schemaErrors('AuditEventRecord', record), [], `receipt event seq ${record.seq} is a full-preimage AuditEventRecord`);

  // A-008 S1: T038's pre-seal manifest unchanged, plus final_pdf_digest only.
  const { final_pdf_digest: finalPdfDigest, ...preSeal } = member(built.bytes, 'approval-manifest.json');
  assert.deepEqual(preSeal, base.approvalManifest);
  assert.equal(finalPdfDigest, sha256Hex(base.finalPdf));

  // T039 is called once, with the package's limits: five entries, inclusive.
  assert.deepEqual({ ...PACKAGE_ZIP_LIMITS }, { entryCountLimit: 5, entryBytesLimit: MAX_SEALED_PDF_BYTES, archiveBytesLimit: MAX_PACKAGE_BYTES });
  const five = Object.values(PACKAGE_FILES).map((name) => ({ name, data: Buffer.from(name) }));
  const fiveBytes = writeZip(five, PACKAGE_ZIP_LIMITS).length;
  assert.ok(fiveBytes > 0, `five entries are accepted: ${fiveBytes} bytes`);
  let sixth;
  try {
    writeZip([...five, { name: 'extra.json', data: Buffer.from('{}') }], PACKAGE_ZIP_LIMITS);
  } catch (error) {
    sixth = error;
  }
  same(sixth?.code ?? 'accepted', 'too-many-entries', 'a sixth entry');
  same([...SOURCE.matchAll(/\bwriteZip\(/g)].length, 1, 'writeZip calls in the builder');
  assert.match(SOURCE, /writeZip\(\s*\[[\s\S]*?\],\s*PACKAGE_ZIP_LIMITS,?\s*\)/, 'and passes PACKAGE_ZIP_LIMITS');
});

test('[PK-01] size bound: final.pdf at MAX_SEALED_PDF_BYTES and every other member within its owner-derived budget fit T028\'s 64 MiB blob', () => {
  // The bound's inputs, compared with their owners' exports.
  same(MAX_PACKAGE_BYTES, DEFAULT_MAX_BLOB_BYTES, 'T028\'s per-blob limit');
  same(MAX_SEALED_PDF_BYTES, 50_331_648, 'T036\'s sealed-PDF bound (bounds.ts)');
  same(MAX_NON_PDF_BYTES, 16 * 1024 * 1024, '16 MiB for the other members and the framing');
  same(AUDIT_METADATA_BYTES, MAX_METADATA_BYTES, 'T029\'s metadata limit');
  same(MAX_REPORT_CHECKS, CHECK_IDS.length, 'T014\'s fixed check list');
  // verification.json's budget is the stored row's bound, so any report bytes T038 can store
  // are packaged (request #74).
  const reportRowBound = Number(/report_bytes BLOB CHECK \(length\(report_bytes\) BETWEEN 2 AND (\d+)\)/.exec(ARTIFACTS_MIGRATION)?.[1]);
  same(MAX_VERIFICATION_BYTES, reportRowBound, 'verification.json\'s budget against migration 0005\'s report_bytes bound');
  same(MAX_MANIFEST_BYTES + MAX_RECEIPT_BYTES + MAX_VERIFICATION_BYTES + MAX_INDEX_BYTES + ZIP_OVERHEAD_BYTES, MAX_NON_PDF_BYTES, 'the budgets fill the 16 MiB exactly');

  // The framing, measured with T039's writer.
  const tiny = Object.values(PACKAGE_FILES).map((name) => ({ name, data: Buffer.from('x') }));
  assert.equal(writeZip(tiny, PACKAGE_ZIP_LIMITS).length - tiny.length, ZIP_OVERHEAD_BYTES);
  assert.equal(ZIP_OVERHEAD_BYTES, 570);

  // The receipt: the worst-case record and frame give the capacity.
  const worst = {
    tenantId: 'T'.repeat(64),
    seq: Number.MAX_SAFE_INTEGER,
    type: `a${'z'.repeat(60)}`,
    actor: { kind: 'human-operator', ref: control(100) },
    serverTime: '2026-11-19T00:00:00.000Z',
    envelopeId: 'E'.repeat(64),
    subjectDigest: 'f'.repeat(64),
    metadata: { pad: 'x'.repeat(AUDIT_METADATA_BYTES - 10) },
    prevDigest: 'f'.repeat(64),
  };
  assert.equal(Buffer.byteLength(jcs(worst.metadata)), AUDIT_METADATA_BYTES);
  same(Buffer.byteLength(jcs({ ...preimageOf(worst), event_digest: 'f'.repeat(64) })) + 1, MAX_EVENT_RECORD_BYTES, 'the largest record, with its comma');
  const frame = { schema: 'opensig.audit-receipt/1', envelope_id: 'E'.repeat(64), events: [], chain_head_digest: 'f'.repeat(64), checkpoint: { seq: Number.MAX_SAFE_INTEGER, digest: 'f'.repeat(64), created_at: '2026-11-19T00:00:00.000Z' } };
  assert.equal(Buffer.byteLength(jcs(frame)), RECEIPT_FRAME_BYTES);
  atMost(RECEIPT_FRAME_BYTES - 1 + RECEIPT_EVENT_CAPACITY * MAX_EVENT_RECORD_BYTES, MAX_RECEIPT_BYTES, `${RECEIPT_EVENT_CAPACITY} worst-case records in the receipt budget`);
  const oneMore = RECEIPT_FRAME_BYTES - 1 + (RECEIPT_EVENT_CAPACITY + 1) * MAX_EVENT_RECORD_BYTES;
  assert.ok(oneMore > MAX_RECEIPT_BYTES, `and is the largest that fits: one more record takes ${oneMore}, over ${MAX_RECEIPT_BYTES}`);
  assert.equal(RECEIPT_EVENT_CAPACITY, 2754);

  // The receipt's events (requests #46 and #50): T008's ceiling plus the sources that are
  // never refused and are bounded per envelope, each from its owner.
  const attemptCeiling = Number(/max_attempts INTEGER NOT NULL CHECK \(max_attempts BETWEEN 1 AND (\d+)\)/.exec(JOBS_MIGRATION)?.[1]);
  same(attemptCeiling, 100, 'migration 0004\'s attempt ceiling');
  assert.match(JOBS_MIGRATION, /CHECK \(attempt_count <= max_attempts\)/, 'and attempts to max_attempts');
  const neverRefused = {
    sendInvitation: 1, // recipient.invited for ordinal 1 at send (T008)
    approvals: ENVELOPE_MAX_RECIPIENTS, // recipient.approved, one per recipient (T010)
    followUpInvitation: ENVELOPE_MAX_RECIPIENTS - 1, // recipient.invited for ordinal 2 after approval 1 (T008)
    terminalWithReissue: 3, // a decline (recipient.declined + one revocation) or a void or expiry, then a reissue's revocation
    finalization: attemptCeiling * FINALIZATION_EVENTS_PER_ATTEMPT + FINALIZATION_ONCE_EVENTS,
  };
  const neverRefusedTotal = Object.values(neverRefused).reduce((sum, count) => sum + count, 0);
  same(ENVELOPE_REPEATABLE_EVENT_CEILING, 2052, 'T008\'s ceiling');
  assert.equal(neverRefusedTotal, 309);
  atMost(ENVELOPE_REPEATABLE_EVENT_CEILING + neverRefusedTotal, RECEIPT_EVENT_CAPACITY, `the ceiling ${ENVELOPE_REPEATABLE_EVENT_CEILING} plus ${neverRefusedTotal} never refused, against the receipt capacity`);

  // The report: T014's fixed checks within its limits, canonical and pretty-printed.
  const report = {
    ...JSON.parse(Buffer.from(base.verification).toString('utf8')),
    trust_anchor_ref: control(REPORT_LIMITS.trustAnchorRef),
    verifier: { name: control(REPORT_LIMITS.verifierName), version: control(REPORT_LIMITS.verifierVersion) },
    verified_at: '2026-11-19T00:00:00.123456789+14:00',
    checks: CHECK_IDS.map(() => ({ id: control(REPORT_LIMITS.checkId), result: 'not-run', detail_code: control(REPORT_LIMITS.detailCode) })),
  };
  atMost(Buffer.byteLength(jcs(report)), MAX_VERIFICATION_BYTES, 'the largest report, RFC 8785 bytes');
  atMost(Buffer.byteLength(JSON.stringify(report, null, 2)), MAX_VERIFICATION_BYTES, 'the largest report, two-space JSON bytes');

  // The manifest and the index.
  atMost(Buffer.byteLength(jcs(worstManifest())), MAX_MANIFEST_BYTES, 'the largest manifest, bytes');
  const index = { schema: 'opensig.package-index/1', envelope_id: 'E'.repeat(64), artifact_id: 'A'.repeat(64), files: INDEX_ORDER.map((path) => ({ path, sha256: 'f'.repeat(64), bytes: MAX_SEALED_PDF_BYTES })) };
  atMost(Buffer.byteLength(jcs(index)), MAX_INDEX_BYTES, 'the largest index, bytes');

  // A build at the sealed-PDF bound stays within the blob limit; one byte more is refused.
  const pdf = syntheticPdf('at-the-bound', MAX_SEALED_PDF_BYTES);
  const atBound = buildPackage(variant((input) => {
    input.finalPdf = pdf;
    input.report.artifact_digest = sha256Hex(pdf);
  }, { reseal: false }));
  atMost(atBound.bytes.length, MAX_PACKAGE_BYTES, 'the package at the sealed-PDF bound, bytes');
  const over = syntheticPdf('over-the-bound', MAX_SEALED_PDF_BYTES + 1);
  assertRefused(variant((input) => {
    input.finalPdf = over;
    input.report.artifact_digest = sha256Hex(over);
  }, { reseal: false }), 'pdf-invalid', /MAX_SEALED_PDF_BYTES/, 'a final.pdf over the bound');

  // A member over its budget is refused, never truncated: the manifest, the report and the receipt.
  assertRefused(variant((input) => {
    input.approvalManifest.approvals[0].date_values = [{ key: 'date-1', value: 'x'.repeat(MAX_MANIFEST_BYTES) }];
  }), 'member-too-large', /approval-manifest\.json/, 'a manifest over its budget');
  const padded = structuredClone(base);
  padded.verification = Buffer.concat([Buffer.from(padded.verification), Buffer.alloc(MAX_VERIFICATION_BYTES, 0x20)]);
  assertRefused(padded, 'member-too-large', /verification\.json/, 'report bytes over their budget');
  const tenantId = base.tenantId;
  const envelopeId = base.envelopeId;
  const heavy = memoryChain(tenantId, envelopeId, Math.ceil(MAX_RECEIPT_BYTES / 4096) + 1, () => ({ metadata: { pad: 'x'.repeat(4000) } }));
  assertRefused(packageInput({ tenantId, envelopeId, ...heavy }), 'member-too-large', /audit-receipt\.json/, 'a receipt over its budget');
});

test('[PK-02] package-index.json and every member are cross-linked by digests', () => {
  const built = buildPackage(base);
  const members = unzip(built.bytes);
  const index = member(built.bytes, 'package-index.json');
  sameDeep(index.files.map((file) => file.path), [...INDEX_ORDER], 'the four other members, in the builder\'s own order');
  for (const file of index.files) {
    same(file.sha256, sha256Hex(members.get(file.path)), `${file.path}: digest of its exact bytes`);
    same(file.bytes, members.get(file.path).length, `${file.path}: its byte length, not its character count`);
  }
  assert.equal(index.envelope_id, base.envelopeId);
  assert.equal(index.artifact_id, base.artifactId);
  assert.equal(built.packageDigest, sha256Hex(built.bytes));
  same(built.members['verification.json'].sha256, sha256Hex(base.verification), 'readVerification\'s ETag digest is the index entry');
  assert.equal(built.members['package-index.json'].sha256, sha256Hex(members.get('package-index.json')));

  const manifest = member(built.bytes, 'approval-manifest.json');
  const report = member(built.bytes, 'verification.json');
  const receipt = member(built.bytes, 'audit-receipt.json');
  const artifactDigest = sha256Hex(base.finalPdf);
  assert.equal(built.artifactDigest, artifactDigest);
  same(report.artifact_digest, artifactDigest, 'report → final.pdf');
  same(manifest.final_pdf_digest, artifactDigest, 'manifest → final.pdf');
  const { final_pdf_digest: _excluded, ...preSeal } = manifest;
  same(report.approval_evidence_digest, jcsDigest(preSeal), 'the sealed evidence digest → the manifest without final_pdf_digest');
  assert.equal(built.approvalEvidenceDigest, jcsDigest(preSeal));
  same(report.signer_certificate_sha256, manifest.seal.signer_certificate_sha256, 'report → manifest seal');
  same(manifest.manifest_digest, jcsDigest(manifest.field_manifest), 'manifest_digest → field manifest');
  const anchor = manifest.seal_audit_anchor;
  const receiptSeqs = receipt.events.map((event) => event.seq);
  assert.ok(receipt.events.some((event) => event.seq === anchor.seq && event.event_digest === anchor.event_digest), `seal anchor seq ${anchor.seq} (${anchor.event_digest}) → receipt seqs ${shown(receiptSeqs)}`);
  const foreign = receipt.events.filter((event) => event.envelope_id !== base.envelopeId || event.tenant_id !== base.tenantId).map((event) => event.seq);
  sameDeep(foreign, [], `receipt → envelope ${base.envelopeId}: seqs of another envelope or tenant`);
  sameDeep(receiptSeqs, [1, 3, 4, 5, 6], 'the envelope\'s events up to the chain head (seq 7); seq 8 is after it');
  assert.equal(receipt.chain_head_digest, chain.chainHead.digest);
  assert.deepEqual(receipt.checkpoint, { ...chain.checkpoint });
  same(report.trust, 'untrusted', 'trust is not part of the verdict');
});

test('[PK-02] every broken cross-link, receipt rule or verdict is refused, and nothing is built', () => {
  const memory = memoryChain(base.tenantId, base.envelopeId, 4);
  const memoryInput = () => packageInput({ tenantId: base.tenantId, envelopeId: base.envelopeId, ...structuredClone(memory) });
  const check = (input, id) => input.report.checks.find((entry) => entry.id === id);
  const cases = [
    ['the report verifies another artifact', variant((i) => (i.report.artifact_digest = hex('another-artifact')), { reseal: false }), 'cross-link', /another artifact/],
    ['the evidence digest includes final_pdf_digest', variant((i) => (i.report.approval_evidence_digest = jcsDigest({ ...i.approvalManifest, final_pdf_digest: sha256Hex(i.finalPdf) })), { reseal: false }), 'cross-link', /evidence digest/],
    ['the report names another signer', variant((i) => (i.report.signer_certificate_sha256 = hex('another-signer')), { reseal: false }), 'cross-link', /signer certificate/],
    ['the manifest names another envelope', variant((i) => (i.approvalManifest.envelope_id = chain.otherId)), 'cross-link', /another envelope/],
    ['a supplied final_pdf_digest is wrong', variant((i) => (i.approvalManifest.final_pdf_digest = hex('another-pdf'))), 'cross-link', /final_pdf_digest/],
    ['manifest_digest is not the field manifest\'s', variant((i) => (i.approvalManifest.manifest_digest = hex('another-manifest'))), 'cross-link', /manifest_digest/],
    ['an approval binds another document', variant((i) => (i.approvalManifest.approvals[0].document_digest = hex('another-document'))), 'cross-link', /another document/],
    ['a consent text does not match its digest', variant((i) => (i.approvalManifest.consent_texts[0].text += ' Changed.')), 'cross-link', /consent text 0/],
    ['an approval names a consent text the manifest lacks', variant((i) => (i.approvalManifest.approvals[0].consent_version = 'another-1')), 'cross-link', /consent text the manifest/],
    ['the seal anchor is not a receipt event', variant((i) => (i.approvalManifest.seal_audit_anchor.event_digest = hex('another-anchor'))), 'cross-link', /seal audit anchor/],
    ['the checkpoint is not the chain head', variant((i) => (i.checkpoint.digest = hex('another-checkpoint')), { reseal: false }), 'cross-link', /checkpoint/],
    ['an event of another envelope', variant((i) => i.events.push(structuredClone(chain.otherEvents[0])), { reseal: false }), 'receipt-invalid', /another envelope/],
    ['an event of another tenant', variant((i) => i.events.push(structuredClone(memoryChain(sid('tenant'), base.envelopeId, 1).events[0])), { reseal: false }), 'receipt-invalid', /another tenant/],
    ['a stored digest that is not the preimage\'s', variant((i) => (i.events[1].eventDigest = hex('edited')), { reseal: false }), 'receipt-invalid', /does not match/],
    ['metadata edited after hashing', variant((i) => (i.events[1].event.metadata = { ...i.events[1].event.metadata, attempt: 2 }), { reseal: false }), 'receipt-invalid', /does not match/],
    ['two events share a seq', variant((i) => i.events.push(structuredClone(i.events[0])), { reseal: false }), 'receipt-invalid', /share a seq/],
    ['no event precedes the head', variant((i) => (i.events = []), { reseal: false }), 'receipt-invalid', /no event/],
    ['consecutive events that do not link', (() => {
      const broken = memoryChain(base.tenantId, base.envelopeId, 4, (seq) => (seq === 3 ? { prevDigest: hex('elsewhere') } : {}));
      return packageInput({ tenantId: base.tenantId, envelopeId: base.envelopeId, ...broken });
    })(), 'receipt-invalid', /do not link/],
    ['the event at the head has another digest', (() => {
      const input = memoryInput();
      input.chainHead = { ...input.chainHead, digest: hex('another-head') };
      input.checkpoint = { ...input.checkpoint, digest: hex('another-head') };
      return input;
    })(), 'cross-link', /event at the chain head/],
    ['final.pdf is not a PDF', variant((i) => {
      i.finalPdf = Buffer.from('not a pdf, synthetic');
      i.report.artifact_digest = sha256Hex(i.finalPdf);
    }, { reseal: false }), 'pdf-invalid', /PDF header/],
    ['the report has another schema', variant((i) => (i.report.schema = 'opensig.verification/2'), { reseal: false }), 'input-invalid', /verification\.schema/],
    ['the report bytes are not JSON', (() => {
      const input = structuredClone(base);
      input.verification = Buffer.from('{"schema":', 'utf8');
      return input;
    })(), 'input-invalid', /not one JSON value/],
    ['the report bytes start with a byte-order mark', (() => {
      const input = structuredClone(base);
      input.verification = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(base.verification)]);
      return input;
    })(), 'input-invalid', /not one JSON value/],
    // Replaced, not appended: a 17th check would meet the 16-item bound first.
    ['a check outside T014\'s list', variant((i) => (i.report.checks[0] = { id: 'extra-check', result: 'pass' }), { reseal: false }), 'input-invalid', /checks\[0\]\.id/],
    ['a repeated check', variant((i) => (i.report.checks[1] = { ...i.report.checks[0] }), { reseal: false }), 'input-invalid', /checks\[1\] repeats a check/],
    ['a 17th check', variant((i) => i.report.checks.push({ id: 'trust-anchors', result: 'fail' }), { reseal: false }), 'input-invalid', /must list 0 to 16 items/],
    ['integrity not valid', variant((i) => (i.report.integrity = 'invalid'), { reseal: false }), 'verdict', /integrity/],
    ['coverage not complete', variant((i) => (i.report.revision_coverage = 'incomplete'), { reseal: false }), 'verdict', /revision coverage/],
    ['the evidence check a mismatch', variant((i) => Object.assign(check(i, 'approval-evidence-digest'), { result: 'fail', detail_code: 'mismatch' }), { reseal: false }), 'verdict', /approval-evidence check/],
    ['the evidence check not run', variant((i) => (check(i, 'approval-evidence-digest').result = 'not-run'), { reseal: false }), 'verdict', /approval-evidence check/],
    ['the artifact-digest check not passed', variant((i) => Object.assign(check(i, 'artifact-digest'), { result: 'fail', detail_code: 'artifact-digest-mismatch' }), { reseal: false }), 'verdict', /artifact-digest check/],
  ];
  for (const [what, input, code, message] of cases) assertRefused(input, code, message, what);
  // The controls: the same inputs, unbroken, build; trust `untrusted` and a failed trust-anchors check do not refuse.
  const storageBuilt = buildPackage(structuredClone(base)).bytes.length;
  assert.ok(storageBuilt > 0, `the storage-seeded control builds: ${storageBuilt} bytes`);
  const memoryBuilt = buildPackage(memoryInput()).bytes.length;
  assert.ok(memoryBuilt > 0, `the in-memory control builds: ${memoryBuilt} bytes`);
  assert.equal(check(base, 'trust-anchors').result, 'fail');
});

test('[PK-02] a two-approval package builds, with every cross-link over both approvals', () => {
  const built = buildPackage(pair);
  const manifest = member(built.bytes, 'approval-manifest.json');
  const report = member(built.bytes, 'verification.json');
  const approvals = manifest.approvals;
  same(approvals.length, ENVELOPE_MAX_RECIPIENTS, 'approvals in the packaged manifest');
  sameDeep(approvals.map((approval) => approval.recipient.ordinal), [1, 2], 'approval ordinals');
  same(approvals[0].prior_approval_digest, null, 'the first approval chains to nothing');
  same(approvals[1].prior_approval_digest, approvals[0].approval_digest, 'the second approval chains to the first');
  const manifestDigest = jcsDigest(manifest.field_manifest);
  same(manifest.manifest_digest, manifestDigest, 'manifest_digest → the two-field manifest');
  same(manifest.field_manifest.fields.length, 2, 'fields, one per recipient');
  for (const [index, approval] of approvals.entries()) {
    same(approval.document_digest, manifest.document.digest, `approval ${index} → the document`);
    same(approval.manifest_digest, manifestDigest, `approval ${index} → the field manifest`);
    same(approval.consent_text_digest, manifest.consent_texts.find((entry) => entry.version === approval.consent_version)?.text_digest, `approval ${index} → its consent text ${approval.consent_version}`);
  }
  const { final_pdf_digest: _excluded, ...preSeal } = manifest;
  same(report.approval_evidence_digest, jcsDigest(preSeal), 'the evidence digest covers both approvals');
  same(built.approvalEvidenceDigest, jcsDigest(preSeal), 'the builder\'s evidence digest');
  sameDeep(schemaErrors('ApprovalManifest', manifest), [], 'the two-approval manifest is a contract ApprovalManifest');
  // Two approvals naming two consent texts build too: each text is named once.
  const twoTexts = buildPackage(approvalsOf(ENVELOPE_MAX_RECIPIENTS, { ownTexts: true }));
  const textVersions = member(twoTexts.bytes, 'approval-manifest.json').consent_texts.map((entry) => entry.version);
  sameDeep(textVersions, ['consent-1', 'consent-2'], 'two approvals with their own consent texts');
});

test('[PK-02] the field-manifest, ordinal, approval-chain, consent and genesis links: each broken alone is refused with its own message', () => {
  const tenantId = base.tenantId;
  const envelopeId = base.envelopeId;
  const genesis = (shape) => packageInput({ tenantId, envelopeId, ...memoryChain(tenantId, envelopeId, 4, shape) });
  const unnamedText = 'A second synthetic consent wording that no approval names.';
  // Each row breaks one link and repairs every digest that depends on it, so only the check
  // under test can refuse (package.ts at cb0c629: :444, :445, :476, :479, :485 and :613).
  const rows = [
    ['the field manifest names another envelope (:444)', variant((i) => {
      i.approvalManifest.field_manifest.envelope_id = chain.otherId;
      refrozen(i);
    }), 'cross-link', /: the field manifest names another envelope$/],
    ['the field manifest binds another document (:445)', variant((i) => {
      i.approvalManifest.field_manifest.document_digest = hex('another-document');
      refrozen(i);
    }), 'cross-link', /: the field manifest binds another document$/],
    ['one approval with ordinal 2 (:476)', variant((i) => (i.approvalManifest.approvals[0].recipient.ordinal = 2)), 'cross-link', /approvals\[0\] is out of ordinal order$/],
    ['two approvals with their ordinals swapped (:476)', variantOf(pair, (i) => {
      const [first, second] = i.approvalManifest.approvals;
      [first.recipient.ordinal, second.recipient.ordinal] = [2, 1];
    }), 'cross-link', /approvals\[0\] is out of ordinal order$/],
    ['the first approval names a prior approval (:479)', variant((i) => (i.approvalManifest.approvals[0].prior_approval_digest = hex('before-the-first'))), 'cross-link', /approvals\[0\] does not chain to the prior approval$/],
    ['the second approval chains to another approval (:479)', variantOf(pair, (i) => (i.approvalManifest.approvals[1].prior_approval_digest = hex('another-approval'))), 'cross-link', /approvals\[1\] does not chain to the prior approval$/],
    ['the second approval chains to nothing (:479)', variantOf(pair, (i) => (i.approvalManifest.approvals[1].prior_approval_digest = null)), 'cross-link', /approvals\[1\] does not chain to the prior approval$/],
    ['a consent text no approval names (:485)', variant((i) => i.approvalManifest.consent_texts.push({ version: 'unnamed-1', text_digest: sha256Hex(Buffer.from(unnamedText, 'utf8')), text: unnamedText })), 'cross-link', /: a consent text is named by no approval$/],
    ['seq 1 of the tenant chain carries a prev_digest (:613)', genesis((seq) => (seq === 1 ? { prevDigest: hex('before-genesis') } : {})), 'receipt-invalid', /: only seq 1 of the tenant chain has no prev_digest$/],
    ['a later event carries no prev_digest (:613)', genesis((seq) => (seq === 3 ? { prevDigest: null } : {})), 'receipt-invalid', /: only seq 1 of the tenant chain has no prev_digest$/],
  ];
  for (const [what, input, code, message] of rows) assertRefused(input, code, message, what);
  // The controls: the unbroken inputs of every row build.
  for (const [what, input] of [['the one-approval input', base], ['the two-approval input', pair], ['the in-memory chain', genesis(() => ({}))]]) {
    const bytes = buildPackage(structuredClone(input)).bytes.length;
    assert.ok(bytes > 0, `${what} builds: ${bytes} bytes`);
  }
});

test('[PK-02] each list cap the builder enforces is its owner\'s export: a build at the cap, a refusal one above', () => {
  // F4 (row T016-TESTS): every cap comes from its owner, never a literal, so a raised owner
  // limit fails here instead of stranding an approved envelope at packaging.
  const caps = [
    {
      path: 'approval-manifest.field_manifest.fields',
      owner: 'T007 MAX_FIELDS',
      cap: MAX_FIELDS,
      min: 1,
      at: (count) => variant((i) => {
        const [first] = i.approvalManifest.field_manifest.fields;
        i.approvalManifest.field_manifest.fields = Array.from({ length: count }, (_, index) => ({ ...first, key: `sig-${index + 1}` }));
        refrozen(i);
      }),
    },
    {
      path: 'approval-manifest.document.pages',
      owner: 'T007 MAX_PAGES',
      cap: MAX_PAGES,
      min: 1,
      at: (count) => variant((i) => {
        const [first] = i.approvalManifest.document.pages;
        i.approvalManifest.document.pages = Array.from({ length: count }, (_, index) => ({ ...first, number: index + 1 }));
      }),
    },
    {
      path: 'approval-manifest.approvals[0].field_values',
      owner: 'T010 MAX_FIELD_VALUES',
      cap: MAX_FIELD_VALUES,
      min: 1,
      at: (count) => variant((i) => {
        const [first] = i.approvalManifest.approvals[0].field_values;
        i.approvalManifest.approvals[0].field_values = Array.from({ length: count }, (_, index) => ({ ...first, key: `sig-${index + 1}` }));
      }),
    },
    {
      // A date value is filled for a date field value, so T010's cap bounds both lists.
      path: 'approval-manifest.approvals[0].date_values',
      owner: 'T010 MAX_FIELD_VALUES',
      cap: MAX_FIELD_VALUES,
      min: 0,
      at: (count) => variant((i) => {
        i.approvalManifest.approvals[0].date_values = Array.from({ length: count }, (_, index) => ({ key: `date-${index + 1}`, value: '2026-11-19' }));
      }),
    },
    { path: 'approval-manifest.approvals', owner: 'T008 ENVELOPE_MAX_RECIPIENTS', cap: ENVELOPE_MAX_RECIPIENTS, min: 1, at: (count) => approvalsOf(count) },
    // One consent text per approval at most, so the recipient cap bounds the texts too.
    { path: 'approval-manifest.consent_texts', owner: 'T008 ENVELOPE_MAX_RECIPIENTS', cap: ENVELOPE_MAX_RECIPIENTS, min: 1, at: (count) => approvalsOf(count, { ownTexts: true }) },
    { path: 'approval-manifest.consent_texts[0].text', owner: 'T008 MAX_CONSENT_TEXT_LENGTH', cap: MAX_CONSENT_TEXT_LENGTH, min: 1, text: true, at: (count) => variant((i) => reworded(i, 0, 'c'.repeat(count))) },
  ];
  for (const { path, owner, cap, min, text = false, at } of caps) {
    let built;
    try {
      built = buildPackage(at(cap));
    } catch (error) {
      assert.fail(`${path} at ${owner} = ${cap} is refused: ${error.message}`);
    }
    const packaged = valueAt(member(built.bytes, 'approval-manifest.json'), path);
    same(text ? [...packaged].length : packaged?.length, cap, `${path} at ${owner}: packaged size`);
    const limit = text ? `${path} must be a string of ${min} to ${cap} characters` : `${path} must list ${min} to ${cap} items`;
    assertRefused(at(cap + 1), 'input-invalid', new RegExp(`: ${escapeRegExp(limit)}$`), `${path} one above ${owner} (${cap + 1})`);
  }
});

test('[PK-03] key material and members outside the contract schemas are refused in every JSON member', () => {
  // The armour line of a key generated in memory now (never written, never a literal here).
  const armour = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'pem', type: 'pkcs8' }).split('\n')[0];
  const leaked = memoryChain(base.tenantId, base.envelopeId, 3, (seq) => (seq === 2 ? { metadata: { note: armour } } : {}));
  const cases = [
    ['the manifest source', variant((i) => (i.approvalManifest.source.record = armour)), 'capability-leak'],
    ['a recipient role', variant((i) => (i.approvalManifest.approvals[0].recipient.role = armour)), 'capability-leak'],
    ['the report verifier', variant((i) => (i.report.verifier.name = armour), { reseal: false }), 'capability-leak'],
    ['audit event metadata', packageInput({ tenantId: base.tenantId, envelopeId: base.envelopeId, ...leaked }), 'capability-leak'],
    ['an extra manifest member', variant((i) => (i.approvalManifest.unexpected_member = sid('value'))), 'input-invalid'],
    ['an extra recipient member', variant((i) => (i.approvalManifest.approvals[0].recipient.unexpected_member = sid('value'))), 'input-invalid'],
    ['an extra report member', variant((i) => (i.report.unexpected_member = sid('value')), { reseal: false }), 'input-invalid'],
  ];
  for (const [what, input, code] of cases) assertRefused(input, code, code === 'capability-leak' ? /PEM armour/ : /outside its contract schema/, what);
  // The control: the storage-seeded package carries no armour in any member.
  for (const [name, bytes] of unzip(buildPackage(base).bytes)) assert.ok(!bytes.includes('-----BEGIN'), `${name} holds no PEM armour`);
});

test('[PK-05] every event_digest recomputes from the receipt alone with a test-local RFC 8785 serializer, and a single-field change fails', () => {
  const receiptBytes = unzip(buildPackage(base).bytes).get('audit-receipt.json');
  const receipt = JSON.parse(receiptBytes.toString('utf8'));
  sameBytes(receiptBytes, jcsBytes(receipt), 'the receipt is its own RFC 8785 form');
  assert.ok(receipt.events.length >= 5, `receipt events: ${receipt.events.length}, at least 5`);
  const flip = (digest) => (digest[0] === '0' ? `1${digest.slice(1)}` : `0${digest.slice(1)}`);
  const changes = {
    schema: (r) => (r.schema = 'opensig.audit-event/2'),
    tenant_id: (r) => (r.tenant_id = sid('tenant')),
    seq: (r) => (r.seq += 1),
    type: (r) => (r.type = `${r.type}x`),
    'actor.kind': (r) => (r.actor.kind = r.actor.kind === 'system' ? 'service' : 'system'),
    'actor.ref': (r) => (r.actor.ref = `${r.actor.ref}x`),
    server_time: (r) => (r.server_time = r.server_time.replace(/\.\d{3}Z$/, '.999Z')),
    envelope_id: (r) => (r.envelope_id = chain.otherId),
    subject_digest: (r) => (r.subject_digest = r.subject_digest === null ? hex('subject') : flip(r.subject_digest)),
    metadata: (r) => (r.metadata = { ...r.metadata, extra: 1 }),
    prev_digest: (r) => (r.prev_digest = r.prev_digest === null ? hex('prev') : flip(r.prev_digest)),
  };
  for (const record of receipt.events) {
    const { event_digest: stored, ...preimage } = record;
    sameDeep(Object.keys(preimage).sort(), ['actor', 'envelope_id', 'metadata', 'prev_digest', 'schema', 'seq', 'server_time', 'subject_digest', 'tenant_id', 'type'], `seq ${record.seq}: the full preimage`);
    same(jcsDigest(preimage), stored, `seq ${record.seq}: recomputed from the receipt alone`);
    for (const [field, change] of Object.entries(changes)) {
      const edited = structuredClone(preimage);
      change(edited);
      const recomputed = jcsDigest(edited);
      assert.notEqual(recomputed, stored, `seq ${record.seq}: a change of ${field} still recomputes to ${recomputed}`);
    }
  }
  // Continuity between consecutive seq values, and the head and checkpoint.
  for (let index = 1; index < receipt.events.length; index += 1) {
    const [previous, current] = [receipt.events[index - 1], receipt.events[index]];
    if (current.seq === previous.seq + 1) same(current.prev_digest, previous.event_digest, `seq ${current.seq} links to seq ${previous.seq}`);
  }
  assert.equal(receipt.checkpoint.digest, receipt.chain_head_digest);
  const afterHead = receipt.events.filter((event) => event.seq > receipt.checkpoint.seq).map((event) => event.seq);
  sameDeep(afterHead, [], `events after the head seq ${receipt.checkpoint.seq}`);
});

test('[PK-07] equal inputs give equal bytes, whatever the order of events or manifest members, and read no clock', () => {
  const first = buildPackage(base);
  const again = buildPackage(base);
  sameBytes(again.bytes, first.bytes, 'a repeated build');
  const copied = structuredClone(base);
  copied.approvalManifest = reversedKeys(copied.approvalManifest);
  copied.events = [...copied.events].reverse();
  copied.finalPdf = Buffer.from(copied.finalPdf);
  copied.verification = Buffer.from(copied.verification);
  const reordered = buildPackage(copied);
  sameBytes(reordered.bytes, first.bytes, 'copied buffers, reversed manifest members and reversed events');
  assert.equal(reordered.packageDigest, first.packageDigest);
  const shuffled = structuredClone(base);
  shuffled.events = [shuffled.events[2], shuffled.events[0], shuffled.events[5], shuffled.events[1], shuffled.events[4], shuffled.events[3]];
  same(buildPackage(shuffled).packageDigest, first.packageDigest, 'shuffled events, package digest');

  // The result shares no memory with the input.
  const input = structuredClone(base);
  const built = buildPackage(input);
  input.finalPdf.fill(0x20);
  input.verification.fill(0x20);
  assert.equal(sha256Hex(built.bytes), built.packageDigest);

  // No clock, randomness or environment in the builder's source.
  assert.doesNotMatch(SOURCE, /\bDate\b|Math\.random|randomBytes|randomUUID|hrtime|performance\.|process\.env/);

  // A one-byte change changes the package.
  const changed = variant((i) => {
    i.finalPdf = Buffer.from(i.finalPdf);
    i.finalPdf[20] ^= 0x01;
    i.report.artifact_digest = sha256Hex(i.finalPdf);
  }, { reseal: false });
  assert.notEqual(buildPackage(changed).packageDigest, first.packageDigest);
});
