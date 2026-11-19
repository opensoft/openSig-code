// SPDX-License-Identifier: Apache-2.0
//
// T034 follow-up, EA-07 (A-010 requests #44, #45 and #46; rows SIZE-BOUND, T036-NUMRANGE and
// T036-RESIDUAL): the upload refuses a document the composer could not seal. The upload runs
// T036's predicate on the live parse report, before the blob is stored and before any state
// changes, and refuses with 422 unsupported_pdf. Its one detail is the predicate's first
// refusal, in the order of SEAL_REFUSAL_DETAILS: composition_too_large, number_range,
// dangling_form_reference, annots_shape, acroform_shape, xref_size, page_box or name_character.
// One bounded upload_unsealable request-log record per refused upload (request #57 (3)) holds
// the correlation id, the envelope id, the detail, at most 16 of that refusal's object
// references and their total count; the response is unchanged. Refusing at upload keeps every
// accepted document sealable, so no approved envelope strands at finalization.
//
// What is real. Every document is built at run time (sealable-pdf.mjs) and parsed by the real
// isolated parse service (T033). The router, authenticator, handlers, upload cap and blob store
// are the production ones (support.mjs createWorld). Nothing stubs the predicate: T036's
// committed bounds.ts decides, through T034's one adapter (src/api/envelopes/sealable.ts), and
// these tests take its order from SEAL_REFUSAL_DETAILS through that adapter.
//
// Runtime cost. 25 parse-service runs: two shared-array bases of 3.0 MB and 1.8 MB, and 23
// small documents of under 3 KB. Each run is well inside the parse limits. No composition runs,
// so the 66 MB the composer would write never exists, and no load is generated. Each test
// starts its own world and closes it once the services drain.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { MAX_LOGGED_REFS, SEAL_REFUSAL_DETAILS, SEALED_PDF_LIMIT, sealabilityOf } from '../../../src/api/envelopes/index.ts';
import { MAX_DOCUMENT_BYTES } from '../../../src/pdf/limits.ts';
import { parseAdmissions, parsePdf } from '../../../src/pdf/service.ts';
import {
  MANY_PAGE_BOX_PAGES,
  MANY_REFUSALS,
  TOO_LARGE_NAMES,
  UNDER_BOUND_NAMES,
  acroformIsPagePdf,
  acroformShapePdf,
  annotsShapePdf,
  croppedExponentPdf,
  danglingAcroFormPdf,
  danglingAnnotsPdf,
  danglingFieldsPdf,
  exponentCatalogPdf,
  exponentPagePdf,
  exponentProtoKeyPdf,
  fieldsShapePdf,
  manyPageBoxesPdf,
  manyRefusalsPdf,
  nulKeyPdf,
  nulNamePdf,
  pageBoxCoordinatePdf,
  pageBoxSidePdf,
  sealableFormPdf,
  sharedArrayPdf,
  xrefSizePdf,
} from './sealable-pdf.mjs';
import { REPO, TENANTS, assertSameRows, contractErrors, createEnvelope, createWorld, isIdle, newKey, readEnvelope, sha256, until, uploadRequest } from './support.mjs';

const ALPHA = TENANTS.alpha.id;
const parses = () => parseAdmissions().next_ticket;
const isRefPair = (ref) => Array.isArray(ref) && ref.length === 2 && ref.every((n) => Number.isSafeInteger(n) && n >= 0);

/**
 * Every member an upload_unsealable record may hold (request #57 (3)): the logger's own (time,
 * level, event), the request logger's correlation_id, api.ts's envelope_id, and the adapter's
 * detail, refs and refs_total. Nothing else, so no document byte, name, string, stream content,
 * file name or capability value has a place in it.
 */
const RECORD_MEMBERS = Object.freeze(['correlation_id', 'detail', 'envelope_id', 'event', 'level', 'refs', 'refs_total', 'time']);

/** Assert one upload_unsealable record against its refused upload (request #57 (3)). */
function assertBoundedRecord(record, { response, draft, detail, what }) {
  assert.deepEqual(Object.keys(record).sort(), RECORD_MEMBERS, `${what}: the record holds its ruled members and nothing else`);
  assert.equal(record.correlation_id, response.json?.correlation_id, `${what}: the request's correlation id`);
  assert.equal(record.envelope_id, draft.id, `${what}: the envelope id`);
  assert.equal(record.detail, detail, `${what}: the detail of the response`);
  assert.ok(Array.isArray(record.refs) && record.refs.every(isRefPair), `${what}: references as integer [number, generation] pairs only`);
  assert.ok(Number.isSafeInteger(record.refs_total) && record.refs_total >= 0, `${what}: a total count`);
  assert.equal(record.refs.length, Math.min(record.refs_total, MAX_LOGGED_REFS), `${what}: at most ${MAX_LOGGED_REFS} references, all of them when fewer`);
}

/** A world for one test, closed unconditionally once the parse service and the upload cap drain. */
async function sealWorld(t) {
  const world = await createWorld();
  t.after(async () => {
    await until(isIdle, 'cleanup: the parse service and the upload cap drain to idle');
    await world.close();
  });
  return world;
}

/**
 * Upload `pdf` to a fresh alpha draft and assert the EA-07 refusal with `detail`:
 * - 422 unsupported_pdf, in the contract's Error shape, with exactly that one detail on
 *   `document` and no object reference in the response;
 * - decided after exactly one parse, so by the sealability check and not before the parse;
 * - one bounded upload_unsealable request-log record (request #57 (3)), naming `detail`;
 * - the upload slot released, no blob stored, and no row changed for the tenant (the envelope
 *   and its version, revisions, idempotency records, audit and outbox events).
 */
async function expectUnsealable(world, pdf, detail, what) {
  assert.ok(pdf.length <= MAX_DOCUMENT_BYTES, `${what}: within the 10 MiB upload cap (${pdf.length} bytes)`);
  const draft = await createEnvelope(world);
  const blobs = world.blobs.list(ALPHA);
  const before = world.snapshot('alpha');
  const logged = world.logged('upload_unsealable').length;
  const ticket = parses();
  const key = newKey();
  const response = await uploadRequest(world, { envelope: draft, pdf, key });
  assert.equal(response.status, 422, `${what}: status ${response.status} ${response.json?.code ?? ''}`);
  assert.equal(response.json?.code, 'unsupported_pdf', `${what}: the code`);
  assert.deepEqual(response.json?.details, [{ field: 'document', code: detail }], `${what}: the predicate's first refusal is the one detail`);
  // The contract Error admits no other member (additionalProperties: false), so no reference.
  assert.deepEqual(contractErrors('Error', response.json), [], `${what}: the body is a contract Error, with no object reference`);
  assert.equal(parses(), ticket + 1, `${what}: refused after exactly one parse`);
  const records = world.logged('upload_unsealable');
  assert.equal(records.length, logged + 1, `${what}: one request-log record per refused upload`);
  const record = records.at(-1);
  assertBoundedRecord(record, { response, draft, detail, what });
  await until(isIdle, `${what}: the upload slot and the parse service are released`);
  assert.deepEqual(world.blobs.list(ALPHA), blobs, `${what}: no blob was stored`);
  assert.equal(world.blobs.check(ALPHA, sha256(pdf)), 'missing', `${what}: the refused bytes are not in the blob store`);
  assertSameRows(world.snapshot('alpha'), before, `${what}: a refused upload changes no row`);
  assert.equal((await readEnvelope(world, { envelope: draft })).version, 1, `${what}: the envelope version is unchanged`);
  return { draft, key, record };
}

test("[EA-07] EA-07 refuses on the predicate's eight details, in their landed order (SEAL_REFUSAL_DETAILS, through the adapter)", () => {
  assert.deepEqual(
    [...SEAL_REFUSAL_DETAILS],
    ['composition_too_large', 'number_range', 'dangling_form_reference', 'annots_shape', 'acroform_shape', 'xref_size', 'page_box', 'name_character'],
    'the eight details as ruled by request #46, in the landed order',
  );
});

test('[EA-07] composition_too_large: an upload whose worst-case sealed PDF exceeds MAX_SEALED_PDF_BYTES is refused, and nothing is stored', async (t) => {
  const world = await sealWorld(t);
  const pdf = sharedArrayPdf(TOO_LARGE_NAMES);
  t.diagnostic(`shared-array base: ${pdf.length} bytes (upload cap ${MAX_DOCUMENT_BYTES}); sealed bound ${SEALED_PDF_LIMIT}`);
  const { record } = await expectUnsealable(world, pdf, 'composition_too_large', 'the adversarial shared-array base');
  // The worst case counts 22 objects: the catalog, the shared array and the 20 pages.
  assert.deepEqual([record.refs.length, record.refs_total], [MAX_LOGGED_REFS, 22], 'the record holds 16 of the 22 counted objects, and their total');
});

test('[EA-07] number_range: an exponent-form number in a value the composer writes is refused, also under a key named __proto__', async (t) => {
  const world = await sealWorld(t);
  await expectUnsealable(world, exponentPagePdf(), 'number_range', '0.0000001 on a page that no widget is placed on');
  await expectUnsealable(world, exponentCatalogPdf(), 'number_range', 'a 22-digit integer in the catalog');
  await expectUnsealable(world, exponentProtoKeyPdf(), 'number_range', 'an exponent-form number under a page key named __proto__');
});

test('[EA-07] dangling_form_reference: a page /Annots or an AcroForm /Fields that refers to no object is refused', async (t) => {
  const world = await sealWorld(t);
  await expectUnsealable(world, danglingAnnotsPdf(), 'dangling_form_reference', 'a page /Annots referring to a free object');
  await expectUnsealable(world, danglingFieldsPdf(), 'dangling_form_reference', 'an AcroForm /Fields referring to a free object');
});

test('[EA-07] annots_shape: a page /Annots that is not an array is refused', async (t) => {
  const world = await sealWorld(t);
  await expectUnsealable(world, annotsShapePdf(), 'annots_shape', 'a page /Annots that is a dictionary');
});

test('[EA-07] acroform_shape: an AcroForm that is not a dictionary, whose /Fields is not an array, or that is also a page is refused', async (t) => {
  const world = await sealWorld(t);
  await expectUnsealable(world, acroformShapePdf(), 'acroform_shape', 'an /AcroForm that is an array');
  await expectUnsealable(world, fieldsShapePdf(), 'acroform_shape', 'an AcroForm /Fields that is a number');
  await expectUnsealable(world, acroformIsPagePdf(), 'acroform_shape', 'an AcroForm object that is also the page');
});

test('[EA-07] xref_size: a trailer /Size that leaves no room for the largest request\'s new objects is refused', async (t) => {
  const world = await sealWorld(t);
  const { record } = await expectUnsealable(world, xrefSizePdf(), 'xref_size', 'a trailer /Size of 8,388,608');
  assert.deepEqual([record.refs, record.refs_total], [[], 0], 'xref_size names no object: the trailer is not one');
});

test('[EA-07] page_box: a page coordinate above 1,000,000 points or a page side under one centipoint is refused', async (t) => {
  const world = await sealWorld(t);
  await expectUnsealable(world, pageBoxCoordinatePdf(), 'page_box', 'a MediaBox coordinate of 1,000,001');
  await expectUnsealable(world, pageBoxSidePdf(), 'page_box', 'a page side of 0.004 point');
});

test('[EA-07] the upload_unsealable record is bounded: a refusal naming more than 16 objects logs exactly the first 16 and their true total, and no forbidden member', async (t) => {
  const world = await sealWorld(t);
  assert.equal(MAX_LOGGED_REFS, 16, 'the ruled cap (request #57 (3))');
  const { record } = await expectUnsealable(world, manyPageBoxesPdf(), 'page_box', `page_box on ${MANY_PAGE_BOX_PAGES} pages`);
  assert.equal(record.refs_total, MANY_PAGE_BOX_PAGES, 'the true total: every page');
  assert.equal(record.refs.length, MAX_LOGGED_REFS, 'exactly 16 references');
  assert.deepEqual(record.refs, Array.from({ length: MAX_LOGGED_REFS }, (_, index) => [index + 3, 0]), 'the first 16 by object number, [3, 0] .. [18, 0]');
  // No forbidden member: the record's members are exactly the ruled ones (assertBoundedRecord),
  // refs is its only structured value and holds integers only, and every string value is one of
  // its six string members, none of them document content.
  assert.deepEqual(Object.entries(record).filter(([, value]) => typeof value === 'object').map(([key]) => key), ['refs'], 'refs is the only structured member');
  assert.ok(record.refs.flat().every((n) => typeof n === 'number'), 'refs hold numbers only, never a name or string');
  assert.deepEqual(Object.entries(record).filter(([, value]) => typeof value === 'string').map(([key]) => key).sort(), ['correlation_id', 'detail', 'envelope_id', 'event', 'level', 'time'], 'the only strings are the record\'s own');
});

test('[EA-07] name_character: a NUL in a name or in a dictionary key is refused', async (t) => {
  const world = await sealWorld(t);
  await expectUnsealable(world, nulNamePdf(), 'name_character', 'a NUL in a name');
  await expectUnsealable(world, nulKeyPdf(), 'name_character', 'a NUL in a dictionary key');
});

test('[EA-07] sealable documents still upload: a form document with boundary numbers, and a shared-array base under the bound, are accepted, stored and recorded', async (t) => {
  const world = await sealWorld(t);
  const controls = [
    ['a form document with numbers just inside the plain-decimal range', sealableFormPdf()],
    ['a shared-array base under MAX_SEALED_PDF_BYTES', sharedArrayPdf(UNDER_BOUND_NAMES)],
  ];
  for (const [what, pdf] of controls) {
    const draft = await createEnvelope(world);
    const ticket = parses();
    const logged = world.logged('upload_unsealable').length;
    const response = await uploadRequest(world, { envelope: draft, pdf });
    assert.equal(response.status, 200, `${what}: accepted (${response.json?.code ?? 'no code'} ${JSON.stringify(response.json?.details ?? [])})`);
    assert.deepEqual(contractErrors('Envelope', response.json), [], `${what}: the body is a contract Envelope`);
    assert.equal(response.json.version, 2, `${what}: version + 1`);
    assert.equal(response.json.document.digest, sha256(pdf), `${what}: the document digest`);
    assert.equal(parses(), ticket + 1, `${what}: one parse`);
    assert.equal(world.logged('upload_unsealable').length, logged, `${what}: no refusal logged`);
    assert.equal(world.blobs.check(ALPHA, sha256(pdf)), 'ok', `${what}: the exact bytes are stored`);
    assert.equal(world.rows('document_revisions', 'WHERE envelope_id = ?', [draft.id]).length, 1, `${what}: one revision recorded`);
  }
});

test('[EA-07] first refusal wins: pre-parse refusals come first, then the parse service, then the predicate, whose first refusal in SEAL_REFUSAL_DETAILS order is the one detail', async (t) => {
  const world = await sealWorld(t);
  const pdf = manyRefusalsPdf();

  // The material: the parse service accepts it, and the predicate lists seven refusals, each
  // once, in SEAL_REFUSAL_DETAILS order.
  const outcome = await parsePdf(pdf);
  assert.equal(outcome.ok, true, 'the parse service accepts the seven-refusal document');
  const { details } = sealabilityOf(outcome.report);
  assert.deepEqual(details, SEAL_REFUSAL_DETAILS.filter((detail) => MANY_REFUSALS.includes(detail)), 'seven refusals, once each, in SEAL_REFUSAL_DETAILS order');
  assert.equal(details[0], 'number_range', 'whose first is number_range');

  // Pre-parse: a stale If-Match is 409 version_conflict, and nothing is parsed or judged.
  const draft = await createEnvelope(world);
  let ticket = parses();
  const stale = await uploadRequest(world, { envelope: draft, pdf, ifMatch: 2 });
  assert.deepEqual([stale.status, stale.json?.code], [409, 'version_conflict'], 'the pre-parse version check answers first');
  assert.equal(parses(), ticket, 'a pre-parse refusal never reaches the parse service or the predicate');

  // The parse service before the predicate: its own refusal answers, never an EA-07 detail.
  // A dangling /AcroForm is T033's malformed, as ruled (request #46 Part C(3)).
  const parseRefusals = [
    ['a cropped page that also holds an exponent-form number', croppedExponentPdf(), 'cropbox_differs'],
    ['an /AcroForm reference to a free object', danglingAcroFormPdf(), 'malformed'],
  ];
  for (const [what, doc, code] of parseRefusals) {
    ticket = parses();
    const answer = await uploadRequest(world, { envelope: draft, pdf: doc });
    assert.deepEqual([answer.status, answer.json?.code], [422, 'unsupported_pdf'], what);
    assert.deepEqual(answer.json?.details, [{ field: 'document', code }], `${what}: the parse service's refusal is the detail`);
    assert.equal(parses(), ticket + 1, `${what}: parsed once`);
  }

  // Within the predicate: its first refusal is the one detail, and nothing is stored. The one
  // record names that refusal only: number_range on page 1 (object 3).
  const { record } = await expectUnsealable(world, pdf, details[0], 'the seven-refusal document');
  assert.deepEqual([record.refs, record.refs_total], [[[3, 0]], 1], 'the record holds the first refusal\'s references only');
});

test('[EA-07] a refused upload leaves no blob and no state, and its Idempotency-Key stays new: the same key is judged again, then takes a sealable document', async (t) => {
  const world = await sealWorld(t);
  const refused = exponentPagePdf();
  const { draft, key } = await expectUnsealable(world, refused, 'number_range', 'the first refused upload');
  const uploadRecords = () => world.rows('idempotency_records', 'WHERE route = ? AND key = ?', ['uploadDocument', key]).length;
  assert.equal(uploadRecords(), 0, 'the refusal recorded no response under its key');

  // The same key and the same refused document: there is no record to replay, so the
  // document is parsed and refused again.
  let ticket = parses();
  const again = await uploadRequest(world, { envelope: draft, pdf: refused, key });
  assert.deepEqual([again.status, again.json?.details], [422, [{ field: 'document', code: 'number_range' }]], 'refused again, with the same detail');
  assert.equal(parses(), ticket + 1, 'judged again (parsed), not replayed');
  assert.equal(uploadRecords(), 0, 'still no record');

  // The same key with a sealable document: accepted, as under a new key.
  const sealable = sealableFormPdf();
  ticket = parses();
  const accepted = await uploadRequest(world, { envelope: draft, pdf: sealable, key });
  assert.equal(accepted.status, 200, `the key was not consumed by the refusals (${accepted.json?.code ?? 'no code'})`);
  assert.equal(accepted.json.version, 2);
  assert.equal(parses(), ticket + 1);
  assert.equal(uploadRecords(), 1, 'the accepted upload recorded its response');

  // Now the key has a record (request #16). The same request replays without a parse, and the
  // refused document under it is 409 idempotency_conflict without a parse, so it never
  // reaches the predicate.
  ticket = parses();
  const replay = await uploadRequest(world, { envelope: draft, pdf: sealable, key, ifMatch: 1 });
  assert.equal(replay.status, 200, 'the recorded upload replays');
  assert.ok(replay.bytes.equals(accepted.bytes), 'with the exact stored bytes');
  const conflict = await uploadRequest(world, { envelope: draft, pdf: refused, key, ifMatch: 1 });
  assert.deepEqual([conflict.status, conflict.json?.code], [409, 'idempotency_conflict'], 'a different document under a recorded key');
  assert.equal(parses(), ticket, 'a recorded key is resolved before any parse');
});

test("[EA-07] T036's predicate is used through one adapter that imports bounds.ts only, on the live parse report, before the blob is stored or anything is recorded", () => {
  const dir = join(REPO, 'src', 'api', 'envelopes');
  const sources = new Map(
    readdirSync(dir)
      .filter((name) => name.endsWith('.ts'))
      .map((name) => [name, readFileSync(join(dir, name), 'utf8')]),
  );
  const specifiers = [...sources].flatMap(([name, text]) => [...text.matchAll(/from\s+'([^']*cryptograph\/compose[^']*)'/g)].map((match) => [name, match[1]]));
  for (const [name, specifier] of specifiers) assert.equal(specifier, '../../cryptograph/compose/bounds.ts', `${name}: the composer is reached through bounds.ts only, never compose/index.ts`);
  assert.ok(specifiers.some(([name]) => name === 'sealable.ts'), 'the adapter imports bounds.ts');
  for (const name of ['api.ts', 'handlers.ts', 'index.ts', 'request.ts', 'uploads.ts']) {
    assert.ok(!specifiers.some(([file]) => file === name), `${name} reaches the predicate only through the adapter`);
  }
  const api = sources.get('api.ts') ?? '';
  const start = api.indexOf('async upload(');
  const end = api.indexOf('#uploadPrecheck(principal: OperatorPrincipal');
  assert.ok(start > 0 && end > start, 'upload() is found in api.ts');
  const upload = api.slice(start, end);
  const check = upload.indexOf('sealabilityRefusal(outcome.report)');
  assert.ok(check > 0, 'upload() runs the adapter on the live report (outcome.report)');
  assert.equal(upload.split('sealabilityRefusal(').length - 1, 1, 'exactly once');
  const store = upload.indexOf('this.#blobs.put(');
  const record = upload.indexOf('this.#mutate(');
  assert.ok(store > check, 'before the blob is stored');
  assert.ok(record > check, 'and before the domain records anything');
});
