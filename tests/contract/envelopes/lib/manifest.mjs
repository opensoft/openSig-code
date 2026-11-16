// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006): the conformance manifest.
//
// fixtures/synthetic/envelopes/manifest.json indexes four fixture files, one per
// category, and the named preconditions ("givens") cases refer to. Format,
// counts and the consumer contract are documented in
// fixtures/synthetic/envelopes/README.md. Kind: harness. The manifest is never
// success-criterion evidence and never runtime acceptance.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { REPO_ROOT } from './contract.mjs';

export const MANIFEST_DIR = 'fixtures/synthetic/envelopes';
export const MANIFEST_FILE = `${MANIFEST_DIR}/manifest.json`;
export const MANIFEST_SCHEMA = 'opensig.envelope-conformance-manifest/1';
export const FIXTURE_SCHEMA = 'opensig.envelope-conformance-fixture/1';

/** Fixture categories, in manifest order, with their case-id prefixes. */
export const FIXTURE_CATEGORIES = Object.freeze({
  envelope: 'EC-ENV',
  version: 'EC-VER',
  'upload-limit': 'EC-LIM',
  'unsupported-pdf': 'EC-PDF',
});

export const PRINCIPALS = Object.freeze(['sender', 'service']);
export const GIVEN_STATES = Object.freeze(['draft', 'prepared']);

/** PDF features a pdf-content defect may name; the names equal inspectPdf() feature names, plus "malformed". */
export const PDF_DEFECT_FEATURES = Object.freeze([
  'malformed',
  'pages-over-50',
  'encrypt',
  'signature',
  'javascript',
  'launch',
  'rich-media',
  'xfa',
  'embedded-file',
  'cropbox-differs',
]);

export const DEFECT_KINDS = Object.freeze([
  'body-schema',
  'body-syntax',
  'body-rule',
  'header-missing',
  'header-invalid',
  'path-parameter',
  'absent-resource',
  'version-mismatch',
  'state',
  'body-too-large',
  'media-type',
  'pdf-content',
  'field-bounds',
]);

/**
 * The outcome the contract assigns to each single defect: [status, error code, detail codes].
 * Every row is checked against the contract per case (status declared for the
 * operation; the code named by the declared response's description).
 */
export function expectedOutcome(defect) {
  switch (defect.kind) {
    case 'body-schema':
    case 'body-syntax':
    case 'body-rule':
    case 'header-invalid':
    case 'path-parameter':
      return { status: 400, code: 'invalid_request', detailCodes: [] };
    case 'header-missing':
      return defect.header === 'If-Match'
        ? { status: 428, code: 'precondition_required', detailCodes: [] }
        : { status: 400, code: 'invalid_request', detailCodes: [] };
    case 'absent-resource':
      return { status: 404, code: 'not_found', detailCodes: [] };
    case 'version-mismatch':
      return { status: 409, code: 'version_conflict', detailCodes: [] };
    case 'state':
      return { status: 409, code: 'state_conflict', detailCodes: [] };
    case 'body-too-large':
      return { status: 413, code: 'payload_too_large', detailCodes: [] };
    case 'media-type':
      return { status: 415, code: 'unsupported_media_type', detailCodes: [] };
    case 'pdf-content':
      return { status: 422, code: 'unsupported_pdf', detailCodes: defect.feature === 'cropbox-differs' ? ['cropbox_differs'] : [] };
    case 'field-bounds':
      return { status: 422, code: 'field_out_of_bounds', detailCodes: [] };
    default:
      throw new Error(`unknown defect kind ${defect.kind}`);
  }
}

/**
 * Load the manifest index and its fixture files.
 * Returns { index, fixtures: [{ category, file, declared, cases }], cases (all, in order), total }.
 */
export function loadManifest(root = REPO_ROOT) {
  const index = JSON.parse(readFileSync(join(root, MANIFEST_FILE), 'utf8'));
  const fixtures = (index.fixtures ?? []).map((entry) => {
    const data = JSON.parse(readFileSync(join(root, MANIFEST_DIR, entry.file), 'utf8'));
    return { category: entry.category, file: entry.file, declared: entry.cases, schema: data.schema, fileCategory: data.category, cases: data.cases ?? [] };
  });
  const cases = fixtures.flatMap((fixture) => fixture.cases.map((c) => ({ ...c, category: fixture.category })));
  return { index, fixtures, cases, total: index.total };
}

const CASE_KEYS = new Set(['id', 'title', 'given', 'request', 'defect', 'expect', 'basis']);
const REQUEST_KEYS = new Set(['operationId', 'principal', 'path', 'headers', 'body']);
const EXPECT_KEYS = new Set(['status', 'code', 'detailCodes', 'body']);
const ASSERTION_KEYS = new Set(['path', 'equals', 'notEquals', 'greaterThan', 'length']);
const BODY_FORMS = Object.freeze(['json', 'text', 'pdf']);

/** Structural problems of the loaded manifest (empty when well formed). Contract derivation is checked separately. */
export function manifestProblems(manifest) {
  const problems = [];
  const { index } = manifest;
  if (index.schema !== MANIFEST_SCHEMA) problems.push(`manifest schema must be ${MANIFEST_SCHEMA}`);
  if (index.kind !== 'harness') problems.push('manifest kind must be harness');
  const categories = manifest.fixtures.map((f) => f.category);
  if (JSON.stringify(categories) !== JSON.stringify(Object.keys(FIXTURE_CATEGORIES))) problems.push(`fixture categories must be ${Object.keys(FIXTURE_CATEGORIES).join(', ')} in order`);
  let sum = 0;
  for (const fixture of manifest.fixtures) {
    if (fixture.schema !== FIXTURE_SCHEMA) problems.push(`${fixture.file}: schema must be ${FIXTURE_SCHEMA}`);
    if (fixture.fileCategory !== fixture.category) problems.push(`${fixture.file}: category ${fixture.fileCategory} differs from the index entry ${fixture.category}`);
    if (fixture.declared !== fixture.cases.length) problems.push(`${fixture.file}: index declares ${fixture.declared} cases, file holds ${fixture.cases.length}`);
    sum += fixture.cases.length;
  }
  if (index.total !== sum) problems.push(`index total ${index.total} differs from the ${sum} cases present`);
  for (const [name, given] of Object.entries(index.givens ?? {})) {
    if (!GIVEN_STATES.includes(given.state)) problems.push(`given ${name}: unknown state ${given.state}`);
    if (!PRINCIPALS.includes(given.principal)) problems.push(`given ${name}: unknown principal ${given.principal}`);
    const implied = given.prepare ? 'prepared' : 'draft';
    if (given.state !== implied) problems.push(`given ${name}: state ${given.state} but its steps imply ${implied}`);
    if (given.prepare && !given.document) problems.push(`given ${name}: prepare needs a document`);
  }
  const seen = new Set();
  manifest.cases.forEach((c, position) => {
    const at = `case ${c.id ?? `#${position}`}`;
    for (const key of Object.keys(c)) if (!CASE_KEYS.has(key) && key !== 'category') problems.push(`${at}: unknown key ${key}`);
    const prefix = FIXTURE_CATEGORIES[c.category];
    if (typeof c.id !== 'string' || !new RegExp(`^${prefix}-\\d{2}$`).test(c.id)) problems.push(`${at}: id must be ${prefix}-NN in fixture ${c.category}`);
    if (seen.has(c.id)) problems.push(`${at}: duplicate id`);
    seen.add(c.id);
    if (typeof c.title !== 'string' || c.title.length < 8) problems.push(`${at}: needs a title`);
    if (c.given !== null && !Object.hasOwn(index.givens ?? {}, c.given)) problems.push(`${at}: unknown given ${c.given}`);
    const request = c.request ?? {};
    for (const key of Object.keys(request)) if (!REQUEST_KEYS.has(key)) problems.push(`${at}: unknown request key ${key}`);
    if (typeof request.operationId !== 'string') problems.push(`${at}: request.operationId is required`);
    if (request.principal !== undefined && !PRINCIPALS.includes(request.principal)) problems.push(`${at}: unknown principal ${request.principal}`);
    if (request.body !== undefined) {
      const forms = BODY_FORMS.filter((form) => Object.hasOwn(request.body, form));
      if (forms.length !== 1) problems.push(`${at}: request.body needs exactly one of ${BODY_FORMS.join(', ')}`);
    }
    const expect = c.expect ?? {};
    for (const key of Object.keys(expect)) if (!EXPECT_KEYS.has(key)) problems.push(`${at}: unknown expect key ${key}`);
    if (!Number.isInteger(expect.status)) problems.push(`${at}: expect.status must be an integer`);
    const positive = expect.status >= 200 && expect.status < 300;
    if (positive) {
      if (c.defect !== null) problems.push(`${at}: an accepting case has no defect`);
      if (expect.code !== undefined || expect.detailCodes !== undefined) problems.push(`${at}: an accepting case has no error code`);
      for (const assertion of expect.body ?? []) {
        for (const key of Object.keys(assertion)) if (!ASSERTION_KEYS.has(key)) problems.push(`${at}: unknown assertion key ${key}`);
        const matchers = ['equals', 'notEquals', 'greaterThan', 'length'].filter((m) => Object.hasOwn(assertion, m));
        if (typeof assertion.path !== 'string' || matchers.length !== 1) problems.push(`${at}: each body assertion needs a path and exactly one matcher`);
      }
    } else {
      if (!c.defect || !DEFECT_KINDS.includes(c.defect.kind)) problems.push(`${at}: a rejecting case names exactly one defect of a known kind`);
      if (typeof expect.code !== 'string') problems.push(`${at}: a rejecting case names an error code`);
      if (expect.body !== undefined) problems.push(`${at}: a rejecting case has no body assertions`);
      if (c.defect?.kind === 'pdf-content' && !PDF_DEFECT_FEATURES.includes(c.defect.feature)) problems.push(`${at}: unknown pdf feature ${c.defect.feature}`);
    }
    if (!Array.isArray(c.basis) || c.basis.length === 0) problems.push(`${at}: basis needs at least one contract quote`);
    for (const quote of c.basis ?? []) {
      const kinds = ['text', 'value'].filter((k) => Object.hasOwn(quote, k));
      if (typeof quote.pointer !== 'string' || kinds.length !== 1) problems.push(`${at}: each basis entry is {pointer, text} or {pointer, value}`);
    }
  });
  return problems;
}
