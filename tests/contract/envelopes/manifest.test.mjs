// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006), kind harness: the conformance manifest.
//   EC-04 frozen structure and counts (T034 consumes the manifest with a count check)
//   EC-05 well-formed cases and preconditions ("givens")
//   EC-ENV-nn / EC-VER-nn / EC-LIM-nn / EC-PDF-nn: one derivation test per case.
//     Each proves, against the vendored contract only, that
//       - every basis quote appears verbatim at its JSON pointer;
//       - the principal may call the operation (x-opensig-role-matrix);
//       - an accepting case is defect-free and expects the operation's declared 2xx,
//         and each body assertion names a path of the response schema with a
//         value that schema allows;
//       - a rejecting case carries exactly its one declared defect, expects the
//         outcome the contract assigns to it (status declared for the operation,
//         code named by that response's description, body valid as Error).
// Harness checks only: never success-criterion evidence, never runtime acceptance.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { declaredResponse, deref, getOperation, loadVendoredContract, operationIndex, resolvePointer, responseSchema, successStatus } from './lib/contract.mjs';
import { createContext, materialize, pathTokens, pdfFindings, requestFindings, resolvePlaceholders } from './lib/harness.mjs';
import { expectedOutcome, FIXTURE_CATEGORIES, loadManifest, manifestProblems } from './lib/manifest.mjs';
import { buildPdf, inspectPdf } from './lib/pdf.mjs';
import { deepEqual, validate } from './lib/schema.mjs';

/** Frozen manifest shape. Changing a count is a manifest change that T034's count check must see. */
const FROZEN_COUNTS = Object.freeze({ envelope: 29, version: 17, 'upload-limit': 7, 'unsupported-pdf': 19 });
const FROZEN_TOTAL = 72;

const { doc } = loadVendoredContract();
const index = operationIndex(doc);
const manifest = loadManifest();

const REQUEST_LEVEL = new Set(['body-schema', 'body-syntax', 'header-missing', 'header-invalid', 'path-parameter', 'media-type', 'body-too-large']);

/** A synthetic arranged envelope for derivation: create = version 1, +1 per upload and per prepare. */
function derivationContext(c) {
  if (c.given === null) return createContext(null);
  const given = manifest.index.givens[c.given];
  return createContext({ envelope_id: 'derivationEnvelope0001', version: 1 + (given.document ? 1 : 0) + (given.prepare ? 1 : 0) });
}

function expandSchemas(list) {
  const out = [];
  for (const schema of list) {
    const resolved = deref(doc, schema);
    if (Array.isArray(resolved.oneOf)) out.push(...expandSchemas(resolved.oneOf));
    else out.push(resolved);
  }
  return out;
}

/** Candidate subschemas at an assertion path (oneOf branches expanded), or [] when the path is not in the schema. */
function subschemasAt(schema, tokens) {
  let candidates = [schema];
  for (const token of tokens) {
    const next = [];
    for (const candidate of expandSchemas(candidates)) {
      if (typeof token === 'number') {
        if (candidate.items !== undefined) next.push(candidate.items);
      } else if (candidate.properties && Object.hasOwn(candidate.properties, token)) {
        next.push(candidate.properties[token]);
      }
    }
    if (next.length === 0) return [];
    candidates = next;
  }
  return candidates;
}

function checkQuote(quote) {
  const target = resolvePointer(doc, quote.pointer);
  assert.notEqual(target, undefined, `basis pointer ${quote.pointer} does not resolve in the vendored contract`);
  if (Object.hasOwn(quote, 'text')) {
    assert.equal(typeof target, 'string', `basis pointer ${quote.pointer} is not text`);
    assert.ok(target.includes(quote.text), `contract text at ${quote.pointer} does not contain ${JSON.stringify(quote.text)}`);
  } else {
    assert.ok(deepEqual(target, quote.value), `contract value at ${quote.pointer} is ${JSON.stringify(target)}, not ${JSON.stringify(quote.value)}`);
  }
}

function ordinalRuleHolds(recipients) {
  const ordinals = (recipients ?? []).map((r) => r.ordinal);
  return deepEqual(ordinals, [1]) || deepEqual(ordinals, [1, 2]);
}

function rectWithinBounds(rect) {
  return rect.x + rect.width <= 1 && rect.y + rect.height <= 1;
}

function jsonBody(request) {
  return JSON.parse(request.body.toString('utf8'));
}

test('[EC-04] the manifest structure and case counts are frozen and documented', () => {
  assert.equal(manifest.index.kind, 'harness');
  assert.match(manifest.index.evidence_scope, /never success-criterion evidence and never runtime acceptance/);
  assert.match(manifest.index.acceptance, /^provisional/);
  assert.deepEqual(manifest.index.limits, { json_body_bytes: 262144, pdf_body_bytes: 10485760, pdf_pages: 50 });
  assert.deepEqual(
    Object.fromEntries(manifest.fixtures.map((f) => [f.category, f.cases.length])),
    FROZEN_COUNTS,
    'per-fixture case counts changed: update the frozen counts, fixtures/synthetic/envelopes/README.md and every consumer count check together',
  );
  assert.deepEqual(Object.fromEntries(manifest.index.fixtures.map((f) => [f.category, f.cases])), FROZEN_COUNTS);
  assert.equal(manifest.total, FROZEN_TOTAL);
  assert.equal(manifest.cases.length, FROZEN_TOTAL);
  for (const fixture of manifest.fixtures) {
    const prefix = FIXTURE_CATEGORIES[fixture.category];
    const ids = fixture.cases.map((c) => c.id);
    const expectedIds = fixture.cases.map((_, i) => `${prefix}-${String(i + 1).padStart(2, '0')}`);
    assert.deepEqual(ids, expectedIds, `${fixture.file}: case ids must run ${prefix}-01.. without gaps, in file order`);
    const accepting = fixture.cases.filter((c) => c.expect.status >= 200 && c.expect.status < 300).length;
    const rejecting = fixture.cases.length - accepting;
    assert.ok(accepting >= 1, `${fixture.file} needs an accepting case (so a reject-everything subject fails it)`);
    assert.ok(rejecting >= 1, `${fixture.file} needs a rejecting case (so an accept-everything subject fails it)`);
  }
});

test('[EC-05] every case and precondition is well formed and contract-valid', () => {
  assert.deepEqual(manifestProblems(manifest), []);
  const createSchema = resolvePointer(doc, '#/components/schemas/EnvelopeCreate');
  const prepareSchema = resolvePointer(doc, '#/components/schemas/Prepare');
  const roles = doc['x-opensig-role-matrix'];
  for (const [name, given] of Object.entries(manifest.index.givens)) {
    assert.deepEqual(validate(doc, createSchema, given.create), [], `given ${name}: create body`);
    assert.ok(ordinalRuleHolds(given.create.recipients), `given ${name}: ordinals must be exactly 1 or 1..2`);
    for (const operationId of ['createEnvelope', 'uploadDocument', 'prepareEnvelope']) {
      assert.ok(roles[operationId].roles.includes(given.principal), `given ${name}: ${given.principal} may not call ${operationId}`);
    }
    if (given.document) {
      const report = inspectPdf(buildPdf(given.document));
      assert.ok(report.ok, `given ${name}: document is not a well-formed PDF`);
      assert.deepEqual(report.features, [], `given ${name}: document carries unsupported features`);
    }
    if (given.prepare) {
      assert.deepEqual(validate(doc, prepareSchema, { expected_version: 1, fields: given.prepare }), [], `given ${name}: prepare fields`);
      for (const field of given.prepare) assert.ok(rectWithinBounds(field.rect), `given ${name}: field ${field.key} out of bounds`);
      for (const recipient of given.create.recipients) {
        assert.ok(
          given.prepare.some((f) => f.recipient_ordinal === recipient.ordinal && f.type === 'signature'),
          `given ${name}: recipient ${recipient.ordinal} needs a signature field`,
        );
      }
    }
  }
});

for (const c of manifest.cases) {
  test(`[${c.id}] ${c.title}`, () => {
    const entry = getOperation(index, c.request.operationId);
    for (const quote of c.basis) checkQuote(quote);
    const principal = c.request.principal ?? 'sender';
    assert.ok(doc['x-opensig-role-matrix'][entry.operationId].roles.includes(principal), `${principal} may not call ${entry.operationId}`);

    const ctx = derivationContext(c);
    const { request, pathValues, info } = materialize(c, index, ctx);
    ctx.upload_sha256 = info.sha256;
    ctx.upload_bytes = info.length;
    const findings = requestFindings(doc, entry, request, pathValues);
    const contentType = String(request.headers['content-type'] ?? '').split(';')[0];
    const pdf = info.kind === 'pdf' && contentType === 'application/pdf' ? pdfFindings(request.body) : [];

    if (c.expect.status >= 200 && c.expect.status < 300) {
      assert.equal(c.expect.status, successStatus(entry), `${entry.operationId} declares ${successStatus(entry)} as its success status`);
      assert.deepEqual(findings, [], 'an accepting case must be a contract-valid request');
      assert.deepEqual(pdf, [], 'an accepting upload must be a clean, well-formed PDF');
      if (entry.operationId === 'createEnvelope') assert.ok(ordinalRuleHolds(jsonBody(request).recipients), 'ordinals must be exactly 1 or 1..2');
      if (entry.operationId === 'prepareEnvelope') for (const field of jsonBody(request).fields) assert.ok(rectWithinBounds(field.rect));
      const schema = responseSchema(doc, entry, c.expect.status);
      assert.ok(schema, 'the success response has a JSON schema');
      assert.ok((c.expect.body ?? []).length > 0, 'an accepting case asserts at least one body property');
      for (const assertion of c.expect.body) {
        const candidates = expandSchemas(subschemasAt(schema, pathTokens(assertion.path)));
        assert.ok(candidates.length > 0, `assertion path ${assertion.path} is not in the ${entry.operationId} response schema`);
        if (Object.hasOwn(assertion, 'equals')) {
          const want = resolvePlaceholders(assertion.equals, ctx);
          assert.ok(candidates.some((s) => validate(doc, s, want).length === 0), `${assertion.path}: the schema does not allow ${JSON.stringify(want)}`);
        } else if (Object.hasOwn(assertion, 'notEquals')) {
          assert.ok(candidates.some((s) => s.type !== 'null'), `${assertion.path}: the schema allows only null`);
        } else if (Object.hasOwn(assertion, 'greaterThan')) {
          assert.ok(candidates.some((s) => s.type === 'integer' || s.type === 'number'), `${assertion.path}: not numeric`);
        } else {
          assert.ok(
            candidates.some((s) => s.type === 'array' && (s.minItems ?? 0) <= assertion.length && assertion.length <= (s.maxItems ?? Infinity)),
            `${assertion.path}: the schema does not allow ${assertion.length} items`,
          );
        }
      }
      return;
    }

    // Rejecting case: the contract's outcome for its single defect.
    const outcome = expectedOutcome(c.defect);
    assert.equal(c.expect.status, outcome.status);
    assert.equal(c.expect.code, outcome.code);
    assert.deepEqual(c.expect.detailCodes ?? [], outcome.detailCodes);
    const declared = declaredResponse(doc, entry, c.expect.status);
    assert.ok(declared, `${entry.operationId} does not declare ${c.expect.status}`);
    assert.ok(declared.ref, `${entry.operationId} ${c.expect.status} is not a shared component response`);
    assert.ok(declared.response.description.includes(c.expect.code), `components/responses/${declared.ref} does not name ${c.expect.code}`);
    const errorBody = { code: c.expect.code, correlation_id: 'derivation0001', details: (c.expect.detailCodes ?? []).map((code) => ({ field: 'document', code })) };
    assert.deepEqual(validate(doc, responseSchema(doc, entry, c.expect.status), errorBody), [], 'the expected error must be a valid Error body');

    const kind = c.defect.kind;
    if (REQUEST_LEVEL.has(kind)) {
      const name = c.defect.header ?? c.defect.parameter;
      assert.deepEqual(findings, [name === undefined ? { kind } : { kind, name }], `the request must carry exactly the ${kind} defect`);
      if (kind !== 'media-type') assert.deepEqual(pdf, [], 'no PDF defect besides the declared one');
      return;
    }
    assert.deepEqual(findings, [], `a ${kind} case must be a contract-valid request apart from its defect`);
    switch (kind) {
      case 'body-rule':
        assert.equal(entry.operationId, 'createEnvelope');
        assert.equal(ordinalRuleHolds(jsonBody(request).recipients), false, 'the ordinal rule must be broken');
        break;
      case 'absent-resource':
        assert.equal(c.given, null, 'an absent resource is never arranged');
        assert.equal(pathValues[c.defect.parameter], ctx.absent_envelope_id);
        break;
      case 'version-mismatch': {
        const sent = entry.operationId === 'uploadDocument' ? Number(/^"(\d+)"$/.exec(request.headers['if-match'])?.[1]) : jsonBody(request).expected_version;
        assert.ok(Number.isInteger(sent) && sent >= 1, 'the version sent must be well formed');
        assert.notEqual(sent, ctx.version, 'the version sent must differ from the arranged version');
        break;
      }
      case 'state':
        assert.equal(manifest.index.givens[c.given].state, c.defect.state);
        assert.notEqual(c.defect.state, 'draft');
        break;
      case 'pdf-content':
        assert.deepEqual(pdf, [c.defect.feature], `the PDF must carry exactly the ${c.defect.feature} defect`);
        break;
      case 'field-bounds': {
        const fields = jsonBody(request).fields;
        assert.ok(fields.some((f) => !rectWithinBounds(f.rect)), 'a field rectangle must leave the page');
        break;
      }
      default:
        assert.fail(`unhandled defect kind ${kind}`);
    }
    if (kind !== 'pdf-content') assert.deepEqual(pdf, [], 'no PDF defect besides the declared one');
  });
}
