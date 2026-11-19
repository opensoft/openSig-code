// SPDX-License-Identifier: Apache-2.0
//
// VB-06, the bounds (A-010, request #44). The verifier restates the US2
// sealed-PDF bound, because src/verifier/ may not import T036 (VB-01); this test
// compares the two. Each structure limit is at least T033's limit for the same
// quantity, so the verifier reads any sealed file whose base the parse service
// accepted. Read-only imports of other modules' exported constants are not
// `files:` changes (request #43). This file stands alone, so the T036 export it
// names cannot stop the other VB-06 tests from loading.
//
// T036 exports MAX_SEALED_PDF_BYTES from src/cryptograph/compose/bounds.ts,
// which imports nothing (landed at b47c4ef; request #45 keeps this test as
// drafted). Numbers of up to 15 digits are T033's lexer rule (its readUnsigned),
// which no exported constant states, so it is asserted by value.
//
// Mutants killed here: a verifier bound that drifts from T036's; any structure
// limit below T033's (fewer sections, entries, nesting or inflate budget); a
// T033 limit added without a decision here; a file at the bound refused, or one
// byte over it evaluated; a restated T033 ceiling that is not T033's ceiling,
// or a verifier limit below one (request #58 (3)); and a header-skip bound below the input bound
// (request #56 B6: the assertion kills any such bound, the file whose one
// skipped run nearly fills the input bound kills one more than 1 KiB below it).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_SEALED_PDF_BYTES,
  readRevisionStructure,
  T033_PARSER_CEILINGS,
  VERIFIER_LIMITS,
  verifyPdf,
} from '../../../src/verifier/index.ts';
import { MAX_SEALED_PDF_BYTES as T036_MAX_SEALED_PDF_BYTES } from '../../../src/cryptograph/compose/bounds.ts';
import { DEFAULT_PARSER_LIMITS, MAX_DOCUMENT_BYTES, resolveParserLimits } from '../../../src/pdf/limits.ts';
import { checkOf } from './helpers/agreement.mjs';
import { buildBase } from './helpers/pdf-build.mjs';

// T033 quantity -> the verifier limit that must be at least it (plus the seal revision where noted).
const COUNTERPARTS = Object.freeze({
  maxBytes: (t033) => VERIFIER_LIMITS.maxInputBytes >= t033,
  maxXrefSections: (t033) => VERIFIER_LIMITS.maxRevisions >= t033 + 1,
  maxObjects: (t033) => VERIFIER_LIMITS.maxXrefEntries >= t033,
  maxDepth: (t033) => VERIFIER_LIMITS.maxNestingDepth >= t033,
  maxInflatedBytes: (t033) => VERIFIER_LIMITS.maxXrefInflatedBytes >= t033,
});
// T033 limits with no counterpart: pages are not read; no per-stream ratio is imposed, so none is stricter.
const NO_COUNTERPART = Object.freeze(['maxPages', 'maxRatio']);

test('[VB-06] the input bound equals T036 MAX_SEALED_PDF_BYTES (48 MiB)', () => {
  assert.equal(MAX_SEALED_PDF_BYTES, 50_331_648);
  assert.equal(MAX_SEALED_PDF_BYTES, T036_MAX_SEALED_PDF_BYTES);
  assert.equal(VERIFIER_LIMITS.maxInputBytes, MAX_SEALED_PDF_BYTES);
  assert.ok(MAX_SEALED_PDF_BYTES > MAX_DOCUMENT_BYTES);
});

test('[VB-06] each structure limit is at least T033 limit for the same quantity', () => {
  assert.deepEqual(Object.keys(DEFAULT_PARSER_LIMITS).sort(), [...Object.keys(COUNTERPARTS), ...NO_COUNTERPART].sort());
  for (const [quantity, atLeast] of Object.entries(COUNTERPARTS)) {
    assert.ok(atLeast(DEFAULT_PARSER_LIMITS[quantity]), `${quantity}: ${DEFAULT_PARSER_LIMITS[quantity]}`);
  }
  // T033's hard ceilings (PARSER_CEILINGS at code 909172b, not exported), which callers may raise to.
  assert.ok(VERIFIER_LIMITS.maxRevisions >= 256 + 1);
  assert.ok(VERIFIER_LIMITS.maxXrefEntries >= 1_000_000);
  assert.ok(VERIFIER_LIMITS.maxNestingDepth >= 256);
  // T033's readUnsigned reads 1 to 15 digits, leading zeros allowed (row T014-XREFSTART).
  assert.ok(VERIFIER_LIMITS.maxIntegerDigits >= 15);
});

/** A base of exactly `target` bytes: `build(padding)` grows with its padding. */
function sizedBase(target, build) {
  let padding = target - build(0).bytes.length;
  for (let i = 0; i < 4; i += 1) {
    const doc = build(padding);
    const delta = target - doc.bytes.length;
    if (delta === 0) return doc;
    padding += delta;
  }
  throw new Error('could not build a file of the exact size');
}

const baseOfSize = (target) => sizedBase(target, (padding) => buildBase({ contentPadding: padding }));

test('[VB-06] a file of exactly MAX_SEALED_PDF_BYTES is read; one byte more is outside the bound', () => {
  const atBound = baseOfSize(MAX_SEALED_PDF_BYTES);
  assert.equal(atBound.bytes.length, MAX_SEALED_PDF_BYTES);
  const structure = readRevisionStructure(atBound.bytes);
  assert.equal(structure.ok, true, structure.ok ? '' : structure.detail);
  const outcome = verifyPdf(atBound.bytes, { validationTime: new Date() });
  assert.equal(checkOf(outcome, 'input-size').result, 'pass');
  assert.equal(checkOf(outcome, 'revision-structure').result, 'pass');
  assert.equal(outcome.integrity, 'invalid', 'it carries no seal');
  const over = baseOfSize(MAX_SEALED_PDF_BYTES + 1);
  const overStructure = readRevisionStructure(over.bytes);
  assert.equal(overStructure.ok, false);
  assert.equal(overStructure.detail, 'input-too-large');
  const overOutcome = verifyPdf(over.bytes, { validationTime: new Date() });
  assert.equal(overOutcome.integrity, 'indeterminate');
  assert.equal(checkOf(overOutcome, 'input-size').detail, 'input-too-large');
});

test('[VB-06] the header-skip bound is at least MAX_SEALED_PDF_BYTES (request #56 B6)', () => {
  assert.ok(VERIFIER_LIMITS.maxHeaderSkipBytes >= MAX_SEALED_PDF_BYTES, `${VERIFIER_LIMITS.maxHeaderSkipBytes}`);
  assert.ok(VERIFIER_LIMITS.maxHeaderSkipBytes >= T036_MAX_SEALED_PDF_BYTES);
  // One comment before object 1, named by its entry, so the entry check skips
  // nearly the whole file in one run.
  const doc = sizedBase(MAX_SEALED_PDF_BYTES, (padding) =>
    buildBase({ commentBeforeObjects: true, pointAtComment: true, commentPadding: padding }),
  );
  assert.equal(doc.bytes.length, MAX_SEALED_PDF_BYTES);
  const run = doc.bytes.indexOf('1 0 obj') - doc.bytes.indexOf('% a synthetic note');
  assert.ok(run > MAX_SEALED_PDF_BYTES - 1024, `the skipped run is ${run} bytes`);
  const structure = readRevisionStructure(doc.bytes);
  assert.equal(structure.ok, true, structure.ok ? '' : structure.detail);
});

test('[VB-06] each restated T033 ceiling is proven against resolveParserLimits, and each verifier limit is at least it (request #58 (3))', () => {
  assert.deepEqual(Object.keys(T033_PARSER_CEILINGS).sort(), ['maxDepth', 'maxInflatedBytes', 'maxObjects', 'maxRatio', 'maxXrefSections']);
  // T033 exports no ceilings; resolveParserLimits accepts an override up to its ceiling and throws above it.
  for (const [key, ceiling] of Object.entries(T033_PARSER_CEILINGS)) {
    assert.doesNotThrow(() => resolveParserLimits({ [key]: ceiling }), key);
    assert.throws(() => resolveParserLimits({ [key]: ceiling + 1 }), TypeError, key);
  }
  assert.ok(VERIFIER_LIMITS.maxRevisions >= T033_PARSER_CEILINGS.maxXrefSections + 1);
  assert.ok(VERIFIER_LIMITS.maxXrefEntries >= T033_PARSER_CEILINGS.maxObjects);
  assert.ok(VERIFIER_LIMITS.maxNestingDepth >= T033_PARSER_CEILINGS.maxDepth);
  assert.ok(VERIFIER_LIMITS.maxXrefInflatedBytes >= T033_PARSER_CEILINGS.maxInflatedBytes);
  // T033 caps no container below the input, and reads number tokens of up to 32 characters.
  assert.equal(VERIFIER_LIMITS.maxContainerItems, MAX_SEALED_PDF_BYTES);
  assert.equal(VERIFIER_LIMITS.maxNumberChars, 32);
});
