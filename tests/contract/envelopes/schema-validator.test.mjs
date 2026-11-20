// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006), kind harness: the test-local schema validator.
//   EC-11 it implements every keyword the vendored contract's schemas use, and fails closed on others
//   EC-12 it asserts each keyword with JSON Schema 2020-12 semantics

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { loadVendoredContract, resolvePointer } from './lib/contract.mjs';
import { ANNOTATION_KEYWORDS, ASSERTION_KEYWORDS, contractSchemaKeywords, validate } from './lib/schema.mjs';

const { doc } = loadVendoredContract();

test('[EC-11] the validator implements every keyword the contract schemas use and fails closed on others', () => {
  const used = contractSchemaKeywords(doc);
  const known = new Set([...ANNOTATION_KEYWORDS, ...ASSERTION_KEYWORDS]);
  const unknown = [...used].filter((k) => !known.has(k));
  assert.deepEqual(unknown, [], 'the contract uses schema keywords this validator does not implement');
  for (const keyword of ['$ref', 'type', 'enum', 'const', 'properties', 'required', 'additionalProperties', 'pattern', 'oneOf', 'items', 'prefixItems']) {
    assert.ok(used.has(keyword), `expected the contract to use ${keyword}`);
  }
  assert.throws(() => validate(doc, { patternProperties: {} }, {}), /unsupported schema keyword "patternProperties"/);
  assert.throws(() => validate(doc, { if: { type: 'string' } }, 'x'), /unsupported schema keyword "if"/);
  // Every component schema can be walked without an unsupported keyword.
  for (const name of Object.keys(doc.components.schemas)) {
    assert.doesNotThrow(() => validate(doc, { $ref: `#/components/schemas/${name}` }, {}), name);
  }
});

test('[EC-12] the validator asserts each keyword with JSON Schema 2020-12 semantics', () => {
  const error = { $ref: '#/components/schemas/Error' };
  assert.deepEqual(validate(doc, error, { code: 'not_found', correlation_id: 'abcd1234' }), []);
  assert.notDeepEqual(validate(doc, error, { code: 'not_found' }), [], 'required');
  assert.notDeepEqual(validate(doc, error, { code: 'nope', correlation_id: 'abcd1234' }), [], 'enum');
  assert.notDeepEqual(validate(doc, error, { code: 'not_found', correlation_id: 'abc' }), [], 'pattern');
  assert.notDeepEqual(validate(doc, error, { code: 'not_found', correlation_id: 'abcd1234', extra: 1 }), [], 'additionalProperties false');
  assert.notDeepEqual(validate(doc, error, { code: 'not_found', correlation_id: 'abcd1234', message: 'm'.repeat(201) }), [], 'maxLength');
  assert.notDeepEqual(validate(doc, error, { code: 'not_found', correlation_id: 'abcd1234', details: [{ field: 'x' }] }), [], 'nested required');

  // Types: integer versus number, null, and the oneOf [value, null] pattern used for nullable fields.
  assert.deepEqual(validate(doc, { type: 'integer' }, 3), []);
  assert.notDeepEqual(validate(doc, { type: 'integer' }, 1.5), []);
  assert.deepEqual(validate(doc, { type: 'number' }, 1.5), []);
  assert.deepEqual(validate(doc, { type: 'number' }, 2), []);
  assert.notDeepEqual(validate(doc, { type: 'integer' }, '1'), []);
  const nullableDigest = resolvePointer(doc, '#/components/schemas/Envelope/properties/manifest_digest');
  assert.deepEqual(validate(doc, nullableDigest, null), []);
  assert.deepEqual(validate(doc, nullableDigest, 'c'.repeat(64)), []);
  assert.notDeepEqual(validate(doc, nullableDigest, 'C'.repeat(64)), []);

  // oneOf needs exactly one passing branch.
  assert.notDeepEqual(validate(doc, { oneOf: [{ type: 'number' }, { type: 'integer' }] }, 2), [], 'two branches pass');
  assert.deepEqual(validate(doc, { oneOf: [{ type: 'number' }, { type: 'string' }] }, 2), []);
  assert.deepEqual(validate(doc, { anyOf: [{ type: 'number' }, { type: 'integer' }] }, 2), []);
  assert.notDeepEqual(validate(doc, { allOf: [{ type: 'number' }, { minimum: 3 }] }, 2), []);

  // Lengths count code points; patterns are Unicode-aware.
  assert.deepEqual(validate(doc, { type: 'string', maxLength: 2 }, '\u{1F600}\u{1F600}'), []);
  assert.notDeepEqual(validate(doc, { type: 'string', minLength: 3 }, '\u{1F600}\u{1F600}'), []);

  // Numeric bounds.
  assert.notDeepEqual(validate(doc, { exclusiveMinimum: 0 }, 0), []);
  assert.deepEqual(validate(doc, { exclusiveMinimum: 0 }, 0.001), []);
  assert.notDeepEqual(validate(doc, { exclusiveMaximum: 1 }, 1), []);
  assert.notDeepEqual(validate(doc, { maximum: 1 }, 1.0001), []);

  // Arrays: prefixItems, items, bounds, uniqueItems; const and deep enum.
  const point = { type: 'array', prefixItems: [{ type: 'number', minimum: 0, maximum: 1 }, { type: 'number', minimum: 0, maximum: 1 }], minItems: 2, maxItems: 2 };
  assert.deepEqual(validate(doc, point, [0.5, 0.25]), []);
  assert.notDeepEqual(validate(doc, point, [0.5, 1.5]), []);
  assert.notDeepEqual(validate(doc, point, [0.5]), []);
  assert.notDeepEqual(validate(doc, { type: 'array', uniqueItems: true }, [{ a: 1 }, { a: 1 }]), []);
  assert.notDeepEqual(validate(doc, { type: 'array', items: { type: 'string' } }, ['a', 2]), []);
  assert.deepEqual(validate(doc, { const: { a: [1, 2] } }, { a: [1, 2] }), []);
  assert.notDeepEqual(validate(doc, { const: true }, 'true'), []);
  assert.deepEqual(validate(doc, { enum: [{ b: 1, a: 2 }] }, { a: 2, b: 1 }), [], 'enum compares structurally, not by key order');

  // format is an annotation in 2020-12 and is not asserted.
  assert.deepEqual(validate(doc, { type: 'string', format: 'email' }, 'not-an-address'), []);
});
