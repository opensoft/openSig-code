// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006): a minimal JSON Schema 2020-12 validator
// for the keyword subset the vendored contract uses. It is test-local and fails
// closed: a schema keyword it does not implement throws instead of passing.
// "format" is an annotation in 2020-12 and is not asserted.

import { deref } from './contract.mjs';

/** Keywords that only annotate; they never change the validation outcome. */
export const ANNOTATION_KEYWORDS = Object.freeze([
  'description',
  'format',
  'contentMediaType',
  'title',
  'examples',
  'default',
  'deprecated',
  'readOnly',
  'writeOnly',
  '$comment',
]);

/** Keywords this validator asserts. */
export const ASSERTION_KEYWORDS = Object.freeze([
  '$ref',
  'type',
  'enum',
  'const',
  'properties',
  'required',
  'additionalProperties',
  'pattern',
  'minLength',
  'maxLength',
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'items',
  'prefixItems',
  'minItems',
  'maxItems',
  'uniqueItems',
  'oneOf',
  'anyOf',
  'allOf',
]);

const KNOWN = new Set([...ANNOTATION_KEYWORDS, ...ASSERTION_KEYWORDS]);

export function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((v, i) => deepEqual(v, b[i]));
  if (typeof a === 'object') {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    return deepEqual(ka, kb) && ka.every((k) => deepEqual(a[k], b[k]));
  }
  return false;
}

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value;
}

function matchesType(value, type) {
  const actual = typeOf(value);
  if (type === 'number') return actual === 'number' || actual === 'integer';
  return actual === type;
}

function isNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * Validate `value` against `schema` (resolved against `doc` for $ref).
 * Returns a list of error strings; an empty list means valid.
 */
export function validate(doc, schema, value, path = '$') {
  const errors = [];
  check(doc, schema, value, path, errors);
  return errors;
}

function check(doc, schema, value, path, errors) {
  if (schema === true) return;
  if (schema === false) {
    errors.push(`${path}: no value is allowed here`);
    return;
  }
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) throw new Error(`invalid schema at ${path}`);
  for (const keyword of Object.keys(schema)) {
    if (!KNOWN.has(keyword)) throw new Error(`unsupported schema keyword "${keyword}" at ${path}`);
  }
  if (typeof schema.$ref === 'string') check(doc, deref(doc, { $ref: schema.$ref }), value, path, errors);

  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((t) => matchesType(value, t))) {
      errors.push(`${path}: expected type ${types.join('|')}, found ${typeOf(value)}`);
      return;
    }
  }
  if (schema.enum !== undefined && !schema.enum.some((option) => deepEqual(option, value))) {
    errors.push(`${path}: value is not one of the enumerated values`);
  }
  if (Object.hasOwn(schema, 'const') && !deepEqual(schema.const, value)) errors.push(`${path}: value differs from the constant`);

  if (typeof value === 'string') {
    const length = [...value].length;
    if (schema.minLength !== undefined && length < schema.minLength) errors.push(`${path}: shorter than ${schema.minLength}`);
    if (schema.maxLength !== undefined && length > schema.maxLength) errors.push(`${path}: longer than ${schema.maxLength}`);
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(value)) errors.push(`${path}: does not match ${schema.pattern}`);
  }
  if (isNumber(value)) {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${path}: below minimum ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${path}: above maximum ${schema.maximum}`);
    if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) errors.push(`${path}: not above ${schema.exclusiveMinimum}`);
    if (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum) errors.push(`${path}: not below ${schema.exclusiveMaximum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errors.push(`${path}: fewer than ${schema.minItems} items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${path}: more than ${schema.maxItems} items`);
    const prefix = schema.prefixItems ?? [];
    prefix.forEach((itemSchema, i) => {
      if (i < value.length) check(doc, itemSchema, value[i], `${path}[${i}]`, errors);
    });
    if (schema.items !== undefined) {
      for (let i = prefix.length; i < value.length; i += 1) check(doc, schema.items, value[i], `${path}[${i}]`, errors);
    }
    if (schema.uniqueItems === true) {
      for (let i = 0; i < value.length; i += 1) {
        for (let j = i + 1; j < value.length; j += 1) {
          if (deepEqual(value[i], value[j])) errors.push(`${path}: items ${i} and ${j} are equal`);
        }
      }
    }
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const name of schema.required ?? []) {
      if (!Object.hasOwn(value, name)) errors.push(`${path}: missing required property ${name}`);
    }
    const properties = schema.properties ?? {};
    for (const [name, item] of Object.entries(value)) {
      if (Object.hasOwn(properties, name)) check(doc, properties[name], item, `${path}.${name}`, errors);
      else if (schema.additionalProperties === false) errors.push(`${path}: unknown property ${name}`);
      else if (schema.additionalProperties !== undefined && schema.additionalProperties !== true) {
        check(doc, schema.additionalProperties, item, `${path}.${name}`, errors);
      }
    }
  }
  if (schema.allOf !== undefined) for (const sub of schema.allOf) check(doc, sub, value, path, errors);
  if (schema.anyOf !== undefined && !schema.anyOf.some((sub) => validate(doc, sub, value, path).length === 0)) {
    errors.push(`${path}: matches none of anyOf`);
  }
  if (schema.oneOf !== undefined) {
    const passing = schema.oneOf.filter((sub) => validate(doc, sub, value, path).length === 0).length;
    if (passing !== 1) errors.push(`${path}: matches ${passing} of oneOf (exactly one required)`);
  }
}

/**
 * Every keyword used by schema objects reachable from the contract's schema
 * locations: component schemas, parameter schemas, request and response
 * media-type schemas, and header schemas.
 */
export function contractSchemaKeywords(doc) {
  const found = new Set();
  const visit = (schema) => {
    if (schema === true || schema === false || schema === null || typeof schema !== 'object' || Array.isArray(schema)) return;
    for (const [keyword, value] of Object.entries(schema)) {
      found.add(keyword);
      if (['properties'].includes(keyword)) for (const sub of Object.values(value)) visit(sub);
      else if (['items', 'additionalProperties'].includes(keyword)) visit(value);
      else if (['prefixItems', 'oneOf', 'anyOf', 'allOf'].includes(keyword)) for (const sub of value) visit(sub);
    }
  };
  for (const schema of Object.values(doc.components?.schemas ?? {})) visit(schema);
  for (const parameter of Object.values(doc.components?.parameters ?? {})) visit(parameter.schema);
  const visitContent = (content) => {
    for (const media of Object.values(content ?? {})) visit(media.schema);
  };
  const visitHeaders = (headers) => {
    for (const header of Object.values(headers ?? {})) visit(header.schema);
  };
  for (const response of Object.values(doc.components?.responses ?? {})) {
    visitContent(response.content);
    visitHeaders(response.headers);
  }
  const visitOperation = (operation) => {
    for (const parameter of operation.parameters ?? []) if (parameter.schema) visit(parameter.schema);
    if (operation.requestBody?.content) visitContent(operation.requestBody.content);
    for (const response of Object.values(operation.responses ?? {})) {
      visitContent(response.content);
      visitHeaders(response.headers);
    }
  };
  for (const item of [...Object.values(doc.paths ?? {}), ...Object.values(doc.webhooks ?? {})]) {
    for (const parameter of item.parameters ?? []) if (parameter.schema) visit(parameter.schema);
    for (const [method, operation] of Object.entries(item)) {
      if (method !== 'parameters' && operation && typeof operation === 'object') visitOperation(operation);
    }
  }
  return found;
}
