// SPDX-License-Identifier: Apache-2.0
//
// A test-local validator for the JSON Schema subset the vendored contract uses
// for VerificationReport (VB-02). It refuses any keyword it does not know, so a
// contract change it cannot judge fails the test instead of passing silently.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ANNOTATIONS = new Set(['description', 'title', 'examples', 'deprecated']);
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export function loadContractSchema(name) {
  const path = fileURLToPath(new URL('../../../../contracts/http-api.json', import.meta.url));
  const contract = JSON.parse(readFileSync(path, 'utf8'));
  const schema = contract.components?.schemas?.[name];
  if (schema === undefined) throw new Error(`the vendored contract has no schema ${name}`);
  return { contract, schema };
}

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (Number.isInteger(value)) return 'integer';
  return typeof value;
}

/** Every violation of `schema` by `value`, as `path: reason` strings. */
export function validate(schema, value, root, path = '$') {
  const errors = [];
  if (schema.$ref !== undefined) {
    const target = schema.$ref.replace(/^#\//, '').split('/').reduce((node, key) => node?.[key], root);
    if (target === undefined) return [`${path}: unresolved ${schema.$ref}`];
    return validate(target, value, root, path);
  }
  for (const keyword of Object.keys(schema)) {
    if (ANNOTATIONS.has(keyword)) continue;
    switch (keyword) {
      case 'type': {
        const types = Array.isArray(schema.type) ? schema.type : [schema.type];
        const actual = typeOf(value);
        if (!types.includes(actual) && !(actual === 'integer' && types.includes('number'))) errors.push(`${path}: type ${actual}`);
        break;
      }
      case 'const':
        if (value !== schema.const) errors.push(`${path}: not the constant`);
        break;
      case 'enum':
        if (!schema.enum.includes(value)) errors.push(`${path}: not in the enum`);
        break;
      case 'pattern':
        if (typeof value === 'string' && !new RegExp(schema.pattern, 'u').test(value)) errors.push(`${path}: pattern`);
        break;
      case 'maxLength':
        if (typeof value === 'string' && [...value].length > schema.maxLength) errors.push(`${path}: longer than ${schema.maxLength}`);
        break;
      case 'minLength':
        if (typeof value === 'string' && [...value].length < schema.minLength) errors.push(`${path}: shorter than ${schema.minLength}`);
        break;
      case 'format':
        if (schema.format === 'date-time') {
          if (typeof value === 'string' && !DATE_TIME.test(value)) errors.push(`${path}: not a date-time`);
        } else if (schema.format !== 'email' && schema.format !== 'uri') {
          throw new Error(`unknown format ${schema.format}`);
        }
        break;
      case 'minimum':
        if (typeof value === 'number' && value < schema.minimum) errors.push(`${path}: below ${schema.minimum}`);
        break;
      case 'maximum':
        if (typeof value === 'number' && value > schema.maximum) errors.push(`${path}: above ${schema.maximum}`);
        break;
      case 'maxItems':
        if (Array.isArray(value) && value.length > schema.maxItems) errors.push(`${path}: more than ${schema.maxItems} items`);
        break;
      case 'minItems':
        if (Array.isArray(value) && value.length < schema.minItems) errors.push(`${path}: fewer than ${schema.minItems} items`);
        break;
      case 'items':
        if (Array.isArray(value)) value.forEach((item, i) => errors.push(...validate(schema.items, item, root, `${path}[${i}]`)));
        break;
      case 'required':
        if (typeOf(value) === 'object') for (const key of schema.required) if (!Object.hasOwn(value, key)) errors.push(`${path}: missing ${key}`);
        break;
      case 'properties':
        if (typeOf(value) === 'object') {
          for (const [key, sub] of Object.entries(schema.properties)) {
            if (Object.hasOwn(value, key)) errors.push(...validate(sub, value[key], root, `${path}.${key}`));
          }
        }
        break;
      case 'additionalProperties':
        if (schema.additionalProperties === false && typeOf(value) === 'object') {
          for (const key of Object.keys(value)) if (!Object.hasOwn(schema.properties ?? {}, key)) errors.push(`${path}: extra ${key}`);
        } else if (schema.additionalProperties !== false) {
          throw new Error('only additionalProperties: false is supported');
        }
        break;
      case 'oneOf': {
        const passing = schema.oneOf.filter((sub) => validate(sub, value, root, path).length === 0).length;
        if (passing !== 1) errors.push(`${path}: matches ${passing} of oneOf`);
        break;
      }
      default:
        throw new Error(`unsupported schema keyword ${keyword} at ${path}`);
    }
  }
  return errors;
}
