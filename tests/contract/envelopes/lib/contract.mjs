// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006): access to the vendored spec-leg contract.
//
// The contract is contracts/http-api.json, a byte-exact copy of the spec leg's
// specs/001-corporate-signing-mvp/contracts/http-api.yaml (OpenAPI 3.1 written
// as JSON). contracts/http-api.source.json records {repo, commit, path, sha256}.
// This module imports nothing from src/.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Repository root: tests/contract/envelopes/lib -> four levels up. */
export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');

export const CONTRACT_FILE = 'contracts/http-api.json';
export const CONTRACT_SOURCE_FILE = 'contracts/http-api.source.json';

export const HTTP_METHODS = Object.freeze(['get', 'put', 'post', 'delete', 'patch', 'head', 'options', 'trace']);

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Load the vendored contract and its source record.
 * Returns { bytes, doc, source, sha256 } where sha256 is computed over the bytes.
 */
export function loadVendoredContract(root = REPO_ROOT) {
  const bytes = readFileSync(join(root, CONTRACT_FILE));
  const source = JSON.parse(readFileSync(join(root, CONTRACT_SOURCE_FILE), 'utf8'));
  const doc = JSON.parse(bytes.toString('utf8'));
  return { bytes, doc, source, sha256: sha256Hex(bytes) };
}

/** Resolve a local JSON pointer ("#/a/b~1c") against the document; undefined when absent. */
export function resolvePointer(doc, pointer) {
  if (typeof pointer !== 'string' || !pointer.startsWith('#')) throw new Error(`not a local JSON pointer: ${pointer}`);
  if (pointer === '#') return doc;
  if (!pointer.startsWith('#/')) throw new Error(`not a local JSON pointer: ${pointer}`);
  let node = doc;
  for (const raw of pointer.slice(2).split('/')) {
    const token = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (node === null || typeof node !== 'object' || !Object.hasOwn(node, token)) return undefined;
    node = node[token];
  }
  return node;
}

/** Follow $ref chains on a node (objects whose only meaningful key is $ref). */
export function deref(doc, node) {
  let current = node;
  const seen = new Set();
  while (current && typeof current === 'object' && typeof current.$ref === 'string') {
    if (seen.has(current.$ref)) throw new Error(`$ref cycle at ${current.$ref}`);
    seen.add(current.$ref);
    const target = resolvePointer(doc, current.$ref);
    if (target === undefined) throw new Error(`unresolvable $ref ${current.$ref}`);
    current = target;
  }
  return current;
}

/**
 * Index of operations by operationId:
 * { operationId, method (upper case), pathTemplate, operation, parameters[] (dereferenced, path level then operation level) }.
 */
export function operationIndex(doc) {
  const index = new Map();
  for (const [pathTemplate, rawItem] of Object.entries(doc.paths ?? {})) {
    const item = deref(doc, rawItem);
    const shared = (item.parameters ?? []).map((p) => deref(doc, p));
    for (const method of HTTP_METHODS) {
      const operation = item[method];
      if (!operation) continue;
      const own = (operation.parameters ?? []).map((p) => deref(doc, p));
      const byKey = new Map();
      for (const parameter of [...shared, ...own]) byKey.set(`${parameter.in}:${parameter.name.toLowerCase()}`, parameter);
      if (index.has(operation.operationId)) throw new Error(`duplicate operationId ${operation.operationId}`);
      index.set(operation.operationId, {
        operationId: operation.operationId,
        method: method.toUpperCase(),
        pathTemplate,
        operation,
        parameters: [...byKey.values()],
      });
    }
  }
  return index;
}

/** The operation entry or a thrown error naming the missing operationId. */
export function getOperation(index, operationId) {
  const entry = index.get(operationId);
  if (!entry) throw new Error(`operation ${operationId} is not in the vendored contract`);
  return entry;
}

/** Path template parameter names in order: "/v1/envelopes/{envelope_id}" -> ["envelope_id"]. */
export function templateParameters(pathTemplate) {
  return [...pathTemplate.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
}

/** Media types the operation accepts for its request body (empty when it has none). */
export function requestMediaTypes(doc, entry) {
  const body = entry.operation.requestBody ? deref(doc, entry.operation.requestBody) : null;
  return body ? Object.keys(body.content ?? {}) : [];
}

/** Request body schema for a media type, or null. */
export function requestSchema(doc, entry, mediaType) {
  const body = entry.operation.requestBody ? deref(doc, entry.operation.requestBody) : null;
  const media = body?.content?.[mediaType];
  return media?.schema ?? null;
}

/** The single 2xx status the operation declares (as a number); throws when there is not exactly one. */
export function successStatus(entry) {
  const statuses = Object.keys(entry.operation.responses ?? {}).filter((s) => /^2\d\d$/.test(s));
  if (statuses.length !== 1) throw new Error(`${entry.operationId} declares ${statuses.length} 2xx responses`);
  return Number(statuses[0]);
}

/**
 * The declared response for a status: { ref (component response name or null), response (dereferenced) },
 * or null when the status is not declared for the operation.
 */
export function declaredResponse(doc, entry, status) {
  const raw = entry.operation.responses?.[String(status)];
  if (!raw) return null;
  const ref = typeof raw.$ref === 'string' && raw.$ref.startsWith('#/components/responses/') ? raw.$ref.slice('#/components/responses/'.length) : null;
  return { ref, response: deref(doc, raw) };
}

/** JSON response schema for a declared status, or null. */
export function responseSchema(doc, entry, status) {
  const declared = declaredResponse(doc, entry, status);
  return declared?.response?.content?.['application/json']?.schema ?? null;
}

/** The Error.code enum of the contract. */
export function errorCodes(doc) {
  const schema = deref(doc, resolvePointer(doc, '#/components/schemas/Error'));
  return [...schema.properties.code.enum];
}
