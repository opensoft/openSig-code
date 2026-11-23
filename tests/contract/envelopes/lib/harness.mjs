// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006): turns manifest cases into transport-level
// requests, sends them to a subject, and judges each response against the case
// expectation and the vendored contract. Kind: harness. A run of this harness is
// never success-criterion evidence and never runtime acceptance; T034 consumes it
// with a count check (fixtures/synthetic/envelopes/README.md).
//
// A subject is
//   {
//     name: string,
//     arrange(given, tools, givenName): Promise<{ envelope_id: string, version: integer >= 1 }>,
//     handle(request): Promise<{ status: integer, headers: object, body: Buffer | Uint8Array | string }>,
//   }
// where request is
//   { operationId, method, path, principal: "sender" | "service", headers (lower-case names), body: Buffer | null }.
// makeApiSubject(handle) builds arrange() from contract operations, so a real
// implementation only supplies handle().
//
// This module imports nothing from src/.

import { randomBytes } from 'node:crypto';

import {
  declaredResponse,
  deref,
  getOperation,
  operationIndex,
  requestMediaTypes,
  requestSchema,
  responseSchema,
  sha256Hex,
  successStatus,
  templateParameters,
} from './contract.mjs';
import { buildPdf, inspectPdf } from './pdf.mjs';
import { deepEqual, validate } from './schema.mjs';

/** Route body limits, from the contract's PayloadTooLarge description ("10 MiB for PDF upload ... 256 KiB for JSON"). */
export const LIMITS = Object.freeze({ json: 256 * 1024, pdf: 10 * 1024 * 1024 });

// ---------------------------------------------------------------------------
// Context, placeholders and generators
// ---------------------------------------------------------------------------

function newIdempotencyKey() {
  return `ec${randomBytes(18).toString('base64url')}`;
}

const GENERATORS = Object.freeze({
  'idempotency-key': newIdempotencyKey,
  // 15 characters from the allowed alphabet: one short of the contract's {16,128}.
  'idempotency-key-short': () => randomBytes(12).toString('base64url').slice(0, 15),
});

/** Case context from an arranged envelope (or none). */
export function createContext(arranged) {
  const ctx = { absent_envelope_id: `absent${randomBytes(15).toString('base64url')}` };
  if (arranged) {
    const { envelope_id: id, version } = arranged;
    Object.assign(ctx, {
      envelope_id: id,
      version,
      next_version: version + 1,
      previous_version: version - 1,
      version_text: String(version),
      if_match_current: `"${version}"`,
      if_match_next: `"${version + 1}"`,
      if_match_weak: `W/"${version}"`,
    });
  }
  return ctx;
}

/** Replace {"$ctx": name} and {"$gen": name} placeholders, recursively. */
export function resolvePlaceholders(template, ctx) {
  if (Array.isArray(template)) return template.map((item) => resolvePlaceholders(item, ctx));
  if (template !== null && typeof template === 'object') {
    const keys = Object.keys(template);
    if (keys.length === 1 && keys[0] === '$ctx') {
      const name = template.$ctx;
      if (!Object.hasOwn(ctx, name)) throw new Error(`context value ${name} is not available for this case`);
      if (name === 'previous_version' && ctx.previous_version < 1) {
        throw new Error(`previous_version needs an arranged version of at least 2, got ${ctx.version}`);
      }
      return ctx[name];
    }
    if (keys.length === 1 && keys[0] === '$gen') {
      const generator = GENERATORS[template.$gen];
      if (!generator) throw new Error(`unknown generator ${template.$gen}`);
      return generator();
    }
    return Object.fromEntries(keys.map((key) => [key, resolvePlaceholders(template[key], ctx)]));
  }
  return template;
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/** Build the request body for a body descriptor: { bytes, contentType, kind, json? }. */
export function buildBody(body, ctx) {
  if (Object.hasOwn(body, 'json')) {
    const value = resolvePlaceholders(body.json, ctx);
    let text = JSON.stringify(value);
    if (body.padTo !== undefined) {
      const length = Buffer.byteLength(text, 'utf8');
      if (length > body.padTo) throw new Error(`JSON body is ${length} bytes, above padTo ${body.padTo}`);
      text += ' '.repeat(body.padTo - length); // insignificant whitespace after the value
    }
    return { bytes: Buffer.from(text, 'utf8'), contentType: body.contentType ?? 'application/json', kind: 'json' };
  }
  if (Object.hasOwn(body, 'text')) {
    return { bytes: Buffer.from(body.text, 'utf8'), contentType: body.contentType ?? 'text/plain', kind: 'text' };
  }
  if (Object.hasOwn(body, 'pdf')) {
    return { bytes: buildPdf(body.pdf), contentType: body.contentType ?? 'application/pdf', kind: 'pdf' };
  }
  throw new Error('request body needs json, text or pdf');
}

const pdfCache = new Map();

function cachedBody(body, ctx) {
  // PDF bodies are pure functions of their descriptor; large ones are built once per process.
  if (Object.hasOwn(body, 'pdf')) {
    const key = JSON.stringify(body);
    if (!pdfCache.has(key)) pdfCache.set(key, buildBody(body, ctx));
    return pdfCache.get(key);
  }
  return buildBody(body, ctx);
}

/**
 * Materialize a case request.
 * Returns { request, pathValues, info: { kind, contentType, length, sha256 } }.
 * Defaults: an Idempotency-Key when the operation declares one, an If-Match of
 * the arranged version when it declares one, and the body's media type.
 * request.headers overrides them; a null value removes the header.
 */
export function materialize(c, index, ctx) {
  const entry = getOperation(index, c.request.operationId);
  const pathValues = {};
  let path = entry.pathTemplate;
  for (const name of templateParameters(entry.pathTemplate)) {
    const template = c.request.path?.[name];
    if (template === undefined) throw new Error(`path parameter ${name} has no value`);
    const value = String(resolvePlaceholders(template, ctx));
    pathValues[name] = value;
    path = path.replace(`{${name}}`, encodeURIComponent(value));
  }
  const headers = {};
  for (const parameter of entry.parameters.filter((p) => p.in === 'header')) {
    if (parameter.name === 'Idempotency-Key') headers['idempotency-key'] = newIdempotencyKey();
    if (parameter.name === 'If-Match' && ctx.if_match_current !== undefined) headers['if-match'] = ctx.if_match_current;
  }
  let body = null;
  const info = { kind: 'none', contentType: null, length: 0, sha256: null };
  if (c.request.body !== undefined) {
    const built = cachedBody(c.request.body, ctx);
    body = built.bytes;
    headers['content-type'] = built.contentType;
    Object.assign(info, { kind: built.kind, contentType: built.contentType, length: built.bytes.length, sha256: sha256Hex(built.bytes) });
  }
  for (const [name, value] of Object.entries(c.request.headers ?? {})) {
    if (value === null) delete headers[name.toLowerCase()];
    else headers[name.toLowerCase()] = String(resolvePlaceholders(value, ctx));
  }
  const request = { operationId: entry.operationId, method: entry.method, path, principal: c.request.principal ?? 'sender', headers, body };
  return { request, pathValues, info };
}

/**
 * Contract-level findings for a request: what a validating server must reject
 * before any state or PDF inspection. Each finding is { kind, name? }.
 * Kinds: path-parameter, header-missing, header-invalid, media-type, body-too-large, body-syntax, body-schema.
 */
export function requestFindings(doc, entry, request, pathValues) {
  const findings = [];
  for (const parameter of entry.parameters) {
    if (parameter.in === 'path') {
      if (validate(doc, parameter.schema, pathValues[parameter.name]).length > 0) findings.push({ kind: 'path-parameter', name: parameter.name });
    } else if (parameter.in === 'header') {
      const value = request.headers[parameter.name.toLowerCase()];
      if (value === undefined) {
        if (parameter.required) findings.push({ kind: 'header-missing', name: parameter.name });
      } else if (validate(doc, parameter.schema, value).length > 0) {
        findings.push({ kind: 'header-invalid', name: parameter.name });
      }
    }
  }
  const media = requestMediaTypes(doc, entry);
  if (media.length > 0) {
    const contentType = String(request.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (!media.includes(contentType)) {
      findings.push({ kind: 'media-type' });
      return findings;
    }
    const body = request.body ?? Buffer.alloc(0);
    const limit = contentType === 'application/pdf' ? LIMITS.pdf : LIMITS.json;
    if (body.length > limit) findings.push({ kind: 'body-too-large' });
    if (contentType === 'application/json') {
      let parsed;
      try {
        parsed = JSON.parse(body.toString('utf8'));
      } catch {
        findings.push({ kind: 'body-syntax' });
        return findings;
      }
      if (validate(doc, requestSchema(doc, entry, contentType), parsed).length > 0) findings.push({ kind: 'body-schema' });
    }
  }
  return findings;
}

/** PDF content findings for upload bytes: "malformed", or the inspector's policy features. */
export function pdfFindings(bytes) {
  const report = inspectPdf(bytes);
  return report.ok ? report.features : ['malformed'];
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
  return key === undefined ? undefined : headers[key];
}

/** Tokens of an assertion path: "document.pages[1].width" -> ["document", "pages", 1, "width"]. */
export function pathTokens(path) {
  const tokens = [];
  for (const part of path.split('.')) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*)((?:\[\d+\])*)$/.exec(part);
    if (!m) throw new Error(`bad assertion path ${path}`);
    tokens.push(m[1]);
    for (const index of m[2].matchAll(/\[(\d+)\]/g)) tokens.push(Number(index[1]));
  }
  return tokens;
}

function valueAt(value, tokens) {
  let node = value;
  for (const token of tokens) {
    if (node === null || typeof node !== 'object' || !Object.hasOwn(node, token)) return { found: false };
    node = node[token];
  }
  return { found: true, value: node };
}

/** Check body assertions; returns reasons for each that fails. */
export function assertionFailures(assertions, body, ctx) {
  const reasons = [];
  for (const assertion of assertions ?? []) {
    const at = valueAt(body, pathTokens(assertion.path));
    const expected = (key) => resolvePlaceholders(assertion[key], ctx);
    if (Object.hasOwn(assertion, 'equals')) {
      const want = expected('equals');
      if (!at.found || !deepEqual(at.value, want)) reasons.push(`${assertion.path} is ${at.found ? JSON.stringify(at.value) : 'absent'}, expected ${JSON.stringify(want)}`);
    } else if (Object.hasOwn(assertion, 'notEquals')) {
      const avoid = expected('notEquals');
      if (!at.found || deepEqual(at.value, avoid)) reasons.push(`${assertion.path} must differ from ${JSON.stringify(avoid)}`);
    } else if (Object.hasOwn(assertion, 'greaterThan')) {
      const floor = expected('greaterThan');
      if (!at.found || typeof at.value !== 'number' || !(at.value > floor)) reasons.push(`${assertion.path} must be greater than ${floor}`);
    } else if (Object.hasOwn(assertion, 'length')) {
      if (!at.found || !Array.isArray(at.value) || at.value.length !== assertion.length) reasons.push(`${assertion.path} must hold ${assertion.length} items`);
    }
  }
  return reasons;
}

/**
 * Judge a subject response for a case. Returns { pass, reasons }.
 * Every case requires the exact expected status and a JSON body. A 2xx body must
 * validate against the contract's response schema for that operation and status
 * and meet the case's body assertions. A 4xx body must validate against the
 * contract's Error schema, carry the expected code and every expected detail code.
 */
export function judge(doc, index, c, response, ctx) {
  const reasons = [];
  if (!response || !Number.isInteger(response.status)) return { pass: false, reasons: ['no response status'] };
  if (response.status !== c.expect.status) return { pass: false, reasons: [`status ${response.status}, expected ${c.expect.status}`] };
  const contentType = String(headerValue(response.headers, 'content-type') ?? '');
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) return { pass: false, reasons: [`content-type ${JSON.stringify(contentType)} is not application/json`] };
  let body;
  try {
    const raw = typeof response.body === 'string' ? response.body : Buffer.from(response.body ?? []).toString('utf8');
    body = JSON.parse(raw);
  } catch {
    return { pass: false, reasons: ['response body is not JSON'] };
  }
  const entry = getOperation(index, c.request.operationId);
  const schema = responseSchema(doc, entry, c.expect.status);
  if (!schema) return { pass: false, reasons: [`the contract declares no JSON body for ${entry.operationId} ${c.expect.status}`] };
  reasons.push(...validate(doc, schema, body).map((e) => `body ${e}`));
  if (c.expect.status >= 200 && c.expect.status < 300) {
    reasons.push(...assertionFailures(c.expect.body, body, ctx));
  } else {
    if (body?.code !== c.expect.code) reasons.push(`error code ${JSON.stringify(body?.code)}, expected ${c.expect.code}`);
    const details = Array.isArray(body?.details) ? body.details.map((d) => d?.code) : [];
    for (const code of c.expect.detailCodes ?? []) if (!details.includes(code)) reasons.push(`error details lack code ${code}`);
  }
  return { pass: reasons.length === 0, reasons };
}

// ---------------------------------------------------------------------------
// Running cases
// ---------------------------------------------------------------------------

/** Tools handed to subject.arrange(). */
export function arrangeTools(doc, index) {
  return { buildPdf, contract: doc, operation: (id) => getOperation(index, id), newIdempotencyKey };
}

/** Run one case against a subject. Returns { id, category, pass, stage, reasons }. */
export async function runCase(subject, c, env) {
  const { doc, index, manifest } = env;
  const result = { id: c.id, category: c.category, pass: false, stage: 'arrange', reasons: [] };
  let arranged = null;
  if (c.given !== null) {
    try {
      arranged = await subject.arrange(manifest.index.givens[c.given], arrangeTools(doc, index), c.given);
    } catch (error) {
      result.reasons.push(`arrange ${c.given} failed: ${error?.message ?? error}`);
      return result;
    }
    if (!arranged || typeof arranged.envelope_id !== 'string' || !Number.isInteger(arranged.version) || arranged.version < 1) {
      result.reasons.push(`arrange ${c.given} returned no envelope_id and version`);
      return result;
    }
  }
  const ctx = createContext(arranged);
  result.stage = 'request';
  let materialized;
  try {
    materialized = materialize(c, index, ctx);
  } catch (error) {
    result.reasons.push(`request could not be built: ${error?.message ?? error}`);
    return result;
  }
  ctx.upload_sha256 = materialized.info.sha256;
  ctx.upload_bytes = materialized.info.length;
  result.stage = 'handle';
  let response;
  try {
    response = await subject.handle(materialized.request);
  } catch (error) {
    result.reasons.push(`handle threw: ${error?.message ?? error}`);
    return result;
  }
  result.stage = 'verdict';
  const verdict = judge(doc, index, c, response, ctx);
  result.pass = verdict.pass;
  result.reasons = verdict.reasons;
  return result;
}

/**
 * Run every case (or options.ids) against a subject, sequentially, in manifest order.
 * env: { doc, index, manifest } from contract.mjs / manifest.mjs.
 */
export async function runManifest(subject, env, options = {}) {
  const wanted = options.ids ? new Set(options.ids) : null;
  const results = [];
  for (const c of env.manifest.cases) {
    if (wanted && !wanted.has(c.id)) continue;
    results.push(await runCase(subject, c, env));
  }
  return results;
}

/** Per-category counts: { category: { cases, passed, failed } }. */
export function summarize(results) {
  const out = {};
  for (const r of results) {
    out[r.category] ??= { cases: 0, passed: 0, failed: 0 };
    out[r.category].cases += 1;
    out[r.category][r.pass ? 'passed' : 'failed'] += 1;
  }
  return out;
}

/** Match a concrete method and path to a contract operation: { entry, pathValues } or null. */
export function matchOperation(index, method, path) {
  const [pathname] = path.split('?');
  for (const entry of index.values()) {
    if (entry.method !== method.toUpperCase()) continue;
    const names = templateParameters(entry.pathTemplate);
    const pattern = new RegExp(`^${entry.pathTemplate.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{[^}]+\}/g, '([^/]+)')}$`);
    const m = pattern.exec(pathname);
    if (m) return { entry, pathValues: Object.fromEntries(names.map((n, i) => [n, decodeURIComponent(m[i + 1])])) };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Arranging through the contract operations (for real subjects)
// ---------------------------------------------------------------------------

async function call(handle, index, operationId, { principal, pathValues = {}, body = null, contentType = null, ifMatch = null }) {
  const entry = getOperation(index, operationId);
  let path = entry.pathTemplate;
  for (const name of templateParameters(entry.pathTemplate)) path = path.replace(`{${name}}`, encodeURIComponent(pathValues[name]));
  const headers = {};
  if (entry.parameters.some((p) => p.in === 'header' && p.name === 'Idempotency-Key')) headers['idempotency-key'] = newIdempotencyKey();
  if (ifMatch !== null) headers['if-match'] = ifMatch;
  if (contentType !== null) headers['content-type'] = contentType;
  const request = { operationId, method: entry.method, path, principal, headers, body };
  const response = await handle(request);
  const expected = successStatus(entry);
  if (response?.status !== expected) throw new Error(`${operationId} returned ${response?.status}, expected ${expected}`);
  const raw = typeof response.body === 'string' ? response.body : Buffer.from(response.body ?? []).toString('utf8');
  const envelope = JSON.parse(raw);
  if (typeof envelope?.id !== 'string' || !Number.isInteger(envelope?.version)) throw new Error(`${operationId} returned no envelope id and version`);
  return envelope;
}

/**
 * Bring an envelope into a manifest "given" through contract operations:
 * createEnvelope, then uploadDocument (If-Match the current version) when the
 * given has a document, then prepareEnvelope when it has fields to prepare.
 * Returns { envelope_id, version } from the last response.
 */
export async function arrangeThroughApi(handle, given, index) {
  const principal = given.principal;
  let envelope = await call(handle, index, 'createEnvelope', {
    principal,
    body: Buffer.from(JSON.stringify(given.create), 'utf8'),
    contentType: 'application/json',
  });
  if (given.document) {
    envelope = await call(handle, index, 'uploadDocument', {
      principal,
      pathValues: { envelope_id: envelope.id },
      body: buildPdf(given.document),
      contentType: 'application/pdf',
      ifMatch: `"${envelope.version}"`,
    });
  }
  if (given.prepare) {
    envelope = await call(handle, index, 'prepareEnvelope', {
      principal,
      pathValues: { envelope_id: envelope.id },
      body: Buffer.from(JSON.stringify({ expected_version: envelope.version, fields: given.prepare }), 'utf8'),
      contentType: 'application/json',
    });
  }
  if (envelope.state !== given.state) throw new Error(`arranged envelope is ${envelope.state}, expected ${given.state}`);
  return { envelope_id: envelope.id, version: envelope.version };
}

/** A subject whose arrange() goes through the contract operations of `handle`. */
export function makeApiSubject(name, handle, doc) {
  const index = operationIndex(doc);
  return { name, handle, arrange: (given) => arrangeThroughApi(handle, given, index) };
}

/** Re-export for subjects that need to read declared responses. */
export { declaredResponse, deref };
