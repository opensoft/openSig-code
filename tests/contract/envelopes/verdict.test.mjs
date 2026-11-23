// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006), kind harness: the verdict function.
//   EC-09 for every case, a response meeting its expectation passes
//   EC-10 each single deviation from that response fails, for the reason it deviates
// The conforming responses below are a test control built from the case
// expectations. They prove the verdict is satisfiable and discriminating; they
// say nothing about any implementation.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { loadVendoredContract, operationIndex } from './lib/contract.mjs';
import { createContext, judge, materialize, pathTokens, resolvePlaceholders } from './lib/harness.mjs';
import { loadManifest } from './lib/manifest.mjs';

const { doc } = loadVendoredContract();
const index = operationIndex(doc);
const manifest = loadManifest();

const TIME = '2026-11-16T00:00:00Z';

function contextFor(c) {
  const given = c.given === null ? null : manifest.index.givens[c.given];
  const ctx = createContext(given ? { envelope_id: 'verdictEnvelope000001', version: 1 + (given.document ? 1 : 0) + (given.prepare ? 1 : 0) } : null);
  const { info } = materialize(c, index, ctx);
  ctx.upload_sha256 = info.sha256;
  ctx.upload_bytes = info.length;
  return ctx;
}

function templateEnvelope() {
  return {
    id: 'verdictEnvelope000001',
    version: 1,
    state: 'draft',
    created_by: { kind: 'human-operator', ref: 'operator-ref-1' },
    source: { app: 'manual', record: 'synthetic-record-0001', version: 'v1' },
    expires_at: TIME,
    reissue_of: null,
    reissued_as: null,
    document: { digest: 'd'.repeat(64), bytes: 1024, pages: [{ number: 1, width: 612, height: 792, rotate: 0 }] },
    manifest_digest: 'b'.repeat(64),
    fields: [{ key: 'sig_1', recipient_id: 'recipientRef00000001', recipient_ordinal: 1, page: 1, type: 'signature', rect: { x: 0.1, y: 0.8, width: 0.3, height: 0.08 } }],
    recipients: [
      { id: 'recipientRef00000001', ordinal: 1, role: 'approver', email: 'signer.one@example.test', status: 'pending', invited_at: null, approved_at: null, approval_digest: null },
    ],
    approvals_complete: false,
    send_confirmation: { required: false, authorization_reference: null },
    finalization: null,
    artifact: null,
    anchor_status: 'disabled',
    created_at: TIME,
    updated_at: TIME,
  };
}

function setAt(target, tokens, value) {
  let node = target;
  tokens.slice(0, -1).forEach((token, i) => {
    if (node[token] === null || typeof node[token] !== 'object') node[token] = typeof tokens[i + 1] === 'number' ? [] : {};
    node = node[token];
  });
  node[tokens.at(-1)] = value;
}

function getAt(target, tokens) {
  return tokens.reduce((node, token) => (node === null || node === undefined ? undefined : node[token]), target);
}

function resize(list, length) {
  while (list.length > length) list.pop();
  while (list.length < length) {
    const copy = structuredClone(list.at(-1));
    if ('number' in copy) copy.number = list.length + 1;
    if ('ordinal' in copy) copy.ordinal = list.length + 1;
    if ('id' in copy) copy.id = `recipientRef0000000${list.length + 1}`;
    list.push(copy);
  }
}

/** A response that meets the case expectation exactly. */
function conformingResponse(c, ctx) {
  const headers = { 'content-type': 'application/json; charset=utf-8' };
  if (c.expect.status >= 400) {
    const body = { code: c.expect.code, correlation_id: 'conforming0001' };
    if ((c.expect.detailCodes ?? []).length > 0) body.details = c.expect.detailCodes.map((code) => ({ field: 'document', code }));
    return { status: c.expect.status, headers, body: Buffer.from(JSON.stringify(body)) };
  }
  const body = templateEnvelope();
  const assertions = c.expect.body;
  for (const a of assertions.filter((x) => Object.hasOwn(x, 'length'))) resize(getAt(body, pathTokens(a.path)), a.length);
  for (const a of assertions) {
    const tokens = pathTokens(a.path);
    if (Object.hasOwn(a, 'equals')) setAt(body, tokens, resolvePlaceholders(a.equals, ctx));
    else if (Object.hasOwn(a, 'greaterThan')) setAt(body, tokens, resolvePlaceholders(a.greaterThan, ctx) + 1);
    else if (Object.hasOwn(a, 'notEquals')) assert.notEqual(getAt(body, tokens), null, `template value at ${a.path} must be non-null`);
  }
  return { status: c.expect.status, headers, body: Buffer.from(JSON.stringify(body)) };
}

function withBody(response, mutate) {
  const body = JSON.parse(response.body.toString('utf8'));
  mutate(body);
  return { ...response, body: Buffer.from(JSON.stringify(body)) };
}

function perturb(value) {
  if (value === null) return 'non-null';
  if (typeof value === 'number') return value + 1;
  if (typeof value === 'boolean') return !value;
  if (typeof value === 'string') return `${value}-other`;
  if (typeof value === 'object') {
    const copy = structuredClone(value);
    const key = Object.keys(copy).find((k) => typeof copy[k] === 'number');
    copy[key] += 1;
    return copy;
  }
  throw new Error(`cannot perturb ${typeof value}`);
}

test('[EC-09] for every case, a response meeting its expectation passes the verdict', () => {
  for (const c of manifest.cases) {
    const ctx = contextFor(c);
    const verdict = judge(doc, index, c, conformingResponse(c, ctx), ctx);
    assert.deepEqual(verdict, { pass: true, reasons: [] }, c.id);
  }
});

test('[EC-10] each single deviation from a conforming response fails the verdict for its own reason', () => {
  let deviations = 0;
  const fails = (c, ctx, response, reasonPattern, label) => {
    const verdict = judge(doc, index, c, response, ctx);
    assert.equal(verdict.pass, false, `${c.id}: ${label} must fail`);
    assert.ok(verdict.reasons.some((r) => reasonPattern.test(r)), `${c.id}: ${label} failed for another reason: ${verdict.reasons.join('; ')}`);
    deviations += 1;
  };
  for (const c of manifest.cases) {
    const ctx = contextFor(c);
    const good = conformingResponse(c, ctx);
    fails(c, ctx, { ...good, status: c.expect.status === 200 ? 201 : 200 }, /^status /, 'another status');
    fails(c, ctx, { ...good, headers: { 'content-type': 'text/plain' } }, /^content-type /, 'a non-JSON media type');
    fails(c, ctx, { ...good, body: Buffer.from('not json') }, /not JSON/, 'an unparsable body');
    if (c.expect.status >= 400) {
      fails(c, ctx, withBody(good, (b) => { b.code = b.code === 'internal' ? 'not_found' : 'internal'; }), /^error code /, 'another error code');
      fails(c, ctx, withBody(good, (b) => { delete b.correlation_id; }), /missing required property correlation_id/, 'a missing correlation_id');
      fails(c, ctx, withBody(good, (b) => { b.trace = 'x'; }), /unknown property trace/, 'an unknown Error property');
      fails(c, ctx, withBody(good, (b) => { b.message = 'm'.repeat(201); }), /longer than 200/, 'an overlong message');
      if ((c.expect.detailCodes ?? []).length > 0) fails(c, ctx, withBody(good, (b) => { delete b.details; }), /error details lack code/, 'missing detail codes');
    } else {
      fails(c, ctx, withBody(good, (b) => { delete b.updated_at; }), /missing required property updated_at/, 'a missing required property');
      fails(c, ctx, withBody(good, (b) => { b.invitation_link = 'x'; }), /unknown property invitation_link/, 'an unknown Envelope property');
      for (const a of c.expect.body) {
        const tokens = pathTokens(a.path);
        let mutate;
        if (Object.hasOwn(a, 'equals')) mutate = (b) => setAt(b, tokens, perturb(getAt(b, tokens)));
        else if (Object.hasOwn(a, 'notEquals')) mutate = (b) => setAt(b, tokens, null);
        else if (Object.hasOwn(a, 'greaterThan')) mutate = (b) => setAt(b, tokens, resolvePlaceholders(a.greaterThan, ctx));
        else mutate = (b) => { const list = getAt(b, tokens); if (list.length > 1) list.pop(); else list.push(structuredClone(list[0])); };
        const escaped = a.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        fails(c, ctx, withBody(good, mutate), new RegExp(`^${escaped} `), `a changed ${a.path}`);
      }
    }
  }
  assert.ok(deviations > manifest.cases.length * 4, `ran ${deviations} deviations`);
});
