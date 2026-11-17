// SPDX-License-Identifier: Apache-2.0
//
// T034 uploadDocument: the per-tenant upload cap and client aborts (A-010 LBR4-1, EA-01), no
// caller-supplied option reaching parsePdf() (A-009 LBR-3), and the upload's own refusals.
//
// EA-01 choreography. Every pass criterion is state the services report themselves:
// bodyReadCapacity() and parseAdmissions() of the parse service (T033) and uploadCapacity()
// of the upload cap, reached through barriers (a bounded poll under one hang guard). No fixed
// sleep orders the test, no wall-clock bound is a pass criterion, and no load is generated:
// the held uploads are raw sockets that send part of a small synthetic document and then
// nothing, until the test destroys them.
//
// The held uploads stand for what the server's body timing allows an honest client: a
// minimum-rate sender, or a front-loaded upload that then trickles, may keep its body-read
// permit for up to 640 s (T031 SEC-10). The test must not wait minutes for that, so the two
// EA-01 worlds below, and no other, widen the server's body idle timer and minimum-rate grace
// to the hang guard (WIDE_TIMING). Disclosure (A-010, request #16, doubt 4): this goes only
// through T031's existing options config.limits.bodyIdleMs and config.limits.bodyRateGraceMs
// (createWorld refuses any other name); production defaults (loadServerConfig) are unchanged,
// every other world in these tests uses them, and T031's SEC-10 keeps testing them. That
// timer is T031's and is not under test here. Everything else is the production path: the
// real router, authenticator, handlers, upload cap and parse service.
//
// Cleanup is unconditional (t.after): every socket is destroyed, every issued request
// settles, and the services drain to idle before the world closes. Each test starts by
// asserting idle, so one test's leftover never surfaces as a misleading failure in the next.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { UPLOADS_PER_TENANT, uploadCapacity } from '../../../src/api/envelopes/index.ts';
import { HttpError } from '../../../src/server/types.ts';
import { bodyReadCapacity, MAX_CONCURRENT_BODY_READS, parseAdmissions } from '../../../src/pdf/service.ts';
import {
  HANG_GUARD_MS,
  REPO,
  SINGLE_PAGE,
  TENANTS,
  absentId,
  createEnvelope,
  createWorld,
  documentBytes,
  headersOnlyUpload,
  heldUpload,
  isIdle,
  newKey,
  prepareEnvelope,
  readEnvelope,
  requestLog,
  settle,
  sha256,
  showState,
  until,
  uploadDocument,
  uploadRequest,
} from './support.mjs';

const WIDE_TIMING = Object.freeze({ bodyIdleMs: HANG_GUARD_MS, bodyRateGraceMs: HANG_GUARD_MS });

function assertIdle(which) {
  assert.ok(isIdle(), `${which} must start idle (no parse running or waiting, no body-read permit, no upload slot): ${showState()}`);
}

/** A world for one test, torn down unconditionally with everything the test opened. */
async function flight(t, options) {
  const world = await createWorld(options);
  const sockets = new Set();
  const issued = [];
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await settle(Promise.allSettled(issued), 'cleanup: every issued request settles');
    await until(isIdle, 'cleanup: the parse service and the upload cap drain to idle');
    await world.close();
  });
  const issue = (promise) => {
    promise.catch(() => {});
    issued.push(promise);
    return promise;
  };
  return { world, sockets, issue };
}

test('[EA-01] one tenant holding its upload cap never stops another tenant\'s upload from taking a body-read permit; a further upload of the capped tenant is refused before its body is read', async (t) => {
  const { world, sockets, issue } = await flight(t, { bodyTiming: WIDE_TIMING });
  const pdf = documentBytes(SINGLE_PAGE);
  const alpha = TENANTS.alpha.id;
  const beta = TENANTS.beta.id;

  // The cap is derived from the parse service's own permit count, never copied.
  const max = bodyReadCapacity().max;
  assert.equal(max, MAX_CONCURRENT_BODY_READS, 'bodyReadCapacity() reports the exported permit count');
  assert.equal(UPLOADS_PER_TENANT, Math.max(1, Math.floor(max / 2)), 'the per-tenant cap is half of the body-read permits, at least 1');
  assert.ok(UPLOADS_PER_TENANT === 1 || 2 * UPLOADS_PER_TENANT <= max, 'one tenant never holds more than half of the permits');
  assert.equal(uploadCapacity(alpha).max, UPLOADS_PER_TENANT);
  t.diagnostic(`upload cap: ${UPLOADS_PER_TENANT} per tenant of ${max} body-read permits`);

  // Warm the parse service (its sandbox probe runs once per process) so no barrier below
  // waits on it; then the test starts idle.
  const warm = await createEnvelope(world, { tenant: 'beta' });
  await uploadDocument(world, { tenant: 'beta', envelope: warm, pdf });
  assertIdle('EA-01 (cap)');

  const drafts = [];
  for (let i = 0; i <= UPLOADS_PER_TENANT; i += 1) drafts.push(await createEnvelope(world, { tenant: 'alpha' }));
  const betaDrafts = [];
  for (let i = 0; i <= UPLOADS_PER_TENANT; i += 1) betaDrafts.push(await createEnvelope(world, { tenant: 'beta' }));

  // Alpha holds its cap with controlled uploads: alternately a minimum-rate start (one byte)
  // and a front-loaded body (all but the last byte). Barrier: each holds a body-read permit
  // and an upload slot.
  const shapes = [1, pdf.length - 1];
  for (let i = 0; i < UPLOADS_PER_TENANT; i += 1) heldUpload(world, sockets, { tenant: 'alpha', envelope: drafts[i], pdf, sendBytes: shapes[i % 2] });
  await until(
    () => bodyReadCapacity().held === UPLOADS_PER_TENANT && uploadCapacity(alpha).held === UPLOADS_PER_TENANT,
    `alpha's ${UPLOADS_PER_TENANT} held uploads each take a body-read permit and an upload slot`,
  );
  const ticket = parseAdmissions().next_ticket;

  // A further alpha upload, headers only: 429 upload-capacity before any body byte, and it
  // never takes a body-read permit.
  const refused = headersOnlyUpload(world, sockets, { tenant: 'alpha', envelope: drafts[UPLOADS_PER_TENANT], pdf });
  const answer = await settle(issue(refused.response), 'the further alpha upload is answered');
  assert.equal(answer.status, 429, 'alpha at its cap is refused');
  assert.equal(answer.json?.code, 'rate_limited');
  assert.deepEqual(answer.json?.details, [{ field: 'tenant', code: 'upload-capacity' }], 'refused by the tenant cap, not by the parse service');
  assert.equal(refused.bodyBytesSent(), 0, 'the 429 arrived before any body byte was sent');
  assert.equal(bodyReadCapacity().held, UPLOADS_PER_TENANT, `the refusal took no body-read permit (${showState()})`);
  assert.equal(uploadCapacity(alpha).held, UPLOADS_PER_TENANT, 'and no upload slot');

  // Beta's honest upload takes one of the remaining permits and is accepted, while alpha holds its cap.
  const accepted = await settle(issue(uploadRequest(world, { tenant: 'beta', envelope: betaDrafts[0], pdf })), "beta's upload, with alpha at its cap, returns its response");
  assert.equal(accepted.status, 200, `beta's upload is accepted while alpha holds its cap (${accepted.json?.code ?? 'no code'})`);
  assert.equal(accepted.json.version, 2);
  assert.equal(parseAdmissions().next_ticket, ticket + 1, "beta's parse entered the gate; alpha's held uploads drew no ticket");
  assert.equal(bodyReadCapacity().held, UPLOADS_PER_TENANT, 'alpha still holds its permits');

  // Beta can hold its own share of permits beside alpha's: together they never exceed the set.
  const betaShare = Math.min(UPLOADS_PER_TENANT, max - UPLOADS_PER_TENANT);
  for (let i = 1; i <= betaShare; i += 1) heldUpload(world, sockets, { tenant: 'beta', envelope: betaDrafts[i], pdf, sendBytes: shapes[i % 2] });
  await until(
    () => uploadCapacity(beta).held === betaShare && bodyReadCapacity().held === UPLOADS_PER_TENANT + betaShare,
    `beta's ${betaShare} held uploads each take one of the permits alpha left`,
  );
  assert.ok(bodyReadCapacity().held <= max, `never more than ${max} permits held (${showState()})`);
  // t.after: destroy the held uploads, settle everything, drain to idle.
});

test('[EA-01] a client abort mid-body is handled with no 500 and no partial revision, and releases the upload slot and the body-read permit', async (t) => {
  const { world, sockets } = await flight(t, { bodyTiming: WIDE_TIMING });
  const pdf = documentBytes(SINGLE_PAGE);
  const alpha = TENANTS.alpha.id;
  const warm = await createEnvelope(world);
  await uploadDocument(world, { envelope: warm, pdf });
  assertIdle('EA-01 (abort)');

  const draft = await createEnvelope(world);
  const path = `/v1/envelopes/${draft.id}/document`;
  const revisions = world.rows('document_revisions').length;
  const ticket = parseAdmissions().next_ticket;
  const socket = heldUpload(world, sockets, { tenant: 'alpha', envelope: draft, pdf, sendBytes: Math.floor(pdf.length / 2) });
  await until(() => bodyReadCapacity().held === 1 && uploadCapacity(alpha).held === 1, 'the upload takes a body-read permit and an upload slot');
  socket.destroy();
  await until(() => requestLog(world, 'uploadDocument', path).length === 1, 'the server finishes the aborted upload');

  const [record] = requestLog(world, 'uploadDocument', path);
  assert.ok(record.status >= 400 && record.status < 500, `the aborted upload ends with the body's own 4xx, never a 500 (status ${record.status})`);
  assert.equal(world.logged('handler_exception').length, 0, 'parsePdf()\'s rejection was handled: no handler exception');
  assert.ok(isIdle(), `the upload slot and the body-read permit are released (${showState()})`);
  assert.equal(parseAdmissions().next_ticket, ticket, 'the aborted upload never entered the parse gate');
  assert.equal(world.rows('document_revisions').length, revisions, 'no partial revision');
  assert.equal((await readEnvelope(world, { envelope: draft })).version, 1, 'the envelope version is unchanged');

  // A body that fails with a non-HTTP error inside the parse service's read is a 400 too, and releases the slot.
  const principal = Object.freeze({
    scheme: 'operator',
    tenant_id: alpha,
    kind: 'human-operator',
    roles: Object.freeze(['sender']),
    scopes: Object.freeze(['envelopes:write']),
    ref: draft.created_by.ref,
    issuer: TENANTS.alpha.oidc.issuer,
    expires_at: Math.floor(Date.now() / 1000) + 60,
  });
  const failing = (async function* body() {
    yield pdf.subarray(0, 64);
    throw new Error('synthetic connection reset');
  })();
  await assert.rejects(
    world.api.upload({ principal, envelopeId: draft.id, key: newKey(), expectedVersion: 1, body: failing, logger: { info() {}, warn() {}, error() {}, child() { return this; } } }),
    (error) => error instanceof HttpError && error.status === 400 && error.code === 'invalid_request',
    'a failing body is the request\'s own 400, never a 500',
  );
  assert.ok(isIdle(), `nothing is held after the failing body (${showState()})`);
  assert.equal(world.rows('document_revisions').length, revisions, 'still no partial revision');

  // The released slot admits the tenant's next upload.
  const next = await settle(uploadRequest(world, { envelope: draft, pdf }), 'the next upload, after the abort, returns its response');
  assert.equal(next.status, 200, `the next upload is admitted (${next.json?.code ?? 'no code'})`);
  assert.equal(next.json.version, 2);
});

test('[EH-02] uploadDocument never forwards a caller-supplied option to parsePdf (A-009 LBR-3)', () => {
  // Static: every parsePdf call in the envelope handlers passes exactly one argument (the
  // body), and nothing there reaches the parse service's test seams.
  const dir = join(REPO, 'src', 'api', 'envelopes');
  const sources = readdirSync(dir).filter((name) => name.endsWith('.ts')).map((name) => ({ name, text: readFileSync(join(dir, name), 'utf8') }));
  const calls = [];
  for (const { name, text } of sources) {
    for (const match of text.matchAll(/\bparsePdf\s*\(/g)) {
      // The argument list up to the matching close parenthesis.
      let depth = 1;
      let index = match.index + match[0].length;
      const start = index;
      while (index < text.length && depth > 0) {
        if (text[index] === '(') depth += 1;
        else if (text[index] === ')') depth -= 1;
        index += 1;
      }
      calls.push({ name, args: text.slice(start, index - 1) });
    }
    assert.doesNotMatch(text, /createParseServiceForTests|workerEntry|launchers\s*:/, `${name} reaches no parse service test seam`);
  }
  assert.ok(calls.length >= 1, 'the upload calls parsePdf');
  for (const { name, args } of calls) {
    let depth = 0;
    let topLevelCommas = 0;
    for (const char of args) {
      if ('([{'.includes(char)) depth += 1;
      else if (')]}'.includes(char)) depth -= 1;
      else if (char === ',' && depth === 0) topLevelCommas += 1;
    }
    assert.equal(topLevelCommas, 0, `${name}: parsePdf receives the body only, no options`);
  }
});

test('[EH-03] uploadDocument checks If-Match, the media type, the envelope and the parse outcome before recording anything, and stores the accepted bytes under their digest', async (t) => {
  const { world } = await flight(t, {});
  const pdf = documentBytes(SINGLE_PAGE);
  const draft = await createEnvelope(world);
  const path = `/v1/envelopes/${draft.id}/document`;
  const ticket = () => parseAdmissions().next_ticket;

  // Refusals decided before any body byte reaches the parse service.
  const before = ticket();
  const missing = await world.op({ method: 'PUT', path, body: pdf });
  assert.deepEqual([missing.status, missing.json?.code], [428, 'precondition_required'], 'no If-Match');
  for (const value of ['1', 'W/"1"', '"0"', '"01"', '"1", "2"']) {
    const malformed = await world.op({ method: 'PUT', path, body: pdf, ifMatch: value });
    assert.deepEqual([malformed.status, malformed.json?.code], [400, 'invalid_request'], 'a malformed If-Match');
  }
  const noKey = await world.op({ method: 'PUT', path, body: pdf, ifMatch: 1, key: null });
  assert.deepEqual([noKey.status, noKey.json?.code], [400, 'invalid_request'], 'no Idempotency-Key');
  const wrongType = await world.op({ method: 'PUT', path, body: pdf, ifMatch: 1, headers: { 'content-type': 'application/octet-stream' } });
  assert.deepEqual([wrongType.status, wrongType.json?.code], [415, 'unsupported_media_type']);
  const absent = await world.op({ method: 'PUT', path: `/v1/envelopes/${absentId()}/document`, body: pdf, ifMatch: 1 });
  assert.deepEqual([absent.status, absent.json?.code], [404, 'not_found']);
  const stale = await world.op({ method: 'PUT', path, body: pdf, ifMatch: 2 });
  assert.deepEqual([stale.status, stale.json?.code], [409, 'version_conflict']);
  assert.equal(ticket(), before, 'none of these refusals reached the parse service');

  // An unsupported PDF is 422 unsupported_pdf with its reason, and records nothing.
  const encrypted = await world.op({ method: 'PUT', path, body: documentBytes('encrypted-flag.pdf'), ifMatch: 1 });
  assert.deepEqual([encrypted.status, encrypted.json?.code], [422, 'unsupported_pdf']);
  assert.deepEqual(encrypted.json?.details, [{ field: 'document', code: 'encrypted' }]);
  assert.equal(world.rows('document_revisions').length, 0, 'a rejected document records no revision');

  // An accepted document: version + 1, geometry from the parse service, bytes stored under their digest.
  const accepted = await uploadDocument(world, { envelope: draft, pdf });
  assert.equal(accepted.version, 2);
  assert.equal(accepted.document.digest, sha256(pdf));
  assert.equal(accepted.document.bytes, pdf.length);
  assert.deepEqual(accepted.document.pages, [{ number: 1, width: 612, height: 792, rotate: 0 }]);
  assert.ok(world.blobs.read(TENANTS.alpha.id, sha256(pdf)).equals(pdf), 'the exact bytes are stored in the tenant\'s blob store');
  const [revision] = world.rows('document_revisions');
  const summary = JSON.parse(revision.parse_report_json);
  assert.equal(summary.digest, sha256(pdf));
  assert.equal(summary.network_sandbox === 'netns+fs-enforced (local)' || summary.network_sandbox === 'unavailable', true, 'the observed sandbox label is recorded');
  assert.equal(Object.hasOwn(summary, 'objects') || Object.hasOwn(summary, 'trailer'), false, 'the stored summary carries no document objects');

  // A prepared envelope takes no upload: 409 state_conflict, decided before the body is parsed.
  const prepared = await prepareEnvelope(world, { envelope: accepted });
  const parsedBefore = ticket();
  const late = await world.op({ method: 'PUT', path, body: pdf, ifMatch: prepared.version });
  assert.deepEqual([late.status, late.json?.code], [409, 'state_conflict']);
  assert.equal(ticket(), parsedBefore, 'the refused upload was never parsed');
});
