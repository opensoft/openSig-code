// SPDX-License-Identifier: Apache-2.0
//
// T034 request rules and idempotent mutation (EA-02, SC002-23; tasks.md § T006 readings and
// data-model.md § Transitions and races, item 1, and § IdempotencyRecord).
//
// - Duplicate or gapped recipient ordinals are 400 invalid_request (T006 reading (a)).
// - A malformed envelope_id in the path gets T031's uniform 404 not_found before auth (T006
//   reading (b) as re-ruled by request #16, row T006-EC22). That is the router's behaviour,
//   tested by T031's SEC-04 and by the amended EC-ENV-22 in manifest.test.mjs; this file has
//   no case of its own for it.
// - Create sets version 1; each successful upload and prepare adds exactly 1; reads, refused
//   requests and replays add nothing (T006 reading (c)).
// - The same Idempotency-Key with the same payload replays the stored status and the exact
//   stored bytes, with no second mutation, version change, audit event or mail, also after
//   the envelope has moved on (EA-02). A changed payload is 409 idempotency_conflict and
//   changes nothing (SC002-23).
// - Every idempotent handler resolves an existing key before it validates the body (row
//   T034R-RESEND, request #23): a reused key with a malformed body (one that breaks the
//   schema, or one that is not JSON at all) is 409 idempotency_conflict, never 400, and
//   changes nothing. Under a new key the same bodies are 400. A body the client aborts under a
//   reused key was never compared: it is logged as the abort, exactly as under a new key,
//   never as 409, and writes nothing (request #25). Looking a key up takes no write lock, so
//   while another connection holds it the transport answers (415, the body timer's 408) still
//   come at once and first. The upload's pre-parse check reads without a write lock too, so a
//   new-key upload whose streamed body is too large is 413 at once while the lock is held.
// - An upload whose Idempotency-Key already has a record is resolved before any parse
//   (request #16): the same request replays, any other is 409 idempotency_conflict whatever
//   the PDF's validity, and the parse service's admission counter (parseAdmissions()
//   .next_ticket, which every parse that enters the gate advances) does not move. Only a new
//   key is parsed.
// Every request goes through the real router and handlers. "No second mutation" is checked
// on the content of every envelope table, so a replay that wrote anything at all would fail.

import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { DatabaseSync } from 'node:sqlite';
import { after, before, test } from 'node:test';

import { EnvelopeApi } from '../../../src/api/envelopes/index.ts';
import { DEFAULT_PARSER_LIMITS } from '../../../src/pdf/limits.ts';
import { parseAdmissions } from '../../../src/pdf/service.ts';
import { loadServerConfig } from '../../../src/server/config.ts';
import {
  MULTI_PAGE,
  SINGLE_PAGE,
  assertSameRows,
  confirmRequest,
  createEnvelope,
  createInput,
  createWorld,
  documentBytes,
  fieldsFor,
  heldJsonRequest,
  isIdle,
  newKey,
  readEnvelope,
  requestLog,
  resendRequest,
  sendRequest,
  sentEnvelope,
  showState,
  streamedUpload,
  takeInvitation,
  until,
  voidRequest,
} from './support.mjs';

let world;
before(async () => {
  world = await createWorld();
});
after(async () => {
  await world?.close();
});

/** A replay: the same status and the exact bytes, and nothing written, mailed or parsed. */
async function assertReplay(label, original, replayOf) {
  const rows = world.snapshot();
  const mails = world.mails().length;
  const replay = await replayOf();
  assert.equal(replay.status, original.status, `${label}: the stored status`);
  assert.ok(replay.bytes.equals(original.bytes), `${label}: byte-identical to the original response`);
  assertSameRows(world.snapshot(), rows, `${label}: no second mutation (no row of any envelope table changed, audit events and idempotency records included)`);
  assert.equal(world.mails().length, mails, `${label}: nothing mailed`);
  return replay;
}

test('[EA-02] duplicate or gapped recipient ordinals are 400 invalid_request, and nothing is created', async () => {
  const rows = world.snapshot();
  const shapes = {
    duplicate: [
      { email: 'signer.one@example.test', role: 'approver', ordinal: 1 },
      { email: 'signer.two@example.test', role: 'countersigner', ordinal: 1 },
    ],
    'gap before 2': [{ email: 'signer.two@example.test', role: 'countersigner', ordinal: 2 }],
    'duplicate 2': [
      { email: 'signer.one@example.test', role: 'approver', ordinal: 2 },
      { email: 'signer.two@example.test', role: 'countersigner', ordinal: 2 },
    ],
  };
  for (const [label, recipients] of Object.entries(shapes)) {
    for (const who of ['sender', 'service']) {
      const response = await world.op({ who, method: 'POST', path: '/v1/envelopes', body: createInput(1, { recipients }) });
      assert.equal(response.status, 400, `${label} (${who}): 400`);
      assert.equal(response.json?.code, 'invalid_request', `${label} (${who}): invalid_request`);
    }
  }
  assertSameRows(world.snapshot(), rows, 'no envelope, recipient or idempotency record was written');
  // Control: ordinals 2 then 1 are not a gap.
  const reordered = await world.op({ method: 'POST', path: '/v1/envelopes', body: createInput(2, { recipients: [...createInput(2).recipients].reverse() }) });
  assert.equal(reordered.status, 201);
  assert.deepEqual(reordered.json.recipients.map((recipient) => recipient.ordinal), [1, 2]);
});

test('[EA-02] create sets version 1, and each upload and prepare adds exactly 1; reads, refusals and replays add nothing', async () => {
  const create = await world.op({ method: 'POST', path: '/v1/envelopes', body: createInput(2) });
  assert.equal(create.status, 201);
  assert.equal(create.json.version, 1, 'create: version 1');
  const id = create.json.id;
  const path = `/v1/envelopes/${id}`;
  const version = async () => (await readEnvelope(world, { envelope: { id } })).version;
  assert.equal(await version(), 1, 'a read leaves it');

  const first = await world.op({ method: 'PUT', path: `${path}/document`, body: documentBytes(SINGLE_PAGE), ifMatch: 1 });
  assert.equal(first.status, 200);
  assert.equal(first.json.version, 2, 'upload: + 1');
  const second = await world.op({ method: 'PUT', path: `${path}/document`, body: documentBytes(MULTI_PAGE), ifMatch: 2 });
  assert.equal(second.status, 200);
  assert.equal(second.json.version, 3, 'a replacing upload: + 1');

  // Refusals leave the version: a stale If-Match, a stale expected_version, an invalid field.
  assert.equal((await world.op({ method: 'PUT', path: `${path}/document`, body: documentBytes(SINGLE_PAGE), ifMatch: 2 })).status, 409);
  assert.equal((await world.op({ method: 'POST', path: `${path}/prepare`, body: { expected_version: 2, fields: fieldsFor(2) } })).status, 409);
  const outside = fieldsFor(2).map((field, index) => (index === 0 ? { ...field, rect: { x: 0.9, y: 0.9, width: 0.3, height: 0.3 } } : field));
  assert.equal((await world.op({ method: 'POST', path: `${path}/prepare`, body: { expected_version: 3, fields: outside } })).status, 422);
  assert.equal(await version(), 3, 'refused requests leave it');

  const key = newKey();
  const prepare = await world.op({ method: 'POST', path: `${path}/prepare`, body: { expected_version: 3, fields: fieldsFor(2) }, key });
  assert.equal(prepare.status, 200);
  assert.equal(prepare.json.version, 4, 'prepare: + 1');
  const replay = await world.op({ method: 'POST', path: `${path}/prepare`, body: { expected_version: 3, fields: fieldsFor(2) }, key });
  assert.equal(replay.status, 200);
  assert.equal(replay.json.version, 4, 'the replay answers the original version');
  assert.equal(await version(), 4, 'a replay leaves it');
});

test('[EA-02] the same Idempotency-Key with the same payload replays the stored status and exact body, with no second mutation, version change, audit event or mail, also after the envelope has moved on', async () => {
  const ticket = () => parseAdmissions().next_ticket;
  const keys = { create: newKey(), upload: newKey(), prepare: newKey(), send: newKey(), resend: newKey(), void: newKey() };
  const input = createInput(1);
  const pdf = documentBytes(SINGLE_PAGE);

  const create = await world.op({ method: 'POST', path: '/v1/envelopes', body: input, key: keys.create });
  assert.equal(create.status, 201);
  const id = create.json.id;
  const path = `/v1/envelopes/${id}`;
  await assertReplay('create, at once', create, () => world.op({ method: 'POST', path: '/v1/envelopes', body: input, key: keys.create }));

  const upload = await world.op({ method: 'PUT', path: `${path}/document`, body: pdf, ifMatch: 1, key: keys.upload });
  assert.equal(upload.status, 200);
  const prepareBody = { expected_version: 2, fields: fieldsFor(1) };
  const prepare = await world.op({ method: 'POST', path: `${path}/prepare`, body: prepareBody, key: keys.prepare });
  assert.equal(prepare.status, 200);
  const send = await sendRequest(world, { envelope: prepare.json, key: keys.send });
  assert.equal(send.status, 200);
  assert.equal(send.json.state, 'sent');
  takeInvitation(world);
  const recipient = send.json.recipients[0];
  const resend = await resendRequest(world, { envelope: send.json, recipient, key: keys.resend });
  assert.equal(resend.status, 202);
  assert.deepEqual(resend.json, { status: 'accepted' });
  takeInvitation(world);

  // The envelope has moved on (sent, resent); every earlier key still replays its original answer.
  await assertReplay('create, after send', create, () => world.op({ method: 'POST', path: '/v1/envelopes', body: input, key: keys.create }));
  const parsed = ticket();
  const uploadReplay = await assertReplay('upload, after send', upload, () => world.op({ method: 'PUT', path: `${path}/document`, body: pdf, ifMatch: 1, key: keys.upload }));
  assert.equal(uploadReplay.json.state, 'draft', 'the upload replay is the original draft response');
  assert.equal(ticket(), parsed, 'the upload replay was resolved before any parse: no parse ticket drawn (request #16)');
  await assertReplay('prepare, after send', prepare, () => world.op({ method: 'POST', path: `${path}/prepare`, body: prepareBody, key: keys.prepare }));
  await assertReplay('send, after resend', send, () => sendRequest(world, { envelope: prepare.json, key: keys.send }));
  await assertReplay('resend, at once', resend, () => resendRequest(world, { envelope: send.json, recipient, key: keys.resend }));

  // Void, then every key again: the original answers, nothing new.
  const voided = await voidRequest(world, { envelope: send.json, key: keys.void });
  assert.equal(voided.status, 200);
  await assertReplay('send, after void', send, () => sendRequest(world, { envelope: prepare.json, key: keys.send }));
  await assertReplay('resend, after void', resend, () => resendRequest(world, { envelope: send.json, recipient, key: keys.resend }));
  await assertReplay('void, at once', voided, () => voidRequest(world, { envelope: send.json, key: keys.void }));
  assert.equal((await readEnvelope(world, { envelope: { id } })).version, voided.json.version, 'the replays left the version');

  // The key is scoped by principal: the same key from another operator is that operator's own request.
  const other = await world.op({ who: 'service', method: 'POST', path: '/v1/envelopes', body: input, key: keys.create });
  assert.equal(other.status, 201, 'another principal\'s request with the same key is a new request');
  assert.notEqual(other.json.id, id);
});

test('[EA-02] an upload whose Idempotency-Key already has a record is resolved before any parse: the same request replays, any other is 409 idempotency_conflict whatever the PDF, and no parse ticket is drawn (request #16)', async () => {
  const ticket = () => parseAdmissions().next_ticket;
  const pdf = documentBytes(SINGLE_PAGE);
  const encrypted = documentBytes('encrypted-flag.pdf');
  const notPdf = Buffer.from('synthetic upload body that is not a PDF document\n', 'utf8');
  const key = newKey();

  const create = await world.op({ method: 'POST', path: '/v1/envelopes', body: createInput(1) });
  assert.equal(create.status, 201);
  const path = `/v1/envelopes/${create.json.id}`;
  const first = ticket();
  const upload = await world.op({ method: 'PUT', path: `${path}/document`, body: pdf, ifMatch: 1, key });
  assert.equal(upload.status, 200);
  assert.equal(ticket(), first + 1, 'a new key is parsed: one parse ticket');

  // The same key and the same request: the stored answer, and the parse service is not called.
  const parsed = ticket();
  await assertReplay('upload replay', upload, () => world.op({ method: 'PUT', path: `${path}/document`, body: pdf, ifMatch: 1, key }));
  assert.equal(ticket(), parsed, 'upload replay: no parse ticket drawn');

  // The same key and another request: 409, whatever the body, and still no parse.
  const other = await world.op({ method: 'POST', path: '/v1/envelopes', body: createInput(1) });
  assert.equal(other.status, 201);
  const conflicts = [
    ['another valid PDF', () => world.op({ method: 'PUT', path: `${path}/document`, body: documentBytes(MULTI_PAGE), ifMatch: 1, key })],
    ['bytes that are not a PDF', () => world.op({ method: 'PUT', path: `${path}/document`, body: notPdf, ifMatch: 1, key })],
    ['a PDF the parse service would refuse (encrypted)', () => world.op({ method: 'PUT', path: `${path}/document`, body: encrypted, ifMatch: 1, key })],
    ['the same PDF under another If-Match', () => world.op({ method: 'PUT', path: `${path}/document`, body: pdf, ifMatch: 2, key })],
    ['the same PDF on another envelope', () => world.op({ method: 'PUT', path: `/v1/envelopes/${other.json.id}/document`, body: pdf, ifMatch: 1, key })],
  ];
  for (const [label, attempt] of conflicts) {
    const rows = world.snapshot();
    const response = await attempt();
    assert.deepEqual([response.status, response.json?.code], [409, 'idempotency_conflict'], `${label}: 409 idempotency_conflict (got ${response.status})`);
    assertSameRows(world.snapshot(), rows, `${label}: nothing changed`);
    assert.equal(ticket(), parsed, `${label}: no parse ticket drawn`);
  }

  // Controls, so the counter is shown to move when a parse happens: a new key with the refused
  // PDF reaches the parse service (422, one ticket), and the same key from another principal
  // is that principal's own new upload (200, one ticket).
  const refused = await world.op({ method: 'PUT', path: `${path}/document`, body: encrypted, ifMatch: 2 });
  assert.equal(refused.status, 422, 'a new key with the refused PDF reaches the parse service');
  assert.equal(ticket(), parsed + 1, 'and draws one parse ticket');
  const theirs = await world.op({ who: 'service', method: 'POST', path: '/v1/envelopes', body: createInput(1) });
  assert.equal(theirs.status, 201);
  const theirUpload = await world.op({ who: 'service', method: 'PUT', path: `/v1/envelopes/${theirs.json.id}/document`, body: pdf, ifMatch: 1, key });
  assert.equal(theirUpload.status, 200, 'the same key from another principal is a new upload');
  assert.equal(ticket(), parsed + 2, 'and is parsed');
});

test('[EA-02] every idempotent handler resolves an existing key before it validates the body: a reused key with a malformed body is 409 idempotency_conflict, never 400 (T034R-RESEND)', async () => {
  const ticket = () => parseAdmissions().next_ticket;
  const keys = { create: newKey(), upload: newKey(), prepare: newKey(), confirm: newKey(), send: newKey(), resend: newKey(), void: newKey(), reissue: newKey() };

  // Each key is first used once, successfully, by the same principal.
  const create = await world.op({ method: 'POST', path: '/v1/envelopes', body: createInput(1), key: keys.create });
  assert.equal(create.status, 201);
  const path = `/v1/envelopes/${create.json.id}`;
  const upload = await world.op({ method: 'PUT', path: `${path}/document`, body: documentBytes(SINGLE_PAGE), ifMatch: 1, key: keys.upload });
  assert.equal(upload.status, 200);
  const prepare = await world.op({ method: 'POST', path: `${path}/prepare`, body: { expected_version: 2, fields: fieldsFor(1) }, key: keys.prepare });
  assert.equal(prepare.status, 200);
  const confirm = await confirmRequest(world, { envelope: prepare.json, key: keys.confirm });
  assert.equal(confirm.status, 201);
  const send = await sendRequest(world, { envelope: prepare.json, key: keys.send });
  assert.equal(send.status, 200);
  takeInvitation(world);
  const recipient = send.json.recipients[0];
  const resend = await resendRequest(world, { envelope: send.json, recipient, key: keys.resend });
  assert.equal(resend.status, 202);
  takeInvitation(world);
  const voided = await voidRequest(world, { envelope: send.json, key: keys.void });
  assert.equal(voided.status, 200);
  const reissue = await world.op({ method: 'POST', path: `${path}/reissue`, body: { expected_version: voided.json.version }, key: keys.reissue });
  assert.equal(reissue.status, 201);

  // resendInvitation first: it is the handler that validated its body before its key.
  const routes = [
    ['resendInvitation', (body, key = keys.resend) => world.op({ method: 'POST', path: `${path}/recipients/${recipient.id}/resend-invitation`, body, key })],
    ['createEnvelope', (body, key = keys.create) => world.op({ method: 'POST', path: '/v1/envelopes', body, key })],
    ['prepareEnvelope', (body, key = keys.prepare) => world.op({ method: 'POST', path: `${path}/prepare`, body, key })],
    ['confirmSend', (body, key = keys.confirm) => world.op({ method: 'POST', path: `${path}/send-confirmations`, body, key })],
    ['sendEnvelope', (body, key = keys.send) => world.op({ method: 'POST', path: `${path}/send`, body, key })],
    ['voidEnvelope', (body, key = keys.void) => world.op({ method: 'POST', path: `${path}/void`, body, key })],
    ['reissueEnvelope', (body, key = keys.reissue) => world.op({ method: 'POST', path: `${path}/reissue`, body, key })],
  ];
  const NOT_JSON = '{"expected_version": ';
  const malformed = [
    ['a JSON body that breaks the schema', {}],
    ['a body that is not JSON', NOT_JSON],
  ];
  const attempts = [];
  for (const [route, request] of routes) for (const [shape, body] of malformed) attempts.push([`${route}, ${shape}`, () => request(body)]);
  attempts.push(['uploadDocument, a body that is not a PDF', () => world.op({ method: 'PUT', path: `${path}/document`, body: Buffer.from('synthetic upload body that is not a PDF document\n', 'utf8'), ifMatch: 1, key: keys.upload })]);

  const parsed = ticket();
  for (const [label, attempt] of attempts) {
    const rows = world.snapshot();
    const mails = world.mails().length;
    const response = await attempt();
    assert.deepEqual([response.status, response.json?.code], [409, 'idempotency_conflict'], `${label}, under the reused key: 409 idempotency_conflict (got ${response.status} ${response.json?.code ?? ''})`);
    assertSameRows(world.snapshot(), rows, `${label}: nothing changed`);
    assert.equal(world.mails().length, mails, `${label}: nothing mailed`);
    assert.equal(ticket(), parsed, `${label}: nothing parsed`);
  }

  // Controls: under a new key the same bodies are the request's own 400, so the 409 above came
  // from the key. A body that is not JSON is refused by every handler; resend checks its body
  // (now after the key) before the envelope's state.
  for (const [route, request] of routes) {
    const response = await request(NOT_JSON, newKey());
    assert.deepEqual([response.status, response.json?.code], [400, 'invalid_request'], `${route}, a body that is not JSON, under a new key: 400`);
  }
  const [, resendWith] = routes[0];
  const fresh = await resendWith({}, newKey());
  assert.deepEqual([fresh.status, fresh.json?.code], [400, 'invalid_request'], 'resendInvitation, a JSON body that breaks the schema, under a new key: 400');
});

test('[EA-02] a body aborted under a reused key is logged as the abort, as under a new key, never as 409, and writes nothing (request #25)', async (t) => {
  const sockets = new Set();
  t.after(() => {
    for (const socket of sockets) socket.destroy();
  });
  // Barrier: the handler looks its key up at arrival, just before it reads the body, so
  // counting the lookups tells the test that the body is being read when it aborts.
  assert.equal(typeof EnvelopeApi.prototype.hasLiveRecord, 'function', 'the API looks an Idempotency-Key up at arrival');
  const original = EnvelopeApi.prototype.hasLiveRecord;
  let lookups = 0;
  EnvelopeApi.prototype.hasLiveRecord = function counted(...args) {
    lookups += 1;
    return original.apply(this, args);
  };
  t.after(() => {
    EnvelopeApi.prototype.hasLiveRecord = original;
  });

  const { envelope } = await sentEnvelope(world);
  const recipient = envelope.recipients[0];
  const key = newKey();
  const resent = await resendRequest(world, { envelope, recipient, key });
  assert.equal(resent.status, 202);
  takeInvitation(world);
  const path = `/v1/envelopes/${envelope.id}/recipients/${recipient.id}/resend-invitation`;
  // A changed payload: completed under the reused key it would be 409 (the control below).
  const body = { expected_version: envelope.version + 1 };

  /** Send part of the body, abort once the handler reads it, and return the logged status. */
  async function aborted(useKey, label) {
    const logged = requestLog(world, 'resendInvitation', path).length;
    const seen = lookups;
    const socket = heldJsonRequest(world, sockets, { path, key: useKey, body, sendBytes: 5 });
    await until(() => lookups > seen, `${label}: the handler looked its key up and reads the body`);
    socket.destroy();
    await until(() => requestLog(world, 'resendInvitation', path).length === logged + 1, `${label}: the server logs the aborted request`);
    return requestLog(world, 'resendInvitation', path).at(-1).status;
  }

  const rows = world.snapshot();
  const mails = world.mails().length;
  const exceptions = world.logged('handler_exception').length;
  const underNewKey = await aborted(newKey(), 'abort under a new key');
  const underReusedKey = await aborted(key, 'abort under the reused key');
  assert.ok(underNewKey >= 400 && underNewKey < 500 && underNewKey !== 409, `an abort under a new key has T031's abort answer (status ${underNewKey})`);
  assert.equal(underReusedKey, underNewKey, `an abort under the reused key is logged as the same abort, never as 409 (status ${underReusedKey})`);
  assertSameRows(world.snapshot(), rows, 'the aborted requests wrote nothing: no record, no mutation');
  assert.equal(world.mails().length, mails, 'and mailed nothing');
  assert.equal(world.logged('handler_exception').length, exceptions, 'no handler exception');

  // Control: the same changed body, completed under the reused key, is the conflict.
  const completed = await resendRequest(world, { envelope, recipient, key, version: envelope.version + 1 });
  assert.deepEqual([completed.status, completed.json?.code], [409, 'idempotency_conflict'], 'the completed changed body under the reused key is 409');
});

test('[EA-02] looking up a reused key takes no write lock: while another connection holds it, a wrong media type is 415 at once and a stalled body is 408, and nothing is written (request #25)', async (t) => {
  const sockets = new Set();
  t.after(() => {
    for (const socket of sockets) socket.destroy();
  });
  const { envelope } = await sentEnvelope(world);
  const recipient = envelope.recipients[0];
  const key = newKey();
  const resent = await resendRequest(world, { envelope, recipient, key });
  assert.equal(resent.status, 202);
  takeInvitation(world);
  const path = `/v1/envelopes/${envelope.id}/recipients/${recipient.id}/resend-invitation`;
  const body = { expected_version: envelope.version };
  const busy = world.db.busyTimeoutMs;
  const rows = world.snapshot();
  const exceptions = world.logged('handler_exception').length;

  // A second connection on the same database file holds the write lock throughout.
  const locker = new DatabaseSync(world.path);
  let wrongType;
  let elapsed;
  let stalled;
  try {
    locker.exec('BEGIN IMMEDIATE');
    const started = performance.now();
    wrongType = await world.op({ method: 'POST', path, key, body: JSON.stringify(body), headers: { 'content-type': 'text/plain' } });
    elapsed = performance.now() - started;
    // A stalled body under the reused key: the server's body timer answers it (T031 default).
    const logged = requestLog(world, 'resendInvitation', path).length;
    heldJsonRequest(world, sockets, { path, key, body, sendBytes: 5 });
    await until(() => requestLog(world, 'resendInvitation', path).length === logged + 1, 'the stalled body under the reused key is answered');
    stalled = requestLog(world, 'resendInvitation', path).at(-1).status;
  } finally {
    if (locker.isTransaction) locker.exec('ROLLBACK');
    locker.close();
  }
  t.diagnostic(`415 under a held write lock in ${Math.round(elapsed)} ms (busy timeout ${busy} ms)`);
  assert.deepEqual([wrongType.status, wrongType.json?.code], [415, 'unsupported_media_type'], `a wrong media type under the reused key is 415 while another connection holds the write lock (got ${wrongType.status} ${wrongType.json?.code ?? ''})`);
  assert.ok(elapsed < busy / 2, `the 415 came at once: ${Math.round(elapsed)} ms, against a busy timeout of ${busy} ms`);
  assert.equal(stalled, 408, `a stalled body under the reused key is the body timer's 408, while the lock is held (status ${stalled})`);
  assertSameRows(world.snapshot(), rows, 'nothing was written');
  assert.equal(world.logged('handler_exception').length, exceptions, 'no handler exception');
});

test('[EA-02] the upload\'s pre-parse check takes no write lock: while another connection holds it, a new-key upload whose streamed body is too large is 413 at once, with nothing written and nothing parsed (request #25)', async (t) => {
  const draft = await createEnvelope(world);
  // Over both the server's PDF body limit and the parse service's: a chunked body with no
  // Content-Length, so only reading it can find it too large.
  const limit = Math.max(loadServerConfig({ OPENSIG_PORT: '0' }).limits.pdfBytes, DEFAULT_PARSER_LIMITS.maxBytes);
  const oversized = Buffer.alloc(limit + 64 * 1024, 0x20);
  const busy = world.db.busyTimeoutMs;
  const rows = world.snapshot();
  const ticket = parseAdmissions().next_ticket;
  const exceptions = world.logged('handler_exception').length;

  // A second connection on the same database file holds the write lock throughout.
  const locker = new DatabaseSync(world.path);
  let answer;
  let elapsed;
  try {
    locker.exec('BEGIN IMMEDIATE');
    const started = performance.now();
    answer = await streamedUpload(world, { envelope: draft, bytes: oversized });
    elapsed = performance.now() - started;
  } finally {
    if (locker.isTransaction) locker.exec('ROLLBACK');
    locker.close();
  }
  t.diagnostic(`streamed over-limit upload answered under a held write lock in ${Math.round(elapsed)} ms (busy timeout ${busy} ms)`);
  assert.deepEqual([answer.status, answer.json?.code], [413, 'payload_too_large'], `a new-key upload whose streamed body is too large is 413 while another connection holds the write lock (got ${answer.status} ${answer.json?.code ?? ''})`);
  assert.ok(elapsed < busy / 2, `the 413 came at once: ${Math.round(elapsed)} ms, against a busy timeout of ${busy} ms`);
  assertSameRows(world.snapshot(), rows, 'nothing was written');
  assert.equal(parseAdmissions().next_ticket, ticket, 'nothing was parsed');
  assert.ok(isIdle(), `the upload slot and the body-read permit are released (${showState()})`);
  assert.equal(world.logged('handler_exception').length, exceptions, 'no handler exception');
});

test('[SC002-23] the same Idempotency-Key with a changed payload is 409 idempotency_conflict and changes nothing', async () => {
  const keys = { create: newKey(), upload: newKey(), prepare: newKey(), send: newKey(), resend: newKey(), void: newKey() };
  const create = await world.op({ method: 'POST', path: '/v1/envelopes', body: createInput(1), key: keys.create });
  const id = create.json.id;
  const path = `/v1/envelopes/${id}`;
  const upload = await world.op({ method: 'PUT', path: `${path}/document`, body: documentBytes(SINGLE_PAGE), ifMatch: 1, key: keys.upload });
  const prepare = await world.op({ method: 'POST', path: `${path}/prepare`, body: { expected_version: 2, fields: fieldsFor(1) }, key: keys.prepare });
  const send = await sendRequest(world, { envelope: prepare.json, key: keys.send });
  takeInvitation(world);
  const recipient = send.json.recipients[0];
  const resend = await resendRequest(world, { envelope: send.json, recipient, key: keys.resend });
  takeInvitation(world);
  assert.deepEqual([create.status, upload.status, prepare.status, send.status, resend.status], [201, 200, 200, 200, 202]);

  const changed = [
    ['create', () => world.op({ method: 'POST', path: '/v1/envelopes', body: createInput(1, { source: { app: 'manual', record: 'synthetic-record-0002', version: 'v1' } }), key: keys.create })],
    ['upload (another document)', () => world.op({ method: 'PUT', path: `${path}/document`, body: documentBytes(MULTI_PAGE), ifMatch: 1, key: keys.upload })],
    ['prepare (other fields)', () => world.op({ method: 'POST', path: `${path}/prepare`, body: { expected_version: 2, fields: fieldsFor(1).slice(0, 1) }, key: keys.prepare })],
    ['send (another version)', () => sendRequest(world, { envelope: prepare.json, version: send.json.version, key: keys.send })],
    ['resend (another version)', () => resendRequest(world, { envelope: send.json, recipient, version: send.json.version + 1, key: keys.resend })],
  ];
  const parsed = parseAdmissions().next_ticket;
  for (const [label, attempt] of changed) {
    const rows = world.snapshot();
    const mails = world.mails().length;
    const response = await attempt();
    assert.equal(response.status, 409, `${label}: 409 (got ${response.status} ${response.json?.code ?? ''})`);
    assert.equal(response.json?.code, 'idempotency_conflict', `${label}: idempotency_conflict`);
    assertSameRows(world.snapshot(), rows, `${label}: nothing changed`);
    assert.equal(world.mails().length, mails, `${label}: nothing mailed`);
    assert.equal(parseAdmissions().next_ticket, parsed, `${label}: nothing parsed (request #16)`);
  }

  // The void key, used once, then with another reason: the same rule.
  const voided = await voidRequest(world, { envelope: send.json, key: keys.void, reason: 'superseded' });
  assert.equal(voided.status, 200);
  const rows = world.snapshot();
  const conflict = await voidRequest(world, { envelope: send.json, key: keys.void, reason: 'error-in-document' });
  assert.deepEqual([conflict.status, conflict.json?.code], [409, 'idempotency_conflict'], 'void with another reason');
  assertSameRows(world.snapshot(), rows, 'void conflict: nothing changed');
});
