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
// - An upload whose Idempotency-Key already has a record is resolved before any parse
//   (request #16): the same request replays, any other is 409 idempotency_conflict whatever
//   the PDF's validity, and the parse service's admission counter (parseAdmissions()
//   .next_ticket, which every parse that enters the gate advances) does not move. Only a new
//   key is parsed.
// Every request goes through the real router and handlers. "No second mutation" is checked
// on the content of every envelope table, so a replay that wrote anything at all would fail.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { parseAdmissions } from '../../../src/pdf/service.ts';
import {
  MULTI_PAGE,
  SINGLE_PAGE,
  createInput,
  createWorld,
  documentBytes,
  fieldsFor,
  newKey,
  readEnvelope,
  resendRequest,
  sendRequest,
  takeInvitation,
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
  assert.deepEqual(world.snapshot(), rows, `${label}: no second mutation (no row of any envelope table changed, audit events and idempotency records included)`);
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
  assert.deepEqual(world.snapshot(), rows, 'no envelope, recipient or idempotency record was written');
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
    assert.deepEqual(world.snapshot(), rows, `${label}: nothing changed`);
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
    assert.deepEqual(world.snapshot(), rows, `${label}: nothing changed`);
    assert.equal(world.mails().length, mails, `${label}: nothing mailed`);
    assert.equal(parseAdmissions().next_ticket, parsed, `${label}: nothing parsed (request #16)`);
  }

  // The void key, used once, then with another reason: the same rule.
  const voided = await voidRequest(world, { envelope: send.json, key: keys.void, reason: 'superseded' });
  assert.equal(voided.status, 200);
  const rows = world.snapshot();
  const conflict = await voidRequest(world, { envelope: send.json, key: keys.void, reason: 'error-in-document' });
  assert.deepEqual([conflict.status, conflict.json?.code], [409, 'idempotency_conflict'], 'void with another reason');
  assert.deepEqual(world.snapshot(), rows, 'void conflict: nothing changed');
});
