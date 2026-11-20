// SPDX-License-Identifier: Apache-2.0
//
// T034 expiry announcement (A-010 row EXPIRED-EVT, request #26; test EA-06).
//
// An operator request that finds a pre-reservation envelope past its expires_at makes T007's
// domain expire the envelope and refuse the request with 409 state_conflict. Through the
// EnvelopeApi, uploadDocument, prepareEnvelope, confirmSend, sendEnvelope and voidEnvelope
// can each commit such an expiry. Each must write exactly one envelope.expired outbox event,
// in the expiry's own transaction (T010's expiryAnnouncer, composed once as the
// EnvelopeService's onChange); no other change writes one, and a request on an envelope that
// is already expired commits no expiry and announces nothing.
//
// The upload is refused before its body is read or parsed (row UPLOAD-OVERDUE, request #27):
// its pre-parse check expires the envelope through T007's expiry path, so the parse service's
// admission counter (parseAdmissions().next_ticket) does not move, and the unread body gets
// the server's early-answer handling (Connection: close).
//
// "In the expiry's own transaction" is shown by what the event records: the outbox refuses an
// insert outside a transaction and accepts only the envelope version written in it, and the
// event carries the version and the instant of the expiry itself.
//
// This file has its own world, because it moves the world's clock past every envelope's
// expires_at. Operator credentials use real time and are unaffected.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

import { parseAdmissions } from '../../../src/pdf/service.ts';
import {
  SINGLE_PAGE,
  createEnvelope,
  createWorld,
  documentBytes,
  fieldsFor,
  preparedEnvelope,
  readPreview,
  sendRequest,
  sentEnvelope,
  uploadDocument,
  voidRequest,
} from './support.mjs';

let world;
before(async () => {
  world = await createWorld();
});
after(async () => {
  await world?.close();
});

/** The envelope.expired outbox events of one envelope, or of every envelope. */
function expiredEvents(envelopeId = null) {
  return envelopeId === null
    ? world.rows('outbox_events', 'WHERE type = ?', ['envelope.expired'])
    : world.rows('outbox_events', 'WHERE type = ? AND envelope_id = ?', ['envelope.expired', envelopeId]);
}

test('[EA-06] an expiry committed by an operator request writes exactly one envelope.expired, in the expiry\'s transaction; no other change writes one; an overdue upload is refused before any parse', async () => {
  // One envelope for each operator request that can commit an expiry, in the state it needs.
  const forUpload = await createEnvelope(world);
  const forPrepare = await uploadDocument(world, { envelope: await createEnvelope(world), pdf: documentBytes(SINGLE_PAGE) });
  const forConfirm = await preparedEnvelope(world);
  const confirmation = await readPreview(world, { envelope: forConfirm });
  const forSend = await preparedEnvelope(world);
  const { envelope: forVoid } = await sentEnvelope(world);
  assert.equal(expiredEvents().length, 0, 'create, upload, prepare and send (changes that are not an expiry) wrote no envelope.expired');

  // Every one of them is now past its expires_at.
  const envelopes = [forUpload, forPrepare, forConfirm, forSend, forVoid];
  const latest = Math.max(...envelopes.map((envelope) => Date.parse(envelope.expires_at)));
  world.time.advance(latest - world.time.now.getTime() + 1000);

  const attempts = [
    ['uploadDocument', forUpload, () => world.op({ method: 'PUT', path: `/v1/envelopes/${forUpload.id}/document`, body: documentBytes(SINGLE_PAGE), ifMatch: forUpload.version })],
    ['prepareEnvelope', forPrepare, () => world.op({ method: 'POST', path: `/v1/envelopes/${forPrepare.id}/prepare`, body: { expected_version: forPrepare.version, fields: fieldsFor(1) } })],
    [
      'confirmSend',
      forConfirm,
      () =>
        world.op({
          method: 'POST',
          path: `/v1/envelopes/${forConfirm.id}/send-confirmations`,
          body: { expected_version: confirmation.version, document_digest: confirmation.document.digest, manifest_digest: confirmation.manifest_digest, recipients_digest: confirmation.recipients_digest },
        }),
    ],
    ['sendEnvelope', forSend, () => sendRequest(world, { envelope: forSend })],
    ['voidEnvelope', forVoid, () => voidRequest(world, { envelope: forVoid })],
  ];
  for (const [label, envelope, attempt] of attempts) {
    const ticket = parseAdmissions().next_ticket;
    const response = await attempt();
    assert.deepEqual([response.status, response.json?.code], [409, 'state_conflict'], `${label}: refused, because the envelope has expired`);
    if (label === 'uploadDocument') {
      // UPLOAD-OVERDUE: refused by the pre-parse check, so nothing was parsed and the body was never read.
      assert.equal(parseAdmissions().next_ticket, ticket, 'uploadDocument: the overdue upload drew no parse ticket');
      assert.equal(response.headers.connection, 'close', 'uploadDocument: the unread body gets the early answer\'s Connection: close');
    }
    const [row] = world.rows('envelopes', 'WHERE id = ?', [envelope.id]);
    assert.equal(row.state, 'expired', `${label}: the request committed the expiry`);
    assert.equal(Number(row.version), envelope.version + 1, `${label}: the expiry wrote one new version`);
    const events = expiredEvents(envelope.id);
    assert.equal(events.length, 1, `${label}: exactly one envelope.expired (found ${events.length})`);
    assert.equal(Number(events[0].envelope_version), Number(row.version), `${label}: the event announces the version the expiry wrote`);
    assert.equal(events[0].created_at, row.updated_at, `${label}: the event was written at the expiry's instant`);

    // The envelope is expired now: the same request commits no expiry and announces nothing.
    const again = await attempt();
    assert.equal(again.status, 409, `${label}, again: refused`);
    assert.equal(expiredEvents(envelope.id).length, 1, `${label}, again: no second envelope.expired`);
    if (label === 'uploadDocument') assert.equal(parseAdmissions().next_ticket, ticket, 'uploadDocument, again: still nothing parsed');
  }
  assert.equal(expiredEvents().length, attempts.length, 'one envelope.expired for each committed expiry, and no other');
});
