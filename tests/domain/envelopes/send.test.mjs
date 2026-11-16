// SPDX-License-Identifier: Apache-2.0
//
// Send rules (T007): a service-created envelope is sent only with a
// single-use, digest-bound, unexpired SendConfirmation made by a human
// operator (contract § Sending and human confirmation).

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { confirmationProblems } from '../../../src/domain/envelopes/index.ts';
import { consumeSendConfirmation, getSendConfirmation, insertSendConfirmation } from '../../../src/storage/repositories/envelopes.ts';
import {
  BASE_TIME,
  contractErrors,
  createInput,
  documentInput,
  fieldsFor,
  hex,
  HUMAN,
  makeScratch,
  preparedEnvelope,
  refusedByTrigger,
  rejectsWith,
  req,
  SERVICE,
  setup,
  sid,
} from './support.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

const HOUR = 60 * 60 * 1000;

function confirmInput(preview, overrides = {}) {
  return {
    expected_version: preview.version,
    document_digest: preview.document.digest,
    manifest_digest: preview.manifest_digest,
    recipients_digest: preview.recipients_digest,
    ...overrides,
  };
}

function storedConfirmation(ctx, reference) {
  return ctx.db.transaction(() => getSendConfirmation(ctx.db.forTenant(ctx.tenant), reference));
}

test('[ST-07] a service-created envelope needs a human confirmation of the exact preview, which one send consumes', () => {
  const ctx = setup(scratch);
  try {
    const prepared = preparedEnvelope(ctx, { creator: SERVICE });
    assert.deepEqual(prepared.send_confirmation, { required: true, authorization_reference: null });
    rejectsWith(() => ctx.service.send(req(ctx.tenant, SERVICE), prepared.id, { expected_version: prepared.version }), 'confirmation_required', 409);
    rejectsWith(() => ctx.service.send(req(ctx.tenant, HUMAN), prepared.id, { expected_version: prepared.version }), 'confirmation_required', 409);

    const preview = ctx.service.preview(req(ctx.tenant, SERVICE), prepared.id);
    assert.equal(preview.requires_human_confirmation, true);
    rejectsWith(() => ctx.service.confirmSend(req(ctx.tenant, SERVICE), prepared.id, confirmInput(preview)), 'forbidden', 403);
    rejectsWith(() => ctx.service.confirmSend(req(ctx.tenant, HUMAN), prepared.id, confirmInput(preview, { recipients_digest: hex('other-recipients') })), 'digest_mismatch', 409);
    rejectsWith(() => ctx.service.confirmSend(req(ctx.tenant, HUMAN), prepared.id, confirmInput(preview, { manifest_digest: hex('other-manifest') })), 'digest_mismatch', 409);
    rejectsWith(() => ctx.service.confirmSend(req(ctx.tenant, HUMAN), prepared.id, confirmInput(preview, { document_digest: hex('other-document') })), 'digest_mismatch', 409);
    rejectsWith(() => ctx.service.confirmSend(req(ctx.tenant, HUMAN), prepared.id, confirmInput(preview, { expected_version: preview.version - 1 })), 'version_conflict', 409);
    assert.equal(ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).count('send_confirmations')), 0, 'no refused confirmation was stored');

    const confirmed = ctx.service.confirmSend(req(ctx.tenant, HUMAN), prepared.id, confirmInput(preview));
    assert.equal(confirmed.status, 201);
    const confirmation = confirmed.body;
    assert.deepEqual(contractErrors('SendConfirmation', confirmation), []);
    assert.equal(confirmation.envelope_id, prepared.id);
    assert.equal(confirmation.envelope_version, prepared.version);
    assert.deepEqual(confirmation.confirmed_by, HUMAN);
    assert.equal(confirmation.expires_at, new Date(BASE_TIME + 24 * HOUR).toISOString(), '24 hours, earlier than the 7-day envelope expiry');
    assert.equal(ctx.service.read(req(ctx.tenant, SERVICE), prepared.id).send_confirmation.authorization_reference, confirmation.authorization_reference);

    const other = preparedEnvelope(ctx, { creator: SERVICE });
    rejectsWith(
      () => ctx.service.send(req(ctx.tenant, SERVICE), other.id, { expected_version: other.version, authorization_reference: confirmation.authorization_reference }),
      'confirmation_invalid',
      409,
    );
    rejectsWith(
      () => ctx.service.send(req(ctx.tenant, SERVICE), prepared.id, { expected_version: prepared.version, authorization_reference: sid('unknown-ref') }),
      'confirmation_invalid',
      409,
    );

    const sent = ctx.service.send(req(ctx.tenant, SERVICE), prepared.id, { expected_version: prepared.version, authorization_reference: confirmation.authorization_reference }).body;
    assert.equal(sent.state, 'sent');
    assert.equal(sent.version, prepared.version + 1);
    assert.deepEqual(sent.recipients.map((r) => [r.status, r.invited_at]), [['invited', ctx.time.now.toISOString()]]);
    assert.equal(sent.send_confirmation.authorization_reference, null, 'a consumed confirmation is no longer offered');
    assert.equal(storedConfirmation(ctx, confirmation.authorization_reference).consumedAt, ctx.time.now.toISOString(), 'the send consumed it');
    assert.equal(JSON.stringify(sent).includes('#i='), false, 'the response carries no invitation link');

    // Single use: a confirmation consumed elsewhere is refused, and the schema refuses a second consumption.
    const third = preparedEnvelope(ctx, { creator: SERVICE });
    const thirdRef = ctx.service.confirmSend(req(ctx.tenant, HUMAN), third.id, confirmInput(ctx.service.preview(req(ctx.tenant), third.id))).body.authorization_reference;
    assert.equal(ctx.db.transaction(() => consumeSendConfirmation(ctx.db.forTenant(ctx.tenant), thirdRef, ctx.time.now.toISOString())), true);
    rejectsWith(() => ctx.service.send(req(ctx.tenant, SERVICE), third.id, { expected_version: third.version, authorization_reference: thirdRef }), 'confirmation_invalid', 409);
    refusedByTrigger(ctx.db, () => ctx.db.forTenant(ctx.tenant).update('send_confirmations', { authorization_reference: thirdRef }, { consumed_at: new Date(BASE_TIME + HOUR).toISOString() }), /single use/);
    assert.equal(ctx.service.read(req(ctx.tenant), third.id).state, 'prepared');
  } finally {
    ctx.db.close();
  }
});

test('[ST-07] a confirmation is refused once expired, when bound to another version or digest set, and can never come from a service principal; human-created envelopes need none', () => {
  const ctx = setup(scratch);
  try {
    const stale = preparedEnvelope(ctx, { creator: SERVICE });
    const staleRef = ctx.service.confirmSend(req(ctx.tenant, HUMAN), stale.id, confirmInput(ctx.service.preview(req(ctx.tenant), stale.id))).body.authorization_reference;
    ctx.time.advance(24 * HOUR);
    rejectsWith(() => ctx.service.send(req(ctx.tenant, SERVICE), stale.id, { expected_version: stale.version, authorization_reference: staleRef }), 'confirmation_invalid', 409);
    assert.equal(storedConfirmation(ctx, staleRef).consumedAt, null, 'a refused send consumes nothing');

    const now = ctx.time.now.getTime();
    const short = ctx.service.create(req(ctx.tenant, SERVICE), createInput(1, { expires_at: new Date(now + 2 * HOUR).toISOString() })).body;
    ctx.service.uploadDocument(req(ctx.tenant, SERVICE), short.id, 1, documentInput(1));
    const shortPrepared = ctx.service.prepare(req(ctx.tenant, SERVICE), short.id, { expected_version: 2, fields: fieldsFor(1) }).body;
    const shortConfirmation = ctx.service.confirmSend(req(ctx.tenant, HUMAN), short.id, confirmInput(ctx.service.preview(req(ctx.tenant), short.id))).body;
    assert.equal(shortConfirmation.expires_at, new Date(now + 2 * HOUR).toISOString(), 'never later than the envelope expiry');

    // Digest and version binding, checked again at send.
    const shortRecipientsDigest = ctx.service.preview(req(ctx.tenant), short.id).recipients_digest;
    const bound = (patch) => {
      const reference = sid('crafted-ref');
      ctx.db.transaction(() =>
        insertSendConfirmation(ctx.db.forTenant(ctx.tenant), {
          authorizationReference: reference,
          envelopeId: short.id,
          envelopeVersion: shortPrepared.version,
          documentDigest: shortPrepared.document.digest,
          manifestDigest: shortPrepared.manifest_digest,
          recipientsDigest: shortRecipientsDigest,
          confirmedBy: HUMAN,
          confirmedAt: ctx.time.now.toISOString(),
          expiresAt: new Date(now + HOUR).toISOString(),
          ...patch,
        }),
      );
      return reference;
    };
    for (const [label, patch] of [
      ['a stale envelope version', { envelopeVersion: shortPrepared.version - 1 }],
      ['another recipients digest', { recipientsDigest: hex('changed-recipients') }],
      ['another manifest digest', { manifestDigest: hex('changed-manifest') }],
      ['another document digest', { documentDigest: hex('changed-document') }],
    ]) {
      const reference = bound(patch);
      rejectsWith(() => ctx.service.send(req(ctx.tenant, SERVICE), short.id, { expected_version: shortPrepared.version, authorization_reference: reference }), 'confirmation_invalid', 409);
      assert.equal(storedConfirmation(ctx, reference).consumedAt, null, `${label}: nothing consumed`);
    }
    assert.throws(
      () => bound({ confirmedBy: SERVICE }),
      (error) => error.code === 'storage_constraint' && /human-operator/.test(error.message),
      'the schema refuses a confirmation by a service principal',
    );
    const serviceMade = { ...storedConfirmation(ctx, shortConfirmation.authorization_reference), confirmedBy: SERVICE };
    assert.ok(
      confirmationProblems(serviceMade, { envelopeId: short.id, version: shortPrepared.version, documentDigest: shortPrepared.document.digest, manifestDigest: shortPrepared.manifest_digest, recipientsDigest: serviceMade.recipientsDigest }, ctx.time.now).includes('not-human'),
      'the send rule also refuses one',
    );
    const sent = ctx.service.send(req(ctx.tenant, SERVICE), short.id, { expected_version: shortPrepared.version, authorization_reference: shortConfirmation.authorization_reference }).body;
    assert.equal(sent.state, 'sent');

    // A human-created envelope: send_confirmation.required is false (created_by.kind is not service).
    const human = preparedEnvelope(ctx, { creator: HUMAN });
    assert.deepEqual(human.send_confirmation, { required: false, authorization_reference: null });
    assert.equal(ctx.service.send(req(ctx.tenant, HUMAN), human.id, { expected_version: human.version }).body.state, 'sent');
    const humanForService = preparedEnvelope(ctx, { creator: HUMAN });
    assert.equal(ctx.service.send(req(ctx.tenant, SERVICE), humanForService.id, { expected_version: humanForService.version }).body.state, 'sent');
  } finally {
    ctx.db.close();
  }
});
