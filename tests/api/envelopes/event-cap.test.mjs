// SPDX-License-Identifier: Apache-2.0
//
// T034 follow-up, EA-08 (A-010 requests #46 and #50, confirmed by request #57 (2); row
// EVENT-CAP): a resend refused at the envelope's event cap. T008's gate runs inside T034's own
// resend transaction (EnvelopeApi.resend -> RecipientCeremony.resendInvitation). At the cap it
// throws 429 rate_limited, and T034 passes it through unchanged (httpErrorOf), with no code of
// its own for the cap (request #50). The answer carries one detail on `envelope`, whose code is
// T008's ENVELOPE_EVENT_LIMIT_DETAIL, and no Retry-After, because waiting never lifts the cap.
// It writes nothing: no audit event, invitation, idempotency record or mail. Because no record is kept,
// a retry with the same key follows the order every T034 idempotent handler uses (requests
// #16 and #25; T034R-RESEND) and answers 429 again.
//
// T008's landed code governs (read at 23eb039). This test uses T008's exports and restates
// none of their values:
// - A1: src/api/recipients/index.ts exports ENVELOPE_REPEATABLE_EVENT_CAP,
//   ENVELOPE_EVENT_LIMIT_DETAIL and the predicate isEnvelopeEventLimit;
// - A2: envelopeEventCount counts every audit_events row of the envelope, whatever its type,
//   so rows appended through the audit writer count;
// - A3: envelopeEventCapReached refuses at count >= cap;
// - A4: resendInvitation counts after its own 404 and 409 checks and before its first write,
//   through the store of T034's transaction, so the throw rolls everything back;
// - A5: T034 calls resendInvitation(store, envelopeId, recipientId, actor), unchanged.
// T034's own checks (key, body rules, 404, state, version) run before the gate.
//
// Runtime cost. One parse-service run (the upload of the sent envelope); about 2,040 audit
// events appended in one transaction through the real writer, each a head read, a SHA-256
// and an insert, with a checkpoint every 100 events (well under a second); three resends; and
// two table snapshots of about 2,050 audit rows. Nothing is mailed past the control resend.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ENVELOPE_EVENT_LIMIT_DETAIL, ENVELOPE_REPEATABLE_EVENT_CAP, isEnvelopeEventLimit } from '../../../src/api/recipients/index.ts';
import { AuditWriter } from '../../../src/storage/audit/index.ts';
import { RESEND_ROUTE } from '../../../src/api/envelopes/index.ts';
import { HttpError } from '../../../src/server/types.ts';
import { envelopeEventCapReached, envelopeEventCount } from '../../../src/storage/repositories/recipients.ts';
import { TENANTS, assertSameRows, contractErrors, createWorld, errorShape, isIdle, newKey, resendRequest, sentEnvelope, takeInvitation, until } from './support.mjs';

const ALPHA = TENANTS.alpha.id;
/** The cap refusal's one detail, built from T008's exported detail code (request #50). */
const LIMIT_DETAILS = Object.freeze([{ field: 'envelope', code: ENVELOPE_EVENT_LIMIT_DETAIL }]);

/** Whether a response is the cap refusal, judged by T008's own predicate over the response's status, code and details. */
const isCapRefusal = (response) => isEnvelopeEventLimit(new HttpError(response.status, response.json?.code, { details: response.json?.details ?? [] }));

test('[EA-08] a resend refused at the envelope event cap answers 429 rate_limited with detail envelope_event_limit and no Retry-After, writes nothing, and a same-key retry answers 429 again', async (t) => {
  const world = await createWorld();
  t.after(async () => {
    await until(isIdle, 'cleanup: the parse service and the upload cap drain to idle');
    await world.close();
  });
  const { envelope } = await sentEnvelope(world);
  const recipient = envelope.recipients[0];
  const store = world.db.forTenant(ALPHA);
  // T008's own count and predicate (A2, A3), read outside any transaction like T034's prechecks.
  const events = () => envelopeEventCount(store, envelope.id);
  const atCap = () => envelopeEventCapReached(store, envelope.id);
  const resendRecords = (key) => world.rows('idempotency_records', 'WHERE route = ? AND key = ?', [RESEND_ROUTE, key]).length;

  // Control: below the cap the resend is open, so nothing else (no rate limit) refuses it.
  const open = await resendRequest(world, { envelope, recipient });
  assert.equal(open.status, 202, `below the cap a resend is accepted (${open.json?.code ?? 'no code'})`);
  takeInvitation(world);

  // Bring the envelope to exactly the cap, through the real audit writer (A2).
  const missing = ENVELOPE_REPEATABLE_EVENT_CAP - events();
  assert.ok(missing > 0 && !atCap(), `the envelope is below the cap before seeding (${events()} events)`);
  const writer = new AuditWriter(world.db, { clock: world.time.clock });
  world.db.transaction(() => {
    for (let index = 0; index < missing; index += 1) writer.append(ALPHA, { type: 'test.ea08-seed', actor: { kind: 'system', ref: 'ea-08-seed' }, envelopeId: envelope.id });
  });
  assert.equal(events(), ENVELOPE_REPEATABLE_EVENT_CAP, 'the envelope holds exactly the cap');
  assert.ok(atCap(), "T008's predicate reports the cap reached (A3)");

  // T034's own order first: at the cap, a stale expected_version is 409 version_conflict.
  const before = world.snapshot('alpha');
  const mails = world.mails().length;
  const stale = await resendRequest(world, { envelope, recipient, version: envelope.version + 1 });
  assert.deepEqual([stale.status, stale.json?.code], [409, 'version_conflict'], "T034's version check comes before T008's gate");
  assertSameRows(world.snapshot('alpha'), before, 'the stale resend writes nothing');

  // At the cap: 429 rate_limited, the one envelope_event_limit detail, no Retry-After, nothing written.
  const key = newKey();
  const refused = await resendRequest(world, { envelope, recipient, key });
  assert.equal(refused.status, 429, `the resend at the cap is refused (${refused.status} ${refused.json?.code ?? ''})`);
  assert.equal(refused.json?.code, 'rate_limited');
  assert.deepEqual(refused.json?.details, LIMIT_DETAILS, 'the one detail: envelope_event_limit on envelope');
  assert.ok(isCapRefusal(refused), "T008's isEnvelopeEventLimit recognises the answer");
  assert.equal(refused.headers['retry-after'], undefined, 'no Retry-After: waiting never lifts the cap');
  assert.deepEqual(contractErrors('Error', refused.json), [], 'a contract Error body');
  assertSameRows(world.snapshot('alpha'), before, 'the refusal writes nothing: no audit event, invitation or idempotency record');
  assert.equal(resendRecords(key), 0, 'no idempotency record under the key');
  assert.equal(world.mails().length, mails, 'and no mail');
  assert.equal(events(), ENVELOPE_REPEATABLE_EVENT_CAP, 'the event count is unchanged');

  // A same-key retry: no record was kept, so the key resolves to nothing, the gate runs
  // again, and the answer is 429 again, identical apart from its correlation id.
  const retry = await resendRequest(world, { envelope, recipient, key });
  assert.equal(retry.status, 429, `the same-key retry answers 429 again (${retry.status} ${retry.json?.code ?? ''})`);
  assert.deepEqual(errorShape(retry), errorShape(refused), 'with the same Error body');
  assert.ok(isCapRefusal(retry), "T008's isEnvelopeEventLimit recognises the retry's answer");
  assert.equal(retry.headers['retry-after'], undefined, 'and no Retry-After');
  assertSameRows(world.snapshot('alpha'), before, 'the retry writes nothing either');
  assert.equal(resendRecords(key), 0, 'still no idempotency record');
  assert.equal(world.mails().length, mails, 'still no mail');
});
