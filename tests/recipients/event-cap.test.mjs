// SPDX-License-Identifier: Apache-2.0
//
// T008 recipient ceremony: the per-envelope cap on the actions a person can
// repeat (A-010 rows EVENT-CAP and REVOKE-META, requests #46 and #50; cases
// CH-10 and CH-11).
//
// CH-10. An invitation resend, a challenge request and a recipient-session
// creation each count the envelope's audit events through the
// audit_events_envelope index, inside their own write transaction, and are
// refused once the count has reached ENVELOPE_REPEATABLE_EVENT_CAP (2048),
// writing nothing. The resend and the session creation refuse with 429
// rate_limited, details [{ field: 'envelope', code: 'envelope_event_limit' }],
// and no Retry-After. The challenge request is refused silently: its generic 202
// comes before any per-invitation work (row T008-F1), and at the cap its work
// stores and mails nothing and logs the refusal once. A recipient keeps at most
// one unrevoked session, so a session creation writes at most three events and
// at most two session ends follow the cap: nothing passes
// ENVELOPE_REPEATABLE_EVENT_CEILING (2052). Approvals, declines, voids,
// expiries, reissues, session ends and reads are never refused for the cap.
//
// CH-11. A revocation names every revoked id. It is one event while the lists
// fit the audit writer's MAX_METADATA_BYTES; for older rows holding hundreds of
// unrevoked sessions it splits into several disjoint events, so a void, an
// expiry, a resend and a session creation stay live.
//
// Events are seeded through the storage layer's own append path (T029's
// AuditWriter, which the ceremony itself uses), in one write transaction per
// envelope, so each seeding is a single WAL commit. Older sessions are seeded
// through the repository's insertSession. Capability values stay in memory and
// never appear in a test name or an assertion message.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { Worker } from 'node:worker_threads';

// The cap's own exports are read through namespace imports, so this file loads, and each case
// fails on its own assertion, against code that predates them.
import * as recipientsApi from '../../src/api/recipients/index.ts';
import { RecipientCeremony, loadChallengeKey } from '../../src/api/recipients/index.ts';
import { canonicalize } from '../../src/domain/canonical/index.ts';
import { ApprovalService } from '../../src/domain/approval/index.ts';
import { EnvelopeService } from '../../src/domain/envelopes/index.ts';
import { createNotifier, createSpoolTransport } from '../../src/notifications/index.ts';
import { createLogger } from '../../src/server/redact.ts';
import { HttpError } from '../../src/server/types.ts';
import { AuditWriter, MAX_METADATA_BYTES } from '../../src/storage/audit/index.ts';
import { StorageError, TenantStore, openDatabase } from '../../src/storage/db/index.ts';
import * as recipientsRepo from '../../src/storage/repositories/recipients.ts';
import { auditedRevocationsOf, insertSession } from '../../src/storage/repositories/recipients.ts';
import { createTenant, envelopeRow } from '../storage/support/fixtures.mjs';
import {
  COOKIE,
  CONSENT_WORDING,
  HOUR,
  HUMAN,
  MINUTE,
  ORIGIN,
  approveFirst,
  comparableHeaders,
  contractErrors,
  cookieOf,
  createInput,
  createSession,
  createWorld,
  fieldsFor,
  logsFreeOf,
  openSession,
  pageReport,
  readAs,
  requestChallenge,
  requestCode,
  resend,
  sentEnvelope,
  sha256,
  sid,
  syntheticPdf,
  tokenOf,
  ts,
  wrongCode,
} from './support.mjs';

// The ruled values (requests #46 and #50). The ceiling case checks the exports against them.
const CAP = 2048;
const MAX_EVENTS = 3;
const MAX_RECIPIENTS = 2;
const SESSION_ENDS = 2;
const CEILING = 2052;
const LIMIT_DETAILS = [{ field: 'envelope', code: 'envelope_event_limit' }];
const SEED_ACTOR = Object.freeze({ kind: 'system', ref: 'event-cap-seed' });
const REVOKED = 'recipient.capabilities_revoked';
/** A client address other than the world's loopback one (TEST-NET-1), for direct ceremony calls. */
const OTHER_ADDRESS = '192.0.2.10';
/** The race's shared flags: [GO] is set by this thread, [ENTERING] by the second connection's worker. */
const GO = 0;
const ENTERING = 1;
/** Deadlock guard only (worker start-up included); no assertion depends on elapsed time. */
const RACE_WAIT_MS = 30_000;
/** CH-11: unrevoked sessions seeded for one recipient, as code before request #50 could leave them. */
const OLD_SESSIONS = 300;

/** The envelope's audit events, counted through the tenant store as the ceremony counts them. */
function eventCount(world, envelopeId, tenant = world.tenant) {
  return world.db.forTenant(tenant).count('audit_events', { envelope_id: envelopeId });
}

/** Bring the envelope to exactly `target` audit events through the AuditWriter, in one write transaction. */
function seedTo(world, envelopeId, target, tenant = world.tenant) {
  const writer = new AuditWriter(world.db, { clock: world.time.clock });
  world.db.transaction(() => {
    const have = eventCount(world, envelopeId, tenant);
    assert.ok(have <= target, `premise: the envelope holds ${have} events, at most ${target}`);
    for (let ordinal = have + 1; ordinal <= target; ordinal += 1) {
      writer.append(tenant, { type: 'test.event_cap_seed', actor: SEED_ACTOR, envelopeId, metadata: { seed_ordinal: ordinal } });
    }
  });
  assert.equal(eventCount(world, envelopeId, tenant), target, `premise: the envelope holds exactly ${target} events`);
}

/** CH-11: `n` unrevoked sessions for the recipient, through the repository, bound like its invitation; returns their ids. */
function seedSessions(world, envelopeId, recipientId, n) {
  const [invitation] = world.rows('invitations', `WHERE envelope_id = '${envelopeId}' AND recipient_id = '${recipientId}'`);
  assert.ok(invitation, 'premise: the recipient has an invitation');
  const ids = [];
  world.db.transaction(() => {
    const store = world.store();
    for (let index = 0; index < n; index += 1) {
      const id = sid('sess');
      insertSession(store, {
        id,
        valueHash: sha256(randomBytes(32)),
        envelopeId,
        recipientId,
        revisionId: invitation.revision_id,
        manifestDigest: invitation.manifest_digest,
        csrfSecret: randomBytes(32),
        now: world.time.now.toISOString(),
      });
      ids.push(id);
    }
  });
  return ids;
}

/** The highest audit sequence number of the world's tenant. */
function headSeq(world) {
  return Number(world.rows('audit_events').at(-1)?.seq ?? 0);
}

/** The envelope's revocation events after `seq`, with their parsed metadata. */
function revocationsAfter(world, envelopeId, seq) {
  return world
    .rows('audit_events', `WHERE envelope_id = '${envelopeId}' AND type = '${REVOKED}' AND seq > ${seq}`)
    .map((row) => ({ row, metadata: JSON.parse(row.metadata_json) }));
}

/** Unrevoked rows of `table` for the recipient on the envelope. */
function unrevoked(world, table, envelopeId, recipientId) {
  return world.rows(table, `WHERE envelope_id = '${envelopeId}' AND recipient_id = '${recipientId}' AND revoked_at IS NULL`);
}

/** Every ceremony table's content and the spool's message names: what a refusal must leave as it was. */
function stateOf(world) {
  return { tables: world.snapshot(), mails: world.mails().map((mail) => mail.name) };
}

/** The HTTP cap refusal: 429 rate_limited, detail envelope_event_limit, a contract Error, no cookie, no Retry-After. */
function assertCapResponse(response, label) {
  assert.equal(response.status, 429, `${label}: 429`);
  assert.equal(response.json?.code, 'rate_limited', `${label}: code rate_limited`);
  assert.deepEqual(response.json?.details, LIMIT_DETAILS, `${label}: detail envelope_event_limit on envelope`);
  assert.deepEqual(contractErrors('Error', response.json), [], `${label}: a contract Error body`);
  assert.equal(response.headers['set-cookie'], undefined, `${label}: no cookie`);
  assert.equal(response.headers['retry-after'], undefined, `${label}: no Retry-After, since waiting does not lift the cap`);
}

/** The thrown cap refusal, as resendInvitation hands it to T034's transaction. */
function capRefusal(error) {
  assert.ok(error instanceof HttpError, 'the refusal is an HttpError');
  assert.equal(error.status, 429);
  assert.equal(error.code, 'rate_limited');
  assert.deepEqual([...error.details], LIMIT_DETAILS);
  assert.deepEqual({ ...error.headers }, {});
  assert.equal(typeof recipientsApi.isEnvelopeEventLimit, 'function', 'the refusal predicate is exported for T034');
  assert.equal(recipientsApi.isEnvelopeEventLimit(error), true);
  return true;
}

/** A resend inside the caller's own write transaction and capture(), as T034's EnvelopeApi.resend runs it. */
function resendIn(world, envelopeId, recipientId, { ceremony = world.ceremony, db = world.db, tenant = world.tenant } = {}) {
  return ceremony.run(() => db.transaction(() => ceremony.resendInvitation(db.forTenant(tenant), envelopeId, recipientId, HUMAN)));
}

/** endRecipientSession through the real server. */
function endSession(world, opened) {
  return world.http({ method: 'DELETE', path: '/v1/recipient-session', headers: { origin: ORIGIN, cookie: `${COOKIE}=${opened.session}`, 'x-csrf-token': opened.csrf } });
}

/** Void the envelope at its current version. */
function voidEnvelope(world, envelopeId) {
  const current = world.service.read(world.req(), envelopeId);
  world.service.void(world.req(), envelopeId, { expected_version: current.version, reason_code: 'sender-cancelled' });
  return world.service.read(world.req(), envelopeId);
}

/** A spool notifier for a second ceremony instance, writing to the world's spool. */
function spoolNotifier(world) {
  return createNotifier({
    transport: createSpoolTransport({ dir: world.spoolDir }),
    from: 'no-reply@opensig.test',
    publicOrigin: ORIGIN,
    rateLimit: { limit: 1000, windowMs: 10 * MINUTE },
    logger: createLogger(() => {}),
    now: () => world.time.now.getTime(),
  });
}

/** A second tenant in the world's database, with its consent text in force. */
function addTenant(world) {
  const tenant = sid('tenant');
  createTenant(world.db, tenant);
  const consentId = sid('consent');
  world.db.transaction(() => {
    const store = world.db.forTenant(tenant);
    store.insert('consent_texts', {
      id: consentId,
      version: world.consent.version,
      locale: 'en',
      text: CONSENT_WORDING,
      text_digest: sha256(Buffer.from(CONSENT_WORDING, 'utf8')),
      effective_from: ts(0),
      created_at: ts(0),
    });
    store.update('tenants', {}, { consent_text_id: consentId });
  });
  return tenant;
}

/** The same id sequence for every service built from it, so two tenants get the same envelope and recipient ids. */
function sameIds() {
  let next = 0;
  return () => `capx${String((next += 1)).padStart(16, '0')}`;
}

/** sentEnvelope (support.mjs) for any tenant and envelope service: { envelope, token }. */
async function sentEnvelopeIn(world, tenant, service) {
  const req = { tenantId: tenant, actor: HUMAN };
  const pdf = syntheticPdf(sid('doc'));
  const put = world.blobs.put(tenant, pdf);
  const pages = [
    { number: 1, width: 612, height: 792, rotate: 0 },
    { number: 2, width: 612, height: 792, rotate: 90 },
  ];
  const created = service.create(req, createInput(1)).body;
  const uploaded = service.uploadDocument(req, created.id, created.version, {
    digest: put.digest,
    bytes: pdf.length,
    pages,
    parseReport: { pages: pageReport(pages), network_sandbox: 'netns+fs-enforced (local)' },
  }).body;
  const prepared = service.prepare(req, created.id, { expected_version: uploaded.version, fields: fieldsFor(1) }).body;
  const sent = (await world.ceremony.run(() => service.send(req, prepared.id, { expected_version: prepared.version }))).body;
  const mails = world.takeMails('recipient_invitation', 'signer.one@example.test');
  assert.equal(mails.length, 1, 'sending mails exactly one invitation');
  return { envelope: sent, token: tokenOf(mails[0]) };
}

// ------------------------------------------------------------------------ CH-10

test('[CH-10] resendInvitation at 2047 envelope events revokes and reissues within the exported per-action maximum; at 2048 it throws 429 rate_limited, detail envelope_event_limit, inside the caller\'s transaction, which rolls back, so no row, event, outbox entry or mail is written and the old invitation stays live (A-010 EVENT-CAP, requests #46 and #50)', async () => {
  const world = await createWorld();
  try {
    const below = await sentEnvelope(world);
    seedTo(world, below.envelope.id, CAP - 1);
    const fresh = await resend(world, below.envelope, below.envelope.recipients[0], HUMAN);
    assert.notEqual(fresh, below.token, 'below the cap the resend issues a new invitation');
    const added = eventCount(world, below.envelope.id) - (CAP - 1);
    assert.equal(added, 2, 'the resend appends recipient.capabilities_revoked and recipient.invited');
    assert.ok(added <= MAX_EVENTS, 'within the exported per-action maximum');

    const at = await sentEnvelope(world);
    seedTo(world, at.envelope.id, CAP);
    const before = stateOf(world);
    await assert.rejects(resendIn(world, at.envelope.id, at.envelope.recipients[0].id), capRefusal);
    assert.deepEqual(stateOf(world), before, 'the refused resend wrote nothing and mailed nothing');
    const invitations = world.rows('invitations', `WHERE envelope_id = '${at.envelope.id}'`);
    assert.equal(invitations.length, 1, 'no invitation was issued');
    assert.equal(invitations[0].revoked_at, null, 'the old invitation stays live');
    // The resend's own refusals keep their precedence: an unknown recipient is still 404.
    await assert.rejects(resendIn(world, at.envelope.id, sid('recipient')), (error) => error instanceof HttpError && error.status === 404);
  } finally {
    await world.close();
  }
});

test('[CH-10] requestChallenge at 2047 stores and mails a code and appends no audit event; at 2048 it is refused silently: the same generic 202, byte for byte and header for header as for an unknown invitation, nothing superseded, stored or mailed, and one log line with only the correlation ID and the detail (A-010 EVENT-CAP, request #50; the 202 precedes all per-invitation work, row T008-F1)', async () => {
  const world = await createWorld();
  try {
    const below = await sentEnvelope(world);
    seedTo(world, below.envelope.id, CAP - 1);
    assert.ok((await requestCode(world, below.token)) !== null, 'below the cap a code is mailed');
    assert.equal(eventCount(world, below.envelope.id), CAP - 1, 'a challenge request appends no audit event');

    const at = await sentEnvelope(world);
    assert.ok((await requestCode(world, at.token)) !== null, 'premise: an open challenge exists before the cap');
    seedTo(world, at.envelope.id, CAP);
    const before = stateOf(world);
    const stats = world.ceremony.challengeWorkStats();
    const capped = await requestChallenge(world, at.token);
    const unknown = await requestChallenge(world, 'U'.repeat(43));
    assert.equal(capped.status, 202, 'the capped request is answered 202');
    assert.deepEqual(capped.json, { status: 'accepted' });
    assert.ok(capped.bytes.equals(unknown.bytes), 'the same body as for an unknown invitation');
    assert.deepEqual(comparableHeaders(capped), comparableHeaders(unknown), 'the same headers as for an unknown invitation');
    assert.deepEqual(stateOf(world), before, 'the open challenge is not superseded; nothing is stored or mailed');
    assert.deepEqual(world.ceremony.challengeWorkStats(), { pending: 0, completed: stats.completed + 2, failed: stats.failed }, 'both works completed and none failed');

    const refusals = world.lines.map((line) => JSON.parse(line)).filter((record) => record.event === 'challenge_refused');
    assert.equal(refusals.length, 1, 'the refusal is logged once; the unknown invitation logs nothing');
    assert.deepEqual(Object.keys(refusals[0]).sort(), ['correlation_id', 'detail', 'event', 'level', 'time'], 'only the correlation ID and the detail');
    assert.equal(refusals[0].correlation_id, capped.headers['x-correlation-id'], 'the capped request\'s correlation ID');
    assert.equal(refusals[0].detail, 'envelope_event_limit');
    assert.ok(logsFreeOf(world, [at.token]), 'no capability value is logged');
  } finally {
    await world.close();
  }
});

test('[CH-10] createRecipientSession at 2047 that replaces the recipient\'s session writes three events (challenge_verified, the revocation naming the old session, session_created) and the old cookie stops working; at 2048 a wrong code and then the right code each get 429 rate_limited, detail envelope_event_limit, decided before the code is compared, so the challenge keeps its attempts and stays open and no session, counter, revocation, lockout event, mail or cookie is written', async () => {
  const world = await createWorld();
  try {
    const below = await sentEnvelope(world);
    const earlier = await openSession(world, below.token);
    const [earlierRow] = world.rows('recipient_sessions', `WHERE envelope_id = '${below.envelope.id}'`);
    const belowCode = await requestCode(world, below.token);
    seedTo(world, below.envelope.id, CAP - 1);
    const replaced = await createSession(world, below.token, belowCode);
    assert.equal(replaced.status, 201, 'below the cap the right code opens the session');
    const added = world.rows('audit_events', `WHERE envelope_id = '${below.envelope.id}'`).slice(-3);
    assert.deepEqual(added.map((row) => row.type), ['recipient.challenge_verified', REVOKED, 'recipient.session_created'], 'verified, the revocation, then created');
    assert.deepEqual(JSON.parse(added[1].metadata_json).session_ids, [earlierRow.id], 'the revocation names the replaced session');
    assert.equal(added[1].actor_kind, 'recipient', 'with the recipient as actor');
    assert.equal(eventCount(world, below.envelope.id), CAP - 1 + MAX_EVENTS, 'three events: the exported per-action maximum');
    assert.equal((await readAs(world, earlier.session)).status, 401, 'the replaced session no longer works');
    assert.equal(unrevoked(world, 'recipient_sessions', below.envelope.id, below.envelope.recipients[0].id).length, 1, 'one unrevoked session');

    const at = await sentEnvelope(world);
    await openSession(world, at.token);
    const atCode = await requestCode(world, at.token);
    seedTo(world, at.envelope.id, CAP);
    const before = stateOf(world);
    assertCapResponse(await createSession(world, at.token, wrongCode(atCode)), 'a wrong code at the cap');
    assertCapResponse(await createSession(world, at.token, atCode), 'the right code at the cap');
    assert.deepEqual(stateOf(world), before, 'no session, counter, revocation, event or mail was written');
  } finally {
    await world.close();
  }
});

test('[CH-10] no sequence passes ENVELOPE_REPEATABLE_EVENT_CEILING: on a two-recipient envelope at 2047 a replacing session creation writes three events, every further repeatable action is refused, and the session ends that still follow, at most one per recipient, stop at 2052; an envelope row with recipients_count 3 is refused, which ties ENVELOPE_SESSION_ENDS_PAST_CAP to the schema (A-010 EVENT-CAP, request #50)', async () => {
  const world = await createWorld();
  try {
    assert.deepEqual(
      {
        cap: recipientsRepo.ENVELOPE_REPEATABLE_EVENT_CAP,
        maxEvents: recipientsRepo.REPEATABLE_ACTION_MAX_EVENTS,
        maxRecipients: recipientsRepo.ENVELOPE_MAX_RECIPIENTS,
        sessionEnds: recipientsRepo.ENVELOPE_SESSION_ENDS_PAST_CAP,
        ceiling: recipientsRepo.ENVELOPE_REPEATABLE_EVENT_CEILING,
      },
      { cap: CAP, maxEvents: MAX_EVENTS, maxRecipients: MAX_RECIPIENTS, sessionEnds: SESSION_ENDS, ceiling: CEILING },
      'the exports carry the ruled values',
    );
    assert.equal(CEILING, CAP - 1 + MAX_EVENTS + SESSION_ENDS, 'the ceiling is the cap less one, plus one action, plus the session ends');
    assert.deepEqual(
      [recipientsApi.ENVELOPE_REPEATABLE_EVENT_CAP, recipientsApi.ENVELOPE_REPEATABLE_EVENT_CEILING, recipientsApi.ENVELOPE_SESSION_ENDS_PAST_CAP, typeof recipientsApi.splitRevocationMetadata],
      [CAP, CEILING, SESSION_ENDS, 'function'],
      'the recipients API re-exports them and the splitter',
    );
    world.db.transaction(() => {
      assert.throws(() => world.store().insert('envelopes', envelopeRow(sid('env'), { recipients_count: MAX_RECIPIENTS + 1 })), StorageError, 'recipients_count 3 is refused');
      world.store().insert('envelopes', envelopeRow(sid('env'), { recipients_count: MAX_RECIPIENTS }));
    });

    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    const [first, second] = [1, 2].map((ordinal) => envelope.recipients.find((entry) => entry.ordinal === ordinal));
    const firstSession = await openSession(world, token);
    const approved = await approveFirst(world, envelope);
    assert.ok(approved.token !== null, 'premise: recipient 2 is invited');
    await openSession(world, approved.token, 'signer.two@example.test');
    const code = await requestCode(world, approved.token, 'signer.two@example.test');
    seedTo(world, envelope.id, CAP - 1);

    const replaced = await createSession(world, approved.token, code);
    assert.equal(replaced.status, 201);
    assert.equal(eventCount(world, envelope.id), CAP - 1 + MAX_EVENTS, 'the replacing session creation wrote three events');
    for (const recipient of [first, second]) {
      assert.ok(unrevoked(world, 'recipient_sessions', envelope.id, recipient.id).length <= 1, `recipient ${recipient.ordinal} holds at most one unrevoked session`);
    }

    // Every repeatable action is refused now.
    assert.equal(await requestCode(world, approved.token, 'signer.two@example.test'), null, 'no code');
    await assert.rejects(resendIn(world, envelope.id, second.id), capRefusal);

    // Session ends are never refused: at most one per recipient remains to end.
    let ended = 0;
    for (const opened of [firstSession, { session: cookieOf(replaced), csrf: replaced.json.csrf_token }]) {
      if ((await endSession(world, opened)).status === 204) ended += 1;
    }
    assert.equal(ended, SESSION_ENDS, 'one live session per recipient ends (an approval revokes nothing)');
    assert.equal(eventCount(world, envelope.id), CEILING, 'the worst case reaches the ceiling exactly and no further');
    for (const recipient of [first, second]) {
      assert.equal(unrevoked(world, 'recipient_sessions', envelope.id, recipient.id).length, 0, 'no session remains to end');
    }
  } finally {
    await world.close();
  }
});

test('[CH-10] at the cap the actions that cannot be repeated are never refused: an existing session\'s read and its end, recipient 1\'s approval with recipient 2\'s follow-up invitation, the void, and the reissue, whose new envelope starts its own count (A-010 EVENT-CAP)', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    const opened = await openSession(world, token);
    seedTo(world, envelope.id, CAP);

    assert.equal((await readAs(world, opened.session)).status, 200, 'an existing session still reads at the cap');
    assert.equal((await endSession(world, opened)).status, 204, 'the session ends at the cap');
    assert.equal(eventCount(world, envelope.id), CAP + 1, 'its recipient.capabilities_revoked is appended past the cap');

    const approved = await approveFirst(world, envelope);
    assert.ok(approved.token !== null, 'recipient 1\'s approval invites recipient 2 at the cap');
    assert.equal(eventCount(world, envelope.id), CAP + 2, 'the follow-up recipient.invited is appended');
    assert.equal(await requestCode(world, approved.token, 'signer.two@example.test'), null, 'recipient 2\'s challenge request is refused: the envelope can be voided or reissued');

    const voided = voidEnvelope(world, envelope.id);
    assert.equal(voided.state, 'voided', 'the void commits at the cap');
    assert.equal(eventCount(world, envelope.id), CAP + 3, 'the void records what it revoked');

    world.time.advance(MINUTE);
    const reissued = world.service.reissue(world.req(), envelope.id, { expected_version: voided.version });
    assert.equal(reissued.status, 201, 'the reissue commits');
    assert.notEqual(reissued.body.id, envelope.id);
    assert.ok(eventCount(world, reissued.body.id) < CAP, 'the reissued envelope starts its own count');
  } finally {
    await world.close();
  }
});

test('[CH-10] past the cap a decline and an expiry are never refused: each commits and appends its events (A-010 EVENT-CAP)', async () => {
  const world = await createWorld();
  try {
    const approvals = new ApprovalService({ db: world.db, clock: world.time.clock, envelopes: world.service });

    const declining = await sentEnvelope(world);
    const opened = await openSession(world, declining.token);
    seedTo(world, declining.envelope.id, CAP + 50);
    const session = world.ceremony.authenticate({ headers: { cookie: `${COOKIE}=${opened.session}` } }, { refresh: false });
    assert.ok(session !== null, 'premise: the session opened before the cap is live');
    assert.equal(approvals.decline(session, { expected_version: declining.envelope.version }).status, 200, 'the decline commits past the cap');
    assert.equal(world.service.read(world.req(), declining.envelope.id).state, 'declined');
    assert.equal(eventCount(world, declining.envelope.id), CAP + 52, 'recipient.declined and its revocation record are appended');

    const expiring = await sentEnvelope(world, { expiresAt: new Date(world.time.now.getTime() + 2 * HOUR).toISOString() });
    await openSession(world, expiring.token);
    seedTo(world, expiring.envelope.id, CAP + 10);
    world.time.advance(3 * HOUR);
    assert.equal(world.service.expireIfDue(world.tenant, expiring.envelope.id), true, 'the expiry commits past the cap');
    assert.equal(eventCount(world, expiring.envelope.id), CAP + 11, 'the expiry records what it revoked');
  } finally {
    await world.close();
  }
});

test('[CH-10] the cap is durable: a fresh ceremony on a second connection to the same file, with its own per-process limits and no shared memory, refuses all three actions at 2048 and still allows them at 2047', async () => {
  const world = await createWorld();
  const db2 = openDatabase({ path: world.path, busyTimeoutMs: 2_000 });
  try {
    const fresh = new RecipientCeremony({
      db: db2,
      blobs: world.blobs,
      notifier: spoolNotifier(world),
      challengeKey: loadChallengeKey({ path: world.keyPath }),
      clock: world.time.clock,
      logger: createLogger(() => {}),
    });

    const at = await sentEnvelope(world);
    const atCode = await requestCode(world, at.token);
    seedTo(world, at.envelope.id, CAP);
    const before = stateOf(world);
    assert.throws(() => fresh.createSession({ invitation: at.token, code: atCode }, OTHER_ADDRESS), capRefusal);
    await assert.rejects(resendIn(world, at.envelope.id, at.envelope.recipients[0].id, { ceremony: fresh, db: db2 }), capRefusal);
    fresh.requestChallenge({ invitation: at.token }, OTHER_ADDRESS, 'cap-fresh-instance');
    await fresh.drain();
    assert.deepEqual(stateOf(world), before, 'the fresh instance refused all three and wrote nothing');

    const below = await sentEnvelope(world);
    const belowCode = await requestCode(world, below.token);
    seedTo(world, below.envelope.id, CAP - 1);
    const created = fresh.createSession({ invitation: below.token, code: belowCode }, OTHER_ADDRESS);
    assert.equal(typeof created.value, 'string', 'the fresh instance allows a session at 2047');
  } finally {
    db2.close();
    await world.close();
  }
});

test('[CH-10] two connections at 2047 do not both write: a session creation holds its write transaction open after its count and its writes until a second connection\'s challenge work has entered its own transaction; that work counts only after the commit, sees 2049, and stores and mails nothing (data-model.md § Persistence, BEGIN IMMEDIATE)', async () => {
  const flags = new Int32Array(new SharedArrayBuffer(2 * Int32Array.BYTES_PER_ELEMENT));
  const pause = { armed: false, timedOut: false };
  // The only test device: a proxy over the first connection whose transaction() can pause just
  // before its commit, once armed. The connection, the write lock and every statement are real.
  const wrapDb = (db) =>
    new Proxy(db, {
      get(target, property) {
        if (property === 'transaction') {
          return (fn) =>
            target.transaction(() => {
              const value = fn();
              if (pause.armed) {
                pause.armed = false;
                Atomics.store(flags, GO, 1);
                Atomics.notify(flags, GO);
                if (Atomics.wait(flags, ENTERING, 0, RACE_WAIT_MS) === 'timed-out') pause.timedOut = true;
              }
              return value;
            });
        }
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  const world = await createWorld({ wrapDb });
  let worker;
  try {
    const { envelope, token } = await sentEnvelope(world);
    const code = await requestCode(world, token);
    seedTo(world, envelope.id, CAP - 1);
    const before = { challenges: world.rows('challenges').length, mails: world.mails().length };
    worker = new Worker(new URL('./event-cap-race-worker.mjs', import.meta.url), {
      workerData: {
        flags: flags.buffer,
        dbPath: world.path,
        keyPath: world.keyPath,
        spoolDir: world.spoolDir,
        blobRoot: world.scratch.dir('opensig-race-blobs-'),
        origin: ORIGIN,
        invitation: token,
        nowMs: world.time.now.getTime(),
        waitMs: RACE_WAIT_MS,
        busyTimeoutMs: 10_000,
      },
    });
    const [ready] = await once(worker, 'message');
    assert.deepEqual(ready, { ready: true }, 'premise: the second connection is open and waiting');
    const reported = once(worker, 'message');

    pause.armed = true;
    const created = world.ceremony.createSession({ invitation: token, code }, OTHER_ADDRESS);
    assert.equal(pause.timedOut, false, 'the second connection entered its transaction while the first held its own');
    assert.equal(typeof created.value, 'string', 'the first action wrote');
    const [report] = await reported;
    assert.equal(report.error, undefined, 'the second connection ran its action');
    assert.deepEqual(report.stats, { pending: 0, completed: 1, failed: 0 }, 'its work completed without a failure');
    assert.equal(eventCount(world, envelope.id), CAP - 1 + 2, 'only the session creation wrote (a first session: nothing to revoke)');
    assert.equal(world.rows('challenges').length, before.challenges, 'the challenge request stored nothing');
    assert.equal(world.mails().length, before.mails, 'and mailed nothing');
  } finally {
    if (worker !== undefined) await worker.terminate();
    await world.close();
  }
});

test('[CH-10] the count is per tenant: a second tenant\'s envelope with the same envelope and recipient ids, at one event, takes all three actions, while the first tenant\'s envelope at 2048 still refuses them', async () => {
  const world = await createWorld();
  try {
    const other = addTenant(world);
    const first = await sentEnvelopeIn(world, world.tenant, new EnvelopeService({ db: world.db, clock: world.time.clock, onChange: world.ceremony.onEnvelopeChange, newId: sameIds() }));
    const second = await sentEnvelopeIn(world, other, new EnvelopeService({ db: world.db, clock: world.time.clock, onChange: world.ceremony.onEnvelopeChange, newId: sameIds() }));
    assert.equal(second.envelope.id, first.envelope.id, 'premise: the same envelope id in both tenants');
    assert.equal(second.envelope.recipients[0].id, first.envelope.recipients[0].id, 'premise: the same recipient id');
    const firstCode = await requestCode(world, first.token);
    seedTo(world, first.envelope.id, CAP);
    assert.equal(eventCount(world, second.envelope.id, other), 1, 'premise: the second tenant\'s envelope holds one event');

    const secondCode = await requestCode(world, second.token);
    assert.ok(secondCode !== null, 'the second tenant\'s challenge request is not refused');
    assert.equal((await createSession(world, second.token, secondCode)).status, 201, 'nor its session creation');
    await resendIn(world, second.envelope.id, second.envelope.recipients[0].id, { tenant: other });
    assert.equal(world.takeMails('recipient_invitation', 'signer.one@example.test').length, 1, 'nor its resend');

    assertCapResponse(await createSession(world, first.token, firstCode), 'the first tenant at the cap');
    await assert.rejects(resendIn(world, first.envelope.id, first.envelope.recipients[0].id), capRefusal);
  } finally {
    await world.close();
  }
});

test('[CH-10] an envelope already past the cap keeps every row: refused actions change no row of its 2100 events or its ceremony rows, a void only appends, and nothing is backfilled or deleted', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world);
    const code = await requestCode(world, token);
    seedTo(world, envelope.id, 2100);
    const events = world.rows('audit_events', `WHERE envelope_id = '${envelope.id}'`);
    const before = stateOf(world);
    assertCapResponse(await createSession(world, token, code), 'a session past the cap');
    assert.equal((await requestChallenge(world, token)).status, 202);
    await assert.rejects(resendIn(world, envelope.id, envelope.recipients[0].id), capRefusal);
    assert.deepEqual(stateOf(world), before, 'the refused actions changed no row');

    voidEnvelope(world, envelope.id);
    const after = world.rows('audit_events', `WHERE envelope_id = '${envelope.id}'`);
    assert.deepEqual(after.slice(0, events.length), events, 'every earlier event row is unchanged');
    assert.equal(after.length, events.length + 1, 'the void appended only its revocation record');
  } finally {
    await world.close();
  }
});

test('[CH-10] each repeatable action counts exactly once, inside its write transaction, and SQLite answers that count from the audit_events_envelope index alone (covering-index search on tenant_id and envelope_id)', async () => {
  const world = await createWorld();
  const original = TenantStore.prototype.count;
  const counts = [];
  TenantStore.prototype.count = function spiedCount(table, where) {
    if (table === 'audit_events') counts.push({ inTransaction: world.db.inTransaction, where: { ...where } });
    return original.call(this, table, where);
  };
  try {
    const { envelope, token } = await sentEnvelope(world);
    const single = [{ inTransaction: true, where: { envelope_id: envelope.id } }];
    counts.length = 0;
    const code = await requestCode(world, token);
    assert.deepEqual(counts, single, 'the challenge work counted once, in its transaction');
    counts.length = 0;
    assert.equal((await createSession(world, token, code)).status, 201);
    assert.deepEqual(counts, single, 'the session creation counted once, in its transaction');
    counts.length = 0;
    await resend(world, envelope, envelope.recipients[0], HUMAN);
    assert.deepEqual(counts, single, 'the resend counted once, in the caller\'s transaction');

    const raw = new DatabaseSync(world.path, { readOnly: true });
    try {
      const plan = raw
        .prepare('EXPLAIN QUERY PLAN SELECT count(*) AS n FROM "audit_events" WHERE "tenant_id" = ? AND "envelope_id" = ?')
        .all(world.tenant, envelope.id)
        .map((row) => String(row.detail))
        .join('\n');
      assert.match(plan, /COVERING INDEX audit_events_envelope \(tenant_id=\? AND envelope_id=\?\)/, 'the count is a covering-index search');
    } finally {
      raw.close();
    }
  } finally {
    TenantStore.prototype.count = original;
    await world.close();
  }
});

// ------------------------------------------------------------------------ CH-11

test('[CH-11] splitRevocationMetadata gives one part with the full lists whenever they fit, exactly at the limit included; otherwise disjoint parts, each within the limit and carrying the scope, that in order name every id exactly once, a part closing only when the next id would not fit (row REVOKE-META)', () => {
  const scope = { envelope_version: 7 };
  const size = (metadata) => Buffer.byteLength(canonicalize(metadata), 'utf8');
  const idsOf = (prefix, n) => Array.from({ length: n }, (_, index) => `${prefix}${String(index).padStart(20, '0')}`);
  assert.deepEqual(recipientsRepo.splitRevocationMetadata(scope, { invitationIds: [], sessionIds: [] }), [], 'nothing revoked, no event');
  for (const limit of [MAX_METADATA_BYTES, 600, 200]) {
    for (const [invitations, sessions] of [[0, 1], [1, 0], [1, 3], [2, 150], [1, OLD_SESSIONS], [0, 1000]]) {
      const label = `limit ${limit}, ${invitations} invitations, ${sessions} sessions`;
      const revoked = { invitationIds: idsOf('inv', invitations), sessionIds: idsOf('ses', sessions) };
      const whole = { ...scope, invitation_ids: revoked.invitationIds, session_ids: revoked.sessionIds };
      const parts = recipientsRepo.splitRevocationMetadata(scope, revoked, limit);
      if (size(whole) <= limit) {
        assert.deepEqual(parts, [whole], `${label}: one part, exactly the full lists`);
        continue;
      }
      assert.ok(parts.length > 1, `${label}: split`);
      for (const part of parts) {
        assert.ok(size(part) <= limit, `${label}: each part within the limit`);
        assert.equal(part.envelope_version, 7, `${label}: each part carries the scope`);
      }
      assert.deepEqual(parts.flatMap((part) => part.invitation_ids), revoked.invitationIds, `${label}: invitations once each, in order`);
      assert.deepEqual(parts.flatMap((part) => part.session_ids), revoked.sessionIds, `${label}: sessions once each, in order`);
      for (let index = 0; index + 1 < parts.length; index += 1) {
        const next = parts[index + 1];
        const member = next.invitation_ids.length > 0 ? 'invitation_ids' : 'session_ids';
        const grown = { ...parts[index], [member]: [...parts[index][member], next[member][0]] };
        assert.ok(size(grown) > limit, `${label}: part ${index + 1} closed only when the next id would not fit`);
      }
    }
  }
  const revoked = { invitationIds: idsOf('inv', 1), sessionIds: idsOf('ses', 10) };
  const exact = size({ ...scope, invitation_ids: revoked.invitationIds, session_ids: revoked.sessionIds });
  assert.equal(recipientsRepo.splitRevocationMetadata(scope, revoked, exact).length, 1, 'lists of exactly the limit are one event');
  assert.ok(recipientsRepo.splitRevocationMetadata(scope, revoked, exact - 1).length > 1, 'one byte over splits');
});

test('[CH-11] revocation stays live with many capabilities: on envelopes seeded through the repository with 300 unrevoked sessions for one recipient, a void commits and its revocation is several events, each within MAX_METADATA_BYTES, with the same actor, subject and scope, naming every revoked id exactly once, all returned by auditedRevocationsOf; a resend, a session creation and an expiry each commit on the same seeding (row REVOKE-META)', async () => {
  const world = await createWorld();
  try {
    const assertNamedOnce = (events, expected, label) => {
      assert.ok(events.length > 1, `${label}: the revocation is split over several events`);
      const named = events.flatMap(({ metadata }) => [...metadata.invitation_ids, ...metadata.session_ids]);
      assert.equal(named.length, new Set(named).size, `${label}: no id is named twice`);
      assert.deepEqual([...named].sort(), [...expected].sort(), `${label}: every revoked id is named`);
      for (const { metadata } of events) assert.ok(Buffer.byteLength(canonicalize(metadata), 'utf8') <= MAX_METADATA_BYTES, `${label}: each event within the limit`);
      assert.equal(new Set(events.map(({ row }) => `${row.actor_kind}/${row.actor_ref}/${row.subject_digest}`)).size, 1, `${label}: one actor and subject`);
      const scopes = events.map(({ metadata }) => {
        const { invitation_ids: _invitations, session_ids: _sessions, ...scope } = metadata;
        return JSON.stringify(scope);
      });
      assert.equal(new Set(scopes).size, 1, `${label}: one scope`);
    };
    const invitationOf = (envelope) => world.rows('invitations', `WHERE envelope_id = '${envelope.id}'`)[0].id;

    // A void.
    const voiding = await sentEnvelope(world);
    const voidSessions = seedSessions(world, voiding.envelope.id, voiding.envelope.recipients[0].id, OLD_SESSIONS);
    const voidInvitation = invitationOf(voiding.envelope);
    let seq = headSeq(world);
    assert.equal(voidEnvelope(world, voiding.envelope.id).state, 'voided', 'the void commits');
    assertNamedOnce(revocationsAfter(world, voiding.envelope.id, seq), [voidInvitation, ...voidSessions], 'void');
    const audited = auditedRevocationsOf(world.store(), voiding.envelope.id);
    for (const id of [voidInvitation, ...voidSessions]) assert.ok(audited.has(id), 'auditedRevocationsOf returns every revoked id');

    // A resend.
    const resending = await sentEnvelope(world);
    const resendSessions = seedSessions(world, resending.envelope.id, resending.envelope.recipients[0].id, OLD_SESSIONS);
    const resendInvitation = invitationOf(resending.envelope);
    seq = headSeq(world);
    await resend(world, resending.envelope, resending.envelope.recipients[0], HUMAN);
    assertNamedOnce(revocationsAfter(world, resending.envelope.id, seq), [resendInvitation, ...resendSessions], 'resend');

    // A session creation.
    const signing = await sentEnvelope(world);
    const code = await requestCode(world, signing.token);
    const signingSessions = seedSessions(world, signing.envelope.id, signing.envelope.recipients[0].id, OLD_SESSIONS);
    seq = headSeq(world);
    assert.equal((await createSession(world, signing.token, code)).status, 201, 'the session creation commits');
    assertNamedOnce(revocationsAfter(world, signing.envelope.id, seq), signingSessions, 'session creation');
    assert.equal(unrevoked(world, 'recipient_sessions', signing.envelope.id, signing.envelope.recipients[0].id).length, 1, 'only the new session is unrevoked');

    // An expiry (last: it moves the clock).
    const expiring = await sentEnvelope(world, { expiresAt: new Date(world.time.now.getTime() + 2 * HOUR).toISOString() });
    const expirySessions = seedSessions(world, expiring.envelope.id, expiring.envelope.recipients[0].id, OLD_SESSIONS);
    const expiryInvitation = invitationOf(expiring.envelope);
    seq = headSeq(world);
    world.time.advance(3 * HOUR);
    assert.equal(world.service.expireIfDue(world.tenant, expiring.envelope.id), true, 'the expiry commits');
    assertNamedOnce(revocationsAfter(world, expiring.envelope.id, seq), [expiryInvitation, ...expirySessions], 'expiry');
  } finally {
    await world.close();
  }
});

test('[CH-11] under the fixed code, after several session creations for each recipient, each recipient holds exactly one unrevoked session and at most one unrevoked invitation, each replacement names one session in one event with the recipient as actor, and a void writes one revocation event (row REVOKE-META, request #50)', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    const recipients = [1, 2].map((ordinal) => envelope.recipients.find((entry) => entry.ordinal === ordinal));
    for (let round = 0; round < 3; round += 1) await openSession(world, token);
    const approved = await approveFirst(world, envelope);
    assert.ok(approved.token !== null, 'premise: recipient 2 is invited');
    for (let round = 0; round < 3; round += 1) await openSession(world, approved.token, 'signer.two@example.test');

    for (const recipient of recipients) {
      assert.equal(unrevoked(world, 'recipient_sessions', envelope.id, recipient.id).length, 1, `recipient ${recipient.ordinal} holds exactly one unrevoked session`);
      assert.ok(unrevoked(world, 'invitations', envelope.id, recipient.id).length <= 1, `recipient ${recipient.ordinal} holds at most one unrevoked invitation`);
    }
    const replacements = revocationsAfter(world, envelope.id, 0);
    assert.equal(replacements.length, 4, 'two replacements for each recipient');
    for (const { row, metadata } of replacements) {
      assert.equal(metadata.session_ids.length, 1, 'each replacement names the one session it revoked');
      assert.deepEqual(metadata.invitation_ids, []);
      assert.equal(row.actor_kind, 'recipient', 'with the recipient as actor');
    }

    const seq = headSeq(world);
    assert.equal(voidEnvelope(world, envelope.id).state, 'voided');
    const voidEvents = revocationsAfter(world, envelope.id, seq);
    assert.equal(voidEvents.length, 1, 'the void writes one revocation event');
    assert.equal(voidEvents[0].metadata.session_ids.length, 2, 'naming each recipient\'s one session');
  } finally {
    await world.close();
  }
});
