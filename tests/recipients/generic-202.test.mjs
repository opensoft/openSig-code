// SPDX-License-Identifier: Apache-2.0
//
// T008, row T008-F1: requestChallenge's generic 202 is indistinguishable in
// timing (data-model.md § Authentication and secrets, "Generic 202 (A-010)").
// Before it answers, requestChallenge does only schema validation and the
// rate-limit decision; the lookup, the supersession, the challenge write and
// the mail run after the 202, serialized per invitation, in their own
// transaction. CH-07 proves that order deterministically, with no wall-clock
// threshold, no latency comparison and no padding.
//
// The oracle is an observed committed 202. The per-invitation work is held
// (heldWork holds the ceremony's scheduled work, so the lookup and the write
// cannot start; heldNotifier holds the mail). The client then has the complete
// response, status line, headers and body, while the work is still held, and
// at that moment no challenge row and no mail exist. Only then is the work
// released, and the outcome asserted. Release points are awaited through the
// work itself (heldNotifier.whenWaiting, the ceremony's drain()), never through
// time. The only timer is a hang guard: at a head that answers only after the
// work, the held work would block the 202 forever, and the guard turns that
// hang into a failure with its own message. A pass never depends on it.
//
// Paths: (a) slow mail, (b) mail error, (c) storage error on the write and on
// the lookup, (d) unknown, expired, superseded and locked invitations, and the
// per-invitation serialization. Capability values stay in memory; assertion
// messages carry labels only.
//
// Those cases hold the work through an injected scheduler, so they cannot see
// where the DEFAULT scheduler starts it. The last case (A-010 D5, G1) runs the
// production default with no hold and records, inside this process, the order
// of two server-side events for each request: the 202's commit (the
// ServerResponse's end() has returned with the status line, headers and body
// handed to the socket) and the ceremony's first per-invitation storage work
// (its first transaction or invitation lookup, seen through a database spy).
// The 202 must come first. The order is an event sequence, not a time.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';

import {
  HOUR,
  codeOf,
  comparableHeaders,
  createSession,
  createWorld,
  heldNotifier,
  heldWork,
  lockOut,
  logsFreeOf,
  postChallenge,
  requestCode,
  resend,
  sentEnvelope,
  settle,
} from './support.mjs';

const GENERIC_BODY = '{"status":"accepted"}';
const HANG_GUARD_MS = 20_000;

/** Await `promise`, failing with a message of its own if it never settles (a hang guard, not the oracle). */
async function guarded(promise, label) {
  let timer;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${label}: no complete 202 arrived while the per-invitation work was held (hang guard; it bounds a failure and is not the oracle)`)),
      HANG_GUARD_MS,
    );
  });
  try {
    return await Promise.race([promise, guard]);
  } finally {
    clearTimeout(timer);
  }
}

/** The complete generic 202: status line, headers and the whole body are in. */
function assertCommitted202(response, label) {
  assert.equal(response.status, 202, `${label}: status 202`);
  assert.equal(response.bytes.toString('utf8'), GENERIC_BODY, `${label}: the complete generic body`);
  assert.equal(response.headers['content-length'], String(response.bytes.length), `${label}: every byte of the declared body arrived`);
  assert.equal(typeof response.headers['x-correlation-id'], 'string', `${label}: the correlation ID header`);
}

function challengeMailCount(world) {
  return world.mails().filter((mail) => mail.kind === 'recipient_challenge').length;
}

function failureLines(world) {
  return world.lines.map((line) => JSON.parse(line)).filter((record) => record.event === 'challenge_work_failed');
}

function lastInvitation(world) {
  const rows = world.rows('invitations');
  return rows[rows.length - 1];
}

test('[CH-07] the generic 202 is committed while the per-invitation work is held, for live, unknown, expired, superseded and locked invitations; once released only the live one gets a challenge and a mail', async () => {
  const work = heldWork();
  const mail = heldNotifier();
  const world = await createWorld({ scheduleWork: work.schedule, wrapNotifier: mail.wrap });
  try {
    const expiring = await sentEnvelope(world, { expiresAt: new Date(world.time.now.getTime() + 2 * HOUR).toISOString() });
    const superseded = await sentEnvelope(world);
    await resend(world, superseded.envelope, superseded.envelope.recipients[0]);
    const locked = await sentEnvelope(world);
    await lockOut(world, locked.token);
    world.time.advance(3 * HOUR);
    const live = await sentEnvelope(world);
    const liveInvitation = lastInvitation(world);
    const cases = [
      ['live invitation', live.token],
      ['unknown token', randomBytes(32).toString('base64url')],
      ['expired invitation', expiring.token],
      ['superseded invitation', superseded.token],
      ['locked invitation', locked.token],
    ];
    const challengesBefore = world.rows('challenges').length;
    const mailsBefore = challengeMailCount(world);

    work.hold();
    mail.hold();
    const responses = [];
    for (const [index, [label, token]] of cases.entries()) {
      const response = await guarded(postChallenge(world, token), label);
      // The oracle: the complete 202 is in while this request's work is held.
      assertCommitted202(response, label);
      assert.equal(work.waiting, index + 1, `${label}: its per-invitation work is held, not started`);
      assert.equal(world.ceremony.challengeWorkStats().pending, index + 1, `${label}: the ceremony counts its work as pending (the setup settled all earlier work)`);
      assert.equal(mail.waiting, 0, `${label}: nothing has reached the notifier`);
      assert.equal(world.rows('challenges').length, challengesBefore, `${label}: no challenge row is written yet`);
      assert.equal(challengeMailCount(world), mailsBefore, `${label}: no mail is in the spool yet`);
      responses.push([label, response]);
    }
    // Held work has neither completed nor failed, so these are the counts from before the requests.
    const statsBefore = world.ceremony.challengeWorkStats();
    const [, first] = responses[0];
    for (const [label, response] of responses.slice(1)) {
      assert.deepEqual(comparableHeaders(response), comparableHeaders(first), `${label}: the same headers as the live invitation's (except date and x-correlation-id)`);
      assert.ok(response.bytes.equals(first.bytes), `${label}: the same body bytes`);
    }

    // Release the lookup and the write: only the live invitation writes a challenge, and its
    // mail then waits at the held notifier (path a, slow mail).
    work.release();
    await mail.whenWaiting(1);
    const written = world.rows('challenges');
    assert.equal(written.length, challengesBefore + 1, 'exactly one challenge is written');
    assert.equal(written[written.length - 1].invitation_id, liveInvitation.id, 'for the live invitation');
    assert.equal(challengeMailCount(world), mailsBefore, 'its mail has not arrived while the notifier is held');

    mail.release();
    await settle(world);
    const mails = world.takeMails('recipient_challenge');
    assert.equal(mails.length, 1, 'once released, exactly one code is mailed');
    assert.equal(mails[0].to, 'signer.one@example.test', 'to the live invitation\'s recipient');
    assert.equal(world.rows('challenges').length, challengesBefore + 1, 'no row for the unknown, expired, superseded or locked invitation');
    const stats = world.ceremony.challengeWorkStats();
    assert.equal(stats.pending, 0, 'all work settled');
    assert.equal(stats.completed, statsBefore.completed + cases.length, 'every request\'s work ran');
    assert.equal(stats.failed, statsBefore.failed, 'nothing failed');
    assert.equal(failureLines(world).length, 0, 'no failure was logged');
    assert.equal((await createSession(world, live.token, codeOf(mails[0]))).status, 201, 'the mailed code opens a session');
  } finally {
    mail.open();
    work.open();
    await settle(world);
    await world.close();
  }
});

test('[CH-07] a mail failure after the committed 202 is logged with the correlation ID and counted; the challenge it wrote stays open and unmailed, and the recipient can request again', async () => {
  const work = heldWork();
  const mail = heldNotifier();
  const world = await createWorld({ scheduleWork: work.schedule, wrapNotifier: mail.wrap });
  try {
    const { token } = await sentEnvelope(world);
    const invitationBefore = world.rows('invitations')[0];
    work.hold();
    mail.hold();
    const response = await guarded(postChallenge(world, token), 'live invitation');
    assertCommitted202(response, 'live invitation');
    const statsBefore = world.ceremony.challengeWorkStats();
    assert.equal(work.waiting, 1, 'the work is held');
    assert.equal(world.rows('challenges').length, 0, 'no challenge row yet');
    assert.equal(challengeMailCount(world), 0, 'no mail yet');

    work.release();
    await mail.whenWaiting(1);
    assert.equal(world.rows('challenges').length, 1, 'the challenge is written before the mail is attempted');
    mail.fail(new Error('synthetic transport failure'));
    await settle(world);

    // Path (b): logged with the request's correlation ID, never a token or code, and counted.
    const failures = failureLines(world);
    assert.equal(failures.length, 1, 'one failure line');
    assert.equal(failures[0].correlation_id, response.headers['x-correlation-id'], 'it carries the 202\'s correlation ID');
    assert.equal(failures[0].stage, 'mail');
    assert.equal(failures[0].reason, 'delivery_failed');
    assert.equal(failures[0].failures, statsBefore.failed + 1, 'it carries the running failure count');
    assert.equal(world.ceremony.challengeWorkStats().failed, statsBefore.failed + 1, 'the failure is counted');
    assert.ok(logsFreeOf(world, [token]), 'no log line carries the invitation');

    // What a mail failure leaves in storage: the committed challenge, open (not consumed, not
    // superseded, no attempts), whose code was mailed to nobody; the invitation's counters and
    // revocation are unchanged. Nothing more is mailed.
    const [orphan] = world.rows('challenges');
    assert.equal(orphan.consumed_at, null);
    assert.equal(orphan.superseded_at, null);
    assert.equal(orphan.attempts, 0);
    assert.deepEqual(world.rows('invitations')[0], invitationBefore, 'the invitation row is unchanged');
    assert.equal(challengeMailCount(world), 0, 'no code was mailed');

    // "The recipient can request again": the next request supersedes the unmailed challenge and
    // mails a fresh code, which opens a session.
    mail.open();
    work.open();
    const code = await requestCode(world, token);
    assert.ok(code !== null, 'the next request mails a code');
    const rows = world.rows('challenges');
    assert.equal(rows.length, 2);
    assert.notEqual(rows[0].superseded_at, null, 'the unmailed challenge is superseded');
    assert.equal(rows[1].superseded_at, null);
    assert.equal((await createSession(world, token, code)).status, 201, 'the fresh code opens a session');
  } finally {
    mail.open();
    work.open();
    await settle(world);
    await world.close();
  }
});

test('[CH-07] a storage failure after the committed 202, on the write or on the lookup, is logged and counted, and leaves nothing written or mailed', async () => {
  const work = heldWork();
  const mail = heldNotifier();
  const lookup = { fail: false };
  const wrapDb = (db) =>
    new Proxy(db, {
      get(target, property) {
        if (property === 'resolveCapability') {
          return (...args) => {
            if (lookup.fail) throw new Error('synthetic storage failure on the lookup');
            return target.resolveCapability(...args);
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  const world = await createWorld({ scheduleWork: work.schedule, wrapNotifier: mail.wrap, wrapDb });
  try {
    const { token } = await sentEnvelope(world);
    // An open challenge already exists, so a failed write must also undo its supersession.
    const firstCode = await requestCode(world, token);
    assert.ok(firstCode !== null);
    const before = world.rows('challenges');
    assert.equal(before.length, 1);

    // (c1) The write fails: a raw writer installs a refusing trigger once the 202 is committed.
    work.hold();
    mail.hold();
    const writeFails = await guarded(postChallenge(world, token), 'write failure');
    assertCommitted202(writeFails, 'write failure');
    const statsBefore = world.ceremony.challengeWorkStats();
    assert.equal(work.waiting, 1, 'the work is held');
    const raw = new DatabaseSync(world.path);
    try {
      raw.exec("CREATE TRIGGER ch07_injected_write_failure BEFORE INSERT ON challenges BEGIN SELECT RAISE(ABORT, 'synthetic storage failure on the write'); END;");
    } finally {
      raw.close();
    }
    work.release();
    await settle(world);
    const dropper = new DatabaseSync(world.path);
    try {
      dropper.exec('DROP TRIGGER ch07_injected_write_failure');
    } finally {
      dropper.close();
    }
    assert.deepEqual(world.rows('challenges'), before, 'the transaction rolled back: no new challenge, and the open one is not superseded');
    assert.equal(mail.waiting, 0, 'nothing reached the notifier');
    assert.equal(challengeMailCount(world), 1, 'only the earlier code was ever mailed');
    let failures = failureLines(world);
    assert.equal(failures.length, 1, 'one failure line');
    assert.equal(failures[0].correlation_id, writeFails.headers['x-correlation-id'], 'it carries the 202\'s correlation ID');
    assert.equal(failures[0].stage, 'storage');
    assert.equal(world.ceremony.challengeWorkStats().failed, statsBefore.failed + 1, 'the failure is counted');

    // (c2) The lookup fails.
    const lookupFails = await guarded(postChallenge(world, token), 'lookup failure');
    assertCommitted202(lookupFails, 'lookup failure');
    assert.equal(work.waiting, 1, 'the work is held');
    lookup.fail = true;
    work.release();
    await settle(world);
    lookup.fail = false;
    assert.deepEqual(world.rows('challenges'), before, 'nothing written');
    assert.equal(challengeMailCount(world), 1, 'nothing mailed');
    failures = failureLines(world);
    assert.equal(failures.length, 2, 'a second failure line');
    assert.equal(failures[1].correlation_id, lookupFails.headers['x-correlation-id']);
    assert.equal(failures[1].stage, 'storage');
    assert.equal(failures[1].failures, statsBefore.failed + 2);
    assert.equal(world.ceremony.challengeWorkStats().failed, statsBefore.failed + 2, 'both failures are counted');
    assert.ok(logsFreeOf(world, [token, firstCode]), 'no log line carries the invitation or a code');

    // The earlier code still works: nothing was lost but the failed requests' own work.
    mail.open();
    work.open();
    assert.equal((await createSession(world, token, firstCode)).status, 201);
  } finally {
    lookup.fail = false;
    mail.open();
    work.open();
    await settle(world);
    await world.close();
  }
});

test('[CH-07] the post-response work is serialized per invitation: a second request\'s lookup and write wait until the first one\'s mail is done', async () => {
  const work = heldWork();
  const mail = heldNotifier();
  const world = await createWorld({ scheduleWork: work.schedule, wrapNotifier: mail.wrap });
  try {
    const { token } = await sentEnvelope(world);
    work.hold();
    mail.hold();
    const one = await guarded(postChallenge(world, token), 'first request');
    const two = await guarded(postChallenge(world, token), 'second request');
    assertCommitted202(one, 'first request');
    assertCommitted202(two, 'second request');
    assert.equal(work.waiting, 2, 'both requests\' work is held');
    assert.equal(world.rows('challenges').length, 0);

    work.release();
    await mail.whenWaiting(1);
    assert.equal(world.rows('challenges').length, 1, 'the second request\'s work waits while the first one\'s mail is pending');
    mail.release();
    await mail.whenWaiting(1);
    const rows = world.rows('challenges');
    assert.equal(rows.length, 2, 'then the second request writes its challenge');
    assert.notEqual(rows[0].superseded_at, null, 'superseding the first');
    assert.equal(world.takeMails('recipient_challenge').length, 1, 'the first code was mailed before the second challenge was written');
    mail.release();
    await settle(world);
    const mails = world.takeMails('recipient_challenge');
    assert.equal(mails.length, 1, 'the second code is mailed last');
    assert.equal((await createSession(world, token, codeOf(mails[0]))).status, 201, 'the last mailed code is the open one');
  } finally {
    mail.open();
    work.open();
    await settle(world);
    await world.close();
  }
});

test('[CH-07] with the default scheduler and no hold, the generic 202 is committed before the first per-invitation storage work, for live and not-live invitations (A-010 D5, G1)', async () => {
  // A spy on the ceremony's database: its transactions and its invitation lookups, while armed.
  const observed = { armed: false, events: [] };
  const wrapDb = (db) =>
    new Proxy(db, {
      get(target, property) {
        if (property === 'transaction') {
          return (...args) => {
            if (observed.armed) observed.events.push('transaction');
            return target.transaction(...args);
          };
        }
        if (property === 'resolveCapability') {
          return (...args) => {
            if (observed.armed && args[0] === 'invitations') observed.events.push('invitation lookup');
            return target.resolveCapability(...args);
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  // The production defaults: no scheduleWork, no notifier wrapper.
  const world = await createWorld({ wrapDb });
  // The 202's commit, seen on the real server's ServerResponse: end() has returned for the challenge route.
  world.server.prependListener('request', (req, res) => {
    const end = res.end;
    res.end = function observedEnd(...args) {
      const result = end.apply(this, args);
      if (observed.armed && req.method === 'POST' && req.url === '/v1/recipient-session/challenges' && this.statusCode === 202) {
        observed.events.push(this.writableEnded ? '202 committed' : '202 end() returned without ending');
      }
      return result;
    };
  });
  try {
    const expiring = await sentEnvelope(world, { expiresAt: new Date(world.time.now.getTime() + 2 * HOUR).toISOString() });
    const superseded = await sentEnvelope(world);
    await resend(world, superseded.envelope, superseded.envelope.recipients[0]);
    const locked = await sentEnvelope(world);
    await lockOut(world, locked.token);
    world.time.advance(3 * HOUR);
    const live = await sentEnvelope(world);
    world.takeMails('recipient_challenge');
    const cases = [
      ['live invitation', live.token, 1],
      ['unknown token', randomBytes(32).toString('base64url'), 0],
      ['expired invitation', expiring.token, 0],
      ['superseded invitation', superseded.token, 0],
      ['locked invitation', locked.token, 0],
    ];
    // Every case is observed before the order is asserted, so a failure names each case's order.
    const workFirst = [];
    for (const [label, token, mailed] of cases) {
      observed.events = [];
      observed.armed = true;
      const response = await postChallenge(world, token);
      await settle(world);
      observed.armed = false;
      const sequence = observed.events.join(' > ');
      assertCommitted202(response, label);
      assert.equal(observed.events.filter((event) => event.startsWith('202')).length, 1, `${label}: one 202 commit observed (observed: ${sequence})`);
      assert.ok(observed.events.includes('transaction') && observed.events.includes('invitation lookup'), `${label}: the per-invitation work ran and was observed (observed: ${sequence})`);
      if (observed.events[0] !== '202 committed') workFirst.push(`${label}: ${sequence}`);
      assert.equal(world.takeMails('recipient_challenge').length, mailed, `${label}: ${mailed} code mailed once the work settled`);
    }
    assert.deepEqual(workFirst, [], 'for every case the 202 is committed before the first per-invitation transaction or invitation lookup');
    const stats = world.ceremony.challengeWorkStats();
    assert.equal(stats.pending, 0);
    assert.equal(stats.failed, 0, 'no post-response work failed');
  } finally {
    observed.armed = false;
    await settle(world);
    await world.close();
  }
});
