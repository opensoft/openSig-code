// SPDX-License-Identifier: Apache-2.0
//
// T008 recipient ceremony: invitation issuance (RC-01) and the challenge code,
// its HMAC storage and the 0600 key file (CH-01). Capability values are read
// from the spool and compared as booleans; none appears in a name or message.
// CH-01 (extended, A-010 KEY-FIFO): a FIFO at the key path is refused at once;
// a worker thread (fifo-rescue-worker.mjs) bounds a regression's blocking open.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { closeSync, lstatSync, mkdirSync, mkdtempSync, openSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import { ChallengeKeyError, loadChallengeKey, newChallengeCode, newInvitationToken, RecipientCeremony } from '../../src/api/recipients/index.ts';
import {
  CODE_SHAPE,
  CROCKFORD,
  DAY,
  codeOf,
  createWorld,
  expectedHmac,
  fieldsFor,
  createInput,
  logsFreeOf,
  requestChallenge,
  sentEnvelope,
  sha256,
  syntheticPdf,
} from './support.mjs';

test('[RC-01] sending issues a 256-bit invitation, stores only its hash, binds it, and mails it once in the URL fragment after the commit', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    assert.ok(/^[A-Za-z0-9_-]{43}$/.test(token), 'the token is 43 base64url characters: 256 bits');
    const rows = world.rows('invitations');
    assert.equal(rows.length, 1, 'only recipient 1 is invited at send');
    const row = rows[0];
    const recipient1 = envelope.recipients.find((entry) => entry.ordinal === 1);
    assert.equal(row.recipient_id, recipient1.id, 'bound to recipient 1');
    assert.equal(row.manifest_digest, envelope.manifest_digest, 'bound to the frozen manifest');
    const revision = world.rows('document_revisions', `WHERE envelope_id = '${envelope.id}'`)[0];
    assert.equal(row.revision_id, revision.id, 'bound to the frozen revision');
    assert.ok(row.token_hash === sha256(Buffer.from(token, 'ascii')), 'the stored form is the SHA-256 of the token');
    assert.ok(!Object.values(row).some((value) => typeof value === 'string' && value.includes(token)), 'no column holds the token');
    assert.equal(row.sent_at, world.time.now.toISOString());
    assert.equal(Date.parse(row.expires_at) - Date.parse(row.sent_at), 7 * DAY, 'expires 7 days after sending (the envelope expires later)');
    assert.equal(row.cumulative_wrong_codes, 0);
    assert.equal(row.revoked_at, null);

    // The mail: one link, /sign, no query, the token only in the fragment, exactly once.
    const mail = world.mails().find((entry) => entry.kind === 'recipient_invitation');
    const text = mail.text;
    assert.equal(text.split(token).length - 1, 1, 'the token appears exactly once in the message');
    const head = text.slice(0, text.indexOf('\r\n\r\n'));
    assert.ok(!head.includes(token), 'never in a header');
    const link = /^(https:\/\/\S+)\r$/m.exec(text)?.[1] ?? '';
    const url = new URL(link);
    assert.equal(url.origin, 'https://sign.alpha.test');
    assert.equal(url.pathname, '/sign');
    assert.equal(url.search, '');
    assert.ok(url.hash === `#i=${token}`, 'the invitation travels only in the URL fragment');
    assert.equal(mail.to, 'signer.one@example.test');
    assert.ok(logsFreeOf(world, [token]), 'no log line carries the token');

    // A mutation that rolls back mails nothing and leaves no invitation.
    const rolled = await createWorld({ idempotencyBodyLimit: 2 });
    try {
      const pdf = syntheticPdf('rollback');
      const put = rolled.blobs.put(rolled.tenant, pdf);
      const created = rolled.service.create(rolled.req(), createInput(1)).body;
      const uploaded = rolled.service.uploadDocument(rolled.req(), created.id, 1, { digest: put.digest, bytes: pdf.length, pages: [{ number: 1, width: 612, height: 792, rotate: 0 }], parseReport: { pages: 1 } }).body;
      const prepared = rolled.service.prepare(rolled.req(), created.id, { expected_version: uploaded.version, fields: fieldsFor(1) }).body;
      // The 2-byte idempotency body limit fails the send inside its transaction, after the invitation was issued.
      await assert.rejects(
        rolled.ceremony.run(() => rolled.service.send({ ...rolled.req(), idempotency: { key: 'send-key-0000000000000001', request: { expected_version: prepared.version } } }, prepared.id, { expected_version: prepared.version })),
        (error) => error?.code === 'internal',
      );
      assert.equal(rolled.rows('invitations').length, 0, 'the rolled-back send left no invitation');
      assert.equal(rolled.mails().length, 0, 'and mailed nothing');
      assert.equal(rolled.rows('envelopes')[0].state, 'prepared');

      // A change reported outside capture() is refused, so the send itself rolls back.
      assert.throws(() => rolled.service.send(rolled.req(), prepared.id, { expected_version: prepared.version }), /capture/);
      assert.equal(rolled.rows('envelopes')[0].state, 'prepared', 'an invitation is never issued without being mailed');
      assert.equal(rolled.rows('invitations').length, 0);
    } finally {
      await rolled.close();
    }

    // An InvitationMail never reveals its token.
    const { mails } = world.ceremony.capture(() => null);
    assert.equal(mails.length, 0);
    const second = await createWorld();
    try {
      const pdf = syntheticPdf('opaque');
      const put = second.blobs.put(second.tenant, pdf);
      const created = second.service.create(second.req(), createInput(1)).body;
      const uploaded = second.service.uploadDocument(second.req(), created.id, 1, { digest: put.digest, bytes: pdf.length, pages: [{ number: 1, width: 612, height: 792, rotate: 0 }], parseReport: { pages: 1 } }).body;
      const prepared = second.service.prepare(second.req(), created.id, { expected_version: uploaded.version, fields: fieldsFor(1) }).body;
      const captured = second.ceremony.capture(() => second.service.send(second.req(), prepared.id, { expected_version: prepared.version }));
      assert.equal(captured.mails.length, 1, 'one invitation awaits delivery after the commit');
      assert.equal(second.mails().length, 0, 'nothing is mailed before deliver()');
      const printed = `${JSON.stringify(captured.mails)} ${(await import('node:util')).inspect(captured.mails[0])} ${Object.keys(captured.mails[0]).join(',')}`;
      const storedHash = second.rows('invitations')[0].token_hash;
      assert.equal(/[A-Za-z0-9_-]{43}/.test(printed), false, 'no token-shaped value is printed or serialized');
      assert.deepEqual(await second.ceremony.deliver(captured.mails), { delivered: 1, failed: 0 });
      assert.deepEqual(await second.ceremony.deliver(captured.mails), { delivered: 0, failed: 1 }, 'each mail is delivered at most once');
      const token2 = /#i=([A-Za-z0-9_-]{43})/.exec(second.mails()[0].text)[1];
      assert.ok(sha256(Buffer.from(token2, 'ascii')) === storedHash, 'the delivered token is the committed invitation');
    } finally {
      await second.close();
    }
  } finally {
    await world.close();
  }
});

test('[CH-01] codes are 10 Crockford base32 characters (50 bits), mailed once and stored only as an HMAC under the key file', async () => {
  // The generator: uniform over the 32-symbol alphabet, never I, L, O or U.
  const used = new Set();
  for (let i = 0; i < 2000; i += 1) {
    const code = newChallengeCode();
    assert.ok(CODE_SHAPE.test(code), 'every generated code has the Crockford shape');
    for (const symbol of code) used.add(symbol);
  }
  assert.equal(used.size, 32, 'all 32 symbols occur');
  assert.equal([...used].some((symbol) => 'ILOU'.includes(symbol)), false);
  assert.equal(CROCKFORD.length ** 10, 2 ** 50, '10 symbols of 32 are 50 bits');
  assert.ok(/^[A-Za-z0-9_-]{43}$/.test(newInvitationToken()), 'a fresh invitation token is 256 bits of base64url');

  const world = await createWorld();
  try {
    const { token } = await sentEnvelope(world);
    assert.equal((await requestChallenge(world, token)).status, 202);
    const mails = world.takeMails('recipient_challenge', 'signer.one@example.test');
    assert.equal(mails.length, 1, 'one code is mailed');
    const code = codeOf(mails[0]);
    assert.ok(CODE_SHAPE.test(code), 'the mailed code has the Crockford shape');
    assert.equal(mails[0].text.split(code).length - 1, 1, 'the code appears once in the mail');
    assert.equal(/https?:|\/sign|#i=/.test(mails[0].text.slice(mails[0].text.indexOf('\r\n\r\n'))), false, 'the challenge mail carries no link');

    const invitation = world.rows('invitations')[0];
    const [challenge] = world.rows('challenges');
    assert.equal(challenge.invitation_id, invitation.id);
    assert.ok(challenge.code_hmac === expectedHmac(world.keyBytes, invitation.id, challenge.id, code), 'the stored value is HMAC-SHA256 under the key file, bound to the invitation and challenge');
    assert.ok(!Object.values(challenge).some((value) => typeof value === 'string' && value.includes(code)), 'no column holds the code');
    assert.equal(Date.parse(challenge.expires_at) - Date.parse(challenge.created_at), 10 * 60_000, 'a 10-minute TTL');
    assert.equal(challenge.attempts, 0);
    assert.ok(logsFreeOf(world, [token, code]), 'no log line carries the token or the code');
  } finally {
    await world.close();
  }
});

test('[CH-01] the challenge key comes only from a 0600 file or an inherited descriptor, never the environment or argv', async () => {
  const world = await createWorld();
  try {
    const dir = world.scratch.dir('opensig-keys-');
    const good = join(dir, 'good.key');
    writeFileSync(good, Buffer.alloc(32, 7), { mode: 0o600 });
    const key = loadChallengeKey({ path: good });
    assert.equal(key.codeHmac('inv-0000000000000001', 'chal-000000000000001', 'ABCDEFGHJK'), expectedHmac(Buffer.alloc(32, 7), 'inv-0000000000000001', 'chal-000000000000001', 'ABCDEFGHJK'));
    assert.equal(key.verify('inv-0000000000000001', 'chal-000000000000001', 'ABCDEFGHJK', key.codeHmac('inv-0000000000000001', 'chal-000000000000001', 'ABCDEFGHJK')), true);
    assert.equal(key.verify('inv-0000000000000001', 'chal-000000000000002', 'ABCDEFGHJK', key.codeHmac('inv-0000000000000001', 'chal-000000000000001', 'ABCDEFGHJK')), false, 'an HMAC verifies only for its own challenge');

    const fd = openSync(good, 'r');
    try {
      assert.equal(loadChallengeKey({ fd }).codeHmac('inv-0000000000000001', 'chal-000000000000001', 'ABCDEFGHJK'), key.codeHmac('inv-0000000000000001', 'chal-000000000000001', 'ABCDEFGHJK'), 'an inherited descriptor gives the same key');
    } finally {
      closeSync(fd);
    }

    const loose = join(dir, 'loose.key');
    writeFileSync(loose, Buffer.alloc(32, 7), { mode: 0o644 });
    const short = join(dir, 'short.key');
    writeFileSync(short, Buffer.alloc(31, 7), { mode: 0o600 });
    const link = join(dir, 'link.key');
    symlinkSync(good, link);
    const folder = join(dir, 'folder');
    mkdirSync(folder, { mode: 0o700 });
    const refusals = [
      [{ path: loose }, /0600/],
      [{ path: short }, /32 to 4096 bytes/],
      [{ path: link }, /symbolic link/],
      [{ path: folder }, /regular file/],
      [{ path: 'relative/challenge.key' }, /absolute/],
      [{ path: join(dir, 'missing.key') }, /cannot be opened/],
      [{ fd: -1 }, /descriptor/],
      [{ key: Buffer.alloc(32, 7) }, /file path or inherited file descriptor only/],
      [{ env: 'OPENSIG_CHALLENGE_KEY' }, /file path or inherited file descriptor only/],
      [{ path: good, value: 'x' }, /file path or inherited file descriptor only/],
      ['--challenge-key=00', /file path or inherited file descriptor only/],
    ];
    for (const [source, pattern] of refusals) {
      assert.throws(() => loadChallengeKey(source), (error) => error instanceof ChallengeKeyError && pattern.test(error.message), `refused: ${pattern}`);
    }
    assert.throws(
      () => new RecipientCeremony({ db: world.db, blobs: world.blobs, notifier: { send: async () => ({}) }, clock: world.time.clock, challengeKey: Buffer.alloc(32) }),
      /challenge key loaded from its key file/,
      'the ceremony takes only a loaded key',
    );
  } finally {
    await world.close();
  }
});

/** The FIFO rescuer: opens the FIFO's other end if the load has not returned in FIFO_RESCUE_AFTER_MS. */
const FIFO_RESCUE_WORKER = fileURLToPath(new URL('./fifo-rescue-worker.mjs', import.meta.url));
const FIFO_RESCUE_AFTER_MS = 2_000;

test('[CH-01] a FIFO swapped in at the key path after the server\'s own check is refused at once as not a regular file: the loader\'s open never blocks (A-010 KEY-FIFO, request #30)', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'opensig-key-fifo-'));
  // [0]: the load returned; [1]: the rescuer had to open the FIFO's other end.
  const flags = new Int32Array(new SharedArrayBuffer(2 * Int32Array.BYTES_PER_ELEMENT));
  let worker;
  try {
    // The server's lstat check (src/server/main.ts) refuses a FIFO that is already there. This is
    // the race it cannot see: the loader itself meets a FIFO at the path it opens.
    const fifo = join(dir, 'challenge-hmac.key');
    assert.equal(spawnSync('mkfifo', ['-m', '600', fifo]).status, 0, 'premise: a FIFO was created at the key path');
    assert.ok(lstatSync(fifo).isFIFO(), 'premise: the key path names a FIFO, with no writer');
    worker = new Worker(FIFO_RESCUE_WORKER, { workerData: { path: fifo, afterMs: FIFO_RESCUE_AFTER_MS, flags: flags.buffer } });
    const [armed] = await once(worker, 'message');
    assert.equal(armed, 'armed', 'premise: the rescuer is armed before the load');

    const started = performance.now();
    let refused;
    try {
      loadChallengeKey({ path: fifo });
    } catch (error) {
      refused = error;
    }
    Atomics.store(flags, 0, 1);
    const elapsed = performance.now() - started;
    const rescued = Atomics.load(flags, 1) === 1;
    t.diagnostic(`a FIFO at the key path was refused in ${Math.round(elapsed)} ms (rescue armed at ${FIFO_RESCUE_AFTER_MS} ms; rescued: ${rescued})`);

    assert.equal(rescued, false, `the loader's open of the FIFO did not block: it returned before the test opened the FIFO's other end (${Math.round(elapsed)} ms)`);
    assert.ok(refused instanceof ChallengeKeyError && /regular file/.test(refused.message), `the FIFO is refused as not a regular file (got ${refused})`);
    assert.ok(elapsed < FIFO_RESCUE_AFTER_MS / 2, `refused promptly: ${Math.round(elapsed)} ms, against a rescue at ${FIFO_RESCUE_AFTER_MS} ms`);
  } finally {
    Atomics.store(flags, 0, 1);
    await worker?.terminate();
    rmSync(dir, { recursive: true, force: true });
  }
});
