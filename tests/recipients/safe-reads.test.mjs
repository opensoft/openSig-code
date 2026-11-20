// SPDX-License-Identifier: Apache-2.0
//
// T008 recipient ceremony: GET, HEAD and prefetch are safe. SC002-25 (opening,
// reloading or prefetching the invitation link changes no state; session reads
// never consume, approve or change the envelope) and RC-03 (the exact frozen
// document and canonical manifest bytes, with their headers).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { COOKIE, contractErrors, createSession, createWorld, logsFreeOf, openSession, readAs, requestCode, sentEnvelope, sha256 } from './support.mjs';

const PREFETCH_HEADERS = [
  { 'sec-purpose': 'prefetch' },
  { 'sec-purpose': 'prefetch;prerender' },
  { purpose: 'prefetch' },
  { 'x-purpose': 'preview' },
  { 'x-moz': 'prefetch' },
];

test('[SC002-25] GET, HEAD or prefetch of the invitation link changes no state, mails nothing and leaves the invitation usable', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world, { recipients: 2 });
    const before = world.snapshot();
    const mailsBefore = world.mails().length;

    // The link is /sign#i=<token>: the fragment never reaches the server. A scanner may still
    // fetch /sign, reload it, prefetch it, or even put the token in a query string.
    const requests = [
      { method: 'GET', path: '/sign' },
      { method: 'HEAD', path: '/sign' },
      { method: 'GET', path: '/sign' },
      ...PREFETCH_HEADERS.map((headers) => ({ method: 'GET', path: '/sign', headers })),
      { method: 'GET', path: `/sign?i=${token}` },
      { method: 'HEAD', path: `/sign?i=${token}` },
      { method: 'GET', path: `/sign?i=${token}`, headers: { 'sec-purpose': 'prefetch' } },
      // Safe methods on the ceremony's own paths: unauthenticated reads, and methods that are not routes.
      { method: 'GET', path: '/v1/recipient-session' },
      { method: 'HEAD', path: '/v1/recipient-session' },
      { method: 'GET', path: '/v1/recipient-session/document' },
      { method: 'GET', path: '/v1/recipient-session/manifest', headers: { 'sec-purpose': 'prefetch' } },
      { method: 'GET', path: '/v1/recipient-session/challenges' },
      { method: 'HEAD', path: '/v1/recipient-session/challenges' },
      { method: 'GET', path: `/v1/recipient-session/challenges?invitation=${token}` },
      { method: 'GET', path: '/v1/recipient-session/approval' },
    ];
    for (const options of requests) {
      const response = await world.http(options);
      assert.ok(response.status >= 400 || response.status === 200, `${options.method} ${options.path.split('?')[0]}: answered`);
      assert.equal(response.headers['set-cookie'], undefined, `${options.method} ${options.path.split('?')[0]}: no cookie is set`);
    }
    assert.deepEqual(world.snapshot(), before, 'no envelope, recipient, invitation, challenge, session, approval, audit or outbox change');
    assert.equal(world.mails().length, mailsBefore, 'nothing was mailed');
    assert.equal(world.rows('envelopes', `WHERE id = '${envelope.id}'`)[0].version, envelope.version, 'the envelope version is unchanged');
    assert.equal(world.rows('approvals').length, 0, 'no approval');
    assert.ok(logsFreeOf(world, [token]), 'the token in a query string is never logged');

    // Nothing was consumed: the invitation still opens a session.
    const code = await requestCode(world, token);
    assert.equal((await createSession(world, token, code)).status, 201);
  } finally {
    await world.close();
  }
});

test('[SC002-25] session reads (GET, HEAD and prefetch of the state, document and manifest) never consume, approve or change the envelope', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world);
    const { session } = await openSession(world, token);
    const paths = ['/v1/recipient-session', '/v1/recipient-session/document', '/v1/recipient-session/manifest'];

    // A prefetch changes nothing at all, not even the session's last_seen_at.
    world.time.advance(60_000);
    const untouched = world.snapshot();
    for (const path of paths) {
      for (const headers of PREFETCH_HEADERS) {
        const response = await readAs(world, session, path, { headers });
        assert.equal(response.status, 200, `prefetch ${path}`);
      }
    }
    assert.deepEqual(world.snapshot(), untouched, 'prefetching changed no row');

    // GET and HEAD move only last_seen_at.
    const before = world.snapshot({ recipient_sessions: ['last_seen_at'] });
    for (const path of paths) {
      for (const method of ['GET', 'HEAD', 'GET']) {
        const response = await readAs(world, session, path, { method });
        assert.equal(response.status, 200, `${method} ${path}`);
        if (method === 'HEAD') assert.equal(response.bytes.length, 0, `HEAD ${path} has no body`);
      }
    }
    assert.deepEqual(world.snapshot({ recipient_sessions: ['last_seen_at'] }), before, 'reads changed nothing but last_seen_at');
    assert.equal(world.rows('recipient_sessions')[0].last_seen_at, world.time.now.toISOString(), 'the reads kept the session alive');
    const stored = world.rows('envelopes', `WHERE id = '${envelope.id}'`)[0];
    assert.equal(stored.version, envelope.version);
    assert.equal(stored.state, 'sent');
    assert.equal(world.rows('recipients', `WHERE envelope_id = '${envelope.id}' AND ordinal = 1`)[0].status, 'invited', 'reading never approves');
    assert.equal(world.rows('approvals').length, 0);
    assert.equal(world.mails().filter((mail) => mail.kind !== 'recipient_invitation' && mail.kind !== 'recipient_challenge').length, 0);
  } finally {
    await world.close();
  }
});

test('[RC-03] the document is the exact frozen bytes, framable only by the shell; the manifest is the exact canonical bytes of manifest_digest', async () => {
  const world = await createWorld();
  try {
    const { envelope, token, pdf } = await sentEnvelope(world);
    const { session, state } = await openSession(world, token);

    const document = await readAs(world, session, '/v1/recipient-session/document');
    assert.equal(document.status, 200);
    assert.ok(document.bytes.equals(pdf), 'the exact bytes that were stored');
    assert.equal(sha256(document.bytes), state.document.digest, 'their SHA-256 is the session’s document digest');
    assert.equal(document.bytes.length, state.document.bytes);
    assert.equal(document.headers['content-type'], 'application/pdf');
    assert.equal(document.headers['content-disposition'], 'inline');
    assert.equal(document.headers['cache-control'], 'no-store');
    assert.match(document.headers['content-security-policy'], /frame-ancestors 'self'/, 'only this response may be framed, by the shell');
    assert.equal(document.headers['referrer-policy'], 'no-referrer');
    const head = await readAs(world, session, '/v1/recipient-session/document', { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(head.bytes.length, 0);
    assert.equal(head.headers['content-length'], String(pdf.length));

    const manifest = await readAs(world, session, '/v1/recipient-session/manifest');
    assert.equal(manifest.status, 200);
    assert.match(manifest.headers['content-type'], /^application\/json/);
    assert.match(manifest.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(sha256(manifest.bytes), state.manifest_digest, 'SHA-256 of the exact bytes is manifest_digest');
    assert.equal(sha256(manifest.bytes), envelope.manifest_digest);
    const parsed = JSON.parse(manifest.bytes.toString('utf8'));
    assert.deepEqual(contractErrors('FieldManifest', parsed), []);
    assert.equal(parsed.document_digest, state.document.digest, 'the manifest binds the same document');
    assert.equal(parsed.envelope_id, envelope.id);
    const storedManifest = world.rows('field_manifests', `WHERE envelope_id = '${envelope.id}'`)[0];
    assert.ok(Buffer.from(storedManifest.canonical_bytes).equals(manifest.bytes), 'the bytes frozen at prepare, unchanged');

    // The state response is never framable either.
    const read = await readAs(world, session);
    assert.match(read.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(read.headers['cache-control'], 'no-store');
    assert.equal(read.headers['access-control-allow-origin'], undefined);
    // Another session's cookie name or a missing cookie reads nothing.
    assert.equal((await world.http({ path: '/v1/recipient-session/document', headers: { cookie: `other=${session}` } })).status, 401);
    assert.ok(COOKIE.startsWith('__Host-'));
  } finally {
    await world.close();
  }
});
