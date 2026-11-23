// SPDX-License-Identifier: Apache-2.0
//
// NT-02: the SMTP adapter talks only to a loopback relay (an in-process sink here) and
// fails closed. NT-03: recipient domains outside .test, example.com and example.org are
// refused unless the owner's explicit pilot configuration names them.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { connect as netConnect } from 'node:net';
import { join } from 'node:path';
import { after, test } from 'node:test';

import {
  createNotifier,
  createNotifierFromConfig,
  createSmtpTransport,
  createSpoolTransport,
  loadNotificationConfig,
  PILOT_SCHEMA,
} from '../../src/notifications/index.ts';
import {
  captureLogger,
  cleanup,
  closedPort,
  FROM,
  invitationRequest,
  isCode,
  newInvitation,
  ORIGIN,
  quietLogger,
  RECIPIENT,
  startSink,
  statusRequest,
  tempDir,
  tick,
} from './support.mjs';

after(cleanup);

const smtpNotifier = (port, extra = {}) =>
  createNotifier({
    transport: createSmtpTransport({ relay: { host: '127.0.0.1', port, timeoutMs: 5000 }, pilot: extra.pilot ?? null, connect: extra.connect }),
    from: FROM,
    publicOrigin: ORIGIN,
    pilot: extra.pilot ?? null,
    logger: extra.logger ?? quietLogger(),
  });

const rawMessage = (text) => ({ from: FROM, to: RECIPIENT, data: Buffer.from(text, 'ascii'), messageId: randomBytes(16).toString('hex'), date: new Date() });

test('[NT-02] every non-loopback relay is refused before any connection is attempted', () => {
  let connects = 0;
  const connect = () => {
    connects += 1;
    throw new Error('no connection may be attempted');
  };
  const refused = [
    'smtp.example.com',
    'relay.alpha.test',
    'localhost',
    '127.0.0.1.alpha.test',
    '0.0.0.0',
    '10.0.0.25',
    '192.0.2.10',
    '169.254.169.254',
    '::',
    '2001:db8::25',
    '::ffff:127.0.0.1',
    '127.1',
    '0177.0.0.1',
    '[::1]',
    ' 127.0.0.1',
  ];
  for (const host of refused) {
    assert.throws(() => createSmtpTransport({ relay: { host, port: 2525 }, pilot: null, connect }), isCode('relay_refused'), host);
    assert.throws(
      () => loadNotificationConfig({ OPENSIG_MAIL_TRANSPORT: 'smtp', OPENSIG_SMTP_HOST: host }),
      (error) => isCode('relay_refused')(error) && (!/[a-z]{3}/i.test(host) || !error.message.includes(host)),
      host,
    );
  }
  for (const host of [undefined, null, 25]) assert.throws(() => createSmtpTransport({ relay: { host }, pilot: null, connect }), isCode('relay_refused'));
  assert.equal(connects, 0, 'no socket was requested for a refused relay');

  for (const host of ['127.0.0.1', '127.0.0.53', '::1']) createSmtpTransport({ relay: { host, port: 2525 }, pilot: null, connect });
  assert.equal(connects, 0, 'creating a transport opens nothing');

  const credential = randomBytes(9).toString('base64url');
  assert.throws(
    () => loadNotificationConfig({ OPENSIG_MAIL_TRANSPORT: 'smtp', OPENSIG_SMTP_HOST: '127.0.0.1', OPENSIG_SMTP_PASSWORD: credential }),
    (error) => isCode('config_invalid')(error) && !error.message.includes(credential),
  );
  assert.throws(() => loadNotificationConfig({ OPENSIG_MAIL_TRANSPORT: 'smtp' }), isCode('config_invalid'), 'a relay host is required');
  assert.throws(() => loadNotificationConfig({ OPENSIG_MAIL_TRANSPORT: 'sendmail' }), isCode('config_invalid'));
});

test('[NT-02] a loopback relay receives the exact envelope and message, and a peer off loopback is refused', async () => {
  const sink = await startSink();
  try {
    const invitation = newInvitation();
    const receipt = await smtpNotifier(sink.port).send(invitationRequest(invitation));
    assert.equal(receipt.transport, 'smtp');
    const [session] = sink.sessions;
    assert.deepEqual(session.commands, ['EHLO opensig.test', `MAIL FROM:<${FROM}>`, `RCPT TO:<${RECIPIENT}>`, 'DATA', 'QUIT']);
    assert.match(session.data, /^Date: [A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} \+0000\r\n/);
    assert.ok(session.data.includes(`\r\nMessage-ID: <${receipt.message_id}@opensig.test>\r\n`));
    assert.ok(session.data.includes(`\r\nTo: ${RECIPIENT}\r\n`));
    assert.ok(session.data.includes(`\r\n${ORIGIN}/sign#i=${invitation}\r\n`));

    // Dot-stuffing (RFC 5321 4.5.2): lines starting with "." survive unchanged.
    const text = 'Subject: dot-stuffing probe\r\n\r\n.leading dot\r\n..two dots\r\n.\r\nlast line\r\n';
    await createSmtpTransport({ relay: { host: '127.0.0.1', port: sink.port }, pilot: null }).deliver(rawMessage(text));
    assert.deepEqual(sink.sessions[1].rawData, ['Subject: dot-stuffing probe', '', '..leading dot', '...two dots', '..', 'last line']);
    assert.equal(sink.sessions[1].data, text);
    await assert.rejects(
      createSmtpTransport({ relay: { host: '127.0.0.1', port: sink.port }, pilot: null }).deliver(rawMessage('Subject: bare\nLF only\n')),
      isCode('delivery_failed'),
    );

    // A connection whose peer is not a loopback address is dropped before any command.
    const offLoopback = (target) => {
      const socket = netConnect(target);
      Object.defineProperty(socket, 'remoteAddress', { get: () => '192.0.2.10' });
      return socket;
    };
    const before = sink.sessions.length;
    await assert.rejects(
      createSmtpTransport({ relay: { host: '127.0.0.1', port: sink.port }, pilot: null, connect: offLoopback }).deliver(rawMessage(text)),
      isCode('relay_refused'),
    );
    await tick();
    for (const later of sink.sessions.slice(before)) assert.deepEqual(later.commands, [], 'no SMTP command reached the peer');
  } finally {
    await sink.close();
  }
});

test('[NT-02] relay refusals, malformed replies, silence and a closed port fail closed without echoing reply text', async () => {
  const rejecting = await startSink({ rcptReply: '550 5.1.1 <recipient.two@alpha.test> mailbox unavailable' });
  const garbage = await startSink({ garbage: true });
  const silent = await startSink({ silent: true });
  try {
    await assert.rejects(smtpNotifier(rejecting.port).send(invitationRequest(newInvitation())), (error) => {
      isCode('delivery_failed')(error);
      assert.equal(error.smtpStatus, 550);
      assert.ok(!error.message.includes('alpha.test') && !error.message.includes('unavailable'), 'the reply text is not echoed');
      return true;
    });
    assert.ok(!rejecting.sessions[0].commands.includes('DATA'), 'no message after a refused recipient');
    await assert.rejects(smtpNotifier(garbage.port).send(invitationRequest(newInvitation())), isCode('delivery_failed'));

    const started = Date.now();
    const slow = createNotifier({
      transport: createSmtpTransport({ relay: { host: '127.0.0.1', port: silent.port, timeoutMs: 300 }, pilot: null }),
      from: FROM,
      publicOrigin: ORIGIN,
      logger: quietLogger(),
    });
    await assert.rejects(slow.send(invitationRequest(newInvitation())), isCode('delivery_failed'));
    assert.ok(Date.now() - started < 3000, 'the session deadline bounds a silent relay');

    await assert.rejects(smtpNotifier(await closedPort()).send(invitationRequest(newInvitation())), isCode('delivery_failed'));
  } finally {
    await Promise.all([rejecting.close(), garbage.close(), silent.close()]);
  }
});

test('[NT-03] without pilot configuration only .test, example.com and example.org recipients are accepted', async () => {
  const sink = await startSink();
  try {
    const notifier = smtpNotifier(sink.port);
    const refused = [
      'person@example.net',
      'person@pilot.example.net',
      'person@corp.invalid',
      'person@example.com.attacker.invalid',
      'person@notexample.com',
      'person@example.test.invalid',
      'person@mail.example',
    ];
    for (const to of refused) {
      await assert.rejects(notifier.send(invitationRequest(newInvitation(), { to })), isCode('recipient_domain_refused'), to);
      await assert.rejects(notifier.send(statusRequest({ to })), isCode('recipient_domain_refused'), `${to} (operator)`);
    }
    for (const to of ['person@test', 'person@localhost', 'person@[127.0.0.1]', '"quoted"@alpha.test']) {
      await assert.rejects(notifier.send(invitationRequest(newInvitation(), { to })), isCode('invalid_notification'), to);
    }
    assert.equal(sink.sessions.length, 0, 'no connection was opened for a refused recipient');

    const accepted = ['person@alpha.test', 'person@example.com', 'person@mail.example.org', 'Person@ALPHA.Test'];
    for (const to of accepted) await notifier.send(invitationRequest(newInvitation(), { to }));
    assert.deepEqual(
      sink.sessions.map((session) => session.commands[2]),
      ['RCPT TO:<person@alpha.test>', 'RCPT TO:<person@example.com>', 'RCPT TO:<person@mail.example.org>', 'RCPT TO:<Person@alpha.test>'],
    );

    // The adapter enforces the policy itself, even when called directly.
    const direct = createSmtpTransport({ relay: { host: '127.0.0.1', port: sink.port }, pilot: null });
    await assert.rejects(direct.deliver({ ...rawMessage('Subject: x\r\n\r\nbody\r\n'), to: 'person@example.net' }), isCode('recipient_domain_refused'));
    assert.equal(sink.sessions.length, accepted.length, 'the direct refusal opened no connection');

    // The development spool applies the same recipient policy.
    const dir = tempDir('domain-spool');
    const spool = createNotifier({ transport: createSpoolTransport({ dir }), from: FROM, publicOrigin: ORIGIN, logger: quietLogger() });
    await assert.rejects(spool.send(invitationRequest(newInvitation(), { to: 'person@example.net' })), isCode('recipient_domain_refused'));
    assert.deepEqual(readdirSync(dir), []);
  } finally {
    await sink.close();
  }
});

test('[NT-03] an explicit owner pilot configuration admits exactly the domains it names and nothing else', async () => {
  const sink = await startSink();
  const dir = tempDir('pilot');
  const write = (name, value, mode = 0o644) => {
    const path = join(dir, name);
    writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value), { mode });
    chmodSync(path, mode);
    return path;
  };
  const pilot = { schema: PILOT_SCHEMA, reference: 'synthetic owner authorization OA-0001', recipient_domains: ['pilot.example.net'] };
  const file = write('pilot.json', pilot);
  try {
    const env = { OPENSIG_MAIL_TRANSPORT: 'smtp', OPENSIG_SMTP_HOST: '127.0.0.1', OPENSIG_SMTP_PORT: String(sink.port), OPENSIG_PUBLIC_ORIGIN: ORIGIN };
    const { logger } = captureLogger();
    const notifier = createNotifierFromConfig(loadNotificationConfig({ ...env, OPENSIG_MAIL_PILOT_FILE: file }), { logger });
    await notifier.send(invitationRequest(newInvitation(), { to: 'recipient@pilot.example.net' }));
    assert.equal(sink.sessions[0].commands[2], 'RCPT TO:<recipient@pilot.example.net>');
    await notifier.send(invitationRequest(newInvitation(), { to: 'recipient@alpha.test' }));
    for (const to of ['recipient@other.example.net', 'recipient@sub.pilot.example.net', 'recipient@example.net']) {
      await assert.rejects(notifier.send(invitationRequest(newInvitation(), { to })), isCode('recipient_domain_refused'), to);
    }
    assert.equal(sink.sessions.length, 2);

    const invalid = [
      write('wildcard.json', { ...pilot, recipient_domains: ['*.example.net'] }),
      write('upper.json', { ...pilot, recipient_domains: ['Pilot.Example.NET'] }),
      write('single.json', { ...pilot, recipient_domains: ['net'] }),
      write('empty.json', { ...pilot, recipient_domains: [] }),
      write('extra.json', { ...pilot, allow_all: true }),
      write('schema.json', { ...pilot, schema: 'opensig.mail-pilot.v0' }),
      write('noref.json', { schema: PILOT_SCHEMA, recipient_domains: ['pilot.example.net'] }),
      write('syntax.json', '{"schema":'),
      write('writable.json', pilot, 0o664),
      join(dir, 'missing.json'),
      'pilot.json',
    ];
    const link = join(dir, 'link.json');
    symlinkSync(file, link);
    invalid.push(link);
    for (const path of invalid) {
      assert.throws(() => loadNotificationConfig({ ...env, OPENSIG_MAIL_PILOT_FILE: path }), isCode('config_invalid'), path);
    }

    // The pilot list widens recipient domains only; the relay stays loopback-only.
    assert.throws(
      () => loadNotificationConfig({ ...env, OPENSIG_SMTP_HOST: 'relay.pilot.example.net', OPENSIG_MAIL_PILOT_FILE: file }),
      isCode('relay_refused'),
    );
  } finally {
    await sink.close();
  }
});
