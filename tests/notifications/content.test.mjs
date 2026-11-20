// SPDX-License-Identifier: Apache-2.0
//
// NT-05: content redaction. Recipient invitation mail carries the invitation only in the
// URL fragment of the one /sign link; challenge mail carries the code and no link;
// operator and service notifications never carry a link or a code; logs, errors and
// receipts carry no capability value, address or link.

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { createNotifier, createSpoolTransport, renderMessage } from '../../src/notifications/index.ts';
import { assertContent, composeNotification } from '../../src/notifications/content.ts';
import { parseAddress } from '../../src/notifications/policy.ts';
import {
  captureLogger,
  challengeRequest,
  cleanup,
  ENVELOPE_ID,
  FROM,
  invitationRequest,
  isCode,
  newCode,
  newInvitation,
  occurrences,
  ORIGIN,
  quietLogger,
  RECIPIENT,
  splitMessage,
  statusRequest,
  tempDir,
} from './support.mjs';

after(cleanup);

function spoolNotifier(options = {}) {
  const dir = tempDir('content');
  const notifier = createNotifier({
    transport: createSpoolTransport({ dir }),
    from: FROM,
    publicOrigin: ORIGIN,
    logger: options.logger ?? quietLogger(),
    ...(options.rateLimit ? { rateLimit: options.rateLimit } : {}),
  });
  const read = (receipt) => {
    const name = readdirSync(dir).find((file) => file.includes(receipt.message_id));
    return { name, text: readFileSync(join(dir, name), 'ascii') };
  };
  return { dir, notifier, read, count: () => readdirSync(dir).length };
}

const LINK = /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s]*/g;
const CODE_SHAPE = /(?<![A-Za-z0-9_-])[0-9A-HJKMNP-TV-Z]{10}(?![A-Za-z0-9_-])/;
const render = (composed) => renderMessage(composed, { from: parseAddress(FROM, 'from'), messageId: randomBytes(16).toString('hex'), date: new Date() });

test('[NT-05] recipient invitation mail carries the invitation only in the URL fragment of its one /sign link', async () => {
  const { notifier, read, count } = spoolNotifier();
  const invitation = newInvitation();
  const receipt = await notifier.send(invitationRequest(invitation));
  const { name, text } = read(receipt);
  const { head, body } = splitMessage(text);

  assert.equal(occurrences(text, invitation), 1, 'the invitation appears exactly once');
  assert.ok(!head.includes(invitation), 'never in a header, subject or Message-ID');
  assert.ok(!name.includes(invitation) && !JSON.stringify(receipt).includes(invitation));
  assert.deepEqual(body.match(LINK), [`${ORIGIN}/sign#i=${invitation}`], 'exactly one link');
  const url = new URL(body.match(LINK)[0]);
  assert.equal(url.origin, ORIGIN);
  assert.equal(url.pathname, '/sign');
  assert.equal(url.search, '', 'no query string');
  assert.equal(url.hash, `#i=${invitation}`, 'the invitation is the fragment, which browsers never send to a server');
  assert.match(head, /\r\nContent-Type: text\/plain; charset=us-ascii\r\n/);
  assert.match(head, /\r\nX-OpenSig-Notification: recipient_invitation(?:\r\n|$)/);

  // The caller can neither choose the origin nor add text, and the token must be a token.
  for (const extra of [{ origin: 'https://attacker.invalid' }, { link: 'https://attacker.invalid/sign' }, { note: 'click here' }]) {
    await assert.rejects(notifier.send(invitationRequest(newInvitation(), extra)), isCode('invalid_notification'));
  }
  for (const bad of [`${ORIGIN}/sign?i=x`, 'short', `${newInvitation()}#`, 42]) {
    await assert.rejects(notifier.send(invitationRequest(bad)), isCode('invalid_notification'));
  }
  assert.equal(count(), 1, 'refused requests wrote nothing');

  // The origin comes from configuration and is validated there.
  for (const origin of ['http://sign.alpha.test', `${ORIGIN}/path`, `${ORIGIN}/?i=x`, 'https://user@sign.alpha.test', 'ftp://sign.alpha.test']) {
    assert.throws(() => createNotifier({ transport: createSpoolTransport({ dir: tempDir() }), from: FROM, publicOrigin: origin }), isCode('config_invalid'), origin);
  }
  const unconfigured = createNotifier({ transport: createSpoolTransport({ dir: tempDir() }), from: FROM, publicOrigin: null, logger: quietLogger() });
  await assert.rejects(unconfigured.send(invitationRequest(newInvitation())), isCode('config_invalid'));
  const local = createNotifier({ transport: createSpoolTransport({ dir: tempDir() }), from: FROM, publicOrigin: 'http://127.0.0.1:8443', logger: quietLogger() });
  await local.send(invitationRequest(newInvitation()));

  // The guard itself rejects a template that would put the invitation anywhere else.
  const composed = composeNotification(invitationRequest(invitation), ORIGIN);
  const variants = [
    { ...composed, link: `${ORIGIN}/sign?i=${invitation}`, lines: composed.lines.map((line) => (line === composed.link ? `${ORIGIN}/sign?i=${invitation}` : line)) },
    { ...composed, lines: [...composed.lines, invitation] },
    { ...composed, subject: `Review ${invitation}` },
    { ...composed, lines: [...composed.lines, `${ORIGIN}/help`] },
  ];
  for (const variant of variants) assert.throws(() => assertContent(variant, render(variant)), isCode('content_refused'));
});

test('[NT-05] recipient challenge mail carries the code once in its body and no link', async () => {
  const { notifier, read, count } = spoolNotifier();
  const code = newCode();
  const { text } = read(await notifier.send(challengeRequest(code)));
  const { head, body } = splitMessage(text);
  assert.equal(occurrences(text, code), 1);
  assert.ok(!head.includes(code), 'never in a header or subject');
  assert.ok(body.includes(code));
  assert.equal(text.match(LINK), null, 'no link');
  assert.doesNotMatch(text, /https?:|\/sign|#i=|www\./i);
  for (const bad of ['ABCDEFGHIL', 'abcdefghjk', 'ABCDEFGHJ', 'ABCDEFGHJKM', `${ORIGIN}/x`]) {
    await assert.rejects(notifier.send(challengeRequest(bad)), isCode('invalid_notification'), bad);
  }
  await assert.rejects(notifier.send(challengeRequest(newCode(), { link: `${ORIGIN}/sign` })), isCode('invalid_notification'));
  assert.equal(count(), 1);
  const composed = composeNotification(challengeRequest(code), ORIGIN);
  const withLink = { ...composed, lines: [...composed.lines, `${ORIGIN}/sign`] };
  assert.throws(() => assertContent(withLink, render(withLink)), isCode('content_refused'));
});

test('[NT-05] operator and service notifications never carry a link or a code', async () => {
  const { notifier, read, count } = spoolNotifier();
  for (const audience of ['operator', 'service']) {
    for (const state of ['sent', 'completed', 'declined']) {
      const { text } = read(await notifier.send(statusRequest({ audience, state })));
      assert.ok(text.includes(ENVELOPE_ID) && text.includes(state));
      assert.equal(text.match(LINK), null, `${audience} ${state}: no link`);
      assert.doesNotMatch(text, /https?:|\/sign|#i=|www\.|mailto:/i);
      assert.doesNotMatch(splitMessage(text).body, CODE_SHAPE, `${audience} ${state}: no code`);
    }
  }
  assert.equal(count(), 6);

  // A recipient invitation and code mailed by this notifier...
  const invitation = newInvitation();
  const code = newCode();
  await notifier.send(invitationRequest(invitation));
  await notifier.send(challengeRequest(code));
  // ...can never reach operator or service mail, by any member.
  const attempts = [
    [{ link: `${ORIGIN}/sign#i=${invitation}` }, 'invalid_notification'],
    [{ code }, 'invalid_notification'],
    [{ invitation }, 'invalid_notification'],
    [{ envelope_id: `${ORIGIN}/sign` }, 'invalid_notification'],
    [{ envelope_id: code }, 'invalid_notification'],
    [{ state: `completed ${ORIGIN}` }, 'invalid_notification'],
    [{ envelope_version: 1_234_567_890 }, 'invalid_notification'],
    [{ audience: 'recipient' }, 'invalid_notification'],
    [{ envelope_id: invitation }, 'content_refused'],
    [{ envelope_id: `x${invitation}` }, 'content_refused'],
    [{ envelope_id: `env_${code}_x` }, 'content_refused'],
  ];
  for (const audience of ['operator', 'service']) {
    for (const [overrides, expected] of attempts) {
      await assert.rejects(notifier.send(statusRequest({ audience, ...overrides })), isCode(expected), `${audience} ${Object.keys(overrides)[0]}`);
    }
  }
  assert.equal(count(), 8, 'no refused notification was written');

  // The guard rejects an operator template that would carry a link or a code.
  const composed = composeNotification(statusRequest(), null);
  for (const line of [`See ${ORIGIN}/envelopes`, 'Visit www.alpha.test', `Code ${newCode()}`, 'Open /sign to continue']) {
    const variant = { ...composed, lines: [...composed.lines, line] };
    assert.throws(() => assertContent(variant, render(variant)), isCode('content_refused'), line);
  }
});

test('[NT-05] logs, errors and receipts carry no capability value, address or link', async () => {
  const { logger, lines } = captureLogger();
  const { notifier } = spoolNotifier({ logger, rateLimit: { limit: 3, windowMs: 60_000 } });
  const invitation = newInvitation();
  const code = newCode();
  const address = 'recipient.private@alpha.test';
  const outputs = [];
  outputs.push(await notifier.send(invitationRequest(invitation, { to: address })));
  outputs.push(await notifier.send(challengeRequest(code, { to: address })));
  outputs.push(await notifier.send(statusRequest({ to: 'operator.private@alpha.test' })));
  const refusals = [
    invitationRequest(newInvitation(), { to: 'recipient.private@example.net' }),
    challengeRequest(`${code.slice(0, 9)}I`, { to: address }),
    invitationRequest(invitation, { to: `${address}\r\nBcc: victim@alpha.test` }),
    statusRequest({ envelope_id: invitation }),
    invitationRequest(invitation, { to: address }),
  ];
  const codes = [];
  for (const request of refusals) {
    try {
      await notifier.send(request);
      assert.fail('the request must be refused');
    } catch (error) {
      codes.push(error.code);
      outputs.push({ message: error.message, ...error });
    }
  }
  assert.deepEqual(codes, ['recipient_domain_refused', 'invalid_notification', 'invalid_notification', 'content_refused', 'rate_limited']);

  const records = lines.map((line) => JSON.parse(line));
  assert.deepEqual(
    records.map((record) => record.event),
    ['notification_accepted', 'notification_accepted', 'notification_accepted', ...Array(5).fill('notification_refused')],
  );
  assert.equal(records[0].recipient_domain, 'alpha.test');
  const haystack = `${lines.join('\n')}\n${JSON.stringify(outputs)}`;
  for (const hidden of [invitation, code, 'recipient.private', 'operator.private', 'victim', 'example.net', ORIGIN, '/sign', '#i=', RECIPIENT]) {
    assert.ok(!haystack.includes(hidden), 'no capability value, address or link in logs, errors or receipts');
  }
});
