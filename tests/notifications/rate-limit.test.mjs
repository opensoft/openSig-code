// SPDX-License-Identifier: Apache-2.0
//
// NT-04: notifications are rate-limited per tenant. Over the limit a send is refused
// with a retry delay and nothing is delivered; other tenants are unaffected; refused
// requests consume no budget.

import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { after, test } from 'node:test';

import { createNotifier, createSpoolTransport, DEFAULT_TENANT_RATE_LIMIT, loadNotificationConfig } from '../../src/notifications/index.ts';
import {
  captureLogger,
  challengeRequest,
  cleanup,
  FROM,
  invitationRequest,
  isCode,
  makeClock,
  newCode,
  newInvitation,
  ORIGIN,
  statusRequest,
  tempDir,
  TENANT_A,
  TENANT_B,
} from './support.mjs';

after(cleanup);

function limited(limit, windowMs) {
  const dir = tempDir('rate');
  const clock = makeClock();
  const { logger, lines } = captureLogger();
  const notifier = createNotifier({
    transport: createSpoolTransport({ dir }),
    from: FROM,
    publicOrigin: ORIGIN,
    rateLimit: { limit, windowMs },
    now: clock.now,
    logger,
  });
  return { dir, clock, notifier, lines, files: () => readdirSync(dir).length };
}

test('[NT-04] a tenant over its limit is refused with a retry delay and nothing is delivered', async () => {
  const { clock, notifier, files } = limited(3, 60_000);
  // Every audience draws on the same tenant budget.
  await notifier.send(invitationRequest(newInvitation()));
  await notifier.send(challengeRequest(newCode()));
  clock.advance(10_000);
  await notifier.send(statusRequest({ audience: 'service' }));
  assert.equal(files(), 3);

  // The two oldest sends (t=0 s) leave the 60 s window at t=60 s; now is t=10 s.
  await assert.rejects(notifier.send(statusRequest()), (error) => isCode('rate_limited')(error) && error.retryAfterSeconds === 50);
  await assert.rejects(notifier.send(invitationRequest(newInvitation())), isCode('rate_limited'));
  assert.equal(files(), 3, 'a refused send writes nothing');

  await notifier.send(statusRequest({ tenant_id: TENANT_B }));
  assert.equal(files(), 4, 'another tenant keeps its own budget');

  clock.advance(30_000);
  await assert.rejects(notifier.send(statusRequest()), (error) => isCode('rate_limited')(error) && error.retryAfterSeconds === 20);
  clock.advance(20_000);
  await notifier.send(statusRequest());
  await notifier.send(statusRequest());
  assert.equal(files(), 6, 'the window slides: the two oldest sends expired');
  await assert.rejects(notifier.send(statusRequest()), (error) => isCode('rate_limited')(error) && error.retryAfterSeconds === 10);
  assert.equal(files(), 6);
});

test('[NT-04] refused requests take no budget, refusals are logged without content, and limits are configurable', async () => {
  const { notifier, files, lines } = limited(2, 60_000);
  for (let index = 0; index < 5; index += 1) {
    await assert.rejects(notifier.send(statusRequest({ to: `operator${index}@example.net` })), isCode('recipient_domain_refused'));
    await assert.rejects(notifier.send(statusRequest({ envelope_id: 'short' })), isCode('invalid_notification'));
  }
  await notifier.send(statusRequest());
  await notifier.send(statusRequest({ state: 'declined' }));
  await assert.rejects(notifier.send(statusRequest()), isCode('rate_limited'));
  assert.equal(files(), 2);
  const refusals = lines.map((line) => JSON.parse(line)).filter((record) => record.event === 'notification_refused');
  assert.equal(refusals.at(-1).reason, 'rate_limited');
  assert.equal(refusals.at(-1).tenant_id, TENANT_A);
  assert.equal(refusals.at(-1).retry_after_seconds, 60);
  assert.ok(!lines.join('\n').includes('example.net'), 'refused addresses are not logged');

  assert.deepEqual(loadNotificationConfig({}).rateLimit, DEFAULT_TENANT_RATE_LIMIT);
  assert.deepEqual(DEFAULT_TENANT_RATE_LIMIT, { limit: 100, windowMs: 600_000 });
  assert.deepEqual(loadNotificationConfig({ OPENSIG_MAIL_TENANT_LIMIT: '5', OPENSIG_MAIL_TENANT_WINDOW_SECONDS: '30' }).rateLimit, { limit: 5, windowMs: 30_000 });
  for (const [name, value] of [
    ['OPENSIG_MAIL_TENANT_LIMIT', '0'],
    ['OPENSIG_MAIL_TENANT_LIMIT', '100001'],
    ['OPENSIG_MAIL_TENANT_LIMIT', 'ten'],
    ['OPENSIG_MAIL_TENANT_WINDOW_SECONDS', '0'],
    ['OPENSIG_MAIL_TENANT_WINDOW_SECONDS', '86401'],
  ]) {
    assert.throws(() => loadNotificationConfig({ [name]: value }), isCode('config_invalid'), `${name}=${value}`);
  }
  assert.throws(
    () => createNotifier({ transport: createSpoolTransport({ dir: tempDir('rate-bad') }), from: FROM, publicOrigin: ORIGIN, rateLimit: { limit: 0, windowMs: 1000 } }),
    RangeError,
  );
});
