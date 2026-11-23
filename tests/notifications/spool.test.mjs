// SPDX-License-Identifier: Apache-2.0
//
// NT-01: the development file spool writes 0600 files in a 0700 directory under the
// gitignored var/spool/, refuses unsafe directories, returns no content to callers and
// offers no read path to any principal.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, readdirSync, readFileSync, rmdirSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { ROUTES } from '../../src/api/routes.ts';
import { createNotifier, createNotifierFromConfig, createSpoolTransport, loadNotificationConfig } from '../../src/notifications/index.ts';
import { cleanup, FROM, invitationRequest, isCode, newInvitation, ORIGIN, quietLogger, RECIPIENT, REPO, tempDir } from './support.mjs';

after(cleanup);

const notifierFor = (dir) => createNotifier({ transport: createSpoolTransport({ dir }), from: FROM, publicOrigin: ORIGIN, logger: quietLogger() });

test('[NT-01] the default spool is the gitignored var/spool and each message is a 0600 file in a 0700 directory', async () => {
  const config = loadNotificationConfig({ OPENSIG_PUBLIC_ORIGIN: ORIGIN });
  assert.equal(config.transport, 'spool');
  const spool = join(REPO, 'var', 'spool');
  assert.equal(config.spoolDir, spool);
  assert.equal(spawnSync('git', ['-C', REPO, 'check-ignore', '-q', 'var/spool/probe.eml']).status, 0, 'var/spool/ must be gitignored');

  const varDir = join(REPO, 'var');
  const createdVar = !existsSync(varDir);
  const createdSpool = !existsSync(spool);
  const before = new Set(createdSpool ? [] : readdirSync(spool));
  const written = [];
  try {
    const receipt = await createNotifierFromConfig(config, { logger: quietLogger() }).send(invitationRequest(newInvitation()));
    written.push(...readdirSync(spool).filter((name) => !before.has(name)));
    assert.equal(written.length, 1, 'exactly one new spool file');
    const [name] = written;
    assert.match(name, /^\d{8}T\d{6}Z-[0-9a-f]{32}\.eml$/);
    assert.ok(name.includes(receipt.message_id));
    assert.equal(statSync(join(spool, name)).mode & 0o777, 0o600, 'message file mode');
    const dirMode = statSync(spool).mode & 0o777;
    assert.equal(dirMode & 0o077, 0, 'no group or other access to the spool directory');
    if (createdSpool) assert.equal(dirMode, 0o700);
    const status = spawnSync('git', ['-C', REPO, 'status', '--porcelain', '--untracked-files=all', '--', 'var']);
    assert.equal(status.stdout.toString(), '', 'spooled mail is never visible to git');
    assert.match(readFileSync(join(spool, name), 'ascii'), /^Date: .*\r\nFrom: no-reply@opensig\.test\r\n/);
  } finally {
    for (const name of written) rmSync(join(spool, name), { force: true });
    try {
      if (createdSpool) rmdirSync(spool);
      if (createdVar) rmdirSync(varDir);
    } catch {
      // leave a non-empty directory alone
    }
  }
});

test('[NT-01] unsafe spool directories are refused and nothing is written', async () => {
  for (const mode of [0o750, 0o705, 0o777]) {
    const dir = tempDir('spool-mode');
    chmodSync(dir, mode);
    await assert.rejects(notifierFor(dir).send(invitationRequest(newInvitation())), isCode('spool_unsafe'));
    assert.deepEqual(readdirSync(dir), [], `mode ${mode.toString(8)} wrote nothing`);
  }

  const real = tempDir('spool-real');
  const link = join(tempDir('spool-link'), 'spool');
  symlinkSync(real, link);
  await assert.rejects(notifierFor(link).send(invitationRequest(newInvitation())), isCode('spool_unsafe'));
  assert.deepEqual(readdirSync(real), [], 'nothing written through a symlinked spool');

  const tracked = join(REPO, 'src', 'notifications-spool-probe');
  assert.throws(() => createSpoolTransport({ dir: tracked }), isCode('spool_unsafe'));
  assert.equal(existsSync(tracked), false, 'a spool inside the repository outside var/ is never created');
  assert.throws(() => createSpoolTransport({ dir: 'var/spool' }), isCode('config_invalid'));
  assert.throws(() => loadNotificationConfig({ OPENSIG_SPOOL_DIR: 'var/spool' }), isCode('config_invalid'));
  assert.throws(() => loadNotificationConfig({ OPENSIG_SMTP_HOST: '127.0.0.1' }), isCode('config_invalid'), 'SMTP settings without the smtp transport');
});

test('[NT-01] the caller receives status only and no principal-facing surface reads the spool', async () => {
  const dir = tempDir('spool-receipt');
  const notifier = notifierFor(dir);
  const invitation = newInvitation();
  const receipt = await notifier.send(invitationRequest(invitation));
  assert.deepEqual(Object.keys(receipt).sort(), ['message_id', 'status', 'transport']);
  assert.equal(receipt.status, 'accepted');
  assert.equal(receipt.transport, 'spool');
  assert.match(receipt.message_id, /^[0-9a-f]{32}$/);
  const shown = JSON.stringify(receipt);
  for (const hidden of [invitation, RECIPIENT, ORIGIN, '/sign', dir]) assert.ok(!shown.includes(hidden), 'the receipt carries no content, address or path');

  // Delivery-only interfaces: nothing that holds a notifier or transport can read mail back.
  assert.deepEqual(Object.keys(notifier).sort(), ['send', 'transport']);
  assert.deepEqual(Object.keys(createSpoolTransport({ dir })).sort(), ['deliver', 'name']);
  const spoolSource = readFileSync(join(REPO, 'src', 'notifications', 'spool.ts'), 'utf8');
  assert.doesNotMatch(spoolSource, /readFile|readdir|opendir|createReadStream|readSync|\.read\(/, 'the spool module never reads mail back');

  // No HTTP operation (and therefore no Hermes tool, which maps onto operations) exposes it.
  for (const route of ROUTES) {
    assert.doesNotMatch(`${route.operationId} ${route.path}`, /spool|mail|notif|outbox/i, `route ${route.operationId}`);
  }
});
