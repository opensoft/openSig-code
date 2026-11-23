// SPDX-License-Identifier: Apache-2.0
//
// WK-03: a crash, a non-zero exit, the timeout, a broken reply, an abort, a bad
// or mismatched key and a non-regular descriptor each give their reason and
// retryable flag, with no artifact and no secret in any message (plan.md § Case
// catalogs, WK; the T037 line, requests #39 Part F and #44). Crashes, the
// wall-time kill, broken replies and the mid-run abort come from a fault entry
// run through the worker's own launch (testing.ts); key failures and the
// public abort run the real child on a real descriptor.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { closeSync, constants, existsSync, openSync, writeSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { sealComposedPdf } from '../../src/cryptograph/worker/index.ts';
import { launchForTests, sealRequestForTests } from '../../src/cryptograph/worker/testing.ts';
import { assertSealError, composeSynthetic, EVIDENCE_DIGEST, keyPair, pemOf, selfSignedCertificate, withScratch, withSealKey } from './support.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FAULT = join(HERE, 'support', 'fault-child.mjs');
const pair = keyPair('seal');
const certificateDer = selfSignedCertificate(pair);
const composed = composeSynthetic(certificateDer);
const original = Buffer.from(composed.bytes);
const SHORT_WALL = { limits: { wallMs: 1500 } };

function faultRequest(mode) {
  const digest = Uint8Array.from(EVIDENCE_DIGEST);
  digest[0] = mode;
  return {
    document: composed.bytes,
    certificateDer,
    byteRange: composed.byteRange,
    contentsOffset: composed.contents.offset,
    contentsHexLength: composed.contents.hexLength,
    approvalEvidenceDigest: digest,
  };
}

async function expectRefusal(promise, expected, secrets) {
  await assert.rejects(promise, (error) => assertSealError(error, expected, secrets));
  assert.deepEqual(Buffer.from(composed.bytes), original, "no partial artifact: the caller's bytes are unchanged");
}

const sealWith = (fd, options) => sealComposedPdf({ composed, certificateDer, approvalEvidenceDigest: EVIDENCE_DIGEST, keyFd: fd }, options);

function assertGone(pid) {
  assert.throws(() => process.kill(pid, 0), (error) => error.code === 'ESRCH', 'the child no longer exists when the call settles');
}

test('[WK-03] a worker killed by a signal, or exiting non-zero after a well-formed refusal, is a retryable worker-crashed failure', async () => {
  await withSealKey(pair, async ({ fd, dir, pem }) => {
    await expectRefusal(sealRequestForTests(FAULT, faultRequest(1), fd), { reason: 'worker-crashed', retryable: true }, { pem, dir });
    await expectRefusal(sealRequestForTests(FAULT, faultRequest(2), fd), { reason: 'worker-crashed', retryable: true }, { pem, dir });
  });
});

test('[WK-03] a hung worker is killed at the wall-time limit, retryably, and is gone when the call settles', async () => {
  await withSealKey(pair, async ({ fd, dir, pem }) => {
    const started = performance.now();
    const outcome = await launchForTests(FAULT, faultRequest(3), fd, SHORT_WALL);
    assert.equal(outcome.timedOut, true, 'the wall-time limit fired');
    assert.equal(outcome.signal, 'SIGKILL', 'the child was SIGKILLed');
    assert.ok(performance.now() - started < 15_000, 'the kill came near the limit');
    assertGone(outcome.pid);
    await expectRefusal(sealRequestForTests(FAULT, faultRequest(3), fd, SHORT_WALL), { reason: 'worker-timeout', retryable: true }, { pem, dir });
  });
});

test('[WK-03] an oversized, truncated, inconsistent or unfilled reply is a retryable worker-protocol failure with no artifact', async () => {
  await withSealKey(pair, async ({ fd, dir, pem }) => {
    // 4 one byte more than a sealed reply may hold; 5 a change outside the
    // placeholder with a consistent digest; 6 a truncated reply; 7 a wrong
    // finalPdfDigest; 8 the placeholder left all zeros.
    for (const mode of [4, 5, 6, 7, 8]) {
      await expectRefusal(sealRequestForTests(FAULT, faultRequest(mode), fd), { reason: 'worker-protocol', retryable: true }, { pem, dir });
    }
  });
});

test('[WK-03] an abort kills the worker with SIGKILL, settles on close and gives the retryable reason aborted, with no artifact', async () => {
  await withSealKey(pair, async ({ fd, dir, pem }) => {
    // Before the call: no child starts.
    await expectRefusal(sealWith(fd, { signal: AbortSignal.abort() }), { reason: 'aborted', retryable: true }, { pem, dir });
    // Straight after the call, while the real child is running.
    const controller = new AbortController();
    const pending = sealWith(fd, { signal: controller.signal });
    controller.abort();
    await expectRefusal(pending, { reason: 'aborted', retryable: true }, { pem, dir });
    // A hung child aborted after it has started: SIGKILL, then settlement on close.
    const hung = new AbortController();
    const launched = launchForTests(FAULT, faultRequest(3), fd, { signal: hung.signal });
    await delay(300);
    hung.abort();
    const outcome = await launched;
    assert.equal(outcome.aborted, true);
    assert.equal(outcome.timedOut, false, 'the abort, not the timer, ended it');
    assert.equal(outcome.signal, 'SIGKILL');
    assertGone(outcome.pid);
    const again = new AbortController();
    const refused = sealRequestForTests(FAULT, faultRequest(3), fd, { signal: again.signal });
    await delay(300);
    again.abort();
    await expectRefusal(refused, { reason: 'aborted', retryable: true }, { pem, dir });
  });
  await assert.rejects(sealWith(3, { signal: AbortSignal.abort(), limits: { wallMs: 1 } }), (e) => e.reason === 'input-invalid' && e.retryable === false, 'the signal is the only option');
});

test('[WK-03] a key file with a group or other bit, an empty or oversized body, or no key in it is a retryable key failure', async () => {
  const cases = [
    [{ mode: 0o640 }, 'key-mode-too-open'],
    [{ mode: 0o604 }, 'key-mode-too-open'],
    [{ data: '' }, 'key-size-out-of-bounds'],
    [{ data: Buffer.alloc(16 * 1024 + 1, 0x41) }, 'key-size-out-of-bounds'],
    [{ data: 'synthetic text that is not a key\n' }, 'key-key-unreadable'],
  ];
  for (const [options, reason] of cases) {
    await withSealKey(pair, ({ fd, dir, pem }) => expectRefusal(sealWith(fd), { reason, retryable: true }, { pem, dir }), options);
  }
});

test("[WK-03] a FIFO holding the key, a directory or a device as the key descriptor is refused in the worker by T013's custody check", async () => {
  await withSealKey(pair, async ({ dir, pem }) => {
    const dirFd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY);
    try {
      await expectRefusal(sealWith(dirFd), { reason: 'key-not-regular-file', retryable: true }, { pem, dir });
    } finally {
      closeSync(dirFd);
    }
    const nullFd = openSync('/dev/null', constants.O_RDONLY);
    try {
      await expectRefusal(sealWith(nullFd), { reason: 'key-not-regular-file', retryable: true }, { pem, dir });
    } finally {
      closeSync(nullFd);
    }
  });
  // A pipe that really holds the key: a worker that skipped the custody check
  // would read it and seal. mkfifo runs as a hang-safe child with its own
  // timeout (request #44), and both FIFO ends open non-blocking.
  await withScratch(async (dir) => {
    const mkfifo = ['/usr/bin/mkfifo', '/bin/mkfifo'].find((path) => existsSync(path));
    assert.ok(mkfifo, 'premise: mkfifo is present at a fixed path');
    const fifo = join(dir, 'seal.key');
    const made = spawnSync(mkfifo, ['-m', '600', fifo], { env: {}, stdio: 'ignore', timeout: 10_000, killSignal: 'SIGKILL' });
    assert.equal(made.error, undefined, 'premise: mkfifo ran within its timeout');
    assert.equal(made.status, 0, 'premise: the FIFO exists');
    const pem = pemOf(pair);
    const readEnd = openSync(fifo, constants.O_RDONLY | constants.O_NONBLOCK);
    try {
      const writeEnd = openSync(fifo, constants.O_WRONLY | constants.O_NONBLOCK);
      writeSync(writeEnd, Buffer.from(pem, 'latin1'));
      closeSync(writeEnd);
      await expectRefusal(sealWith(readEnd), { reason: 'key-not-regular-file', retryable: true }, { pem, dir });
    } finally {
      closeSync(readEnd);
    }
  });
});

test('[WK-03] a key that does not match the certificate, or is not RSA-3072, is a retryable key failure', async () => {
  await withSealKey(keyPair('other'), ({ fd, dir, pem }) => expectRefusal(sealWith(fd), { reason: 'key-certificate-mismatch', retryable: true }, { pem, dir }));
  await withSealKey(keyPair('small', 2048), ({ fd, dir, pem }) => expectRefusal(sealWith(fd), { reason: 'key-wrong-modulus', retryable: true }, { pem, dir }));
});
