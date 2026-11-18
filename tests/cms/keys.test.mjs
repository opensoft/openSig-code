// SPDX-License-Identifier: Apache-2.0
//
// T013 file-backed development seal key adapter (plan.md § Case catalogs, CMS;
// A-010, request #39).
// KEY-01: the development seal key loads only from an owner-only regular file,
//   either given by absolute path (opened without following a final symbolic
//   link and without blocking) or through an inherited descriptor open on such
//   a file. An unencrypted RSA-3072 key with public exponent 65537 yields an
//   RSASSA-PKCS1-v1_5 SHA-256 signer. Loose modes, symbolic links, relative
//   paths, non-regular files (a FIFO, a pipe), missing, empty or oversized
//   files (over 16 KiB), other key types or sizes, encrypted keys and other
//   exponents are refused.
// KEY-02: key material is never taken from the environment, argv, a string, a
//   buffer or a key object, and loading refuses while PEM private-key text is
//   visible in the environment or argv. A refusal names a code, never a path
//   or key bytes.
// Keys are generated at run time in an owner-only scratch directory and removed
// afterwards.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { constants, generateKeyPairSync, randomBytes, verify } from 'node:crypto';
import { chmodSync, closeSync, constants as fsConstants, fstatSync, lstatSync, mkdirSync, openSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';

import { loadDevelopmentSealKey, MAX_KEY_FILE_BYTES, SealKeyError } from '../../src/cryptograph/keys/index.ts';
import { rsaPrivateKeyPem, withScratch, writePrivateFile } from './support.mjs';

function refusedWith(code, ...forbidden) {
  return (error) => {
    assert.ok(error instanceof SealKeyError, 'a SealKeyError');
    assert.equal(error.code, code);
    for (const text of forbidden) assert.ok(!error.message.includes(text), 'the message carries no path or key text');
    return true;
  };
}

const RSA_PKCS1 = { padding: constants.RSA_PKCS1_PADDING };

test('[KEY-01] an unencrypted RSA-3072 key with exponent 65537 in an owner-only file given by absolute path yields an RSASSA-PKCS1-v1_5 SHA-256 signer', async () => {
  await withScratch(async (dir) => {
    for (const mode of [0o600, 0o400]) {
      const keyPath = join(dir, `seal-key-${mode.toString(8)}.pem`);
      writePrivateFile(keyPath, rsaPrivateKeyPem(), mode);
      const signer = loadDevelopmentSealKey({ path: keyPath });
      assert.equal(signer.publicKey.type, 'public');
      assert.equal(signer.publicKey.asymmetricKeyType, 'rsa');
      assert.equal(signer.publicKey.asymmetricKeyDetails.modulusLength, 3072);
      assert.equal(signer.publicKey.asymmetricKeyDetails.publicExponent, 65537n);
      assert.equal('privateKey' in signer, false, 'the private key is not exposed');
      const data = Buffer.from('synthetic signed attributes (test only)');
      const first = signer.sign(data);
      assert.equal(first.length, 384);
      assert.ok(verify('sha256', data, { key: signer.publicKey, ...RSA_PKCS1 }, first), `mode ${mode.toString(8)}`);
      assert.ok(Buffer.from(signer.sign(data)).equals(Buffer.from(first)), 'PKCS#1 v1.5 signing is deterministic');
    }
  });
});

test('[KEY-01] an inherited descriptor open on an owner-only key file is accepted and left open; one on a loose file is refused', async () => {
  await withScratch(async (dir) => {
    const keyPath = join(dir, 'seal-key.pem');
    writePrivateFile(keyPath, rsaPrivateKeyPem());
    const fd = openSync(keyPath, 'r');
    try {
      const signer = loadDevelopmentSealKey({ fd });
      assert.equal(signer.publicKey.asymmetricKeyDetails.modulusLength, 3072);
      assert.ok(fstatSync(fd).isFile(), 'the caller still owns the open descriptor');
      chmodSync(keyPath, 0o640);
      assert.throws(() => loadDevelopmentSealKey({ fd }), refusedWith('mode-too-open', keyPath));
    } finally {
      closeSync(fd);
    }
    assert.throws(() => loadDevelopmentSealKey({ fd: -1 }), refusedWith('descriptor-invalid'));
    assert.throws(() => loadDevelopmentSealKey({ fd: 1.5 }), refusedWith('descriptor-invalid'));
  });
});

test('[KEY-01] loose modes, symbolic links, relative paths, non-regular files (a FIFO, a pipe), missing, empty and oversized files are refused', async () => {
  await withScratch(async (dir) => {
    const pem = rsaPrivateKeyPem();
    for (const mode of [0o640, 0o604, 0o644, 0o660, 0o606, 0o610, 0o601]) {
      const path = join(dir, `loose-${mode.toString(8)}.pem`);
      writePrivateFile(path, pem, mode);
      assert.throws(() => loadDevelopmentSealKey({ path }), refusedWith('mode-too-open', path), `mode ${mode.toString(8)}`);
    }
    const good = join(dir, 'good.pem');
    writePrivateFile(good, pem);
    const link = join(dir, 'link.pem');
    symlinkSync(good, link);
    assert.throws(() => loadDevelopmentSealKey({ path: link }), refusedWith('symlink-refused', link, good));
    assert.throws(() => loadDevelopmentSealKey({ path: 'good.pem' }), refusedWith('path-not-absolute'));
    assert.throws(() => loadDevelopmentSealKey({ path: '' }), refusedWith('path-not-absolute'));
    const folder = join(dir, 'folder');
    mkdirSync(folder, { mode: 0o700 });
    assert.throws(() => loadDevelopmentSealKey({ path: folder }), refusedWith('not-regular-file', folder));

    const fifo = join(dir, 'fifo.pem');
    assert.equal(spawnSync('mkfifo', ['-m', '600', fifo]).status, 0, 'premise: a FIFO exists at the key path');
    assert.ok(lstatSync(fifo).isFIFO(), 'premise: the path names a FIFO with no writer');
    const started = performance.now();
    assert.throws(() => loadDevelopmentSealKey({ path: fifo }), refusedWith('not-regular-file', fifo));
    assert.ok(performance.now() - started < 5_000, 'the FIFO is refused without blocking');
    const pipeFd = openSync(fifo, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK);
    try {
      assert.ok(fstatSync(pipeFd).isFIFO(), 'premise: the descriptor is a pipe');
      assert.throws(() => loadDevelopmentSealKey({ fd: pipeFd }), refusedWith('not-regular-file', fifo));
    } finally {
      closeSync(pipeFd);
    }

    const missing = join(dir, 'missing.pem');
    assert.throws(() => loadDevelopmentSealKey({ path: missing }), refusedWith('unopenable', missing));
    const empty = join(dir, 'empty.pem');
    writePrivateFile(empty, Buffer.alloc(0));
    assert.throws(() => loadDevelopmentSealKey({ path: empty }), refusedWith('size-out-of-bounds', empty));
    assert.equal(MAX_KEY_FILE_BYTES, 16 * 1024, 'the key file cap is 16 KiB');
    const large = join(dir, 'large.pem');
    writePrivateFile(large, Buffer.alloc(MAX_KEY_FILE_BYTES + 1, 0x41));
    assert.throws(() => loadDevelopmentSealKey({ path: large }), refusedWith('size-out-of-bounds', large));
    assert.ok(loadDevelopmentSealKey({ path: good }), 'positive control: the owner-only file itself loads');
  });
});

test('[KEY-01] other key types or sizes, other exponents, encrypted keys and non-key contents are refused', async () => {
  await withScratch(async (dir) => {
    const cases = [];
    cases.push(['rsa2048', rsaPrivateKeyPem(2048), 'wrong-modulus']);
    cases.push(['rsa4096', rsaPrivateKeyPem(4096), 'wrong-modulus']);
    cases.push(['exponent3', rsaPrivateKeyPem(3072, 3), 'wrong-exponent']);
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
    cases.push(['ec', ec, 'not-rsa']);
    const pss = generateKeyPairSync('rsa-pss', { modulusLength: 3072 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
    cases.push(['pss', pss, 'not-rsa']);
    const pass = randomBytes(16).toString('hex');
    const encrypted = generateKeyPairSync('rsa', { modulusLength: 3072 }).privateKey.export({
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: pass,
    });
    cases.push(['encrypted', encrypted, 'encrypted-key-refused']);
    cases.push(['garbage', Buffer.from('not a key (synthetic)\n'), 'key-unreadable']);
    for (const [name, contents, code] of cases) {
      const path = join(dir, `${name}.pem`);
      writePrivateFile(path, contents);
      assert.throws(() => loadDevelopmentSealKey({ path }), refusedWith(code, path, pass), name);
    }
  });
});

test('[KEY-02] key material is never taken from the environment, argv, a string, a buffer or a key object', async () => {
  await withScratch(async (dir) => {
    const pem = rsaPrivateKeyPem();
    const keyPath = join(dir, 'seal-key.pem');
    writePrivateFile(keyPath, pem);
    const keyObject = generateKeyPairSync('rsa', { modulusLength: 3072 }).privateKey;
    const sources = [
      pem,
      Buffer.from(pem),
      keyObject,
      { env: 'OPENSIG_TEST_SEAL_MATERIAL' },
      { argv: 2 },
      { pem },
      { path: keyPath, fd: 0 },
      { path: keyPath, env: 'OPENSIG_TEST_SEAL_MATERIAL' },
      null,
      undefined,
      [],
      [keyPath],
    ];
    for (const source of sources) assert.throws(() => loadDevelopmentSealKey(source), refusedWith('source-refused', pem, keyPath));
  });
});

test('[KEY-02] loading refuses while PEM private-key text is visible in the environment or argv, naming a code, never a path or key bytes', async () => {
  await withScratch(async (dir) => {
    const pem = rsaPrivateKeyPem();
    const keyPath = join(dir, 'seal-key.pem');
    writePrivateFile(keyPath, pem);
    const name = 'OPENSIG_TEST_SEAL_MATERIAL';
    assert.equal(process.env[name], undefined);
    process.env[name] = pem;
    try {
      assert.throws(() => loadDevelopmentSealKey({ path: keyPath }), refusedWith('key-material-in-environment', pem, name, keyPath));
    } finally {
      delete process.env[name];
    }
    process.argv.push(pem);
    try {
      assert.throws(() => loadDevelopmentSealKey({ path: keyPath }), refusedWith('key-material-in-argv', pem, keyPath));
    } finally {
      const at = process.argv.lastIndexOf(pem);
      if (at >= 0) process.argv.splice(at, 1);
    }
    assert.ok(loadDevelopmentSealKey({ path: keyPath }), 'positive control: with env and argv clean the same file loads');
  });
});
