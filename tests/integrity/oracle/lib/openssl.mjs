// SPDX-License-Identifier: Apache-2.0
//
// OpenSSL CLI access for the T012 oracle. Every signature is made and checked
// by the `openssl` binary; this module never signs or verifies in-process.
// Runtime material lives in an owner-only mkdtemp directory (mode 0700,
// Addendum 1); private key files are 0600; the caller removes the directory
// in `finally`. Nothing here is ever written into the repository.
// Public (T014): createWorkDir, removeWorkDir.

import { spawnSync } from 'node:child_process';
import { chmodSync, closeSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const TIMEOUT_MS = 120_000;
const MAX_BUFFER = 64 * 1024 * 1024;

// Hermetic configuration: OPENSSL_CONF points here, so no host openssl.cnf
// setting changes the oracle's behaviour.
const CONFIG = [
  '# T012 integrity oracle: synthetic development configuration (runtime only)',
  '[ req ]',
  'distinguished_name = oracle_dn',
  '[ oracle_dn ]',
  'commonName = Common Name',
  '[ oracle_self_signed ]',
  'basicConstraints = critical, CA:FALSE',
  'keyUsage = critical, digitalSignature, nonRepudiation',
  'subjectKeyIdentifier = hash',
  '[ oracle_ca ]',
  'basicConstraints = critical, CA:TRUE, pathlen:0',
  'keyUsage = critical, keyCertSign, cRLSign',
  'subjectKeyIdentifier = hash',
  '[ oracle_leaf ]',
  'basicConstraints = critical, CA:FALSE',
  'keyUsage = critical, digitalSignature, nonRepudiation',
  'subjectKeyIdentifier = hash',
  'authorityKeyIdentifier = keyid:always',
  '',
].join('\n');

export function modeOf(path) {
  return statSync(path).mode & 0o777;
}

export function createWorkDir() {
  const dir = mkdtempSync(join(tmpdir(), 'opensig-oracle-'));
  chmodSync(dir, 0o700);
  const confPath = join(dir, 'oracle-openssl.cnf');
  writeFileSync(confPath, CONFIG, { mode: 0o600, flag: 'wx' });
  const env = { OPENSSL_CONF: confPath, LC_ALL: 'C' };
  for (const name of ['PATH', 'LD_LIBRARY_PATH', 'OPENSSL_MODULES']) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  return { dir, confPath, env, seq: 0 };
}

export function removeWorkDir(work) {
  rmSync(work.dir, { recursive: true, force: true });
}

function nextPath(work, stem) {
  work.seq += 1;
  return join(work.dir, `${String(work.seq).padStart(4, '0')}-${stem}`);
}

function writeRuntimeFile(work, stem, bytes) {
  const path = nextPath(work, stem);
  writeFileSync(path, bytes, { mode: 0o600, flag: 'wx' });
  return path;
}

function clip(buffer) {
  return Buffer.from(buffer ?? []).toString('latin1').trim().slice(0, 400);
}

function run(work, args, { allowFailure = false } = {}) {
  const r = spawnSync('openssl', args, {
    cwd: work.dir,
    env: work.env,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
  });
  if (r.error) throw new Error(`openssl ${args[0]} could not run: ${r.error.code ?? r.error.message}`);
  if (!allowFailure && r.status !== 0) {
    throw new Error(`openssl ${args[0]} exited ${r.status ?? r.signal}: ${clip(r.stderr)}`);
  }
  return { ok: r.status === 0, stdout: r.stdout, stderr: clip(r.stderr) };
}

export function opensslVersion(work) {
  return clip(run(work, ['version']).stdout);
}

/** A runtime RSA-3072 private key in a 0600 file (created owner-only first). */
export function generateRsaKey(work, label) {
  const path = nextPath(work, `${label}-private.pem`);
  closeSync(openSync(path, 'wx', 0o600));
  run(work, ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', path]);
  if (modeOf(path) !== 0o600) throw new Error(`private key file mode is ${modeOf(path).toString(8)}, expected 600`);
  return path;
}

export function selfSignedCertificate(work, { keyPath, label, subject, extensions, serial }) {
  const out = nextPath(work, `${label}-cert.pem`);
  run(work, ['req', '-new', '-x509', '-key', keyPath, '-sha256', '-days', '30', '-subj', subject,
    '-set_serial', serial, '-config', work.confPath, '-extensions', extensions, '-out', out]);
  return out;
}

export function issueCertificate(work, { keyPath, label, subject, caCertPath, caKeyPath, serial }) {
  const csr = nextPath(work, `${label}.csr`);
  run(work, ['req', '-new', '-key', keyPath, '-subj', subject, '-config', work.confPath, '-out', csr]);
  const out = nextPath(work, `${label}-cert.pem`);
  run(work, ['x509', '-req', '-in', csr, '-CA', caCertPath, '-CAkey', caKeyPath, '-set_serial', serial,
    '-days', '30', '-sha256', '-extfile', work.confPath, '-extensions', 'oracle_leaf', '-out', out]);
  return out;
}

/** Detached CMS SignedData (DER) over `content`, made by `openssl cms -sign`. */
export function cmsSignDetached(work, signer, content) {
  const input = writeRuntimeFile(work, 'signed-ranges.bin', content);
  const out = nextPath(work, 'signature.der');
  run(work, ['cms', '-sign', '-binary', '-in', input, '-signer', signer.certPath, '-inkey', signer.keyPath,
    '-md', 'sha256', '-nosmimecap', '-cades', '-outform', 'DER', '-out', out]);
  return readFileSync(out);
}

/**
 * `openssl cms -verify -binary -inform DER` of `der` over `content`.
 * anchors === null: integrity only (-noverify: signature and messageDigest,
 * no certificate path). anchors = [paths]: trust against exactly those
 * anchors, with the default CA file, directory and store disabled.
 */
export function cmsVerifyDetached(work, der, content, { anchors = null } = {}) {
  const derPath = writeRuntimeFile(work, 'verify.der', der);
  const contentPath = writeRuntimeFile(work, 'verify-content.bin', content);
  const out = nextPath(work, 'verify.out');
  const args = ['cms', '-verify', '-binary', '-inform', 'DER', '-in', derPath, '-content', contentPath, '-out', out];
  if (anchors === null) {
    args.push('-noverify');
  } else {
    if (anchors.length > 0) {
      const bundle = writeRuntimeFile(work, 'anchors.pem', Buffer.concat(anchors.map((p) => readFileSync(p))));
      args.push('-CAfile', bundle);
    } else {
      args.push('-no-CAfile');
    }
    args.push('-no-CApath', '-no-CAstore', '-purpose', 'any');
  }
  const r = run(work, args, { allowFailure: true });
  return { ok: r.ok, stderr: r.stderr };
}

/** RSA PKCS#1 v1.5 / SHA-256 signature of `bytes` (OC-09 splice only). */
export function dgstSign(work, signer, bytes) {
  const input = writeRuntimeFile(work, 'signed-attributes.der', bytes);
  const out = nextPath(work, 'attributes.sig');
  run(work, ['dgst', '-sha256', '-sign', signer.keyPath, '-out', out, input]);
  return readFileSync(out);
}
