// SPDX-License-Identifier: Apache-2.0
//
// T013 test support. It imports nothing from src/:
// - owner-only scratch directories (mkdtemp, mode 0700) removed in `finally`;
// - test-only RSA keys generated at run time with node:crypto and written at
//   mode 0600, and self-signed development certificates made by the OpenSSL
//   CLI from those keys (never committed; no fixture holds a key or a
//   certificate);
// - the OpenSSL CLI runner: a spawn error (CLI absent, timeout) fails the test,
//   it never passes; the runner's `openssl` probe gives CAPABILITY_ABSENT first;
// - a test-local DER walker and OID encodings computed independently of the
//   product encoder.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { chmodSync, closeSync, fchmodSync, lstatSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const OPENSSL_TIMEOUT_MS = 60_000;

/** Run `body(dir)` in a fresh owner-only directory, removed afterwards whatever happens. */
export async function withScratch(body) {
  const dir = mkdtempSync(join(tmpdir(), 'opensig-cms-'));
  try {
    chmodSync(dir, 0o700);
    assert.equal(lstatSync(dir).mode & 0o777, 0o700, 'the scratch directory is owner-only');
    return await body(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Create a new file at exactly `mode` (default 0600) holding `data`. */
export function writePrivateFile(path, data, mode = 0o600) {
  const fd = openSync(path, 'wx', 0o600);
  try {
    writeSync(fd, data);
    fchmodSync(fd, mode);
  } finally {
    closeSync(fd);
  }
}

/** A fresh test-only RSA private key, PKCS#8 PEM. */
export function rsaPrivateKeyPem(modulusLength = 3072, publicExponent = 0x10001) {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength, publicExponent });
  return privateKey.export({ type: 'pkcs8', format: 'pem' });
}

/** An `openssl req` configuration; `commentBytes` > 0 adds an nsComment that long, to make an oversized certificate. */
function reqConfig(commentBytes) {
  return [
    '[req]',
    'distinguished_name = dn',
    'prompt = no',
    'x509_extensions = ext',
    '',
    '[dn]',
    'CN = openSig Development Seal (test only)',
    'O = Example Test',
    '',
    '[ext]',
    'basicConstraints = critical, CA:true',
    'keyUsage = critical, digitalSignature, nonRepudiation, keyCertSign',
    'subjectKeyIdentifier = hash',
    ...(commentBytes > 0 ? [`nsComment = ${'c'.repeat(commentBytes)}`] : []),
    '',
  ].join('\n');
}

/** Run the OpenSSL CLI with a minimal environment. */
export function openssl(args) {
  const run = spawnSync('openssl', args, {
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '', LC_ALL: 'C' },
    timeout: OPENSSL_TIMEOUT_MS,
    maxBuffer: 16 * 1024 * 1024,
  });
  assert.ifError(run.error);
  return { status: run.status, stdout: run.stdout, stderr: run.stderr };
}

/**
 * A development seal fixture in `dir`: a 0600 key file holding a fresh key and
 * a self-signed certificate for it, made by `openssl req -x509`.
 */
export function devFixture(dir, { modulusLength = 3072, publicExponent = 0x10001, commentBytes = 0, name = 'seal', serial = '0x5eed0013' } = {}) {
  const keyPath = join(dir, `${name}-key.pem`);
  writePrivateFile(keyPath, rsaPrivateKeyPem(modulusLength, publicExponent));
  const configPath = join(dir, `${name}-req.cnf`);
  writeFileSync(configPath, reqConfig(commentBytes), { mode: 0o600 });
  const certPath = join(dir, `${name}-cert.pem`);
  const made = openssl(['req', '-new', '-x509', '-config', configPath, '-key', keyPath, '-sha256', '-days', '2', '-set_serial', serial, '-out', certPath]);
  assert.equal(made.status, 0, 'openssl req -x509 made the development certificate');
  const certDer = new Uint8Array(new X509Certificate(readFileSync(certPath)).raw);
  return { keyPath, certPath, certDer };
}

/** Synthetic detached content with CR, LF and every octet value, so `-binary` matters. */
export function syntheticContent() {
  const text = Buffer.from('%PDF-1.7\r\n% synthetic ByteRange content (test only)\n', 'latin1');
  const octets = Buffer.from(Array.from({ length: 256 }, (_, index) => index));
  return Buffer.concat([text, octets, text]);
}

export const sha256 = (data) => createHash('sha256').update(data).digest();
export const hex = (text) => Buffer.from(text.replace(/\s+/g, ''), 'hex');
export const toHex = (bytes) => Buffer.from(bytes).toString('hex');

/** A fixed approval-evidence digest: not printable and not parseable as DER, so asn1parse shows a hex dump. */
export const EVIDENCE_DIGEST = Uint8Array.from({ length: 32 }, (_, index) => (0xf0 + index) & 0xff);
export const EVIDENCE_OID_TEXT = '2.25.254263291653419018820250361524609646248';

/** OID TLVs, computed independently of src/cryptograph/cms/der.ts. */
export const OID_HEX = Object.freeze({
  data: '06092a864886f70d010701',
  signedData: '06092a864886f70d010702',
  contentType: '06092a864886f70d010903',
  messageDigest: '06092a864886f70d010904',
  signingTime: '06092a864886f70d010905',
  signingCertificateV2: '060b2a864886f70d010910022f',
  approvalEvidenceDigest: '06146982fec9aa89d68ec297b5b4ac8d91fcd2e1fd28',
  sha256: '0609608648016503040201',
  sha256WithRSAEncryption: '06092a864886f70d01010b',
});

// --- test-local DER walker ---------------------------------------------------

/** One TLV at `offset` (definite lengths only). */
export function tlvAt(bytes, offset, limit = bytes.length) {
  assert.ok(offset + 2 <= limit, 'a DER header fits inside its parent');
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    assert.ok(count >= 1 && count <= 4, 'a definite long-form length');
    length = 0;
    for (let index = 0; index < count; index += 1) length = length * 256 + bytes[offset + 2 + index];
    header += count;
  }
  const end = offset + header + length;
  assert.ok(end <= limit, 'a DER element lies inside its parent');
  return { tag, start: offset, body: offset + header, end };
}

/** The elements that exactly fill `element`'s content. */
export function kids(bytes, element) {
  const out = [];
  for (let offset = element.body; offset < element.end; ) {
    const child = tlvAt(bytes, offset, element.end);
    out.push(child);
    offset = child.end;
  }
  return out;
}

export const bytesOf = (bytes, element) => Buffer.from(bytes.subarray(element.start, element.end));
export const bodyOf = (bytes, element) => Buffer.from(bytes.subarray(element.body, element.end));

/** The issuer Name and serialNumber TLVs of a certificate, by the test-local walker. */
export function issuerAndSerial(certDer) {
  const certificate = tlvAt(certDer, 0);
  const [tbs] = kids(certDer, certificate);
  const fields = kids(certDer, tbs);
  const index = fields[0].tag === 0xa0 ? 1 : 0;
  return { serial: bytesOf(certDer, fields[index]), issuer: bytesOf(certDer, fields[index + 2]) };
}

// --- OpenSSL output -------------------------------------------------------------

/** `openssl asn1parse` lines as { offset, depth, length, form, type, value }. */
export function asn1parseLines(stdout) {
  return stdout
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => {
      const match = /^\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+)\s+(prim|cons):\s+(.*)$/.exec(line);
      assert.ok(match, 'every asn1parse line has the expected shape');
      const rest = match[6];
      const colon = rest.indexOf(':');
      return {
        offset: Number(match[1]),
        depth: Number(match[2]),
        length: Number(match[4]),
        form: match[5],
        type: (colon < 0 ? rest : rest.slice(0, colon)).trim(),
        value: colon < 0 ? '' : rest.slice(colon + 1).trim(),
      };
    });
}
