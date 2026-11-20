// SPDX-License-Identifier: Apache-2.0
//
// Shared support for the sealing-worker tests (T037, mode `cryptograph`).
//
// Test material without OpenSSL (the mode declares no capability):
// - RSA key pairs come from crypto.generateKeyPairSync, in memory, once per
//   test process.
// - The signer certificate is a synthetic self-signed X.509 certificate made
//   here: T013's exported DER encoder builds the TBSCertificate, crypto.sign
//   signs it, and crypto.X509Certificate must parse it and verify its signature
//   before it is used. Subject: CN=opensig-seal.example.test. Nothing is
//   written for the certificate; it is not secret.
// - The private key touches disk only as a 0600 file inside an owner-only
//   mkdtemp directory (0700) in the OS temp dir, outside the tree, removed in
//   `finally` (data-model.md § Authentication and secrets). It is opened as
//   T038 will open it (read-only, no final symlink, non-blocking) and passed by
//   descriptor. Nothing key-like is ever printed: assertion messages are fixed.
// - Composed documents are synthetic: a three-object base plus one appended
//   revision holding a /Sig dictionary in T036's layout (CP-05, request #44):
//   one object, direct values, the /ByteRange slot written by T036's own
//   byteRangeText (compose/index.ts item 6 names it for T037's synthetic /Sig;
//   it is imported here from compose.ts, which index.ts re-exports, so the test
//   process never loads the parse service), and a zero /Contents placeholder of
//   2 x signedDataLength(certificate) digits. They are not made by
//   composeSealRevision, which needs the parse sandbox this mode does not
//   declare. A zero-filled slot style is kept as a tolerance case.
// - The CMS reader below is independent of T013's reader.
// PEM markers are assembled at run time, so no source file holds one.

import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, verify, X509Certificate } from 'node:crypto';
import { chmodSync, closeSync, constants, existsSync, fchmodSync, lstatSync, mkdtempSync, openSync, rmSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';

import { concat, contextConstructed, derNull, integer, objectIdentifier, OID, sequence, setOf, signedDataLength, tlv } from '../../src/cryptograph/cms/index.ts';
import { BYTE_RANGE_WIDTH, byteRangeText as composerByteRangeText } from '../../src/cryptograph/compose/compose.ts';

export const DASHES = '-'.repeat(5);
export const PEM_MARK = `${DASHES}BEGIN`;
export const sha256 = (data) => createHash('sha256').update(data).digest();
export const sha256hex = (data) => createHash('sha256').update(data).digest('hex');
export const EVIDENCE_DIGEST = Uint8Array.from({ length: 32 }, (_, i) => (0xa0 + i) & 0xff);
export const EVIDENCE_OID = '2.25.254263291653419018820250361524609646248';

// ---------------------------------------------------------------- scratch

export async function withScratch(body) {
  const dir = mkdtempSync(join(tmpdir(), 'opensig-seal-'));
  try {
    chmodSync(dir, 0o700);
    assert.equal(lstatSync(dir).mode & 0o777, 0o700, 'the scratch directory is owner-only');
    return await body(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    assert.equal(existsSync(dir), false, 'the scratch directory is removed');
  }
}

/** Write `data` to a new file created 0600, then set `mode`. Returns the path. */
export function writeKeyFile(dir, data, { name = 'seal.key', mode = 0o600 } = {}) {
  const path = join(dir, name);
  const fd = openSync(path, 'wx', 0o600);
  try {
    writeSync(fd, typeof data === 'string' ? Buffer.from(data, 'latin1') : data);
    fchmodSync(fd, mode);
  } finally {
    closeSync(fd);
  }
  return path;
}

/** Open a key file as the runner does: read-only, no final symlink, no controlling tty, non-blocking. */
export function openKeyFd(path) {
  return openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NOCTTY | constants.O_NONBLOCK);
}

/** Run `body(fd)` with `path` opened as a key descriptor, closing it afterwards. */
export async function withKeyFd(path, body) {
  const fd = openKeyFd(path);
  try {
    return await body(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Run body({ fd, dir, pem }) with `pair`'s private key in a key file (0600
 * unless `mode` says otherwise) in a fresh owner-only directory, opened as a
 * descriptor; the descriptor is closed and the directory removed afterwards.
 */
export async function withSealKey(pair, body, { mode = 0o600, data } = {}) {
  const pem = pemOf(pair);
  return withScratch(async (dir) => {
    const path = writeKeyFile(dir, data ?? pem, { mode });
    return withKeyFd(path, (fd) => body({ fd, dir, pem }));
  });
}

// ---------------------------------------------------------------- keys and certificates

const pairs = new Map();

/** An RSA key pair held in memory, generated once per process per name. */
export function keyPair(name = 'seal', modulusLength = 3072) {
  const id = `${name}/${modulusLength}`;
  if (!pairs.has(id)) pairs.set(id, generateKeyPairSync('rsa', { modulusLength, publicExponent: 0x10001 }));
  return pairs.get(id);
}

/** The PKCS#8 PEM text of a private key, for writing into a key file only. */
export const pemOf = (pair) => pair.privateKey.export({ type: 'pkcs8', format: 'pem' });

const utf8Name = (commonName) => sequence(setOf([sequence(objectIdentifier('2.5.4.3'), tlv(0x0c, Buffer.from(commonName, 'utf8')))]));
const utcTime = (text) => tlv(0x17, Buffer.from(text, 'latin1'));

/** A synthetic self-signed v3 certificate (no extensions) for `pair`; parsed and verified before use. */
export function selfSignedCertificate(pair, { commonName = 'opensig-seal.example.test', serial = 0x5eed0037n } = {}) {
  const algorithm = sequence(objectIdentifier(OID.sha256WithRSAEncryption), derNull());
  const name = utf8Name(commonName);
  const spki = pair.publicKey.export({ type: 'spki', format: 'der' });
  const tbs = sequence(contextConstructed(0, integer(2)), integer(serial), algorithm, name, sequence(utcTime('260101000000Z'), utcTime('270101000000Z')), name, spki);
  const signature = sign('sha256', tbs, pair.privateKey);
  const der = sequence(tbs, algorithm, tlv(0x03, concat([Uint8Array.of(0), signature])));
  const x509 = new X509Certificate(Buffer.from(der));
  assert.equal(x509.verify(pair.publicKey), true, 'the synthetic certificate verifies under its own key');
  return Uint8Array.from(der);
}

// ---------------------------------------------------------------- synthetic composed documents

export const BYTE_RANGE_SLOT = BYTE_RANGE_WIDTH;

/** The slot text: T036's own format ('composer'), or ten-digit zero-filled numbers ('zeros'). */
export function byteRangeText([a, b, c, d], style = 'composer') {
  if (style === 'composer') return composerByteRangeText(b, c, d);
  const field = (n) => String(n).padStart(10, '0');
  return `[${a} ${field(b)} ${field(c)} ${field(d)}]`;
}

/**
 * A base plus one appended revision with an unfilled seal placeholder.
 * Returns { bytes, byteRange, contents: { offset, hexLength }, slotAt, style }.
 */
export function composeSynthetic(certificateDer, { hexLength = 2 * signedDataLength(certificateDer), style = 'composer' } = {}) {
  let text = '%PDF-1.7\n%âãÏÓ\n';
  const offsets = [];
  ['<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [3 0 R] /Count 1 >>', '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>'].forEach((body, i) => {
    offsets.push(text.length);
    text += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const baseXref = text.length;
  text += `xref\n0 4\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}`;
  text += `trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n${baseXref}\n%%EOF\n`;
  const sigOffset = text.length;
  const prefix = '4 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange ';
  const slotAt = sigOffset + prefix.length;
  text += `${prefix}${' '.repeat(BYTE_RANGE_SLOT)} /Contents <`;
  const o1 = text.length - 1;
  text += `${'0'.repeat(hexLength)}>`;
  const o2 = text.length;
  text += ' /M (D:20261118000000Z) /Reason (Organization seal. Synthetic test revision.) >>\nendobj\n';
  const revisionXref = text.length;
  text += `xref\n4 1\n${String(sigOffset).padStart(10, '0')} 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R /Prev ${baseXref} >>\nstartxref\n${revisionXref}\n%%EOF\n`;
  const bytes = Buffer.from(text, 'latin1');
  const byteRange = [0, o1, o2, bytes.length - o2];
  bytes.write(byteRangeText(byteRange, style), slotAt, 'latin1');
  return { bytes: Uint8Array.from(bytes), byteRange, contents: { offset: o1 + 1, hexLength }, slotAt, style };
}

/** A copy of `composed` whose bytes `edit(buffer)` has changed (geometry kept unless returned). */
export function edited(composed, edit) {
  const buffer = Buffer.from(composed.bytes);
  const overrides = edit(buffer) ?? {};
  return { ...composed, bytes: Uint8Array.from(buffer), ...overrides };
}

// ---------------------------------------------------------------- independent CMS reader

export function tlvAt(bytes, offset) {
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let body = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i += 1) length = length * 256 + bytes[body + i];
    body += count;
  }
  return { tag, start: offset, body, end: body + length };
}

export function kids(bytes, element) {
  const out = [];
  for (let at = element.body; at < element.end; ) {
    const child = tlvAt(bytes, at);
    out.push(child);
    at = child.end;
  }
  return out;
}

/** DER of an OBJECT IDENTIFIER, computed here (not by T013). */
export function oidDer(dotted) {
  const arcs = dotted.split('.').map((arc) => BigInt(arc));
  const values = [arcs[0] * 40n + arcs[1], ...arcs.slice(2)];
  const body = [];
  for (const value of values) {
    const groups = [];
    let v = value;
    do {
      groups.unshift(Number(v & 0x7fn));
      v >>= 7n;
    } while (v > 0n);
    groups.forEach((g, i) => body.push(i < groups.length - 1 ? g | 0x80 : g));
  }
  return Buffer.from([0x06, body.length, ...body]);
}

/** The CMS hex in the placeholder of `sealed`, decoded. */
export function extractCms(sealed, contents) {
  return Buffer.from(Buffer.from(sealed.subarray(contents.offset, contents.offset + contents.hexLength)).toString('latin1'), 'hex');
}

/** { attributes: Map(oid DER hex -> value TLV bytes), signedAttrsSet, signature } of a one-signer SignedData. */
export function readSignerInfo(cms) {
  const bytes = Buffer.from(cms);
  const [, explicit] = kids(bytes, tlvAt(bytes, 0));
  const [signedData] = kids(bytes, explicit);
  const fields = kids(bytes, signedData);
  const [signerInfo] = kids(bytes, fields.at(-1));
  const parts = kids(bytes, signerInfo);
  const attrs = parts.find((p) => p.tag === 0xa0);
  const signature = parts.at(-1);
  const attributes = new Map();
  for (const attribute of kids(bytes, attrs)) {
    const [type, values] = kids(bytes, attribute);
    const [value] = kids(bytes, values);
    attributes.set(bytes.subarray(type.start, type.end).toString('hex'), bytes.subarray(value.start, value.end));
  }
  const signedAttrsSet = Buffer.concat([Buffer.from([0x31]), bytes.subarray(attrs.start + 1, attrs.end)]);
  return { attributes, signedAttrsSet, signature: bytes.subarray(signature.body, signature.end) };
}

/** The OCTET STRING content of the attribute `dotted`, or undefined. */
export function octetAttribute(cms, dotted) {
  const value = readSignerInfo(cms).attributes.get(oidDer(dotted).toString('hex'));
  if (value === undefined) return undefined;
  assert.equal(value[0], 0x04, 'the attribute value is an OCTET STRING');
  return value.subarray(tlvAt(value, 0).body);
}

export function signatureVerifies(cms, pair) {
  const { signedAttrsSet, signature } = readSignerInfo(cms);
  return verify('sha256', signedAttrsSet, pair.publicKey, signature);
}

// ---------------------------------------------------------------- secrets

/** Assert that nothing reachable from `error` carries key material or the key's location. */
export function assertNoSecret(error, { pem, dir }) {
  const body = pem.split('\n').filter((line) => line.length > 0 && !line.startsWith(DASHES)).join('');
  const fragments = [body.slice(0, 32), body.slice(body.length >> 1, (body.length >> 1) + 32), body.slice(-32)];
  const text = [error?.message, error?.reason, error?.code, String(error?.stack), JSON.stringify(error ?? null), inspect(error, { depth: 5 })].join('\n');
  assert.equal(text.includes(PEM_MARK), false, 'no PEM marker in the error');
  assert.equal(fragments.some((fragment) => text.includes(fragment)), false, 'no key text in the error');
  assert.equal(text.includes(dir), false, 'no key directory in the error');
  assert.equal(text.includes('seal.key'), false, 'no key file name in the error');
  assert.equal(error?.cause, undefined, 'the error carries no cause');
}

/** Assert a SealError with `reason` and `retryable`, and no secret. */
export function assertSealError(error, { reason, retryable }, secrets) {
  assert.equal(error?.name, 'SealError', 'a SealError');
  assert.equal(error.code, 'seal_failed');
  assert.equal(error.reason, reason);
  assert.equal(error.retryable, retryable);
  assert.ok(`${error.code}:${error.reason}`.length <= 60, 'fits last_error_code');
  if (secrets) assertNoSecret(error, secrets);
  return true;
}
