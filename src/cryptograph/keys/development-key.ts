// SPDX-License-Identifier: Apache-2.0
//
// File-backed development seal key adapter (T013; research.md § Engine
// decision, key adapter; data-model.md § Keys and secrets).
//
// - The private key comes from a file by absolute path, or from an inherited
//   file descriptor, only. Any other source (a key object, a PEM string or
//   buffer, an environment variable or an argv entry) is refused, and the
//   adapter also refuses to load while PEM private-key material is visible in
//   this process's environment or argv (KEY-02).
// - The file must be a regular file owned by this process's user with no
//   group or other permission bits, for example 0600 or 0400 (request #30's
//   rule, as for the challenge key; request #39), and at most 16 KiB. An
//   inherited descriptor gets the same fstat checks (regular file, owner,
//   mode, size), so it must be open on the key file itself; a pipe, FIFO or
//   other non-regular descriptor is refused.
// - A path is opened with O_NOFOLLOW: a symbolic link as the last component is
//   refused rather than followed, so the configured path is the only path
//   whose custody is checked and a link cannot redirect the process to some
//   other file its user owns. Links in parent directories are still followed;
//   the key's directory must be writable only by the server user.
// - O_NONBLOCK keeps a FIFO or device swapped in at the path from blocking the
//   open; the fstat check then refuses it as not a regular file.
// - The key must be an unencrypted PEM RSA key with a 3072-bit modulus and
//   public exponent 65537 (no passphrase source exists, because a passphrase
//   would itself be a secret in env or argv). RSA-PSS and other key types,
//   sizes and exponents are refused (A-010, request #39).
// - Signing is RSASSA-PKCS1-v1_5 with SHA-256 through crypto.sign, which is
//   deterministic. The private KeyObject never leaves this module's closure.
// - Error messages carry a stable code and never a path, key bytes or a
//   value read from env or argv.
//
// Development only: production managed key custody is a separate release
// gate (`trusted-certificate-key-custody`), which would supply another
// SealSigner implementation.

import { constants as cryptoConstants, createPrivateKey, createPublicKey, sign, type KeyObject } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { isAbsolute } from 'node:path';

/** The modulus size and public exponent the seal profile requires (request #39). */
export const SEAL_KEY_MODULUS_BITS = 3072;
export const SEAL_KEY_PUBLIC_EXPONENT = 65537n;

/** Bounds on the key file (at most 16 KiB, request #39); an unencrypted 3072-bit PEM key is about 2.5 KB. */
export const MIN_KEY_FILE_BYTES = 1;
export const MAX_KEY_FILE_BYTES = 16 * 1024;

/** What the CMS builder needs from a key custodian. */
export interface SealSigner {
  /** The RSA-3072 public key matching the private key. */
  readonly publicKey: KeyObject;
  /** RSASSA-PKCS1-v1_5 with SHA-256 over `data`; the result is exactly 384 bytes. */
  sign(data: Uint8Array): Uint8Array;
}

/** Where the development seal key comes from: an absolute file path or an inherited file descriptor. */
export type SealKeySource = { readonly path: string } | { readonly fd: number };

export type SealKeyErrorCode =
  | 'source-refused'
  | 'key-material-in-environment'
  | 'key-material-in-argv'
  | 'path-not-absolute'
  | 'descriptor-invalid'
  | 'symlink-refused'
  | 'unopenable'
  | 'not-regular-file'
  | 'wrong-owner'
  | 'mode-too-open'
  | 'size-out-of-bounds'
  | 'changed-while-read'
  | 'encrypted-key-refused'
  | 'key-unreadable'
  | 'not-rsa'
  | 'wrong-modulus'
  | 'wrong-exponent';

export class SealKeyError extends Error {
  readonly code: SealKeyErrorCode;

  constructor(code: SealKeyErrorCode, message: string) {
    super(message);
    this.name = 'SealKeyError';
    this.code = code;
  }
}

// A PEM private-key header of any type. The pattern is assembled at run time so
// that this source file never holds the header text itself.
const DASHES = '-'.repeat(5);
const PRIVATE_KEY_PEM = new RegExp(`${DASHES}BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY${DASHES}`);

/** Refuse to proceed while private-key PEM text is visible in this process's environment or argv. */
export function refuseKeyMaterialInProcess(): void {
  for (const value of Object.values(process.env)) {
    if (typeof value === 'string' && PRIVATE_KEY_PEM.test(value)) {
      throw new SealKeyError('key-material-in-environment', 'private-key material is present in the process environment; keys are passed by file or descriptor only');
    }
  }
  for (const value of [...process.execArgv, ...process.argv]) {
    if (PRIVATE_KEY_PEM.test(value)) {
      throw new SealKeyError('key-material-in-argv', 'private-key material is present in the process arguments; keys are passed by file or descriptor only');
    }
  }
}

function checkSource(source: unknown): SealKeySource {
  const refused = new SealKeyError('source-refused', 'the seal key is passed by absolute file path or inherited file descriptor only');
  if (typeof source !== 'object' || source === null || Array.isArray(source) || ArrayBuffer.isView(source)) throw refused;
  if (Object.getPrototypeOf(source) !== Object.prototype) throw refused;
  const keys = Object.keys(source);
  if (keys.length !== 1 || (keys[0] !== 'path' && keys[0] !== 'fd')) throw refused;
  if (keys[0] === 'path') {
    const path = (source as { path: unknown }).path;
    if (typeof path !== 'string' || path.length === 0 || path.includes('\0') || !isAbsolute(path)) {
      throw new SealKeyError('path-not-absolute', 'the seal key path must be an absolute path');
    }
    return { path };
  }
  const fd = (source as { fd: unknown }).fd;
  if (typeof fd !== 'number' || !Number.isSafeInteger(fd) || fd < 0) {
    throw new SealKeyError('descriptor-invalid', 'the seal key descriptor must be a file descriptor number');
  }
  return { fd };
}

function readKeyFile(fd: number): Buffer {
  const stat = fstatSync(fd);
  if (!stat.isFile()) throw new SealKeyError('not-regular-file', 'the seal key must be a regular file');
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new SealKeyError('wrong-owner', 'the seal key file must be owned by the server user');
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new SealKeyError('mode-too-open', 'the seal key file must not be group- or other-accessible (mode 0600)');
  }
  if (stat.size < MIN_KEY_FILE_BYTES || stat.size > MAX_KEY_FILE_BYTES) {
    throw new SealKeyError('size-out-of-bounds', `the seal key file must hold ${MIN_KEY_FILE_BYTES} to ${MAX_KEY_FILE_BYTES} bytes`);
  }
  const bytes = Buffer.alloc(stat.size);
  let offset = 0;
  while (offset < bytes.length) {
    const read = readSync(fd, bytes, offset, bytes.length - offset, offset);
    if (read === 0) break;
    offset += read;
  }
  if (offset !== bytes.length) {
    bytes.fill(0);
    throw new SealKeyError('changed-while-read', 'the seal key file changed while it was read');
  }
  return bytes;
}

// An encrypted PEM key: the PKCS#8 "ENCRYPTED PRIVATE KEY" label, or a legacy
// "Proc-Type: 4,ENCRYPTED" header. Detected from the structure first, because
// the error crypto raises for a missing passphrase differs between Node and
// OpenSSL versions (Node 24.22.2 raises ERR_OSSL_CRYPTO_INTERRUPTED_OR_CANCELLED,
// not ERR_MISSING_PASSPHRASE); both codes are still mapped below. The buffer is
// searched in place, so no string copy of the key is made.
const ENCRYPTED_PEM_MARKERS = [Buffer.from(`${DASHES}BEGIN ENCRYPTED PRIVATE KEY${DASHES}`, 'latin1'), Buffer.from('Proc-Type: 4,ENCRYPTED', 'latin1')];
const PASSPHRASE_ERRORS = new Set(['ERR_MISSING_PASSPHRASE', 'ERR_OSSL_CRYPTO_INTERRUPTED_OR_CANCELLED']);

function privateKeyFrom(bytes: Buffer): KeyObject {
  const encryptedRefusal = new SealKeyError('encrypted-key-refused', 'an encrypted seal key is refused; no passphrase source is allowed');
  if (ENCRYPTED_PEM_MARKERS.some((marker) => bytes.includes(marker))) throw encryptedRefusal;
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: bytes, format: 'pem' });
  } catch (error) {
    if (PASSPHRASE_ERRORS.has(String((error as NodeJS.ErrnoException).code))) throw encryptedRefusal;
    throw new SealKeyError('key-unreadable', 'the seal key file does not hold a PEM private key');
  }
  if (key.asymmetricKeyType !== 'rsa') throw new SealKeyError('not-rsa', 'the seal key must be an RSA (PKCS#1 v1.5) key');
  if (key.asymmetricKeyDetails?.modulusLength !== SEAL_KEY_MODULUS_BITS) {
    throw new SealKeyError('wrong-modulus', `the seal key must have a ${SEAL_KEY_MODULUS_BITS}-bit modulus`);
  }
  if (key.asymmetricKeyDetails?.publicExponent !== SEAL_KEY_PUBLIC_EXPONENT) {
    throw new SealKeyError('wrong-exponent', `the seal key must have public exponent ${SEAL_KEY_PUBLIC_EXPONENT}`);
  }
  return key;
}

function signerFrom(privateKey: KeyObject): SealSigner {
  const publicKey = createPublicKey(privateKey);
  return Object.freeze({
    publicKey,
    sign(data: Uint8Array): Uint8Array {
      if (!(data instanceof Uint8Array)) throw new TypeError('the data to sign must be a Uint8Array');
      return sign('sha256', data, { key: privateKey, padding: cryptoConstants.RSA_PKCS1_PADDING });
    },
  });
}

/**
 * Load the development seal key from a 0600 file (absolute path, never
 * followed through a final symbolic link) or from an inherited descriptor,
 * which stays open and is read from offset 0. The caller owns that descriptor.
 */
export function loadDevelopmentSealKey(source: SealKeySource): SealSigner {
  refuseKeyMaterialInProcess();
  const checked = checkSource(source);
  let fd: number;
  let owned = false;
  if ('path' in checked) {
    try {
      fd = openSync(checked.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NOCTTY | constants.O_NONBLOCK);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ELOOP') {
        throw new SealKeyError('symlink-refused', 'the seal key path must not be a symbolic link');
      }
      throw new SealKeyError('unopenable', 'the seal key file cannot be opened');
    }
    owned = true;
  } else {
    fd = checked.fd;
  }
  let bytes: Buffer | undefined;
  try {
    try {
      bytes = readKeyFile(fd);
    } catch (error) {
      if (error instanceof SealKeyError) throw error;
      throw new SealKeyError('unopenable', 'the seal key cannot be read');
    }
    return signerFrom(privateKeyFrom(bytes));
  } finally {
    bytes?.fill(0);
    if (owned) closeSync(fd);
  }
}
