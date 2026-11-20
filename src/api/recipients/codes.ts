// SPDX-License-Identifier: Apache-2.0
//
// Capability values of the recipient ceremony (T008; data-model.md § Entities,
// Invitation and Challenge; contracts/sessions-events-adapters.md § Recipient
// ceremony).
//
// - Invitation token: 256 random bits, base64url (43 characters). Mailed only,
//   in the URL fragment; the database keeps its SHA-256.
// - Challenge code: 10 characters of Crockford base32 (alphabet without I, L, O
//   and U), each drawn uniformly with crypto.randomInt, so 50 bits. The
//   database keeps only HMAC-SHA256(key, "opensig.challenge/1\n" + invitation
//   id + "\n" + challenge id + "\n" + code): binding both ids means a stored
//   HMAC verifies only for its own challenge. Codes are compared in constant
//   time.
// - The HMAC key is read once from a 0600 file, by path or inherited file
//   descriptor, and never from the environment or argv (data-model.md
//   § Authentication and secrets). The file must be a regular file owned by
//   the server's user with no group or other permission bits, at least 32
//   bytes long. The bytes become a KeyObject and the read buffer is zeroed.

import { createHmac, createSecretKey, randomBytes, randomInt, timingSafeEqual, type KeyObject } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { isAbsolute } from 'node:path';

export const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const CHALLENGE_CODE_LENGTH = 10;
/** A generated code: 10 Crockford base32 characters (the notifier checks the same shape). */
export const CHALLENGE_CODE_PATTERN = /^[0-9A-HJKMNP-TV-Z]{10}$/;
export const INVITATION_TOKEN_BYTES = 32;
export const MIN_CHALLENGE_KEY_BYTES = 32;
export const MAX_CHALLENGE_KEY_BYTES = 4096;
const HMAC_CONTEXT = 'opensig.challenge/1\n';
const HEX_DIGEST = /^[0-9a-f]{64}$/;

/** A fresh invitation token: 256 random bits, base64url. */
export function newInvitationToken(): string {
  return randomBytes(INVITATION_TOKEN_BYTES).toString('base64url');
}

/** A fresh challenge code: 10 uniformly drawn Crockford base32 characters (50 bits). */
export function newChallengeCode(): string {
  let code = '';
  for (let index = 0; index < CHALLENGE_CODE_LENGTH; index += 1) code += CROCKFORD_ALPHABET[randomInt(CROCKFORD_ALPHABET.length)];
  return code;
}

export class ChallengeKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ChallengeKeyError';
  }
}

/** Where the challenge-HMAC key comes from: an absolute file path or an inherited file descriptor. */
export type ChallengeKeySource = { readonly path: string } | { readonly fd: number };

export interface ChallengeKey {
  /** The stored form of `code` for this invitation and challenge (lowercase hex). */
  codeHmac(invitationId: string, challengeId: string, code: string): string;
  /** Constant-time check of a presented code against a stored HMAC. */
  verify(invitationId: string, challengeId: string, code: string, storedHmac: string): boolean;
}

function readKeyBytes(fd: number): Buffer {
  const stat = fstatSync(fd);
  if (!stat.isFile()) throw new ChallengeKeyError('the challenge key must be a regular file');
  if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
    throw new ChallengeKeyError('the challenge key file must be owned by the server user');
  }
  if ((stat.mode & 0o077) !== 0) throw new ChallengeKeyError('the challenge key file must not be group- or other-accessible (mode 0600)');
  if (stat.size < MIN_CHALLENGE_KEY_BYTES || stat.size > MAX_CHALLENGE_KEY_BYTES) {
    throw new ChallengeKeyError(`the challenge key must hold ${MIN_CHALLENGE_KEY_BYTES} to ${MAX_CHALLENGE_KEY_BYTES} bytes`);
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
    throw new ChallengeKeyError('the challenge key file changed while it was read');
  }
  return bytes;
}

function checkSource(source: unknown): ChallengeKeySource {
  if (typeof source !== 'object' || source === null || Array.isArray(source)) {
    throw new ChallengeKeyError('the challenge key is passed by file path or inherited file descriptor only');
  }
  const keys = Object.keys(source);
  if (keys.length !== 1 || (keys[0] !== 'path' && keys[0] !== 'fd')) {
    throw new ChallengeKeyError('the challenge key is passed by file path or inherited file descriptor only');
  }
  if ('path' in source) {
    const path = source.path;
    if (typeof path !== 'string' || path.length === 0 || path.includes('\0') || !isAbsolute(path)) {
      throw new ChallengeKeyError('the challenge key path must be an absolute path');
    }
    return { path };
  }
  const fd = (source as { fd: unknown }).fd;
  if (typeof fd !== 'number' || !Number.isSafeInteger(fd) || fd < 0) throw new ChallengeKeyError('the challenge key descriptor must be a file descriptor number');
  return { fd };
}

function message(invitationId: string, challengeId: string, code: string): string {
  return `${HMAC_CONTEXT}${invitationId}\n${challengeId}\n${code}`;
}

function keyFrom(key: KeyObject): ChallengeKey {
  const hmac = (invitationId: string, challengeId: string, code: string): Buffer =>
    createHmac('sha256', key).update(message(invitationId, challengeId, code), 'utf8').digest();
  return Object.freeze({
    codeHmac: (invitationId: string, challengeId: string, code: string): string => hmac(invitationId, challengeId, code).toString('hex'),
    verify(invitationId: string, challengeId: string, code: string, storedHmac: string): boolean {
      if (typeof code !== 'string' || typeof storedHmac !== 'string' || !HEX_DIGEST.test(storedHmac)) return false;
      return timingSafeEqual(hmac(invitationId, challengeId, code), Buffer.from(storedHmac, 'hex'));
    },
  });
}

/**
 * Load the challenge-HMAC key from a 0600 file (absolute path, never followed
 * through a symbolic link) or from an inherited file descriptor, which stays
 * open and is read from offset 0. Any other way of passing a key is refused.
 *
 * A path is opened with O_NONBLOCK too (A-010 KEY-FIFO, request #30): a FIFO
 * or a device swapped in at the path after the server's own lstat check then
 * opens at once instead of blocking startup, and the fstat check below refuses
 * it as not a regular file. O_NONBLOCK changes nothing for a regular file.
 */
export function loadChallengeKey(source: ChallengeKeySource): ChallengeKey {
  const checked = checkSource(source);
  let fd: number;
  let owned = false;
  if ('path' in checked) {
    try {
      fd = openSync(checked.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NOCTTY | constants.O_NONBLOCK);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ELOOP') throw new ChallengeKeyError('the challenge key path must not be a symbolic link');
      throw new ChallengeKeyError('the challenge key file cannot be opened');
    }
    owned = true;
  } else {
    fd = checked.fd;
  }
  let bytes: Buffer | undefined;
  try {
    try {
      bytes = readKeyBytes(fd);
    } catch (error) {
      if (error instanceof ChallengeKeyError) throw error;
      throw new ChallengeKeyError('the challenge key cannot be read');
    }
    return keyFrom(createSecretKey(bytes));
  } finally {
    bytes?.fill(0);
    if (owned) closeSync(fd);
  }
}
