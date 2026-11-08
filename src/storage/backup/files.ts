// SPDX-License-Identifier: Apache-2.0
//
// File helpers for backup and restore: private (0600/0700) creation, durable
// atomic replacement, streamed copies and digests.

import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  renameSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';

import { StorageUsageError } from '../db/errors.ts';

const CHUNK = 1024 * 1024;

export function checkAbsolute(path: unknown, name: string): string {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0') || !isAbsolute(path)) {
    throw new StorageUsageError(`${name} must be an absolute path`);
  }
  return path;
}

export function syncDirectory(path: string): void {
  const fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function writeAll(fd: number, data: Uint8Array): void {
  let offset = 0;
  while (offset < data.byteLength) offset += writeSync(fd, data, offset, data.byteLength - offset);
}

/** Create `path` exclusively with mode 0600 and write `data`, fsynced. */
export function writePrivateFile(path: string, data: Uint8Array): void {
  const fd = openSync(path, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
  try {
    writeAll(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Replace `path` atomically: private temp file, fsync, rename, directory fsync. */
export function replaceFileAtomically(path: string, data: Uint8Array): void {
  const temp = join(dirname(path), `.${randomBytes(12).toString('hex')}.tmp`);
  try {
    writePrivateFile(temp, data);
    renameSync(temp, path);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
  syncDirectory(dirname(path));
}

/** Copy `source` to a new 0600 file at `target` (exclusive), fsynced. */
export function copyPrivateFile(source: string, target: string): void {
  const input = openSync(source, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const output = openSync(target, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, 0o600);
    try {
      const buffer = Buffer.alloc(CHUNK);
      for (;;) {
        const read = readSync(input, buffer, 0, CHUNK, null);
        if (read === 0) break;
        writeAll(output, buffer.subarray(0, read));
      }
      fsyncSync(output);
    } finally {
      closeSync(output);
    }
  } finally {
    closeSync(input);
  }
}

/** Streamed SHA-256 and size of a regular file (links refused). */
export function fileDigest(path: string): { readonly sha256: string; readonly bytes: number } {
  const fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(CHUNK);
    let bytes = 0;
    for (;;) {
      const read = readSync(fd, buffer, 0, CHUNK, null);
      if (read === 0) break;
      hash.update(buffer.subarray(0, read));
      bytes += read;
    }
    return { sha256: hash.digest('hex'), bytes };
  } finally {
    closeSync(fd);
  }
}

/** Create a new private directory, or accept an existing empty one. Returns true if created. */
export function prepareEmptyDirectory(path: string): boolean {
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (stat === undefined) {
    mkdirSync(path, { mode: 0o700 });
    syncDirectory(dirname(path));
    return true;
  }
  if (!stat.isDirectory()) throw new StorageUsageError(`${path} must be a directory, not a link or file`);
  if (readdirSync(path).length > 0) throw new StorageUsageError(`${path} must be empty`);
  return false;
}

export function removeQuietly(path: string): void {
  rmSync(path, { force: true, recursive: true });
}
