// SPDX-License-Identifier: Apache-2.0
//
// Development file spool (T032). Each message is one RFC 5322 file, `<UTC stamp>-<random
// id>.eml`, holding exactly the bytes an SMTP relay would receive. Rules:
//
// - The default directory is the gitignored `<repo>/var/spool/` (the dev launcher sets
//   OPENSIG_SPOOL_DIR to it). A spool inside the repository must stay under `var/`, so
//   mail can never land in a tracked path. A directory outside the repository is allowed
//   (tests use a mkdtemp directory).
// - The directory is created with mode 0700 and must be a real directory (not a symlink)
//   owned by the server's user with no group or other permission bits; otherwise every
//   delivery is refused (spool_unsafe). Service principals (Hermes runs under another
//   user or container) therefore cannot list or read it.
// - Files are created 0600 with O_CREAT|O_EXCL|O_NOFOLLOW under a temporary name, fsynced
//   and renamed into place, so a reader never sees a partial message.
// - The spool only writes. No openSig code path reads it back; local tooling reads the
//   files directly from the filesystem.

import { constants } from 'node:fs';
import { lstat, mkdir, open, rename, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { NotificationError } from './errors.ts';
import type { OutboundMessage, Transport } from './transport.ts';

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** `<root>/var/spool`, the gitignored development spool. */
export function defaultSpoolDir(root: string = REPO_ROOT): string {
  return join(root, 'var', 'spool');
}

function within(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function unsafe(message: string): NotificationError {
  return new NotificationError('spool_unsafe', `spool directory: ${message}`);
}

function stamp(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/[-:]/g, '');
}

export interface SpoolOptions {
  /** Absolute spool directory. */
  readonly dir: string;
  /** Repository root used for the location rule (default: this checkout). */
  readonly root?: string;
}

export function createSpoolTransport(options: SpoolOptions): Transport {
  const root = resolve(options.root ?? REPO_ROOT);
  if (typeof options.dir !== 'string' || !isAbsolute(options.dir)) {
    throw new NotificationError('config_invalid', 'the spool directory must be an absolute path');
  }
  const dir = resolve(options.dir);
  if (within(root, dir) && !within(join(root, 'var'), dir)) {
    throw unsafe('inside the repository it must be under the gitignored var/ directory');
  }

  const ensureDir = async (): Promise<void> => {
    try {
      await mkdir(dir, { recursive: true, mode: 0o700 });
    } catch {
      throw unsafe('it cannot be created');
    }
    const stat = await lstat(dir);
    if (!stat.isDirectory()) throw unsafe('it must be a directory, not a symlink or file');
    if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw unsafe('it must be owned by the server user');
    if ((stat.mode & 0o077) !== 0) throw unsafe('it must not grant group or other permissions (mode 0700)');
  };

  return Object.freeze({
    name: 'spool' as const,
    async deliver(message: OutboundMessage): Promise<void> {
      await ensureDir();
      if (!/^[0-9a-f]{32}$/.test(message.messageId)) throw new NotificationError('delivery_failed', 'the message id is malformed');
      const name = `${stamp(message.date)}-${message.messageId}.eml`;
      const finalPath = join(dir, name);
      const tempPath = join(dir, `.${name}.tmp`);
      try {
        const handle = await open(tempPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        try {
          await handle.writeFile(message.data);
          await handle.sync();
        } finally {
          await handle.close();
        }
        await rename(tempPath, finalPath);
      } catch (error) {
        await unlink(tempPath).catch(() => undefined);
        throw new NotificationError('delivery_failed', 'the spool could not store the message', { cause: error });
      }
      try {
        const handle = await open(dir, constants.O_RDONLY);
        try {
          await handle.sync();
        } finally {
          await handle.close();
        }
      } catch {
        // Directory fsync is best effort; the file itself is already durable.
      }
    },
  });
}
