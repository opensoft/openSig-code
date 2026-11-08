// SPDX-License-Identifier: Apache-2.0
//
// Immutable, tenant-namespaced, content-addressed blob store on the local
// filesystem, behind the BlobStore object-store interface.
//
// Layout under the root directory:
//   tenants/<tenant_id>/sha256/<digest>   published blobs, mode 0400
//   tenants/<tenant_id>/tmp/<random>.partial   in-progress writes
//
// Write: the bytes go to a new temp file in the tenant's tmp directory, which
// is fsynced, made read-only and closed. The temp file is then published
// under its digest by link(2), which is atomic and never replaces an existing
// entry (Node has no rename(2) with RENAME_NOREPLACE, so this is the
// no-overwrite form of the rename step). The sha256 directory is fsynced and
// the temp name is removed. A crash before publication leaves only a .partial
// file, never a visible blob.
//
// No overwrite: when a blob already exists, a write verifies the existing
// bytes and returns created=false; a corrupt existing blob is reported, never
// replaced. Reads hash the whole content and refuse a mismatch. There is no
// cross-tenant deduplication: equal bytes in two tenants are two files.
// dispose() is the only removal, for retention; nothing is changed in place.

import { createHash, randomBytes } from 'node:crypto';
import { constants as fsConstants, type Stats } from 'node:fs';
import { isAbsolute, join } from 'node:path';

import { StorageUsageError } from '../db/errors.ts';
import { BlobDigestMismatchError, BlobIntegrityError, BlobNotFoundError, BlobTooLargeError } from './errors.ts';
import { nodeFsOps, type FsOps } from './fs-ops.ts';
import { blobRef, checkDigest, checkTenantId, DIGEST_PATTERN, parseBlobRef } from './refs.ts';

export const DEFAULT_MAX_BLOB_BYTES = 64 * 1024 * 1024;
export const MAX_BLOB_BYTES_LIMIT = 1024 * 1024 * 1024;

const BLOB_MODE = 0o400;
const TEMP_MODE = 0o600;
const DIRECTORY_MODE = 0o700;
const PARTIAL_NAME = /^[0-9a-f]{32}\.partial$/;

export interface BlobStoreOptions {
  /** Absolute path of an existing directory that holds the store. */
  readonly root: string;
  /** Largest blob accepted or read, in bytes (default 64 MiB, at most 1 GiB). */
  readonly maxBytes?: number;
  /** Filesystem operations (default node:fs); a seam for tests. */
  readonly fsOps?: FsOps;
}

export interface PutOptions {
  /** When given, the write is refused unless the bytes hash to this digest. */
  readonly expectedDigest?: string;
}

export interface PutResult {
  readonly ref: string;
  readonly tenantId: string;
  readonly digest: string;
  readonly size: number;
  /** False when the tenant already held this blob; nothing was rewritten. */
  readonly created: boolean;
}

export type BlobStatus = 'ok' | 'missing' | 'corrupt';

export interface BlobStore {
  put(tenantId: string, bytes: Uint8Array, options?: PutOptions): PutResult;
  putStream(tenantId: string, source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>, options?: PutOptions): Promise<PutResult>;
  read(tenantId: string, digest: string): Buffer;
  readRef(tenantId: string, ref: string): Buffer;
  check(tenantId: string, digest: string): BlobStatus;
  list(tenantId: string): string[];
  dispose(tenantId: string, digest: string): boolean;
  sweepPartials(tenantId: string): number;
}

type Inspection =
  | { readonly status: 'missing' }
  | { readonly status: 'corrupt'; readonly reason: string }
  | { readonly status: 'ok'; readonly size: number; readonly bytes: Buffer };

function errorCode(error: unknown): string | undefined {
  return typeof error === 'object' && error !== null ? (error as NodeJS.ErrnoException).code : undefined;
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export class FileBlobStore implements BlobStore {
  readonly root: string;
  readonly maxBytes: number;
  readonly #fs: FsOps;

  /** Internal: use openBlobStore(). */
  constructor(root: string, maxBytes: number, fsOps: FsOps) {
    this.root = root;
    this.maxBytes = maxBytes;
    this.#fs = fsOps;
    this.#ensureDirectory(join(root, 'tenants'), root);
  }

  #tenantDir(tenantId: string): string {
    return join(this.root, 'tenants', tenantId);
  }

  #blobDir(tenantId: string): string {
    return join(this.#tenantDir(tenantId), 'sha256');
  }

  #tmpDir(tenantId: string): string {
    return join(this.#tenantDir(tenantId), 'tmp');
  }

  /** 'missing' or 'directory'; anything else (a link, a file) is refused. */
  #directoryState(path: string): 'missing' | 'directory' {
    const stat = this.#fs.lstat(path);
    if (stat === undefined) return 'missing';
    if (!stat.isDirectory()) throw new BlobIntegrityError(`blob store path is not a directory: ${path}`);
    return 'directory';
  }

  #syncDirectory(path: string): void {
    const fd = this.#fs.open(path, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
    try {
      this.#fs.fsync(fd);
    } finally {
      this.#fs.close(fd);
    }
  }

  /** Create a directory (mode 0700) if absent, fsyncing its parent when created. */
  #ensureDirectory(path: string, parent: string): void {
    if (this.#directoryState(path) === 'directory') return;
    try {
      this.#fs.mkdir(path, DIRECTORY_MODE);
    } catch (error) {
      if (errorCode(error) !== 'EEXIST') throw error;
    }
    this.#directoryState(path);
    this.#syncDirectory(parent);
  }

  #ensureTenant(tenantId: string): void {
    const tenants = join(this.root, 'tenants');
    this.#ensureDirectory(tenants, this.root);
    this.#ensureDirectory(this.#tenantDir(tenantId), tenants);
    this.#ensureDirectory(this.#blobDir(tenantId), this.#tenantDir(tenantId));
    this.#ensureDirectory(this.#tmpDir(tenantId), this.#tenantDir(tenantId));
  }

  /** Read and hash the entry at `path` without following links. */
  #inspect(path: string, digest: string): Inspection {
    let fd: number;
    try {
      // O_NONBLOCK: a FIFO planted at a blob path must not block the reader.
      fd = this.#fs.open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    } catch (error) {
      const code = errorCode(error);
      if (code === 'ENOENT') return { status: 'missing' };
      if (code === 'ELOOP') return { status: 'corrupt', reason: 'the entry is a symbolic link' };
      throw error;
    }
    try {
      const stat: Stats = this.#fs.fstat(fd);
      if (!stat.isFile()) return { status: 'corrupt', reason: 'the entry is not a regular file' };
      if (stat.size > this.maxBytes) return { status: 'corrupt', reason: 'the entry exceeds the size limit' };
      const bytes = Buffer.alloc(stat.size);
      let filled = 0;
      while (filled < bytes.byteLength) {
        const read = this.#fs.read(fd, bytes.subarray(filled), filled);
        if (read === 0) break;
        filled += read;
      }
      if (filled !== stat.size || this.#fs.read(fd, Buffer.alloc(1), filled) !== 0) {
        return { status: 'corrupt', reason: 'the entry changed size while being read' };
      }
      if (sha256(bytes) !== digest) return { status: 'corrupt', reason: 'the content does not match its digest' };
      return { status: 'ok', size: stat.size, bytes };
    } finally {
      this.#fs.close(fd);
    }
  }

  /** Create a new temp file (mode 0600, exclusive, no links) in the tenant's tmp directory. */
  #openTemp(tenantId: string): { readonly temp: string; readonly fd: number } {
    this.#ensureTenant(tenantId);
    const temp = join(this.#tmpDir(tenantId), `${randomBytes(16).toString('hex')}.partial`);
    const fd = this.#fs.open(
      temp,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      TEMP_MODE,
    );
    return { temp, fd };
  }

  /** fsync the written temp file, make it read-only and close it. */
  #completeTemp(temp: string, fd: number): void {
    try {
      this.#fs.fsync(fd);
      this.#fs.fchmod(fd, BLOB_MODE);
    } catch (error) {
      this.#abandonTemp(temp, fd);
      throw error;
    }
    try {
      this.#fs.close(fd);
    } catch (error) {
      this.#removeQuietly(temp);
      throw error;
    }
  }

  /** Close (best effort) and remove an unfinished temp file. */
  #abandonTemp(temp: string, fd: number): void {
    try {
      this.#fs.close(fd);
    } catch {
      // The write error that led here is the one to report.
    }
    this.#removeQuietly(temp);
  }

  #removeQuietly(path: string): void {
    try {
      this.#fs.unlink(path);
    } catch (error) {
      if (errorCode(error) !== 'ENOENT') throw error;
    }
  }

  /** Publish a synced temp file under its digest without replacing anything. */
  #publish(tenantId: string, temp: string, digest: string, size: number): PutResult {
    const target = join(this.#blobDir(tenantId), digest);
    const ref = blobRef(tenantId, digest);
    try {
      let created = true;
      try {
        this.#fs.link(temp, target);
      } catch (error) {
        if (errorCode(error) !== 'EEXIST') throw error;
        created = false;
      }
      if (created) {
        this.#syncDirectory(this.#blobDir(tenantId));
      } else {
        const existing = this.#inspect(target, digest);
        if (existing.status !== 'ok') {
          throw new BlobIntegrityError(
            `existing blob ${ref} is ${existing.status === 'corrupt' ? `corrupt (${existing.reason})` : 'unreadable'}; it is never overwritten`,
          );
        }
      }
      return { ref, tenantId, digest, size, created };
    } finally {
      this.#removeQuietly(temp);
    }
  }

  #checkExpected(digest: string, options: PutOptions | undefined): void {
    if (options?.expectedDigest === undefined) return;
    const expected = checkDigest(options.expectedDigest);
    if (expected !== digest) {
      throw new BlobDigestMismatchError(`the bytes hash to ${digest}, not the expected ${expected}`);
    }
  }

  /** Store `bytes` under the tenant's namespace; returns created=false if already present. */
  put(tenantId: string, bytes: Uint8Array, options?: PutOptions): PutResult {
    checkTenantId(tenantId);
    if (!(bytes instanceof Uint8Array)) throw new StorageUsageError('blob content must be a Uint8Array');
    if (bytes.byteLength > this.maxBytes) {
      throw new BlobTooLargeError(`blob of ${bytes.byteLength} bytes exceeds the ${this.maxBytes}-byte limit`);
    }
    const digest = sha256(bytes);
    this.#checkExpected(digest, options);
    const { temp, fd } = this.#openTemp(tenantId);
    try {
      this.#fs.writeAll(fd, bytes);
    } catch (error) {
      this.#abandonTemp(temp, fd);
      throw error;
    }
    this.#completeTemp(temp, fd);
    return this.#publish(tenantId, temp, digest, bytes.byteLength);
  }

  /** Stream content into the store, hashing as it is written; enforces maxBytes. */
  async putStream(
    tenantId: string,
    source: AsyncIterable<Uint8Array> | Iterable<Uint8Array>,
    options?: PutOptions,
  ): Promise<PutResult> {
    checkTenantId(tenantId);
    if (options?.expectedDigest !== undefined) checkDigest(options.expectedDigest);
    const hash = createHash('sha256');
    let size = 0;
    const { temp, fd } = this.#openTemp(tenantId);
    try {
      for await (const chunk of source) {
        if (!(chunk instanceof Uint8Array)) throw new StorageUsageError('blob stream chunks must be Uint8Array');
        size += chunk.byteLength;
        if (size > this.maxBytes) throw new BlobTooLargeError(`blob stream exceeds the ${this.maxBytes}-byte limit`);
        hash.update(chunk);
        this.#fs.writeAll(fd, chunk);
      }
    } catch (error) {
      this.#abandonTemp(temp, fd);
      throw error;
    }
    this.#completeTemp(temp, fd);
    const digest = hash.digest('hex');
    try {
      this.#checkExpected(digest, options);
    } catch (error) {
      this.#removeQuietly(temp);
      throw error;
    }
    return this.#publish(tenantId, temp, digest, size);
  }

  /** The verified bytes of a blob. */
  read(tenantId: string, digest: string): Buffer {
    checkTenantId(tenantId);
    checkDigest(digest);
    const ref = blobRef(tenantId, digest);
    if (this.#directoryState(this.#tenantDir(tenantId)) === 'missing' || this.#directoryState(this.#blobDir(tenantId)) === 'missing') {
      throw new BlobNotFoundError(`blob ${ref} does not exist`);
    }
    const inspection = this.#inspect(join(this.#blobDir(tenantId), digest), digest);
    if (inspection.status === 'missing') throw new BlobNotFoundError(`blob ${ref} does not exist`);
    if (inspection.status === 'corrupt') throw new BlobIntegrityError(`blob ${ref} failed verification: ${inspection.reason}`);
    return inspection.bytes;
  }

  /** Read a stored ref; the ref must belong to `tenantId`. */
  readRef(tenantId: string, ref: string): Buffer {
    checkTenantId(tenantId);
    const key = parseBlobRef(ref);
    if (key.tenantId !== tenantId) throw new StorageUsageError('blob ref belongs to another tenant');
    return this.read(key.tenantId, key.digest);
  }

  /** 'ok', 'missing' or 'corrupt', without throwing for a bad blob (restore checks). */
  check(tenantId: string, digest: string): BlobStatus {
    try {
      this.read(tenantId, digest);
      return 'ok';
    } catch (error) {
      if (error instanceof BlobNotFoundError) return 'missing';
      if (error instanceof BlobIntegrityError) return 'corrupt';
      throw error;
    }
  }

  /** Digests of the tenant's published blobs, sorted. In-progress writes are not listed. */
  list(tenantId: string): string[] {
    checkTenantId(tenantId);
    if (this.#directoryState(this.#tenantDir(tenantId)) === 'missing') return [];
    if (this.#directoryState(this.#blobDir(tenantId)) === 'missing') return [];
    return this.#fs.readdir(this.#blobDir(tenantId)).filter((name) => DIGEST_PATTERN.test(name)).sort();
  }

  /**
   * Remove a blob (retention disposal only; the caller records the
   * DisposalRecord). Returns false when the tenant has no such blob.
   */
  dispose(tenantId: string, digest: string): boolean {
    checkTenantId(tenantId);
    checkDigest(digest);
    const dir = this.#blobDir(tenantId);
    if (this.#directoryState(this.#tenantDir(tenantId)) === 'missing' || this.#directoryState(dir) === 'missing') return false;
    const path = join(dir, digest);
    const stat = this.#fs.lstat(path);
    if (stat === undefined) return false;
    if (!stat.isFile()) throw new BlobIntegrityError(`blob ${blobRef(tenantId, digest)} is not a regular file`);
    this.#fs.unlink(path);
    this.#syncDirectory(dir);
    return true;
  }

  /**
   * Remove leftover .partial files from interrupted writes. Call only while
   * no write for this tenant is in progress (for example at startup of the
   * single instance). Returns the number removed.
   */
  sweepPartials(tenantId: string): number {
    checkTenantId(tenantId);
    if (this.#directoryState(this.#tenantDir(tenantId)) === 'missing') return 0;
    const dir = this.#tmpDir(tenantId);
    if (this.#directoryState(dir) === 'missing') return 0;
    let removed = 0;
    for (const name of this.#fs.readdir(dir)) {
      if (!PARTIAL_NAME.test(name)) continue;
      this.#removeQuietly(join(dir, name));
      removed += 1;
    }
    return removed;
  }
}

export function openBlobStore(options: BlobStoreOptions): FileBlobStore {
  if (typeof options !== 'object' || options === null) throw new StorageUsageError('blob store options are required');
  const { root } = options;
  if (typeof root !== 'string' || root.length === 0 || root.includes('\0') || !isAbsolute(root)) {
    throw new StorageUsageError('blob store root must be an absolute path');
  }
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BLOB_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_BLOB_BYTES_LIMIT) {
    throw new StorageUsageError(`blob size limit must be an integer in 1..${MAX_BLOB_BYTES_LIMIT}`);
  }
  const fsOps = options.fsOps ?? nodeFsOps;
  const stat = fsOps.lstat(root);
  if (stat === undefined || !stat.isDirectory()) {
    throw new StorageUsageError('blob store root must be an existing directory, not a link');
  }
  return new FileBlobStore(root, maxBytes, fsOps);
}
