// SPDX-License-Identifier: Apache-2.0
//
// The filesystem operations the blob store uses, behind a narrow interface.
// Production uses nodeFsOps. Tests may wrap it to observe the order of
// operations (temp write, fsync, publish, directory fsync) or to make one
// operation fail; the wrapper only ever adds behavior around real calls.

import {
  closeSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  unlinkSync,
  writeSync,
  type Stats,
} from 'node:fs';

export interface FsOps {
  open(path: string, flags: number, mode?: number): number;
  /** Write every byte of `data` at the current position. */
  writeAll(fd: number, data: Uint8Array): void;
  fsync(fd: number): void;
  fchmod(fd: number, mode: number): void;
  close(fd: number): void;
  /** Hard-link `existing` as `target`; fails with EEXIST when `target` exists. */
  link(existing: string, target: string): void;
  unlink(path: string): void;
  mkdir(path: string, mode: number): void;
  /** lstat, or undefined when the path does not exist. */
  lstat(path: string): Stats | undefined;
  fstat(fd: number): Stats;
  read(fd: number, buffer: Uint8Array, position: number): number;
  readdir(path: string): string[];
}

export const nodeFsOps: FsOps = Object.freeze({
  open: (path: string, flags: number, mode?: number) => openSync(path, flags, mode),
  writeAll: (fd: number, data: Uint8Array) => {
    let offset = 0;
    while (offset < data.byteLength) offset += writeSync(fd, data, offset, data.byteLength - offset);
  },
  fsync: (fd: number) => fsyncSync(fd),
  fchmod: (fd: number, mode: number) => fchmodSync(fd, mode),
  close: (fd: number) => closeSync(fd),
  link: (existing: string, target: string) => linkSync(existing, target),
  unlink: (path: string) => unlinkSync(path),
  mkdir: (path: string, mode: number) => mkdirSync(path, { mode }),
  lstat: (path: string) => lstatSync(path, { throwIfNoEntry: false }),
  fstat: (fd: number) => fstatSync(fd),
  read: (fd: number, buffer: Uint8Array, position: number) => readSync(fd, buffer, 0, buffer.byteLength, position),
  readdir: (path: string) => readdirSync(path),
});
