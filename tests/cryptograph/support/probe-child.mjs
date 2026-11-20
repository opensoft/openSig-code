// SPDX-License-Identifier: Apache-2.0
//
// Probe entry (T037, WK-02). Launched by testing.ts launchForTests through the
// sealing worker's own launch (same file, flags, empty environment and
// descriptors; its read grant covers this file only). It drains the request
// and prints one JSON object describing what the child sees: environment
// names, argv, execArgv, the permission model's grants, the kind of every
// descriptor 0..63, and whether fd 3 can be read. It never prints a value
// read from fd 3, only whether a read returned bytes.

import { fstatSync, readSync } from 'node:fs';

for await (const chunk of process.stdin) void chunk;

function kind(fd) {
  try {
    const stat = fstatSync(fd);
    if (stat.isFile()) return { kind: 'file', mode: stat.mode & 0o777 };
    if (stat.isFIFO()) return { kind: 'fifo' };
    if (stat.isSocket()) return { kind: 'socket' };
    if (stat.isCharacterDevice()) return { kind: 'char' };
    if (stat.isDirectory()) return { kind: 'dir' };
    return { kind: 'other' };
  } catch {
    return { kind: 'closed' };
  }
}

let keyReadable = false;
try {
  const probe = Buffer.alloc(16);
  keyReadable = readSync(3, probe, 0, probe.length, 0) > 0;
  probe.fill(0);
} catch {
  keyReadable = false;
}

const permission = process.permission;
const report = {
  env: Object.keys(process.env),
  argv: process.argv.slice(2),
  execArgv: process.execArgv,
  permission: {
    active: permission !== undefined,
    fsWrite: permission?.has('fs.write') ?? true,
    child: permission?.has('child') ?? true,
    worker: permission?.has('worker') ?? true,
    readsTmp: permission?.has('fs.read', '/tmp') ?? true,
  },
  fds: Array.from({ length: 64 }, (_, fd) => kind(fd)),
  keyReadable,
};
process.stdout.write(JSON.stringify(report));
process.exitCode = 0;
