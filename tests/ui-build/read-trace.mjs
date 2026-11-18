// SPDX-License-Identifier: Apache-2.0
//
// UB-05 read trace (T035). Loaded with `--import` into the build process, and only there.
// It wraps the node:fs entry points that read file content, list directories or write,
// records each call's absolute path, and re-syncs the ESM named exports
// (syncBuiltinESMExports, as tests/outbox-restore/support/ledger-child.mjs does), so the
// builder's `import { readFileSync } from 'node:fs'` binds the wrapped functions. At exit it
// writes the records to OPENSIG_UI_READ_TRACE. This is the build process's own observation of
// what it touched, taken independently of the provenance manifest the build writes.
//
// Records: { op: 'read' | 'list' | 'write', fn, path } with an absolute path, or path null
// when a call named no path (a file descriptor), which the test refuses.

import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const target = process.env.OPENSIG_UI_READ_TRACE;
if (typeof target !== 'string' || target === '') throw new Error('OPENSIG_UI_READ_TRACE is not set');

const writeTrace = fs.writeFileSync;
const records = [];

function pathOf(value) {
  if (typeof value === 'string') return resolve(value.startsWith('file:') ? fileURLToPath(value) : value);
  if (value instanceof URL) return resolve(fileURLToPath(value));
  if (Buffer.isBuffer(value)) return resolve(value.toString('utf8'));
  return null;
}

function opensForRead(flags) {
  if (flags === undefined || flags === null) return true;
  if (typeof flags === 'number') return (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) === 0;
  return /^(?:r|rs|sr)$/.test(String(flags));
}

function wrap(owner, name, describe) {
  const original = owner[name];
  if (typeof original !== 'function') return;
  owner[name] = function traced(...args) {
    for (const [op, value] of describe(args)) records.push({ op, fn: name, path: pathOf(value) });
    return Reflect.apply(original, this, args);
  };
}

const read = (args) => [['read', args[0]]];
const list = (args) => [['list', args[0]]];
const write = (args) => [['write', args[0]]];
const open = (args) => [[opensForRead(args[1]) ? 'read' : 'write', args[0]]];
const copy = (args) => [
  ['read', args[0]],
  ['write', args[1]],
];
const rename = (args) => [
  ['write', args[0]],
  ['write', args[1]],
];

for (const [name, describe] of [
  ['readFileSync', read],
  ['readFile', read],
  ['createReadStream', read],
  ['openSync', open],
  ['open', open],
  ['openAsBlob', read],
  ['readdirSync', list],
  ['readdir', list],
  ['opendirSync', list],
  ['opendir', list],
  ['copyFileSync', copy],
  ['copyFile', copy],
  ['cpSync', copy],
  ['cp', copy],
  ['writeFileSync', write],
  ['writeFile', write],
  ['appendFileSync', write],
  ['appendFile', write],
  ['createWriteStream', write],
  ['mkdirSync', write],
  ['mkdir', write],
  ['mkdtempSync', write],
  ['mkdtemp', write],
  ['rmSync', write],
  ['rm', write],
  ['rmdirSync', write],
  ['unlinkSync', write],
  ['renameSync', rename],
  ['rename', rename],
  ['symlinkSync', (args) => [['write', args[1]]]],
  ['linkSync', copy],
]) {
  wrap(fs, name, describe);
}

for (const [name, describe] of [
  ['readFile', read],
  ['open', open],
  ['readdir', list],
  ['opendir', list],
  ['copyFile', copy],
  ['cp', copy],
  ['writeFile', write],
  ['appendFile', write],
  ['mkdir', write],
  ['mkdtemp', write],
  ['rm', write],
  ['rename', rename],
]) {
  wrap(fs.promises, name, describe);
}

syncBuiltinESMExports();

process.on('exit', () => {
  writeTrace(target, JSON.stringify(records));
});
