// SPDX-License-Identifier: Apache-2.0
//
// Runs scripts/backup.mjs with one node:fs fault injected into this process,
// to observe the exit status of a failure the command line has no seam for
// (it never exposes one). Usage:
//   node cli-fault.mjs ledger-dir-fsync <ledger-path> <backup.mjs arguments...>
// ledger-dir-fsync: once a rename onto the ledger path has returned, opening
// the ledger directory (to fsync it) fails with EIO. All data is synthetic.

import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { mock } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const [fault, ledgerPath, ...args] = process.argv.slice(2);
if (fault !== 'ledger-dir-fsync') throw new Error(`unknown fault ${fault}`);
const ledgerDir = dirname(ledgerPath);
let renamed = false;
const realRename = fs.renameSync;
const realOpen = fs.openSync;
mock.method(fs, 'renameSync', function (from, to) {
  const result = realRename.call(fs, from, to);
  if (String(to) === ledgerPath) renamed = true;
  return result;
});
mock.method(fs, 'openSync', function (path, ...rest) {
  if (renamed && String(path) === ledgerDir) throw Object.assign(new Error(`EIO: synthetic I/O failure, open '${path}'`), { code: 'EIO' });
  return realOpen.call(fs, path, ...rest);
});
syncBuiltinESMExports();

const script = join(resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..'), 'scripts', 'backup.mjs');
process.argv = [process.argv[0], script, ...args];
await import(pathToFileURL(script).href);
