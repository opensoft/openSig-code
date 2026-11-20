// SPDX-License-Identifier: Apache-2.0
//
// Runs scripts/backup.mjs with node:fs faults injected into this process, to
// observe the exit status of failures the command line has no seam for (it
// never exposes one). Usage:
//   node cli-fault.mjs <fault>[,<fault>...] <ledger-path> <backup.mjs arguments...>
// Faults:
//   ledger-dir-fsync   once a rename onto the ledger path has returned,
//                      opening the ledger directory (to fsync it) fails (EIO);
//   lock-swap          at the first read of the ledger while its lock exists
//                      (inside the session), the lock path is replaced by
//                      another file, as a writer that ignores the protocol
//                      would; the session's lock is then lost;
//   target-db-appears  at the first temp file of the restore's target blob
//                      store, a file appears at the target database path
//                      (--db), as another process creating it mid-run.
// All data is synthetic.

import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { dirname, join, resolve, sep } from 'node:path';
import { mock } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const KNOWN = ['ledger-dir-fsync', 'lock-swap', 'target-db-appears'];
const [faultList, ledgerPath, ...args] = process.argv.slice(2);
const faults = new Set(String(faultList).split(','));
for (const fault of faults) if (!KNOWN.includes(fault)) throw new Error(`unknown fault ${fault}`);
const ledgerDir = dirname(ledgerPath);
const lockPath = `${ledgerPath}.lock`;
const valueOf = (flag) => {
  const index = args.indexOf(flag);
  return index < 0 ? undefined : args[index + 1];
};
const targetDb = valueOf('--db');
const targetBlobs = valueOf('--blobs');

const realRename = fs.renameSync;
const realOpen = fs.openSync;
const realRead = fs.readFileSync;
let renamed = false;
let swapped = false;
mock.method(fs, 'renameSync', function (from, to) {
  const result = realRename.call(fs, from, to);
  if (String(to) === ledgerPath) renamed = true;
  return result;
});
mock.method(fs, 'openSync', function (path, ...rest) {
  const text = String(path);
  if (faults.has('ledger-dir-fsync') && renamed && text === ledgerDir) throw Object.assign(new Error(`EIO: synthetic I/O failure, open '${text}'`), { code: 'EIO' });
  if (faults.has('target-db-appears') && targetDb !== undefined && targetBlobs !== undefined && text.startsWith(`${targetBlobs}${sep}`) && text.endsWith('.partial')) {
    if (fs.lstatSync(targetDb, { throwIfNoEntry: false }) === undefined) fs.writeFileSync(targetDb, 'a database another process created during the restore');
  }
  return realOpen.call(fs, path, ...rest);
});
mock.method(fs, 'readFileSync', function (path, ...rest) {
  if (faults.has('lock-swap') && !swapped && String(path) === ledgerPath && fs.lstatSync(lockPath, { throwIfNoEntry: false }) !== undefined) {
    swapped = true;
    fs.rmSync(lockPath);
    fs.writeFileSync(lockPath, "a lock that is not this run's", { flag: 'wx', mode: 0o600 });
  }
  return realRead.call(fs, path, ...rest);
});
syncBuiltinESMExports();

const script = join(resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..'), 'scripts', 'backup.mjs');
process.argv = [process.argv[0], script, ...args];
await import(pathToFileURL(script).href);
