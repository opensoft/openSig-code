// SPDX-License-Identifier: Apache-2.0
//
// A ledger writer in its own OS process, for the two-process and crash tests
// (OR-16, OR-17, OR-19). Usage:
//   node ledger-child.mjs <mode> <op> <config-json>
// mode:
//   free             run the operation normally
//   blocked          hold the first rename onto the ledger at a file barrier:
//                    write <barrier>/ready, wait for <barrier>/go (bounded)
//   crash-temp       SIGKILL at the first open of a temp file in the ledger
//                    directory (before the commit point)
//   crash-committed  SIGKILL right after the rename onto the ledger returns
//                    (after the commit point)
// op: record (recordExportedHead) | backup (createBackup) | loop (record seq
// 1..n of a synthetic chain, retrying while the ledger is locked) | hold (open
// a LedgerSession, write <barrier>/held.json (its pid, and whether it sees its
// own descriptor on the lock in /proc/self/fd, which a process can always
// read; null off Linux) and <barrier>/ready, keep the lock until
// <barrier>/go, then release; a live lock holder for the damaged-lock tests).
// Faults are injected through node:fs (node:test mock), the same in any
// version of the code. Prints one JSON line. All data is synthetic.

import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { dirname, join } from 'node:path';
import { mock } from 'node:test';

import { createBackup, LedgerSession, readLedger, recordExportedHead } from '../../../src/storage/backup/index.ts';

const [mode, op, configJson] = process.argv.slice(2);
const cfg = JSON.parse(configJson);
const sleep = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
const ledgerDir = dirname(cfg.ledgerPath);

if (mode === 'blocked' || mode === 'crash-committed') {
  const realRename = fs.renameSync;
  let held = false;
  mock.method(fs, 'renameSync', function (from, to) {
    if (!held && String(to) === cfg.ledgerPath) {
      held = true;
      if (mode === 'blocked') {
        fs.writeFileSync(join(cfg.barrier, 'ready'), String(process.pid));
        const deadline = Date.now() + 30_000;
        while (!fs.existsSync(join(cfg.barrier, 'go'))) {
          if (Date.now() > deadline) process.exit(3);
          sleep(5);
        }
      } else {
        realRename.call(fs, from, to);
        process.kill(process.pid, 'SIGKILL');
      }
    }
    return realRename.call(fs, from, to);
  });
  syncBuiltinESMExports();
} else if (mode === 'crash-temp') {
  const realOpen = fs.openSync;
  mock.method(fs, 'openSync', function (path, ...rest) {
    if (dirname(String(path)) === ledgerDir && String(path).endsWith('.tmp')) process.kill(process.pid, 'SIGKILL');
    return realOpen.call(fs, path, ...rest);
  });
  syncBuiltinESMExports();
} else if (mode !== 'free') {
  throw new Error(`unknown mode ${mode}`);
}

let t = Date.parse(cfg.clockStart ?? '2026-11-16T12:00:00.000Z');
const clock = () => new Date((t += 1000));
const outcome = (fn) => {
  try {
    return { ok: true, value: fn() };
  } catch (error) {
    return { ok: false, code: error.code ?? 'error', message: String(error.message).slice(0, 300) };
  }
};

if (op === 'record') {
  const result = outcome(() => recordExportedHead(cfg.ledgerPath, cfg.tenant, cfg.head, { clock, source: 'receipt', digestAt: (seq) => cfg.digests[String(seq)] }).seq);
  process.stdout.write(`${JSON.stringify(result)}\n`);
} else if (op === 'backup') {
  let result;
  try {
    const manifest = await createBackup({ databasePath: cfg.databasePath, blobRoot: cfg.blobRoot, outDir: cfg.outDir, ledgerPath: cfg.ledgerPath, clock, firstBackup: cfg.firstBackup === true });
    result = { ok: true, heads: Object.fromEntries(manifest.tenants.map((tenant) => [tenant.tenant_id, tenant.audit_head?.seq ?? null])) };
  } catch (error) {
    result = { ok: false, code: error.code ?? 'error', message: String(error.message).slice(0, 300) };
  }
  process.stdout.write(`${JSON.stringify(result)}\n`);
} else if (op === 'loop') {
  let lost = 0;
  let retries = 0;
  for (let seq = 1; seq <= cfg.n; seq += 1) {
    for (;;) {
      const result = outcome(() =>
        recordExportedHead(cfg.ledgerPath, cfg.tenant, { seq, digest: cfg.chain[seq] }, { clock, source: 'receipt', digestAt: (s) => cfg.chain[s], createIfMissing: true }),
      );
      if (result.ok) break;
      if (result.code !== 'ledger_locked') throw new Error(result.message);
      retries += 1;
      sleep(1 + Math.floor(Math.random() * 3));
    }
    for (;;) {
      const read = outcome(() => readLedger(cfg.ledgerPath)[cfg.tenant]);
      if (!read.ok) {
        sleep(1);
        continue;
      }
      if (read.value === undefined || read.value.seq < seq) lost += 1;
      break;
    }
  }
  process.stdout.write(`${JSON.stringify({ ok: true, lost, retries })}\n`);
} else if (op === 'hold') {
  const session = LedgerSession.open(cfg.ledgerPath);
  let ownLockDescriptor = null;
  try {
    const lock = fs.statSync(`${cfg.ledgerPath}.lock`);
    ownLockDescriptor = fs.readdirSync('/proc/self/fd').some((fd) => {
      try {
        const target = fs.statSync(`/proc/self/fd/${fd}`);
        return target.dev === lock.dev && target.ino === lock.ino;
      } catch {
        return false;
      }
    });
  } catch {
    ownLockDescriptor = null;
  }
  fs.writeFileSync(join(cfg.barrier, 'held.json'), JSON.stringify({ pid: process.pid, ownLockDescriptor }));
  fs.writeFileSync(join(cfg.barrier, 'ready'), String(process.pid));
  const deadline = Date.now() + 60_000;
  while (!fs.existsSync(join(cfg.barrier, 'go'))) {
    if (Date.now() > deadline) break;
    sleep(5);
  }
  session.release();
  process.stdout.write(`${JSON.stringify({ ok: true })}\n`);
} else {
  throw new Error(`unknown op ${op}`);
}
