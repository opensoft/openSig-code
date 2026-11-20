// SPDX-License-Identifier: Apache-2.0
//
// T015 parent side of a case's child processes (the pattern of tests/approval/support/race.mjs).
// - Each runner child is a separate OS process on the pinned Node (process.execPath) running
//   support/runner-child.mjs with a 0600 job file and, for a held runner, the explicit harness
//   flag --opensig-test-fault-hook=<phase>:<FIFO>. Its environment is PATH only. It is never
//   detached, so it stays in the runner's process group and the per-file timeout reaches it.
// - A held runner announces its phase on stdout and blocks reading its release FIFO (0600, made
//   by mkfifo at a fixed path, as tests/cryptograph/failures.test.mjs does, with its own timeout).
//   release() writes one byte to it; kill() sends SIGKILL to the child's recorded PID.
// - Every wait is notification-driven (stdout data and 'close' events) and bounded by a hang
//   guard; "cannot finish while held" is one bounded timer, as AP-12 uses. Nothing polls.
// - A case's children are recorded in its group; stopAll() signals only those PIDs, and only
//   while they still run: no process scan, no pattern kill. Cases run serially.

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, constants as fsConstants, existsSync, openSync, writeFileSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { FAULT_HOOK_FLAG } from '../../../src/domain/finalization/fault-hook.ts';
import { CASE_BUSY_TIMEOUT_MS, LEASE_MS, REPO } from './world.mjs';

const CHILD = fileURLToPath(new URL('./runner-child.mjs', import.meta.url));
/** The bound on any single wait for a child's event or exit (Node start-up included). */
export const EVENT_LIMIT_MS = 60_000;
/** How long a child queued behind a held write lock is watched to show it cannot finish. */
export const BLOCKED_WATCH_MS = 1_000;

let sequence = 0;

export function childGroup() {
  const handles = [];
  return {
    handles,
    add(handle) {
      handles.push(handle);
      return handle;
    },
    /** SIGKILL every recorded child still running, then wait for each to close. */
    async stopAll() {
      const exits = [];
      for (const handle of handles) exits.push({ role: handle.role, ...(await handle.stop()) });
      return exits;
    },
  };
}

function makeFifo(path) {
  const mkfifo = ['/usr/bin/mkfifo', '/bin/mkfifo'].find((candidate) => existsSync(candidate));
  assert.ok(mkfifo, 'premise: mkfifo is present at a fixed path');
  const made = spawnSync(mkfifo, ['-m', '600', path], { env: {}, stdio: 'ignore', timeout: 10_000, killSignal: 'SIGKILL' });
  assert.equal(made.error, undefined, `premise: mkfifo ran within its timeout (${made.error?.code ?? 'ok'})`);
  assert.equal(made.status, 0, `premise: the release FIFO exists (mkfifo status ${made.status})`);
}

/**
 * Start one runner pass. `role` names it in messages and receipts; `clockMs` is its one instant;
 * `phase` (a catalog phase) holds it at that phase's hook, through the explicit flag; without it
 * the child carries no flag at all.
 */
export function startRunner(group, world, { role, clockMs, phase = null }) {
  sequence += 1;
  const label = `${role}-${sequence}`;
  const jobPath = join(world.jobsDir, `${label}.json`);
  writeFileSync(
    jobPath,
    JSON.stringify({ dbPath: world.path, blobRoot: world.blobRoot, sealKeyFile: world.sealKeyFile, owner: `recovery-${label}`, leaseMs: LEASE_MS, busyTimeoutMs: CASE_BUSY_TIMEOUT_MS, clockMs }),
    { mode: 0o600 },
  );
  const argv = [CHILD, jobPath];
  let fifo = null;
  if (phase !== null) {
    fifo = join(world.jobsDir, `${label}.release`);
    makeFifo(fifo);
    argv.push(`${FAULT_HOOK_FLAG}=${phase.flag}:${fifo}`);
  }
  const child = spawn(process.execPath, argv, { cwd: REPO, env: { PATH: process.env.PATH ?? '' }, stdio: ['ignore', 'pipe', 'pipe'], detached: false });
  const events = [];
  const watchers = new Set();
  let stdout = '';
  let stderr = '';
  let exit = null;
  let cursor = 0;
  const notify = () => {
    for (const watcher of [...watchers]) watcher();
  };
  child.stdout.on('data', (chunk) => {
    stdout += chunk.toString('utf8');
    let newline;
    while ((newline = stdout.indexOf('\n')) >= 0) {
      const line = stdout.slice(0, newline);
      stdout = stdout.slice(newline + 1);
      try {
        events.push(JSON.parse(line));
      } catch {
        events.push({ event: 'unparsed', length: line.length });
      }
    }
    notify();
  });
  child.stderr.on('data', (chunk) => {
    stderr = (stderr + chunk.toString('utf8')).slice(-2000);
  });
  child.on('error', () => {});
  const closed = new Promise((resolveClose) => {
    child.on('close', (code, signal) => {
      exit = { code, signal };
      notify();
      resolveClose(exit);
    });
  });

  const describe = () =>
    `${label} at ${new Date(clockMs).toISOString()}${phase ? ` held at ${phase.label}` : ''} (events: ${events.map((event) => (event.event === 'fault-hook' ? `hook at ${event.phase}` : event.event === 'outcome' ? `outcome reclaimed ${event.reclaimed} attempts [${event.attempts}]` : `${event.event} ${event.name ?? ''} ${event.code ?? ''}`)).join(', ') || 'none'}; exit ${exit === null ? 'running' : `${exit.code ?? exit.signal}`}; stderr tail: ${stderr.trim().slice(-300) || 'none'})`;

  const bounded = (what, limitMs, check) =>
    new Promise((resolveWait, rejectWait) => {
      let timer = null;
      const done = () => {
        watchers.delete(run);
        if (timer !== null) clearTimeout(timer);
      };
      const run = () => {
        const verdict = check();
        if (verdict === undefined) return;
        done();
        if (verdict.error) rejectWait(verdict.error);
        else resolveWait(verdict.value);
      };
      timer = setTimeout(() => {
        done();
        const error = new Error(`${describe()}: no ${what} within ${limitMs} ms (a hang guard, not the oracle)`);
        error.timedOut = true;
        rejectWait(error);
      }, limitMs);
      watchers.add(run);
      run();
    });

  const untilExit = (limitMs) => bounded('exit', limitMs, () => (exit !== null ? { value: exit } : undefined));

  const handle = {
    role,
    label,
    pid: child.pid,
    events,
    get exit() {
      return exit;
    },
    describe,
    /** The hook's announcement of `phase` (held there). */
    held(limitMs = EVENT_LIMIT_MS) {
      return bounded(`hold at ${phase?.label}`, limitMs, () => {
        for (let index = cursor; index < events.length; index += 1) {
          if (events[index].event === 'fault-hook') {
            cursor = index + 1;
            return events[index].phase === phase?.flag ? { value: events[index] } : { error: new Error(`${describe()}: held at ${events[index].phase}, expected ${phase?.flag}`) };
          }
        }
        return exit !== null ? { error: new Error(`${describe()} exited before its hold`) } : undefined;
      });
    },
    /** True when the child still runs after `limitMs` (one bounded timer). */
    async absentFor(limitMs = BLOCKED_WATCH_MS) {
      try {
        await untilExit(limitMs);
        return false;
      } catch (error) {
        if (error.timedOut !== true) throw error;
        return true;
      }
    },
    /** Write the one release byte; the child must still be held. */
    release() {
      assert.equal(exit, null, `${describe()}: released only while held`);
      assert.ok(fifo !== null, `${describe()}: only a held runner is released`);
      const fd = openSync(fifo, fsConstants.O_WRONLY | fsConstants.O_NONBLOCK);
      try {
        writeSync(fd, Buffer.from([0x31]));
      } finally {
        closeSync(fd);
      }
    },
    /** SIGKILL this child's recorded PID while it is held, and wait for it to close. */
    async kill() {
      assert.equal(exit, null, `${describe()}: premise: still held when killed`);
      child.kill('SIGKILL');
      return untilExit(EVENT_LIMIT_MS);
    },
    /** The child's own end: a clean exit and its one outcome line. */
    async outcome(limitMs = EVENT_LIMIT_MS) {
      const ended = await untilExit(limitMs);
      assert.deepEqual([ended.code, ended.signal], [0, null], `${describe()} exits 0 by itself`);
      const outcomes = events.filter((event) => event.event === 'outcome');
      assert.equal(outcomes.length, 1, `${describe()} reports exactly one outcome`);
      return outcomes[0];
    },
    /** Cleanup on every path: SIGKILL only while running, then wait for close. */
    async stop() {
      if (exit === null) child.kill('SIGKILL');
      await Promise.race([closed, new Promise((resolveLate) => setTimeout(resolveLate, EVENT_LIMIT_MS).unref())]);
      return exit ?? { code: null, signal: 'unclosed' };
    },
  };
  return group.add(handle);
}

/** Assert an outcome's reclaim count and attempt outcomes (T038's AttemptOutcome kinds). */
export function assertOutcome(handle, outcome, { reclaimed, attempts }) {
  assert.deepEqual({ reclaimed: outcome.reclaimed, attempts: outcome.attempts }, { reclaimed, attempts }, `${handle.describe()}: expected reclaimed ${reclaimed}, attempts [${attempts}]`);
}
