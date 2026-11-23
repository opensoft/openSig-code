// SPDX-License-Identifier: Apache-2.0
//
// Parent side of the T010 race tests: start racers (race-child.mjs) as separate OS processes
// on the test world's database file, follow their JSON-line events, and answer their barriers.
// Every wait is bounded and notification-driven (no polling, no fixed sleep orders a step). Each
// racer's PID is recorded; stop() kills only those PIDs, and only while they are still running.
// Job files hold a session value for the racer, so they are written 0600 into the world's own
// mkdtemp directory and removed with it.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const CHILD = join(HERE, 'race-child.mjs');
const REPO = resolve(HERE, '..', '..', '..');

/** The bound on any single wait for a racer's event (node start-up included). */
export const EVENT_LIMIT_MS = 60_000;
/** The busy timeout of every racer's connection: longer than any pause in these tests. */
export const RACE_BUSY_TIMEOUT_MS = 20_000;

let sequence = 0;

/**
 * Start one racer. `job` is merged over the world's file locations. Returns a handle:
 * - waitFor(event, limitMs): the next event of that name after the previous wait's position
 *   (rejects when the racer exits first, or after limitMs);
 * - answer(): one line on stdin (releases a gate or a pause);
 * - result(): waitFor('result') and the racer's exit;
 * - stop(): kill the racer if it is still running.
 */
export function startRacer(world, dir, job) {
  sequence += 1;
  const label = `${job.action}-${sequence}`;
  const jobPath = join(dir, `${label}.json`);
  writeFileSync(
    jobPath,
    JSON.stringify({ dbPath: world.path, keyPath: world.keyPath, blobRoot: world.blobRoot, spoolDir: world.spoolDir, busyTimeoutMs: RACE_BUSY_TIMEOUT_MS, ...job }),
    { mode: 0o600 },
  );
  const child = spawn(process.execPath, [CHILD, jobPath], { cwd: REPO, stdio: ['pipe', 'pipe', 'pipe'] });
  const events = [];
  const watchers = new Set();
  let stderr = '';
  let pending = '';
  let exit = null;
  let cursor = 0;
  const notify = () => {
    for (const watcher of [...watchers]) watcher();
  };
  child.stdout.on('data', (chunk) => {
    pending += chunk.toString('utf8');
    let newline;
    while ((newline = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, newline);
      pending = pending.slice(newline + 1);
      try {
        events.push(JSON.parse(line));
      } catch {
        // Not an event line.
      }
    }
    notify();
  });
  child.stderr.on('data', (chunk) => {
    stderr = (stderr + chunk.toString('utf8')).slice(-2000);
  });
  const exited = new Promise((resolveExit) => {
    child.on('close', (code, signal) => {
      exit = { code, signal };
      notify();
      resolveExit(exit);
    });
  });
  child.on('error', () => {});
  child.stdin.on('error', () => {});

  const describeRacer = () => `${label} (events: ${events.map((event) => event.event).join(', ') || 'none'}; exit: ${exit === null ? 'running' : `${exit.code ?? exit.signal}`}; stderr: ${stderr.trim().slice(-300) || 'none'})`;

  const handle = {
    label,
    pid: child.pid,
    events,
    get exited() {
      return exit;
    },
    waitFor(name, limitMs = EVENT_LIMIT_MS) {
      return new Promise((resolveEvent, rejectEvent) => {
        let timer = null;
        const check = () => {
          for (let index = cursor; index < events.length; index += 1) {
            if (events[index].event === name) {
              cursor = index + 1;
              done();
              resolveEvent(events[index]);
              return;
            }
            if (events[index].event === 'error') {
              done();
              rejectEvent(new Error(`racer ${describeRacer()} failed: ${events[index].message}`));
              return;
            }
          }
          if (exit !== null) {
            done();
            rejectEvent(new Error(`racer ${describeRacer()} exited before ${name}`));
          }
        };
        const done = () => {
          watchers.delete(check);
          if (timer !== null) clearTimeout(timer);
        };
        timer = setTimeout(() => {
          done();
          const error = new Error(`racer ${describeRacer()}: no ${name} within ${limitMs} ms`);
          error.timedOut = true;
          rejectEvent(error);
        }, limitMs);
        watchers.add(check);
        check();
      });
    },
    /** True when `name` does not arrive within `limitMs` (the racer keeps running). */
    async absentFor(name, limitMs) {
      const saved = cursor;
      try {
        await handle.waitFor(name, limitMs);
        return false;
      } catch (error) {
        if (error.timedOut !== true) throw error;
        cursor = saved;
        return true;
      }
    },
    answer() {
      child.stdin.write('\n');
    },
    async result() {
      const result = await handle.waitFor('result');
      const ended = await Promise.race([exited, new Promise((resolveLate) => setTimeout(() => resolveLate(null), EVENT_LIMIT_MS).unref())]);
      assert.ok(ended !== null && ended.code === 0, `racer ${describeRacer()} exits cleanly after its result`);
      return result;
    },
    stop() {
      if (exit === null) child.kill('SIGKILL');
      child.stdin.destroy();
      return exited;
    },
  };
  return handle;
}

/** Stop every racer that is still running (only the recorded handles). */
export async function stopAll(racers) {
  await Promise.all(racers.map((racer) => racer.stop()));
}

/** The approval receipt bytes a racer returned. */
export function bytesOf(result) {
  return Buffer.from(String(result.bytes ?? ''), 'base64');
}
