// SPDX-License-Identifier: Apache-2.0
//
// T015's fault-injection hook (tasks.md T015 line; plan.md § Case catalogs,
// SC-003; A-010 request #61 (2), (3) and (7)).
//
// The finalization runner (src/jobs/finalize.ts) and the publish transaction
// (publish.ts) call faultPoint(phase) at the eight positions request #61 (2)
// rules:
// - reserve: right after the lease grant commits;
// - compose: before the seal anchor, the phase's first durable write when the
//   attempt writes it;
// - seal and verify: at the phase's start (neither has a durable write of its own);
// - store-pdf: before the sealed PDF's attempt record;
// - store-evidence: before approval-manifest.json's attempt record (the
//   checkpoint, the receipt and the package are the tail of this phase);
// - publish: inside the publish transaction, after its last statement and
//   before COMMIT;
// - outbox: right after the publish transaction commits (the outbox insert is
//   its last statement).
//
// Inert unless this process was started with the explicit harness flag
// `--opensig-test-fault-hook=<phase>:<absolute FIFO path>` on its command line
// (REC-01). That flag is the hook's only input: it reads no environment
// variable and no setting, and opens no file except the FIFO the flag names.
// Without the flag, faultPoint returns at once and touches nothing, so a run
// with every hook point compiled in behaves exactly as an unhooked run. No
// production entry passes the flag.
//
// Armed, the hook holds the attempt once per process, at the phase the flag
// names. It opens the FIFO read-write: on Linux that never blocks, and it keeps
// a reader open, so a release written at once is never lost. It then writes one
// line, {"event":"fault-hook","phase":"<phase>"}, on stdout, and blocks in one
// read of the FIFO until the harness writes a byte (the release) or SIGKILLs
// the process. The read parks the thread in the kernel: nothing spins or polls.
// The hold is synchronous, so it also holds inside the publish transaction's
// synchronous callback, keeping the write lock. The hook never kills its own
// process and never changes what the attempt writes.

import { closeSync, constants as fsConstants, fstatSync, openSync, readSync, writeSync } from 'node:fs';
import { isAbsolute } from 'node:path';

export const FAULT_HOOK_FLAG = '--opensig-test-fault-hook';

/** The eight phases, in the runner's order (plan.md SC-003), as the flag spells them. */
export const FAULT_PHASES = Object.freeze(['reserve', 'compose', 'seal', 'verify', 'store-pdf', 'store-evidence', 'publish', 'outbox'] as const);
export type FaultPhase = (typeof FAULT_PHASES)[number];

export interface FaultHookConfig {
  readonly phase: FaultPhase;
  readonly releasePath: string;
}

function isFaultPhase(value: string): value is FaultPhase {
  return (FAULT_PHASES as readonly string[]).includes(value);
}

/** The harness flag in a command line: null when absent; a repeated or malformed flag throws. */
export function parseFaultHookFlag(argv: readonly string[]): FaultHookConfig | null {
  const prefix = `${FAULT_HOOK_FLAG}=`;
  const given = argv.filter((arg) => arg === FAULT_HOOK_FLAG || arg.startsWith(prefix));
  if (given.length === 0) return null;
  const [only] = given;
  if (given.length > 1 || only === undefined) throw new TypeError('the fault hook flag is given more than once');
  const value = only.slice(prefix.length);
  const separator = value.indexOf(':');
  const phase = separator < 0 ? '' : value.slice(0, separator);
  const releasePath = separator < 0 ? '' : value.slice(separator + 1);
  if (!isFaultPhase(phase)) throw new TypeError('the fault hook flag names no known phase');
  if (!isAbsolute(releasePath) || releasePath.includes('\0')) throw new TypeError('the fault hook flag names no absolute release path');
  return Object.freeze({ phase, releasePath });
}

// undefined until the first hook point reads the flag; null when inert, and after the one hold.
let armed: FaultHookConfig | null | undefined;

/** One hook point (see the header). Inert without the harness flag. */
export function faultPoint(phase: FaultPhase): void {
  if (armed === undefined) armed = parseFaultHookFlag(process.argv);
  if (armed === null || armed.phase !== phase) return;
  const { releasePath } = armed;
  armed = null;
  const fd = openSync(releasePath, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
  try {
    if (!fstatSync(fd).isFIFO()) throw new TypeError('the fault hook release path is not a FIFO');
    writeSync(1, `${JSON.stringify({ event: 'fault-hook', phase })}\n`);
    readSync(fd, Buffer.alloc(1), 0, 1, null);
  } finally {
    closeSync(fd);
  }
}
