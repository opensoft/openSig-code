// SPDX-License-Identifier: Apache-2.0
//
// The sealing worker's launcher (T037): the parent side.
//
// - Launch: sealWorkerCommand() is a pure plan. The file is process.execPath
//   (the pinned Node that runs the service and the gate); the argv is the fixed
//   flag list in child.ts's header followed by the entry, with no request value
//   in it; the environment is empty (data-model.md: child-process environments
//   are cleared of secrets); cwd is the worker directory. The read grants are
//   the child's own modules only: worker/, cms/, keys/ and T036's bounds module.
// - Descriptors: [0 request pipe, 1 reply pipe, 2 'ignore' (/dev/null), 3 the
//   caller's key descriptor]. libuv marks every other descriptor close-on-exec,
//   so nothing else is inherited. The caller (T038) opened the key descriptor
//   and still owns it: this module never closes it.
// - Limits: the wall-time limit is armed at spawn and SIGKILLs the child; the
//   V8 heap is capped by --max-old-space-size; the reply is capped at the
//   exact size a sealed reply can have, and a longer reply kills the child.
//   The child cannot fork (no child-process or worker grant), so killing its
//   pid ends all of it. No CPU rlimit is set: no shell is involved.
// - Abort (request #44): an AbortSignal, the call's only option. Already
//   aborted: no child starts. Aborted later: the child is SIGKILLed, and the
//   call settles on 'close' with the retryable reason `aborted`, whatever the
//   child had written. T038 aborts on lease loss.
// - Settlement: the promise settles only on 'close', after the child has been
//   reaped and its pipes have closed, on every path (sealed, refused, crash,
//   timeout, overflow, abort, spawn failure). The timer and the abort listener
//   are always removed.
// - Validation: a sealed reply is accepted only if its bytes equal the input
//   outside the placeholder, the placeholder holds exactly hexLength lowercase
//   hex digits, and the reported SHA-256 matches a recomputation here. Anything
//   else is worker-protocol. The child's stderr is never read.
// - No partial artifact: the caller's bytes are only read (the request frame is
//   a copy), and sealed bytes are returned only after all of the above.
//
// This does not reuse T033's parse sandbox (src/pdf/sandbox.ts): process
// isolation is enough for the worker, which parses no document (request #44),
// and the sandbox needs launchers the `cryptograph` mode does not declare.

import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SealError } from './errors.ts';
import { decodeReply, encodeRequest, maxReplyBytes, type SealedReply, type SealRequest } from './frame.ts';

const WORKER_DIR = dirname(fileURLToPath(import.meta.url));
const CRYPTOGRAPH_DIR = dirname(WORKER_DIR);
export const CHILD_ENTRY = join(WORKER_DIR, 'child.ts');
/** The child's whole import closure: bounds.ts imports nothing (its header; request #45). */
export const READ_GRANTS: readonly string[] = Object.freeze([
  `${WORKER_DIR}${sep}`,
  `${join(CRYPTOGRAPH_DIR, 'cms')}${sep}`,
  `${join(CRYPTOGRAPH_DIR, 'keys')}${sep}`,
  join(CRYPTOGRAPH_DIR, 'compose', 'bounds.ts'),
]);

export interface SealLimits {
  /** Wall-clock limit from spawn to the child's end. */
  readonly wallMs: number;
  /** V8 old-space cap of the child. */
  readonly heapMiB: number;
}

export const DEFAULT_SEAL_LIMITS: Readonly<SealLimits> = Object.freeze({ wallMs: 20_000, heapMiB: 64 });

/** Limits may only be lowered, never raised past DEFAULT_SEAL_LIMITS (test seams only; the public call takes none). */
export function resolveSealLimits(overrides?: Partial<SealLimits>): SealLimits {
  const out: { wallMs: number; heapMiB: number } = { ...DEFAULT_SEAL_LIMITS };
  for (const [name, value] of Object.entries(overrides ?? {})) {
    if (!(name in DEFAULT_SEAL_LIMITS)) throw new SealError('input-invalid');
    const ceiling = DEFAULT_SEAL_LIMITS[name as keyof SealLimits];
    if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > ceiling) throw new SealError('input-invalid');
    out[name as keyof SealLimits] = value as number;
  }
  return Object.freeze(out);
}

export interface SealWorkerCommand {
  readonly file: string;
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, never>>;
  readonly cwd: string;
}

/** The exact launch for `entry` (the real child, or a test entry that gets a read grant on itself only). */
export function sealWorkerCommand(limits: SealLimits = DEFAULT_SEAL_LIMITS, entry: string = CHILD_ENTRY): SealWorkerCommand {
  const grants = entry === CHILD_ENTRY ? READ_GRANTS : [entry];
  return Object.freeze({
    file: process.execPath,
    args: Object.freeze([
      `--max-old-space-size=${limits.heapMiB}`,
      '--permission',
      ...grants.map((grant) => `--allow-fs-read=${grant}`),
      '--disallow-code-generation-from-strings',
      entry,
    ]),
    env: Object.freeze({}),
    cwd: WORKER_DIR,
  });
}

export interface ChildOutcome {
  readonly spawned: boolean;
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly timedOut: boolean;
  readonly aborted: boolean;
  readonly overflow: boolean;
  readonly stdout: Buffer;
  readonly pid: number | undefined;
}

const NOT_STARTED: ChildOutcome = Object.freeze({ spawned: false, code: null, signal: null, timedOut: false, aborted: false, overflow: false, stdout: Buffer.alloc(0), pid: undefined });

/** Run one child to its end. Never rejects; settles only after 'close'. */
export function runSealChild(command: SealWorkerCommand, frame: Buffer, keyFd: number, replyCap: number, wallMs: number, signal?: AbortSignal): Promise<ChildOutcome> {
  if (signal?.aborted) return Promise.resolve({ ...NOT_STARTED, aborted: true });
  return new Promise((resolve) => {
    let child: ChildProcess;
    try {
      child = spawn(command.file, command.args, { cwd: command.cwd, env: { ...command.env }, stdio: ['pipe', 'pipe', 'ignore', keyFd] });
    } catch {
      resolve(NOT_STARTED);
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let overflow = false;
    let timedOut = false;
    let aborted = false;
    const kill = (): void => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    };
    const onAbort = (): void => {
      aborted = true;
      kill();
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, wallMs);
    child.on('error', kill);
    child.stdin?.on('error', () => {
      // EPIPE: the child refused, or was killed, before reading the whole request.
    });
    child.stdout?.on('data', (chunk: Buffer) => {
      if (overflow) return;
      size += chunk.length;
      if (size > replyCap) {
        overflow = true;
        chunks.length = 0;
        kill();
        return;
      }
      chunks.push(chunk);
    });
    child.on('close', (code: number | null, exitSignal: NodeJS.Signals | null) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      resolve({
        spawned: child.pid !== undefined,
        code,
        signal: exitSignal,
        timedOut,
        aborted,
        overflow,
        stdout: overflow || aborted ? Buffer.alloc(0) : Buffer.concat(chunks, size),
        pid: child.pid,
      });
    });
    child.stdin?.end(frame);
  });
}

const sha256 = (data: Uint8Array): Buffer => createHash('sha256').update(data).digest();
const equal = (a: Uint8Array, b: Uint8Array): boolean => Buffer.compare(a, b) === 0;
const LOWER_HEX = /^[0-9a-f]*$/;

/** Accept a sealed reply only if it is consistent with the request (see the header). */
export function validateSealed(request: SealRequest, reply: SealedReply): void {
  const protocol = new SealError('worker-protocol');
  const { document, contentsOffset: offset, contentsHexLength: hexLength } = request;
  const sealed = reply.document;
  if (sealed.length !== document.length) throw protocol;
  if (!equal(sealed.subarray(0, offset), document.subarray(0, offset))) throw protocol;
  if (!equal(sealed.subarray(offset + hexLength), document.subarray(offset + hexLength))) throw protocol;
  const hex = Buffer.from(sealed.subarray(offset, offset + hexLength)).toString('latin1');
  // Lowercase hex of a DER SEQUENCE: an unfilled (all-zero) placeholder is not a seal.
  if (!LOWER_HEX.test(hex) || !hex.startsWith('30')) throw protocol;
  if (!equal(sha256(sealed), reply.finalPdfDigest)) throw protocol;
}

/** Launch `entry` for `request` and map every outcome to sealed bytes or a SealError. */
export async function sealWith(entry: string, request: SealRequest, keyFd: number, limits: SealLimits, signal?: AbortSignal): Promise<SealedReply> {
  const frame = encodeRequest(request);
  const outcome = await runSealChild(sealWorkerCommand(limits, entry), frame, keyFd, maxReplyBytes(request.document.length), limits.wallMs, signal);
  if (outcome.aborted) throw new SealError('aborted');
  if (!outcome.spawned) throw new SealError('worker-spawn-failed');
  if (outcome.timedOut) throw new SealError('worker-timeout');
  if (outcome.overflow) throw new SealError('worker-protocol');
  if (outcome.signal !== null || outcome.code !== 0) throw new SealError('worker-crashed');
  const reply = decodeReply(outcome.stdout, request.document.length);
  if (reply.status === 'refused') throw new SealError(reply.reason);
  validateSealed(request, reply);
  return reply;
}
