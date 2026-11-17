// SPDX-License-Identifier: Apache-2.0
//
// Isolated PDF parse service (T033). Upload validation (T007/T034) and composition (T036)
// call parsePdf(); the parser itself runs only in a sandboxed child process:
//
// - Input: a byte array or an async iterable of chunks (for example a request stream). The
//   10 MiB streaming cap is enforced while reading: the first chunk that would exceed it
//   ends the read (the iterator is closed, so a stream is destroyed) and the outcome is
//   413 payload_too_large before the body is read in full or a child is started. The
//   child receives the bytes over its stdin pipe.
// - Child: /bin/sh sets RLIMIT_CPU (`ulimit -t`, a kernel backstop inherited through the
//   launcher) and execs the sandbox launcher (sandbox.ts), which runs the pinned Node with
//   --max-old-space-size, --permission with read access to the worker sources only (no
//   fs-write, child-process, worker, addon or WASI grant) and
//   --disallow-code-generation-from-strings, under an empty environment.
// - Sandbox (A-009 LBR-1): user, network, mount, IPC, UTS and PID namespaces, a minimal
//   read-only root (library directories, the Node binary and the worker's files only),
//   no capabilities. IP connects fail (only a down loopback exists), host abstract sockets
//   are unreachable (other network namespace) and host pathname sockets do not exist in
//   the root. See sandbox.ts for exactly what is and is not provided.
// - Limits: the parent polls /proc for the launcher and every process below it, and kills
//   the sandbox when its CPU time or resident memory exceeds the limit, or at the wall-clock
//   limit, which is armed at spawn and so covers sandbox start-up. A V8 heap exhaustion is
//   detected from the child's exit. Every kill is a 422 resource-limit rejection.
// - A decided kill ends the whole sandbox (A-010 PL11-ESC). The launcher is the service's own
//   child, spawned as it always was, in the service's process group and session. Each child of
//   the launcher is the init of the sandbox's PID namespace: bwrap's, or the process unshare
//   forks. Under bwrap, --new-session runs in that init, which leads its own session and process
//   group; the worker is the init's child, in its namespace, session and group. The kill uses no
//   group or session membership. It first stops the launcher (SIGSTOP). A stopped process can
//   neither fork nor reap, so its children are then complete, and each child's pid stays
//   allocated to that child. The kill captures and kills each child, then kills the launcher.
//   An init's death ends every process in its namespace, and nothing can start after the
//   decision: the stopped launcher cannot fork, and a killed child cannot either.
// - The launcher is SIGKILLed only once it is observed stopped, or after it has exited, so it
//   is never left stopped and never killed while it could still fork unseen (A-010 request #20).
//   If its stop is still pending after STOP_GRACE_MS (in practice, uninterruptible sleep), every
//   poll tick captures its children again and kills each through its identity: a live launcher
//   keeps its children capturable, because a child is reparented only when its parent exits.
//   Such a launcher delays the kill, and so settlement, until it stops or exits (PL11-ESC-LIM
//   (6)). parseStopsPastCap() is a read-only, process-wide count of stops still pending after
//   the cap (A-010 request #21). While the stop is pending, the launcher can reap a child between
//   capture and kill: the identity re-check runs immediately before each kill (PL11-ESC-LIM (1)).
// - Ownership lease: an identity captured while ownership is proven. The launcher is signalled
//   only while Node has not reaped it: until then its pid cannot be reused, because Linux keeps a
//   pid while its task, live or zombie, holds it. A child of the launcher is captured only while
//   the launcher is unreaped. Capture opens a handle on /proc/<pid> and reads, through that
//   handle, the child's parent (it must be the launcher) and its start time. The handle names
//   that one process: reads through it fail once the process is reaped, even if its pid is
//   reused. A captured process is signalled only when its handle shows it alive and its pid
//   still shows the same start time.
// - Orphans: a captured child still alive after the launcher has ended (it exited or was
//   killed first) is ended through its identity. parseOrphans() is a read-only, process-wide
//   count of those ends (A-010 request #15).
// - parsePdf() settles only once the sandbox is gone: the child's stdio has closed, a decided
//   kill has sent all its signals, and every captured child has terminated: reaped, or a zombie
//   whose thread count is 1, both read through its handle (A-010 request #20). A zombie leader
//   alone is not enough: the leader of a multithreaded process (util-linux's init is the Node
//   worker) can be a zombie while its other threads still run. An exiting PID-namespace init
//   first kills, and waits for, every other task of its namespace, so a terminated init means
//   its worker is gone.
// - Fail closed: without a launcher whose isolation the probe confirms, parsePdf() returns
//   500 internal, reason sandbox-unavailable, and starts no child. The one exception is the
//   explicit development opt-in OPENSIG_PARSER_ALLOW_UNSANDBOXED=1, read from the process
//   environment only and honoured only when no launcher is usable on the host;
//   OPENSIG_ENV and NODE_ENV are never consulted.
// - No caller-supplied option can choose the launcher, the environment or the worker
//   (LBR-3): parsePdf() accepts `limits` and `service` only and refuses anything else.
//   createParseServiceForTests() exists for the tests; its options can only narrow the
//   launchers (a narrowed set that is unusable refuses), replace the worker inside the
//   same sandbox, or apply one test-only launch seam (PL-26: a held start-up, a launcher that
//   ends first, a channel to the worker, or a launcher held unstopped while it forks a late
//   child), and never downgrade or relabel it.
// - Every outcome carries `network_sandbox`: `netns+fs-enforced (local)` or `unavailable`.
//   That is the locally observed capability; it never claims the production gate
//   `parser-network-sandbox` passed (that gate needs deployment-environment evidence).
// - The parent never trusts the child (P09, LBR-4): a report must be well formed, with
//   1..maxPages pages numbered in order, finite positive sizes matching the boxes, a rotate
//   of 0/90/180/270, crop box equal to media box, the isolation flags the permission model
//   guarantees, a byte count equal to the input length, a bounded trailer and objects map
//   whose references are consistent, and reported objects that pass the active-content
//   policy (policy.ts). Anything else is a fail-closed 500 service-failure.
// - Report budget (A-010 LBR3-1): the report is bounded in bytes and in JSON values by
//   reportBudget() (limits.ts), derived from the parser limits. The child refuses a document
//   whose report would exceed it (422 limit-exceeded); the parent stops reading a longer
//   report and stops converting one with more values, and fails closed (500 service-failure).
//   At the 10 MiB input ceiling that keeps one maximal report under 128 MiB of parent memory.
// - Concurrency (A-010 LBR3-1, LBR4-1). Parse slots: at most MAX_CONCURRENT_PARSES children
//   run, and have their reports decoded, at once; up to MAX_WAITING_PARSES more parses wait
//   for a slot in FIFO order; when that queue is full a parse is refused at once, before its
//   input is read: 429 rate_limited, reason parse-capacity. parseAdmissions() is a read-only,
//   bounded record of arrival tickets in admission order (PL24-ORC). A parse takes its slot only once
//   its input is fully buffered within maxBytes, so a slow body never holds a slot and a
//   composition (an in-memory input) never waits behind a body that is still arriving.
//   Body reads: a streamed input is read only under one of MAX_CONCURRENT_BODY_READS read
//   permits, held while it is read and while the buffered input waits for its slot, so the
//   memory of buffered uploads stays bounded. When every permit is held, a streamed parse is
//   refused at once, before its input is read: 429 rate_limited, reason body-read-capacity
//   (refused, not queued, so an upload never waits behind slow senders). Every path releases
//   what it holds: a completed parse, a rejection, a 413, a refusal, or a client abort (the
//   input iterator throws; parsePdf() rethrows that error).
// - The PL-12 import boundary (src/pdf/ imports no net, http, https, dns, tls, dgram or
//   http2 module) stays as defence in depth; it is not the isolation.
//
// Linux only (the pinned runtime is linux-x64).

import { Buffer } from 'node:buffer';
import { spawn, type ChildProcessByStdio, type StdioOptions } from 'node:child_process';
import { createHash } from 'node:crypto';
import { closeSync, lstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, sep } from 'node:path';
import type { Duplex, Readable, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';

import { REJECT_REASONS, type RejectReason } from './errors.ts';
import { isDict, isRef, type PdfDict, type PdfValue } from './lexer.ts';
import {
  DEFAULT_PARSER_LIMITS,
  MAX_DOCUMENT_PAGES,
  reportBudget,
  resolveParserLimits,
  resolveServiceLimits,
  type ParserLimits,
  type ServiceLimits,
} from './limits.ts';
import type { PageReport, ParseReport } from './parser.ts';
import { classifyValue, createFindings } from './policy.ts';
import {
  descendants,
  LAUNCHER_KINDS,
  launcherCommand,
  probeSandbox,
  rootBinds,
  sourceFiles,
  type LauncherKind,
  type SandboxProbe,
} from './sandbox.ts';

export type { PageReport, ParseReport } from './parser.ts';
export type { LauncherKind, SandboxProbe } from './sandbox.ts';

export const WORKER_ENTRY = join(dirname(fileURLToPath(import.meta.url)), 'worker.ts');
const SHELL = '/bin/sh';
const POLL_MS = 10;
const RESCAN_MS = 50;
const CLOCK_TICKS_PER_SECOND = 100;
const PAGE_BYTES = 4096;
const MAX_STDERR_BYTES = 64 * 1024;
/** Exit statuses a launcher reports for a child killed by SIGKILL or SIGXCPU. */
const KILLED_EXIT_CODES = new Set([128 + 9, 128 + 24]);

/** The locally observed isolation of the parse child. */
export type NetworkSandboxLabel = 'netns+fs-enforced (local)' | 'unavailable';
export const SANDBOX_ENFORCED: NetworkSandboxLabel = 'netns+fs-enforced (local)';
export const SANDBOX_UNAVAILABLE: NetworkSandboxLabel = 'unavailable';
/** The only switch that permits an unsandboxed child, and only when no launcher is usable. */
export const UNSANDBOXED_FLAG = 'OPENSIG_PARSER_ALLOW_UNSANDBOXED';

export interface Isolation {
  permission_model: boolean;
  fs_write: boolean;
  child_process: boolean;
  worker: boolean;
  environment: string[];
}

export interface ServiceReport extends ParseReport {
  /** SHA-256 (lowercase hex) of the exact bytes parsed. */
  digest: string;
  /** Permission state the child observed, and the names (never values) of its environment variables. */
  isolation: Isolation;
  /** Locally observed isolation (never a claim about the production gate). */
  network_sandbox: NetworkSandboxLabel;
}

export type ParseOutcome =
  | { ok: true; status: 200; report: ServiceReport; network_sandbox: NetworkSandboxLabel }
  | {
      ok: false;
      status: 413 | 422 | 429 | 500;
      code: 'payload_too_large' | 'unsupported_pdf' | 'rate_limited' | 'internal';
      reason: RejectReason | 'service-failure' | 'sandbox-unavailable' | 'parse-capacity' | 'body-read-capacity';
      detail: string;
      detections: string[];
      network_sandbox: NetworkSandboxLabel;
    };

/** How the service runs the child on this host. */
export interface ServicePlan {
  readonly mode: 'sandboxed' | 'unsandboxed' | 'refused';
  readonly network_sandbox: NetworkSandboxLabel;
  readonly probe: SandboxProbe;
}

export interface ParseOptions {
  limits?: Partial<ParserLimits>;
  service?: Partial<ServiceLimits>;
}

const PARSE_OPTION_KEYS = new Set(['limits', 'service']);

function reject(reason: RejectReason, detail: string, label: NetworkSandboxLabel, detections: string[] = []): ParseOutcome {
  if (reason === 'size-limit') return { ok: false, status: 413, code: 'payload_too_large', reason, detail, detections, network_sandbox: label };
  return { ok: false, status: 422, code: 'unsupported_pdf', reason, detail, detections, network_sandbox: label };
}

function failure(detail: string, label: NetworkSandboxLabel): ParseOutcome {
  return { ok: false, status: 500, code: 'internal', reason: 'service-failure', detail, detections: [], network_sandbox: label };
}

// --- concurrency ---------------------------------------------------------------------------

/** Parse children that run, and have their reports decoded, at once (A-010 LBR3-1). */
export const MAX_CONCURRENT_PARSES = 2;
/** Parses that may wait for a slot; one more is refused with 429 rate_limited. */
export const MAX_WAITING_PARSES = 32;

/** Admissions kept in the read-only admission record (A-010 PL24-ORC). */
export const ADMISSION_RECORD_SIZE = 128;

interface Waiter {
  readonly ticket: number;
  readonly admit: () => void;
}

/**
 * The parse gate. Every parse that enters it (takes a slot at once or joins the queue) draws
 * the next arrival ticket; a refused parse draws none. `admitted` records the tickets in the
 * order their slots were granted, keeping the last ADMISSION_RECORD_SIZE. The record only
 * observes: it changes nothing about who gets a slot or when.
 */
const gate = { running: 0, waiting: [] as Waiter[], nextTicket: 0, admitted: [] as number[] };

function recordAdmission(ticket: number): void {
  gate.admitted.push(ticket);
  if (gate.admitted.length > ADMISSION_RECORD_SIZE) gate.admitted.shift();
}

/** Take a slot, or join the FIFO queue for one; null when the queue is full. */
function acquireSlot(): Promise<void> | null {
  if (gate.running < MAX_CONCURRENT_PARSES) {
    gate.running += 1;
    recordAdmission(gate.nextTicket++);
    return Promise.resolve();
  }
  if (gate.waiting.length >= MAX_WAITING_PARSES) return null;
  const ticket = gate.nextTicket++;
  return new Promise<void>((resolveSlot) => gate.waiting.push({ ticket, admit: resolveSlot }));
}

/** Pass the slot to the oldest waiting parse, or free it. */
function releaseSlot(): void {
  const next = gate.waiting.shift();
  if (next !== undefined) {
    recordAdmission(next.ticket);
    next.admit();
  } else {
    gate.running -= 1;
  }
}

/** Current use of the parse slots (read-only; for monitoring and the tests). */
export function parseCapacity(): { running: number; waiting: number; max_concurrent: number; max_waiting: number } {
  return { running: gate.running, waiting: gate.waiting.length, max_concurrent: MAX_CONCURRENT_PARSES, max_waiting: MAX_WAITING_PARSES };
}

/**
 * The admission record (read-only; for monitoring and the tests, A-010 PL24-ORC): the ticket
 * the next parse to enter the gate will draw, and the tickets of the last admissions in the
 * order their slots were granted (at most ADMISSION_RECORD_SIZE). A frozen copy.
 */
export function parseAdmissions(): { readonly next_ticket: number; readonly admitted: readonly number[]; readonly max_records: number } {
  return Object.freeze({ next_ticket: gate.nextTicket, admitted: Object.freeze([...gate.admitted]), max_records: ADMISSION_RECORD_SIZE });
}

/** Captured children ended because they outlived their launcher, over every parse child (A-010 PL11-ESC). */
const orphanRecord = { ended: 0 };

/**
 * The orphan record (read-only; for monitoring and the tests, A-010 PL11-ESC, request #15): how
 * many captured children this process has ended because they outlived their launcher. Each
 * end counts once, exactly as in that child's lifecycle `orphans_ended`. A frozen copy.
 */
export function parseOrphans(): { readonly orphans_ended: number } {
  return Object.freeze({ orphans_ended: orphanRecord.ended });
}

/** Decided kills whose launcher stop was still pending after STOP_GRACE_MS, over every parse child (A-010 PL11-ESC). */
const stopRecord = { pastCap: 0 };

/**
 * The stop record (read-only; for monitoring and the tests, A-010 PL11-ESC, request #21): how many
 * decided kills in this process found the launcher still unstopped after STOP_GRACE_MS. Each such
 * kill counts once, exactly as its lifecycle `stop_past_cap`. A frozen copy.
 */
export function parseStopsPastCap(): { readonly stops_past_cap: number } {
  return Object.freeze({ stops_past_cap: stopRecord.pastCap });
}

/** True when a parse arriving now would find every slot taken and the queue full. */
function parseQueueFull(): boolean {
  return gate.running >= MAX_CONCURRENT_PARSES && gate.waiting.length >= MAX_WAITING_PARSES;
}

/** Streamed inputs read (or buffered and waiting for a slot) at once (A-010 LBR4-1). */
export const MAX_CONCURRENT_BODY_READS = 4;

const bodyReads = { held: 0 };

/** Take a body-read permit; false when every permit is held. */
function acquireBodyRead(): boolean {
  if (bodyReads.held >= MAX_CONCURRENT_BODY_READS) return false;
  bodyReads.held += 1;
  return true;
}

function releaseBodyRead(): void {
  bodyReads.held -= 1;
}

/** Current use of the body-read permits (read-only; for monitoring and the tests). */
export function bodyReadCapacity(): { held: number; max: number } {
  return { held: bodyReads.held, max: MAX_CONCURRENT_BODY_READS };
}

function rateLimited(reason: 'parse-capacity' | 'body-read-capacity', label: NetworkSandboxLabel): ParseOutcome {
  const detail =
    reason === 'parse-capacity'
      ? `${MAX_CONCURRENT_PARSES} parses are running and ${MAX_WAITING_PARSES} are waiting`
      : `${MAX_CONCURRENT_BODY_READS} uploads are being read`;
  return { ok: false, status: 429, code: 'rate_limited', reason, detail, detections: [], network_sandbox: label };
}

// --- plan --------------------------------------------------------------------------------

/**
 * Decide how the child runs, probing only `kinds`. The development opt-in is honoured
 * only when the full launcher set is unusable on this host, so narrowing `kinds` can
 * refuse but never downgrade.
 */
async function planFor(kinds: readonly LauncherKind[]): Promise<ServicePlan> {
  const probe = await probeSandbox(kinds);
  if (probe.available) return Object.freeze({ mode: 'sandboxed', network_sandbox: SANDBOX_ENFORCED, probe });
  const host = kinds.length === LAUNCHER_KINDS.length && kinds.every((kind, index) => kind === LAUNCHER_KINDS[index]) ? probe : await probeSandbox(LAUNCHER_KINDS);
  const mode = !host.available && process.env[UNSANDBOXED_FLAG] === '1' ? 'unsandboxed' : 'refused';
  return Object.freeze({ mode, network_sandbox: SANDBOX_UNAVAILABLE, probe });
}

/** The production plan for this host (probed once per process). */
export function parseServicePlan(): Promise<ServicePlan> {
  return planFor(LAUNCHER_KINDS);
}

// --- child command -------------------------------------------------------------------------

/** The child command before sandboxing: file and argv (no shell interpolation of values). */
export function workerCommand(parser: ParserLimits, service: ServiceLimits, entry: string = WORKER_ENTRY): { file: string; args: string[] } {
  const cpuSeconds = Math.ceil(service.cpuMs / 1000) + 1;
  const readable = `${dirname(entry)}${sep}`;
  return {
    file: SHELL,
    args: [
      '-c',
      'ulimit -t "$1" || exit 70; shift; exec "$@"',
      'opensig-pdf-parse',
      String(cpuSeconds),
      process.execPath,
      `--max-old-space-size=${service.heapMiB}`,
      '--permission',
      `--allow-fs-read=${readable}`,
      '--disallow-code-generation-from-strings',
      entry,
      JSON.stringify(parser),
    ],
  };
}

/** The read-only files a worker entry needs: the worker sources, or a single test entry. */
function workerFiles(entry: string): string[] {
  return entry === WORKER_ENTRY ? sourceFiles(dirname(WORKER_ENTRY)) : [entry];
}

/** The exact command the service runs under `plan` (null when the plan refuses). */
export function serviceCommand(plan: ServicePlan, parser: ParserLimits, service: ServiceLimits, entry: string = WORKER_ENTRY): { file: string; args: string[] } | null {
  if (plan.mode === 'refused') return null;
  if (plan.mode === 'unsandboxed') return workerCommand(parser, service, entry);
  const real = realpathSync(entry);
  const base = workerCommand(parser, service, real);
  const [node, ...nodeArgs] = base.args.slice(4);
  const wrapped = launcherCommand(plan.probe, rootBinds(workerFiles(entry).map((file) => (file === entry ? real : file))), node as string, nodeArgs);
  return { file: SHELL, args: [...base.args.slice(0, 4), wrapped.file, ...wrapped.args] };
}

/**
 * The service's sandbox launcher for an arbitrary command (used by the isolation tests):
 * the same launcher and root as the worker, plus `extraFiles` bound read-only.
 */
export function sandboxedCommand(probe: SandboxProbe, file: string, args: readonly string[], extraFiles: readonly string[] = []): { file: string; args: string[] } {
  return launcherCommand(probe, rootBinds([], extraFiles), file, args);
}

async function collect(input: Uint8Array | AsyncIterable<Uint8Array | string>, maxBytes: number): Promise<Buffer | { tooLarge: number }> {
  if (input instanceof Uint8Array) {
    if (input.length > maxBytes) return { tooLarge: input.length };
    return Buffer.from(input.buffer, input.byteOffset, input.length);
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of input) {
    const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : Buffer.from(chunk.buffer, chunk.byteOffset, chunk.length);
    if (total + buffer.length > maxBytes) return { tooLarge: total + buffer.length };
    total += buffer.length;
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, total);
}

function sample(pid: number): { cpuMs: number; rssBytes: number } | null {
  let text: string;
  try {
    text = readFileSync(`/proc/${pid}/stat`, 'latin1');
  } catch {
    return null;
  }
  const fields = text.slice(text.lastIndexOf(')') + 2).split(' ');
  const utime = Number(fields[11]);
  const stime = Number(fields[12]);
  const rss = Number(fields[21]);
  if (!Number.isFinite(utime) || !Number.isFinite(stime) || !Number.isFinite(rss)) return null;
  return { cpuMs: ((utime + stime) * 1000) / CLOCK_TICKS_PER_SECOND, rssBytes: rss * PAGE_BYTES };
}

// --- child report validation (never trust the child) ---------------------------------------

type ChildResult =
  | { ok: true; report: ParseReport & { isolation: Isolation } }
  | { ok: false; reason: RejectReason; detail: string; detections: string[] };

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const isCount = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const isPositive = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value > 0;
const isShortString = (value: unknown, max: number): value is string => typeof value === 'string' && value.length <= max;
const isStringList = (value: unknown, maxItems: number, maxLength: number): value is string[] =>
  Array.isArray(value) && value.length <= maxItems && value.every((item) => isShortString(item, maxLength));
const hasExactly = (record: Record<string, unknown>, keys: readonly string[]): boolean => {
  const own = Object.keys(record);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(record, key));
};

function isRefPair(value: unknown, size: number): value is [number, number] {
  return Array.isArray(value) && value.length === 2 && isCount(value[0]) && value[0] >= 1 && value[0] < size && isCount(value[1]) && value[1] <= 65535;
}

function isBox(value: unknown): value is [number, number, number, number] {
  return (
    Array.isArray(value) &&
    value.length === 4 &&
    value.every((n) => typeof n === 'number' && Number.isFinite(n)) &&
    (value[2] as number) > (value[0] as number) &&
    (value[3] as number) > (value[1] as number)
  );
}

function validPage(value: unknown, index: number, size: number): value is PageReport {
  if (!isObject(value) || !hasExactly(value, ['number', 'width', 'height', 'rotate', 'media_box', 'crop_box', 'ref'])) return false;
  const { number, width, height, rotate, media_box: media, crop_box: crop, ref } = value;
  if (number !== index + 1 || !isPositive(width) || !isPositive(height)) return false;
  if (rotate !== 0 && rotate !== 90 && rotate !== 180 && rotate !== 270) return false;
  if (!isBox(media) || !isBox(crop) || !media.every((n, i) => n === crop[i])) return false;
  const boxWidth = crop[2] - crop[0];
  const boxHeight = crop[3] - crop[1];
  const [shownWidth, shownHeight] = rotate % 180 === 0 ? [boxWidth, boxHeight] : [boxHeight, boxWidth];
  if (width !== shownWidth || height !== shownHeight) return false;
  return isRefPair(ref, size);
}

function validIsolation(value: unknown): value is Isolation {
  return (
    isObject(value) &&
    value.permission_model === true &&
    value.fs_write === false &&
    value.child_process === false &&
    value.worker === false &&
    isStringList(value.environment, 16, 64)
  );
}

/**
 * Convert a reported JSON value (parser.ts toJson form) back to a PDF value, or undefined if
 * it is not one. The bounds are the parser's own, so an honest report always converts
 * (LBR2-1): nesting up to the parser's maxDepth; names, strings and arrays of any length
 * (the report as a whole is capped at reportBudget().bytes); references with any object
 * number of at least 1, because a reference to an object outside the file is legal and means
 * null. Each value takes one node from `budget`, exactly as the child counts them (parser.ts
 * toJson); past the budget the conversion stops (LBR3-1).
 */
function fromJson(value: unknown, maxDepth: number, budget: { nodes: number }, depth = 0): PdfValue | undefined {
  budget.nodes -= 1;
  if (budget.nodes < 0 || depth > maxDepth) return undefined;
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (Array.isArray(value)) {
    const items: PdfValue[] = [];
    for (const item of value) {
      const converted = fromJson(item, maxDepth, budget, depth + 1);
      if (converted === undefined) return undefined;
      items.push(converted);
    }
    return items;
  }
  if (!isObject(value)) return undefined;
  const keys = Object.keys(value);
  if (keys.length !== 1) return undefined;
  if (typeof value.name === 'string') return { t: 'name', v: value.name };
  if (typeof value.hex === 'string') {
    const hex = value.hex;
    return hex.length % 2 === 0 && /^[0-9a-f]*$/.test(hex) ? { t: 'str', v: Buffer.from(hex, 'hex') } : undefined;
  }
  if (value.ref !== undefined) {
    const ref = value.ref;
    return Array.isArray(ref) && ref.length === 2 && isCount(ref[0]) && ref[0] >= 1 && isCount(ref[1]) && ref[1] <= 65535
      ? { t: 'ref', num: ref[0], gen: ref[1] }
      : undefined;
  }
  if (isObject(value.dict)) {
    const map = new Map<string, PdfValue>();
    for (const [key, inner] of Object.entries(value.dict)) {
      const converted = fromJson(inner, maxDepth, budget, depth + 1);
      if (converted === undefined) return undefined;
      map.set(key, converted);
    }
    return { t: 'dict', map };
  }
  return undefined;
}

/** A reference that may point outside the file (legal; it means null). */
function isAnyRefPair(value: unknown): value is [number, number] {
  return Array.isArray(value) && value.length === 2 && isCount(value[0]) && value[0] >= 1 && isCount(value[1]) && value[1] <= 65535;
}

function validTrailer(value: unknown, size: number): value is ParseReport['trailer'] {
  if (!isObject(value) || !hasExactly(value, ['root', 'info', 'id'])) return false;
  if (!isRefPair(value.root, size)) return false;
  if (value.info !== null && !isAnyRefPair(value.info)) return false;
  if (value.id === null) return true;
  return Array.isArray(value.id) && value.id.length === 2 && value.id.every((part) => typeof part === 'string' && part.length % 2 === 0 && /^[0-9a-f]*$/.test(part));
}

/** Shape, bounds, references and policy of the reported objects map (LBR-4); returns the catalog. */
function validObjects(report: Record<string, unknown>, pages: PageReport[], size: number, maxDepth: number, maxNodes: number): PdfDict | null {
  const objects = report.objects;
  if (!isObject(objects)) return null;
  const entries = Object.entries(objects);
  if (entries.length > 3 + 2 * pages.length) return null;
  const converted = new Map<number, { gen: number; value: PdfValue }>();
  const budget = { nodes: maxNodes };
  for (const [key, entry] of entries) {
    // Any object number the cross-reference covers (every entry is below /Size).
    if (!/^[1-9]\d*$/.test(key) || !Number.isSafeInteger(Number(key)) || Number(key) >= size) return null;
    if (!isObject(entry) || !hasExactly(entry, ['gen', 'value']) || !isCount(entry.gen) || entry.gen > 65535) return null;
    const value = fromJson(entry.value, maxDepth, budget);
    if (value === undefined) return null;
    converted.set(Number(key), { gen: entry.gen, value });
  }
  const dictAt = (ref: [number, number], type: string): PdfDict | null => {
    const found = converted.get(ref[0]);
    if (found === undefined || found.gen !== ref[1] || !isDict(found.value)) return null;
    const typeValue = found.value.map.get('Type');
    return typeValue !== undefined && typeValue !== null && !Array.isArray(typeValue) && typeof typeValue === 'object' && typeValue.t === 'name' && typeValue.v === type
      ? found.value
      : null;
  };
  const trailer = report.trailer as ParseReport['trailer'];
  const catalog = dictAt(trailer.root, 'Catalog');
  if (catalog === null) return null;
  const seen = new Set<number>();
  for (const page of pages) {
    if (seen.has(page.ref[0]) || dictAt(page.ref, 'Page') === null) return null;
    seen.add(page.ref[0]);
  }
  // The reported objects must pass the same active-content and signature policy.
  const findings = createFindings();
  const resolve = (value: PdfValue | undefined): PdfValue | undefined => {
    if (!isRef(value)) return value;
    const found = converted.get(value.num);
    return found !== undefined && found.gen === value.gen ? found.value : undefined;
  };
  for (const { value } of converted.values()) classifyValue(value, resolve, findings);
  return findings.active.size === 0 && findings.signatures === 0 ? catalog : null;
}

const KNOWN_FEATURES = new Set(['acroform', 'incremental-updates', 'hybrid-xref', 'object-streams', 'xref-stream', 'jbig2', 'jpx', 'unsigned-signature-field']);
const STATS_KEYS = ['objects', 'object_streams', 'max_depth', 'inflated_bytes'];

/** Known feature names only, and those the report itself determines must agree with it. */
function validFeatures(features: string[], xref: Record<string, unknown>, stats: Record<string, unknown>, catalog: PdfDict): boolean {
  if (new Set(features).size !== features.length || !features.every((feature) => KNOWN_FEATURES.has(feature))) return false;
  const acroform = catalog.map.get('AcroForm');
  return (
    features.includes('acroform') === (acroform !== undefined && acroform !== null) &&
    features.includes('incremental-updates') === (xref.sections as number) > 1 &&
    features.includes('hybrid-xref') === xref.hybrid &&
    features.includes('object-streams') === (stats.object_streams as number) > 0
  );
}

/**
 * Validate the child's result against the input it was given. Returns null for anything
 * that is not exactly a well-formed rejection or a consistent report. `maxDepth` and
 * `maxNodes` are the parser's nesting limit and the report node budget (reportBudget).
 */
export function validateChildResult(
  value: unknown,
  inputBytes: number,
  maxPages: number,
  maxDepth: number = DEFAULT_PARSER_LIMITS.maxDepth,
  maxNodes: number = reportBudget(DEFAULT_PARSER_LIMITS).nodes,
): ChildResult | null {
  if (!isObject(value)) return null;
  if (value.ok === false) {
    const { reason, detail, detections } = value;
    if (typeof reason !== 'string' || !(REJECT_REASONS as readonly string[]).includes(reason) || !isShortString(detail, 200)) return null;
    const list = detections === undefined ? [] : detections;
    if (!isStringList(list, 32, 64)) return null;
    return { ok: false, reason: reason as RejectReason, detail, detections: [...list] };
  }
  if (value.ok !== true || !isObject(value.report)) return null;
  const report = value.report;
  if (!hasExactly(report, ['schema', 'header_version', 'bytes', 'pages', 'xref', 'trailer', 'objects', 'features', 'stats', 'isolation'])) return null;
  if (report.schema !== 'opensig.pdf.parse-report.v1') return null;
  if (report.bytes !== inputBytes) return null;
  if (typeof report.header_version !== 'string' || !/^(?:1\.[0-7]|2\.0)$/.test(report.header_version)) return null;
  const xref = report.xref;
  if (!isObject(xref) || !hasExactly(xref, ['kind', 'sections', 'startxref', 'size', 'hybrid'])) return null;
  if ((xref.kind !== 'table' && xref.kind !== 'stream') || !isCount(xref.sections) || !isCount(xref.startxref) || !isCount(xref.size) || xref.size < 2) return null;
  if (typeof xref.hybrid !== 'boolean') return null;
  const size = xref.size;
  const pages = report.pages;
  const ceiling = Math.min(maxPages, MAX_DOCUMENT_PAGES);
  if (!Array.isArray(pages) || pages.length < 1 || pages.length > ceiling || !pages.every((page, index) => validPage(page, index, size))) return null;
  if (!validTrailer(report.trailer, size)) return null;
  if (!isObject(report.stats) || !hasExactly(report.stats, STATS_KEYS) || !Object.values(report.stats).every((n) => isCount(n))) return null;
  if (!isStringList(report.features, 64, 64)) return null;
  if (!validIsolation(report.isolation)) return null;
  const catalog = validObjects(report, pages as PageReport[], size, maxDepth, maxNodes);
  if (catalog === null || !validFeatures(report.features, xref, report.stats, catalog)) return null;
  return { ok: true, report: report as unknown as ParseReport & { isolation: Isolation } };
}

// --- parse -----------------------------------------------------------------------------------

interface Runner {
  readonly kinds: readonly LauncherKind[];
  readonly entry: string;
  readonly hooks: ChildHooks;
}

/** One parse child's lifecycle as the parent saw it (tests only; A-010 PL11-ESC, PL-26). */
export interface ChildLifecycle {
  /** The kill the parent decided, or null if it decided none. */
  readonly kill: 'cpu' | 'memory' | 'wall-time' | 'report-size' | null;
  /** Bytes the parent read from the child's stdout and stderr after it decided that kill. */
  readonly output_after_kill: number;
  /** Captured children ended because they outlived the launcher (the orphan path). */
  readonly orphans_ended: number;
  /**
   * Milliseconds from stopping the launcher to signalling the sandbox, or null when the launcher
   * was not stopped (no decided kill, or the launcher had already ended).
   */
  readonly stop_ms: number | null;
  /** The launcher's stop was still pending after STOP_GRACE_MS (A-010 request #20). */
  readonly stop_past_cap: boolean;
  /**
   * How the launcher ended after a decided kill: SIGKILLed once observed stopped ('stopped'), or
   * it had already exited ('exited', so it was not signalled); null without a decided kill.
   */
  readonly launcher_kill: 'stopped' | 'exited' | null;
  /** Every captured child the service SIGKILLed through its identity, in order. */
  readonly killed: readonly { readonly pid: number; readonly start: string }[];
  /** With the late-fork seam: the pid of the late child the held launcher reported, else null. */
  readonly late_child: number | null;
}

/**
 * Test-only launch seams (createParseServiceForTests; PL-26). Production has none.
 * - hold-startup: the launch forks a start-up stage that waits on fd 3 and only then execs the
 *   launcher. The service lets it go on only after a decided kill has sent all its signals.
 * - orphan-launcher: the same held start-up. As soon as the stage's identity has been captured,
 *   the service kills the launcher alone, so the stage outlives it as an orphan.
 * - channel: fd 3 passes through the unchanged launch into the sandbox, to the worker, so a
 *   test can synchronize with the worker.
 * - late-fork: a held launcher that forks one child at once and waits on fd 3. On a decided
 *   kill the service does not stop it at once: it tells it (fd 3) to fork a late child, and
 *   waits for it to report that child; only then does the stop clock start, and the stop itself
 *   is sent only after twice STOP_GRACE_MS. So the launcher stays unstopped past the cap with a
 *   child the service has not captured (A-010 request #20).
 */
export type LaunchSeam = 'hold-startup' | 'orphan-launcher' | 'channel' | 'late-fork';
const LAUNCH_SEAMS: readonly LaunchSeam[] = Object.freeze(['hold-startup', 'orphan-launcher', 'channel', 'late-fork']);

interface ChildHooks {
  readonly seam: LaunchSeam | null;
  /** Receives the child's lifecycle when its outcome settles. */
  readonly observe: ((lifecycle: ChildLifecycle) => void) | null;
  /** Receives fd 3 of a child launched with the channel seam. */
  readonly channel: ((stream: Duplex) => void) | null;
}

const NO_HOOKS: ChildHooks = Object.freeze({ seam: null, observe: null, channel: null });

/**
 * The held launch script (hold-startup and orphan-launcher). The shell forks a start-up stage
 * that blocks reading fd 3 and only then execs the launcher, and the shell waits for it. The
 * ulimit, the launcher, the sandbox and the worker are the production ones. fd 3 never reaches
 * the launcher, and the stage gives it the child's stdin back (fd 4), since a background job
 * of a non-interactive shell starts with stdin from /dev/null. Unlike production, the launcher
 * inherits SIGINT and SIGQUIT ignored from that background job; the seams use SIGKILL only.
 */
const HELD_STARTUP_SCRIPT = 'ulimit -t "$1" || exit 70; shift; exec 4<&0; ( read -r line <&3; exec 0<&4 3<&- 4<&- "$@" ) & exec 3<&- 4<&-; wait $!';

/**
 * The late-fork launch script. The shell forks an early child, waits for a line on fd 3, then
 * forks a late child, reports its pid on fd 3, and waits on fd 3 again; it never exits by itself
 * while fd 3 is open. Both children close fd 3 and sleep 80 s, a containment above the tests'
 * hang guard: they never end within a test by themselves.
 */
const LATE_FORK_SCRIPT =
  'ulimit -t "$1" || exit 70; shift; ( exec 3<&-; exec /bin/sleep 80 ) & read -r line <&3; ( exec 3<&-; exec /bin/sleep 80 ) & echo "forked $!" >&3; read -r line <&3';

/** Lifecycles kept per test service (createParseServiceForTests). */
const LIFECYCLE_RECORDS = 16;
/** How long a decided kill waits for the launcher to stop before ending it through identities. */
const STOP_GRACE_MS = 100;

/** A child of the launcher, captured while ownership was proven (the ownership lease). */
interface Identity {
  readonly pid: number;
  /** Start time from /proc/<pid>/stat (clock ticks since boot): with the pid, it names one process. */
  readonly start: string;
  /** A handle on /proc/<pid>. Reads through it fail once that very process is reaped. */
  readonly fd: number;
}

interface ProcStat {
  readonly state: string;
  readonly ppid: number;
  readonly start: string;
}

function parseStat(text: string): ProcStat {
  const fields = text.slice(text.lastIndexOf(')') + 2).split(' ');
  return { state: fields[0] ?? '', ppid: Number(fields[1]), start: fields[19] ?? '' };
}

/** /proc/<pid>/stat looked up by number, or null. */
function statByPid(pid: number): ProcStat | null {
  try {
    return parseStat(readFileSync(`/proc/${pid}/stat`, 'latin1'));
  } catch {
    return null;
  }
}

/** /proc/<pid>/stat read through a captured handle, or null once that process has been reaped. */
function statByHandle(fd: number): ProcStat | null {
  try {
    return parseStat(readFileSync(`/proc/self/fd/${fd}/stat`, 'latin1'));
  } catch {
    return null;
  }
}

/** /proc/<pid>/status read through a captured handle, or null once that process has been reaped. */
function statusByHandle(fd: number): string | null {
  try {
    return readFileSync(`/proc/self/fd/${fd}/status`, 'latin1');
  } catch {
    return null;
  }
}

/**
 * The settle predicate (A-010 request #20), on /proc status text (null: reaped). Terminated means
 * reaped, or a zombie (or a dead task being released) whose thread count is 1. A zombie leader
 * with other threads still counted is a process that can still run. Missing fields never count.
 */
function terminatedFromStatus(status: string | null): boolean {
  if (status === null) return true;
  const state = /^State:\s+(\S)/m.exec(status)?.[1];
  const threads = /^Threads:\s+(\d+)\s*$/m.exec(status)?.[1];
  return (state === 'Z' || state === 'X') && threads === '1';
}

/** The settle predicate for a captured process, read through its handle. */
const terminatedByHandle = (fd: number): boolean => terminatedFromStatus(statusByHandle(fd));

/**
 * The children of `pid`, from its own /proc record; on a kernel without that record, from the
 * /proc scan the poller already uses.
 */
function childrenOf(pid: number): number[] {
  try {
    return readFileSync(`/proc/${pid}/task/${pid}/children`, 'latin1')
      .trim()
      .split(/\s+/)
      .filter((item) => item !== '')
      .map(Number);
  } catch {
    return descendants(pid).filter((child) => statByPid(child)?.ppid === pid);
  }
}

/** Capture `pid` as a child of `parent`: open its handle and confirm the parent through it. */
function captureIdentity(pid: number, parent: number): Identity | null {
  let fd: number;
  try {
    fd = openSync(`/proc/${pid}`, 'r');
  } catch {
    return null;
  }
  const stat = statByHandle(fd);
  if (stat === null || terminatedByHandle(fd) || stat.ppid !== parent) {
    closeSync(fd);
    return null;
  }
  return Object.freeze({ pid, start: stat.start, fd });
}

/**
 * SIGKILL a captured process, only if right now its handle shows it alive and its pid still
 * shows its start time. True when the signal was sent.
 */
function killIdentity(identity: Identity): boolean {
  if (terminatedByHandle(identity.fd)) return false;
  if (statByPid(identity.pid)?.start !== identity.start) return false;
  try {
    process.kill(identity.pid, 'SIGKILL');
    return true;
  } catch {
    return false;
  }
}

async function runParse(input: Uint8Array | AsyncIterable<Uint8Array | string>, options: ParseOptions, runner: Runner): Promise<ParseOutcome> {
  const parser = resolveParserLimits(options.limits);
  const service = resolveServiceLimits(options.service);
  const plan = await planFor(runner.kinds);
  const label = plan.network_sandbox;
  const command = serviceCommand(plan, parser, service, runner.entry);
  if (command === null) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      reason: 'sandbox-unavailable',
      detail: `no sandbox launcher is usable and ${UNSANDBOXED_FLAG}=1 is not set`,
      detections: [],
      network_sandbox: label,
    };
  }
  if (input instanceof Uint8Array && input.length > parser.maxBytes) return reject('size-limit', `more than ${parser.maxBytes} bytes`, label);
  if (parseQueueFull()) return rateLimited('parse-capacity', label);

  // A-010 LBR4-1: buffer a streamed input in full, under a body-read permit, before taking a
  // parse slot. The permit is held until the slot is taken (or the parse is refused).
  let bytes: Buffer;
  let permit = false;
  if (input instanceof Uint8Array) {
    bytes = Buffer.from(input.buffer, input.byteOffset, input.length);
  } else {
    if (!acquireBodyRead()) return rateLimited('body-read-capacity', label);
    permit = true;
    let collected: Buffer | { tooLarge: number };
    try {
      collected = await collect(input, parser.maxBytes);
    } catch (error) {
      releaseBodyRead();
      throw error;
    }
    if (!(collected instanceof Buffer)) {
      releaseBodyRead();
      return reject('size-limit', `more than ${parser.maxBytes} bytes`, label);
    }
    bytes = collected;
  }
  const slot = acquireSlot();
  if (slot === null) {
    if (permit) releaseBodyRead();
    return rateLimited('parse-capacity', label);
  }
  await slot;
  if (permit) releaseBodyRead();
  try {
    return await runChild(bytes, command, parser, service, label, runner.hooks);
  } finally {
    releaseSlot();
  }
}

/**
 * Run one parse child on `bytes` and validate its report; holds a parse slot throughout. The
 * outcome settles only once the whole sandbox is gone (see the header, A-010 PL11-ESC).
 */
function runChild(
  bytes: Buffer,
  { file, args }: { file: string; args: string[] },
  parser: ParserLimits,
  service: ServiceLimits,
  label: NetworkSandboxLabel,
  hooks: ChildHooks = NO_HOOKS,
): Promise<ParseOutcome> {
  const digest = createHash('sha256').update(bytes).digest('hex');
  const budget = reportBudget(parser);

  return new Promise<ParseOutcome>((resolveOutcome) => {
    const seam = hooks.seam;
    const held = seam === 'hold-startup' || seam === 'orphan-launcher';
    const stdio: StdioOptions = seam === null ? ['pipe', 'pipe', 'pipe'] : ['pipe', 'pipe', 'pipe', 'pipe'];
    const argv = held ? ['-c', HELD_STARTUP_SCRIPT, ...args.slice(2)] : seam === 'late-fork' ? ['-c', LATE_FORK_SCRIPT, ...args.slice(2)] : args;
    const child = spawn(file, argv, { cwd: dirname(WORKER_ENTRY), env: {}, stdio }) as ChildProcessByStdio<Writable, Readable, Readable>;
    // A seam's fd 3 (tests only). A socket error on it must never crash the service.
    const seamStream = seam === null ? null : (child.stdio[3] as Duplex | null);
    seamStream?.on('error', () => {
      // The seam's socket may reset when the sandbox dies.
    });
    if (seam === 'channel' && seamStream !== null) hooks.channel?.(seamStream);
    let killedFor: 'cpu' | 'memory' | 'wall-time' | 'report-size' | null = null;
    let outputAfterKill = 0;
    let orphansEnded = 0;
    let closed: { code: number | null; signal: NodeJS.Signals | null } | null = null;
    /** The launcher's children, captured while it was unreaped (the ownership lease). */
    const owned: Identity[] = [];
    /** A decided kill has started, and has sent every signal it will send. */
    let killing = false;
    let killSent = false;
    let stopTimer: ReturnType<typeof setTimeout> | null = null;
    let stopMs: number | null = null;
    let stopPastCap = false;
    let launcherKill: 'stopped' | 'exited' | null = null;
    /** Captured children SIGKILLed through their identity (the lifecycle record). */
    const killed: { readonly pid: number; readonly start: string }[] = [];
    let lateChild: number | null = null;
    let deferredStop: ReturnType<typeof setTimeout> | null = null;
    let seamFired = false;
    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let stderr = '';
    let settled = false;
    let tree: number[] = [];
    let scanned = 0;

    /** Node has not reaped the launcher, so its pid still names it (live or zombie). */
    const launcherUnreaped = (): boolean => child.pid !== undefined && child.exitCode === null && child.signalCode === null;
    /** Signal the launcher, only while Node has not reaped it. */
    const signalLauncher = (signal: NodeJS.Signals): void => {
      const launcher = child.pid;
      if (launcher === undefined || !launcherUnreaped()) return;
      try {
        process.kill(launcher, signal);
      } catch {
        // Unreachable while the launcher is unreaped.
      }
    };

    /** Capture each child of the unreaped launcher that is not captured yet. */
    const captureChildren = (): void => {
      const launcher = child.pid;
      if (launcher === undefined || !launcherUnreaped()) return;
      for (const pid of childrenOf(launcher)) {
        if (owned.some((identity) => identity.pid === pid && !terminatedByHandle(identity.fd))) continue;
        const identity = captureIdentity(pid, launcher);
        if (identity === null) continue;
        owned.push(identity);
        // PL-26 orphan-launcher seam: the launcher ends first, its captured child still alive.
        if (seam === 'orphan-launcher' && !seamFired) {
          seamFired = true;
          signalLauncher('SIGKILL');
        }
      }
    };
    /** Kill every captured process still alive, each through its identity; returns how many. */
    const killCaptured = (): number =>
      owned.reduce((count, identity) => {
        if (!killIdentity(identity)) return count;
        killed.push(Object.freeze({ pid: identity.pid, start: identity.start }));
        return count + 1;
      }, 0);
    /** The launcher has ended: kill each captured child still alive, and count it as an orphan. */
    const endOrphans = (): void => {
      const ended = killCaptured();
      orphansEnded += ended;
      orphanRecord.ended += ended;
    };
    /** A decided kill has sent every signal it will send. */
    const killComplete = (): void => {
      killSent = true;
      // PL-26 hold-startup seam: a held start-up may go on only now.
      if (seam === 'hold-startup') seamStream?.destroy();
      settleIfGone();
    };
    /**
     * PL-26 late-fork seam: the decided kill does not stop the launcher yet. It tells the held
     * launcher (fd 3) to fork a late child and waits for its report; the stop clock starts then,
     * and the stop itself is sent only after twice STOP_GRACE_MS.
     */
    const holdForLateFork = (stream: Duplex, awaitStop: (stopSent: number) => void): void => {
      let reply = '';
      stream.on('data', (chunk: Buffer) => {
        if (lateChild !== null) return;
        reply += chunk.toString('latin1');
        const match = /^forked (\d+)$/m.exec(reply);
        if (match === null) return;
        lateChild = Number(match[1]);
        deferredStop = setTimeout(() => {
          deferredStop = null;
          signalLauncher('SIGSTOP');
        }, 2 * STOP_GRACE_MS);
        awaitStop(Date.now());
      });
      stream.write('fork\n');
    };
    const kill = (reason: NonNullable<typeof killedFor>): void => {
      if (killedFor === null) killedFor = reason;
      if (killing) return;
      killing = true;
      const launcher = child.pid;
      if (launcher === undefined || !launcherUnreaped()) {
        launcherKill = 'exited';
        endOrphans();
        return killComplete();
      }
      /** Wait for the stop sent at `stopSent`; the launcher is SIGKILLed only once it is stopped. */
      const awaitStop = (stopSent: number): void => {
        const step = (): void => {
          stopTimer = null;
          const state = launcherUnreaped() ? statByPid(launcher)?.state : 'gone';
          if (state === 'gone' || state === 'Z' || state === 'X') {
            // The launcher exited meanwhile (reaped, or a zombie Node has not reaped yet): its
            // children were reparented when it exited, so the captured ones still alive are orphans.
            launcherKill = 'exited';
            endOrphans();
            return killComplete();
          }
          if (state === 'T' || state === 't') {
            // Stopped: the launcher can neither fork nor reap, so its children are complete and
            // each one's pid stays allocated to it. Capture them all, kill each one, then kill
            // the launcher, so it is never left stopped.
            captureChildren();
            stopMs = Date.now() - stopSent;
            killCaptured();
            launcherKill = 'stopped';
            signalLauncher('SIGKILL');
            return killComplete();
          }
          const pastCap = Date.now() - stopSent >= STOP_GRACE_MS;
          if (pastCap) {
            // Not stopped yet (in practice, uninterruptible sleep). It is alive, so its children
            // are still its own: capture any new one and kill each through its identity, on every
            // tick until it stops or exits (PL11-ESC-LIM (6)). It can reap a child between capture
            // and kill; the identity re-check before each kill covers that (PL11-ESC-LIM (1)).
            if (!stopPastCap) stopRecord.pastCap += 1;
            stopPastCap = true;
            captureChildren();
            killCaptured();
          }
          stopTimer = setTimeout(step, pastCap ? POLL_MS : 1);
        };
        // The stop may already have landed; otherwise check again every millisecond (a timer).
        step();
      };
      if (seam === 'late-fork' && seamStream !== null) return holdForLateFork(seamStream, awaitStop);
      signalLauncher('SIGSTOP');
      awaitStop(Date.now());
    };
    const poller = setInterval(() => {
      if (closed !== null) return settleIfGone();
      if (child.pid === undefined) return;
      if (!killing) captureChildren();
      const now = Date.now();
      if (now - scanned >= RESCAN_MS) {
        tree = [child.pid, ...descendants(child.pid)];
        scanned = now;
      }
      let cpuMs = 0;
      let rssBytes = 0;
      for (const pid of tree) {
        const usage = sample(pid);
        if (usage === null) continue;
        cpuMs += usage.cpuMs;
        rssBytes += usage.rssBytes;
      }
      if (cpuMs > service.cpuMs) kill('cpu');
      else if (rssBytes > service.rssBytes) kill('memory');
    }, POLL_MS);
    const wall = setTimeout(() => kill('wall-time'), service.wallMs);

    const finish = (outcome: ParseOutcome): void => {
      if (settled) return;
      settled = true;
      clearInterval(poller);
      clearTimeout(wall);
      // Settling needs a decided kill to have sent all its signals, and the 'error' handler never
      // settles while one is pending, so no stop or deferred stop can be pending here.
      if (deferredStop !== null) clearTimeout(deferredStop);
      if (stopTimer !== null) clearTimeout(stopTimer);
      for (const identity of owned) {
        try {
          closeSync(identity.fd);
        } catch {
          // already closed
        }
      }
      resolveOutcome(outcome);
    };

    child.stdout.on('data', (chunk: Buffer) => {
      if (killedFor !== null) outputAfterKill += chunk.length;
      if (killedFor === 'report-size') return;
      stdoutBytes += chunk.length;
      if (stdoutBytes > budget.bytes) {
        stdout.length = 0;
        kill('report-size');
      } else {
        stdout.push(chunk);
      }
    });
    child.stderr.setEncoding('latin1');
    child.stderr.on('data', (chunk: string) => {
      if (killedFor !== null) outputAfterKill += chunk.length; // latin1: one character per byte
      if (stderr.length < MAX_STDERR_BYTES) stderr += chunk.slice(0, MAX_STDERR_BYTES - stderr.length);
    });
    child.stdin.on('error', () => {
      // The child may exit before reading all input (early rejection or a kill).
    });
    child.on('error', () => {
      // Node emits 'error' when the spawn fails (no pid, so no stop is ever sent), or when kill()
      // or send() on the child object fails, which this code never calls. A pending stop is
      // never abandoned: the kill completes and settles as usual.
      if (killing && !killSent) return;
      finish(failure('the parse child could not be started', label));
    });
    child.on('exit', () => {
      // The launcher has been reaped. Without a decided kill, a captured child still alive
      // outlived it (the launcher exited or was killed first): end it through its identity.
      if (!killing) endOrphans();
      settleIfGone();
    });
    child.on('close', (code, signal) => {
      closed = { code, signal };
      settleIfGone();
    });

    /**
     * Settle only once the sandbox is gone: the child's stdio has closed, a decided kill has
     * sent all its signals, and every captured child has terminated. A terminated namespace
     * init means its namespace, the worker included, is gone. Until then the poller calls this
     * every POLL_MS.
     */
    const settleIfGone = (): void => {
      if (settled) return;
      const done = closed;
      if (done === null || (killing && !killSent)) return;
      if (!owned.every((identity) => terminatedByHandle(identity.fd))) return;
      hooks.observe?.(
        Object.freeze({
          kill: killedFor,
          output_after_kill: outputAfterKill,
          orphans_ended: orphansEnded,
          stop_ms: stopMs,
          stop_past_cap: stopPastCap,
          launcher_kill: launcherKill,
          killed: Object.freeze([...killed]),
          late_child: lateChild,
        }),
      );
      finish(outcomeAfterClose(done.code, done.signal));
    };
    const outcomeAfterClose = (code: number | null, signal: NodeJS.Signals | null): ParseOutcome => {
      // The child refuses a document whose report would exceed the budget, so a longer report
      // comes only from a broken or lying child (LBR3-1).
      if (killedFor === 'report-size') return failure('the parse child sent more than the report budget', label);
      if (killedFor !== null) return reject('resource-limit', killedFor, label);
      if (/heap out of memory|Reached heap limit|Allocation failed/i.test(stderr)) return reject('resource-limit', 'memory', label);
      if (signal === 'SIGKILL' || signal === 'SIGXCPU' || (code !== null && KILLED_EXIT_CODES.has(code))) return reject('resource-limit', 'cpu', label);
      if (code !== 0) return failure(`the parse child exited with ${signal ?? `status ${code}`}`, label);
      let parsed: unknown;
      try {
        const text = Buffer.concat(stdout, stdoutBytes).toString('utf8');
        stdout.length = 0;
        parsed = JSON.parse(text);
      } catch {
        return failure('the parse child returned no valid result', label);
      }
      const result = validateChildResult(parsed, bytes.length, parser.maxPages, parser.maxDepth, budget.nodes);
      if (result === null) return failure('the parse child returned an invalid report', label);
      if (!result.ok) return reject(result.reason, result.detail, label, result.detections);
      return { ok: true, status: 200, report: { ...result.report, digest, network_sandbox: label }, network_sandbox: label };
    };

    child.stdin.end(bytes);
  });
}

function checkOptions(options: unknown): ParseOptions {
  if (options === undefined) return {};
  if (!isObject(options)) throw new TypeError('parse options must be an object');
  for (const key of Object.keys(options)) if (!PARSE_OPTION_KEYS.has(key)) throw new TypeError(`unknown parse option: ${key.slice(0, 40)}`);
  return options as ParseOptions;
}

const PRODUCTION: Runner = Object.freeze({ kinds: LAUNCHER_KINDS, entry: WORKER_ENTRY, hooks: NO_HOOKS });

/**
 * Parse a PDF in the sandboxed child. Options are `limits` and `service` only; anything
 * else is a TypeError. Resolves with an outcome; never rejects for document content.
 */
export function parsePdf(input: Uint8Array | AsyncIterable<Uint8Array | string>, options?: ParseOptions): Promise<ParseOutcome> {
  let checked: ParseOptions;
  try {
    checked = checkOptions(options);
  } catch (error) {
    return Promise.reject(error);
  }
  return runParse(input, checked, PRODUCTION);
}

export interface TestServiceOptions {
  /** A replacement worker entry (absolute path to a regular file), run in the same sandbox. */
  readonly workerEntry?: string;
  /** Probe only these launchers (narrowing only: an unusable set refuses). */
  readonly launchers?: readonly LauncherKind[];
  /** PL-26: one test-only launch seam (see LaunchSeam). */
  readonly seam?: LaunchSeam;
}

export interface TestParseService {
  plan(): Promise<ServicePlan>;
  parse(input: Uint8Array | AsyncIterable<Uint8Array | string>, options?: ParseOptions): Promise<ParseOutcome>;
  /** Lifecycles of this service's parse children, oldest first (at most LIFECYCLE_RECORDS). */
  lifecycles(): readonly ChildLifecycle[];
  /** With the channel seam: fd 3 of the next child this service launches. */
  nextChannel(): Promise<Duplex>;
  /** The service's settle predicate applied to /proc status text (null: reaped); A-010 request #20. */
  terminatedForSettle(status: string | null): boolean;
}

/**
 * Tests only (PL-13, PL-17, PL-18, PL-26): the production launch with a replacement worker, a
 * narrowed launcher set, or one test-only launch seam. It cannot select an unsandboxed child,
 * change the label, or read the opt-in from anywhere but the process environment.
 * lifecycles() only observes, and terminatedForSettle() is a pure function of its argument.
 * Production callers use parsePdf().
 */
export function createParseServiceForTests(options: TestServiceOptions = {}): TestParseService {
  const entry = options.workerEntry ?? WORKER_ENTRY;
  if (!isAbsolute(entry) || !lstatSync(entry).isFile()) throw new TypeError('workerEntry must be an absolute path to a regular file');
  const kinds = options.launchers ?? LAUNCHER_KINDS;
  if (!Array.isArray(kinds) || !kinds.every((kind) => LAUNCHER_KINDS.includes(kind))) throw new TypeError('launchers must be a subset of bwrap and util-linux');
  const seam = options.seam ?? null;
  if (seam !== null && !LAUNCH_SEAMS.includes(seam)) throw new TypeError('seam must be hold-startup, orphan-launcher, channel or late-fork');
  const records: ChildLifecycle[] = [];
  const observe = (lifecycle: ChildLifecycle): void => {
    records.push(lifecycle);
    if (records.length > LIFECYCLE_RECORDS) records.shift();
  };
  const ready: Duplex[] = [];
  const waiting: ((stream: Duplex) => void)[] = [];
  const channel = (stream: Duplex): void => {
    const waiter = waiting.shift();
    if (waiter === undefined) ready.push(stream);
    else waiter(stream);
  };
  const hooks: ChildHooks = Object.freeze({ seam, observe, channel });
  const runner: Runner = Object.freeze({ kinds: LAUNCHER_KINDS.filter((kind) => kinds.includes(kind)), entry, hooks });
  return Object.freeze({
    plan: () => planFor(runner.kinds),
    parse: async (input: Uint8Array | AsyncIterable<Uint8Array | string>, parseOptions?: ParseOptions) => runParse(input, checkOptions(parseOptions), runner),
    lifecycles: () => Object.freeze([...records]),
    nextChannel: (): Promise<Duplex> => {
      if (seam !== 'channel') return Promise.reject(new TypeError('nextChannel() needs the channel seam'));
      const stream = ready.shift();
      return stream === undefined ? new Promise<Duplex>((resolveStream) => waiting.push(resolveStream)) : Promise.resolve(stream);
    },
    terminatedForSettle: (status: string | null): boolean => terminatedFromStatus(status),
  });
}
