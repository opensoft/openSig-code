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
//   the tree when its CPU time or resident memory exceeds the limit, or at the wall-clock
//   limit. A V8 heap exhaustion is detected from the child's exit. Every kill is a 422
//   resource-limit rejection; the child is always gone when parsePdf() settles.
// - Fail closed: without a launcher whose isolation the probe confirms, parsePdf() returns
//   500 internal, reason sandbox-unavailable, and starts no child. The one exception is the
//   explicit development opt-in OPENSIG_PARSER_ALLOW_UNSANDBOXED=1, read from the process
//   environment only and honoured only when no launcher is usable on the host;
//   OPENSIG_ENV and NODE_ENV are never consulted.
// - No caller-supplied option can choose the launcher, the environment or the worker
//   (LBR-3): parsePdf() accepts `limits` and `service` only and refuses anything else.
//   createParseServiceForTests() exists for the tests; its options can only narrow the
//   launchers (a narrowed set that is unusable refuses) or replace the worker inside the
//   same sandbox, and never downgrade or relabel it.
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
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, sep } from 'node:path';
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
    return await runChild(bytes, command, parser, service, label);
  } finally {
    releaseSlot();
  }
}

/** Run one parse child on `bytes` and validate its report; holds a parse slot throughout. */
function runChild(
  bytes: Buffer,
  { file, args }: { file: string; args: string[] },
  parser: ParserLimits,
  service: ServiceLimits,
  label: NetworkSandboxLabel,
): Promise<ParseOutcome> {
  const digest = createHash('sha256').update(bytes).digest('hex');
  const budget = reportBudget(parser);

  return new Promise<ParseOutcome>((resolveOutcome) => {
    const child = spawn(file, args, { cwd: dirname(WORKER_ENTRY), env: {}, stdio: ['pipe', 'pipe', 'pipe'] });
    let killedFor: 'cpu' | 'memory' | 'wall-time' | 'report-size' | null = null;
    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let stderr = '';
    let settled = false;
    let tree: number[] = [];
    let scanned = 0;

    const kill = (reason: NonNullable<typeof killedFor>): void => {
      if (killedFor === null) killedFor = reason;
      child.kill('SIGKILL');
    };
    const poller = setInterval(() => {
      if (child.pid === undefined) return;
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
      resolveOutcome(outcome);
    };

    child.stdout.on('data', (chunk: Buffer) => {
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
      if (stderr.length < MAX_STDERR_BYTES) stderr += chunk.slice(0, MAX_STDERR_BYTES - stderr.length);
    });
    child.stdin.on('error', () => {
      // The child may exit before reading all input (early rejection or a kill).
    });
    child.on('error', () => finish(failure('the parse child could not be started', label)));
    child.on('close', (code, signal) => {
      // The child refuses a document whose report would exceed the budget, so a longer report
      // comes only from a broken or lying child (LBR3-1).
      if (killedFor === 'report-size') return finish(failure('the parse child sent more than the report budget', label));
      if (killedFor !== null) return finish(reject('resource-limit', killedFor, label));
      if (/heap out of memory|Reached heap limit|Allocation failed/i.test(stderr)) return finish(reject('resource-limit', 'memory', label));
      if (signal === 'SIGKILL' || signal === 'SIGXCPU' || (code !== null && KILLED_EXIT_CODES.has(code))) return finish(reject('resource-limit', 'cpu', label));
      if (code !== 0) return finish(failure(`the parse child exited with ${signal ?? `status ${code}`}`, label));
      let parsed: unknown;
      try {
        const text = Buffer.concat(stdout, stdoutBytes).toString('utf8');
        stdout.length = 0;
        parsed = JSON.parse(text);
      } catch {
        return finish(failure('the parse child returned no valid result', label));
      }
      const result = validateChildResult(parsed, bytes.length, parser.maxPages, parser.maxDepth, budget.nodes);
      if (result === null) return finish(failure('the parse child returned an invalid report', label));
      if (!result.ok) return finish(reject(result.reason, result.detail, label, result.detections));
      return finish({ ok: true, status: 200, report: { ...result.report, digest, network_sandbox: label }, network_sandbox: label });
    });

    child.stdin.end(bytes);
  });
}

function checkOptions(options: unknown): ParseOptions {
  if (options === undefined) return {};
  if (!isObject(options)) throw new TypeError('parse options must be an object');
  for (const key of Object.keys(options)) if (!PARSE_OPTION_KEYS.has(key)) throw new TypeError(`unknown parse option: ${key.slice(0, 40)}`);
  return options as ParseOptions;
}

const PRODUCTION: Runner = Object.freeze({ kinds: LAUNCHER_KINDS, entry: WORKER_ENTRY });

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
}

export interface TestParseService {
  plan(): Promise<ServicePlan>;
  parse(input: Uint8Array | AsyncIterable<Uint8Array | string>, options?: ParseOptions): Promise<ParseOutcome>;
}

/**
 * Tests only (PL-13, PL-17, PL-18): the production launch with a replacement worker or a
 * narrowed launcher set. It cannot select an unsandboxed child, change the label, or read
 * the opt-in from anywhere but the process environment. Production callers use parsePdf().
 */
export function createParseServiceForTests(options: TestServiceOptions = {}): TestParseService {
  const entry = options.workerEntry ?? WORKER_ENTRY;
  if (!isAbsolute(entry) || !lstatSync(entry).isFile()) throw new TypeError('workerEntry must be an absolute path to a regular file');
  const kinds = options.launchers ?? LAUNCHER_KINDS;
  if (!Array.isArray(kinds) || !kinds.every((kind) => LAUNCHER_KINDS.includes(kind))) throw new TypeError('launchers must be a subset of bwrap and util-linux');
  const runner: Runner = Object.freeze({ kinds: LAUNCHER_KINDS.filter((kind) => kinds.includes(kind)), entry });
  return Object.freeze({
    plan: () => planFor(runner.kinds),
    parse: async (input: Uint8Array | AsyncIterable<Uint8Array | string>, parseOptions?: ParseOptions) => runParse(input, checkOptions(parseOptions), runner),
  });
}
