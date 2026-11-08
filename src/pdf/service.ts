// SPDX-License-Identifier: Apache-2.0
//
// Isolated PDF parse service (T033). Upload validation (T007/T034) and composition (T036)
// call parsePdf(); the parser itself runs only in a child process:
//
// - Input: a byte array or an async iterable of chunks (for example a request stream). The
//   10 MiB streaming cap is enforced while reading: the first chunk that would exceed it
//   ends the read (the iterator is closed, so a stream is destroyed) and the outcome is
//   413 payload_too_large before the body is read in full or a child is started.
// - Child: /bin/sh sets RLIMIT_CPU (`ulimit -t`, a kernel backstop) and execs the pinned
//   Node with --max-old-space-size, --permission with read access to src/pdf/ only (no
//   fs-write, child-process, worker, addon or WASI grant) and
//   --disallow-code-generation-from-strings, under an empty environment.
// - Limits: the parent polls /proc/<pid>/stat and kills the child when its CPU time or
//   resident memory exceeds the limit, and kills it at the wall-clock limit. A V8 heap
//   exhaustion is detected from the child's exit. Every kill is a 422 resource-limit
//   rejection; the child is always gone when parsePdf() settles.
// - Output: one JSON line, bounded by maxReportBytes, validated before it is returned.
//
// - Network (A-008 rework): the worker runs inside a new user and network namespace,
//   launched with util-linux unshare (`--user --net`, mapping `--map-current-user` where
//   supported, otherwise `--map-root-user`; no host privilege and no privileged host
//   change). The service probes this once per process. The namespace has only a down
//   loopback interface, so any connect from the parser fails at the OS level.
// - Without the capability the service fails closed (500 internal, reason
//   sandbox-unavailable) and starts no child. The one exception is the explicit
//   development opt-in OPENSIG_PARSER_ALLOW_UNSANDBOXED=1, honoured only while namespaces
//   are unavailable; OPENSIG_ENV and NODE_ENV are never consulted. The opt-in cannot
//   downgrade a host where the sandbox works.
// - Every outcome carries `network_sandbox`: `netns-enforced (local)` or `unavailable`.
//   That is the locally observed capability; it never claims the production gate
//   `parser-network-sandbox` passed (that gate needs deployment-environment evidence).
// - The parent never trusts the child: a report must be well formed, have 1..maxPages
//   pages numbered in order with finite positive sizes, a rotate of 0/90/180/270, boxes
//   that match the stated geometry (crop box equal to media box), the isolation flags the
//   permission model guarantees, and a byte count equal to the input length. Anything else
//   is a fail-closed 500 service-failure.
// - The PL-12 import boundary (src/pdf/ imports no net, http, https, dns, tls, dgram or
//   http2 module) stays as defence in depth; it is not the network isolation.
//
// Linux only (the pinned runtime is linux-x64).

import { Buffer } from 'node:buffer';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { REJECT_REASONS, type RejectReason } from './errors.ts';
import { MAX_DOCUMENT_PAGES, resolveParserLimits, resolveServiceLimits, type ParserLimits, type ServiceLimits } from './limits.ts';
import type { PageReport, ParseReport } from './parser.ts';

export type { PageReport, ParseReport } from './parser.ts';

export const WORKER_ENTRY = join(dirname(fileURLToPath(import.meta.url)), 'worker.ts');
const SHELL = '/bin/sh';
const POLL_MS = 10;
const CLOCK_TICKS_PER_SECOND = 100;
const PAGE_BYTES = 4096;
const MAX_STDERR_BYTES = 64 * 1024;

/** The locally observed network capability of the parse child. */
export type NetworkSandboxLabel = 'netns-enforced (local)' | 'unavailable';
export const NETNS_ENFORCED: NetworkSandboxLabel = 'netns-enforced (local)';
export const SANDBOX_UNAVAILABLE: NetworkSandboxLabel = 'unavailable';
/** The only switch that permits an unsandboxed child, and only while namespaces are unavailable. */
export const UNSANDBOXED_FLAG = 'OPENSIG_PARSER_ALLOW_UNSANDBOXED';
/** util-linux unshare locations probed, in order (absolute paths; PATH is never searched). */
export const UNSHARE_CANDIDATES: readonly string[] = Object.freeze(['/usr/bin/unshare', '/bin/unshare']);
const PROBE_TIMEOUT_MS = 5_000;

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
  /** Locally observed network capability (never a claim about the production gate). */
  network_sandbox: NetworkSandboxLabel;
}

export type ParseOutcome =
  | { ok: true; status: 200; report: ServiceReport; network_sandbox: NetworkSandboxLabel }
  | {
      ok: false;
      status: 413 | 422 | 500;
      code: 'payload_too_large' | 'unsupported_pdf' | 'internal';
      reason: RejectReason | 'service-failure' | 'sandbox-unavailable';
      detail: string;
      detections: string[];
      network_sandbox: NetworkSandboxLabel;
    };

/** Result of probing for unprivileged user + network namespaces. */
export interface SandboxProbe {
  readonly available: boolean;
  readonly unshare: string | null;
  readonly mapping: 'current-user' | 'root-user' | null;
}

/** How the service runs the child on this host. */
export interface ServicePlan {
  readonly mode: 'sandboxed' | 'unsandboxed' | 'refused';
  readonly network_sandbox: NetworkSandboxLabel;
  readonly probe: SandboxProbe;
}

export interface ServiceRuntime {
  /** Environment for the opt-in flag (default process.env). Only UNSANDBOXED_FLAG is read. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** unshare binaries to probe (default UNSHARE_CANDIDATES). */
  readonly unshareCandidates?: readonly string[];
}

export interface ParseOptions {
  limits?: Partial<ParserLimits>;
  service?: Partial<ServiceLimits>;
  runtime?: ServiceRuntime;
  /** Tests only: an alternative child entry module. Production callers never set it. */
  workerEntry?: string;
}

function reject(reason: RejectReason, detail: string, label: NetworkSandboxLabel, detections: string[] = []): ParseOutcome {
  if (reason === 'size-limit') return { ok: false, status: 413, code: 'payload_too_large', reason, detail, detections, network_sandbox: label };
  return { ok: false, status: 422, code: 'unsupported_pdf', reason, detail, detections, network_sandbox: label };
}

function failure(detail: string, label: NetworkSandboxLabel): ParseOutcome {
  return { ok: false, status: 500, code: 'internal', reason: 'service-failure', detail, detections: [], network_sandbox: label };
}

// --- network sandbox ---------------------------------------------------------------------

function runQuietly(file: string, args: string[]): Promise<boolean> {
  return new Promise((resolveRun) => {
    let child;
    try {
      child = spawn(file, args, { env: {}, stdio: 'ignore', timeout: PROBE_TIMEOUT_MS });
    } catch {
      resolveRun(false);
      return;
    }
    child.on('error', () => resolveRun(false));
    child.on('close', (code) => resolveRun(code === 0));
  });
}

const probes = new Map<string, Promise<SandboxProbe>>();

/**
 * Probe once per candidate list: can this process create a user + network namespace with
 * unshare, mapping the current user (preferred) or root?
 */
export function probeNetworkSandbox(candidates: readonly string[] = UNSHARE_CANDIDATES): Promise<SandboxProbe> {
  const key = candidates.join('\0');
  let probe = probes.get(key);
  if (probe === undefined) {
    probe = (async () => {
      for (const unshare of candidates) {
        if (!unshare.startsWith('/') || !existsSync(unshare)) continue;
        for (const mapping of ['current-user', 'root-user'] as const) {
          const flag = mapping === 'current-user' ? '--map-current-user' : '--map-root-user';
          if (await runQuietly(unshare, ['--user', '--net', flag, '--', SHELL, '-c', 'exit 0'])) {
            return Object.freeze({ available: true, unshare, mapping });
          }
        }
      }
      return Object.freeze({ available: false, unshare: null, mapping: null });
    })();
    probes.set(key, probe);
  }
  return probe;
}

/** The sandbox launcher: `file args...` run inside a new user and network namespace. */
export function sandboxedCommand(probe: SandboxProbe, file: string, args: readonly string[]): { file: string; args: string[] } {
  if (!probe.available || probe.unshare === null || probe.mapping === null) throw new Error('the network namespace sandbox is unavailable');
  return {
    file: probe.unshare,
    args: ['--user', '--net', probe.mapping === 'current-user' ? '--map-current-user' : '--map-root-user', '--', file, ...args],
  };
}

/** Decide how the child runs. OPENSIG_ENV and NODE_ENV are deliberately not consulted. */
export async function parseServicePlan(runtime: ServiceRuntime = {}): Promise<ServicePlan> {
  const probe = await probeNetworkSandbox(runtime.unshareCandidates ?? UNSHARE_CANDIDATES);
  if (probe.available) return Object.freeze({ mode: 'sandboxed', network_sandbox: NETNS_ENFORCED, probe });
  const env = runtime.env ?? process.env;
  const mode = env[UNSANDBOXED_FLAG] === '1' ? 'unsandboxed' : 'refused';
  return Object.freeze({ mode, network_sandbox: SANDBOX_UNAVAILABLE, probe });
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

/** The exact command parsePdf() runs under `plan` (null when the plan refuses). */
export function serviceCommand(plan: ServicePlan, parser: ParserLimits, service: ServiceLimits, entry: string = WORKER_ENTRY): { file: string; args: string[] } | null {
  const base = workerCommand(parser, service, entry);
  if (plan.mode === 'sandboxed') return sandboxedCommand(plan.probe, base.file, base.args);
  if (plan.mode === 'unsandboxed') return base;
  return null;
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

function isBox(value: unknown): value is [number, number, number, number] {
  return (
    Array.isArray(value) &&
    value.length === 4 &&
    value.every((n) => typeof n === 'number' && Number.isFinite(n)) &&
    (value[2] as number) > (value[0] as number) &&
    (value[3] as number) > (value[1] as number)
  );
}

function validPage(value: unknown, index: number): value is PageReport {
  if (!isObject(value)) return false;
  const { number, width, height, rotate, media_box: media, crop_box: crop, ref } = value;
  if (number !== index + 1 || !isPositive(width) || !isPositive(height)) return false;
  if (rotate !== 0 && rotate !== 90 && rotate !== 180 && rotate !== 270) return false;
  if (!isBox(media) || !isBox(crop) || !media.every((n, i) => n === crop[i])) return false;
  const boxWidth = crop[2] - crop[0];
  const boxHeight = crop[3] - crop[1];
  const [shownWidth, shownHeight] = rotate % 180 === 0 ? [boxWidth, boxHeight] : [boxHeight, boxWidth];
  if (width !== shownWidth || height !== shownHeight) return false;
  return Array.isArray(ref) && ref.length === 2 && isCount(ref[0]) && ref[0] >= 1 && isCount(ref[1]) && ref[1] <= 65535;
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
 * Validate the child's result against the input it was given. Returns null for anything
 * that is not exactly a well-formed rejection or a consistent report.
 */
export function validateChildResult(value: unknown, inputBytes: number, maxPages: number): ChildResult | null {
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
  if (report.schema !== 'opensig.pdf.parse-report.v1') return null;
  if (report.bytes !== inputBytes) return null;
  if (typeof report.header_version !== 'string' || !/^(?:1\.[0-7]|2\.0)$/.test(report.header_version)) return null;
  const pages = report.pages;
  const ceiling = Math.min(maxPages, MAX_DOCUMENT_PAGES);
  if (!Array.isArray(pages) || pages.length < 1 || pages.length > ceiling || !pages.every((page, index) => validPage(page, index))) return null;
  const xref = report.xref;
  if (!isObject(xref) || (xref.kind !== 'table' && xref.kind !== 'stream') || !isCount(xref.sections) || !isCount(xref.startxref) || !isCount(xref.size)) return null;
  if (typeof xref.hybrid !== 'boolean') return null;
  if (!isObject(report.trailer) || !isObject(report.objects) || !isObject(report.stats)) return null;
  if (!Object.values(report.stats).every((n) => isCount(n))) return null;
  if (!isStringList(report.features, 64, 64)) return null;
  if (!validIsolation(report.isolation)) return null;
  return { ok: true, report: report as unknown as ParseReport & { isolation: Isolation } };
}

// --- parse -----------------------------------------------------------------------------------

/** Parse a PDF in the isolated child. Resolves with an outcome; never rejects for document content. */
export async function parsePdf(input: Uint8Array | AsyncIterable<Uint8Array | string>, options: ParseOptions = {}): Promise<ParseOutcome> {
  const parser = resolveParserLimits(options.limits);
  const service = resolveServiceLimits(options.service);
  const plan = await parseServicePlan(options.runtime);
  const label = plan.network_sandbox;
  const command = serviceCommand(plan, parser, service, options.workerEntry ?? WORKER_ENTRY);
  if (command === null) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      reason: 'sandbox-unavailable',
      detail: `the network namespace sandbox is unavailable and ${UNSANDBOXED_FLAG}=1 is not set`,
      detections: [],
      network_sandbox: label,
    };
  }
  const collected = await collect(input, parser.maxBytes);
  if (!(collected instanceof Buffer)) return reject('size-limit', `more than ${parser.maxBytes} bytes`, label);
  const bytes = collected;
  const digest = createHash('sha256').update(bytes).digest('hex');
  const { file, args } = command;

  return await new Promise<ParseOutcome>((resolveOutcome) => {
    const child = spawn(file, args, { cwd: dirname(WORKER_ENTRY), env: {}, stdio: ['pipe', 'pipe', 'pipe'] });
    let killedFor: 'cpu' | 'memory' | 'wall-time' | 'report-size' | null = null;
    const stdout: Buffer[] = [];
    let stdoutBytes = 0;
    let stderr = '';
    let settled = false;

    const kill = (reason: NonNullable<typeof killedFor>): void => {
      if (killedFor === null) killedFor = reason;
      child.kill('SIGKILL');
    };
    const poller = setInterval(() => {
      if (child.pid === undefined) return;
      const now = sample(child.pid);
      if (now === null) return;
      if (now.cpuMs > service.cpuMs) kill('cpu');
      else if (now.rssBytes > service.rssBytes) kill('memory');
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
      stdoutBytes += chunk.length;
      if (stdoutBytes > service.maxReportBytes) kill('report-size');
      else stdout.push(chunk);
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
      if (killedFor === 'report-size') return finish(reject('limit-exceeded', 'report-size', label));
      if (killedFor !== null) return finish(reject('resource-limit', killedFor, label));
      if (/heap out of memory|Reached heap limit|Allocation failed/i.test(stderr)) return finish(reject('resource-limit', 'memory', label));
      if (signal === 'SIGKILL' || signal === 'SIGXCPU') return finish(reject('resource-limit', 'cpu', label));
      if (code !== 0) return finish(failure(`the parse child exited with ${signal ?? `status ${code}`}`, label));
      let parsed: unknown;
      try {
        parsed = JSON.parse(Buffer.concat(stdout).toString('utf8'));
      } catch {
        return finish(failure('the parse child returned no valid result', label));
      }
      const result = validateChildResult(parsed, bytes.length, parser.maxPages);
      if (result === null) return finish(failure('the parse child returned an invalid report', label));
      if (!result.ok) return finish(reject(result.reason, result.detail, label, result.detections));
      return finish({ ok: true, status: 200, report: { ...result.report, digest, network_sandbox: label }, network_sandbox: label });
    });

    child.stdin.end(bytes);
  });
}
