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
// Linux only (the pinned runtime is linux-x64).

import { Buffer } from 'node:buffer';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { REJECT_REASONS, type RejectReason } from './errors.ts';
import { resolveParserLimits, resolveServiceLimits, type ParserLimits, type ServiceLimits } from './limits.ts';
import type { ParseReport } from './parser.ts';

export type { PageReport, ParseReport } from './parser.ts';

export const WORKER_ENTRY = join(dirname(fileURLToPath(import.meta.url)), 'worker.ts');
const SHELL = '/bin/sh';
const POLL_MS = 10;
const CLOCK_TICKS_PER_SECOND = 100;
const PAGE_BYTES = 4096;
const MAX_STDERR_BYTES = 64 * 1024;

export interface ServiceReport extends ParseReport {
  /** SHA-256 (lowercase hex) of the exact bytes parsed. */
  digest: string;
  /** Permission state the child observed, and the names (never values) of its environment variables. */
  isolation: { permission_model: boolean; fs_write: boolean; child_process: boolean; worker: boolean; environment: string[] };
}

export type ParseOutcome =
  | { ok: true; status: 200; report: ServiceReport }
  | {
      ok: false;
      status: 413 | 422 | 500;
      code: 'payload_too_large' | 'unsupported_pdf' | 'internal';
      reason: RejectReason | 'service-failure';
      detail: string;
      detections: string[];
    };

export interface ParseOptions {
  limits?: Partial<ParserLimits>;
  service?: Partial<ServiceLimits>;
}

function reject(reason: RejectReason, detail: string, detections: string[] = []): ParseOutcome {
  if (reason === 'size-limit') return { ok: false, status: 413, code: 'payload_too_large', reason, detail, detections };
  return { ok: false, status: 422, code: 'unsupported_pdf', reason, detail, detections };
}

function failure(detail: string): ParseOutcome {
  return { ok: false, status: 500, code: 'internal', reason: 'service-failure', detail, detections: [] };
}

/** The exact command the service runs: file and argv (no shell interpolation of values). */
export function workerCommand(parser: ParserLimits, service: ServiceLimits): { file: string; args: string[] } {
  const cpuSeconds = Math.ceil(service.cpuMs / 1000) + 1;
  const readable = `${dirname(WORKER_ENTRY)}${sep}`;
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
      WORKER_ENTRY,
      JSON.stringify(parser),
    ],
  };
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

function validChildResult(value: unknown): value is { ok: true; report: ParseReport & { isolation: ServiceReport['isolation'] } } | { ok: false; reason: RejectReason; detail: string; detections?: string[] } {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (record.ok === true) {
    const report = record.report as Record<string, unknown> | undefined;
    return typeof report === 'object' && report !== null && report.schema === 'opensig.pdf.parse-report.v1' && Array.isArray(report.pages) && typeof report.isolation === 'object';
  }
  return record.ok === false && typeof record.reason === 'string' && (REJECT_REASONS as readonly string[]).includes(record.reason) && typeof record.detail === 'string';
}

/** Parse a PDF in the isolated child. Resolves with an outcome; never rejects for document content. */
export async function parsePdf(input: Uint8Array | AsyncIterable<Uint8Array | string>, options: ParseOptions = {}): Promise<ParseOutcome> {
  const parser = resolveParserLimits(options.limits);
  const service = resolveServiceLimits(options.service);
  const collected = await collect(input, parser.maxBytes);
  if (!(collected instanceof Buffer)) return reject('size-limit', `more than ${parser.maxBytes} bytes`);
  const bytes = collected;
  const digest = createHash('sha256').update(bytes).digest('hex');
  const { file, args } = workerCommand(parser, service);

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
    child.on('error', () => finish(failure('the parse child could not be started')));
    child.on('close', (code, signal) => {
      if (killedFor === 'report-size') return finish(reject('limit-exceeded', 'report-size'));
      if (killedFor !== null) return finish(reject('resource-limit', killedFor));
      if (/heap out of memory|Reached heap limit|Allocation failed/i.test(stderr)) return finish(reject('resource-limit', 'memory'));
      if (signal === 'SIGKILL' || signal === 'SIGXCPU') return finish(reject('resource-limit', 'cpu'));
      if (code !== 0) return finish(failure(`the parse child exited with ${signal ?? `status ${code}`}`));
      let parsed: unknown;
      try {
        parsed = JSON.parse(Buffer.concat(stdout).toString('utf8'));
      } catch {
        return finish(failure('the parse child returned no valid result'));
      }
      if (!validChildResult(parsed)) return finish(failure('the parse child returned an unexpected result'));
      if (!parsed.ok) return finish(reject(parsed.reason, parsed.detail, Array.isArray(parsed.detections) ? parsed.detections : []));
      return finish({ ok: true, status: 200, report: { ...parsed.report, digest } });
    });

    child.stdin.end(bytes);
  });
}
