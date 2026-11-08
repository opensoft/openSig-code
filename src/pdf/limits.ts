// SPDX-License-Identifier: Apache-2.0
//
// Limits of the bounded PDF parser and of the isolated parse service (T033).
// FR-002 fixes the document ceilings: at most 10 MiB and 50 pages. Callers may lower any
// limit; they may raise the structural and resource limits only up to the hard ceilings
// below, and never the document ceilings.

export const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;
export const MAX_DOCUMENT_PAGES = 50;

export interface ParserLimits {
  /** Input size cap in bytes (FR-002 ceiling 10 MiB). */
  maxBytes: number;
  /** Page count cap (FR-002 ceiling 50). */
  maxPages: number;
  /** Maximum nesting of arrays and dictionaries, and of the page tree. */
  maxDepth: number;
  /** Maximum number of cross-reference entries (in use or free). */
  maxObjects: number;
  /** Maximum inflated/compressed size ratio of one decoded stream. */
  maxRatio: number;
  /** Maximum total inflated bytes across all decoded streams. */
  maxInflatedBytes: number;
  /** Maximum number of cross-reference sections in the /Prev chain. */
  maxXrefSections: number;
}

export interface ServiceLimits {
  /** V8 old-space cap of the parse child, in MiB (--max-old-space-size). */
  heapMiB: number;
  /** Resident memory cap of the parse child, in bytes (polled; killed when exceeded). */
  rssBytes: number;
  /** CPU time cap of the parse child, in ms (polled, plus an RLIMIT_CPU backstop). */
  cpuMs: number;
  /** Wall-clock cap of the parse child, in ms. */
  wallMs: number;
  /** Maximum size of the child's JSON report, in bytes. */
  maxReportBytes: number;
}

export const DEFAULT_PARSER_LIMITS: Readonly<ParserLimits> = Object.freeze({
  maxBytes: MAX_DOCUMENT_BYTES,
  maxPages: MAX_DOCUMENT_PAGES,
  maxDepth: 64,
  maxObjects: 100_000,
  maxRatio: 200,
  maxInflatedBytes: 64 * 1024 * 1024,
  maxXrefSections: 32,
});

const PARSER_CEILINGS: Readonly<ParserLimits> = Object.freeze({
  maxBytes: MAX_DOCUMENT_BYTES,
  maxPages: MAX_DOCUMENT_PAGES,
  maxDepth: 256,
  maxObjects: 1_000_000,
  maxRatio: 2_000,
  maxInflatedBytes: 512 * 1024 * 1024,
  maxXrefSections: 256,
});

export const DEFAULT_SERVICE_LIMITS: Readonly<ServiceLimits> = Object.freeze({
  heapMiB: 128,
  rssBytes: 512 * 1024 * 1024,
  cpuMs: 10_000,
  wallMs: 20_000,
  maxReportBytes: 16 * 1024 * 1024,
});

const SERVICE_CEILINGS: Readonly<ServiceLimits> = Object.freeze({
  heapMiB: 1_024,
  rssBytes: 2 * 1024 * 1024 * 1024,
  cpuMs: 60_000,
  wallMs: 120_000,
  maxReportBytes: 64 * 1024 * 1024,
});

function resolve<T extends object>(kind: string, defaults: Readonly<T>, ceilings: Readonly<T>, overrides: unknown): T {
  const result = { ...defaults } as Record<string, number>;
  if (overrides === undefined || overrides === null) return result as T;
  if (typeof overrides !== 'object' || Array.isArray(overrides)) throw new TypeError(`${kind} limits must be an object`);
  const ceilingTable = ceilings as Record<string, number>;
  for (const [key, value] of Object.entries(overrides as Record<string, unknown>)) {
    const ceiling = ceilingTable[key];
    if (ceiling === undefined) throw new TypeError(`unknown ${kind} limit: ${key}`);
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > ceiling) {
      throw new TypeError(`${kind} limit ${key} must be an integer from 1 to ${ceiling}`);
    }
    result[key] = value;
  }
  return result as T;
}

export function resolveParserLimits(overrides?: unknown): ParserLimits {
  return resolve('parser', DEFAULT_PARSER_LIMITS, PARSER_CEILINGS, overrides);
}

export function resolveServiceLimits(overrides?: unknown): ServiceLimits {
  return resolve('service', DEFAULT_SERVICE_LIMITS, SERVICE_CEILINGS, overrides);
}
