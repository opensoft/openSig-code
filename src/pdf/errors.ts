// SPDX-License-Identifier: Apache-2.0
//
// Rejection reasons of the bounded PDF parser (T033). Details are short engineering
// strings that carry numbers (offsets, object numbers, limits) but never document text.

/** Why a document was rejected. Every reason except size-limit maps to 422 unsupported_pdf. */
export type RejectReason =
  | 'size-limit'
  | 'malformed'
  | 'encrypted'
  | 'already-signed'
  | 'active-content'
  | 'page-limit'
  | 'limit-exceeded'
  | 'unsupported-feature'
  | 'resource-limit';

export const REJECT_REASONS: readonly RejectReason[] = Object.freeze([
  'size-limit',
  'malformed',
  'encrypted',
  'already-signed',
  'active-content',
  'page-limit',
  'limit-exceeded',
  'unsupported-feature',
  'resource-limit',
]);

/** Parser limits that can be exceeded (detail of a limit-exceeded rejection). */
export type LimitName =
  | 'nesting-depth'
  | 'object-count'
  | 'decompression-ratio'
  | 'inflated-bytes'
  | 'xref-sections'
  | 'page-tree-depth'
  | 'report-size';

export class ParseFailure extends Error {
  readonly reason: RejectReason;
  readonly detail: string;
  readonly detections: readonly string[];

  constructor(reason: RejectReason, detail: string, detections: readonly string[] = []) {
    super(`${reason}: ${detail}`);
    this.name = 'ParseFailure';
    this.reason = reason;
    this.detail = detail;
    this.detections = detections;
  }
}

export function malformed(detail: string): ParseFailure {
  return new ParseFailure('malformed', detail);
}

export function limitExceeded(limit: LimitName): ParseFailure {
  return new ParseFailure('limit-exceeded', limit);
}
