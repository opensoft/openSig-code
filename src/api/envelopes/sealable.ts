// SPDX-License-Identifier: Apache-2.0
//
// Upload sealability (T034 follow-up, EA-07; A-010 requests #44, #45 and #46; rows
// SIZE-BOUND, T036-NUMRANGE and T036-RESIDUAL). This is the ONE place the envelope handlers
// use T036's predicate. It imports src/cryptograph/compose/bounds.ts only, never
// compose/index.ts, which pulls in the parse service. Importing it is a read-only use of
// another module's interface, the request #44 to #46 design, not a change to T036's files.
// Reconciling with T036 touches this file only.
//
// uploadDocument (api.ts) runs the predicate on the LIVE parse report, parsePdf()'s
// outcome.report (a ServiceReport). It does so after the parse service has accepted the
// document and the received bytes have matched the report, and before the blob is stored or
// anything is recorded. The stored document input (api.ts documentInput) keeps no objects and
// no trailer, so it cannot answer. A document the composer could not seal is refused at upload,
// so every accepted document is sealable and no approved envelope strands at finalization.
//
// The refusal is 422 unsupported_pdf in the contract's Error shape, with exactly one detail:
// field `document`, and as its code the predicate's FIRST refusal (request #46 Part C(2)). The
// predicate lists its refusals in the order of SEAL_REFUSAL_DETAILS, each kind once:
// composition_too_large, number_range, dangling_form_reference, annots_shape, acroform_shape,
// xref_size, page_box and name_character. An over-bound result always carries
// composition_too_large (request #46 Part C(4)). The first refusal's object references, as the
// predicate gives them (SealRefusal.refs), go to the request log only, never to the response:
// one bounded upload_unsealable record per refused upload (request #57 (3)).
//
// Fail closed: a detail outside the eight is a 500 internal, and nothing is stored. The
// predicate is pure (no I/O, no clock, no randomness), so running it changes no state.

import { estimateSealedSize, MAX_SEALED_PDF_BYTES, type SealRefusal, type SealRefusalDetail } from '../../cryptograph/compose/bounds.ts';
import type { ServiceReport } from '../../pdf/service.ts';
import { HttpError } from '../../server/types.ts';

export { SEAL_REFUSAL_DETAILS } from '../../cryptograph/compose/bounds.ts';

/** The sealed-PDF bound the predicate applies: T036's MAX_SEALED_PDF_BYTES, read, never copied. */
export const SEALED_PDF_LIMIT: number = MAX_SEALED_PDF_BYTES;

/**
 * The details code of each refusal (request #46). The map is keyed by T036's own union, and it
 * is a plain annotated literal, so the excess-property check applies. Adding a detail to that
 * union or removing one fails the typecheck here, in this one adapter, rather than passing
 * silently. The map is module-private and never written.
 */
const DETAIL_CODES: Readonly<Record<SealRefusalDetail, string>> = {
  composition_too_large: 'composition_too_large',
  number_range: 'number_range',
  dangling_form_reference: 'dangling_form_reference',
  annots_shape: 'annots_shape',
  acroform_shape: 'acroform_shape',
  xref_size: 'xref_size',
  page_box: 'page_box',
  name_character: 'name_character',
};

export interface Sealability {
  /** The predicate's worst-case sealed size, in bytes. */
  readonly worstCaseBytes: number;
  /** The predicate's refusals exactly as it gives them (detail and object references, never a value), in its order. */
  readonly refusals: readonly SealRefusal[];
  /** Their details codes, in the same order. Empty means sealable. */
  readonly details: readonly string[];
}

/** The predicate's verdict on a live parse report. */
export function sealabilityOf(report: ServiceReport): Sealability {
  const estimate = estimateSealedSize(report);
  const details = estimate.refusals.map((refusal): string => {
    const code: unknown = Object.hasOwn(DETAIL_CODES, refusal.detail) ? DETAIL_CODES[refusal.detail] : undefined;
    if (typeof code !== 'string') throw new HttpError(500, 'internal');
    return code;
  });
  return Object.freeze({ worstCaseBytes: estimate.worstCaseBytes, refusals: estimate.refusals, details: Object.freeze(details) });
}

/** The most object references one upload_unsealable request-log record holds (request #57 (3)). */
export const MAX_LOGGED_REFS = 16;

/** An EA-07 refusal: the 422 to answer, and the adapter's fields of its request-log record. */
export interface SealabilityRefusal {
  readonly error: HttpError;
  /**
   * For the request log only, never for the response (request #57 (3)): the first refusal's
   * detail, at most MAX_LOGGED_REFS of its SealRefusal.refs as integer [number, generation]
   * pairs (the predicate sorts them by number), and their total count. Never a document byte,
   * name, string, stream content, file name or capability value. api.ts adds the envelope id,
   * and the request logger adds the correlation id.
   */
  readonly log: { readonly detail: string; readonly refs: ReadonlyArray<readonly [number, number]>; readonly refs_total: number };
}

/**
 * EA-07: null when the document is sealable. Otherwise, the 422 unsupported_pdf whose single
 * detail is the predicate's first refusal, and the bounded log fields of that refusal.
 */
export function sealabilityRefusal(report: ServiceReport): SealabilityRefusal | null {
  const { refusals, details } = sealabilityOf(report);
  const [first] = details;
  const [refusal] = refusals;
  if (first === undefined || refusal === undefined) return null;
  return Object.freeze({
    error: new HttpError(422, 'unsupported_pdf', { details: [{ field: 'document', code: first }] }),
    log: Object.freeze({
      detail: first,
      refs: Object.freeze(refusal.refs.slice(0, MAX_LOGGED_REFS).map((ref) => Object.freeze([ref[0], ref[1]] as const))),
      refs_total: refusal.refs.length,
    }),
  });
}
