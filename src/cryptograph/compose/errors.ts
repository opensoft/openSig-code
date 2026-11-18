// SPDX-License-Identifier: Apache-2.0
//
// Composition errors (T036). Each carries a contract Error code
// (contracts/http-api.json, components.schemas.Error), the HTTP status that code
// maps to, a machine `reason`, a short `detail` and a `retryable` flag, so the
// finalization runner (T038) records `last_error_code` and chooses between the
// bounded retry and `failed` without a second table (request #43; data-model.md
// § Transitions and races, item 3). Messages are generic: they never carry a field
// value, document bytes, a key or a path. Details name a member, never its value.
//
// `retryable` is true ONLY for 429 rate_limited and the parse service's 500s.
// - 400 invalid_request: the request breaks its own shape. Not retryable.
// - 422 unsupported_characters: a typed value holds a character WinAnsiEncoding
//   cannot represent (T010 refuses it at approval; the composer again,
//   defensively). Not retryable.
// - 422 unsupported_pdf: a page whose effective CropBox differs from its MediaBox
//   (detail cropbox_differs, A-008 S2, CP-07); and the five refusals the composer
//   can make from the parse report alone (requests #44 and #45), which T034 makes
//   at upload with the same details (EA-07, bounds.ts estimateSealedSize), so after
//   upload each is a broken invariant: a composition above MAX_SEALED_PDF_BYTES
//   (composition_too_large); an exponent-form number in an object the composer
//   rewrites (number_range); a form reference (/AcroForm, /Fields, page /Annots)
//   that resolves to nothing (dangling_form_reference); a page /Annots that is not
//   an array (annots_shape); an AcroForm that is not a dictionary, whose /Fields is
//   not an array, or that is a page the composer also rewrites (acroform_shape); new
//   objects that would pass the object-number limit (xref_size); a page box the
//   composer cannot place fields on (page_box); a NUL in a name or key (name_character)
//   (requests #45 and #46). Not retryable.
// - 413, 422, 429 and 500 from the parse service, passed through with the
//   service's code and reason and a fixed machine detail, never the service's
//   text; retryable for 429 and 500 only.
// - The composer's own 500s, not retryable: report-invalid (the parse report fails
//   the composer's checks, A-009 LBR-4, CP-08), document-digest-mismatch (the
//   stored document is not the one the manifest froze) and certificate-invalid.

export type ComposeErrorCode =
  | 'invalid_request'
  | 'unsupported_characters'
  | 'unsupported_pdf'
  | 'payload_too_large'
  | 'rate_limited'
  | 'internal';

const STATUS: Readonly<Record<ComposeErrorCode, number>> = Object.freeze({
  invalid_request: 400,
  unsupported_characters: 422,
  unsupported_pdf: 422,
  payload_too_large: 413,
  rate_limited: 429,
  internal: 500,
});

export interface ComposeErrorDetail {
  readonly field: string;
  readonly code: string;
}

export class ComposeError extends Error {
  readonly code: ComposeErrorCode;
  readonly status: number;
  /** Machine reason, for example `report-invalid`, `unsupported-feature` or a parse-service reason. */
  readonly reason: string;
  /** Short machine detail, for example `cropbox_differs`; never a value from the document or the request. */
  readonly detail: string;
  readonly details: readonly ComposeErrorDetail[];
  /** True only for 429 rate_limited and the parse service's 500s: T038 may retry; otherwise the job fails at once. */
  readonly retryable: boolean;

  constructor(code: ComposeErrorCode, reason: string, detail: string, message: string, details: readonly ComposeErrorDetail[] = [], retryable = false) {
    super(message);
    this.name = 'ComposeError';
    this.code = code;
    this.status = STATUS[code];
    this.reason = reason;
    this.detail = detail;
    this.details = Object.freeze(details.map((entry) => Object.freeze({ field: entry.field, code: entry.code })));
    this.retryable = retryable;
  }
}

/** 400: the request member `field` breaks rule `rule`. */
export function inputInvalid(field: string, rule: string): ComposeError {
  return new ComposeError('invalid_request', 'input-invalid', rule, 'the composition request is invalid', [{ field, code: rule }]);
}

/** 422: the typed value at `field` holds a character WinAnsiEncoding cannot represent. */
export function unsupportedCharacters(field: string): ComposeError {
  return new ComposeError('unsupported_characters', 'unsupported-characters', 'unsupported_characters', 'a typed value holds characters the document font cannot show', [
    { field, code: 'unsupported_characters' },
  ]);
}

/** 422 (CP-07): page `page` has an effective CropBox that differs from its MediaBox. */
export function cropboxDiffers(page: number): ComposeError {
  return new ComposeError('unsupported_pdf', 'unsupported-feature', 'cropbox_differs', 'the document has a page the composer cannot place fields on', [
    { field: `pages[${page}]`, code: 'cropbox_differs' },
  ]);
}

/** 422 (CP-02): the form reference `what` (acroform, fields or annots) resolves to no object. */
export function danglingReference(what: string): ComposeError {
  return new ComposeError('unsupported_pdf', 'unsupported-feature', 'dangling_form_reference', 'the document has a form reference the composer cannot follow', [
    { field: what, code: 'dangling_form_reference' },
  ]);
}

/** 422 (CP-02; request #45): a page /Annots, inline or by reference, that is not an array. */
export function annotsShape(): ComposeError {
  return new ComposeError('unsupported_pdf', 'unsupported-feature', 'annots_shape', 'the document has a page annotation list the composer cannot extend', [
    { field: 'annots', code: 'annots_shape' },
  ]);
}

/** 422 (CP-02; request #45): the AcroForm is not a dictionary, its /Fields is not an array, or it is a page the composer also rewrites. */
export function acroformShape(): ComposeError {
  return new ComposeError('unsupported_pdf', 'unsupported-feature', 'acroform_shape', 'the document has a form the composer cannot extend', [
    { field: 'acroform', code: 'acroform_shape' },
  ]);
}

/** 422 (request #46): the new objects' numbers would pass the PDF object-number limit. */
export function xrefSize(): ComposeError {
  return new ComposeError('unsupported_pdf', 'unsupported-feature', 'xref_size', 'the document has no room for the objects of a seal', [
    { field: 'document', code: 'xref_size' },
  ]);
}

/** 422 (request #46): page `page` has a box coordinate above 1,000,000 points in magnitude, or a side under one centipoint. */
export function pageBox(page: number): ComposeError {
  return new ComposeError('unsupported_pdf', 'unsupported-feature', 'page_box', 'the document has a page the composer cannot place fields on', [
    { field: `pages[${page}]`, code: 'page_box' },
  ]);
}

/** 422 (request #46): a reported object holds a NUL in a name or a dictionary key. */
export function nameCharacter(): ComposeError {
  return new ComposeError('unsupported_pdf', 'unsupported-feature', 'name_character', 'the document has a name the composer cannot write', [
    { field: 'document', code: 'name_character' },
  ]);
}

/** 500 (CP-08): the parse report fails the composer's own check `what`. */
export function reportInvalid(what: string): ComposeError {
  return new ComposeError('internal', 'report-invalid', what, 'the document could not be composed', [{ field: 'report', code: what }]);
}

/** 500: the stored document's digest is not the field manifest's document_digest. */
export function documentDigestMismatch(): ComposeError {
  return new ComposeError('internal', 'document-digest-mismatch', 'document_digest', 'the document could not be composed', [
    { field: 'fieldManifest.document_digest', code: 'digest_mismatch' },
  ]);
}

/** 500: the configured seal certificate cannot size the /Contents placeholder. */
export function certificateInvalid(code: string): ComposeError {
  return new ComposeError('internal', 'certificate-invalid', code, 'the seal certificate is not usable', [{ field: 'certificateDer', code }]);
}

/** The refusal members of a parse-service outcome (src/pdf/service.ts ParseOutcome with ok false). */
export interface ParseRefusal {
  readonly code: 'payload_too_large' | 'unsupported_pdf' | 'rate_limited' | 'internal';
  readonly reason: string;
  readonly detail: string;
}

/** 422 (CP-08, T036-NUMRANGE): an object the composer rewrites holds an exponent-form number (T034's upload detail). */
export function numberRange(): ComposeError {
  return new ComposeError('unsupported_pdf', 'number-range', 'number_range', 'the document has a number the composer cannot write', [
    { field: 'document', code: 'number_range' },
  ]);
}

/** 422 (SIZE-BOUND): the composition would exceed MAX_SEALED_PDF_BYTES (T034's upload detail); an invariant. */
export function compositionTooLarge(): ComposeError {
  return new ComposeError('unsupported_pdf', 'composition-too-large', 'composition_too_large', 'the sealed document would exceed its size bound', [
    { field: 'document', code: 'composition_too_large' },
  ]);
}

/** Parse-service details that are fixed machine codes and may be carried as they are. */
const FIXED_PARSE_DETAILS: ReadonlySet<string> = new Set(['cropbox_differs']);

/**
 * A parse-service refusal, with the service's code and reason; retryable for 429 and
 * 500 only. `detail` is a fixed machine detail (CP-08, request #44): the service's
 * detail when it is one of FIXED_PARSE_DETAILS, otherwise the service's reason. The
 * service's free text (for example "reference to missing object 5") never passes.
 */
export function fromParseOutcome(outcome: ParseRefusal): ComposeError {
  const retryable = outcome.code === 'rate_limited' || outcome.code === 'internal';
  const detail = FIXED_PARSE_DETAILS.has(outcome.detail) ? outcome.detail : outcome.reason;
  return new ComposeError(outcome.code, outcome.reason, detail, 'the document could not be composed', [{ field: 'document', code: outcome.reason }], retryable);
}

/** A parse call that rejected instead of resolving: a parse-service failure, so retryable. */
export function parseRejected(): ComposeError {
  return new ComposeError('internal', 'service-failure', 'parse-rejected', 'the document could not be composed', [{ field: 'document', code: 'service-failure' }], true);
}
