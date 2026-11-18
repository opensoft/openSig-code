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
//   (detail cropbox_differs, A-008 S2, CP-07), or a form reference (/AcroForm,
//   /Fields, page /Annots) that resolves to nothing (detail
//   dangling_form_reference). Not retryable.
// - 413, 422, 429 and 500 from the parse service, passed through with the
//   service's code, reason and detail; retryable for 429 and 500 only.
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

/** A parse-service refusal, with the service's code, reason and detail; retryable for 429 and 500 only. */
export function fromParseOutcome(outcome: ParseRefusal): ComposeError {
  const retryable = outcome.code === 'rate_limited' || outcome.code === 'internal';
  return new ComposeError(outcome.code, outcome.reason, outcome.detail, 'the document could not be composed', [{ field: 'document', code: outcome.reason }], retryable);
}

/** A parse call that rejected instead of resolving: a parse-service failure, so retryable. */
export function parseRejected(): ComposeError {
  return new ComposeError('internal', 'service-failure', 'parse-rejected', 'the document could not be composed', [{ field: 'document', code: 'service-failure' }], true);
}
