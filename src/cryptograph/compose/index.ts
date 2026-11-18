// SPDX-License-Identifier: Apache-2.0
//
// The incremental-update composer's public surface (T036), for the finalization
// runner (T038) and the sealing worker (T037).
//
// composeSealRevision(request) checks the request (exactly five members; no option
// of any kind), parses the document through the isolated parse service with the
// document as the only argument (A-009 LBR-3, CP-08), checks the report as
// untrusted input (CP-07, CP-08), and returns the composed revision. Every refusal
// is a ComposeError with its contract code, its status, a reason, a detail and
// `retryable`, which is true only for 429 rate_limited and the parse service's
// 500s (request #43): T038 retries those within its bound and moves any other
// refusal to `failed` at once.
//
// What T037 and T038 may rely on:
// 1. `bytes` is the document followed by one appended revision; nothing follows
//    its %%EOF. It is final except for the /Contents hex digits, which are ASCII
//    zeros. `digest` (SHA-256 of `bytes`) is the approval manifest's
//    approved_composition_digest, fixed before the seal.
// 2. `byteRange` is [0, o1, o2, l2] and is already written into `bytes`: o1 is the
//    offset of `<`, o2 the offset just after `>`, and o2 + l2 is the length.
//    signedRanges() gives the two spans in order; contentDigestOf(signedRanges(r))
//    (T013) is the CMS contentDigest.
// 3. `contents.offset` is the first hex digit and `contents.hexLength` equals
//    2 x `signedDataLength`, computed from the certificate passed here. T037 must
//    seal with that same certificate, refuse a DER of any other length (request
//    #39, Part F, Q8), write its hex digits over exactly
//    [contents.offset, contents.offset + contents.hexLength) and change no other
//    byte. final.pdf's digest is then the SHA-256 of the result.
// 4. Composition is pure and deterministic: equal requests give identical bytes,
//    so a retried finalization with the same frozen inputs and the same
//    `sealTime` reproduces the same approved_composition_digest (SC-003).
// 5. The signed revision is the last one, and its cross-reference section is of
//    the base's last kind (`xrefKind`), whose /Prev is the base's startxref.
// 6. `bytes.length` <= MAX_SEALED_PDF_BYTES (48 MiB): the composer refuses anything
//    larger (422 unsupported_pdf composition_too_large, not retryable). The /Sig dictionary is one
//    object whose /ByteRange and /Contents are direct, with at most 4 KiB of text on
//    each side of the /Contents hex string (CP-05). byteRangeText() is the
//    fixed-width /ByteRange writer, for T037's synthetic /Sig.
// 7. For T034 (EA-07): estimateSealedSize(outcome.report) gives the worst-case
//    sealed size and every refusal the composer could make from the report alone, in
//    the order of SEAL_REFUSAL_DETAILS (composition_too_large, number_range,
//    dangling_form_reference, annots_shape, acroform_shape, xref_size, page_box,
//    name_character; T034 takes the first), with object references only; the
//    composer makes each as 422 unsupported_pdf with the same detail, not retryable.
//    bounds.ts imports nothing.
// 8. For T007's prepare check (request #46): placeField(page, rect), the rule the
//    composer places every field with, over page = { rotate, box: centipointBox(
//    media_box) }; null means the composer refuses the field with 400 field_too_small.

import { parsePdf, type ParseOutcome } from '../../pdf/service.ts';
import { checkRequest, composeFromReport, type ComposedRevision, type ComposeRequest } from './compose.ts';
import { fromParseOutcome, parseRejected } from './errors.ts';

export {
  centipointBox,
  estimateSealedSize,
  MAX_SEALED_PDF_BYTES,
  SEAL_REFUSAL_DETAILS,
  UPDATE_BOUND,
  UPDATE_REQUEST_BOUND,
  withinSealedBound,
  type CentipointBox,
  type ObjectRef,
  type SealableReport,
  type SealedSizeEstimate,
  type SealRefusal,
  type SealRefusalDetail,
} from './bounds.ts';
export {
  BYTE_RANGE_WIDTH,
  byteRangeText,
  DATE_WIDGET_CONTENTS,
  SEAL_FIELD_PREFIX,
  SEAL_REASON,
  SIG_FLAGS,
  sealFieldName,
  signedRanges,
  WIDGET_FLAGS,
  type ApprovalInput,
  type ComposedRevision,
  type ComposeRequest,
  type FieldInput,
  type FieldManifestInput,
  type FieldValueInput,
} from './compose.ts';
export { encodeWinAnsi, placeField, type NormalizedRect, type PageGeometry, type Placement } from './appearance.ts';
export { ComposeError, fromParseOutcome, type ComposeErrorCode, type ComposeErrorDetail, type ParseRefusal } from './errors.ts';

/** Compose the seal revision of `request.document` (see the header for the contract). */
export async function composeSealRevision(request: ComposeRequest): Promise<ComposedRevision> {
  const checked = checkRequest(request);
  let outcome: ParseOutcome;
  try {
    outcome = await parsePdf(checked.document);
  } catch {
    throw parseRejected();
  }
  if (!outcome.ok) throw fromParseOutcome(outcome);
  return composeFromReport(checked, outcome.report);
}
