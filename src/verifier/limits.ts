// SPDX-License-Identifier: Apache-2.0
//
// Bounds for the shipped product verifier (T014). Every loop and every size the
// verifier handles is bounded by one of these numbers. An input past a bound is
// outside what the verifier can evaluate, and it never reads as valid.
//
// The input bound is the US2 sealed-PDF bound (A-010, request #44). It is
// restated here because src/verifier/ imports only node:* and src/verifier/**
// (VB-01); a test compares it with T036's MAX_SEALED_PDF_BYTES.
//
// Each structure limit is at least T033's limit for the same quantity
// (src/pdf/limits.ts), so the verifier reads any sealed file whose base the
// parse service accepted (VB-06); a test compares them. Where T033 has a
// default and a hard ceiling, the verifier takes the ceiling, plus room for the
// one seal revision T036 appends:
// - maxRevisions >= maxXrefSections (default 32, ceiling 256) + 1;
// - maxXrefEntries >= maxObjects (default 100,000, ceiling 1,000,000) plus the
//   seal revision's entries;
// - maxNestingDepth >= maxDepth (default 64, ceiling 256);
// - maxXrefInflatedBytes >= maxInflatedBytes (default 64 MiB), counted over
//   every decoded cross-reference stream and every object stream an effective
//   type-2 entry names, a subset of what T033 inflates under its total.
//   T033's per-stream maxRatio has no counterpart here: the verifier sets no
//   ratio limit, so it is not stricter.
// Limits with no T033 counterpart (string, container and stream sizes) are held
// only by the input bound, except the total header-skip bound below.
// Numbers have up to 15 digits, as T033's readUnsigned reads them.

/** The US2 sealed-PDF bound: 48 MiB (request #44), equal to T036's export. */
export const MAX_SEALED_PDF_BYTES = 48 * 1024 * 1024;

export const VERIFIER_LIMITS = Object.freeze({
  /** Largest input the verifier evaluates. */
  maxInputBytes: MAX_SEALED_PDF_BYTES,
  /** Most cross-reference sections walked through /Prev. */
  maxRevisions: 257,
  /** Most cross-reference entries read across all sections, hidden streams included. */
  maxXrefEntries: 1_048_576,
  /** Largest raw cross-reference stream body (held by the input bound). */
  maxXrefStreamBytes: MAX_SEALED_PDF_BYTES,
  /** Most inflated bytes across all decoded cross-reference and object streams. */
  maxXrefInflatedBytes: 64 * 1024 * 1024,
  /** Widest field in a cross-reference stream row, in bytes. */
  maxXrefFieldWidth: 8,
  /** Window at the end of the file in which the final %%EOF must start. */
  tailWindowBytes: 1024,
  /** Bytes searched before the final %%EOF for its startxref keyword. */
  startxrefWindowBytes: 64,
  /** Deepest dictionary or array nesting the tokenizer follows. */
  maxNestingDepth: 256,
  /** Most items in one dictionary or array (an /Index array holds two per subsection). */
  maxContainerItems: 2 * 1_048_576,
  /** Longest literal or hex string the tokenizer reads (held by the input bound). */
  maxStringBytes: MAX_SEALED_PDF_BYTES,
  /** Most digits in an integer token: 15, as T033's readUnsigned (leading zeros allowed). */
  maxIntegerDigits: 15,
  /**
   * Most white-space and comment bytes skipped, in total, before and inside the
   * object headers read at offsets (section starts and entry checks). T033 skips
   * any amount and bounds its work by CPU time instead, so this bound has no
   * T033 counterpart. Request #56 B6 sets it at least at MAX_SEALED_PDF_BYTES,
   * derived from the same constant as the input bound: in a base T033 accepts,
   * each skipped run ends at its own object's header, so the runs are disjoint
   * and their total cannot exceed the file. A run is read once or twice in an
   * ordinary file (a section, hidden-stream or object-stream read, then its
   * entry check), and four times the input bound leaves room for a stream read
   * in more than one role. A test asserts the floor.
   */
  maxHeaderSkipBytes: 4 * MAX_SEALED_PDF_BYTES,
  /** Most hex digits in the signature's /Contents. */
  maxContentsHexDigits: 2 * 64 * 1024,
  /** Largest CMS SignedData. */
  maxCmsBytes: 64 * 1024,
  /** Most children read from one DER constructed value. */
  maxDerChildren: 256,
  /** Most certificates read from the CMS certificates set. */
  maxCertificates: 8,
  /** Largest certificate (T013 caps the product's at 16 KiB). */
  maxCertificateBytes: 16 * 1024,
  /** Most issuer steps from the signer to an anchor. */
  maxChainDepth: 4,
  /** Most configured trust anchors. */
  maxAnchors: 32,
  /** Largest single anchor value (DER or PEM text). */
  maxAnchorBytes: 32 * 1024,
  /** Largest anchors file text T038 may pass to splitPemCertificates. */
  maxAnchorsFileBytes: 1024 * 1024,
});
