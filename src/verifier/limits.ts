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
// Each structure limit is at least T033's CEILING for the same quantity
// (request #58 (3)): callers of the parse service may raise a limit up to its
// ceiling, so only the ceiling makes "at least T033's limit" hold for every
// configuration. The ceilings are restated in T033_PARSER_CEILINGS, and a test
// proves each one against T033's exported resolveParserLimits (V is accepted,
// V + 1 is refused). The verifier's limits derive from them:
// - maxRevisions = maxXrefSections + 1 (the one seal revision T036 appends);
// - maxXrefEntries >= maxObjects, counted as T033 counts it: the distinct
//   effective entries, and separately each section's own, never the sum;
// - maxNestingDepth = maxDepth;
// - maxXrefInflatedBytes = maxInflatedBytes, one total over every decoded
//   cross-reference and object stream. T033's per-stream maxRatio has no
//   counterpart: the verifier sets no ratio limit, so it is not stricter.
// Limits with no T033 counterpart (string, container and stream sizes) are held
// by the input bound. No byte total refuses a file (request #60 (2)): regions
// already read are reused, and each loop is bounded by its own run.
// Table and header numbers have up to 15 digits (T033's readUnsigned); other
// number tokens have up to 32 characters (T033's readValue).

/** The US2 sealed-PDF bound: 48 MiB (request #44), equal to T036's export. */
export const MAX_SEALED_PDF_BYTES = 48 * 1024 * 1024;

/** T033's PARSER_CEILINGS, restated (request #58 (3)); a test proves each against resolveParserLimits. */
export const T033_PARSER_CEILINGS = Object.freeze({
  maxDepth: 256,
  maxObjects: 1_000_000,
  maxRatio: 2_000,
  maxInflatedBytes: 512 * 1024 * 1024,
  maxXrefSections: 256,
});

export const VERIFIER_LIMITS = Object.freeze({
  /** Largest input the verifier evaluates. */
  maxInputBytes: MAX_SEALED_PDF_BYTES,
  /** Most cross-reference sections walked through /Prev. */
  maxRevisions: T033_PARSER_CEILINGS.maxXrefSections + 1,
  /** Most distinct effective entries, and separately most entries in one section (hidden stream apart). */
  maxXrefEntries: 1_048_576,
  /** Largest raw structural stream body (held by the input bound). */
  maxXrefStreamBytes: MAX_SEALED_PDF_BYTES,
  /** Most inflated bytes across all decoded cross-reference and object streams. */
  maxXrefInflatedBytes: T033_PARSER_CEILINGS.maxInflatedBytes,
  /** Widest field in a cross-reference stream row, in bytes (T033 allows 6). */
  maxXrefFieldWidth: 8,
  /** Window at the end of the file in which the final %%EOF must start. */
  tailWindowBytes: 1024,
  /** Bytes searched before the final %%EOF for its startxref keyword. */
  startxrefWindowBytes: 64,
  /** Deepest dictionary or array nesting the tokenizer follows. */
  maxNestingDepth: T033_PARSER_CEILINGS.maxDepth,
  /** Most items in one dictionary or array: T033 has no item cap, so only the input bound holds it. */
  maxContainerItems: MAX_SEALED_PDF_BYTES,
  /** Longest literal or hex string the tokenizer reads (held by the input bound). */
  maxStringBytes: MAX_SEALED_PDF_BYTES,
  /** Most digits in a table or header number: 15, as T033's readUnsigned (leading zeros allowed). */
  maxIntegerDigits: 15,
  /** Most characters in any other number token: 32, as T033's readValue (sign, digits, point). */
  maxNumberChars: 32,
  /**
   * Request #60 (2) replaces request #56 B6's skip bound: no total of skipped
   * white-space and comment bytes refuses a file. T033 bounds that work only by
   * its CPU cap, which a fixed byte total cannot track. Each skip is bounded by
   * its own run, which never passes the input. The value stays, unbounded, so
   * B6's floor (at least MAX_SEALED_PDF_BYTES) still holds, and a region already
   * read is reused rather than skipped again, whether it is read in one role or
   * in more than one role. A test asserts the floor.
   */
  maxHeaderSkipBytes: Number.POSITIVE_INFINITY,
  /** Most hex digits in the signature's /Contents. */
  maxContentsHexDigits: 2 * 64 * 1024,
  /** Largest CMS SignedData. */
  maxCmsBytes: 64 * 1024,
  /** Most children read from one DER constructed value. */
  maxDerChildren: 256,
  /** Most certificates evaluated from the CMS certificates set; more is unsupported (VB-10). */
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
