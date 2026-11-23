// SPDX-License-Identifier: Apache-2.0
//
// The isolated sealing worker (T037), for the finalization runner (T038).
//
// sealComposedPdf({ composed, certificateDer, approvalEvidenceDigest, keyFd },
// { signal }) seals T036's composed revision in a child process (launcher.ts,
// child.ts) and resolves to the sealed bytes and their digests, or rejects with
// a SealError { code: 'seal_failed', reason, retryable } (errors.ts). The
// AbortSignal is the only option (request #44); an abort SIGKILLs the child,
// settles on 'close' and rejects with the retryable reason `aborted`.
//
// The interface T036 landed (src/cryptograph/compose/index.ts at b47c4ef;
// unchanged for T037 since 909172b except item 6, the bound and the layout):
// - `ComposedRevision.bytes` is the base plus one appended revision, final
//   except for the /Contents digits, which are ASCII "0".
// - `byteRange` is [0, o1, o2, l2], already written into the bytes; o1 is the
//   offset of "<", o2 the offset just after ">", o2 + l2 the length.
// - `contents` is { offset: o1 + 1, hexLength: 2 x signedDataLength } for the
//   certificate T036 sized the placeholder with; T037 seals with that same
//   certificate and refuses any other CMS length.
// - The /Sig layout is guaranteed (request #44, CP-05); see embed.ts.
// - `bytes.length` <= MAX_SEALED_PDF_BYTES: the composer refuses more (422
//   composition_too_large), so a larger input here breaks that invariant and
//   is refused, non-retryably, with T036's own predicate withinSealedBound().
// SealableRevision is the subset this module reads; ComposedRevision
// satisfies it structurally, so T038 passes it as it is. This module never
// imports the composer or compose/index.ts (which imports the parse service);
// the child imports only compose/bounds.ts. `digest`, `documentDigest`,
// `documentLength`, `signedDataLength`, `xrefKind`, `objects`, the field name
// and /M are not read here.
//
// Key custody (request #39, Part F): T038 opens OPENSIG_SEAL_KEY_FILE without
// following a final symbolic link and without blocking, for each attempt,
// passes the number as `keyFd`, and closes it afterwards. This module passes it
// to the child as fd 3 and never reads, checks or closes it; T013's adapter
// checks it in the child.
//
// Reported (lowercase hex SHA-256, data-model.md § Global rules), only what
// the T037 line requires (request #44, Q4):
// - finalPdfDigest: of the sealed bytes; FinalArtifact.artifact_digest, the
//   manifest's final_pdf_digest and the report's artifact_digest.
// - signerCertificateSha256: of the certificate the seal embeds;
//   seal.signer_certificate_sha256.
// SealError mirrors ComposeError's `code`, `reason` and `retryable` (it has no
// `status`, `detail` or `details`: a seal failure never reaches HTTP).

import { createHash } from 'node:crypto';

import { SHA256_BYTES } from '../cms/index.ts';
import { withinSealedBound } from '../compose/bounds.ts';
import { SealError } from './errors.ts';
import { CHILD_ENTRY, DEFAULT_SEAL_LIMITS, sealWith } from './launcher.ts';

export { SEAL_ERROR_CODE, SealError, type SealFailureReason } from './errors.ts';
export { MAX_SEALED_PDF_BYTES } from './frame.ts';

export interface SealableRevision {
  readonly bytes: Uint8Array;
  readonly byteRange: readonly [number, number, number, number];
  readonly contents: { readonly offset: number; readonly hexLength: number };
}

export interface SealInput {
  readonly composed: SealableRevision;
  readonly certificateDer: Uint8Array;
  readonly approvalEvidenceDigest: Uint8Array;
  readonly keyFd: number;
}

export interface SealOptions {
  readonly signal?: AbortSignal;
}

export interface SealedPdf {
  readonly bytes: Uint8Array;
  readonly finalPdfDigest: string;
  readonly signerCertificateSha256: string;
}

const INPUT_KEYS = ['approvalEvidenceDigest', 'certificateDer', 'composed', 'keyFd'];
const MAX_FD = 0x7fffffff;

function checkInput(input: unknown): SealInput {
  const invalid = new SealError('input-invalid');
  if (typeof input !== 'object' || input === null || Object.getPrototypeOf(input) !== Object.prototype) throw invalid;
  if (Object.keys(input).sort().join() !== INPUT_KEYS.join()) throw invalid;
  const { composed, certificateDer, approvalEvidenceDigest, keyFd } = input as SealInput;
  if (typeof composed !== 'object' || composed === null || !(composed.bytes instanceof Uint8Array)) throw invalid;
  if (!Array.isArray(composed.byteRange) || composed.byteRange.length !== 4) throw invalid;
  if (typeof composed.contents !== 'object' || composed.contents === null) throw invalid;
  if (![...composed.byteRange, composed.contents.offset, composed.contents.hexLength].every((v) => Number.isSafeInteger(v) && v >= 0 && v <= 0xffffffff)) throw invalid;
  if (composed.bytes.length < 1) throw invalid;
  if (!withinSealedBound(composed.bytes.length)) throw new SealError('document-too-large');
  if (!(certificateDer instanceof Uint8Array)) throw new SealError('certificate-invalid');
  if (!(approvalEvidenceDigest instanceof Uint8Array) || approvalEvidenceDigest.length !== SHA256_BYTES) throw invalid;
  if (!Number.isSafeInteger(keyFd) || keyFd < 3 || keyFd > MAX_FD) throw invalid;
  return { composed, certificateDer, approvalEvidenceDigest, keyFd };
}

function checkOptions(options: unknown): SealOptions {
  if (options === undefined) return {};
  const invalid = new SealError('input-invalid');
  if (typeof options !== 'object' || options === null || Object.getPrototypeOf(options) !== Object.prototype) throw invalid;
  const keys = Object.keys(options);
  if (keys.some((key) => key !== 'signal')) throw invalid;
  const { signal } = options as SealOptions;
  if (signal !== undefined && !(signal instanceof AbortSignal)) throw invalid;
  return signal === undefined ? {} : { signal };
}

/**
 * Seal T036's composed revision (see the header for the contract). The only
 * option is an AbortSignal; no caller can choose the child, its environment,
 * its argv or its limits (testing.ts holds the test seams).
 */
export async function sealComposedPdf(input: SealInput, options?: SealOptions): Promise<SealedPdf> {
  const checked = checkInput(input);
  const { signal } = checkOptions(options);
  const { composed } = checked;
  const reply = await sealWith(
    CHILD_ENTRY,
    {
      document: composed.bytes,
      certificateDer: checked.certificateDer,
      byteRange: [composed.byteRange[0], composed.byteRange[1], composed.byteRange[2], composed.byteRange[3]],
      contentsOffset: composed.contents.offset,
      contentsHexLength: composed.contents.hexLength,
      approvalEvidenceDigest: checked.approvalEvidenceDigest,
    },
    checked.keyFd,
    DEFAULT_SEAL_LIMITS,
    signal,
  );
  return Object.freeze({
    bytes: reply.document,
    finalPdfDigest: Buffer.from(reply.finalPdfDigest).toString('hex'),
    signerCertificateSha256: createHash('sha256').update(checked.certificateDer).digest('hex'),
  });
}
