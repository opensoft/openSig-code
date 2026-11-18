// SPDX-License-Identifier: Apache-2.0
//
// Test seams for the sealing worker (T037). Not exported from index.ts, and
// never used by the runner (T038).
//
// Each seam launches a test entry through the same launch as the real child:
// the same file, flags, empty environment and descriptors. The only
// differences are the entry and its read grant, which covers that entry file
// alone (sealWorkerCommand), and `limits`, which can only narrow. A test entry
// imports node: built-ins only.
// - sealRequestForTests: the full parent path (frame, limits, abort,
//   settlement, reply validation and error mapping) with a fault child in
//   place of the real one.
// - launchForTests: the raw outcome (exit, signal, flags, stdout, pid), for a
//   probe child that reports what it sees instead of a reply frame.

import { resolveSealLimits, runSealChild, sealWith, sealWorkerCommand, type ChildOutcome, type SealLimits } from './launcher.ts';
import { encodeRequest, maxReplyBytes, type SealedReply, type SealRequest } from './frame.ts';

export { CHILD_ENTRY, DEFAULT_SEAL_LIMITS, READ_GRANTS, resolveSealLimits, sealWorkerCommand, validateSealed } from './launcher.ts';
export { checkPlaceholder, embedSignedData, signedSpans, SIG_OBJECT_WINDOW } from './embed.ts';
export { decodeReply, decodeRequest, encodeRefused, encodeRequest, encodeSealed, KEY_FD, MAX_SEALED_PDF_BYTES } from './frame.ts';
export { isRetryable, REASONS } from './errors.ts';

export interface SeamOptions {
  readonly limits?: Partial<SealLimits>;
  readonly signal?: AbortSignal;
}

export function sealRequestForTests(entry: string, request: SealRequest, keyFd: number, options: SeamOptions = {}): Promise<SealedReply> {
  return sealWith(entry, request, keyFd, resolveSealLimits(options.limits), options.signal);
}

/** The raw outcome of a test entry; the reply cap is 64 KiB more than a sealed reply, for a probe's JSON. */
export function launchForTests(entry: string, request: SealRequest, keyFd: number, options: SeamOptions = {}): Promise<ChildOutcome> {
  const resolved = resolveSealLimits(options.limits);
  return runSealChild(sealWorkerCommand(resolved, entry), encodeRequest(request), keyFd, maxReplyBytes(request.document.length) + 64 * 1024, resolved.wallMs, options.signal);
}
