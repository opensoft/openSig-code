// SPDX-License-Identifier: Apache-2.0
//
// The sealing worker's wire frames (T037). Pure functions shared by the parent
// (launcher.ts) and the child (child.ts). Every length is a fixed-width
// big-endian u32 and is bounded before any allocation.
//
// Request, parent -> child on fd 0, written once and then ended:
//   0   8   magic "OSSEALQ1"
//   8   4   documentLength      (1 .. MAX_SEALED_PDF_BYTES)
//   12  4   certificateLength   (1 .. MAX_SIGNER_CERTIFICATE_BYTES)
//   16  16  byteRange           [b0, o1, o2, l2], four u32
//   32  4   contentsOffset
//   36  4   contentsHexLength
//   40  32  approvalEvidenceDigest
//   72  ..  certificate DER, then the composed document; nothing after it
//
// Reply, child -> parent on fd 1, written once:
//   0   8   magic "OSSEALR1"
//   8   1   status: 0 sealed, 1 refused
//   sealed:  9 u32 documentLength, 13 finalPdfDigest (32), 45 the sealed document
//   refused: 9 u8 reasonLength (1..64), 10 the reason in ASCII (errors.ts REASONS)
//
// The key never travels in a frame: it is fd 3, open on the key file itself.
//
// The document bound is T036's MAX_SEALED_PDF_BYTES (48 MiB, 50,331,648
// bytes), from src/cryptograph/compose/bounds.ts (landed at 5db851e and
// 574de5e; requests #44 and #45), which imports nothing, so the child's read
// grant on that one file covers its whole closure.

import { MAX_SIGNER_CERTIFICATE_BYTES, SHA256_BYTES } from '../cms/index.ts';
import { MAX_SEALED_PDF_BYTES } from '../compose/bounds.ts';
import { REASONS, SealError, type SealFailureReason } from './errors.ts';

export { MAX_SEALED_PDF_BYTES };

/** The child's descriptor for the key: open on the key file itself (request #39, Part F). */
export const KEY_FD = 3;

export const REQUEST_MAGIC = Buffer.from('OSSEALQ1', 'latin1');
export const REPLY_MAGIC = Buffer.from('OSSEALR1', 'latin1');
export const REQUEST_HEADER_BYTES = 72;
export const SEALED_HEADER_BYTES = 45;
const MAX_REASON_BYTES = 64;

export interface SealRequest {
  readonly document: Uint8Array;
  readonly certificateDer: Uint8Array;
  readonly byteRange: readonly [number, number, number, number];
  readonly contentsOffset: number;
  readonly contentsHexLength: number;
  readonly approvalEvidenceDigest: Uint8Array;
}

export interface SealedReply {
  readonly status: 'sealed';
  readonly document: Uint8Array;
  readonly finalPdfDigest: Uint8Array;
}

export interface RefusedReply {
  readonly status: 'refused';
  readonly reason: SealFailureReason;
}

const u32 = (value: number): boolean => Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;

export function encodeRequest(request: SealRequest): Buffer {
  const { document, certificateDer, byteRange, contentsOffset, contentsHexLength, approvalEvidenceDigest } = request;
  const fields = [...byteRange, contentsOffset, contentsHexLength];
  if (
    document.length < 1 ||
    document.length > MAX_SEALED_PDF_BYTES ||
    certificateDer.length < 1 ||
    certificateDer.length > MAX_SIGNER_CERTIFICATE_BYTES ||
    approvalEvidenceDigest.length !== SHA256_BYTES ||
    byteRange.length !== 4 ||
    !fields.every(u32)
  ) {
    throw new SealError('input-invalid');
  }
  const header = Buffer.alloc(REQUEST_HEADER_BYTES);
  REQUEST_MAGIC.copy(header, 0);
  header.writeUInt32BE(document.length, 8);
  header.writeUInt32BE(certificateDer.length, 12);
  byteRange.forEach((value, index) => header.writeUInt32BE(value, 16 + index * 4));
  header.writeUInt32BE(contentsOffset, 32);
  header.writeUInt32BE(contentsHexLength, 36);
  header.set(approvalEvidenceDigest, 40);
  return Buffer.concat([header, certificateDer, document]);
}

/** The total request length a header announces, or a worker-protocol refusal. */
export function requestLength(header: Uint8Array): number {
  const view = Buffer.from(header.buffer, header.byteOffset, header.length);
  if (view.length < REQUEST_HEADER_BYTES || !view.subarray(0, 8).equals(REQUEST_MAGIC)) throw new SealError('worker-protocol');
  const documentLength = view.readUInt32BE(8);
  const certificateLength = view.readUInt32BE(12);
  if (documentLength < 1 || documentLength > MAX_SEALED_PDF_BYTES) throw new SealError('worker-protocol');
  if (certificateLength < 1 || certificateLength > MAX_SIGNER_CERTIFICATE_BYTES) throw new SealError('worker-protocol');
  return REQUEST_HEADER_BYTES + certificateLength + documentLength;
}

/** Decode a complete request; the caller has read exactly requestLength() bytes. */
export function decodeRequest(frame: Uint8Array): SealRequest {
  const total = requestLength(frame);
  if (frame.length !== total) throw new SealError('worker-protocol');
  const view = Buffer.from(frame.buffer, frame.byteOffset, frame.length);
  const certificateLength = view.readUInt32BE(12);
  const byteRange = [0, 1, 2, 3].map((index) => view.readUInt32BE(16 + index * 4)) as [number, number, number, number];
  return Object.freeze({
    certificateDer: Uint8Array.from(view.subarray(REQUEST_HEADER_BYTES, REQUEST_HEADER_BYTES + certificateLength)),
    document: view.subarray(REQUEST_HEADER_BYTES + certificateLength),
    byteRange,
    contentsOffset: view.readUInt32BE(32),
    contentsHexLength: view.readUInt32BE(36),
    approvalEvidenceDigest: Uint8Array.from(view.subarray(40, 72)),
  });
}

export function encodeSealed(reply: Omit<SealedReply, 'status'>): Buffer {
  const header = Buffer.alloc(SEALED_HEADER_BYTES);
  REPLY_MAGIC.copy(header, 0);
  header.writeUInt8(0, 8);
  header.writeUInt32BE(reply.document.length, 9);
  header.set(reply.finalPdfDigest, 13);
  return Buffer.concat([header, reply.document]);
}

export function encodeRefused(reason: SealFailureReason): Buffer {
  const text = Buffer.from(REASONS.has(reason) ? reason : 'worker-protocol', 'latin1');
  return Buffer.concat([REPLY_MAGIC, Buffer.from([1, text.length]), text]);
}

/**
 * Decode a complete reply for a request whose document had `documentLength`
 * bytes. Anything else (a short or long frame, an unknown status or reason, a
 * different length) is a worker-protocol failure.
 */
export function decodeReply(frame: Uint8Array, documentLength: number): SealedReply | RefusedReply {
  const view = Buffer.from(frame.buffer, frame.byteOffset, frame.length);
  if (view.length < 10 || !view.subarray(0, 8).equals(REPLY_MAGIC)) throw new SealError('worker-protocol');
  const status = view.readUInt8(8);
  if (status === 1) {
    const length = view.readUInt8(9);
    if (length < 1 || length > MAX_REASON_BYTES || view.length !== 10 + length) throw new SealError('worker-protocol');
    const reason = view.subarray(10).toString('latin1');
    if (!REASONS.has(reason)) throw new SealError('worker-protocol');
    return Object.freeze({ status: 'refused', reason: reason as SealFailureReason });
  }
  if (status !== 0 || view.length !== SEALED_HEADER_BYTES + documentLength || view.readUInt32BE(9) !== documentLength) {
    throw new SealError('worker-protocol');
  }
  return Object.freeze({
    status: 'sealed',
    document: Uint8Array.from(view.subarray(SEALED_HEADER_BYTES)),
    finalPdfDigest: Uint8Array.from(view.subarray(13, SEALED_HEADER_BYTES)),
  });
}

/** The most bytes a reply to a document of `documentLength` bytes may hold. */
export function maxReplyBytes(documentLength: number): number {
  return SEALED_HEADER_BYTES + documentLength;
}
