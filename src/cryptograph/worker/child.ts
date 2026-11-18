// SPDX-License-Identifier: Apache-2.0
//
// The isolated sealing child (T037). Started only by launcher.ts, as
//
//   <pinned node> --max-old-space-size=<MiB> --permission
//     --allow-fs-read=<worker/> --allow-fs-read=<cms/> --allow-fs-read=<keys/>
//     --allow-fs-read=<compose/bounds.ts> --disallow-code-generation-from-strings
//     <worker/child.ts>
//
// with an empty environment, no argument after the entry, and exactly four
// descriptors: 0 the request pipe, 1 the reply pipe, 2 /dev/null, and 3
// (KEY_FD) a descriptor the parent's caller (T038) opened on the key file.
//
// 1. It refuses (worker-isolation) unless its environment is empty and the
//    permission model is active with no fs-write, child-process or worker
//    grant, so it can neither write files nor start processes.
// 2. It reads one request frame from fd 0 (frame.ts), bounded before
//    allocation, and refuses a short, long or malformed frame.
// 3. It checks the placeholder and the written /ByteRange (embed.ts).
// 4. It loads the key with T013's adapter on fd 3, which checks custody by
//    fstat: a regular file owned by this user with no group or other bit and at
//    most 16 KiB; a pipe, FIFO, socket, directory or device is refused. It also
//    refuses while PEM key text is visible in env or argv (KEY-02). fd 3 is
//    closed straight after the load.
//    ASSUMPTION P1 (Phase B must confirm on 24.22.2): the permission model
//    does not gate operations on an already-open descriptor (a documented
//    limitation), so fstat and read on fd 3 work without any read grant on the
//    key's path.
// 5. contentDigest = contentDigestOf(the two spans); the CMS is built with the
//    approval-evidence digest exactly as received (WK-05, A-008 S1).
// 6. The CMS is written over the placeholder of a copy; any other length is
//    refused (request #39, Part F).
// 7. It writes one reply frame (the sealed bytes and their SHA-256) and exits 0. A refusal carries only a reason
//    from errors.ts REASONS; nothing else leaves the process, and stderr is
//    /dev/null.

import { closeSync } from 'node:fs';
import { createHash } from 'node:crypto';

import { buildDetachedSignedData, CertificateError, CmsBuildError, contentDigestOf } from '../cms/index.ts';
import { loadDevelopmentSealKey, SealKeyError, type SealSigner } from '../keys/index.ts';
import { checkPlaceholder, embedSignedData, signedSpans, type SealGeometry } from './embed.ts';
import { keyReason, SealError, type SealFailureReason } from './errors.ts';
import { decodeRequest, encodeRefused, encodeSealed, KEY_FD, REQUEST_HEADER_BYTES, requestLength } from './frame.ts';

const sha256 = (data: Uint8Array): Uint8Array => createHash('sha256').update(data).digest();

function checkIsolation(): void {
  const permission = process.permission;
  const isolated =
    permission !== undefined &&
    !permission.has('fs.write') &&
    !permission.has('child') &&
    !permission.has('worker') &&
    Object.keys(process.env).length === 0 &&
    process.argv.length === 2;
  if (!isolated) throw new SealError('worker-isolation');
}

async function readRequest(): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let received = 0;
  let total = -1;
  for await (const chunk of process.stdin) {
    const buffer = chunk as Buffer;
    received += buffer.length;
    chunks.push(buffer);
    if (total === -1 && received >= REQUEST_HEADER_BYTES) total = requestLength(Buffer.concat(chunks, received).subarray(0, REQUEST_HEADER_BYTES));
    if (total !== -1 && received > total) throw new SealError('worker-protocol');
  }
  if (total === -1 || received !== total) throw new SealError('worker-protocol');
  return Buffer.concat(chunks, received);
}

function loadKey(): SealSigner {
  try {
    return loadDevelopmentSealKey({ fd: KEY_FD });
  } finally {
    try {
      closeSync(KEY_FD);
    } catch {
      // Not open: the adapter has already refused it.
    }
  }
}

function reasonOf(error: unknown): SealFailureReason {
  if (error instanceof SealError) return error.reason;
  if (error instanceof SealKeyError) return keyReason(error.code);
  if (error instanceof CertificateError) return 'certificate-invalid';
  if (error instanceof CmsBuildError) {
    if (error.code === 'key-certificate-mismatch') return 'key-certificate-mismatch';
    if (error.code === 'digest-invalid' || error.code === 'input-invalid') return 'input-invalid';
    return 'key-signer-failed';
  }
  return 'worker-crashed';
}

async function seal(): Promise<Buffer> {
  checkIsolation();
  const request = decodeRequest(await readRequest());
  const geometry: SealGeometry = {
    byteRange: request.byteRange,
    contentsOffset: request.contentsOffset,
    contentsHexLength: request.contentsHexLength,
  };
  checkPlaceholder(request.document, geometry);
  const signer = loadKey();
  const contentDigest = contentDigestOf(signedSpans(request.document, request.byteRange));
  const cms = buildDetachedSignedData({
    contentDigest,
    approvalEvidenceDigest: request.approvalEvidenceDigest,
    certificateDer: request.certificateDer,
    signer,
  });
  const sealed = embedSignedData(request.document, geometry, cms);
  return encodeSealed({ document: sealed, finalPdfDigest: sha256(sealed) });
}

let reply: Buffer;
try {
  reply = await seal();
} catch (error) {
  reply = encodeRefused(reasonOf(error));
}
process.stdout.write(reply);
process.exitCode = 0;
