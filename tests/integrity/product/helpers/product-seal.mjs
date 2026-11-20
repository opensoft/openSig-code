// SPDX-License-Identifier: Apache-2.0
//
// Product-sealed outputs for T014's agreement tests (VB-05), and product
// compositions for the loose-start structure cases (VB-06, request #49). The
// bytes come from the product's own path: T036's composeSealRevision (landed at
// b47c4ef), which parses the base through T033's parse service, then T037's
// sealComposedPdf (draft), which builds the CMS with T013 in its child process
// and embeds it. The digests the sealing step reports are the expected values
// given to BOTH checkers, never re-derived from the bytes under test (request
// #41's rule).
//
// Every assumption about these interfaces lives here and in product-compose.mjs,
// so Phase B adapts two small files. CONFIRMED: P1, the composer's request and
// result types, from the type extract request #56 B7 allows (see
// product-compose.mjs); MAX_SEALED_PDF_BYTES is exported from
// compose/bounds.ts, and T037's draft re-exports it. ASSUMED, to confirm against
// T037's landed sealComposedPdf extract at Phase B:
// P2 (T037 draft) sealComposedPdf({ composed, certificateDer,
//    approvalEvidenceDigest, keyFd }, { signal }) resolves to { bytes,
//    finalPdfDigest, signerCertificateSha256 }, the digests lowercase hex
//    SHA-256; a ComposedRevision satisfies its SealableRevision as it is.
// P3 (T037 draft) the caller opens the key file without following a final
//    symbolic link and without blocking, passes the descriptor as `keyFd`, and
//    closes it afterwards; the worker never closes it.
// P4 (T013, checked in T037's child) the oracle's runtime key file
//    (prepareMaterial: RSA-3072, exponent 65537, mode 0600 in a 0700 directory,
//    owned by the test user) passes T013's adapter. No key is created, copied
//    or printed here.
// P5 the certificate given to the composer is the one given to the worker
//    (T036 sizes the placeholder; T037 refuses any other CMS length), and the
//    evidence digest goes to the worker as its 32 raw bytes.
// P6 composing needs T033's parse sandbox (bubblewrap or unshare), which the
//    `verification` mode does not declare: without it VB-05 and the composed
//    VB-06 cases FAIL, never CAPABILITY_ABSENT and never skipped (request #44;
//    request #56 B5).

import { Buffer } from 'node:buffer';
import { createHash, X509Certificate } from 'node:crypto';
import { closeSync, constants, openSync, readFileSync } from 'node:fs';
import { sealComposedPdf } from '../../../../src/cryptograph/worker/index.ts';
import { composeWithProduct, SEAL_TIME } from './product-compose.mjs';

export { SEAL_TIME };

/** A synthetic approval-manifest digest for a label (stands in for T038's pre-seal manifest digest). */
export function syntheticEvidenceDigest(label) {
  return createHash('sha256').update(`opensig synthetic approval manifest ${label}`, 'utf8').digest('hex');
}

/**
 * Seal `document` through T036 then T037 with an oracle-material signer
 * ({ certPath, keyPath }). Returns { bytes, artifactDigest,
 * signerCertificateSha256, approvalEvidenceDigest } as the sealing step reports them.
 */
export async function sealWithProduct({ document, signer, approvalEvidenceDigest, sealTime = SEAL_TIME }) {
  const certificateDer = new Uint8Array(new X509Certificate(readFileSync(signer.certPath)).raw);
  const composed = await composeWithProduct({ document, certificateDer, sealTime });
  const keyFd = openSync(signer.keyPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const sealed = await sealComposedPdf({
      composed,
      certificateDer,
      approvalEvidenceDigest: new Uint8Array(Buffer.from(approvalEvidenceDigest, 'hex')),
      keyFd,
    });
    return {
      bytes: Buffer.from(sealed.bytes),
      artifactDigest: sealed.finalPdfDigest,
      signerCertificateSha256: sealed.signerCertificateSha256,
      approvalEvidenceDigest,
    };
  } finally {
    closeSync(keyFd);
  }
}
