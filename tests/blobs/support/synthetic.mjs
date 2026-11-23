// SPDX-License-Identifier: Apache-2.0
//
// Deterministic synthetic content for the blob store tests: SHA-256 in
// counter mode over a seed label. No real documents are used.

import { createHash } from 'node:crypto';

export function syntheticBytes(seed, size) {
  const out = Buffer.alloc(size);
  for (let offset = 0, block = 0; offset < size; block += 1) {
    const digest = createHash('sha256').update(`opensig-blob-test:${seed}:${block}`).digest();
    offset += digest.copy(out, offset, 0, Math.min(digest.length, size - offset));
  }
  return out;
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
