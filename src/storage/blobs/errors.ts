// SPDX-License-Identifier: Apache-2.0
//
// Blob store errors. Messages name the tenant and digest of a blob, never its
// content.

import { StorageError } from '../db/errors.ts';

/** No blob with this digest exists in the tenant's namespace. */
export class BlobNotFoundError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('blob_not_found', message, options);
  }
}

/** The stored bytes do not hash to the blob's digest, or the entry is not a regular file. */
export class BlobIntegrityError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('blob_integrity', message, options);
  }
}

/** The bytes offered for writing do not hash to the digest the caller expected. */
export class BlobDigestMismatchError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('blob_digest_mismatch', message, options);
  }
}

/** The blob exceeds the store's size limit. */
export class BlobTooLargeError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('blob_too_large', message, options);
  }
}
