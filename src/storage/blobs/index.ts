// SPDX-License-Identifier: Apache-2.0
//
// Public surface of the blob store (T028).

export { BlobDigestMismatchError, BlobIntegrityError, BlobNotFoundError, BlobTooLargeError } from './errors.ts';
export {
  DEFAULT_MAX_BLOB_BYTES,
  FileBlobStore,
  MAX_BLOB_BYTES_LIMIT,
  openBlobStore,
  type BlobStatus,
  type BlobStore,
  type BlobStoreOptions,
  type PutOptions,
  type PutResult,
} from './file-store.ts';
export { nodeFsOps, type FsOps } from './fs-ops.ts';
export { BLOB_REF_PATTERN, blobRef, DIGEST_PATTERN, parseBlobRef, type BlobKey } from './refs.ts';
