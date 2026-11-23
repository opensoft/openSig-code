// SPDX-License-Identifier: Apache-2.0
//
// Blob keys: tenants/<tenant_id>/sha256/<digest>, where digest is the
// lowercase hex SHA-256 of the exact bytes. The same form is enforced by the
// T003 schema on every *_blob_ref column.

import { StorageUsageError } from '../db/errors.ts';
import { TENANT_ID_PATTERN } from '../db/tenant-store.ts';

export const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
export const BLOB_REF_PATTERN = /^tenants\/([A-Za-z0-9_-]{16,64})\/sha256\/([0-9a-f]{64})$/;

export interface BlobKey {
  readonly tenantId: string;
  readonly digest: string;
}

export function checkTenantId(tenantId: unknown): string {
  if (typeof tenantId !== 'string' || !TENANT_ID_PATTERN.test(tenantId)) {
    throw new StorageUsageError('tenant id must match ^[A-Za-z0-9_-]{16,64}$');
  }
  return tenantId;
}

export function checkDigest(digest: unknown): string {
  if (typeof digest !== 'string' || !DIGEST_PATTERN.test(digest)) {
    throw new StorageUsageError('blob digest must be lowercase hex SHA-256');
  }
  return digest;
}

export function blobRef(tenantId: string, digest: string): string {
  return `tenants/${checkTenantId(tenantId)}/sha256/${checkDigest(digest)}`;
}

export function parseBlobRef(ref: unknown): BlobKey {
  const match = typeof ref === 'string' ? BLOB_REF_PATTERN.exec(ref) : null;
  if (match === null || match[1] === undefined || match[2] === undefined) {
    throw new StorageUsageError('blob ref must be tenants/<tenant_id>/sha256/<digest>');
  }
  return { tenantId: match[1], digest: match[2] };
}
