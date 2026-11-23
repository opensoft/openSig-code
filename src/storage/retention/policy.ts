// SPDX-License-Identifier: Apache-2.0
//
// Tenant retention policy, read from tenants.retention_json. NULL means
// retain: nothing is disposed. A present policy is parsed strictly and an
// invalid one fails closed (the run refuses and disposes nothing):
//
//   { "policy_ref": "<1..200 chars>",
//     "dispose_after_days": <integer 1..36500>,
//     "scope": "documents" | "all" }          (scope optional, default documents)
//
// scope "documents" disposes only document revision blobs (the uploaded
// working copies) and keeps the completed evidence blobs; scope "all" also
// disposes the final PDF, evidence and package blobs. Either way the digests
// of the final artifact stay recorded in the DisposalRecord.

import { parseJson } from '../../domain/canonical/index.ts';
import { StorageError } from '../db/errors.ts';

export type RetentionScope = 'documents' | 'all';

export interface RetentionPolicy {
  readonly policyRef: string;
  readonly disposeAfterDays: number;
  readonly scope: RetentionScope;
}

export class RetentionPolicyError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('retention_policy_invalid', message, options);
  }
}

const KEYS: ReadonlySet<string> = new Set(['policy_ref', 'dispose_after_days', 'scope']);
export const MAX_RETENTION_DAYS = 36_500;

export function parseRetentionPolicy(json: unknown): RetentionPolicy | null {
  if (json === null || json === undefined) return null;
  if (typeof json !== 'string') throw new RetentionPolicyError('retention configuration must be JSON text');
  let value;
  try {
    value = parseJson(json);
  } catch (error) {
    throw new RetentionPolicyError('retention configuration is not valid JSON', { cause: error });
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new RetentionPolicyError('retention configuration must be a JSON object');
  }
  for (const key of Object.keys(value)) {
    if (!KEYS.has(key)) throw new RetentionPolicyError(`unknown retention setting ${JSON.stringify(key)}`);
  }
  const policyRef = value['policy_ref'];
  if (typeof policyRef !== 'string' || policyRef.length < 1 || policyRef.length > 200) {
    throw new RetentionPolicyError('policy_ref must be a string of 1..200 characters');
  }
  const days = value['dispose_after_days'];
  if (typeof days !== 'number' || !Number.isSafeInteger(days) || days < 1 || days > MAX_RETENTION_DAYS) {
    throw new RetentionPolicyError(`dispose_after_days must be an integer in 1..${MAX_RETENTION_DAYS}`);
  }
  const scope = value['scope'] ?? 'documents';
  if (scope !== 'documents' && scope !== 'all') throw new RetentionPolicyError('scope must be "documents" or "all"');
  return { policyRef, disposeAfterDays: days, scope };
}
