// SPDX-License-Identifier: Apache-2.0
//
// The exported-head ledger: per tenant, the most advanced audit chain head
// that has left the system (in a backup, and later in audit receipts). It is
// kept in a file outside the database, so restoring an older database cannot
// roll it back, and restore refuses any backup whose chain does not contain
// the recorded head. Heads only move forward; a different digest at a
// recorded seq is a divergence and is refused.
//
// Format (RFC 8785 canonical JSON, mode 0600):
//   { "schema": "opensig.exported-heads/1",
//     "tenants": { "<tenant_id>": { "seq": n, "digest": hex, "exported_at": iso, "source": "backup" } } }

import { lstatSync, readFileSync } from 'node:fs';

import { canonicalize, parseJson, type JsonValue } from '../../domain/canonical/index.ts';
import { StorageError, StorageUsageError } from '../db/errors.ts';
import { checkAbsolute, replaceFileAtomically } from './files.ts';

export const LEDGER_SCHEMA = 'opensig.exported-heads/1';

export interface ExportedHead {
  readonly seq: number;
  readonly digest: string;
  readonly exported_at: string;
  readonly source: string;
}

export type Ledger = Readonly<Record<string, ExportedHead>>;

export class LedgerError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('ledger_invalid', message, options);
  }
}

const TENANT = /^[A-Za-z0-9_-]{16,64}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const SOURCE = /^[a-z][a-z0-9_.-]{0,39}$/;

function checkHead(tenantId: string, value: unknown): ExportedHead {
  if (!TENANT.test(tenantId) || value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new LedgerError('ledger entry is malformed');
  }
  const entry = value as Record<string, unknown>;
  const keys = Object.keys(entry).sort().join(',');
  if (keys !== 'digest,exported_at,seq,source') throw new LedgerError('ledger entry has unexpected fields');
  const { seq, digest, exported_at: exportedAt, source } = entry;
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 1) throw new LedgerError('ledger seq is malformed');
  if (typeof digest !== 'string' || !DIGEST.test(digest)) throw new LedgerError('ledger digest is malformed');
  if (typeof exportedAt !== 'string' || Number.isNaN(Date.parse(exportedAt))) throw new LedgerError('ledger exported_at is malformed');
  if (typeof source !== 'string' || !SOURCE.test(source)) throw new LedgerError('ledger source is malformed');
  return { seq, digest, exported_at: exportedAt, source };
}

/** Read the ledger; a missing file is an empty ledger. */
export function readLedger(path: string): Ledger {
  checkAbsolute(path, 'ledger path');
  const stat = lstatSync(path, { throwIfNoEntry: false });
  if (stat === undefined) return {};
  if (!stat.isFile()) throw new LedgerError('ledger path is not a regular file');
  let value: JsonValue;
  try {
    value = parseJson(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new LedgerError('ledger is not valid JSON', { cause: error });
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value) || value['schema'] !== LEDGER_SCHEMA) {
    throw new LedgerError('ledger schema is not recognized');
  }
  const tenants = value['tenants'];
  if (tenants === null || typeof tenants !== 'object' || Array.isArray(tenants) || Object.keys(value).length !== 2) {
    throw new LedgerError('ledger tenants are malformed');
  }
  const ledger: Record<string, ExportedHead> = {};
  for (const [tenantId, entry] of Object.entries(tenants)) ledger[tenantId] = checkHead(tenantId, entry);
  return ledger;
}

export interface RecordOptions {
  readonly clock: () => Date;
  readonly source: string;
}

/**
 * Record that `head` left the system for `tenantId`. Keeps the more advanced
 * head; refuses a different digest at an already recorded seq.
 */
export function recordExportedHead(path: string, tenantId: string, head: { readonly seq: number; readonly digest: string }, options: RecordOptions): ExportedHead {
  if (!TENANT.test(tenantId)) throw new StorageUsageError('tenant id is malformed');
  if (!SOURCE.test(options.source)) throw new StorageUsageError('ledger source is malformed');
  const now = options.clock();
  const candidate = checkHead(tenantId, { seq: head.seq, digest: head.digest, exported_at: now.toISOString(), source: options.source });
  const ledger: Record<string, ExportedHead> = { ...readLedger(path) };
  const existing = ledger[tenantId];
  if (existing !== undefined) {
    if (existing.seq === candidate.seq && existing.digest !== candidate.digest) {
      throw new LedgerError('the chain diverged: a different digest was already exported at this seq');
    }
    if (existing.seq >= candidate.seq) return existing;
  }
  ledger[tenantId] = candidate;
  const document = { schema: LEDGER_SCHEMA, tenants: ledger } as unknown as JsonValue;
  replaceFileAtomically(path, Buffer.from(canonicalize(document), 'utf8'));
  return candidate;
}
