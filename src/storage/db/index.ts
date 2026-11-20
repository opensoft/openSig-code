// SPDX-License-Identifier: Apache-2.0
//
// Public surface of the node:sqlite storage layer (T003). The one-shot
// restricted insert (claimRestrictedInsert in tenant-store.ts) is deliberately
// not re-exported here: only src/storage/audit/writer.ts claims it.

export {
  Database,
  DEFAULT_BUSY_TIMEOUT_MS,
  MAX_BUSY_TIMEOUT_MS,
  MIN_BUSY_TIMEOUT_MS,
  openDatabase,
  type CapabilityOwner,
  type OpenOptions,
} from './connection.ts';
export {
  MigrationError,
  StorageBusyError,
  StorageConstraintError,
  StorageError,
  StorageLimitError,
  StorageUsageError,
  type ConstraintKind,
} from './errors.ts';
export type { MigrationResult } from './migrate.ts';
export {
  MAX_LIST_LIMIT,
  TENANT_ID_PATTERN,
  TenantStore,
  type Comparison,
  type IterateOptions,
  type ListOptions,
  type OrderBy,
  type Row,
  type SqlValue,
  type Values,
  type Where,
} from './tenant-store.ts';
