// SPDX-License-Identifier: Apache-2.0
//
// The restricted write path for tables whose policy writer is 'restricted'
// (audit_events and audit_checkpoints). The generic TenantStore.insert refuses
// those tables. This module is intended for src/storage/audit/ only and is not
// exported from index.ts, so an import-boundary check can name its importers.
// Rows still get tenant_id from the store, and the schema triggers still
// enforce chain linkage and append-only behavior.

import { restrictedInsert, type TenantStore, type Values } from './tenant-store.ts';

export function appendRestricted(store: TenantStore, table: string, values: Values): void {
  restrictedInsert(store, table, values);
}
