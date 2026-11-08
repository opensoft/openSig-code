// SPDX-License-Identifier: Apache-2.0
//
// Storage map of the data model (specs/001-corporate-signing-mvp/data-model.md,
// revision 2026-11-08 M4) and the write policy of every table.
//
// Every table created by a migration must appear in TABLES. The storage layer
// refuses tables without a policy, and tests/storage/ checks that the migrated
// schema and this map agree, so a later migration that adds a table must also
// add its policy here.

/**
 * How the generic tenant-scoped helpers may change rows of a table.
 * - mutable: insert, update and delete through the helpers.
 * - guarded: the helpers may try; schema triggers protect bound columns,
 *   single-use values and frozen rows.
 * - immutable: insert only. Update and delete are refused by the helpers and by
 *   schema triggers.
 */
export type Mutability = 'mutable' | 'guarded' | 'immutable';

/**
 * Who may insert rows.
 * - store: any tenant-scoped store.
 * - restricted: only the restricted writer (src/storage/db/restricted-writer.ts),
 *   reserved for the audit chain.
 */
export type Writer = 'store' | 'restricted';

export interface TablePolicy {
  readonly entity: string;
  readonly mutability: Mutability;
  readonly writer: Writer;
  /** A hash column that resolves a presented capability to its tenant. */
  readonly capabilityColumn?: string;
}

export const DATA_MODEL_REVISION = '2026-11-08 (M4)';

export const SYSTEM_TABLES: readonly string[] = Object.freeze(['schema_migrations']);

export const TABLES: Readonly<Record<string, TablePolicy>> = Object.freeze({
  tenants: { entity: 'Tenant', mutability: 'mutable', writer: 'store' },
  consent_texts: { entity: 'ConsentText', mutability: 'immutable', writer: 'store' },
  envelopes: { entity: 'Envelope', mutability: 'mutable', writer: 'store' },
  document_revisions: { entity: 'DocumentRevision', mutability: 'guarded', writer: 'store' },
  recipients: { entity: 'Recipient', mutability: 'mutable', writer: 'store' },
  field_definitions: { entity: 'FieldDefinition', mutability: 'mutable', writer: 'store' },
  field_manifests: { entity: 'FieldManifest', mutability: 'immutable', writer: 'store' },
  send_confirmations: { entity: 'SendConfirmation', mutability: 'guarded', writer: 'store' },
  invitations: { entity: 'Invitation', mutability: 'guarded', writer: 'store', capabilityColumn: 'token_hash' },
  challenges: { entity: 'Challenge', mutability: 'guarded', writer: 'store' },
  recipient_sessions: {
    entity: 'RecipientSession',
    mutability: 'guarded',
    writer: 'store',
    capabilityColumn: 'value_hash',
  },
  approvals: { entity: 'Approval', mutability: 'immutable', writer: 'store' },
  idempotency_records: { entity: 'IdempotencyRecord', mutability: 'guarded', writer: 'store' },
  signing_jobs: { entity: 'SigningJob', mutability: 'guarded', writer: 'store' },
  final_artifacts: { entity: 'FinalArtifact', mutability: 'guarded', writer: 'store' },
  verification_reports: { entity: 'VerificationReport', mutability: 'immutable', writer: 'store' },
  audit_events: { entity: 'AuditEvent', mutability: 'immutable', writer: 'restricted' },
  audit_checkpoints: { entity: 'AuditCheckpoint', mutability: 'immutable', writer: 'restricted' },
  outbox_events: { entity: 'OutboxEvent', mutability: 'guarded', writer: 'store' },
  webhook_registrations: { entity: 'WebhookRegistration / WebhookKey', mutability: 'mutable', writer: 'store' },
  webhook_keys: { entity: 'WebhookRegistration / WebhookKey', mutability: 'guarded', writer: 'store' },
  consumer_attachments: { entity: 'ConsumerAttachment', mutability: 'mutable', writer: 'store' },
  anchor_receipts: { entity: 'AnchorReceipt', mutability: 'mutable', writer: 'store' },
  disposal_records: { entity: 'DisposalRecord', mutability: 'immutable', writer: 'store' },
});

/**
 * Entities that the data model defines as derived rather than stored. Each
 * value says where the entity's data is persisted instead.
 */
export const DERIVED_ENTITIES: Readonly<Record<string, string>> = Object.freeze({
  Principal:
    'derived per request from validated OIDC claims; persisted only as {kind, ref} references ' +
    '(envelopes.created_by_*, send_confirmations.confirmed_by_*, idempotency_records.principal_*, ' +
    'audit_events.actor_*)',
});

/** Entity name to the tables that persist it ([] for a derived entity). */
export function entityTables(): ReadonlyMap<string, readonly string[]> {
  const map = new Map<string, string[]>();
  for (const name of Object.keys(DERIVED_ENTITIES)) map.set(name, []);
  for (const [table, policy] of Object.entries(TABLES)) {
    const tables = map.get(policy.entity) ?? [];
    tables.push(table);
    map.set(policy.entity, tables);
  }
  return map;
}

export function tablePolicy(table: string): TablePolicy | undefined {
  return Object.hasOwn(TABLES, table) ? TABLES[table] : undefined;
}
