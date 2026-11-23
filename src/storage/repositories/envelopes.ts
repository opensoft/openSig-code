// SPDX-License-Identifier: Apache-2.0
//
// Envelope repository (T007): typed reads and writes of envelopes, recipients,
// document revisions, field definitions, field manifests and send
// confirmations, through the tenant-scoped store only (every statement is
// filtered to the store's tenant). Writes need the caller's transaction
// (Database.transaction, BEGIN IMMEDIATE).
//
// compareAndSetEnvelope is the single compare-and-set path for envelope rows:
// it matches (id, version) and moves the version by exactly one, as migration
// 0010 requires for every change of state or content.

import type { Row, TenantStore, Values } from '../db/index.ts';
import { StorageUsageError } from '../db/index.ts';
import { isEnvelopeState, isRecipientStatus, type EnvelopeState, type RecipientStatus } from '../../domain/envelopes/states.ts';
import type { StoredPage } from '../../domain/envelopes/placement.ts';
import type { Actor, DocumentInput, PageGeometry, Rect, Source } from '../../domain/envelopes/validation.ts';

export interface EnvelopeRecord {
  readonly id: string;
  readonly version: number;
  readonly state: EnvelopeState;
  readonly createdBy: Actor;
  readonly source: Source;
  readonly expiresAt: string;
  readonly recipientsCount: number;
  readonly baseRevisionId: string | null;
  readonly manifestDigest: string | null;
  readonly recipientsDigest: string | null;
  readonly approvalsComplete: boolean;
  readonly reissueOf: string | null;
  readonly reissuedAs: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface RecipientRecord {
  readonly id: string;
  readonly envelopeId: string;
  readonly ordinal: number;
  readonly email: string;
  readonly role: string;
  readonly status: RecipientStatus;
  readonly invitedAt: string | null;
  readonly approvedAt: string | null;
  readonly approvalId: string | null;
  /** The approval_digest of this recipient's approval, when it has one. */
  readonly approvalDigest: string | null;
}

export interface RevisionRecord {
  readonly id: string;
  readonly envelopeId: string;
  readonly contentDigest: string;
  readonly blobRef: string;
  readonly bytes: number;
  readonly pages: readonly PageGeometry[];
  readonly pageGeometryJson: string;
  readonly parseReportJson: string;
  readonly createdAt: string;
  readonly frozenAt: string | null;
}

export interface FieldRecord {
  readonly key: string;
  readonly revisionId: string;
  readonly recipientId: string;
  readonly recipientOrdinal: number;
  readonly page: number;
  readonly type: 'signature' | 'date';
  readonly rect: Rect;
}

export interface ManifestRecord {
  readonly revisionId: string;
  readonly schema: string;
  readonly digest: string;
  readonly bytes: Uint8Array;
}

export interface SendConfirmationRecord {
  readonly authorizationReference: string;
  readonly envelopeId: string;
  readonly envelopeVersion: number;
  readonly documentDigest: string;
  readonly manifestDigest: string;
  readonly recipientsDigest: string;
  readonly confirmedBy: Actor;
  readonly confirmedAt: string;
  readonly expiresAt: string;
  readonly consumedAt: string | null;
}

export interface SigningJobRecord {
  readonly status: 'pending' | 'running' | 'retryable' | 'failed' | 'succeeded';
  readonly attemptCount: number;
  readonly maxAttempts: number;
  readonly retryAt: string | null;
  readonly lastErrorCode: string | null;
}

export interface FinalArtifactRecord {
  readonly artifactId: string;
  readonly artifactDigest: string;
  readonly packageDigest: string | null;
  readonly verificationJson: string;
  readonly completedAt: string;
}

export interface EnvelopeAggregate {
  readonly envelope: EnvelopeRecord;
  readonly recipients: readonly RecipientRecord[];
  readonly revision: RevisionRecord | null;
  readonly fields: readonly FieldRecord[];
  readonly manifest: ManifestRecord | null;
  readonly job: SigningJobRecord | null;
  readonly artifact: FinalArtifactRecord | null;
}

function stored(table: string, column: string): StorageUsageError {
  return new StorageUsageError(`${table}.${column} holds an unexpected value`);
}

function str(row: Row, table: string, column: string): string {
  const value = row[column];
  if (typeof value !== 'string') throw stored(table, column);
  return value;
}

function optStr(row: Row, table: string, column: string): string | null {
  const value = row[column];
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') throw stored(table, column);
  return value;
}

function int(row: Row, table: string, column: string): number {
  const value = row[column];
  const n = typeof value === 'bigint' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isSafeInteger(n)) throw stored(table, column);
  return n;
}

function real(row: Row, table: string, column: string): number {
  const value = row[column];
  if (typeof value !== 'number' || !Number.isFinite(value)) throw stored(table, column);
  return value;
}

function principalKind(value: string, table: string, column: string): Actor['kind'] {
  if (value !== 'human-operator' && value !== 'service') throw stored(table, column);
  return value;
}

function one(changed: number, what: string): void {
  if (changed !== 1) throw new StorageUsageError(`${what} changed ${changed} rows, expected exactly one`);
}

export function blobRefFor(tenantId: string, digest: string): string {
  return `tenants/${tenantId}/sha256/${digest}`;
}

// ------------------------------------------------------------------ envelopes

function envelopeFromRow(row: Row): EnvelopeRecord {
  const state = row['state'];
  if (!isEnvelopeState(state)) throw stored('envelopes', 'state');
  const app = str(row, 'envelopes', 'source_app');
  return {
    id: str(row, 'envelopes', 'id'),
    version: int(row, 'envelopes', 'version'),
    state,
    createdBy: {
      kind: principalKind(str(row, 'envelopes', 'created_by_kind'), 'envelopes', 'created_by_kind'),
      ref: str(row, 'envelopes', 'created_by_ref'),
    },
    source: { app: app as Source['app'], record: str(row, 'envelopes', 'source_record'), version: str(row, 'envelopes', 'source_version') },
    expiresAt: str(row, 'envelopes', 'expires_at'),
    recipientsCount: int(row, 'envelopes', 'recipients_count'),
    baseRevisionId: optStr(row, 'envelopes', 'base_revision_id'),
    manifestDigest: optStr(row, 'envelopes', 'manifest_digest'),
    recipientsDigest: optStr(row, 'envelopes', 'recipients_digest'),
    approvalsComplete: int(row, 'envelopes', 'approvals_complete') === 1,
    reissueOf: optStr(row, 'envelopes', 'reissue_of'),
    reissuedAs: optStr(row, 'envelopes', 'reissued_as'),
    createdAt: str(row, 'envelopes', 'created_at'),
    updatedAt: str(row, 'envelopes', 'updated_at'),
  };
}

export interface NewEnvelope {
  readonly id: string;
  readonly source: Source;
  readonly createdBy: Actor;
  readonly expiresAt: string;
  readonly recipientsCount: number;
  readonly reissueOf: string | null;
  readonly now: string;
}

/** Insert a new envelope: always draft at version 1 (data-model.md § Envelope states, Inserts). */
export function insertEnvelope(store: TenantStore, envelope: NewEnvelope): void {
  store.insert('envelopes', {
    id: envelope.id,
    source_app: envelope.source.app,
    source_record: envelope.source.record,
    source_version: envelope.source.version,
    state: 'draft',
    version: 1,
    created_by_kind: envelope.createdBy.kind,
    created_by_ref: envelope.createdBy.ref,
    expires_at: envelope.expiresAt,
    recipients_count: envelope.recipientsCount,
    reissue_of: envelope.reissueOf,
    created_at: envelope.now,
    updated_at: envelope.now,
  });
}

export function getEnvelope(store: TenantStore, envelopeId: string): EnvelopeRecord | undefined {
  const row = store.get('envelopes', { id: envelopeId });
  return row === undefined ? undefined : envelopeFromRow(row);
}

/** The envelope columns a compare-and-set may write; updated_at is always written. */
export interface EnvelopeChanges {
  readonly state?: EnvelopeState;
  readonly baseRevisionId?: string;
  readonly manifestDigest?: string;
  readonly recipientsDigest?: string;
  readonly approvalsComplete?: boolean;
  readonly reissuedAs?: string;
  readonly updatedAt: string;
}

/**
 * The single compare-and-set path: update the envelope only if its version is
 * still `expectedVersion`, and move the version by exactly one. Returns false
 * when the version moved on (or the envelope is not in this tenant).
 */
export function compareAndSetEnvelope(store: TenantStore, envelopeId: string, expectedVersion: number, changes: EnvelopeChanges): boolean {
  const values: Record<string, string | number> = { updated_at: changes.updatedAt };
  if (changes.state !== undefined) values['state'] = changes.state;
  if (changes.baseRevisionId !== undefined) values['base_revision_id'] = changes.baseRevisionId;
  if (changes.manifestDigest !== undefined) values['manifest_digest'] = changes.manifestDigest;
  if (changes.recipientsDigest !== undefined) values['recipients_digest'] = changes.recipientsDigest;
  if (changes.approvalsComplete !== undefined) values['approvals_complete'] = changes.approvalsComplete ? 1 : 0;
  if (changes.reissuedAs !== undefined) values['reissued_as'] = changes.reissuedAs;
  return store.compareAndSet('envelopes', { id: envelopeId }, expectedVersion, values);
}

// ----------------------------------------------------------------- recipients

export interface NewRecipient {
  readonly id: string;
  readonly envelopeId: string;
  readonly ordinal: number;
  readonly email: string;
  readonly role: string;
  readonly now: string;
}

export function insertRecipient(store: TenantStore, recipient: NewRecipient): void {
  store.insert('recipients', {
    id: recipient.id,
    envelope_id: recipient.envelopeId,
    ordinal: recipient.ordinal,
    email: recipient.email,
    role: recipient.role,
    status: 'pending',
    created_at: recipient.now,
    updated_at: recipient.now,
  });
}

export function listRecipients(store: TenantStore, envelopeId: string): RecipientRecord[] {
  const digests = new Map<string, string>();
  for (const row of store.list('approvals', { envelope_id: envelopeId }, { limit: 2 })) {
    digests.set(str(row, 'approvals', 'recipient_id'), str(row, 'approvals', 'approval_digest'));
  }
  return store.list('recipients', { envelope_id: envelopeId }, { orderBy: [['ordinal', 'asc']], limit: 2 }).map((row) => {
    const status = row['status'];
    if (!isRecipientStatus(status)) throw stored('recipients', 'status');
    const id = str(row, 'recipients', 'id');
    return {
      id,
      envelopeId,
      ordinal: int(row, 'recipients', 'ordinal'),
      email: str(row, 'recipients', 'email'),
      role: str(row, 'recipients', 'role'),
      status,
      invitedAt: optStr(row, 'recipients', 'invited_at'),
      approvedAt: optStr(row, 'recipients', 'approved_at'),
      approvalId: optStr(row, 'recipients', 'approval_id'),
      approvalDigest: digests.get(id) ?? null,
    };
  });
}

export interface RecipientProgress {
  readonly status: RecipientStatus;
  readonly invitedAt?: string;
  readonly approvedAt?: string;
  readonly approvalId?: string;
  readonly updatedAt: string;
}

/** Record a recipient's status progress (the binding columns are frozen after draft by migration 0010). */
export function setRecipientProgress(store: TenantStore, recipientId: string, progress: RecipientProgress): void {
  const values: Record<string, string> = { status: progress.status, updated_at: progress.updatedAt };
  if (progress.invitedAt !== undefined) values['invited_at'] = progress.invitedAt;
  if (progress.approvedAt !== undefined) values['approved_at'] = progress.approvedAt;
  if (progress.approvalId !== undefined) values['approval_id'] = progress.approvalId;
  one(store.update('recipients', { id: recipientId }, values), 'recipient progress');
}

/** Move every recipient that is still pending or invited to `status` (revoked or expired). */
export function closeOpenRecipients(store: TenantStore, envelopeId: string, status: 'revoked' | 'expired', now: string): number {
  return store.update('recipients', { envelope_id: envelopeId, status: { op: 'in', values: ['pending', 'invited'] } }, { status, updated_at: now });
}

/** Revoke every outstanding invitation and recipient session of the envelope. */
export function revokeOutstandingCapabilities(store: TenantStore, envelopeId: string, now: string): void {
  store.update('invitations', { envelope_id: envelopeId, revoked_at: null }, { revoked_at: now });
  store.update('recipient_sessions', { envelope_id: envelopeId, revoked_at: null }, { revoked_at: now });
}

// ------------------------------------------------------------------ revisions

function revisionFromRow(row: Row): RevisionRecord {
  const pageGeometryJson = str(row, 'document_revisions', 'page_geometry_json');
  const pages = JSON.parse(pageGeometryJson) as PageGeometry[];
  return {
    id: str(row, 'document_revisions', 'id'),
    envelopeId: str(row, 'document_revisions', 'envelope_id'),
    contentDigest: str(row, 'document_revisions', 'content_digest'),
    blobRef: str(row, 'document_revisions', 'blob_ref'),
    bytes: int(row, 'document_revisions', 'bytes'),
    pages,
    pageGeometryJson,
    parseReportJson: str(row, 'document_revisions', 'parse_report_json'),
    createdAt: str(row, 'document_revisions', 'created_at'),
    frozenAt: optStr(row, 'document_revisions', 'frozen_at'),
  };
}

/** Insert the revision of an accepted upload; its blob ref is the tenant-namespaced content address. */
export function insertRevision(store: TenantStore, id: string, envelopeId: string, document: DocumentInput, now: string): void {
  store.insert('document_revisions', {
    id,
    envelope_id: envelopeId,
    content_digest: document.digest,
    blob_ref: blobRefFor(store.tenantId, document.digest),
    bytes: document.bytes,
    pages: document.pages.length,
    page_geometry_json: JSON.stringify(document.pages),
    parse_report_json: JSON.stringify(document.parseReport),
    created_at: now,
  });
}

/** Copy a revision's content (same digest and blob) to another envelope of the tenant, unfrozen. */
export function copyRevision(store: TenantStore, source: RevisionRecord, id: string, envelopeId: string, now: string): void {
  store.insert('document_revisions', {
    id,
    envelope_id: envelopeId,
    content_digest: source.contentDigest,
    blob_ref: source.blobRef,
    bytes: source.bytes,
    pages: source.pages.length,
    page_geometry_json: source.pageGeometryJson,
    parse_report_json: source.parseReportJson,
    created_at: now,
  });
}

export function getRevision(store: TenantStore, envelopeId: string, revisionId: string): RevisionRecord | undefined {
  const row = store.get('document_revisions', { envelope_id: envelopeId, id: revisionId });
  return row === undefined ? undefined : revisionFromRow(row);
}

const isRotation = (value: unknown): value is PageGeometry['rotate'] => value === 0 || value === 90 || value === 180 || value === 270;
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * The stored page geometry placement reads at prepare (A-010 requests #46, #49 and #53): for
 * each displayed page of `revision`, in order, the rotation and MediaBox its stored parse
 * report holds (the page list T034's upload stores). That list must agree with the stored
 * displayed geometry (page_geometry_json) page by page:
 *   - number: as many pages, each numbered by its place;
 *   - rotation: the same /Rotate;
 *   - displayed size: the report page's width and height, and its MediaBox's width and
 *     height under its rotation, both exactly the stored displayed width and height (the
 *     composer's own page-geometry rule, src/cryptograph/compose/report.ts);
 * and its MediaBox must be four finite numbers with urx > llx and ury > lly. A missing page
 * list, or any disagreement, is a broken invariant, never repaired: StorageUsageError, which
 * no envelope handler maps, so the server answers 500 internal and logs it
 * (handler_exception). Width and height only detect the inconsistency; nothing is ever
 * placed from them.
 */
export function storedPageGeometry(revision: RevisionRecord): StoredPage[] {
  const broken = (what: string): StorageUsageError => new StorageUsageError(`document_revisions.parse_report_json ${what}`);
  let report: unknown;
  try {
    report = JSON.parse(revision.parseReportJson);
  } catch {
    throw broken('holds no page list');
  }
  const list = isRecord(report) ? report['pages'] : undefined;
  if (!Array.isArray(list)) throw broken('holds no page list');
  if (list.length !== revision.pages.length) throw broken('disagrees with the stored geometry in number of pages');
  return list.map((entry: unknown, index): StoredPage => {
    const displayed: unknown = revision.pages[index];
    const at = `page ${index + 1}`;
    if (!isRecord(entry) || !isRecord(displayed)) throw broken(`${at} is not a page`);
    if (entry['number'] !== index + 1 || displayed['number'] !== index + 1) throw broken(`${at} disagrees with the stored geometry in number`);
    const rotate = entry['rotate'];
    if (!isRotation(rotate) || rotate !== displayed['rotate']) throw broken(`${at} disagrees with the stored geometry in rotation`);
    const box = entry['media_box'];
    if (!Array.isArray(box) || box.length !== 4 || !box.every((n: unknown) => typeof n === 'number' && Number.isFinite(n))) throw broken(`${at} holds no usable media_box`);
    const [llx, lly, urx, ury] = box as [number, number, number, number];
    if (!(urx > llx && ury > lly)) throw broken(`${at} holds no usable media_box`);
    const [shownWidth, shownHeight] = rotate % 180 === 0 ? [urx - llx, ury - lly] : [ury - lly, urx - llx];
    const width = displayed['width'];
    const height = displayed['height'];
    if (entry['width'] !== width || entry['height'] !== height || shownWidth !== width || shownHeight !== height) {
      throw broken(`${at} disagrees with the stored geometry in displayed size`);
    }
    return { rotate, media_box: [llx, lly, urx, ury] };
  });
}

/** Freeze a revision at prepare; a frozen revision is immutable (schema trigger of 0002). */
export function freezeRevision(store: TenantStore, envelopeId: string, revisionId: string, now: string): void {
  one(store.update('document_revisions', { envelope_id: envelopeId, id: revisionId, frozen_at: null }, { frozen_at: now }), 'revision freeze');
}

// --------------------------------------------------------- fields and manifest

export interface NewField {
  readonly key: string;
  readonly recipientId: string;
  readonly recipientOrdinal: number;
  readonly page: number;
  readonly type: 'signature' | 'date';
  readonly rect: Rect;
}

export function insertField(store: TenantStore, envelopeId: string, revisionId: string, field: NewField, now: string): void {
  store.insert('field_definitions', {
    envelope_id: envelopeId,
    key: field.key,
    revision_id: revisionId,
    recipient_id: field.recipientId,
    recipient_ordinal: field.recipientOrdinal,
    page: field.page,
    type: field.type,
    rect_x: field.rect.x,
    rect_y: field.rect.y,
    rect_width: field.rect.width,
    rect_height: field.rect.height,
    created_at: now,
  });
}

export function listFields(store: TenantStore, envelopeId: string): FieldRecord[] {
  return store.list('field_definitions', { envelope_id: envelopeId }, { orderBy: [['key', 'asc']], limit: 100 }).map((row) => {
    const type = row['type'];
    if (type !== 'signature' && type !== 'date') throw stored('field_definitions', 'type');
    return {
      key: str(row, 'field_definitions', 'key'),
      revisionId: str(row, 'field_definitions', 'revision_id'),
      recipientId: str(row, 'field_definitions', 'recipient_id'),
      recipientOrdinal: int(row, 'field_definitions', 'recipient_ordinal'),
      page: int(row, 'field_definitions', 'page'),
      type,
      rect: {
        x: real(row, 'field_definitions', 'rect_x'),
        y: real(row, 'field_definitions', 'rect_y'),
        width: real(row, 'field_definitions', 'rect_width'),
        height: real(row, 'field_definitions', 'rect_height'),
      },
    };
  });
}

export function insertManifest(store: TenantStore, envelopeId: string, manifest: ManifestRecord, now: string): void {
  store.insert('field_manifests', {
    envelope_id: envelopeId,
    revision_id: manifest.revisionId,
    schema: manifest.schema,
    manifest_digest: manifest.digest,
    canonical_bytes: manifest.bytes,
    created_at: now,
  });
}

export function getManifest(store: TenantStore, envelopeId: string): ManifestRecord | undefined {
  const row = store.get('field_manifests', { envelope_id: envelopeId });
  if (row === undefined) return undefined;
  const bytes = row['canonical_bytes'];
  if (!(bytes instanceof Uint8Array)) throw stored('field_manifests', 'canonical_bytes');
  return {
    revisionId: str(row, 'field_manifests', 'revision_id'),
    schema: str(row, 'field_manifests', 'schema'),
    digest: str(row, 'field_manifests', 'manifest_digest'),
    bytes,
  };
}

// --------------------------------------------------------- send confirmations

function confirmationFromRow(row: Row): SendConfirmationRecord {
  return {
    authorizationReference: str(row, 'send_confirmations', 'authorization_reference'),
    envelopeId: str(row, 'send_confirmations', 'envelope_id'),
    envelopeVersion: int(row, 'send_confirmations', 'envelope_version'),
    documentDigest: str(row, 'send_confirmations', 'document_digest'),
    manifestDigest: str(row, 'send_confirmations', 'manifest_digest'),
    recipientsDigest: str(row, 'send_confirmations', 'recipients_digest'),
    confirmedBy: {
      kind: principalKind(str(row, 'send_confirmations', 'confirmed_by_kind'), 'send_confirmations', 'confirmed_by_kind'),
      ref: str(row, 'send_confirmations', 'confirmed_by_ref'),
    },
    confirmedAt: str(row, 'send_confirmations', 'confirmed_at'),
    expiresAt: str(row, 'send_confirmations', 'expires_at'),
    consumedAt: optStr(row, 'send_confirmations', 'consumed_at'),
  };
}

export function insertSendConfirmation(store: TenantStore, confirmation: Omit<SendConfirmationRecord, 'consumedAt'>): void {
  const values: Values = {
    authorization_reference: confirmation.authorizationReference,
    envelope_id: confirmation.envelopeId,
    envelope_version: confirmation.envelopeVersion,
    document_digest: confirmation.documentDigest,
    manifest_digest: confirmation.manifestDigest,
    recipients_digest: confirmation.recipientsDigest,
    confirmed_by_kind: confirmation.confirmedBy.kind,
    confirmed_by_ref: confirmation.confirmedBy.ref,
    confirmed_at: confirmation.confirmedAt,
    expires_at: confirmation.expiresAt,
  };
  store.insert('send_confirmations', values);
}

export function getSendConfirmation(store: TenantStore, authorizationReference: string): SendConfirmationRecord | undefined {
  const row = store.get('send_confirmations', { authorization_reference: authorizationReference });
  return row === undefined ? undefined : confirmationFromRow(row);
}

/** Consume a confirmation once; returns false when it was already consumed. */
export function consumeSendConfirmation(store: TenantStore, authorizationReference: string, now: string): boolean {
  return store.update('send_confirmations', { authorization_reference: authorizationReference, consumed_at: null }, { consumed_at: now }) === 1;
}

/** The newest unconsumed, unexpired confirmation bound to the envelope's current version, if any. */
export function openConfirmation(store: TenantStore, envelopeId: string, version: number, now: string): SendConfirmationRecord | undefined {
  const rows = store.list(
    'send_confirmations',
    { envelope_id: envelopeId, envelope_version: version, consumed_at: null, expires_at: { op: '>', value: now } },
    { orderBy: [['confirmed_at', 'desc']], limit: 1 },
  );
  return rows[0] === undefined ? undefined : confirmationFromRow(rows[0]);
}

// ------------------------------------------------------- finalization summary

export function getSigningJob(store: TenantStore, envelopeId: string): SigningJobRecord | null {
  const row = store.get('signing_jobs', { envelope_id: envelopeId });
  if (row === undefined) return null;
  const status = str(row, 'signing_jobs', 'status');
  if (!['pending', 'running', 'retryable', 'failed', 'succeeded'].includes(status)) throw stored('signing_jobs', 'status');
  return {
    status: status as SigningJobRecord['status'],
    attemptCount: int(row, 'signing_jobs', 'attempt_count'),
    maxAttempts: int(row, 'signing_jobs', 'max_attempts'),
    retryAt: optStr(row, 'signing_jobs', 'retry_at'),
    lastErrorCode: optStr(row, 'signing_jobs', 'last_error_code'),
  };
}

export function getFinalArtifact(store: TenantStore, envelopeId: string): FinalArtifactRecord | null {
  const row = store.get('final_artifacts', { envelope_id: envelopeId });
  if (row === undefined) return null;
  return {
    artifactId: str(row, 'final_artifacts', 'artifact_id'),
    artifactDigest: str(row, 'final_artifacts', 'artifact_digest'),
    packageDigest: optStr(row, 'final_artifacts', 'package_digest'),
    verificationJson: str(row, 'final_artifacts', 'verification_json'),
    completedAt: str(row, 'final_artifacts', 'completed_at'),
  };
}

/** Everything the envelope views need, read in the caller's transaction, or with none on a read-only path (data-model.md § Persistence). */
export function loadEnvelope(store: TenantStore, envelopeId: string): EnvelopeAggregate | undefined {
  const envelope = getEnvelope(store, envelopeId);
  if (envelope === undefined) return undefined;
  const revision = envelope.baseRevisionId === null ? undefined : getRevision(store, envelopeId, envelope.baseRevisionId);
  return {
    envelope,
    recipients: listRecipients(store, envelopeId),
    revision: revision ?? null,
    fields: listFields(store, envelopeId),
    manifest: getManifest(store, envelopeId) ?? null,
    job: getSigningJob(store, envelopeId),
    artifact: getFinalArtifact(store, envelopeId),
  };
}
