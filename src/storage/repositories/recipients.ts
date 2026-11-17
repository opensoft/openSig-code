// SPDX-License-Identifier: Apache-2.0
//
// Recipient-ceremony repository (T008): invitations, challenges, recipient
// sessions and the tenant's consent text in force, through the tenant-scoped
// store only (every statement is filtered to the store's tenant). Writes need
// the caller's transaction (Database.transaction, BEGIN IMMEDIATE), which also
// serializes the read-then-write counter updates below; each of them is a
// compare-and-set on the value it read, so a lost update is impossible even
// without the lock.
//
// Capability values are never stored: an invitation keeps the SHA-256 of its
// token, a session the SHA-256 of its value, a challenge an HMAC of its code.
// The only reads without a tenant are the capability resolutions, which go
// through Database.resolveCapability on the declared capability columns.
//
// The schema backs every rule here: binding columns are immutable and
// revocation and consumption are final (0003); expiry is fixed at issue,
// counters never decrease, supersession is final, invitation and challenge
// rows are retained, and the CSRF secret is required and immutable (0013); and
// no row is ever replaced by an insert that repeats one of its keys (0014).
//
// The capability-id reads at the end serve the ceremony's audit events
// (recipient.capabilities_revoked and recipient.locked_out, CH-06): which
// invitations and sessions a revocation revoked, by id only.

import type { CapabilityOwner, Database, Row, TenantStore } from '../db/index.ts';
import { StorageUsageError } from '../db/index.ts';
import type { ConsentText } from '../../domain/consent/index.ts';

/** Twenty wrong codes over an invitation's lifetime revoke it (data-model.md § Entities, Invitation). */
export const INVITATION_LOCKOUT_WRONG_CODES = 20;
/** Five attempts per challenge, then it is locked (data-model.md § Entities, Challenge). */
export const CHALLENGE_MAX_ATTEMPTS = 5;

export interface InvitationRecord {
  readonly id: string;
  readonly envelopeId: string;
  readonly recipientId: string;
  readonly revisionId: string;
  readonly manifestDigest: string;
  readonly sentAt: string;
  readonly expiresAt: string;
  readonly revokedAt: string | null;
  readonly cumulativeWrongCodes: number;
}

export interface ChallengeRecord {
  readonly id: string;
  readonly invitationId: string;
  readonly codeHmac: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly attempts: number;
  readonly consumedAt: string | null;
  readonly supersededAt: string | null;
}

export interface SessionRecord {
  readonly id: string;
  readonly envelopeId: string;
  readonly recipientId: string;
  readonly revisionId: string;
  readonly manifestDigest: string;
  readonly csrfSecret: Buffer;
  readonly createdAt: string;
  readonly lastSeenAt: string;
  readonly revokedAt: string | null;
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

function one(changed: number, what: string): void {
  if (changed !== 1) throw new StorageUsageError(`${what} changed ${changed} rows, expected exactly one`);
}

// ----------------------------------------------------------- capability lookup

/** The tenant and id of the invitation whose token hashes to `tokenHash`, if any. */
export function resolveInvitation(db: Database, tokenHash: string): CapabilityOwner | undefined {
  return db.resolveCapability('invitations', tokenHash);
}

/** The tenant and id of the session whose value hashes to `valueHash`, if any. */
export function resolveSession(db: Database, valueHash: string): CapabilityOwner | undefined {
  return db.resolveCapability('recipient_sessions', valueHash);
}

// ---------------------------------------------------------------- invitations

function invitationFromRow(row: Row): InvitationRecord {
  return {
    id: str(row, 'invitations', 'id'),
    envelopeId: str(row, 'invitations', 'envelope_id'),
    recipientId: str(row, 'invitations', 'recipient_id'),
    revisionId: str(row, 'invitations', 'revision_id'),
    manifestDigest: str(row, 'invitations', 'manifest_digest'),
    sentAt: str(row, 'invitations', 'sent_at'),
    expiresAt: str(row, 'invitations', 'expires_at'),
    revokedAt: optStr(row, 'invitations', 'revoked_at'),
    cumulativeWrongCodes: int(row, 'invitations', 'cumulative_wrong_codes'),
  };
}

export interface NewInvitation {
  readonly id: string;
  readonly envelopeId: string;
  readonly recipientId: string;
  readonly revisionId: string;
  readonly manifestDigest: string;
  readonly tokenHash: string;
  readonly sentAt: string;
  readonly expiresAt: string;
}

export function insertInvitation(store: TenantStore, invitation: NewInvitation): void {
  store.insert('invitations', {
    id: invitation.id,
    envelope_id: invitation.envelopeId,
    recipient_id: invitation.recipientId,
    revision_id: invitation.revisionId,
    manifest_digest: invitation.manifestDigest,
    token_hash: invitation.tokenHash,
    sent_at: invitation.sentAt,
    expires_at: invitation.expiresAt,
  });
}

export function getInvitation(store: TenantStore, invitationId: string): InvitationRecord | undefined {
  const row = store.get('invitations', { id: invitationId });
  return row === undefined ? undefined : invitationFromRow(row);
}

/** The recipient's invitations that are neither revoked nor expired at `now`. */
export function liveInvitationsOf(store: TenantStore, envelopeId: string, recipientId: string, now: string): InvitationRecord[] {
  return store
    .list('invitations', { envelope_id: envelopeId, recipient_id: recipientId, revoked_at: null, expires_at: { op: '>', value: now } }, { limit: 100 })
    .map(invitationFromRow);
}

/** Revoke every unrevoked invitation of the recipient; returns how many. */
export function revokeInvitationsOf(store: TenantStore, envelopeId: string, recipientId: string, now: string): number {
  return store.update('invitations', { envelope_id: envelopeId, recipient_id: recipientId, revoked_at: null }, { revoked_at: now });
}

// ----------------------------------------------------------------- challenges

function challengeFromRow(row: Row): ChallengeRecord {
  return {
    id: str(row, 'challenges', 'id'),
    invitationId: str(row, 'challenges', 'invitation_id'),
    codeHmac: str(row, 'challenges', 'code_hmac'),
    createdAt: str(row, 'challenges', 'created_at'),
    expiresAt: str(row, 'challenges', 'expires_at'),
    attempts: int(row, 'challenges', 'attempts'),
    consumedAt: optStr(row, 'challenges', 'consumed_at'),
    supersededAt: optStr(row, 'challenges', 'superseded_at'),
  };
}

export interface NewChallenge {
  readonly id: string;
  readonly invitationId: string;
  readonly codeHmac: string;
  readonly createdAt: string;
  readonly expiresAt: string;
}

export function insertChallenge(store: TenantStore, challenge: NewChallenge): void {
  store.insert('challenges', {
    id: challenge.id,
    invitation_id: challenge.invitationId,
    code_hmac: challenge.codeHmac,
    created_at: challenge.createdAt,
    expires_at: challenge.expiresAt,
  });
}

/** A new code supersedes the previous one: mark every open (unconsumed, unsuperseded) challenge. */
export function supersedeOpenChallenges(store: TenantStore, invitationId: string, now: string): number {
  return store.update('challenges', { invitation_id: invitationId, consumed_at: null, superseded_at: null }, { superseded_at: now });
}

/**
 * The invitation's current challenge: the one that is neither consumed nor
 * superseded. Requesting a code supersedes every open one in the same
 * transaction, so there is at most one.
 */
export function openChallenge(store: TenantStore, invitationId: string): ChallengeRecord | undefined {
  const rows = store.list('challenges', { invitation_id: invitationId, consumed_at: null, superseded_at: null }, { limit: 2 });
  if (rows.length > 1) throw new StorageUsageError('an invitation has more than one open challenge');
  return rows[0] === undefined ? undefined : challengeFromRow(rows[0]);
}

export interface WrongCodeOutcome {
  readonly attempts: number;
  readonly cumulativeWrongCodes: number;
  /** True when this wrong code reached the lockout and revoked the invitation. */
  readonly revoked: boolean;
}

/**
 * Record one wrong code: the challenge's attempts and the invitation's
 * cumulative count each move up by one, and the twentieth wrong code revokes
 * the invitation in the same write. Both are compare-and-set on the values read.
 */
export function recordWrongCode(store: TenantStore, invitation: InvitationRecord, challenge: ChallengeRecord, now: string): WrongCodeOutcome {
  const attempts = challenge.attempts + 1;
  one(store.update('challenges', { id: challenge.id, attempts: challenge.attempts, consumed_at: null }, { attempts }), 'challenge attempt');
  const cumulative = invitation.cumulativeWrongCodes + 1;
  const revoke = cumulative >= INVITATION_LOCKOUT_WRONG_CODES && invitation.revokedAt === null;
  one(
    store.update(
      'invitations',
      { id: invitation.id, cumulative_wrong_codes: invitation.cumulativeWrongCodes },
      revoke ? { cumulative_wrong_codes: cumulative, revoked_at: now } : { cumulative_wrong_codes: cumulative },
    ),
    'invitation wrong-code count',
  );
  return { attempts, cumulativeWrongCodes: cumulative, revoked: revoke };
}

/** Consume the challenge with a correct code (single use); the attempt is counted. */
export function consumeChallenge(store: TenantStore, challenge: ChallengeRecord, now: string): void {
  one(
    store.update('challenges', { id: challenge.id, attempts: challenge.attempts, consumed_at: null, superseded_at: null }, { attempts: challenge.attempts + 1, consumed_at: now }),
    'challenge consumption',
  );
}

// ------------------------------------------------------------------- sessions

function sessionFromRow(row: Row): SessionRecord {
  const secret = row['csrf_secret'];
  if (!(secret instanceof Uint8Array) || secret.byteLength < 16) throw stored('recipient_sessions', 'csrf_secret');
  return {
    id: str(row, 'recipient_sessions', 'id'),
    envelopeId: str(row, 'recipient_sessions', 'envelope_id'),
    recipientId: str(row, 'recipient_sessions', 'recipient_id'),
    revisionId: str(row, 'recipient_sessions', 'revision_id'),
    manifestDigest: str(row, 'recipient_sessions', 'manifest_digest'),
    csrfSecret: Buffer.from(secret),
    createdAt: str(row, 'recipient_sessions', 'created_at'),
    lastSeenAt: str(row, 'recipient_sessions', 'last_seen_at'),
    revokedAt: optStr(row, 'recipient_sessions', 'revoked_at'),
  };
}

export interface NewSession {
  readonly id: string;
  readonly valueHash: string;
  readonly envelopeId: string;
  readonly recipientId: string;
  readonly revisionId: string;
  readonly manifestDigest: string;
  readonly csrfSecret: Uint8Array;
  readonly now: string;
}

export function insertSession(store: TenantStore, session: NewSession): void {
  store.insert('recipient_sessions', {
    id: session.id,
    value_hash: session.valueHash,
    envelope_id: session.envelopeId,
    recipient_id: session.recipientId,
    revision_id: session.revisionId,
    manifest_digest: session.manifestDigest,
    csrf_secret: session.csrfSecret,
    created_at: session.now,
    last_seen_at: session.now,
  });
}

export function getSession(store: TenantStore, sessionId: string): SessionRecord | undefined {
  const row = store.get('recipient_sessions', { id: sessionId });
  return row === undefined ? undefined : sessionFromRow(row);
}

/** Move a live session's last_seen_at from `lastSeenAt` to `now`; false when it changed or was revoked meanwhile. */
export function touchSession(store: TenantStore, sessionId: string, lastSeenAt: string, now: string): boolean {
  return store.update('recipient_sessions', { id: sessionId, revoked_at: null, last_seen_at: lastSeenAt }, { last_seen_at: now }) === 1;
}

/** Revoke one session (endRecipientSession); false when it was already revoked. */
export function revokeSession(store: TenantStore, sessionId: string, now: string): boolean {
  return store.update('recipient_sessions', { id: sessionId, revoked_at: null }, { revoked_at: now }) === 1;
}

/** Revoke every unrevoked session of the recipient; returns how many. */
export function revokeSessionsOf(store: TenantStore, envelopeId: string, recipientId: string, now: string): number {
  return store.update('recipient_sessions', { envelope_id: envelopeId, recipient_id: recipientId, revoked_at: null }, { revoked_at: now });
}

// -------------------------------------------------------------------- consent

/** The tenant's consent text in force (tenants.consent_text_id), or undefined when none is configured. */
export function getConsentInForce(store: TenantStore): ConsentText | undefined {
  const tenant = store.get('tenants', {});
  const consentId = tenant === undefined ? null : optStr(tenant, 'tenants', 'consent_text_id');
  if (consentId === null) return undefined;
  const row = store.get('consent_texts', { id: consentId });
  if (row === undefined) return undefined;
  return {
    id: str(row, 'consent_texts', 'id'),
    version: str(row, 'consent_texts', 'version'),
    locale: str(row, 'consent_texts', 'locale'),
    text: str(row, 'consent_texts', 'text'),
    textDigest: str(row, 'consent_texts', 'text_digest'),
    effectiveFrom: str(row, 'consent_texts', 'effective_from'),
  };
}

// ------------------------------------------------- revoked capabilities (CH-06)

/** Ids of revoked or revocable capabilities, oldest first. */
export interface CapabilityIds {
  readonly invitationIds: readonly string[];
  readonly sessionIds: readonly string[];
}

function ids(store: TenantStore, table: 'invitations' | 'recipient_sessions', where: Record<string, string | null>): string[] {
  const out: string[] = [];
  for (const row of store.iterate(table, where)) out.push(str(row, table, 'id'));
  return out;
}

/** The recipient's invitations and sessions that are not revoked (what a resend revokes). */
export function outstandingCapabilitiesOf(store: TenantStore, envelopeId: string, recipientId: string): CapabilityIds {
  const where = { envelope_id: envelopeId, recipient_id: recipientId, revoked_at: null };
  return { invitationIds: ids(store, 'invitations', where), sessionIds: ids(store, 'recipient_sessions', where) };
}

/** The envelope's invitations and sessions whose revoked_at is exactly `at`. */
export function capabilitiesRevokedAt(store: TenantStore, envelopeId: string, at: string): CapabilityIds {
  const where = { envelope_id: envelopeId, revoked_at: at };
  return { invitationIds: ids(store, 'invitations', where), sessionIds: ids(store, 'recipient_sessions', where) };
}

/** Audit event types whose metadata names revoked invitations or sessions. */
export const REVOCATION_EVENT_TYPES: readonly string[] = Object.freeze(['recipient.capabilities_revoked', 'recipient.locked_out']);

function namedIds(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === 'string');
  return [];
}

/**
 * Ids of the invitations and sessions that the envelope's earlier revocation
 * and lockout events already name (their invitation_id, invitation_ids and
 * session_ids members).
 */
export function auditedRevocationsOf(store: TenantStore, envelopeId: string): ReadonlySet<string> {
  const named = new Set<string>();
  for (const row of store.iterate('audit_events', { envelope_id: envelopeId, type: { op: 'in', values: [...REVOCATION_EVENT_TYPES] } })) {
    const metadata = JSON.parse(str(row, 'audit_events', 'metadata_json')) as Record<string, unknown>;
    for (const member of ['invitation_id', 'invitation_ids', 'session_ids']) {
      for (const id of namedIds(metadata[member])) named.add(id);
    }
  }
  return named;
}
