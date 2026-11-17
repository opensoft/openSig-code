// SPDX-License-Identifier: Apache-2.0
//
// The recipient ceremony (T008): invitation, mailbox challenge and bound
// session (contracts/sessions-events-adapters.md § Recipient ceremony;
// data-model.md § Entities and § Authentication and secrets).
//
// Invitations. When an envelope is sent (recipient 1) or its first of two
// approvals is recorded (recipient 2), the envelope service reports the change
// inside its transaction (EnvelopeService onChange = onEnvelopeChange). Each
// newly invited recipient then gets an invitation: a 256-bit token whose
// SHA-256 is stored, bound to the recipient, the frozen revision and the
// manifest, and expiring at the earlier of 7 days and the envelope's expiry.
// The raw token is never stored. It is held in memory, inside an InvitationMail
// that never prints it, and mailed through the notifications adapter (T032) only
// after the transaction commits: the caller runs the mutation through
// capture() and then deliver(), or run() for both. A mutation that rolls back
// mails nothing. A change reported outside capture() is refused, which rolls the
// mutation back, so an invitation can never be issued without being mailed.
// resendInvitation revokes the recipient's invitations and sessions and issues
// a fresh one the same way (the invitation half of T034's resendInvitation).
//
// requestChallenge always answers the same generic 202, whether or not the
// invitation exists, is live, or a code was mailed. For a live invitation it
// supersedes the open challenge and stores a new one: a 10-character Crockford
// code kept only as an HMAC under the 0600 key (codes.ts), expiring after 10
// minutes, mailed after the commit. Requests are limited per client address and
// per presented invitation (429 rate_limited with Retry-After).
//
// createRecipientSession compares the code with the open challenge in constant
// time. A wrong code counts against the challenge (5 attempts, then 429
// locked) and against the invitation (the twentieth wrong code over its
// lifetime revokes it; then 429 locked until a resend). Those counts commit even
// though the request fails. An expired, superseded or consumed challenge, an
// expired or revoked invitation and an unknown token are a generic 401. A right
// code consumes the challenge and creates the session: the cookie value (only
// its SHA-256 stored) and an immutable CSRF secret, bound to the tenant,
// envelope, recipient, revision and manifest.
//
// Reads (readRecipientSession, readRecipientDocument, readRecipientManifest)
// never consume, approve or change the envelope: at most a session's
// last_seen_at moves, and a prefetch moves nothing. The document is the exact
// frozen bytes, read from the content-addressed blob store and re-checked
// against the revision's digest and size; the manifest is the exact canonical
// bytes frozen at prepare, re-checked against the manifest digest.

import { createHash, randomBytes } from 'node:crypto';
import { inspect } from 'node:util';

import {
  capabilityHash,
  csrfToken,
  idleExpired,
  newCsrfSecret,
  newSessionValue,
  readSessionCookie,
  sessionExpiresAt,
  type RecipientSession,
  type RecipientSessionAuthority,
  type RequestLike,
} from '../auth/recipient-session.ts';
import type { JsonValue } from '../../domain/canonical/index.ts';
import { ConsentError, checkConsentText, type ConsentText } from '../../domain/consent/index.ts';
import type { EnvelopeChange } from '../../domain/envelopes/service.ts';
import { APPROVING_STATES, turnAfter } from '../../domain/envelopes/states.ts';
import type { RecipientChallengeRequest, RecipientInvitationRequest } from '../../notifications/content.ts';
import { NotificationError } from '../../notifications/errors.ts';
import type { Notifier } from '../../notifications/notifier.ts';
import { createLogger, type Logger } from '../../server/redact.ts';
import { HttpError } from '../../server/types.ts';
import type { BlobStore } from '../../storage/blobs/index.ts';
import type { Database, TenantStore } from '../../storage/db/index.ts';
import {
  getEnvelope,
  getManifest,
  getRevision,
  listFields,
  listRecipients,
  setRecipientProgress,
  type EnvelopeRecord,
  type RecipientRecord,
} from '../../storage/repositories/envelopes.ts';
import {
  CHALLENGE_MAX_ATTEMPTS,
  INVITATION_LOCKOUT_WRONG_CODES,
  consumeChallenge,
  getConsentInForce,
  getInvitation,
  getSession,
  insertChallenge,
  insertInvitation,
  insertSession,
  liveInvitationsOf,
  openChallenge,
  recordWrongCode,
  resolveInvitation,
  resolveSession,
  revokeInvitationsOf,
  revokeSession,
  revokeSessionsOf,
  supersedeOpenChallenges,
  touchSession,
  type InvitationRecord,
  type SessionRecord,
} from '../../storage/repositories/recipients.ts';
import { newChallengeCode, newInvitationToken, type ChallengeKey } from './codes.ts';
import { createWindowLimiter, validWindowLimit, type WindowLimit, type WindowLimiter } from './rate-limit.ts';
import { checkChallengeRequest, checkSessionCreate } from './validation.ts';
import { SESSION_ENVELOPE_STATES, sessionStateView } from './views.ts';

/** Invitations live 7 days from sending, or until the envelope expires if that is earlier. */
export const INVITATION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
/** Challenge codes expire after 10 minutes. */
export const CHALLENGE_TTL_MS = 10 * 60 * 1000;

export interface CeremonyLimits {
  /** requestChallenge per client address. */
  readonly challengePerAddress: WindowLimit;
  /** requestChallenge per presented invitation (known or not). */
  readonly challengePerInvitation: WindowLimit;
  /** createRecipientSession per client address. */
  readonly sessionPerAddress: WindowLimit;
  /** createRecipientSession per presented invitation (known or not). */
  readonly sessionPerInvitation: WindowLimit;
}

export const DEFAULT_CEREMONY_LIMITS: CeremonyLimits = Object.freeze({
  challengePerAddress: Object.freeze({ limit: 30, windowMs: 10 * 60 * 1000 }),
  challengePerInvitation: Object.freeze({ limit: 10, windowMs: 10 * 60 * 1000 }),
  sessionPerAddress: Object.freeze({ limit: 60, windowMs: 10 * 60 * 1000 }),
  sessionPerInvitation: Object.freeze({ limit: 30, windowMs: 10 * 60 * 1000 }),
});

export interface RecipientCeremonyOptions {
  readonly db: Database;
  /** The content-addressed blob store holding the frozen documents. */
  readonly blobs: BlobStore;
  /** The notifications adapter (T032): the only way a token or code leaves the server. */
  readonly notifier: Notifier;
  /** The challenge-HMAC key, loaded from its 0600 file (codes.ts loadChallengeKey). */
  readonly challengeKey: ChallengeKey;
  readonly clock: () => Date;
  readonly logger?: Logger;
  readonly limits?: Partial<CeremonyLimits>;
  readonly newId?: () => string;
}

export interface CreatedSession {
  /** The session value for the cookie only; never logged or stored. */
  readonly value: string;
  /** RecipientSessionState. */
  readonly state: JsonValue;
}

export interface DeliveryReport {
  readonly delivered: number;
  readonly failed: number;
}

// Each InvitationMail's notification request, reachable only from this module.
const REQUESTS = new WeakMap<InvitationMail, RecipientInvitationRequest>();

/**
 * An invitation waiting to be mailed after its transaction commits. It never
 * reveals the token: it has no readable member, serializes to its kind only
 * and prints without content.
 */
export class InvitationMail {
  constructor(request: RecipientInvitationRequest) {
    REQUESTS.set(this, Object.freeze({ ...request }));
    Object.freeze(this);
  }

  toJSON(): JsonValue {
    return { kind: 'recipient_invitation' };
  }

  [inspect.custom](): string {
    return 'InvitationMail { recipient_invitation }';
  }
}

type SessionOutcome =
  | { readonly kind: 'created'; readonly value: string; readonly state: JsonValue }
  | { readonly kind: 'refused' }
  | { readonly kind: 'locked' };

const CLOSED_STATES: ReadonlySet<string> = new Set(['declined', 'expired', 'voided']);

function thenable(value: unknown): boolean {
  return (typeof value === 'object' || typeof value === 'function') && value !== null && typeof (value as { then?: unknown }).then === 'function';
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function internal(): HttpError {
  return new HttpError(500, 'internal');
}

export class RecipientCeremony implements RecipientSessionAuthority {
  readonly #db: Database;
  readonly #blobs: BlobStore;
  readonly #notifier: Notifier;
  readonly #key: ChallengeKey;
  readonly #clock: () => Date;
  readonly #logger: Logger;
  readonly #newId: () => string;
  readonly #challengeByAddress: WindowLimiter;
  readonly #challengeByInvitation: WindowLimiter;
  readonly #sessionByAddress: WindowLimiter;
  readonly #sessionByInvitation: WindowLimiter;
  readonly #captures: InvitationMail[][] = [];

  constructor(options: RecipientCeremonyOptions) {
    if (typeof options?.clock !== 'function') throw new TypeError('the recipient ceremony needs an injected clock');
    if (typeof options.challengeKey?.codeHmac !== 'function' || typeof options.challengeKey.verify !== 'function') {
      throw new TypeError('the recipient ceremony needs a challenge key loaded from its key file');
    }
    if (typeof options.notifier?.send !== 'function') throw new TypeError('the recipient ceremony needs the notifications adapter');
    this.#db = options.db;
    this.#blobs = options.blobs;
    this.#notifier = options.notifier;
    this.#key = options.challengeKey;
    this.#clock = options.clock;
    this.#logger = options.logger ?? createLogger(undefined, { component: 'recipients' });
    this.#newId = options.newId ?? (() => randomBytes(18).toString('base64url'));
    const limits = { ...DEFAULT_CEREMONY_LIMITS, ...(options.limits ?? {}) };
    for (const [name, rule] of Object.entries(limits)) {
      if (!validWindowLimit(rule)) throw new TypeError(`ceremony limit ${name} is invalid`);
    }
    const epoch = (): number => this.#now().getTime();
    this.#challengeByAddress = createWindowLimiter(limits.challengePerAddress, epoch);
    this.#challengeByInvitation = createWindowLimiter(limits.challengePerInvitation, epoch);
    this.#sessionByAddress = createWindowLimiter(limits.sessionPerAddress, epoch);
    this.#sessionByInvitation = createWindowLimiter(limits.sessionPerInvitation, epoch);
    Object.freeze(this);
  }

  #now(): Date {
    const now = this.#clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('the ceremony clock returned an invalid date');
    return now;
  }

  #id(): string {
    const id = this.#newId();
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(id)) throw new TypeError('generated id is malformed');
    return id;
  }

  /** Both limits are decided before either is charged: a refused request takes no budget. */
  #limit(...checks: readonly (readonly [WindowLimiter, string])[]): void {
    let retryAfterMs = 0;
    for (const [limiter, key] of checks) {
      const decision = limiter.check(key);
      if (!decision.ok) retryAfterMs = Math.max(retryAfterMs, decision.retryAfterMs);
    }
    if (retryAfterMs > 0) {
      throw new HttpError(429, 'rate_limited', { headers: { 'retry-after': String(Math.max(1, Math.ceil(retryAfterMs / 1000))) } });
    }
    for (const [limiter, key] of checks) limiter.record(key);
  }

  /** The invitation still names the envelope's frozen revision and manifest. */
  #bound(envelope: EnvelopeRecord, binding: { readonly revisionId: string; readonly manifestDigest: string }): boolean {
    return envelope.baseRevisionId === binding.revisionId && envelope.manifestDigest === binding.manifestDigest;
  }

  // ---------------------------------------------------------------- invitations

  /**
   * EnvelopeService onChange: inside the mutation's transaction, invite every
   * recipient the change made `invited` who holds no live invitation (send:
   * recipient 1; the first of two approvals: recipient 2).
   */
  readonly onEnvelopeChange = (change: EnvelopeChange, store: TenantStore): void => {
    if (change.operation !== 'send' && !(change.operation === 'approval' && change.to === 'in-progress')) return;
    const now = this.#now();
    const iso = now.toISOString();
    const envelope = getEnvelope(store, change.envelopeId);
    if (envelope === undefined) throw new TypeError('the changed envelope is missing');
    for (const recipient of listRecipients(store, envelope.id)) {
      if (recipient.status === 'invited' && liveInvitationsOf(store, envelope.id, recipient.id, iso).length === 0) this.#issue(store, envelope, recipient, now);
    }
  };

  #issue(store: TenantStore, envelope: EnvelopeRecord, recipient: RecipientRecord, now: Date): void {
    const buffer = this.#captures[this.#captures.length - 1];
    if (buffer === undefined) {
      throw new TypeError('invitations are issued only inside RecipientCeremony.capture(), which mails them after the commit');
    }
    if (envelope.baseRevisionId === null || envelope.manifestDigest === null) throw new TypeError('only a prepared envelope has invitations');
    const expires = Math.min(now.getTime() + INVITATION_TTL_MS, Date.parse(envelope.expiresAt));
    if (!(expires > now.getTime())) throw new HttpError(409, 'state_conflict');
    const token = newInvitationToken();
    const expiresAt = new Date(expires).toISOString();
    insertInvitation(store, {
      id: this.#id(),
      envelopeId: envelope.id,
      recipientId: recipient.id,
      revisionId: envelope.baseRevisionId,
      manifestDigest: envelope.manifestDigest,
      tokenHash: capabilityHash(token),
      sentAt: now.toISOString(),
      expiresAt,
    });
    buffer.push(new InvitationMail({ kind: 'recipient_invitation', tenant_id: store.tenantId, to: recipient.email, invitation: token, expires_at: expiresAt }));
  }

  /**
   * Resend (inside the caller's transaction and capture()): the recipient whose
   * turn it is, still invited, on an envelope that takes approvals, loses every
   * outstanding invitation and session and gets a fresh invitation.
   */
  resendInvitation(store: TenantStore, envelopeId: string, recipientId: string): void {
    const now = this.#now();
    const iso = now.toISOString();
    const envelope = getEnvelope(store, envelopeId);
    if (envelope === undefined) throw new HttpError(404, 'not_found');
    if (!APPROVING_STATES.includes(envelope.state) || Date.parse(envelope.expiresAt) <= now.getTime()) throw new HttpError(409, 'state_conflict');
    const recipients = listRecipients(store, envelopeId);
    const recipient = recipients.find((entry) => entry.id === recipientId);
    if (recipient === undefined) throw new HttpError(404, 'not_found');
    const turn = turnAfter(
      recipients.filter((entry) => entry.status === 'approved').map((entry) => entry.ordinal),
      envelope.recipientsCount,
    );
    if (recipient.ordinal !== turn) throw new HttpError(409, 'order_conflict');
    if (recipient.status !== 'invited') throw new HttpError(409, 'state_conflict');
    revokeInvitationsOf(store, envelopeId, recipientId, iso);
    revokeSessionsOf(store, envelopeId, recipientId, iso);
    setRecipientProgress(store, recipientId, { status: 'invited', invitedAt: iso, updatedAt: iso });
    this.#issue(store, envelope, recipient, now);
  }

  /**
   * Run a synchronous mutation (for example EnvelopeService.send) while
   * collecting the invitations it issues. The mails are returned only when the
   * mutation returns, that is after its transaction committed; a throw discards
   * them.
   */
  capture<T>(fn: () => T): { readonly value: T; readonly mails: readonly InvitationMail[] } {
    const buffer: InvitationMail[] = [];
    this.#captures.push(buffer);
    try {
      const value = fn();
      if (thenable(value)) throw new TypeError('a captured mutation must be synchronous');
      return { value, mails: Object.freeze([...buffer]) };
    } finally {
      this.#captures.pop();
    }
  }

  /** Mail committed invitations, each at most once. A failed delivery is logged by reason only. */
  async deliver(mails: readonly InvitationMail[]): Promise<DeliveryReport> {
    let delivered = 0;
    let failed = 0;
    for (const mail of mails) {
      const request = REQUESTS.get(mail);
      REQUESTS.delete(mail);
      if (request === undefined) {
        failed += 1;
        continue;
      }
      try {
        await this.#notifier.send(request);
        delivered += 1;
      } catch (error) {
        failed += 1;
        this.#logger.warn('invitation_mail_refused', { reason: error instanceof NotificationError ? error.code : 'delivery_failed', tenant_id: request.tenant_id });
      }
    }
    return { delivered, failed };
  }

  /** capture() then deliver(): the mutation's value once its invitations are mailed. */
  async run<T>(fn: () => T): Promise<T> {
    const { value, mails } = this.capture(fn);
    await this.deliver(mails);
    return value;
  }

  // ----------------------------------------------------------------- challenge

  /**
   * requestChallenge. Resolves with nothing in every case the client may not
   * tell apart; throws only 400 (schema) and 429 (rate limit).
   */
  async requestChallenge(body: unknown, clientAddress: string): Promise<void> {
    const token = checkChallengeRequest(body);
    const tokenHash = capabilityHash(token);
    this.#limit([this.#challengeByAddress, clientAddress], [this.#challengeByInvitation, tokenHash]);
    const now = this.#now();
    const iso = now.toISOString();
    const mail = this.#db.transaction((): RecipientChallengeRequest | null => {
      const owner = resolveInvitation(this.#db, tokenHash);
      if (owner === undefined) return null;
      const store = this.#db.forTenant(owner.tenantId);
      const invitation = getInvitation(store, owner.id);
      if (invitation === undefined || invitation.revokedAt !== null || Date.parse(invitation.expiresAt) <= now.getTime()) return null;
      const envelope = getEnvelope(store, invitation.envelopeId);
      if (envelope === undefined || !this.#bound(envelope, invitation) || CLOSED_STATES.has(envelope.state) || Date.parse(envelope.expiresAt) <= now.getTime()) return null;
      const recipient = listRecipients(store, envelope.id).find((entry) => entry.id === invitation.recipientId);
      if (recipient === undefined) return null;
      supersedeOpenChallenges(store, invitation.id, iso);
      const challengeId = this.#id();
      const code = newChallengeCode();
      const expiresAt = new Date(now.getTime() + CHALLENGE_TTL_MS).toISOString();
      insertChallenge(store, { id: challengeId, invitationId: invitation.id, codeHmac: this.#key.codeHmac(invitation.id, challengeId, code), createdAt: iso, expiresAt });
      return { kind: 'recipient_challenge', tenant_id: owner.tenantId, to: recipient.email, code, expires_at: expiresAt };
    });
    if (mail === null) return;
    try {
      await this.#notifier.send(mail);
    } catch (error) {
      this.#logger.warn('challenge_mail_refused', { reason: error instanceof NotificationError ? error.code : 'delivery_failed', tenant_id: mail.tenant_id });
    }
  }

  // ------------------------------------------------------------------ session

  /** createRecipientSession: 201 state plus the cookie value, or 401 / 429 locked / 429 rate_limited / 400. */
  createSession(body: unknown, clientAddress: string): CreatedSession {
    const { invitation: token, code } = checkSessionCreate(body);
    const tokenHash = capabilityHash(token);
    this.#limit([this.#sessionByAddress, clientAddress], [this.#sessionByInvitation, tokenHash]);
    const now = this.#now();
    const iso = now.toISOString();
    const outcome = this.#db.transaction((): SessionOutcome => {
      const owner = resolveInvitation(this.#db, tokenHash);
      if (owner === undefined) return { kind: 'refused' };
      const store = this.#db.forTenant(owner.tenantId);
      const invitation = getInvitation(store, owner.id);
      if (invitation === undefined) return { kind: 'refused' };
      if (invitation.revokedAt !== null) {
        return invitation.cumulativeWrongCodes >= INVITATION_LOCKOUT_WRONG_CODES ? { kind: 'locked' } : { kind: 'refused' };
      }
      if (Date.parse(invitation.expiresAt) <= now.getTime()) return { kind: 'refused' };
      const envelope = getEnvelope(store, invitation.envelopeId);
      if (envelope === undefined || !this.#bound(envelope, invitation)) return { kind: 'refused' };
      const challenge = openChallenge(store, invitation.id);
      if (challenge === undefined || Date.parse(challenge.expiresAt) <= now.getTime()) return { kind: 'refused' };
      if (challenge.attempts >= CHALLENGE_MAX_ATTEMPTS) return { kind: 'locked' };
      if (!this.#key.verify(invitation.id, challenge.id, code, challenge.codeHmac)) {
        // Committed although the request fails: the counts only move forward.
        recordWrongCode(store, invitation, challenge, iso);
        return { kind: 'refused' };
      }
      consumeChallenge(store, challenge, iso);
      return this.#openSession(store, invitation, envelope, now);
    });
    if (outcome.kind === 'locked') throw new HttpError(429, 'locked');
    if (outcome.kind === 'refused') throw new HttpError(401, 'unauthenticated');
    return { value: outcome.value, state: outcome.state };
  }

  #openSession(store: TenantStore, invitation: InvitationRecord, envelope: EnvelopeRecord, now: Date): SessionOutcome {
    const iso = now.toISOString();
    const value = newSessionValue();
    const csrfSecret = newCsrfSecret();
    const sessionId = this.#id();
    insertSession(store, {
      id: sessionId,
      valueHash: capabilityHash(value),
      envelopeId: envelope.id,
      recipientId: invitation.recipientId,
      revisionId: invitation.revisionId,
      manifestDigest: invitation.manifestDigest,
      csrfSecret,
      now: iso,
    });
    const session: RecipientSession = {
      tenantId: store.tenantId,
      sessionId,
      envelopeId: envelope.id,
      recipientId: invitation.recipientId,
      revisionId: invitation.revisionId,
      manifestDigest: invitation.manifestDigest,
      csrfSecret,
      lastSeenAt: iso,
    };
    return { kind: 'created', value, state: this.#state(store, session, now) };
  }

  #live(store: TenantStore, record: SessionRecord, now: Date): boolean {
    if (record.revokedAt !== null || idleExpired(record.lastSeenAt, now)) return false;
    const envelope = getEnvelope(store, record.envelopeId);
    return envelope !== undefined && this.#bound(envelope, record);
  }

  #session(tenantId: string, record: SessionRecord, lastSeenAt: string): RecipientSession {
    return Object.freeze({
      tenantId,
      sessionId: record.id,
      envelopeId: record.envelopeId,
      recipientId: record.recipientId,
      revisionId: record.revisionId,
      manifestDigest: record.manifestDigest,
      csrfSecret: record.csrfSecret,
      lastSeenAt,
    });
  }

  #touch(store: TenantStore, record: SessionRecord, now: Date): RecipientSession | null {
    const seen = new Date(Math.max(now.getTime(), Date.parse(record.lastSeenAt))).toISOString();
    if (!touchSession(store, record.id, record.lastSeenAt, seen)) return null;
    return this.#session(store.tenantId, record, seen);
  }

  authenticate(request: RequestLike, options: { readonly refresh: boolean }): RecipientSession | null {
    const value = readSessionCookie(request.headers);
    if (value === null) return null;
    const hash = capabilityHash(value);
    const now = this.#now();
    return this.#db.transaction(() => {
      const owner = resolveSession(this.#db, hash);
      if (owner === undefined) return null;
      const store = this.#db.forTenant(owner.tenantId);
      const record = getSession(store, owner.id);
      if (record === undefined || !this.#live(store, record, now)) return null;
      return options.refresh ? this.#touch(store, record, now) : this.#session(owner.tenantId, record, record.lastSeenAt);
    });
  }

  refresh(session: RecipientSession): RecipientSession | null {
    const now = this.#now();
    return this.#db.transaction(() => {
      const store = this.#db.forTenant(session.tenantId);
      const record = getSession(store, session.sessionId);
      if (record === undefined || !this.#live(store, record, now)) return null;
      return this.#touch(store, record, now);
    });
  }

  // -------------------------------------------------------------------- reads

  #consent(store: TenantStore): ConsentText {
    const consent = getConsentInForce(store);
    if (consent === undefined) throw internal();
    try {
      return checkConsentText(consent);
    } catch (error) {
      if (error instanceof ConsentError) throw internal();
      throw error;
    }
  }

  #state(store: TenantStore, session: RecipientSession, now: Date): JsonValue {
    const envelope = getEnvelope(store, session.envelopeId);
    if (envelope === undefined || !SESSION_ENVELOPE_STATES.includes(envelope.state)) throw internal();
    const recipients = listRecipients(store, envelope.id);
    const recipient = recipients.find((entry) => entry.id === session.recipientId);
    const revision = getRevision(store, envelope.id, session.revisionId);
    if (recipient === undefined || revision === undefined) throw internal();
    return sessionStateView({
      envelope,
      recipients,
      recipient,
      revision,
      manifestDigest: session.manifestDigest,
      fields: listFields(store, envelope.id),
      consent: this.#consent(store),
      csrfToken: csrfToken(session.csrfSecret, session.sessionId),
      sessionExpiresAt: sessionExpiresAt(session.lastSeenAt),
      now,
    });
  }

  /** readRecipientSession: every approval input of the session's recipient. */
  readState(session: RecipientSession): JsonValue {
    const now = this.#now();
    return this.#db.transaction(() => this.#state(this.#db.forTenant(session.tenantId), session, now));
  }

  /** readRecipientDocument: the exact frozen PDF bytes of the session's revision. */
  readDocument(session: RecipientSession): Buffer {
    const revision = this.#db.transaction(() => getRevision(this.#db.forTenant(session.tenantId), session.envelopeId, session.revisionId));
    if (revision === undefined) throw internal();
    let bytes: Buffer;
    try {
      bytes = this.#blobs.read(session.tenantId, revision.contentDigest);
    } catch {
      throw internal();
    }
    if (bytes.length !== revision.bytes || sha256(bytes) !== revision.contentDigest) throw internal();
    return bytes;
  }

  /** readRecipientManifest: the exact canonical manifest bytes frozen at prepare. */
  readManifest(session: RecipientSession): Buffer {
    const manifest = this.#db.transaction(() => getManifest(this.#db.forTenant(session.tenantId), session.envelopeId));
    if (manifest === undefined || manifest.digest !== session.manifestDigest || sha256(manifest.bytes) !== session.manifestDigest) throw internal();
    return Buffer.from(manifest.bytes);
  }

  /** endRecipientSession: revoke the session (the cookie is cleared by the handler). */
  endSession(session: RecipientSession): void {
    const iso = this.#now().toISOString();
    this.#db.transaction(() => {
      revokeSession(this.#db.forTenant(session.tenantId), session.sessionId, iso);
    });
  }
}
