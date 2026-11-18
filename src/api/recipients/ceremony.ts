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
// invitation exists, is live, or a code was mailed, and in the same time
// (data-model.md § Authentication and secrets, "Generic 202 (A-010)"). Before
// the 202 it does only what is the same for every request: schema validation
// and the rate-limit decision, per client address and per presented invitation
// (keyed by the token's hash; 429 rate_limited with Retry-After). Everything
// that depends on the invitation runs after the response: the request's work is
// started by the work scheduler on a later turn of the event loop (by default
// setImmediate; the 202 is written before that turn), serialized per presented
// invitation, so a second request's work waits until the first one's mail is
// done. That work looks the invitation up and, for a live one, supersedes the
// open challenge and stores a new one in one transaction: a 10-character
// Crockford code kept only as an HMAC under the 0600 key (codes.ts), expiring
// after 10 minutes. It mails the code after the commit. A failure there (the
// storage work or the mail) is logged as challenge_work_failed with the
// request's correlation ID and never a token or code, and counted
// (challengeWorkStats). A failed mail leaves the committed challenge open and
// unmailed: nobody holds its code, it expires after 10 minutes, and the
// recipient's next request supersedes it, so the recipient can request again.
// A failed storage step leaves nothing (its transaction rolls back). drain()
// resolves once no such work is pending.
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
// last_seen_at moves, and a prefetch moves nothing. They open no transaction,
// and neither does a session lookup that does not refresh, so none of them
// takes the write lock (data-model.md § Persistence; A-010 READ-LOCK-CER):
// only moving last_seen_at is a write. The document is the exact
// frozen bytes, read from the content-addressed blob store and re-checked
// against the revision's digest and size; the manifest is the exact canonical
// bytes frozen at prepare, re-checked against the manifest digest.
//
// Audit (row CEREMONY-AUDIT, CH-06). Each ceremony step appends to the
// tenant's audit chain through the T029 writer, in the step's own transaction:
// - recipient.invited: an invitation is issued (send, the first of two
//   approvals, or a resend);
// - recipient.challenge_verified: a right code consumed the open challenge;
// - recipient.session_created: the session that code opened;
// - recipient.locked_out: the twentieth wrong code revoked the invitation;
// - recipient.capabilities_revoked: a resend revoked the recipient's
//   invitations and sessions, the recipient ended a session, or the envelope
//   was voided, expired or reissued (the envelope service has revoked every
//   outstanding capability; the event names those revoked at that change's
//   instant that no earlier event names).
// Each event carries the envelope id and the bound manifest digest as its
// subject. Its metadata holds ids, ordinals and digests only (invitation,
// challenge, session, recipient and revision ids, the recipient's ordinal, the
// attempt, the envelope version), never a capability value, a code, an email
// address or a stored hash. The actor is the operator who caused the step, the
// recipient (by id) for their own verification, session and end, or the
// system.

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
import type { Actor } from '../../domain/envelopes/validation.ts';
import type { RecipientChallengeRequest, RecipientInvitationRequest } from '../../notifications/content.ts';
import { NotificationError } from '../../notifications/errors.ts';
import type { Notifier } from '../../notifications/notifier.ts';
import { createLogger, type Logger } from '../../server/redact.ts';
import { HttpError } from '../../server/types.ts';
import { AuditWriter, type AuditActor } from '../../storage/audit/index.ts';
import type { BlobStore } from '../../storage/blobs/index.ts';
import { StorageError, type Database, type TenantStore } from '../../storage/db/index.ts';
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
  auditedRevocationsOf,
  capabilitiesRevokedAt,
  consumeChallenge,
  getConsentInForce,
  getInvitation,
  getSession,
  insertChallenge,
  insertInvitation,
  insertSession,
  liveInvitationsOf,
  openChallenge,
  outstandingCapabilitiesOf,
  recordWrongCode,
  resolveInvitation,
  resolveSession,
  revokeInvitationsOf,
  revokeSession,
  revokeSessionsOf,
  supersedeOpenChallenges,
  touchSession,
  type CapabilityIds,
  type ChallengeRecord,
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

/**
 * Starts requestChallenge's post-response work. The default runs it with
 * setImmediate, a later turn of the event loop than the one in which the
 * handler returns and the server writes the 202.
 */
export type WorkScheduler = (task: () => void) => void;

/** requestChallenge's post-response work: pending (scheduled, not finished), completed, failed. */
export interface ChallengeWorkStats {
  readonly pending: number;
  readonly completed: number;
  readonly failed: number;
}

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
  /** The audit-chain writer (T029); by default one on `db` with `clock`. */
  readonly audit?: AuditWriter;
  /** How requestChallenge's post-response work is started (default: setImmediate). */
  readonly scheduleWork?: WorkScheduler;
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

/** The ceremony's audit event types (CH-06). */
type CeremonyEvent = 'recipient.invited' | 'recipient.challenge_verified' | 'recipient.session_created' | 'recipient.locked_out' | 'recipient.capabilities_revoked';

/** The actor of a step no person took (an approval's follow-up invitation, a lockout, an expiry). */
const SYSTEM_ACTOR: AuditActor = Object.freeze({ kind: 'system', ref: 'recipient-ceremony' });

const DEFAULT_SCHEDULER: WorkScheduler = (task) => {
  setImmediate(task);
};

function operatorActor(actor: Actor | null | undefined): AuditActor {
  return actor === null || actor === undefined ? SYSTEM_ACTOR : { kind: actor.kind, ref: actor.ref };
}

function recipientActor(recipientId: string): AuditActor {
  return { kind: 'recipient', ref: recipientId };
}

type WorkStage = 'storage' | 'mail' | 'work';

function failureReason(stage: WorkStage, error: unknown): string {
  if (stage === 'mail') return error instanceof NotificationError ? error.code : 'delivery_failed';
  if (stage === 'storage') return error instanceof StorageError ? error.code : 'storage_failed';
  return 'internal';
}

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
  readonly #audit: AuditWriter;
  readonly #scheduleWork: WorkScheduler;
  // requestChallenge's post-response work: the last job per presented invitation (token hash),
  // every unfinished job, and the counts.
  readonly #tails = new Map<string, Promise<void>>();
  readonly #inflight = new Set<Promise<void>>();
  readonly #work = { pending: 0, completed: 0, failed: 0 };

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
    if (options.audit !== undefined && !(options.audit instanceof AuditWriter)) throw new TypeError('the ceremony audit writer must be an AuditWriter');
    this.#audit = options.audit ?? new AuditWriter(options.db, { clock: options.clock });
    if (options.scheduleWork !== undefined && typeof options.scheduleWork !== 'function') throw new TypeError('scheduleWork must be a function');
    this.#scheduleWork = options.scheduleWork ?? DEFAULT_SCHEDULER;
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

  /** Append one ceremony event to the tenant's audit chain, inside the caller's transaction. */
  #record(store: TenantStore, type: CeremonyEvent, actor: AuditActor, envelopeId: string, subjectDigest: string | null, metadata: { readonly [key: string]: JsonValue }): void {
    this.#audit.append(store.tenantId, { type, actor, envelopeId, subjectDigest, metadata });
  }

  #ordinalOf(store: TenantStore, envelopeId: string, recipientId: string): number {
    const recipient = listRecipients(store, envelopeId).find((entry) => entry.id === recipientId);
    if (recipient === undefined) throw new TypeError('the bound recipient is missing');
    return recipient.ordinal;
  }

  /** recipient.capabilities_revoked, when the revocation revoked anything. */
  #recordRevoked(store: TenantStore, actor: AuditActor, envelopeId: string, subjectDigest: string | null, scope: { readonly [key: string]: JsonValue }, revoked: CapabilityIds): void {
    if (revoked.invitationIds.length === 0 && revoked.sessionIds.length === 0) return;
    this.#record(store, 'recipient.capabilities_revoked', actor, envelopeId, subjectDigest, {
      ...scope,
      invitation_ids: [...revoked.invitationIds],
      session_ids: [...revoked.sessionIds],
    });
  }

  /** The invitation still names the envelope's frozen revision and manifest. */
  #bound(envelope: EnvelopeRecord, binding: { readonly revisionId: string; readonly manifestDigest: string }): boolean {
    return envelope.baseRevisionId === binding.revisionId && envelope.manifestDigest === binding.manifestDigest;
  }

  // ---------------------------------------------------------------- invitations

  /**
   * EnvelopeService onChange: inside the mutation's transaction, invite every
   * recipient the change made `invited` who holds no live invitation (send:
   * recipient 1; the first of two approvals: recipient 2), and record what a
   * void, an expiry or a reissue revoked.
   */
  readonly onEnvelopeChange = (change: EnvelopeChange, store: TenantStore): void => {
    if (change.operation === 'void' || change.operation === 'expire' || change.operation === 'reissued') {
      this.#recordEnvelopeRevocation(change, store);
      return;
    }
    if (change.operation !== 'send' && !(change.operation === 'approval' && change.to === 'in-progress')) return;
    const now = this.#now();
    const iso = now.toISOString();
    const envelope = getEnvelope(store, change.envelopeId);
    if (envelope === undefined) throw new TypeError('the changed envelope is missing');
    for (const recipient of listRecipients(store, envelope.id)) {
      if (recipient.status === 'invited' && liveInvitationsOf(store, envelope.id, recipient.id, iso).length === 0) {
        this.#issue(store, envelope, recipient, now, operatorActor(change.actor));
      }
    }
  };

  /**
   * The envelope service revoked every outstanding invitation and session of
   * the envelope in this change, with the instant it wrote as the envelope's
   * updated_at. Record those revoked at that instant that no earlier event
   * names (a resend, a lockout or an ended session in the same millisecond).
   */
  #recordEnvelopeRevocation(change: EnvelopeChange, store: TenantStore): void {
    const envelope = getEnvelope(store, change.envelopeId);
    if (envelope === undefined) throw new TypeError('the changed envelope is missing');
    const revoked = capabilitiesRevokedAt(store, envelope.id, envelope.updatedAt);
    if (revoked.invitationIds.length === 0 && revoked.sessionIds.length === 0) return;
    const named = auditedRevocationsOf(store, envelope.id);
    this.#recordRevoked(store, operatorActor(change.actor), envelope.id, envelope.manifestDigest, { envelope_version: change.version }, {
      invitationIds: revoked.invitationIds.filter((id) => !named.has(id)),
      sessionIds: revoked.sessionIds.filter((id) => !named.has(id)),
    });
  }

  #issue(store: TenantStore, envelope: EnvelopeRecord, recipient: RecipientRecord, now: Date, actor: AuditActor): void {
    const buffer = this.#captures[this.#captures.length - 1];
    if (buffer === undefined) {
      throw new TypeError('invitations are issued only inside RecipientCeremony.capture(), which mails them after the commit');
    }
    if (envelope.baseRevisionId === null || envelope.manifestDigest === null) throw new TypeError('only a prepared envelope has invitations');
    const expires = Math.min(now.getTime() + INVITATION_TTL_MS, Date.parse(envelope.expiresAt));
    if (!(expires > now.getTime())) throw new HttpError(409, 'state_conflict');
    const token = newInvitationToken();
    const expiresAt = new Date(expires).toISOString();
    const invitationId = this.#id();
    insertInvitation(store, {
      id: invitationId,
      envelopeId: envelope.id,
      recipientId: recipient.id,
      revisionId: envelope.baseRevisionId,
      manifestDigest: envelope.manifestDigest,
      tokenHash: capabilityHash(token),
      sentAt: now.toISOString(),
      expiresAt,
    });
    this.#record(store, 'recipient.invited', actor, envelope.id, envelope.manifestDigest, {
      invitation_id: invitationId,
      recipient_id: recipient.id,
      recipient_ordinal: recipient.ordinal,
      revision_id: envelope.baseRevisionId,
    });
    buffer.push(new InvitationMail({ kind: 'recipient_invitation', tenant_id: store.tenantId, to: recipient.email, invitation: token, expires_at: expiresAt }));
  }

  /**
   * Resend (inside the caller's transaction and capture()): the recipient whose
   * turn it is, still invited, on an envelope that takes approvals, loses every
   * outstanding invitation and session and gets a fresh invitation. `actor` is
   * the operator who asked for it (the audit events' actor; the system when
   * omitted).
   */
  resendInvitation(store: TenantStore, envelopeId: string, recipientId: string, actor?: Actor): void {
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
    const by = operatorActor(actor);
    const outstanding = outstandingCapabilitiesOf(store, envelopeId, recipientId);
    revokeInvitationsOf(store, envelopeId, recipientId, iso);
    revokeSessionsOf(store, envelopeId, recipientId, iso);
    this.#recordRevoked(store, by, envelopeId, envelope.manifestDigest, { recipient_id: recipientId, recipient_ordinal: recipient.ordinal }, outstanding);
    setRecipientProgress(store, recipientId, { status: 'invited', invitedAt: iso, updatedAt: iso });
    this.#issue(store, envelope, recipient, now, by);
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
   * requestChallenge, before its generic 202: schema validation (400) and the
   * rate-limit decision (429) only, the same work for every token. It then
   * hands the per-invitation work to the work scheduler and returns, so the
   * handler answers before any of that work starts. `correlationId` is the
   * request's, for the failure log.
   */
  requestChallenge(body: unknown, clientAddress: string, correlationId = 'none'): void {
    const token = checkChallengeRequest(body);
    const tokenHash = capabilityHash(token);
    this.#limit([this.#challengeByAddress, clientAddress], [this.#challengeByInvitation, tokenHash]);
    this.#enqueue(tokenHash, correlationId);
  }

  /**
   * Run the request's work once the scheduler starts it and the previous work
   * for the same presented invitation has finished. Nothing here rejects: every
   * failure is logged and counted.
   */
  #enqueue(tokenHash: string, correlationId: string): void {
    const started = new Promise<void>((resolveStart) => {
      this.#scheduleWork(() => resolveStart());
    });
    const previous = this.#tails.get(tokenHash);
    const run = (previous === undefined ? started : Promise.all([previous, started])).then(() => this.#challengeWork(tokenHash, correlationId));
    this.#work.pending += 1;
    const tail: Promise<void> = run
      .catch((error: unknown) => this.#workFailed('work', correlationId, error))
      .finally(() => {
        this.#work.pending -= 1;
        this.#inflight.delete(tail);
        if (this.#tails.get(tokenHash) === tail) this.#tails.delete(tokenHash);
      });
    this.#tails.set(tokenHash, tail);
    this.#inflight.add(tail);
  }

  /** The per-invitation work: the lookup and challenge write in one transaction, then the mail. */
  async #challengeWork(tokenHash: string, correlationId: string): Promise<void> {
    let mail: RecipientChallengeRequest | null;
    try {
      mail = this.#writeChallenge(tokenHash);
    } catch (error) {
      this.#workFailed('storage', correlationId, error);
      return;
    }
    if (mail !== null) {
      try {
        await this.#notifier.send(mail);
      } catch (error) {
        this.#workFailed('mail', correlationId, error);
        return;
      }
    }
    this.#work.completed += 1;
  }

  #workFailed(stage: WorkStage, correlationId: string, error: unknown): void {
    this.#work.failed += 1;
    this.#logger.warn('challenge_work_failed', { correlation_id: correlationId, stage, reason: failureReason(stage, error), failures: this.#work.failed });
  }

  /** Resolves once no requestChallenge work is pending (work started meanwhile included). */
  async drain(): Promise<void> {
    while (this.#inflight.size > 0) await Promise.all([...this.#inflight]);
  }

  challengeWorkStats(): ChallengeWorkStats {
    return Object.freeze({ ...this.#work });
  }

  /** For a live invitation: supersede its open challenge and store a new one; returns the mail, or null. */
  #writeChallenge(tokenHash: string): RecipientChallengeRequest | null {
    const now = this.#now();
    const iso = now.toISOString();
    return this.#db.transaction((): RecipientChallengeRequest | null => {
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
        const wrong = recordWrongCode(store, invitation, challenge, iso);
        if (wrong.revoked) {
          this.#record(store, 'recipient.locked_out', SYSTEM_ACTOR, envelope.id, invitation.manifestDigest, {
            invitation_id: invitation.id,
            challenge_id: challenge.id,
            recipient_id: invitation.recipientId,
            recipient_ordinal: this.#ordinalOf(store, envelope.id, invitation.recipientId),
            wrong_attempt: wrong.cumulativeWrongCodes,
          });
        }
        return { kind: 'refused' };
      }
      consumeChallenge(store, challenge, iso);
      return this.#openSession(store, invitation, challenge, envelope, now);
    });
    if (outcome.kind === 'locked') throw new HttpError(429, 'locked');
    if (outcome.kind === 'refused') throw new HttpError(401, 'unauthenticated');
    return { value: outcome.value, state: outcome.state };
  }

  #openSession(store: TenantStore, invitation: InvitationRecord, challenge: ChallengeRecord, envelope: EnvelopeRecord, now: Date): SessionOutcome {
    const iso = now.toISOString();
    const ordinal = this.#ordinalOf(store, envelope.id, invitation.recipientId);
    const by = recipientActor(invitation.recipientId);
    this.#record(store, 'recipient.challenge_verified', by, envelope.id, invitation.manifestDigest, {
      invitation_id: invitation.id,
      challenge_id: challenge.id,
      recipient_id: invitation.recipientId,
      recipient_ordinal: ordinal,
      attempt: challenge.attempts + 1,
    });
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
    this.#record(store, 'recipient.session_created', by, envelope.id, invitation.manifestDigest, {
      session_id: sessionId,
      invitation_id: invitation.id,
      recipient_id: invitation.recipientId,
      recipient_ordinal: ordinal,
      revision_id: invitation.revisionId,
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

  /**
   * A lookup that refreshes moves last_seen_at, a write, so it runs in one
   * transaction. A lookup that does not refresh (a prefetch, or the first step
   * of a mutation's guard) only reads, so it opens no transaction and takes no
   * write lock (data-model.md § Persistence; A-010 READ-LOCK-CER, CH-09).
   */
  authenticate(request: RequestLike, options: { readonly refresh: boolean }): RecipientSession | null {
    const value = readSessionCookie(request.headers);
    if (value === null) return null;
    const hash = capabilityHash(value);
    const now = this.#now();
    const refresh = options.refresh;
    const lookup = (): RecipientSession | null => {
      const owner = resolveSession(this.#db, hash);
      if (owner === undefined) return null;
      const store = this.#db.forTenant(owner.tenantId);
      const record = getSession(store, owner.id);
      if (record === undefined || !this.#live(store, record, now)) return null;
      return refresh ? this.#touch(store, record, now) : this.#session(owner.tenantId, record, record.lastSeenAt);
    };
    return refresh ? this.#db.transaction(lookup) : lookup();
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

  // The three reads below open no transaction, so they take no write lock
  // (data-model.md § Persistence; A-010 READ-LOCK-CER, CH-09). Their statements
  // cannot interleave with this process's own writes, which all run
  // synchronously, and the store refuses any write outside a transaction.

  /** readRecipientSession: every approval input of the session's recipient. */
  readState(session: RecipientSession): JsonValue {
    const now = this.#now();
    return this.#state(this.#db.forTenant(session.tenantId), session, now);
  }

  /** readRecipientDocument: the exact frozen PDF bytes of the session's revision. */
  readDocument(session: RecipientSession): Buffer {
    const revision = getRevision(this.#db.forTenant(session.tenantId), session.envelopeId, session.revisionId);
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
    const manifest = getManifest(this.#db.forTenant(session.tenantId), session.envelopeId);
    if (manifest === undefined || manifest.digest !== session.manifestDigest || sha256(manifest.bytes) !== session.manifestDigest) throw internal();
    return Buffer.from(manifest.bytes);
  }

  /** endRecipientSession: revoke the session (the cookie is cleared by the handler). */
  endSession(session: RecipientSession): void {
    const iso = this.#now().toISOString();
    this.#db.transaction(() => {
      const store = this.#db.forTenant(session.tenantId);
      if (!revokeSession(store, session.sessionId, iso)) return;
      this.#recordRevoked(
        store,
        recipientActor(session.recipientId),
        session.envelopeId,
        session.manifestDigest,
        { recipient_id: session.recipientId, recipient_ordinal: this.#ordinalOf(store, session.envelopeId, session.recipientId) },
        { invitationIds: [], sessionIds: [session.sessionId] },
      );
    });
  }
}
