// SPDX-License-Identifier: Apache-2.0
//
// Approval and decline (T010; data-model.md § Envelope states, § Transitions
// and races and § Authentication and secrets; contracts/sessions-events-
// adapters.md § Recipient ceremony, items 5 and 6).
//
// Who. Only a live recipient session reaches this module: the handlers
// (src/api/recipients/approval.ts, decline.ts) refuse any operator or service
// credential with 401 and check the session and its CSRF token first. There is
// no operator principal anywhere in this module's API. Inside its transaction
// the service reads the session row again, so a session revoked meanwhile (by
// a decline, a void, an expiry, a resend or a reissue committed after the
// handler's check) is 401 here too.
//
// The one compare-and-set path. Approval, decline, expiry, void and the
// finalization reservation all change an envelope through
// compareAndSetEnvelope (src/storage/repositories/envelopes.ts), which updates
// the row only while its version is still the one read and moves the version
// by exactly one, inside one BEGIN IMMEDIATE transaction. Exactly one of any
// concurrent set wins; the others find a different version or state and get
// 409, and their transaction leaves nothing behind (data-model.md
// § Transitions and races, item 1). Migration 0010 enforces the transition
// graph on the same rows, so nothing leaves finalizing except completion.
// - approval: EnvelopeService.advanceOnApproval (T007), which compares and sets
//   through that function, called inside this module's transaction;
// - decline: declineInTransaction below, through that function directly, with
//   the same transition check (EnvelopeService has no decline operation of its
//   own, and T007's files are not T010's);
// - expiry: EnvelopeService.expireIfDue (T007), run by the sweeper
//   (src/jobs/expiry.ts) and by a request that finds expires_at passed;
// - void: EnvelopeService.void (T007), behind T034's voidEnvelope.
//
// The finalization reservation. The last required approval moves the envelope
// to finalizing (approvals_complete = true: "fully approved", never completed)
// and, in the same transaction, inserts the envelope's SigningJob with
// reserved_version equal to the version that transition wrote. The approval
// row, the recipient's progress, the envelope's compare-and-set, the
// reservation, the audit event and the receipt commit together or not at all,
// so no void, decline or expiry that loses the race can leave a reservation,
// and none that wins can find one.
//
// Approval, in this order (A-010, request #24, ruling (8); each refusal
// records nothing):
// 1. the session row is live and bound as the handler saw it: 401. The handler
//    has already checked the session and its CSRF token before reading the
//    body, so an unauthenticated caller learns nothing about validation;
// 2. an earlier approval of this recipient: the same request (approval request
//    digest, record.ts) replays the stored receipt bytes, 200; any other
//    request, malformed or not, is 409 state_conflict;
// 3. the body (values.ts): 400 invalid_request, then 422 unsupported_characters;
// 4. the envelope is before the reservation and its expires_at has passed: 409
//    state_conflict, and the expiry is then committed in its own transaction
//    through the same compare-and-set (T007 ruling);
// 5. the envelope takes approvals (sent or in-progress): 409 state_conflict;
// 6. expected_version is the envelope's version: 409 version_conflict;
// 7. it is this recipient's turn and the recipient is invited: 409
//    order_conflict;
// 8. document_digest, manifest_digest and prior_approval_digest are the
//    frozen revision's, the frozen manifest's and the prior recipient's
//    approval digest (null for ordinal 1): 409 digest_mismatch;
// 9. consent_version and consent_text_digest are those of the tenant's consent
//    text in force: 409 consent_mismatch;
// 10. exactly one value per field of this recipient, of the field's type: 400
//     invalid_request;
// then the approval is recorded and the envelope advanced.
//
// Decline: the session (401), then the body (400), then 4..7, then: the
// envelope moves to declined through the compare-and-set, the recipient to
// declined, every other recipient still pending or invited to revoked
// (mirroring void; A-010, request #24, ruling (5)), and every outstanding
// invitation and session of the envelope is revoked. The response is the
// generic outcome {envelope_state: declined}.
//
// Events, each in the transaction of the change it records, exactly once, and
// none on a refusal:
// - audit (T029 writer; T007 writes no audit event for these transitions, so
//   none is duplicated): recipient.approved per approval; recipient.declined
//   and recipient.capabilities_revoked (what it revoked) per decline. Metadata
//   holds refs (ids), digests, ordinals, versions, states and the decline's
//   contract reason code only: never a capability value, a field value or an
//   address (ruling (3));
// - outbox (src/storage/outbox, the contract's WebhookEvent): envelope.declined
//   per decline (ruling (6)). envelope.expired is announced by expiryAnnouncer
//   (events.ts) for every expiry T010 drives.

import { randomBytes } from 'node:crypto';

import { canonicalBytes, type JsonValue } from '../../domain/canonical/index.ts';
import { ConsentError, checkConsentText, consentMatches, type ConsentText } from '../consent/index.ts';
import { EnvelopeError } from '../envelopes/errors.ts';
import type { ApprovalOutcome, EnvelopeService } from '../envelopes/service.ts';
import { APPROVING_STATES, PRE_RESERVATION_STATES, canTransition, turnAfter } from '../envelopes/states.ts';
import { AuditWriter, type AuditActor } from '../../storage/audit/index.ts';
import { StorageError, type Database, type TenantStore } from '../../storage/db/index.ts';
import {
  getApprovalOf,
  getApprovalReceiptOf,
  insertApproval,
  insertApprovalReceipt,
  insertFinalizationReservation,
} from '../../storage/repositories/approvals.ts';
import {
  closeOpenRecipients,
  compareAndSetEnvelope,
  getEnvelope,
  getRevision,
  listFields,
  listRecipients,
  revokeOutstandingCapabilities,
  setRecipientProgress,
  type EnvelopeRecord,
  type FieldRecord,
  type RecipientRecord,
} from '../../storage/repositories/envelopes.ts';
import { auditedRevocationsOf, capabilitiesRevokedAt, getConsentInForce, getSession } from '../../storage/repositories/recipients.ts';
import { enqueueOutboxEvent } from '../../storage/outbox/index.ts';
import { ApprovalError } from './errors.ts';
import { approvalRequestDigest, buildApproval, receiptView } from './record.ts';
import { checkApprovalRequest, checkDeclineRequest, type FieldValue } from './values.ts';

/** Attempts a reserved finalization may take (T038's runner owns the retry schedule). */
export const FINALIZATION_MAX_ATTEMPTS = 5;

/** What the service needs of an authenticated recipient session (src/api/auth/recipient-session.ts, RecipientSession). */
export interface ApprovalSession {
  readonly tenantId: string;
  readonly sessionId: string;
  readonly envelopeId: string;
  readonly recipientId: string;
  readonly revisionId: string;
  readonly manifestDigest: string;
}

export interface ApprovalServiceOptions {
  readonly db: Database;
  readonly clock: () => Date;
  /**
   * The T007 envelope service whose advanceOnApproval and expireIfDue compare
   * and set the envelope. Its onChange must be the recipient ceremony's, so the
   * first of two approvals invites recipient 2 and an expiry records what it
   * revoked.
   */
  readonly envelopes: EnvelopeService;
  /** The audit-chain writer (T029); by default one on `db` with `clock`. */
  readonly audit?: AuditWriter;
  readonly newId?: () => string;
  /** max_attempts of a reserved SigningJob (default FINALIZATION_MAX_ATTEMPTS). */
  readonly maxAttempts?: number;
}

export interface ApprovalResult {
  readonly status: 200;
  /** The exact ApprovalReceipt bytes; an exact retry gets the stored bytes. */
  readonly bytes: Buffer;
  readonly replayed: boolean;
}

export interface DeclineResult {
  readonly status: 200;
  /** The generic DeclineOutcome bytes. */
  readonly bytes: Buffer;
}

const DECLINE_OUTCOME: JsonValue = Object.freeze({ envelope_state: 'declined' });

function unauthenticated(): ApprovalError {
  return new ApprovalError('unauthenticated', 'the recipient session is not live');
}

function stateConflict(message: string, expired = false): ApprovalError {
  return new ApprovalError('state_conflict', message, [], { expired });
}

function internal(): ApprovalError {
  return new ApprovalError('internal', 'the request could not be completed');
}

/** advanceOnApproval's refusals keep their contract code; anything else is internal. */
function fromEnvelopeError(error: EnvelopeError): ApprovalError {
  switch (error.code) {
    case 'state_conflict':
    case 'version_conflict':
    case 'order_conflict':
      return new ApprovalError(error.code, 'the envelope did not take the approval');
    default:
      return internal();
  }
}

function recipientActor(recipientId: string): AuditActor {
  return { kind: 'recipient', ref: recipientId };
}

/** Exactly one value per field of this recipient, of the field's type (400 otherwise). */
function matchFields(values: readonly FieldValue[], fields: readonly FieldRecord[]): void {
  const byKey = new Map(fields.map((field) => [field.key, field]));
  for (const value of values) {
    const field = byKey.get(value.key);
    if (field === undefined) throw new ApprovalError('invalid_request', 'the request is invalid', [{ field: 'field_values', code: 'unknown_field' }]);
    if (field.type !== value.type) throw new ApprovalError('invalid_request', 'the request is invalid', [{ field: 'field_values', code: 'type_mismatch' }]);
  }
  if (values.length !== fields.length) throw new ApprovalError('invalid_request', 'the request is invalid', [{ field: 'field_values', code: 'missing_field' }]);
}

export class ApprovalService {
  readonly #db: Database;
  readonly #clock: () => Date;
  readonly #envelopes: EnvelopeService;
  readonly #audit: AuditWriter;
  readonly #newId: () => string;
  readonly #maxAttempts: number;

  constructor(options: ApprovalServiceOptions) {
    if (typeof options?.clock !== 'function') throw new TypeError('the approval service needs an injected clock');
    if (typeof options.db?.transaction !== 'function' || typeof options.db.forTenant !== 'function') throw new TypeError('the approval service needs the database');
    if (typeof options.envelopes?.advanceOnApproval !== 'function' || typeof options.envelopes.expireIfDue !== 'function') {
      throw new TypeError('the approval service needs the envelope service');
    }
    if (options.audit !== undefined && !(options.audit instanceof AuditWriter)) throw new TypeError('the approval audit writer must be an AuditWriter');
    const maxAttempts = options.maxAttempts ?? FINALIZATION_MAX_ATTEMPTS;
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 100) throw new TypeError('max attempts must be an integer in 1..100');
    this.#db = options.db;
    this.#clock = options.clock;
    this.#envelopes = options.envelopes;
    this.#audit = options.audit ?? new AuditWriter(options.db, { clock: options.clock });
    this.#newId = options.newId ?? (() => randomBytes(18).toString('base64url'));
    this.#maxAttempts = maxAttempts;
    Object.freeze(this);
  }

  #now(): Date {
    const now = this.#clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('the approval clock returned an invalid date');
    return now;
  }

  #id(): string {
    const id = this.#newId();
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(id)) throw new TypeError('generated id is malformed');
    return id;
  }

  /** The session row is live and bound exactly as the handler saw it (401 otherwise). */
  #liveSession(store: TenantStore, session: ApprovalSession): void {
    const record = getSession(store, session.sessionId);
    if (
      record === undefined ||
      record.revokedAt !== null ||
      record.envelopeId !== session.envelopeId ||
      record.recipientId !== session.recipientId ||
      record.revisionId !== session.revisionId ||
      record.manifestDigest !== session.manifestDigest
    ) {
      throw unauthenticated();
    }
  }

  /**
   * Steps 4..7: the bound envelope exists, is before its expiry, takes
   * approvals, is at the expected version, and it is this invited recipient's
   * turn. Returns the envelope, its recipients and the session's recipient.
   */
  #turn(store: TenantStore, session: ApprovalSession, expectedVersion: number, now: Date): { envelope: EnvelopeRecord; recipients: RecipientRecord[]; recipient: RecipientRecord } {
    const envelope = getEnvelope(store, session.envelopeId);
    if (envelope === undefined) throw unauthenticated();
    if (PRE_RESERVATION_STATES.includes(envelope.state) && Date.parse(envelope.expiresAt) <= now.getTime()) {
      throw stateConflict('the envelope has expired', true);
    }
    if (!APPROVING_STATES.includes(envelope.state)) throw stateConflict('the envelope no longer takes approvals');
    if (envelope.version !== expectedVersion) throw new ApprovalError('version_conflict', 'the envelope version has changed');
    const recipients = listRecipients(store, envelope.id);
    const recipient = recipients.find((entry) => entry.id === session.recipientId);
    if (recipient === undefined) throw unauthenticated();
    const turn = turnAfter(
      recipients.filter((entry) => entry.status === 'approved').map((entry) => entry.ordinal),
      envelope.recipientsCount,
    );
    if (recipient.ordinal !== turn || recipient.status !== 'invited') throw new ApprovalError('order_conflict', 'it is not this recipient’s turn');
    if (envelope.baseRevisionId !== session.revisionId || envelope.manifestDigest !== session.manifestDigest) throw unauthenticated();
    return { envelope, recipients, recipient };
  }

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

  /** After a refusal for a passed expires_at, commit the expiry in its own transaction (same compare-and-set). */
  #expireAfterRefusal(session: ApprovalSession, error: unknown): void {
    if (!(error instanceof ApprovalError) || !error.expired) return;
    try {
      this.#envelopes.expireIfDue(session.tenantId, session.envelopeId);
    } catch (expiryError) {
      // A busy database or a concurrent change: the sweeper expires it on its next run.
      if (!(expiryError instanceof StorageError) && !(expiryError instanceof EnvelopeError)) throw expiryError;
    }
  }

  /**
   * approveAsHuman for the session's recipient: the receipt, or the original
   * receipt for an exact retry. `body` is the parsed JSON body, or any value
   * that is not an object (such as MALFORMED_BODY) when it did not parse.
   */
  approve(session: ApprovalSession, body: unknown): ApprovalResult {
    const now = this.#now();
    try {
      return this.#db.transaction((): ApprovalResult => this.#approveInTransaction(this.#db.forTenant(session.tenantId), session, body, now));
    } catch (error) {
      this.#expireAfterRefusal(session, error);
      throw error;
    }
  }

  /** The request digest of `body` when it is a valid Approval, else null (a malformed body is never an exact retry). */
  #exactDigest(recipientId: string, body: unknown): string | null {
    try {
      return approvalRequestDigest(recipientId, checkApprovalRequest(body));
    } catch (error) {
      if (error instanceof ApprovalError) return null;
      throw error;
    }
  }

  #approveInTransaction(store: TenantStore, session: ApprovalSession, body: unknown, now: Date): ApprovalResult {
    // 1. The session.
    this.#liveSession(store, session);
    // 2. An earlier approval: the exact request replays its receipt; any other request, malformed or not, is 409.
    const earlier = getApprovalReceiptOf(store, session.recipientId);
    if (earlier !== undefined) {
      if (earlier.requestDigest === this.#exactDigest(session.recipientId, body)) return { status: 200, bytes: earlier.body, replayed: true };
      throw stateConflict('the recipient has already approved with a different request');
    }
    if (getApprovalOf(store, session.recipientId) !== undefined) throw stateConflict('the recipient has already approved');
    // 3. The body.
    const request = checkApprovalRequest(body);
    const requestDigest = approvalRequestDigest(session.recipientId, request);

    const { envelope, recipients, recipient } = this.#turn(store, session, request.expectedVersion, now);
    const revision = getRevision(store, envelope.id, session.revisionId);
    if (revision === undefined || envelope.manifestDigest === null) throw internal();
    if (request.documentDigest !== revision.contentDigest) {
      throw new ApprovalError('digest_mismatch', 'a digest does not match', [{ field: 'document_digest', code: 'mismatch' }]);
    }
    if (request.manifestDigest !== envelope.manifestDigest) {
      throw new ApprovalError('digest_mismatch', 'a digest does not match', [{ field: 'manifest_digest', code: 'mismatch' }]);
    }
    let prior: string | null = null;
    if (recipient.ordinal > 1) {
      prior = recipients.find((entry) => entry.ordinal === recipient.ordinal - 1)?.approvalDigest ?? null;
      if (prior === null) throw internal();
    }
    if (request.priorApprovalDigest !== prior) {
      throw new ApprovalError('digest_mismatch', 'a digest does not match', [{ field: 'prior_approval_digest', code: 'mismatch' }]);
    }
    const consent = this.#consent(store);
    if (!consentMatches(consent, request.consentVersion, request.consentTextDigest)) throw new ApprovalError('consent_mismatch', 'the consent does not match');
    matchFields(
      request.fieldValues,
      listFields(store, envelope.id).filter((field) => field.recipientId === recipient.id),
    );

    const serverTime = now.toISOString();
    const approvalId = this.#id();
    const built = buildApproval({
      approvalId,
      recipient: { id: recipient.id, ordinal: recipient.ordinal, role: recipient.role, email: recipient.email },
      consentVersion: consent.version,
      consentTextDigest: consent.textDigest,
      documentDigest: revision.contentDigest,
      manifestDigest: envelope.manifestDigest,
      priorApprovalDigest: prior,
      fieldValues: request.fieldValues,
      serverTime,
    });
    insertApproval(store, {
      id: approvalId,
      envelopeId: envelope.id,
      recipientId: recipient.id,
      documentDigest: revision.contentDigest,
      manifestDigest: envelope.manifestDigest,
      priorApprovalDigest: prior,
      consentTextId: consent.id,
      consentVersion: consent.version,
      consentTextDigest: consent.textDigest,
      fieldValuesJson: canonicalBytes(built.fieldValues).toString('utf8'),
      fieldValuesDigest: built.fieldValuesDigest,
      serverTime,
      approvalDigest: built.approvalDigest,
    });

    // The compare-and-set: (state, version) as read, version + 1. The last
    // required approval moves the envelope to finalizing.
    let outcome: ApprovalOutcome;
    try {
      outcome = this.#envelopes.advanceOnApproval(store, { envelopeId: envelope.id, expectedVersion: request.expectedVersion, recipientId: recipient.id, approvalId });
    } catch (error) {
      if (error instanceof EnvelopeError) throw fromEnvelopeError(error);
      throw error;
    }
    const state = outcome.state;
    if (state !== 'in-progress' && state !== 'finalizing') throw internal();
    if (outcome.version !== request.expectedVersion + 1 || outcome.fullyApproved !== (state === 'finalizing')) throw internal();
    // The finalization reservation, in the same transaction as that transition.
    if (outcome.fullyApproved) {
      insertFinalizationReservation(store, { envelopeId: envelope.id, reservedVersion: outcome.version, maxAttempts: this.#maxAttempts, now: serverTime });
    }
    this.#audit.append(store.tenantId, {
      type: 'recipient.approved',
      actor: recipientActor(recipient.id),
      envelopeId: envelope.id,
      subjectDigest: built.approvalDigest,
      metadata: {
        approval_id: approvalId,
        recipient_id: recipient.id,
        recipient_ordinal: recipient.ordinal,
        envelope_version: outcome.version,
        envelope_state: state,
      },
    });
    const bytes = canonicalBytes(
      receiptView({
        approvalId,
        approvalDigest: built.approvalDigest,
        recipientId: recipient.id,
        envelopeVersion: outcome.version,
        envelopeState: state,
        dateValues: built.dateValues,
        serverTime,
      }),
    );
    insertApprovalReceipt(store, { approvalId, envelopeId: envelope.id, recipientId: recipient.id, requestDigest, body: bytes, createdAt: serverTime });
    return { status: 200, bytes, replayed: false };
  }

  /** declineAsRecipient for the session's recipient: the generic outcome. */
  decline(session: ApprovalSession, body: unknown): DeclineResult {
    const now = this.#now();
    try {
      return this.#db.transaction((): DeclineResult => this.#declineInTransaction(this.#db.forTenant(session.tenantId), session, body, now));
    } catch (error) {
      this.#expireAfterRefusal(session, error);
      throw error;
    }
  }

  #declineInTransaction(store: TenantStore, session: ApprovalSession, body: unknown, now: Date): DeclineResult {
    this.#liveSession(store, session);
    const request = checkDeclineRequest(body);
    const { envelope, recipient } = this.#turn(store, session, request.expectedVersion, now);
    const iso = now.toISOString();
    if (!canTransition(envelope.state, 'declined')) throw stateConflict('the envelope cannot be declined');
    // The compare-and-set shared with approval, expiry and void.
    if (!compareAndSetEnvelope(store, envelope.id, envelope.version, { state: 'declined', updatedAt: iso })) {
      throw new ApprovalError('version_conflict', 'the envelope version has changed');
    }
    const version = envelope.version + 1;
    setRecipientProgress(store, recipient.id, { status: 'declined', updatedAt: iso });
    // Every other recipient who can no longer act is revoked, as on void.
    closeOpenRecipients(store, envelope.id, 'revoked', iso);
    revokeOutstandingCapabilities(store, envelope.id, iso);
    const actor = recipientActor(recipient.id);
    this.#audit.append(store.tenantId, {
      type: 'recipient.declined',
      actor,
      envelopeId: envelope.id,
      subjectDigest: envelope.manifestDigest,
      metadata: { recipient_id: recipient.id, recipient_ordinal: recipient.ordinal, envelope_version: version, reason: request.reason },
    });
    const revoked = capabilitiesRevokedAt(store, envelope.id, iso);
    const named = auditedRevocationsOf(store, envelope.id);
    const invitationIds = revoked.invitationIds.filter((id) => !named.has(id));
    const sessionIds = revoked.sessionIds.filter((id) => !named.has(id));
    if (invitationIds.length > 0 || sessionIds.length > 0) {
      this.#audit.append(store.tenantId, {
        type: 'recipient.capabilities_revoked',
        actor,
        envelopeId: envelope.id,
        subjectDigest: envelope.manifestDigest,
        metadata: { envelope_version: version, invitation_ids: invitationIds, session_ids: sessionIds },
      });
    }
    // The webhook announcement, in this transaction, exactly once.
    enqueueOutboxEvent(this.#db, store.tenantId, { type: 'envelope.declined', envelopeId: envelope.id, envelopeVersion: version }, { clock: () => now });
    return { status: 200, bytes: canonicalBytes(DECLINE_OUTCOME) };
  }
}
