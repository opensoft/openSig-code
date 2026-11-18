// SPDX-License-Identifier: Apache-2.0
//
// The envelope domain service (T007). Every mutation runs in one
// BEGIN IMMEDIATE transaction (Database.transaction), compares and sets the
// envelope version through the repository's single CAS path, and, when the
// caller passes an Idempotency-Key, records its result in the same
// transaction, so a retry with the same request replays the original status
// and bytes and makes no second mutation. A record keeps at most 256 KiB of
// response: a larger body fails the mutation (500 internal) and is never
// truncated. A record older than 24 hours is no longer a replay: it is
// deleted and the request runs as a new one (data-model.md § IdempotencyRecord).
//
// Version semantics (data-model.md § Transitions and races, item 1): create
// inserts draft at version 1; each successful operation that changes the
// envelope's state or content moves the version by exactly one; a refused
// request, a read, a send confirmation and an idempotent replay leave it.
//
// A read (read, preview) opens no transaction and takes no write lock
// (data-model.md § Persistence; A-010 READ-LOCK-ENV, ST-17).
//
// Order of checks in a mutation: idempotency replay or conflict, then the
// request's own rules, then the envelope's existence in the tenant, then
// expiry (a pre-reservation envelope whose expires_at has passed is expired
// and the request refused), then its state, then the expected version.

import { randomBytes } from 'node:crypto';

import { canonicalBytes, parseJson, type JsonValue } from '../../domain/canonical/index.ts';
import type { Database, TenantStore } from '../../storage/db/index.ts';
import {
  closeOpenRecipients,
  compareAndSetEnvelope,
  consumeSendConfirmation,
  copyRevision,
  freezeRevision,
  getEnvelope,
  getRevision,
  getSendConfirmation,
  insertEnvelope,
  insertField,
  insertManifest,
  insertRecipient,
  insertRevision,
  insertSendConfirmation,
  listRecipients,
  loadEnvelope,
  openConfirmation,
  revokeOutstandingCapabilities,
  setRecipientProgress,
  type EnvelopeAggregate,
  type EnvelopeChanges,
  type EnvelopeRecord,
  type SendConfirmationRecord,
} from '../../storage/repositories/envelopes.ts';
import {
  IDEMPOTENCY_KEY_PATTERN,
  IdempotencyBodyTooLarge,
  MAX_IDEMPOTENCY_BODY_BYTES,
  deleteIdempotencyRecord,
  findIdempotencyRecord,
  idempotencyRequestDigest,
  insertIdempotencyRecord,
  isIdempotencyRecordExpired,
  recordedResponse,
} from '../../storage/repositories/idempotency.ts';
import { EnvelopeError, invalid } from './errors.ts';
import { buildFieldManifest, FIELD_MANIFEST_SCHEMA, recipientsDigest } from './manifest.ts';
import { confirmationExpiry, confirmationProblems, confirmationRequired } from './send.ts';
import {
  APPROVING_STATES,
  PRE_RESERVATION_STATES,
  REISSUABLE_STATES,
  canTransition,
  stateAfterApproval,
  turnAfter,
  type EnvelopeState,
} from './states.ts';
import {
  DEFAULT_EXPIRY_MS,
  checkActor,
  checkCreate,
  checkDocument,
  checkExpectedVersion,
  checkFields,
  checkId,
  checkPrepare,
  checkSend,
  checkSendConfirmation,
  checkVersionOnly,
  checkVoid,
  type Actor,
} from './validation.ts';
import { envelopeView, previewView, sendConfirmationView } from './views.ts';

/** Idempotency routes: the contract's operationIds. */
export const ROUTES = Object.freeze({
  create: 'createEnvelope',
  upload: 'uploadDocument',
  prepare: 'prepareEnvelope',
  confirmSend: 'confirmSend',
  send: 'sendEnvelope',
  void: 'voidEnvelope',
  reissue: 'reissueEnvelope',
});

export type EnvelopeOperation =
  | 'create'
  | 'upload'
  | 'prepare'
  | 'confirm-send'
  | 'send'
  | 'void'
  | 'expire'
  | 'reissue'
  | 'reissued'
  | 'approval';

/** One successful change, reported inside its transaction (for audit events, invitations and the like). */
export interface EnvelopeChange {
  readonly operation: EnvelopeOperation;
  readonly tenantId: string;
  readonly envelopeId: string;
  readonly from: EnvelopeState | null;
  readonly to: EnvelopeState;
  readonly version: number;
  /** The operator principal, or null for a system change such as expiry. */
  readonly actor: Actor | null;
}

export interface EnvelopeServiceOptions {
  readonly db: Database;
  readonly clock: () => Date;
  readonly newId?: () => string;
  /**
   * Called inside the mutation's transaction after each successful change. A
   * throw rolls the whole mutation back.
   */
  readonly onChange?: (change: EnvelopeChange, store: TenantStore) => void;
  /**
   * The largest response body an idempotency record keeps, in bytes. It can
   * only lower the 256 KiB bound (MAX_IDEMPOTENCY_BODY_BYTES), never raise it.
   */
  readonly idempotencyBodyLimit?: number;
}

export interface OperatorRequest {
  readonly tenantId: string;
  readonly actor: Actor;
  /** The Idempotency-Key and the request as received, whose digest binds the key. */
  readonly idempotency?: { readonly key: string; readonly request: JsonValue };
}

export interface MutationResult {
  readonly status: number;
  readonly body: JsonValue;
  /** The exact response bytes (RFC 8785 form of body); a replay returns the stored bytes. */
  readonly bytes: Buffer;
  readonly replayed: boolean;
}

export interface ApprovalAdvance {
  readonly envelopeId: string;
  readonly expectedVersion: number;
  readonly recipientId: string;
  readonly approvalId: string;
}

export interface ApprovalOutcome {
  readonly state: EnvelopeState;
  readonly version: number;
  /** approvals_complete = true: the envelope is fully approved (finalizing), not completed. */
  readonly fullyApproved: boolean;
}

type Outcome =
  | { readonly kind: 'done'; readonly status: number; readonly body: JsonValue; readonly resourceId: string | null }
  | { readonly kind: 'refused'; readonly error: EnvelopeError };

type Settled =
  | { readonly kind: 'done' | 'replay'; readonly status: number; readonly bytes: Buffer }
  | { readonly kind: 'refused'; readonly error: EnvelopeError };

function defaultId(): string {
  return randomBytes(18).toString('base64url');
}

function done(status: number, body: JsonValue, resourceId: string | null): Outcome {
  return { kind: 'done', status, body, resourceId };
}

export class EnvelopeService {
  readonly #db: Database;
  readonly #clock: () => Date;
  readonly #newId: () => string;
  readonly #onChange: ((change: EnvelopeChange, store: TenantStore) => void) | undefined;
  readonly #bodyLimit: number;

  constructor(options: EnvelopeServiceOptions) {
    if (typeof options?.clock !== 'function') throw new TypeError('the envelope service needs an injected clock');
    const bodyLimit = options.idempotencyBodyLimit ?? MAX_IDEMPOTENCY_BODY_BYTES;
    if (!Number.isSafeInteger(bodyLimit) || bodyLimit < 2 || bodyLimit > MAX_IDEMPOTENCY_BODY_BYTES) {
      throw new TypeError(`the idempotency body limit must be an integer in 2..${MAX_IDEMPOTENCY_BODY_BYTES}`);
    }
    this.#db = options.db;
    this.#clock = options.clock;
    this.#newId = options.newId ?? defaultId;
    this.#onChange = options.onChange;
    this.#bodyLimit = bodyLimit;
    Object.freeze(this);
  }

  #now(): Date {
    const now = this.#clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('the envelope clock returned an invalid date');
    return now;
  }

  #id(): string {
    const id = this.#newId();
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{16,64}$/.test(id)) throw new TypeError('generated id is malformed');
    return id;
  }

  #changed(store: TenantStore, change: Omit<EnvelopeChange, 'tenantId'>): void {
    this.#onChange?.({ ...change, tenantId: store.tenantId }, store);
  }

  #load(store: TenantStore, envelopeId: string): EnvelopeRecord {
    const envelope = getEnvelope(store, envelopeId);
    if (envelope === undefined) throw new EnvelopeError('not_found', 'the envelope was not found');
    return envelope;
  }

  #aggregate(store: TenantStore, envelopeId: string): EnvelopeAggregate {
    const aggregate = loadEnvelope(store, envelopeId);
    if (aggregate === undefined) throw new EnvelopeError('not_found', 'the envelope was not found');
    return aggregate;
  }

  #view(store: TenantStore, envelopeId: string, now: Date): JsonValue {
    const aggregate = this.#aggregate(store, envelopeId);
    const open = openConfirmation(store, envelopeId, aggregate.envelope.version, now.toISOString());
    return envelopeView(aggregate, open?.authorizationReference ?? null);
  }

  #cas(store: TenantStore, envelope: EnvelopeRecord, changes: EnvelopeChanges): void {
    if (changes.state !== undefined && changes.state !== envelope.state && !canTransition(envelope.state, changes.state)) {
      throw new EnvelopeError('state_conflict', 'the envelope cannot make that transition');
    }
    if (!compareAndSetEnvelope(store, envelope.id, envelope.version, changes)) {
      throw new EnvelopeError('version_conflict', 'the envelope version has changed');
    }
  }

  /** Expire a pre-reservation envelope whose expires_at has passed (system change, same CAS path). */
  #expireNow(store: TenantStore, envelope: EnvelopeRecord, now: Date): void {
    const iso = now.toISOString();
    this.#cas(store, envelope, { state: 'expired', updatedAt: iso });
    closeOpenRecipients(store, envelope.id, 'expired', iso);
    revokeOutstandingCapabilities(store, envelope.id, iso);
    this.#changed(store, { operation: 'expire', envelopeId: envelope.id, from: envelope.state, to: 'expired', version: envelope.version + 1, actor: null });
  }

  /** When a request finds expires_at passed before reservation, expire the envelope and refuse the request. */
  #expiredRefusal(store: TenantStore, envelope: EnvelopeRecord, now: Date): Outcome | null {
    if (!PRE_RESERVATION_STATES.includes(envelope.state) || Date.parse(envelope.expiresAt) > now.getTime()) return null;
    this.#expireNow(store, envelope, now);
    return { kind: 'refused', error: new EnvelopeError('state_conflict', 'the envelope has expired') };
  }

  #expectState(envelope: EnvelopeRecord, states: readonly EnvelopeState[]): void {
    if (!states.includes(envelope.state)) throw new EnvelopeError('state_conflict', 'the envelope is not in a state that allows this operation');
  }

  #expectVersion(envelope: EnvelopeRecord, expected: number): void {
    if (envelope.version !== expected) throw new EnvelopeError('version_conflict', 'the envelope version has changed');
  }

  #requireHuman(actor: Actor): void {
    if (actor.kind !== 'human-operator') throw new EnvelopeError('forbidden', 'this operation needs a human operator');
  }

  #mutate(request: OperatorRequest, route: string, target: string | null, run: (store: TenantStore, now: Date) => Outcome): MutationResult {
    const actor = checkActor(request?.actor);
    const idempotency = request.idempotency;
    let digest: string | undefined;
    if (idempotency !== undefined) {
      if (typeof idempotency.key !== 'string' || !IDEMPOTENCY_KEY_PATTERN.test(idempotency.key)) throw invalid('Idempotency-Key', 'invalid_key');
      digest = idempotencyRequestDigest({ route, target, request: idempotency.request });
    }
    const now = this.#now();
    const settled = this.#db.transaction((): Settled => {
      const store = this.#db.forTenant(request.tenantId);
      if (idempotency !== undefined && digest !== undefined) {
        const existing = findIdempotencyRecord(store, route, actor.ref, idempotency.key);
        if (existing !== undefined && isIdempotencyRecordExpired(existing, now)) {
          // Past its 24 hours (purged or not), a record is no longer a replay.
          deleteIdempotencyRecord(store, existing);
        } else if (existing !== undefined) {
          if (existing.requestDigest !== digest || existing.principal.kind !== actor.kind) {
            throw new EnvelopeError('idempotency_conflict', 'the Idempotency-Key was used with a different request');
          }
          const response = recordedResponse(existing);
          // Envelope responses carry no one-time secret, so their records always keep the body.
          if (response.kind !== 'body') throw new EnvelopeError('internal', 'the idempotency record holds no response body');
          return { kind: 'replay', status: existing.responseStatus, bytes: response.bytes };
        }
      }
      const outcome = run(store, now);
      if (outcome.kind === 'refused') return outcome;
      if (idempotency === undefined || digest === undefined) return { kind: 'done', status: outcome.status, bytes: canonicalBytes(outcome.body) };
      let bytes: Buffer | null;
      try {
        bytes = insertIdempotencyRecord(
          store,
          {
            route,
            principal: actor,
            key: idempotency.key,
            requestDigest: digest,
            responseStatus: outcome.status,
            response: { kind: 'body', body: outcome.body },
            resourceId: outcome.resourceId,
            createdAt: now.toISOString(),
          },
          this.#bodyLimit,
        );
      } catch (error) {
        // Thrown inside the transaction: the whole mutation rolls back; the body is never truncated.
        if (error instanceof IdempotencyBodyTooLarge) throw new EnvelopeError('internal', 'the response exceeds the idempotency record limit');
        throw error;
      }
      if (bytes === null) throw new EnvelopeError('internal', 'the idempotency record kept no response body');
      return { kind: 'done', status: outcome.status, bytes };
    });
    if (settled.kind === 'refused') throw settled.error;
    return { status: settled.status, body: parseJson(settled.bytes.toString('utf8')), bytes: settled.bytes, replayed: settled.kind === 'replay' };
  }

  /**
   * A read path opens no transaction, so it takes no write lock: node:sqlite is
   * synchronous, and a read waiting for the lock would stall the whole process
   * for up to the busy timeout (data-model.md § Persistence; A-010
   * READ-LOCK-ENV, request #30). Its statements cannot interleave with this
   * process's own writes, which all run synchronously, and every mutation
   * re-checks state, version and digests under the write lock. The store
   * refuses any write outside a transaction, so a read can never write.
   */
  #read<T>(request: { readonly tenantId: string; readonly actor: Actor }, fn: (store: TenantStore, now: Date) => T): T {
    checkActor(request?.actor);
    const now = this.#now();
    return fn(this.#db.forTenant(request.tenantId), now);
  }

  /** createEnvelope: a draft at version 1 with its recipients (ordinals 1, or 1 and 2). */
  create(request: OperatorRequest, input: unknown): MutationResult {
    return this.#mutate(request, ROUTES.create, null, (store, now) => {
      const checked = checkCreate(input, now);
      const iso = now.toISOString();
      const id = this.#id();
      insertEnvelope(store, {
        id,
        source: checked.source,
        createdBy: request.actor,
        expiresAt: checked.expiresAt,
        recipientsCount: checked.recipients.length,
        reissueOf: null,
        now: iso,
      });
      for (const recipient of checked.recipients) {
        insertRecipient(store, { id: this.#id(), envelopeId: id, ordinal: recipient.ordinal, email: recipient.email, role: recipient.role, now: iso });
      }
      this.#changed(store, { operation: 'create', envelopeId: id, from: null, to: 'draft', version: 1, actor: request.actor });
      return done(201, this.#view(store, id, now), id);
    });
  }

  /** readEnvelope: the operator view; a read never changes the version. */
  read(request: { readonly tenantId: string; readonly actor: Actor }, envelopeId: string): JsonValue {
    checkId(envelopeId);
    return this.#read(request, (store, now) => this.#view(store, envelopeId, now));
  }

  /** readRecipientPreview: what a human confirms before sending; prepared envelopes only. */
  preview(request: { readonly tenantId: string; readonly actor: Actor }, envelopeId: string): JsonValue {
    checkId(envelopeId);
    return this.#read(request, (store) => {
      const aggregate = this.#aggregate(store, envelopeId);
      this.#expectState(aggregate.envelope, ['prepared']);
      return previewView(aggregate, request.actor);
    });
  }

  /** uploadDocument (If-Match): record the parse service's accepted document while in draft; version + 1. */
  uploadDocument(request: OperatorRequest, envelopeId: string, expectedVersion: number, document: unknown): MutationResult {
    return this.#mutate(request, ROUTES.upload, envelopeId, (store, now) => {
      checkId(envelopeId);
      const expected = checkExpectedVersion(expectedVersion);
      const checked = checkDocument(document);
      const envelope = this.#load(store, envelopeId);
      const refusal = this.#expiredRefusal(store, envelope, now);
      if (refusal !== null) return refusal;
      this.#expectState(envelope, ['draft']);
      this.#expectVersion(envelope, expected);
      const iso = now.toISOString();
      const revisionId = this.#id();
      insertRevision(store, revisionId, envelopeId, checked, iso);
      this.#cas(store, envelope, { baseRevisionId: revisionId, updatedAt: iso });
      this.#changed(store, { operation: 'upload', envelopeId, from: 'draft', to: 'draft', version: envelope.version + 1, actor: request.actor });
      return done(200, this.#view(store, envelopeId, now), envelopeId);
    });
  }

  /**
   * prepareEnvelope: validate the fields against the document and recipients,
   * then freeze the revision, the field definitions, the field manifest and the
   * recipients digest; state prepared, version + 1.
   */
  prepare(request: OperatorRequest, envelopeId: string, input: unknown): MutationResult {
    return this.#mutate(request, ROUTES.prepare, envelopeId, (store, now) => {
      checkId(envelopeId);
      const checked = checkPrepare(input);
      const envelope = this.#load(store, envelopeId);
      const refusal = this.#expiredRefusal(store, envelope, now);
      if (refusal !== null) return refusal;
      this.#expectState(envelope, ['draft']);
      this.#expectVersion(envelope, checked.expectedVersion);
      if (envelope.baseRevisionId === null) throw new EnvelopeError('state_conflict', 'the envelope has no document to prepare');
      const revision = getRevision(store, envelopeId, envelope.baseRevisionId);
      if (revision === undefined) throw new EnvelopeError('internal', 'the envelope document revision is missing');
      const recipients = listRecipients(store, envelopeId);
      const fields = checkFields(checked.fields, { recipientsCount: envelope.recipientsCount, pageCount: revision.pages.length });
      const recipientIds = new Map(recipients.map((recipient) => [recipient.ordinal, recipient.id]));
      const iso = now.toISOString();
      const manifestFields = fields.map((field) => {
        const recipientId = recipientIds.get(field.recipient_ordinal);
        if (recipientId === undefined) throw new EnvelopeError('internal', 'a declared recipient is missing');
        return { key: field.key, recipient_id: recipientId, recipient_ordinal: field.recipient_ordinal, page: field.page, type: field.type, rect: field.rect };
      });
      for (const field of manifestFields) {
        insertField(store, envelopeId, revision.id, { key: field.key, recipientId: field.recipient_id, recipientOrdinal: field.recipient_ordinal, page: field.page, type: field.type, rect: field.rect }, iso);
      }
      const frozen = buildFieldManifest(envelopeId, revision.contentDigest, manifestFields);
      insertManifest(store, envelopeId, { revisionId: revision.id, schema: FIELD_MANIFEST_SCHEMA, digest: frozen.digest, bytes: frozen.bytes }, iso);
      freezeRevision(store, envelopeId, revision.id, iso);
      this.#cas(store, envelope, { state: 'prepared', manifestDigest: frozen.digest, recipientsDigest: recipientsDigest(recipients), updatedAt: iso });
      this.#changed(store, { operation: 'prepare', envelopeId, from: 'draft', to: 'prepared', version: envelope.version + 1, actor: request.actor });
      return done(200, this.#view(store, envelopeId, now), envelopeId);
    });
  }

  /**
   * confirmSend: a human operator confirms the current preview digests and
   * gets a single-use authorization_reference bound to this envelope version.
   * The envelope's state and content do not change, so neither does its version.
   */
  confirmSend(request: OperatorRequest, envelopeId: string, input: unknown): MutationResult {
    this.#requireHuman(checkActor(request?.actor));
    return this.#mutate(request, ROUTES.confirmSend, envelopeId, (store, now) => {
      checkId(envelopeId);
      const checked = checkSendConfirmation(input);
      const envelope = this.#load(store, envelopeId);
      const refusal = this.#expiredRefusal(store, envelope, now);
      if (refusal !== null) return refusal;
      this.#expectState(envelope, ['prepared']);
      this.#expectVersion(envelope, checked.expectedVersion);
      const aggregate = this.#aggregate(store, envelopeId);
      const documentDigest = aggregate.revision?.contentDigest;
      if (
        checked.documentDigest !== documentDigest ||
        checked.manifestDigest !== envelope.manifestDigest ||
        checked.recipientsDigest !== envelope.recipientsDigest ||
        envelope.manifestDigest === null ||
        envelope.recipientsDigest === null
      ) {
        throw new EnvelopeError('digest_mismatch', 'the confirmed digests are not the current preview');
      }
      const confirmation: Omit<SendConfirmationRecord, 'consumedAt'> = {
        authorizationReference: this.#id(),
        envelopeId,
        envelopeVersion: envelope.version,
        documentDigest: checked.documentDigest,
        manifestDigest: envelope.manifestDigest,
        recipientsDigest: envelope.recipientsDigest,
        confirmedBy: request.actor,
        confirmedAt: now.toISOString(),
        expiresAt: confirmationExpiry(now, envelope.expiresAt),
      };
      insertSendConfirmation(store, confirmation);
      this.#changed(store, { operation: 'confirm-send', envelopeId, from: 'prepared', to: 'prepared', version: envelope.version, actor: request.actor });
      return done(201, sendConfirmationView({ ...confirmation, consumedAt: null }), confirmation.authorizationReference);
    });
  }

  /**
   * sendEnvelope: prepared -> sent, recipient 1 invited, version + 1. A
   * service-created envelope, or any send by a service principal, needs a
   * valid SendConfirmation, which this send consumes; any reference presented
   * is checked and consumed the same way.
   */
  send(request: OperatorRequest, envelopeId: string, input: unknown): MutationResult {
    return this.#mutate(request, ROUTES.send, envelopeId, (store, now) => {
      checkId(envelopeId);
      const checked = checkSend(input);
      const envelope = this.#load(store, envelopeId);
      const refusal = this.#expiredRefusal(store, envelope, now);
      if (refusal !== null) return refusal;
      this.#expectState(envelope, ['prepared']);
      this.#expectVersion(envelope, checked.expectedVersion);
      const aggregate = this.#aggregate(store, envelopeId);
      const iso = now.toISOString();
      if (confirmationRequired(envelope.createdBy, request.actor) && checked.authorizationReference === undefined) {
        throw new EnvelopeError('confirmation_required', 'a human operator must confirm this send');
      }
      if (checked.authorizationReference !== undefined) {
        const confirmation = getSendConfirmation(store, checked.authorizationReference);
        const target = {
          envelopeId,
          version: envelope.version,
          documentDigest: aggregate.revision?.contentDigest ?? '',
          manifestDigest: envelope.manifestDigest ?? '',
          recipientsDigest: envelope.recipientsDigest ?? '',
        };
        if (confirmation === undefined || confirmationProblems(confirmation, target, now).length > 0) {
          throw new EnvelopeError('confirmation_invalid', 'the send confirmation is not valid for this send');
        }
        if (!consumeSendConfirmation(store, checked.authorizationReference, iso)) {
          throw new EnvelopeError('confirmation_invalid', 'the send confirmation is not valid for this send');
        }
      }
      const first = aggregate.recipients.find((recipient) => recipient.ordinal === 1);
      if (first === undefined) throw new EnvelopeError('internal', 'the first recipient is missing');
      this.#cas(store, envelope, { state: 'sent', updatedAt: iso });
      setRecipientProgress(store, first.id, { status: 'invited', invitedAt: iso, updatedAt: iso });
      this.#changed(store, { operation: 'send', envelopeId, from: 'prepared', to: 'sent', version: envelope.version + 1, actor: request.actor });
      return done(200, this.#view(store, envelopeId, now), envelopeId);
    });
  }

  /** voidEnvelope (human operators only): before the reservation; recipients and capabilities revoked; version + 1. */
  void(request: OperatorRequest, envelopeId: string, input: unknown): MutationResult {
    this.#requireHuman(checkActor(request?.actor));
    return this.#mutate(request, ROUTES.void, envelopeId, (store, now) => {
      checkId(envelopeId);
      const checked = checkVoid(input);
      const envelope = this.#load(store, envelopeId);
      this.#expectState(envelope, PRE_RESERVATION_STATES);
      const refusal = this.#expiredRefusal(store, envelope, now);
      if (refusal !== null) return refusal;
      this.#expectVersion(envelope, checked.expectedVersion);
      const iso = now.toISOString();
      this.#cas(store, envelope, { state: 'voided', updatedAt: iso });
      closeOpenRecipients(store, envelopeId, 'revoked', iso);
      revokeOutstandingCapabilities(store, envelopeId, iso);
      this.#changed(store, { operation: 'void', envelopeId, from: envelope.state, to: 'voided', version: envelope.version + 1, actor: request.actor });
      return done(200, this.#view(store, envelopeId, now), envelopeId);
    });
  }

  /**
   * reissueEnvelope (human operators only): from declined, expired or voided,
   * insert a new draft at version 1 linked by reissue_of, with the source and
   * recipients copied (never approvals). A document of the prior envelope is
   * copied as a new revision and attached as an upload would be (version + 1).
   * The prior envelope records reissued_as (version + 1) and loses every
   * outstanding capability.
   */
  reissue(request: OperatorRequest, envelopeId: string, input: unknown): MutationResult {
    this.#requireHuman(checkActor(request?.actor));
    return this.#mutate(request, ROUTES.reissue, envelopeId, (store, now) => {
      checkId(envelopeId);
      const checked = checkVersionOnly(input);
      const prior = this.#load(store, envelopeId);
      this.#expectState(prior, REISSUABLE_STATES);
      this.#expectVersion(prior, checked.expectedVersion);
      if (prior.reissuedAs !== null) throw new EnvelopeError('state_conflict', 'the envelope was already reissued');
      const aggregate = this.#aggregate(store, envelopeId);
      const iso = now.toISOString();
      const id = this.#id();
      insertEnvelope(store, {
        id,
        source: prior.source,
        createdBy: request.actor,
        expiresAt: new Date(now.getTime() + DEFAULT_EXPIRY_MS).toISOString(),
        recipientsCount: prior.recipientsCount,
        reissueOf: prior.id,
        now: iso,
      });
      for (const recipient of aggregate.recipients) {
        insertRecipient(store, { id: this.#id(), envelopeId: id, ordinal: recipient.ordinal, email: recipient.email, role: recipient.role, now: iso });
      }
      let version = 1;
      if (aggregate.revision !== null) {
        const revisionId = this.#id();
        copyRevision(store, aggregate.revision, revisionId, id, iso);
        const draft = this.#load(store, id);
        this.#cas(store, draft, { baseRevisionId: revisionId, updatedAt: iso });
        version = 2;
      }
      this.#changed(store, { operation: 'reissue', envelopeId: id, from: null, to: 'draft', version, actor: request.actor });
      this.#cas(store, prior, { reissuedAs: id, updatedAt: iso });
      closeOpenRecipients(store, prior.id, 'revoked', iso);
      revokeOutstandingCapabilities(store, prior.id, iso);
      this.#changed(store, { operation: 'reissued', envelopeId: prior.id, from: prior.state, to: prior.state, version: prior.version + 1, actor: request.actor });
      return done(201, this.#view(store, id, now), id);
    });
  }

  /**
   * The expiry sweeper's step (T010 schedules it): expire the envelope if it is
   * before reservation and its expires_at has passed. Returns whether it did.
   */
  expireIfDue(tenantId: string, envelopeId: string): boolean {
    checkId(envelopeId);
    const now = this.#now();
    return this.#db.transaction(() => {
      const store = this.#db.forTenant(tenantId);
      const envelope = this.#load(store, envelopeId);
      if (!PRE_RESERVATION_STATES.includes(envelope.state) || Date.parse(envelope.expiresAt) > now.getTime()) return false;
      this.#expireNow(store, envelope, now);
      return true;
    });
  }

  /**
   * The state machine's approval step, inside the caller's transaction, after
   * the caller (T010) has inserted the recipient's Approval. Only the recipient
   * whose turn it is, still invited, may advance the envelope:
   * - one recipient: sent -> finalizing, approvals_complete = true;
   * - two recipients: the first approval sent -> in-progress (recipient 2
   *   invited), the second in-progress -> finalizing, approvals_complete = true.
   * Fully approved is never completed: completion is T038's publish.
   */
  advanceOnApproval(store: TenantStore, input: ApprovalAdvance): ApprovalOutcome {
    checkId(input.envelopeId);
    checkId(input.recipientId, 'recipient_id');
    checkId(input.approvalId, 'approval_id');
    const expected = checkExpectedVersion(input.expectedVersion);
    const now = this.#now();
    const envelope = this.#load(store, input.envelopeId);
    this.#expectState(envelope, APPROVING_STATES);
    if (Date.parse(envelope.expiresAt) <= now.getTime()) throw new EnvelopeError('state_conflict', 'the envelope has expired');
    this.#expectVersion(envelope, expected);
    const recipients = listRecipients(store, envelope.id);
    const recipient = recipients.find((entry) => entry.id === input.recipientId);
    if (recipient === undefined) throw new EnvelopeError('not_found', 'the recipient was not found');
    const turn = turnAfter(
      recipients.filter((entry) => entry.status === 'approved').map((entry) => entry.ordinal),
      envelope.recipientsCount,
    );
    if (recipient.ordinal !== turn || recipient.status !== 'invited') {
      throw new EnvelopeError('order_conflict', 'it is not this recipient’s turn');
    }
    const next = stateAfterApproval(envelope.recipientsCount, recipient.ordinal);
    const iso = now.toISOString();
    setRecipientProgress(store, recipient.id, { status: 'approved', approvedAt: iso, approvalId: input.approvalId, updatedAt: iso });
    this.#cas(store, envelope, next === 'finalizing' ? { state: next, approvalsComplete: true, updatedAt: iso } : { state: next, updatedAt: iso });
    if (next === 'in-progress') {
      const following = recipients.find((entry) => entry.ordinal === recipient.ordinal + 1);
      if (following === undefined) throw new EnvelopeError('internal', 'the next recipient is missing');
      setRecipientProgress(store, following.id, { status: 'invited', invitedAt: iso, updatedAt: iso });
    }
    this.#changed(store, { operation: 'approval', envelopeId: envelope.id, from: envelope.state, to: next, version: envelope.version + 1, actor: null });
    return { state: next, version: envelope.version + 1, fullyApproved: next === 'finalizing' };
  }
}
