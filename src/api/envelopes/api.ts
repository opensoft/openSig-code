// SPDX-License-Identifier: Apache-2.0
//
// The operator envelope API (T034): what each operator envelope route does once the server
// (src/server/app.ts, T031) has authenticated and authorized the request and handlers.ts has
// read its path parameters, headers and body. Contract: contracts/http-api.json, operations
// createEnvelope, readEnvelope, uploadDocument, prepareEnvelope, readRecipientPreview,
// confirmSend, sendEnvelope, voidEnvelope, reissueEnvelope and resendInvitation; behaviour:
// contracts/sessions-events-adapters.md § Operator mutation behavior and § Sending and human
// confirmation; data-model.md § Envelope states and § Transitions and races.
//
// Composition. One EnvelopeApi per process, stored in the server locals under ENVELOPE_API
// (production wiring is T031's US1 composition slot, row WIRE-US1). It mutates through its
// own T007 EnvelopeService, whose onChange is the T008 ceremony's onEnvelopeChange, so a send
// issues recipient 1's invitation inside the send's transaction and a void or reissue records
// what it revoked. Every mutation runs inside RecipientCeremony.capture(), and the captured
// invitations are mailed through the T032 notifier only after the transaction commits
// (deliver()). The HTTP response never carries a link, token or code: invitations reach the
// recipient by mail only.
//
// Expiry announcement (A-010 row EXPIRED-EVT, request #26; test EA-06). An operator request
// that finds a pre-reservation envelope past its expires_at expires it and is refused (409
// state_conflict): prepare, confirmSend, send and void through the domain's refusal path, and
// uploadDocument through expireIfDue in its pre-parse check (below). Both run in the same
// EnvelopeService, whose onChange is therefore T010's expiryAnnouncer wrapped around the
// ceremony's listener, composed once, here, so every such expiry writes exactly one
// envelope.expired outbox event in its own transaction (the announcer runs inside the
// change's transaction, after the compare-and-set), and no other change writes one. resendInvitation commits no expiry: it refuses an envelope past its
// expires_at (409 state_conflict) and writes nothing.
//
// Overdue uploads (A-010 row UPLOAD-OVERDUE, request #27). uploadDocument's pre-parse target
// check applies the domain's order (existence, expiry, state, version), so an upload to a
// pre-reservation envelope past its expires_at expires it through T007's expiry path
// (EnvelopeService.expireIfDue: the one compare-and-set path, its own transaction, with the
// composed announcer writing the single envelope.expired) and is refused with 409
// state_conflict before any body byte is read, before an upload slot is taken and before any
// parse. The unread body is handled as every other early answer's: the server answers with
// Connection: close and closes the connection with its lingering close (T031).
//
// Tenancy. Every read and write goes through the store of the principal's tenant, so an
// envelope of another tenant is exactly as absent as one that never existed: the same 404
// not_found, with the same body and headers (SC002-07, SC002-08, SC002-26).
//
// Idempotency (EA-02, SC002-23). Every mutation passes its Idempotency-Key and its request
// (the JSON body as received; for an upload, the If-Match version and the digest and length
// of the PDF bytes) to the domain, which records the response in the mutation's own
// transaction. The same key with the same request replays the stored status and the exact
// stored bytes, with no second mutation, version change, audit event or mail, also after the
// envelope has moved on; a changed request is 409 idempotency_conflict. resendInvitation has
// no domain mutation of its own, so its record is kept here in the same way, in the resend's
// transaction. Responses are sent as the exact bytes the record keeps.
//
// Key before body (A-010 T034R-RESEND, requests #23 and #25). In every idempotent T034
// handler an existing key is resolved before the body is validated, as request #16 ruled for
// uploads. Authentication, the role matrix and the human-only check come first; then the
// framing answers of the body (415 media type, 413 size, 408 body timeout) and upload's
// If-Match precondition (428/400), which keep their own answers because a 409 needs a
// complete, comparable body; then the key. A complete body that is not a JSON value (bad
// syntax or UTF-8, or no canonical form) under a key this principal has already used on the
// route is a changed payload: 409 idempotency_conflict, never 400 (hasLiveRecord(), judged
// once, at arrival, as request #19 ruled for uploads). A body the client aborted was never
// compared: it keeps T031's abort answer, never 409. A JSON body is digested and resolved
// against the record (replay, or 409) before its own rules run: the domain does this for
// create, prepare, confirmSend, send, void and reissue, and resend() does it here. None of the
// refusals before the comparison writes a record or a mutation.
//
// Upload replays (A-010, request #16). An upload whose Idempotency-Key already has a live
// record of this principal is resolved before any parse: its body is read only for its SHA-256
// and length, within the tenant's upload slot and the parse service's own size limit, and is
// never kept or parsed. The same request (If-Match version, envelope, digest and length)
// replays the stored status and bytes; any other is 409 idempotency_conflict, whatever the
// PDF's validity. Only a new key reaches the parse service, so a replay moves none of its
// admission tickets or body-read permits.
//
// Uploads (A-010 LBR4-1, EA-01; A-009 LBR-3). uploadDocument checks its headers and media type
// first, then (for a new key) that the envelope exists in the tenant, is a draft and is at
// the If-Match version, so a refused upload never reaches the parse service.
// It then takes one of the tenant's upload slots (uploads.ts) and streams the request body
// into parsePdf(), with no options: no caller-supplied value ever reaches the parse service.
// The bytes the service reads are kept as they pass, checked against the service's digest
// and length, stored in the tenant's content-addressed blob store and recorded through the
// domain (version + 1). On a client abort or a body timeout, parsePdf() rejects instead of
// returning an outcome: nothing was parsed or stored, the error is the body's own (400, or
// the server's 408), never a 500, and the slot is released on every path.
//
// Send confirmation (SC002-24). A send needs a valid SendConfirmation when the envelope is
// service-created or the sender is a service (A-010); the domain decides it per send.
// confirmSend, void, reissue and resendInvitation are human-only: the role matrix keeps
// service principals out, and this module checks the principal kind again (403).
//
// Resend actor (EA-05, row T008FU-D8). resendInvitation passes the authenticated operator to
// RecipientCeremony.resendInvitation(), so its recipient.capabilities_revoked and
// recipient.invited audit events name that operator, never the system.

import { createHash } from 'node:crypto';

import type { JsonValue } from '../../domain/canonical/index.ts';
import { expiryAnnouncer } from '../../domain/approval/index.ts';
import {
  APPROVING_STATES,
  EnvelopeService,
  PRE_RESERVATION_STATES,
  ROUTES as IDEMPOTENCY_ROUTES,
  type DocumentInput,
  type MutationResult,
  type OperatorRequest,
} from '../../domain/envelopes/index.ts';
import { checkVersionOnly } from '../../domain/envelopes/validation.ts';
import { DEFAULT_PARSER_LIMITS } from '../../pdf/limits.ts';
import { parsePdf, type ParseOutcome, type ServiceReport } from '../../pdf/service.ts';
import type { Logger } from '../../server/redact.ts';
import { HttpError, type HandlerResult } from '../../server/types.ts';
import type { BlobStore } from '../../storage/blobs/index.ts';
import type { Database } from '../../storage/db/index.ts';
import { getEnvelope, listRecipients } from '../../storage/repositories/envelopes.ts';
import {
  deleteIdempotencyRecord,
  findIdempotencyRecord,
  idempotencyRequestDigest,
  insertIdempotencyRecord,
  isIdempotencyRecordExpired,
  recordedResponse,
} from '../../storage/repositories/idempotency.ts';
import type { OperatorPrincipal } from '../auth/operator.ts';
import { RecipientCeremony } from '../recipients/ceremony.ts';
import { actorOf, bytesResult, httpErrorOf, requireHuman } from './request.ts';
import { acquireUploadSlot } from './uploads.ts';

/** The server locals key of the app's EnvelopeApi. */
export const ENVELOPE_API = 'opensig.envelope-api';

/** The idempotency route of resendInvitation (the contract operationId, like the domain's routes). */
export const RESEND_ROUTE = 'resendInvitation';

/** resendInvitation's generic outcome (contract Accepted). */
const ACCEPTED: JsonValue = Object.freeze({ status: 'accepted' });

const RETRY_AFTER = Object.freeze({ 'retry-after': '1' });

export interface EnvelopeApiOptions {
  readonly db: Database;
  /** The tenant-namespaced, content-addressed blob store that keeps the uploaded documents. */
  readonly blobs: BlobStore;
  /** The recipient ceremony (T008): invitations on send, resend and revocation records. */
  readonly ceremony: RecipientCeremony;
  readonly clock: () => Date;
}

export interface UploadRequest {
  readonly principal: OperatorPrincipal;
  readonly envelopeId: string;
  readonly key: string;
  readonly expectedVersion: number;
  /** The request body (application/pdf), not yet read. */
  readonly body: AsyncIterable<Uint8Array>;
  readonly logger: Logger;
}

/** The bytes a streamed upload carried, kept as the parse service reads them. */
interface Received {
  readonly chunks: Buffer[];
  length: number;
  /** Set when reading the body failed (client abort, body timeout, streaming cap). */
  failure: { readonly error: unknown } | null;
}

/** Pass `source` through to the parse service, keeping each chunk and any read failure in `into`. */
function receive(source: AsyncIterable<Uint8Array>, into: Received): AsyncIterable<Uint8Array> {
  return (async function* received(): AsyncGenerator<Uint8Array> {
    try {
      for await (const chunk of source) {
        const buffer = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
        into.chunks.push(buffer);
        into.length += buffer.length;
        yield chunk;
      }
    } catch (error) {
      into.failure = { error };
      throw error;
    }
  })();
}

/** A body that failed while it was read: its own error (400, 408, 413), never a 500. */
function bodyFailure(error: unknown): HttpError {
  return error instanceof HttpError ? error : new HttpError(400, 'invalid_request');
}

/** What a live idempotency record of the upload route keeps, read before any body byte. */
interface RecordedUpload {
  readonly requestDigest: string;
  readonly principalKind: string;
  readonly status: number;
  readonly bytes: Buffer;
}

/**
 * The idempotency request of an upload, the same for a new key (from the parse report) and a
 * recorded one (from the body's own digest): the If-Match version and the digest and length
 * of the PDF bytes. The domain digests it with the route and the envelope (the target).
 */
function uploadIdempotencyRequest(expectedVersion: number, digest: string, length: number): JsonValue {
  return { expected_version: expectedVersion, document_digest: digest, document_bytes: length };
}

/**
 * Read `source` to its end within `maxBytes`, keeping only its SHA-256 and its length: no byte
 * is kept and nothing is parsed (request #16). A body over the limit is 413 payload_too_large;
 * a failing body is its own error (400, or the server's 408 or 413), never a 500.
 */
async function digestBody(source: AsyncIterable<Uint8Array>, maxBytes: number): Promise<{ readonly digest: string; readonly length: number }> {
  const hash = createHash('sha256');
  let length = 0;
  try {
    for await (const chunk of source) {
      length += chunk.byteLength;
      if (length > maxBytes) throw new HttpError(413, 'payload_too_large');
      hash.update(chunk);
    }
  } catch (error) {
    throw bodyFailure(error);
  }
  return { digest: hash.digest('hex'), length };
}

/** A parse service refusal as the contract Error. Details carry the reason code, never document text. */
function parseRefusal(outcome: Extract<ParseOutcome, { ok: false }>): HttpError {
  switch (outcome.status) {
    case 413:
      return new HttpError(413, 'payload_too_large');
    case 422:
      // A differing effective CropBox has its own detail code (contract Unprocessable, A-008 S2).
      return new HttpError(422, 'unsupported_pdf', { details: [{ field: 'document', code: outcome.detail === 'cropbox_differs' ? 'cropbox_differs' : outcome.reason }] });
    case 429:
      return new HttpError(429, 'rate_limited', { details: [{ field: 'document', code: outcome.reason }], headers: { ...RETRY_AFTER } });
    default:
      return new HttpError(500, 'internal');
  }
}

/** What the domain records for an accepted document: digest, size, displayed geometry and a bounded parse summary. */
function documentInput(report: ServiceReport): DocumentInput {
  return {
    digest: report.digest,
    bytes: report.bytes,
    pages: report.pages.map((page) => ({ number: page.number, width: page.width, height: page.height, rotate: page.rotate })),
    parseReport: {
      schema: report.schema,
      header_version: report.header_version,
      bytes: report.bytes,
      digest: report.digest,
      pages: report.pages.map((page) => ({
        number: page.number,
        width: page.width,
        height: page.height,
        rotate: page.rotate,
        media_box: [...page.media_box],
        crop_box: [...page.crop_box],
      })),
      xref: { kind: report.xref.kind, sections: report.xref.sections, hybrid: report.xref.hybrid },
      features: [...report.features],
      stats: { objects: report.stats.objects, object_streams: report.stats.object_streams, max_depth: report.stats.max_depth, inflated_bytes: report.stats.inflated_bytes },
      network_sandbox: report.network_sandbox,
    },
  };
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export class EnvelopeApi {
  readonly #db: Database;
  readonly #blobs: BlobStore;
  readonly #ceremony: RecipientCeremony;
  readonly #clock: () => Date;
  readonly #envelopes: EnvelopeService;

  constructor(options: EnvelopeApiOptions) {
    if (typeof options?.clock !== 'function') throw new TypeError('the envelope API needs an injected clock');
    if (!(options.ceremony instanceof RecipientCeremony)) throw new TypeError('the envelope API needs the recipient ceremony');
    if (typeof options.blobs?.put !== 'function') throw new TypeError('the envelope API needs the blob store');
    if (typeof options.db?.transaction !== 'function' || typeof options.db.forTenant !== 'function') throw new TypeError('the envelope API needs the database');
    this.#db = options.db;
    this.#blobs = options.blobs;
    this.#ceremony = options.ceremony;
    this.#clock = options.clock;
    // The one composition point of the expiry announcement (EXPIRED-EVT): every EnvelopeApi
    // mutation goes through this service, so every expiry it commits is announced once.
    this.#envelopes = new EnvelopeService({ db: options.db, clock: options.clock, onChange: expiryAnnouncer(options.db, options.clock, options.ceremony.onEnvelopeChange) });
    Object.freeze(this);
  }

  #now(): Date {
    const now = this.#clock();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('the envelope API clock returned an invalid date');
    return now;
  }

  #operator(principal: OperatorPrincipal, key: string, request: JsonValue): OperatorRequest {
    return { tenantId: principal.tenant_id, actor: actorOf(principal), idempotency: { key, request } };
  }

  /** Run one synchronous mutation inside the ceremony's capture, then mail what it issued. */
  async #mutate(run: () => { readonly status: number; readonly bytes: Uint8Array }): Promise<HandlerResult> {
    let captured: { readonly value: { readonly status: number; readonly bytes: Uint8Array }; readonly mails: Parameters<RecipientCeremony['deliver']>[0] };
    try {
      captured = this.#ceremony.capture(run);
    } catch (error) {
      throw httpErrorOf(error);
    }
    if (captured.mails.length > 0) await this.#ceremony.deliver(captured.mails);
    return bytesResult(captured.value.status, captured.value.bytes);
  }

  /** createEnvelope: a draft at version 1 with its recipients (201 Envelope). */
  create(principal: OperatorPrincipal, key: string, body: JsonValue): Promise<HandlerResult> {
    return this.#mutate((): MutationResult => this.#envelopes.create(this.#operator(principal, key, body), body));
  }

  /** readEnvelope: the operator view (200 Envelope); never changes the version. */
  read(principal: OperatorPrincipal, envelopeId: string): HandlerResult {
    try {
      return { status: 200, json: this.#envelopes.read({ tenantId: principal.tenant_id, actor: actorOf(principal) }, envelopeId) };
    } catch (error) {
      throw httpErrorOf(error);
    }
  }

  /** readRecipientPreview: what a human confirms before sending; prepared envelopes only (200 RecipientPreview). */
  preview(principal: OperatorPrincipal, envelopeId: string): HandlerResult {
    try {
      return { status: 200, json: this.#envelopes.preview({ tenantId: principal.tenant_id, actor: actorOf(principal) }, envelopeId) };
    } catch (error) {
      throw httpErrorOf(error);
    }
  }

  /** prepareEnvelope: validate the fields and freeze the document and field manifest (200 Envelope, version + 1). */
  prepare(principal: OperatorPrincipal, envelopeId: string, key: string, body: JsonValue): Promise<HandlerResult> {
    return this.#mutate((): MutationResult => this.#envelopes.prepare(this.#operator(principal, key, body), envelopeId, body));
  }

  /** confirmSend (human operators only): a single-use authorization_reference for the current preview (201 SendConfirmation). */
  async confirmSend(principal: OperatorPrincipal, envelopeId: string, key: string, body: JsonValue): Promise<HandlerResult> {
    requireHuman(principal);
    return this.#mutate((): MutationResult => this.#envelopes.confirmSend(this.#operator(principal, key, body), envelopeId, body));
  }

  /** sendEnvelope: prepared -> sent; recipient 1's invitation is mailed after the commit, never returned (200 Envelope). */
  send(principal: OperatorPrincipal, envelopeId: string, key: string, body: JsonValue): Promise<HandlerResult> {
    return this.#mutate((): MutationResult => this.#envelopes.send(this.#operator(principal, key, body), envelopeId, body));
  }

  /** voidEnvelope (human operators only): before the reservation; capabilities revoked (200 Envelope). */
  async void(principal: OperatorPrincipal, envelopeId: string, key: string, body: JsonValue): Promise<HandlerResult> {
    requireHuman(principal);
    return this.#mutate((): MutationResult => this.#envelopes.void(this.#operator(principal, key, body), envelopeId, body));
  }

  /** reissueEnvelope (human operators only): a new linked draft from a declined, expired or voided envelope (201 Envelope). */
  async reissue(principal: OperatorPrincipal, envelopeId: string, key: string, body: JsonValue): Promise<HandlerResult> {
    requireHuman(principal);
    return this.#mutate((): MutationResult => this.#envelopes.reissue(this.#operator(principal, key, body), envelopeId, body));
  }

  /**
   * resendInvitation (human operators only): the current-turn recipient's outstanding
   * invitations and sessions are revoked and a fresh invitation is mailed after the commit
   * (202 Accepted). Order of checks, as in the domain (T034R-RESEND): idempotency replay or
   * conflict, then the request's own rules (400), the envelope and recipient in the tenant
   * (404), the envelope's state and expiry (409 state_conflict), the expected version (409
   * version_conflict), then the ceremony's turn and status rules (409). So a reused key with a
   * changed or malformed body is 409 idempotency_conflict, never 400. The envelope row itself
   * does not change, so its version does not either.
   */
  async resend(principal: OperatorPrincipal, envelopeId: string, recipientId: string, key: string, body: JsonValue): Promise<HandlerResult> {
    requireHuman(principal);
    const actor = actorOf(principal);
    return this.#mutate(() => {
      const digest = idempotencyRequestDigest({ route: RESEND_ROUTE, target: `${envelopeId}/${recipientId}`, request: body });
      const now = this.#now();
      return this.#db.transaction((): { status: number; bytes: Uint8Array } => {
        const store = this.#db.forTenant(principal.tenant_id);
        const existing = findIdempotencyRecord(store, RESEND_ROUTE, actor.ref, key);
        if (existing !== undefined && isIdempotencyRecordExpired(existing, now)) {
          // Past its 24 hours a record is no longer a replay (data-model.md § IdempotencyRecord).
          deleteIdempotencyRecord(store, existing);
        } else if (existing !== undefined) {
          if (existing.requestDigest !== digest || existing.principal.kind !== actor.kind) throw new HttpError(409, 'idempotency_conflict');
          const response = recordedResponse(existing);
          if (response.kind !== 'body') throw new HttpError(500, 'internal');
          return { status: existing.responseStatus, bytes: response.bytes };
        }
        // The request's own rules come after the key (T034R-RESEND).
        let expectedVersion: number;
        try {
          expectedVersion = checkVersionOnly(body).expectedVersion;
        } catch (error) {
          throw httpErrorOf(error);
        }
        const envelope = getEnvelope(store, envelopeId);
        if (envelope === undefined) throw new HttpError(404, 'not_found');
        if (!listRecipients(store, envelopeId).some((recipient) => recipient.id === recipientId)) throw new HttpError(404, 'not_found');
        if (!APPROVING_STATES.includes(envelope.state) || Date.parse(envelope.expiresAt) <= now.getTime()) throw new HttpError(409, 'state_conflict');
        if (envelope.version !== expectedVersion) throw new HttpError(409, 'version_conflict');
        // EA-05: the operator, not the system, is the actor of the resend's audit events.
        this.#ceremony.resendInvitation(store, envelopeId, recipientId, actor);
        const bytes = insertIdempotencyRecord(store, {
          route: RESEND_ROUTE,
          principal: actor,
          key,
          requestDigest: digest,
          responseStatus: 202,
          response: { kind: 'body', body: ACCEPTED },
          resourceId: recipientId,
          createdAt: now.toISOString(),
        });
        if (bytes === null) throw new HttpError(500, 'internal');
        return { status: 202, bytes };
      });
    });
  }

  /**
   * uploadDocument (If-Match): stream the PDF to the isolated parse service, store the
   * accepted bytes and record the document while in draft (200 Envelope, version + 1).
   */
  async upload(request: UploadRequest): Promise<HandlerResult> {
    const { principal, envelopeId, key, expectedVersion } = request;
    const actor = actorOf(principal);
    const recorded = this.#uploadPrecheck(principal, envelopeId, key, expectedVersion);
    const slot = acquireUploadSlot(principal.tenant_id);
    if (slot === null) throw new HttpError(429, 'rate_limited', { details: [{ field: 'tenant', code: 'upload-capacity' }], headers: { ...RETRY_AFTER } });
    try {
      // Request #16: a key that already has a record is resolved before any parse.
      if (recorded !== null) return await this.#resolveRecordedUpload(request, recorded);
      const received: Received = { chunks: [], length: 0, failure: null };
      let outcome: ParseOutcome;
      try {
        // A-009 LBR-3: the body is the only argument; no caller-supplied option reaches the parse service.
        outcome = await parsePdf(receive(request.body, received));
      } catch (error) {
        // A-010 LBR4-1: a client abort or a body timeout rejects instead of returning an outcome.
        if (received.failure !== null) throw bodyFailure(received.failure.error);
        throw error;
      }
      if (!outcome.ok) {
        if (outcome.status === 500) request.logger.warn('upload_parse_failed', { reason: outcome.reason, network_sandbox: outcome.network_sandbox });
        throw parseRefusal(outcome);
      }
      const bytes = Buffer.concat(received.chunks, received.length);
      received.chunks.length = 0;
      if (bytes.length !== outcome.report.bytes || sha256(bytes) !== outcome.report.digest) {
        request.logger.warn('upload_parse_mismatch', { bytes: bytes.length });
        throw new HttpError(500, 'internal');
      }
      const document = documentInput(outcome.report);
      // The content-addressed blob is written first: a refused record leaves at most an
      // unreferenced blob, never a revision without its bytes.
      this.#blobs.put(principal.tenant_id, bytes);
      const operator: OperatorRequest = {
        tenantId: principal.tenant_id,
        actor,
        idempotency: { key, request: uploadIdempotencyRequest(expectedVersion, document.digest, document.bytes) },
      };
      // A concurrent request with the same new key that committed first is replayed or
      // refused (409) by the domain, in this mutation's own transaction.
      return await this.#mutate((): MutationResult => this.#envelopes.uploadDocument(operator, envelopeId, expectedVersion, document));
    } finally {
      slot.release();
    }
  }

  /**
   * Before any body byte is read. When the key has a live idempotency record of this
   * principal on the upload route, that record is returned, and the request is resolved
   * against it alone, as of its arrival (also after the envelope has moved on); nothing else
   * is checked. Otherwise (a new key, or a record past its 24 hours), in the domain's order:
   * the envelope exists in the tenant (404); it is not overdue (UPLOAD-OVERDUE: a
   * pre-reservation envelope past its expires_at is expired through T007's expiry path, then
   * 409 state_conflict); it is a draft (409 state_conflict); and it is at the If-Match version
   * (409 version_conflict). So a refused upload never reaches the parse service; the domain
   * repeats every check, and deletes an expired record, in its own transaction.
   */
  #uploadPrecheck(principal: OperatorPrincipal, envelopeId: string, key: string, expectedVersion: number): RecordedUpload | null {
    const now = this.#now();
    const actor = actorOf(principal);
    // Single read statements outside any transaction (request #25): Database.transaction()
    // opens BEGIN IMMEDIATE and would wait for the write lock (up to the busy timeout, blocking
    // the event loop) before the body could be read, so before a streaming 413 or a 408 could
    // be answered. In WAL a read takes no write lock and is not blocked by a writer. The reads
    // need no common snapshot: their outcome is a fast refusal or a go-ahead, the domain
    // repeats every check in its own transaction when it records the upload, and the overdue
    // expiry below is T007's own write transaction, which re-reads the envelope.
    const store = this.#db.forTenant(principal.tenant_id);
    const record = findIdempotencyRecord(store, IDEMPOTENCY_ROUTES.upload, actor.ref, key);
    if (record !== undefined && !isIdempotencyRecordExpired(record, now)) {
      const response = recordedResponse(record);
      // Envelope responses carry no one-time secret, so their records always keep the body.
      if (response.kind !== 'body') throw new HttpError(500, 'internal');
      return { requestDigest: record.requestDigest, principalKind: record.principal.kind, status: record.responseStatus, bytes: response.bytes };
    }
    const envelope = getEnvelope(store, envelopeId);
    if (envelope === undefined) throw new HttpError(404, 'not_found');
    if (PRE_RESERVATION_STATES.includes(envelope.state) && Date.parse(envelope.expiresAt) <= now.getTime()) {
      // UPLOAD-OVERDUE: expire through T007's expiry path, in its own transaction (it re-reads
      // the envelope and expires it only if still due, so a concurrent expiry is not repeated),
      // then refuse as the domain refuses a request that finds the envelope expired.
      try {
        this.#envelopes.expireIfDue(principal.tenant_id, envelopeId);
      } catch (error) {
        throw httpErrorOf(error);
      }
      throw new HttpError(409, 'state_conflict');
    }
    if (envelope.state !== 'draft') throw new HttpError(409, 'state_conflict');
    if (envelope.version !== expectedVersion) throw new HttpError(409, 'version_conflict');
    return null;
  }

  /**
   * Request #16: resolve an upload whose key has a record, without the parse service. The body
   * is read only for its digest, inside the upload slot the caller holds and within the parse
   * service's own size limit (read from src/pdf/limits.ts, never copied). The same request as
   * the record's (the domain's digest of route, envelope and uploadIdempotencyRequest(), and
   * the same principal kind, as in the domain) replays the stored status and exact bytes; any
   * other is 409 idempotency_conflict, whatever the PDF's validity.
   */
  async #resolveRecordedUpload(request: UploadRequest, recorded: RecordedUpload): Promise<HandlerResult> {
    const body = await digestBody(request.body, DEFAULT_PARSER_LIMITS.maxBytes);
    const digest = idempotencyRequestDigest({
      route: IDEMPOTENCY_ROUTES.upload,
      target: request.envelopeId,
      request: uploadIdempotencyRequest(request.expectedVersion, body.digest, body.length),
    });
    if (recorded.requestDigest !== digest || recorded.principalKind !== request.principal.kind) throw new HttpError(409, 'idempotency_conflict');
    return bytesResult(recorded.status, recorded.bytes);
  }

  /**
   * T034R-RESEND: whether `key` already has a live idempotency record of this principal on
   * `route` (an operationId), judged once, at arrival, before the body is read. A handler
   * whose body turns out not to be a JSON value answers 409 idempotency_conflict when it has.
   *
   * One read statement, outside any transaction (request #25): Database.transaction() opens
   * BEGIN IMMEDIATE and would wait for the write lock (up to the busy timeout, blocking the
   * event loop) before the body's transport answers (415, 413, 408) could be given. In WAL a
   * single read takes no write lock and is not blocked by a writer; it sees the last commit.
   */
  hasLiveRecord(principal: OperatorPrincipal, route: string, key: string): boolean {
    const now = this.#now();
    const record = findIdempotencyRecord(this.#db.forTenant(principal.tenant_id), route, actorOf(principal).ref, key);
    return record !== undefined && !isIdempotencyRecordExpired(record, now);
  }

  /** The envelope domain service this API mutates through (its onChange is the ceremony's). */
  get envelopes(): EnvelopeService {
    return this.#envelopes;
  }
}
