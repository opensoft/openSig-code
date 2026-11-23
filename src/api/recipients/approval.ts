// SPDX-License-Identifier: Apache-2.0
//
// approveAsHuman (T010): POST /v1/recipient-session/approval, 200
// ApprovalReceipt (contracts/http-api.json; contracts/sessions-events-
// adapters.md § Recipient ceremony, item 5).
//
// The server (src/server/app.ts, T031) has already routed the request, checked
// its Origin against the allowlist (a recipient route must send one: 403
// origin_rejected), refused any Authorization header on a recipient route
// (401), and applied the 256 KiB JSON limit (413). Then, in this order:
// 1. any operator or service credential is 401 unauthenticated, again, here:
//    an Authorization header, or an operator principal on the request
//    (refuseOperatorCredential). Human approval cannot be delegated to an
//    operator bearer or a service credential (SC002-17, SC002-18), whatever
//    else the request carries;
// 2. the recipient session and CSRF guard (T008, withRecipientMutation): a
//    live session (401), then that session's X-CSRF-Token (403 csrf_failed),
//    checked before last_seen_at moves;
// 3. the approval itself (src/domain/approval/), which re-reads the session
//    (401), then answers an earlier approval of this recipient (the original
//    receipt bytes for an exact retry, 409 for any other request, malformed or
//    not), and only then checks the body (400, then 422) and the rest (409),
//    recording nothing on a refusal (A-010, request #24, ruling (8)). A body
//    that is not JSON reaches it as MALFORMED_BODY, so even that is decided
//    after the session and the receipt.
// The first of two approvals invites recipient 2 inside the approval's
// transaction (the ceremony's onEnvelopeChange); the invitation is mailed only
// after that transaction commits (RecipientCeremony.capture, then deliver), and
// never appears in the response.
//
// Composition. One ApprovalApi per process, stored in the server locals under
// APPROVAL_API (production wiring is T031's US1 composition slot, row
// WIRE-US1); a request that finds none is a 500 (fail closed). Its envelope
// service reports changes to the ceremony and announces the expiry an approval
// or decline commits (envelope.expired, expiryAnnouncer). The handlers are T010's
// own map, APPROVAL_HANDLERS / withApprovalHandlers() in src/api/routes.ts; T008's
// RECIPIENT_HANDLERS keeps its guard-only entries until WIRE-US1 composes both
// (ruling (7)).

import { ApprovalError, ApprovalService, MALFORMED_BODY, expiryAnnouncer, type ApprovalSession } from '../../domain/approval/index.ts';
import { EnvelopeError } from '../../domain/envelopes/errors.ts';
import { EnvelopeService } from '../../domain/envelopes/service.ts';
import { HttpError, type HandlerResult, type RequestContext, type RouteHandler } from '../../server/types.ts';
import { AuditWriter } from '../../storage/audit/index.ts';
import type { Database } from '../../storage/db/index.ts';
import { withRecipientMutation } from '../auth/recipient-session.ts';
import { RecipientCeremony } from './ceremony.ts';
import { ceremonyAuthority } from './handlers.ts';

/** The server locals key of the app's ApprovalApi. */
export const APPROVAL_API = 'opensig.approval-api';

const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';

export interface ApprovalApiOptions {
  readonly db: Database;
  /** The recipient ceremony (T008): the session authority, and invitations after the first of two approvals. */
  readonly ceremony: RecipientCeremony;
  readonly clock: () => Date;
  /** max_attempts of a reserved SigningJob (default: the domain's FINALIZATION_MAX_ATTEMPTS). */
  readonly maxAttempts?: number;
}

/** A domain refusal as the contract Error it names; anything else unchanged. */
export function approvalHttpError(error: unknown): unknown {
  if (error instanceof ApprovalError) return new HttpError(error.status, error.code, { details: error.details.map((detail) => ({ field: detail.field, code: detail.code })) });
  if (error instanceof EnvelopeError) {
    if (error.code === 'state_conflict' || error.code === 'version_conflict' || error.code === 'order_conflict') return new HttpError(409, error.code);
    return new HttpError(500, 'internal');
  }
  return error;
}

export class ApprovalApi {
  readonly #ceremony: RecipientCeremony;
  readonly #envelopes: EnvelopeService;
  readonly #service: ApprovalService;

  constructor(options: ApprovalApiOptions) {
    if (typeof options?.clock !== 'function') throw new TypeError('the approval API needs an injected clock');
    if (!(options.ceremony instanceof RecipientCeremony)) throw new TypeError('the approval API needs the recipient ceremony');
    if (typeof options.db?.transaction !== 'function' || typeof options.db.forTenant !== 'function') throw new TypeError('the approval API needs the database');
    this.#ceremony = options.ceremony;
    this.#envelopes = new EnvelopeService({ db: options.db, clock: options.clock, onChange: expiryAnnouncer(options.db, options.clock, options.ceremony.onEnvelopeChange) });
    this.#service = new ApprovalService({
      db: options.db,
      clock: options.clock,
      envelopes: this.#envelopes,
      audit: new AuditWriter(options.db, { clock: options.clock }),
      ...(options.maxAttempts === undefined ? {} : { maxAttempts: options.maxAttempts }),
    });
    Object.freeze(this);
  }

  /** Run one synchronous domain step inside the ceremony's capture, then mail what it issued. */
  async #run(step: () => { readonly status: number; readonly bytes: Uint8Array }): Promise<HandlerResult> {
    let captured: { readonly value: { readonly status: number; readonly bytes: Uint8Array }; readonly mails: Parameters<RecipientCeremony['deliver']>[0] };
    try {
      captured = this.#ceremony.capture(step);
    } catch (error) {
      throw approvalHttpError(error);
    }
    if (captured.mails.length > 0) await this.#ceremony.deliver(captured.mails);
    return { status: captured.value.status, body: captured.value.bytes, contentType: JSON_CONTENT_TYPE };
  }

  /** approveAsHuman for the session's recipient (200 ApprovalReceipt). */
  approve(session: ApprovalSession, body: unknown): Promise<HandlerResult> {
    return this.#run(() => this.#service.approve(session, body));
  }

  /** declineAsRecipient for the session's recipient (200 DeclineOutcome). */
  decline(session: ApprovalSession, body: unknown): Promise<HandlerResult> {
    return this.#run(() => this.#service.decline(session, body));
  }

  /** The domain service this API records through. */
  get service(): ApprovalService {
    return this.#service;
  }

  /** The envelope service whose compare-and-set the approvals use (its onChange is the ceremony's). */
  get envelopes(): EnvelopeService {
    return this.#envelopes;
  }
}

/** The app's ApprovalApi, or a 500 when the server was started without one. */
export function approvalApiOf(ctx: RequestContext): ApprovalApi {
  const api = ctx.locals.get(APPROVAL_API);
  if (!(api instanceof ApprovalApi)) throw new HttpError(500, 'internal');
  return api;
}

/**
 * Human approval and decline take the recipient session only. An operator
 * bearer or a service credential, an Authorization header of any kind, or an
 * operator principal is 401, before the session guard runs and before any
 * state (last_seen_at included) changes. The server refuses the header first;
 * this is the handlers' own check of the same rule.
 */
export function refuseOperatorCredential(ctx: RequestContext): void {
  if (ctx.principal !== null || ctx.request.headers.authorization !== undefined) throw new HttpError(401, 'unauthenticated');
}

/**
 * The JSON request body of a recipient mutation, read after the session and
 * CSRF guard. The server enforces the media type (415) and the 256 KiB limit
 * (413); a body that is not UTF-8 JSON becomes MALFORMED_BODY, which the domain
 * refuses as 400 only after the session and an earlier receipt (ruling (8)).
 */
export async function recipientJsonBody(ctx: RequestContext): Promise<unknown> {
  try {
    return await ctx.json();
  } catch (error) {
    if (error instanceof HttpError && error.status === 400) return MALFORMED_BODY;
    throw error;
  }
}

const guardedApprove: RouteHandler = withRecipientMutation(ceremonyAuthority, async (ctx, session) => {
  const api = approvalApiOf(ctx);
  const body = await recipientJsonBody(ctx);
  return api.approve(session, body);
});

/** approveAsHuman: 401 for any operator or service credential, then the session and CSRF guard, then the approval. */
export const approveAsHuman: RouteHandler = async (ctx) => {
  refuseOperatorCredential(ctx);
  return guardedApprove(ctx);
};
