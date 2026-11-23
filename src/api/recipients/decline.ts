// SPDX-License-Identifier: Apache-2.0
//
// declineAsRecipient (T010): POST /v1/recipient-session/decline, 200
// DeclineOutcome {envelope_state: declined} (contracts/http-api.json;
// contracts/sessions-events-adapters.md § Recipient ceremony, item 6).
//
// The same front as approveAsHuman (approval.ts): the server's Origin
// allowlist, its 401 for an Authorization header on a recipient route and its
// JSON limit; then the handler's own 401 for any operator or service
// credential, the recipient session (401) and CSRF (403 csrf_failed) guard, and
// the decline itself (src/domain/approval/service.ts), which re-reads the
// session (401) before it looks at the body (400): the envelope moves to
// declined through the compare-and-set it shares with approval, expiry and
// void, the recipient to declined and every other non-final recipient to
// revoked, every outstanding invitation and session of the envelope is
// revoked, so the session that declined is no longer live (a repeated decline
// is 401), and envelope.declined is written to the outbox in the same
// transaction. Expected version, state, turn and expiry refusals are 409, a
// malformed body 400, and nothing is recorded.

import type { RouteHandler } from '../../server/types.ts';
import { withRecipientMutation } from '../auth/recipient-session.ts';
import { approvalApiOf, recipientJsonBody, refuseOperatorCredential } from './approval.ts';
import { ceremonyAuthority } from './handlers.ts';

const guardedDecline: RouteHandler = withRecipientMutation(ceremonyAuthority, async (ctx, session) => {
  const api = approvalApiOf(ctx);
  const body = await recipientJsonBody(ctx);
  return api.decline(session, body);
});

/** declineAsRecipient: 401 for any operator or service credential, then the session and CSRF guard, then the decline. */
export const declineAsRecipient: RouteHandler = async (ctx) => {
  refuseOperatorCredential(ctx);
  return guardedDecline(ctx);
};
