// SPDX-License-Identifier: Apache-2.0
//
// Notifications adapter (T032): development file spool, guarded loopback SMTP, content
// redaction and per-tenant rate limits. Typical use:
//
//   const notifier = createNotifierFromConfig(loadNotificationConfig(process.env), { logger });
//   await notifier.send({ kind: 'recipient_invitation', tenant_id, to, invitation, expires_at });
//
// The module exposes delivery only; it has no operation that reads mail back.

export { loadNotificationConfig, DEFAULT_MAIL_FROM } from './config.ts';
export type { NotificationConfig } from './config.ts';
export { composeNotification, ENVELOPE_STATES, parsePublicOrigin, renderMessage } from './content.ts';
export type {
  Audience,
  EnvelopeState,
  EnvelopeStatusRequest,
  NotificationKind,
  NotificationRequest,
  RecipientChallengeRequest,
  RecipientInvitationRequest,
} from './content.ts';
export { NotificationError } from './errors.ts';
export type { NotificationErrorCode } from './errors.ts';
export { createNotifier, createNotifierFromConfig } from './notifier.ts';
export type { DeliveryReceipt, Notifier, NotifierOptions, NotifierRuntime } from './notifier.ts';
export { isReservedDomain, loadPilotPolicy, parsePilotPolicy, PILOT_SCHEMA, RESERVED_RECIPIENT_DOMAINS } from './policy.ts';
export type { PilotPolicy } from './policy.ts';
export { DEFAULT_TENANT_RATE_LIMIT } from './rate-limit.ts';
export type { RateLimitOptions } from './rate-limit.ts';
export { createSmtpTransport } from './smtp.ts';
export type { ConnectFn, SmtpRelay } from './smtp.ts';
export { createSpoolTransport, defaultSpoolDir } from './spool.ts';
export type { OutboundMessage, Transport } from './transport.ts';
