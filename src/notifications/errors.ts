// SPDX-License-Identifier: Apache-2.0
//
// Notification errors (T032). A message never contains a field value: no address,
// domain, relay host, capability value, link or relay reply text. The `field` member
// names the offending request member when there is one.

export type NotificationErrorCode =
  /** A request member is missing, unknown or malformed. */
  | 'invalid_notification'
  /** The recipient domain is outside the reserved test domains and the owner pilot list. */
  | 'recipient_domain_refused'
  /** The SMTP relay is not a loopback address. */
  | 'relay_refused'
  /** The tenant exceeded its notification rate limit. */
  | 'rate_limited'
  /** The rendered message failed a content guard (a link or code where none may appear). */
  | 'content_refused'
  /** The spool directory is unsafe (permissions, owner, symlink or location). */
  | 'spool_unsafe'
  /** The transport did not accept the message. */
  | 'delivery_failed'
  /** The notification configuration is missing or invalid. */
  | 'config_invalid';

export interface NotificationErrorOptions {
  field?: string;
  retryAfterSeconds?: number;
  smtpStatus?: number;
  cause?: unknown;
}

export class NotificationError extends Error {
  readonly code: NotificationErrorCode;
  readonly field: string | null;
  /** Seconds until the tenant may send again (rate_limited only). */
  readonly retryAfterSeconds: number | null;
  /** The SMTP reply code that refused the message (delivery_failed only). */
  readonly smtpStatus: number | null;

  constructor(code: NotificationErrorCode, message: string, options: NotificationErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'NotificationError';
    this.code = code;
    this.field = options.field ?? null;
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
    this.smtpStatus = options.smtpStatus ?? null;
  }
}
