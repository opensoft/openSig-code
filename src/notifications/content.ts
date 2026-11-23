// SPDX-License-Identifier: Apache-2.0
//
// Notification content (T032): strict request validation, fixed templates, RFC 5322
// rendering and the content guards. Rules (contracts/sessions-events-adapters.md
// § Capability values):
//
// - Recipient invitation mail carries exactly one link, `<public origin>/sign#i=<invitation>`.
//   The invitation appears only in that URL fragment: never in a path, query, header,
//   subject, Message-ID or anywhere else. The origin comes from deployment configuration,
//   never from the request.
// - Recipient challenge mail carries the code once in its body and no link.
// - Operator and service notifications carry no link and no code. Their requests have no
//   free-text member: only an envelope id, version, state and time.
// - Requests with unknown members are refused, so a caller cannot add text to a template.
// - Messages are 7-bit ASCII text/plain with CRLF line endings; no HTML.

import { NotificationError } from './errors.ts';
import { parseAddress } from './policy.ts';
import type { ParsedAddress } from './policy.ts';

export type EnvelopeState = 'draft' | 'prepared' | 'sent' | 'in-progress' | 'finalizing' | 'completed' | 'declined' | 'expired' | 'voided';
export type Audience = 'recipient' | 'operator' | 'service';
export type NotificationKind = 'recipient_invitation' | 'recipient_challenge' | 'envelope_status';

export interface RecipientInvitationRequest {
  readonly kind: 'recipient_invitation';
  readonly tenant_id: string;
  readonly to: string;
  /** The raw invitation token (≥ 256 bits, base64url). Mailed only, in the URL fragment. */
  readonly invitation: string;
  readonly expires_at: Date | string;
}

export interface RecipientChallengeRequest {
  readonly kind: 'recipient_challenge';
  readonly tenant_id: string;
  readonly to: string;
  /** The challenge code: 10 Crockford base32 characters. */
  readonly code: string;
  readonly expires_at: Date | string;
}

export interface EnvelopeStatusRequest {
  readonly kind: 'envelope_status';
  readonly audience: 'operator' | 'service';
  readonly tenant_id: string;
  readonly to: string;
  readonly envelope_id: string;
  readonly envelope_version: number;
  readonly state: EnvelopeState;
  readonly occurred_at: Date | string;
}

export type NotificationRequest = RecipientInvitationRequest | RecipientChallengeRequest | EnvelopeStatusRequest;

export interface ComposedMessage {
  readonly kind: NotificationKind;
  readonly audience: Audience;
  readonly tenantId: string;
  readonly to: ParsedAddress;
  readonly subject: string;
  /** Body lines (no line terminators). */
  readonly lines: readonly string[];
  /** Capability values this message carries (recipient mail only). Never returned to callers. */
  readonly capabilities: readonly string[];
  /** The one link a recipient invitation carries, or null. */
  readonly link: string | null;
}

export const ENVELOPE_STATES: readonly EnvelopeState[] = Object.freeze([
  'draft',
  'prepared',
  'sent',
  'in-progress',
  'finalizing',
  'completed',
  'declined',
  'expired',
  'voided',
]);

const ID = /^[A-Za-z0-9_-]{16,64}$/;
const INVITATION = /^[A-Za-z0-9_-]{43,128}$/;
const CODE = /^[0-9A-HJKMNP-TV-Z]{10}$/;
/** A standalone challenge-code-shaped token. */
const CODE_SHAPE = /(?<![A-Za-z0-9_-])[0-9A-HJKMNP-TV-Z]{10}(?![A-Za-z0-9_-])/;
/** Anything that can act as a link in a mail client. */
const LINK_SHAPE = /[A-Za-z][A-Za-z0-9+.-]*:\/\/|\bwww\.|\bmailto:|\/sign\b|#i=|\bhttps?:/i;
const MAX_LINE = 998;
/** Nine digits at most, so a version can never take the shape of a 10-character code. */
const MAX_VERSION = 999_999_999;

const MEMBERS: Readonly<Record<NotificationKind, readonly string[]>> = Object.freeze({
  recipient_invitation: ['kind', 'tenant_id', 'to', 'invitation', 'expires_at'],
  recipient_challenge: ['kind', 'tenant_id', 'to', 'code', 'expires_at'],
  envelope_status: ['kind', 'audience', 'tenant_id', 'to', 'envelope_id', 'envelope_version', 'state', 'occurred_at'],
});

function invalid(field: string, what: string): NotificationError {
  return new NotificationError('invalid_notification', `${field} ${what}`, { field });
}

function utcText(value: unknown, field: string): string {
  const date = value instanceof Date ? value : typeof value === 'string' ? new Date(value) : null;
  if (date === null || Number.isNaN(date.getTime())) throw invalid(field, 'must be a valid time');
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function idValue(value: unknown, field: string): string {
  if (typeof value !== 'string' || !ID.test(value)) throw invalid(field, 'must be an opaque identifier');
  return value;
}

/**
 * Validate a public origin: https://<host>[:port], or http:// on a loopback literal for
 * local development. Returns the normalized origin.
 */
export function parsePublicOrigin(value: unknown): string {
  const bad = () => new NotificationError('config_invalid', 'the public origin must be https://<host>[:port], or http:// on 127.0.0.1 or [::1]');
  if (typeof value !== 'string' || value.length > 200) throw bad();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw bad();
  }
  if (url.origin !== value || url.username !== '' || url.password !== '') throw bad();
  if (url.protocol === 'https:') return url.origin;
  if (url.protocol === 'http:' && (url.hostname === '127.0.0.1' || url.hostname === '[::1]')) return url.origin;
  throw bad();
}

/** Validate a request and render its template. `publicOrigin` is required for invitations. */
export function composeNotification(request: unknown, publicOrigin: string | null): ComposedMessage {
  if (request === null || typeof request !== 'object' || Array.isArray(request)) throw invalid('request', 'must be an object');
  const record = request as Record<string, unknown>;
  const kind = record.kind;
  if (kind !== 'recipient_invitation' && kind !== 'recipient_challenge' && kind !== 'envelope_status') {
    throw invalid('kind', 'is not a supported notification kind');
  }
  const allowed = MEMBERS[kind];
  for (const key of Object.keys(record)) if (!allowed.includes(key)) throw invalid('request', 'has an unknown member');
  const tenantId = idValue(record.tenant_id, 'tenant_id');
  const to = parseAddress(record.to, 'to');

  if (kind === 'recipient_invitation') {
    const invitation = record.invitation;
    if (typeof invitation !== 'string' || !INVITATION.test(invitation)) throw invalid('invitation', 'must be a base64url token of at least 256 bits');
    const expires = utcText(record.expires_at, 'expires_at');
    if (publicOrigin === null) throw new NotificationError('config_invalid', 'no public origin is configured for recipient links');
    const link = `${parsePublicOrigin(publicOrigin)}/sign#i=${invitation}`;
    return Object.freeze({
      kind,
      audience: 'recipient',
      tenantId,
      to,
      subject: 'A document is waiting for your review and approval',
      lines: Object.freeze([
        'A document has been sent to you for review and approval.',
        '',
        'Open this link to review it:',
        '',
        link,
        '',
        `The link expires at ${expires} (UTC).`,
        'Opening the link does not approve anything. After you open it you will be asked',
        'for a one-time code, which is sent to this address in a separate message.',
        '',
        'If you were not expecting this message, you can ignore it.',
      ]),
      capabilities: Object.freeze([invitation]),
      link,
    });
  }

  if (kind === 'recipient_challenge') {
    const code = record.code;
    if (typeof code !== 'string' || !CODE.test(code)) throw invalid('code', 'must be 10 Crockford base32 characters');
    const expires = utcText(record.expires_at, 'expires_at');
    return Object.freeze({
      kind,
      audience: 'recipient',
      tenantId,
      to,
      subject: 'Your one-time review code',
      lines: Object.freeze([
        'Your one-time code for reviewing the document is:',
        '',
        `    ${code}`,
        '',
        `It expires at ${expires} (UTC) and can be used once.`,
        'Enter it only on the review page you opened from the invitation message.',
        'Nobody from the sending organization will ask you for this code.',
        '',
        'If you did not request a code, you can ignore this message.',
      ]),
      capabilities: Object.freeze([code]),
      link: null,
    });
  }

  const audience = record.audience;
  if (audience !== 'operator' && audience !== 'service') throw invalid('audience', 'must be operator or service');
  const envelopeId = idValue(record.envelope_id, 'envelope_id');
  const version = record.envelope_version;
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1 || version > MAX_VERSION) {
    throw invalid('envelope_version', 'must be an integer from 1 to 999999999');
  }
  const state = record.state;
  if (typeof state !== 'string' || !(ENVELOPE_STATES as readonly string[]).includes(state)) throw invalid('state', 'is not an envelope state');
  const occurred = utcText(record.occurred_at, 'occurred_at');
  return Object.freeze({
    kind,
    audience,
    tenantId,
    to,
    subject: `Envelope status: ${state}`,
    lines: Object.freeze([
      `Envelope ${envelopeId} is now ${state} (version ${version}).`,
      `Recorded at ${occurred} (UTC, unsigned server time).`,
      '',
      'Use your openSig client to see the details. This message carries no links or codes.',
    ]),
    capabilities: Object.freeze([]),
    link: null,
  });
}

export interface RenderOptions {
  readonly from: ParsedAddress;
  readonly messageId: string;
  readonly date: Date;
}

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** RFC 5322 date-time in UTC. */
export function rfc5322Date(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${DAYS[date.getUTCDay()]}, ${pad(date.getUTCDate())} ${MONTHS[date.getUTCMonth()]} ${date.getUTCFullYear()} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} +0000`;
}

function assertLine(line: string): void {
  if (line.length > MAX_LINE || !/^[\x20-\x7e]*$/.test(line)) {
    throw new NotificationError('content_refused', 'a message line is not printable 7-bit ASCII of at most 998 characters');
  }
}

/** Render the RFC 5322 message: headers, a blank line and the body, CRLF-terminated. */
export function renderMessage(message: ComposedMessage, options: RenderOptions): Buffer {
  const headers = [
    `Date: ${rfc5322Date(options.date)}`,
    `From: ${options.from.address}`,
    `To: ${message.to.address}`,
    `Subject: ${message.subject}`,
    `Message-ID: <${options.messageId}@${options.from.domain}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=us-ascii',
    'Content-Transfer-Encoding: 7bit',
    'Auto-Submitted: auto-generated',
    `X-OpenSig-Notification: ${message.kind}`,
  ];
  const all = [...headers, '', ...message.lines];
  for (const line of all) assertLine(line);
  return Buffer.from(`${all.join('\r\n')}\r\n`, 'ascii');
}

function refuse(message: string): NotificationError {
  return new NotificationError('content_refused', message);
}

function occurrences(text: string, value: string): number {
  let count = 0;
  for (let index = text.indexOf(value); index !== -1; index = text.indexOf(value, index + 1)) count += 1;
  return count;
}

/**
 * Check rendered mail against the capability rules for its audience. Throws
 * content_refused; the message never contains the offending value.
 */
export function assertContent(message: ComposedMessage, rendered: Buffer): void {
  const text = rendered.toString('ascii');
  const split = text.indexOf('\r\n\r\n');
  if (split < 0) throw refuse('the message has no body');
  const head = text.slice(0, split);
  const body = text.slice(split + 4);
  // What a reader sees as text: the subject and the body. Address headers are validated
  // addr-specs and are excluded from the shape checks (an address is not a link).
  const visible = `${message.subject}\n${body}`;

  if (message.audience !== 'recipient') {
    if (message.capabilities.length !== 0 || message.link !== null) throw refuse('operator and service notifications carry no capability');
    if (LINK_SHAPE.test(visible)) throw refuse('operator and service notifications must not contain a link');
    if (CODE_SHAPE.test(visible)) throw refuse('operator and service notifications must not contain a code');
    return;
  }

  for (const capability of message.capabilities) {
    if (head.includes(capability)) throw refuse('a capability value must not appear in a mail header');
    if (occurrences(body, capability) !== 1) throw refuse('a capability value must appear exactly once in recipient mail');
  }

  if (message.kind === 'recipient_challenge') {
    if (LINK_SHAPE.test(visible)) throw refuse('challenge mail must not contain a link');
    return;
  }

  // recipient_invitation: one link, the invitation only in its fragment.
  const [invitation] = message.capabilities;
  if (invitation === undefined || message.link === null) throw refuse('an invitation message needs its link');
  const links = body.match(/[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s]*/g) ?? [];
  if (links.length !== 1 || links[0] !== message.link) throw refuse('invitation mail must carry exactly one link');
  if (LINK_SHAPE.test(message.subject) || LINK_SHAPE.test(body.replace(message.link, ''))) throw refuse('invitation mail must carry exactly one link');
  let url: URL;
  try {
    url = new URL(message.link);
  } catch {
    throw refuse('the invitation link is not a URL');
  }
  if (url.pathname !== '/sign' || url.search !== '' || url.hash !== `#i=${invitation}`) {
    throw refuse('the invitation must appear only in the URL fragment of the /sign link');
  }
  if (url.href.indexOf(invitation) !== url.href.length - invitation.length) throw refuse('the invitation must appear only in the URL fragment');
}
