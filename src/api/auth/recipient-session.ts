// SPDX-License-Identifier: Apache-2.0
//
// The recipient session scheme (T008; contract securitySchemes.recipientSession;
// contracts/sessions-events-adapters.md § Recipient ceremony; data-model.md
// § Entities, RecipientSession, and § Authentication and secrets).
//
// - The session value is 256 random bits (base64url) and exists only in the
//   cookie `__Host-opensig_rs` (HttpOnly, Secure, SameSite=Strict, Path=/, no
//   Domain). The database keeps its SHA-256, which is how a presented cookie
//   resolves to its tenant and row.
// - Each session row keeps a random 256-bit csrf_secret, NOT NULL and immutable
//   (migration 0013). The CSRF token is HMAC-SHA256(csrf_secret,
//   "opensig.recipient-csrf/1\n" + session id), base64url: stable for the life
//   of the session, bound to it server-side, and never stored. Mutations
//   compare the X-CSRF-Token header with it in constant time (403 csrf_failed).
//   The Origin allowlist runs before any handler (src/server/app.ts).
// - Idle expiry: a session whose last_seen_at is 30 minutes or more in the past
//   is unauthenticated (401). An authenticated request moves last_seen_at to
//   now, except a prefetch: prefetching changes nothing at all.
// - Operators can never use this scheme: an Authorization header on a recipient
//   route is a 401 before any handler runs (src/server/app.ts).
//
// The scheme reads no storage itself: a RecipientSessionAuthority (the
// ceremony, src/api/recipients/ceremony.ts) resolves cookies to sessions.

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import { HttpError, type HandlerResult, type RequestContext, type RouteHandler } from '../../server/types.ts';

/**
 * Request headers as the server parses them (lower-case names). Declared here
 * structurally: the auth modules import no network module (T005 AU-04).
 */
export type HeaderBag = Readonly<Record<string, string | readonly string[] | undefined>>;

/** What the scheme reads from a request: its headers only. */
export interface RequestLike {
  readonly headers: HeaderBag;
}

export const SESSION_COOKIE = '__Host-opensig_rs';
export const SESSION_IDLE_MS = 30 * 60 * 1000;
export const CSRF_HEADER = 'x-csrf-token';

/** A capability value as it travels: base64url, 43 to 128 characters (256 bits or more). */
export const CAPABILITY_VALUE_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;
const CSRF_CONTEXT = 'opensig.recipient-csrf/1\n';
const CAPABILITY_BYTES = 32;

/** A fresh session value: 256 random bits, base64url (43 characters). */
export function newSessionValue(): string {
  return randomBytes(CAPABILITY_BYTES).toString('base64url');
}

/** A fresh CSRF secret: 256 random bits, stored with the session. */
export function newCsrfSecret(): Buffer {
  return randomBytes(CAPABILITY_BYTES);
}

/** SHA-256 (lowercase hex) of a presented capability value: the stored form. */
export function capabilityHash(value: string): string {
  return createHash('sha256').update(value, 'ascii').digest('hex');
}

/** The session's CSRF token, derived from its stored secret and bound to its id. */
export function csrfToken(secret: Uint8Array, sessionId: string): string {
  if (!(secret instanceof Uint8Array) || secret.byteLength < 16) throw new TypeError('a CSRF secret of at least 16 bytes is required');
  return createHmac('sha256', secret).update(CSRF_CONTEXT + sessionId, 'utf8').digest('base64url');
}

/** Constant-time check of a presented X-CSRF-Token against the session's token. */
export function csrfMatches(secret: Uint8Array, sessionId: string, presented: unknown): boolean {
  if (typeof presented !== 'string' || !CAPABILITY_VALUE_PATTERN.test(presented)) return false;
  const expected = Buffer.from(csrfToken(secret, sessionId), 'ascii');
  const given = Buffer.from(presented, 'ascii');
  return given.length === expected.length && timingSafeEqual(given, expected);
}

/**
 * The session value from the Cookie header, or null when it is absent,
 * malformed or present more than once (an ambiguous cookie never authenticates).
 */
export function readSessionCookie(headers: HeaderBag): string | null {
  const header = headers['cookie'];
  if (typeof header !== 'string' || header.length === 0) return null;
  const found: string[] = [];
  for (const part of header.split(';')) {
    const pair = part.trim();
    const split = pair.indexOf('=');
    if (split <= 0) continue;
    if (pair.slice(0, split).trim() === SESSION_COOKIE) found.push(pair.slice(split + 1).trim());
  }
  if (found.length !== 1) return null;
  const value = found[0] as string;
  return CAPABILITY_VALUE_PATTERN.test(value) ? value : null;
}

/** Set-Cookie for a new session: a host-only, HTTPS-only, script-inaccessible, same-site cookie. */
export function sessionCookie(value: string): string {
  if (!CAPABILITY_VALUE_PATTERN.test(value)) throw new TypeError('session value is malformed');
  return `${SESSION_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict`;
}

/** Set-Cookie that clears the session cookie. */
export function clearedSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`;
}

/** True when a session last seen at `lastSeenAt` is idle-expired at `now` (30 minutes or more). */
export function idleExpired(lastSeenAt: string, now: Date): boolean {
  const seen = Date.parse(lastSeenAt);
  return !Number.isFinite(seen) || now.getTime() - seen >= SESSION_IDLE_MS;
}

/** When a session last seen at `lastSeenAt` idle-expires (unsigned server time). */
export function sessionExpiresAt(lastSeenAt: string): string {
  return new Date(Date.parse(lastSeenAt) + SESSION_IDLE_MS).toISOString();
}

function headerText(value: string | readonly string[] | undefined): string {
  return (typeof value === 'string' ? value : value === undefined ? '' : value.join(',')).toLowerCase();
}

/** True for a browser or scanner prefetch (Sec-Purpose, Purpose, X-Purpose or X-Moz). */
export function isPrefetch(headers: HeaderBag): boolean {
  const secPurpose = headerText(headers['sec-purpose']);
  if (secPurpose.split(/[;,]/).some((token) => token.trim() === 'prefetch')) return true;
  const purpose = headerText(headers['purpose']).trim();
  const xPurpose = headerText(headers['x-purpose']).trim();
  const xMoz = headerText(headers['x-moz']).trim();
  return purpose === 'prefetch' || xPurpose === 'preview' || xPurpose === 'prefetch' || xMoz === 'prefetch';
}

/** An authenticated recipient session, bound to tenant, envelope, recipient, revision and manifest. */
export interface RecipientSession {
  readonly tenantId: string;
  readonly sessionId: string;
  readonly envelopeId: string;
  readonly recipientId: string;
  readonly revisionId: string;
  readonly manifestDigest: string;
  readonly csrfSecret: Buffer;
  readonly lastSeenAt: string;
}

/** Resolves a request's session cookie (the ceremony implements it over storage). */
export interface RecipientSessionAuthority {
  /**
   * The live session of the request's cookie, or null: no cookie, an unknown
   * or revoked session, an idle-expired session or a broken binding. With
   * `refresh`, last_seen_at moves to now.
   */
  authenticate(request: RequestLike, options: { readonly refresh: boolean }): RecipientSession | null;
  /** Move a live session's last_seen_at to now; null when it is no longer live. */
  refresh(session: RecipientSession): RecipientSession | null;
}

export type AuthorityLookup = (ctx: RequestContext) => RecipientSessionAuthority;
export type RecipientHandler = (ctx: RequestContext, session: RecipientSession) => Promise<HandlerResult>;

/**
 * A recipient read (GET; HEAD is served as GET): the session must be live
 * (401 otherwise). A prefetch authenticates without moving last_seen_at.
 */
export function withRecipientSession(lookup: AuthorityLookup, handler: RecipientHandler): RouteHandler {
  return async (ctx) => {
    const session = lookup(ctx).authenticate(ctx.request, { refresh: !isPrefetch(ctx.request.headers) });
    if (session === null) throw new HttpError(401, 'unauthenticated');
    return handler(ctx, session);
  };
}

/**
 * A recipient mutation: a live session (401), then the X-CSRF-Token of that
 * session (403 csrf_failed), checked before last_seen_at moves and before any
 * handler runs. `handler` null keeps the server's convention for an operation
 * whose task has not landed (501), after the same checks.
 */
export function withRecipientMutation(lookup: AuthorityLookup, handler: RecipientHandler | null): RouteHandler {
  return async (ctx) => {
    const authority = lookup(ctx);
    const session = authority.authenticate(ctx.request, { refresh: false });
    if (session === null) throw new HttpError(401, 'unauthenticated');
    if (!csrfMatches(session.csrfSecret, session.sessionId, ctx.request.headers[CSRF_HEADER])) throw new HttpError(403, 'csrf_failed');
    const live = authority.refresh(session);
    if (live === null) throw new HttpError(401, 'unauthenticated');
    if (handler === null) throw new HttpError(501, 'internal');
    return handler(ctx, live);
  };
}
