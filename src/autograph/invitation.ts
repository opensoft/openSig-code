// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// The invitation and the challenge code (T009; contract ChallengeRequest, SessionCreate).
// - The mailed link is /sign#i=<token>. The fragment never reaches the server, its logs or a
//   Referer. The shell reads it once, keeps the token in memory only (never storage), and at
//   once replaces the current history entry with the bare path, so the token is in neither
//   the address bar nor the session history, and Back or a reload cannot bring it back. A
//   query string (a scanner may copy the token there) is dropped the same way and never read.
// - Codes are 10 characters of Crockford base32. Typed input is normalized as Crockford reads
//   it: case-insensitive, spaces and dashes ignored, O read as 0, I and L read as 1.

export const INVITATION_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;
export const CODE_PATTERN = /^[0-9A-HJKMNP-TV-Z]{10}$/;

/** The invitation token in a location hash ("#i=<token>"), or null when there is none or it is malformed. */
export function invitationFromFragment(hash: string): string | null {
  if (!hash.startsWith('#') || hash.length < 2) return null;
  const parameters = new URLSearchParams(hash.slice(1));
  const values = parameters.getAll('i');
  const token = values[0];
  if (values.length !== 1 || token === undefined || !INVITATION_PATTERN.test(token)) return null;
  return token;
}

/**
 * True when a location hash carries the invitation parameter `i` at all, well formed or not
 * ("#i=<token>", "#i=<a>&i=<b>", "#i=x", "#i"). A fragment without it (a skip link or an
 * in-page anchor) is not an invitation and is left alone.
 */
export function carriesInvitationParameter(hash: string): boolean {
  if (!hash.startsWith('#') || hash.length < 2) return false;
  return new URLSearchParams(hash.slice(1)).has('i');
}

/** Replace the current history entry with the bare path: no fragment, no query. */
export function scrubLocation(location: Location, history: History): void {
  if (location.hash === '' && location.search === '') return;
  history.replaceState(null, '', location.pathname);
}

/** A typed code in contract form, or null when it cannot be one. */
export function normalizeCode(input: string): string | null {
  const compact = input.replace(/[\s-]+/g, '').toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1');
  return CODE_PATTERN.test(compact) ? compact : null;
}
