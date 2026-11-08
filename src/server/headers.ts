// SPDX-License-Identifier: Apache-2.0
//
// Security headers (T031) applied to every response, after any handler header, so no
// handler can weaken them:
// - Content-Security-Policy with no 'unsafe-inline', no 'unsafe-eval' and no external
//   source; frame-ancestors 'none';
// - Referrer-Policy: no-referrer; X-Content-Type-Options: nosniff; X-Frame-Options: DENY;
// - Cache-Control: no-store; Cross-Origin-Opener-Policy and -Resource-Policy: same-origin.
// The single exception is the recipient document response (readRecipientDocument, 200,
// application/pdf), which allows frame-ancestors 'self' (and X-Frame-Options SAMEORIGIN)
// so the review shell can show the exact bytes in the browser's own PDF viewer. No CORS
// header is ever sent, so no origin is reflected.

export type Framing = 'none' | 'self';

const BASE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "frame-src 'self'",
  "font-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
];

export function contentSecurityPolicy(framing: Framing): string {
  return [...BASE_CSP, `frame-ancestors '${framing}'`].join('; ');
}

export function securityHeaders(framing: Framing): Record<string, string> {
  return {
    'content-security-policy': contentSecurityPolicy(framing),
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': framing === 'self' ? 'SAMEORIGIN' : 'DENY',
    'cache-control': 'no-store',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
  };
}

/** Header names a handler may not set (security headers and CORS). */
export const RESERVED_HEADERS: ReadonlySet<string> = new Set([
  ...Object.keys(securityHeaders('none')),
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'access-control-allow-headers',
  'access-control-allow-methods',
  'x-correlation-id',
]);
