// SPDX-License-Identifier: Apache-2.0
//
// Central log redactor and logger (T031). Every log record passes through redact() before
// it is serialized, and the serialized line passes through redactText() again, so a
// capability value cannot reach a log by any field. Removed:
// - by key (any depth, case-insensitive): Authorization, Cookie/Set-Cookie, CSRF tokens,
//   invitation and session values, challenge codes, tokens, secrets (including webhook
//   secrets), passwords, passphrases and private/signing keys, and any key ending in
//   _token, _secret, _password, _passphrase or _key;
// - by value: PEM blocks (terminated or not), Bearer/Basic/Digest credentials, JWT-shaped
//   strings, opensig and session cookie pairs, capability query or fragment parameters
//   (i, invitation, token, code, csrf, session, secret), header lines carrying credentials,
//   and JSON text members with secret names.
// Buffers are logged as their length only. The redactor never throws.

export type LogSink = (line: string) => void;

export interface Logger {
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
  child(fields: Record<string, unknown>): Logger;
}

export const REDACTED = '[REDACTED]';

const SENSITIVE_KEY =
  /^(?:authorization|proxy-authorization|cookie|set-cookie|x-csrf-token|csrf|csrf_token|csrftoken|invitation|invitation_token|challenge|challenge_code|code_hmac|session|session_value|session_id|token|access_token|id_token|refresh_token|secret|webhook_secret|client_secret|password|passphrase|private_key|signing_key|api_key|x-api-key|pem)$/i;
const SENSITIVE_SUFFIX = /(?:_token|_secret|_password|_passphrase|_key|-token|-secret)$/i;

const TEXT_RULES: ReadonlyArray<[RegExp, string]> = [
  [/-----BEGIN [^\r\n-]{1,64}-----[\s\S]*?(?:-----END [^\r\n-]{1,64}-----|$)/g, '[REDACTED PEM BLOCK]'],
  [/\b(Bearer|Basic|Digest)\s+[A-Za-z0-9._~+/=-]{4,}/gi, `$1 ${REDACTED}`],
  [/\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.?[A-Za-z0-9_-]*/g, '[REDACTED JWT]'],
  [/\b(__Host-[A-Za-z0-9_-]+|__Secure-[A-Za-z0-9_-]+|session|sessionid|sid)=([^;\s,"]+)/gi, `$1=${REDACTED}`],
  [/([?&#;](?:i|invitation|token|access_token|code|csrf|csrf_token|session|secret|key)=)[^&#\s"]+/gi, `$1${REDACTED}`],
  [/\b(authorization|proxy-authorization|cookie|set-cookie|x-csrf-token)(\s*[:=]\s*)[^\r\n"]+/gi, `$1$2${REDACTED}`],
  [/("(?:[A-Za-z0-9_-]*(?:secret|token|password|passphrase|invitation|csrf)[A-Za-z0-9_-]*|code|challenge_code|session)"\s*:\s*")(?:[^"\\]|\\.)*"/gi, `$1${REDACTED}"`],
];

export function redactText(text: string): string {
  let out = text;
  for (const [pattern, replacement] of TEXT_RULES) out = out.replace(pattern, replacement);
  return out;
}

function sensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key) || SENSITIVE_SUFFIX.test(key);
}

/** A redacted, JSON-safe copy of `value`. */
export function redact(value: unknown, depth = 0, seen: WeakSet<object> = new WeakSet()): unknown {
  if (typeof value === 'string') return redactText(value);
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'bigint') return String(value);
  if (typeof value !== 'object') return typeof value === 'undefined' ? undefined : `[${typeof value}]`;
  if (value instanceof Uint8Array) return `[bytes ${value.length}]`;
  if (depth >= 8) return '[DEPTH]';
  if (seen.has(value)) return '[CYCLE]';
  seen.add(value);
  if (value instanceof Error) return { name: value.name, message: redactText(String(value.message)) };
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => redact(item, depth + 1, seen));
  const out: Record<string, unknown> = {};
  for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
    Object.defineProperty(out, key, {
      value: sensitiveKey(key) ? REDACTED : redact(inner, depth + 1, seen),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

const stdoutSink: LogSink = (line) => {
  process.stdout.write(`${line}\n`);
};

export function createLogger(sink: LogSink = stdoutSink, base: Record<string, unknown> = {}): Logger {
  const write = (level: string, event: string, fields: Record<string, unknown> = {}): void => {
    try {
      const record = redact({ time: new Date().toISOString(), level, event, ...base, ...fields });
      sink(redactText(JSON.stringify(record)));
    } catch {
      sink(JSON.stringify({ level: 'error', event: 'log_failure' }));
    }
  };
  return {
    info: (event, fields) => write('info', event, fields),
    warn: (event, fields) => write('warn', event, fields),
    error: (event, fields) => write('error', event, fields),
    child: (fields) => createLogger(sink, { ...base, ...fields }),
  };
}
