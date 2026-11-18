// SPDX-License-Identifier: Apache-2.0
//
// Server configuration from the environment (T031). The variable names follow the dev
// launcher contract (scripts/dev.mjs, T004) plus the server's own optional settings:
//
//   OPENSIG_HOST                 bind address; default 127.0.0.1. Loopback (127.0.0.1, ::1)
//                                is always allowed; any other address is refused unless
//                                OPENSIG_ALLOW_NON_LOOPBACK_BIND=1 is set explicitly.
//   OPENSIG_PORT                 bind port; default 8443; 0 lets the OS choose.
//   OPENSIG_ALLOWED_ORIGINS      comma-separated exact origins allowed on mutating
//                                requests; default: the server's own loopback origin.
//   OPENSIG_RELAY_SOCKET         absolute path of the optional Unix-domain socket for the
//                                isolated Hermes relay (operator routes only, mode 0600).
//   OPENSIG_OPERATOR_AUTH_FILE   JSON file with the operator OIDC configuration (T005);
//                                without it every operator request is 401.
//   OPENSIG_DATABASE             absolute path of the existing, migrated SQLite database
//                                whose tenants table owns each tenant's allowed roles
//                                (A-008 P11); default <OPENSIG_DATA_DIR>/opensig.db. Needed
//                                whenever OPENSIG_OPERATOR_AUTH_FILE is set (src/server/tenants.ts).
//   OPENSIG_CHALLENGE_KEY_FILE   absolute path of the recipient challenge-HMAC key (T008;
//                                quickstart.md § Configuration). Required: startup refuses
//                                unless it is a regular file, not a link, owned by the
//                                server user, with no group or other permission bit (for
//                                example 0600 or 0400), of 32 to 4096 bytes (main.ts, T008).
//   OPENSIG_DATA_DIR             the service data directory; the blob store (T028) is its
//                                `blobs` subdirectory, created 0700 if absent (row WIRE-US1).
//   OPENSIG_ENV, OPENSIG_MAIL_TRANSPORT, OPENSIG_SPOOL_DIR
//                                passed through to handlers (set by the dev launcher); the
//                                mail settings are read by the T032 notifier (main.ts).
//
// Errors name the variable, never its value.

import { isAbsolute, join } from 'node:path';

export const JSON_BODY_LIMIT = 256 * 1024;
export const PDF_BODY_LIMIT = 10 * 1024 * 1024;
export const DEFAULT_PORT = 8443;
/**
 * Request body timing (A-010 LBR4-1, SEC-10), enforced per request by src/server/body.ts:
 * - idle: at most BODY_IDLE_TIMEOUT_MS while waiting for the next body bytes;
 * - minimum rate: once the time spent waiting for body bytes passes BODY_RATE_GRACE_MS, the
 *   body must have arrived at an average of at least BODY_MIN_BYTES_PER_SECOND over that
 *   time (a 10 MiB upload therefore has at most 640 s).
 * Either is answered with 408 and a connection close.
 */
export const BODY_IDLE_TIMEOUT_MS = 10_000;
export const BODY_RATE_GRACE_MS = 10_000;
export const BODY_MIN_BYTES_PER_SECOND = 16 * 1024;
export const DATABASE_FILE = 'opensig.db';
/** The blob store's directory inside OPENSIG_DATA_DIR (the backup layout uses the same name). */
export const BLOBS_DIRECTORY = 'blobs';

export interface ServerConfig {
  readonly host: string;
  readonly port: number;
  /** Explicit origins, or null to use the server's own loopback origin once bound. */
  readonly allowedOrigins: readonly string[] | null;
  readonly relaySocket: string | null;
  readonly operatorAuthFile: string | null;
  readonly environment: string;
  readonly mailTransport: string | null;
  readonly spoolDir: string | null;
  readonly dataDir: string | null;
  /** The SQLite database holding the tenants table, or null when none is configured. */
  readonly database: string | null;
  /** The recipient challenge-HMAC key file (OPENSIG_CHALLENGE_KEY_FILE), or null when unset. */
  readonly challengeKeyFile: string | null;
  /** The blob store root, <OPENSIG_DATA_DIR>/blobs, or null without an absolute data directory. */
  readonly blobRoot: string | null;
  readonly limits: {
    readonly jsonBytes: number;
    readonly pdfBytes: number;
    readonly bodyIdleMs: number;
    readonly bodyRateGraceMs: number;
    readonly bodyMinBytesPerSecond: number;
  };
}

export class ServerConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ServerConfigError';
  }
}

const LOOPBACK = new Set(['127.0.0.1', '::1']);
const ORIGIN = /^https?:\/\/(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::\d{1,5})?$/;

function value(env: Readonly<Record<string, string | undefined>>, name: string): string | null {
  const raw = env[name];
  return raw === undefined || raw === '' ? null : raw;
}

export function loadServerConfig(env: Readonly<Record<string, string | undefined>>): ServerConfig {
  const host = value(env, 'OPENSIG_HOST') ?? '127.0.0.1';
  if (!LOOPBACK.has(host) && value(env, 'OPENSIG_ALLOW_NON_LOOPBACK_BIND') !== '1') {
    throw new ServerConfigError('OPENSIG_HOST is not a loopback address; set OPENSIG_ALLOW_NON_LOOPBACK_BIND=1 to bind it explicitly');
  }
  const portText = value(env, 'OPENSIG_PORT');
  let port = DEFAULT_PORT;
  if (portText !== null) {
    if (!/^\d{1,5}$/.test(portText) || Number(portText) > 65535) throw new ServerConfigError('OPENSIG_PORT must be an integer from 0 to 65535');
    port = Number(portText);
  }
  let allowedOrigins: string[] | null = null;
  const originsText = value(env, 'OPENSIG_ALLOWED_ORIGINS');
  if (originsText !== null) {
    allowedOrigins = originsText.split(',').map((origin) => origin.trim()).filter((origin) => origin.length > 0);
    if (allowedOrigins.length === 0 || !allowedOrigins.every((origin) => ORIGIN.test(origin))) {
      throw new ServerConfigError('OPENSIG_ALLOWED_ORIGINS must list exact origins (scheme://host[:port], no path)');
    }
  }
  const relaySocket = value(env, 'OPENSIG_RELAY_SOCKET');
  if (relaySocket !== null && (!isAbsolute(relaySocket) || relaySocket.length > 100)) {
    throw new ServerConfigError('OPENSIG_RELAY_SOCKET must be an absolute path of at most 100 characters');
  }
  const dataDir = value(env, 'OPENSIG_DATA_DIR');
  const database = value(env, 'OPENSIG_DATABASE') ?? (dataDir !== null && isAbsolute(dataDir) ? join(dataDir, DATABASE_FILE) : null);
  if (database !== null && !isAbsolute(database)) throw new ServerConfigError('OPENSIG_DATABASE must be an absolute path');
  const challengeKeyFile = value(env, 'OPENSIG_CHALLENGE_KEY_FILE');
  if (challengeKeyFile !== null && !isAbsolute(challengeKeyFile)) throw new ServerConfigError('OPENSIG_CHALLENGE_KEY_FILE must be an absolute path');
  return Object.freeze({
    host,
    port,
    allowedOrigins: allowedOrigins === null ? null : Object.freeze(allowedOrigins),
    relaySocket,
    operatorAuthFile: value(env, 'OPENSIG_OPERATOR_AUTH_FILE'),
    environment: value(env, 'OPENSIG_ENV') ?? 'development',
    mailTransport: value(env, 'OPENSIG_MAIL_TRANSPORT'),
    spoolDir: value(env, 'OPENSIG_SPOOL_DIR'),
    dataDir,
    database,
    challengeKeyFile,
    blobRoot: dataDir !== null && isAbsolute(dataDir) ? join(dataDir, BLOBS_DIRECTORY) : null,
    limits: Object.freeze({
      jsonBytes: JSON_BODY_LIMIT,
      pdfBytes: PDF_BODY_LIMIT,
      bodyIdleMs: BODY_IDLE_TIMEOUT_MS,
      bodyRateGraceMs: BODY_RATE_GRACE_MS,
      bodyMinBytesPerSecond: BODY_MIN_BYTES_PER_SECOND,
    }),
  });
}

/** The server's own origin for a bound loopback address. */
export function loopbackOrigin(host: string, port: number): string {
  return host.includes(':') ? `http://[${host}]:${port}` : `http://${host}:${port}`;
}
