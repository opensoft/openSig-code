// SPDX-License-Identifier: Apache-2.0
//
// Notification configuration from the environment (T032). Errors name the variable,
// never its value.
//
//   OPENSIG_MAIL_TRANSPORT        "spool" (default) or "smtp".
//   OPENSIG_SPOOL_DIR             absolute spool directory; default <repo>/var/spool
//                                 (the dev launcher sets it to that path).
//   OPENSIG_SMTP_HOST             smtp only, required: a loopback IP literal. Any other
//                                 relay is refused (relay_refused).
//   OPENSIG_SMTP_PORT             smtp only; default 25.
//   OPENSIG_SMTP_HELO             smtp only; EHLO name, default opensig.test.
//   OPENSIG_MAIL_FROM             sender address; default no-reply@opensig.test.
//   OPENSIG_PUBLIC_ORIGIN         origin of recipient links (https://host[:port], or
//                                 http:// on a loopback literal). Default: the loopback
//                                 server origin from OPENSIG_HOST/OPENSIG_PORT, unless the
//                                 port is 0 (then invitations are refused until set).
//   OPENSIG_MAIL_PILOT_FILE       absolute path of the owner's explicit pilot
//                                 configuration (policy.ts); without it only the
//                                 reserved test domains receive mail.
//   OPENSIG_MAIL_TENANT_LIMIT     accepted sends per tenant per window; default 100.
//   OPENSIG_MAIL_TENANT_WINDOW_SECONDS  window length; default 600.
//
// Refused outright: relay credentials (OPENSIG_SMTP_USER, _USERNAME, _PASS, _PASSWORD,
// _AUTH) because the MVP holds no SMTP credential, and SMTP settings while the transport
// is not smtp, so a half-configured relay never goes unnoticed.

import { isAbsolute } from 'node:path';

import { NotificationError } from './errors.ts';
import { parsePublicOrigin } from './content.ts';
import { loadPilotPolicy, parseAddress } from './policy.ts';
import type { ParsedAddress, PilotPolicy } from './policy.ts';
import { DEFAULT_TENANT_RATE_LIMIT, validRateLimit } from './rate-limit.ts';
import type { RateLimitOptions } from './rate-limit.ts';
import { validateRelay } from './smtp.ts';
import type { SmtpRelay } from './smtp.ts';
import { defaultSpoolDir, REPO_ROOT } from './spool.ts';

export const DEFAULT_MAIL_FROM = 'no-reply@opensig.test';

export interface NotificationConfig {
  readonly transport: 'spool' | 'smtp';
  /** Spool directory (spool transport), else null. */
  readonly spoolDir: string | null;
  /** Loopback relay (smtp transport), else null. */
  readonly relay: SmtpRelay | null;
  readonly from: ParsedAddress;
  readonly publicOrigin: string | null;
  readonly pilot: PilotPolicy | null;
  readonly rateLimit: RateLimitOptions;
}

type Env = Readonly<Record<string, string | undefined>>;

const CREDENTIAL = /^OPENSIG_SMTP_(?:USER|USERNAME|PASS|PASSWORD|AUTH)$/;
const SMTP_SETTING = /^OPENSIG_SMTP_/;

function value(env: Env, name: string): string | null {
  const raw = env[name];
  return raw === undefined || raw === '' ? null : raw;
}

function error(message: string): NotificationError {
  return new NotificationError('config_invalid', message);
}

function integer(env: Env, name: string, min: number, max: number): number | null {
  const raw = value(env, name);
  if (raw === null) return null;
  if (!/^\d{1,9}$/.test(raw) || Number(raw) < min || Number(raw) > max) throw error(`${name} must be an integer from ${min} to ${max}`);
  return Number(raw);
}

export function loadNotificationConfig(env: Env, options: { root?: string } = {}): NotificationConfig {
  const root = options.root ?? REPO_ROOT;
  for (const name of Object.keys(env).sort()) {
    if (CREDENTIAL.test(name) && value(env, name) !== null) throw error(`${name} is refused: relay authentication is not supported in the MVP`);
  }

  const transport = value(env, 'OPENSIG_MAIL_TRANSPORT') ?? 'spool';
  if (transport !== 'spool' && transport !== 'smtp') throw error('OPENSIG_MAIL_TRANSPORT must be "spool" or "smtp"');

  let spoolDir: string | null = null;
  let relay: SmtpRelay | null = null;
  if (transport === 'spool') {
    for (const name of Object.keys(env).sort()) {
      if (SMTP_SETTING.test(name) && value(env, name) !== null) throw error(`${name} is set but OPENSIG_MAIL_TRANSPORT is not "smtp"`);
    }
    spoolDir = value(env, 'OPENSIG_SPOOL_DIR') ?? defaultSpoolDir(root);
    if (!isAbsolute(spoolDir)) throw error('OPENSIG_SPOOL_DIR must be an absolute path');
  } else {
    const host = value(env, 'OPENSIG_SMTP_HOST');
    if (host === null) throw error('OPENSIG_SMTP_HOST is required when OPENSIG_MAIL_TRANSPORT is "smtp"');
    relay = validateRelay({
      host,
      port: integer(env, 'OPENSIG_SMTP_PORT', 1, 65535) ?? undefined,
      heloName: value(env, 'OPENSIG_SMTP_HELO') ?? undefined,
    });
  }

  let from: ParsedAddress;
  try {
    from = parseAddress(value(env, 'OPENSIG_MAIL_FROM') ?? DEFAULT_MAIL_FROM, 'OPENSIG_MAIL_FROM');
  } catch {
    throw error('OPENSIG_MAIL_FROM must be a plain mail address');
  }

  let publicOrigin: string | null = null;
  const originText = value(env, 'OPENSIG_PUBLIC_ORIGIN');
  if (originText !== null) {
    try {
      publicOrigin = parsePublicOrigin(originText);
    } catch {
      throw error('OPENSIG_PUBLIC_ORIGIN must be https://<host>[:port], or http:// on 127.0.0.1 or [::1]');
    }
  } else {
    const host = value(env, 'OPENSIG_HOST') ?? '127.0.0.1';
    const port = value(env, 'OPENSIG_PORT') ?? '8443';
    if (/^\d{1,5}$/.test(port) && Number(port) > 0 && Number(port) <= 65535) {
      if (host === '127.0.0.1') publicOrigin = `http://127.0.0.1:${Number(port)}`;
      else if (host === '::1') publicOrigin = `http://[::1]:${Number(port)}`;
    }
  }

  const pilotFile = value(env, 'OPENSIG_MAIL_PILOT_FILE');
  const pilot = pilotFile === null ? null : loadPilotPolicy(pilotFile);

  const limit = integer(env, 'OPENSIG_MAIL_TENANT_LIMIT', 1, 100_000) ?? DEFAULT_TENANT_RATE_LIMIT.limit;
  const windowSeconds = integer(env, 'OPENSIG_MAIL_TENANT_WINDOW_SECONDS', 1, 86_400);
  const rateLimit = { limit, windowMs: windowSeconds === null ? DEFAULT_TENANT_RATE_LIMIT.windowMs : windowSeconds * 1000 };
  if (!validRateLimit(rateLimit)) throw error('the tenant rate limit is out of range');

  return Object.freeze({ transport, spoolDir, relay, from, publicOrigin, pilot, rateLimit: Object.freeze(rateLimit) });
}
