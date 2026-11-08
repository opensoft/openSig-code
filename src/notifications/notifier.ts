// SPDX-License-Identifier: Apache-2.0
//
// The notifier (T032): the one entry point for outbound mail. For every request it
//
//   1. validates the request and renders its fixed template (content.ts);
//   2. checks the recipient domain against the reserved list and the owner pilot list;
//   3. renders the RFC 5322 message and runs the content guards: recipient links carry the
//      invitation only in the URL fragment; operator and service mail carry no link or
//      code, and no capability value this notifier has mailed to a recipient;
//   4. takes one unit of the tenant's rate-limit budget (a refused request takes none);
//   5. hands the message to the transport (spool or loopback SMTP).
//
// The caller gets a receipt with status, message id and transport only: never the
// address, subject, body, link, code or a spool path. Logs record the kind, audience,
// tenant, transport, message id and recipient domain, never the address or any content.
//
// Create one notifier per process (for example in the server's `locals`) so the rate
// limit and the capability ledger cover every request.

import { createHash, randomBytes } from 'node:crypto';

import { createLogger } from '../server/redact.ts';
import type { Logger } from '../server/redact.ts';
import { assertContent, composeNotification, parsePublicOrigin, renderMessage } from './content.ts';
import type { ComposedMessage, NotificationRequest } from './content.ts';
import type { NotificationConfig } from './config.ts';
import { NotificationError } from './errors.ts';
import { assertRecipientAllowed, parseAddress } from './policy.ts';
import type { ParsedAddress, PilotPolicy } from './policy.ts';
import { createTenantRateLimiter, DEFAULT_TENANT_RATE_LIMIT } from './rate-limit.ts';
import type { RateLimitOptions } from './rate-limit.ts';
import { createSmtpTransport } from './smtp.ts';
import type { ConnectFn } from './smtp.ts';
import { createSpoolTransport } from './spool.ts';
import type { Transport } from './transport.ts';

export interface DeliveryReceipt {
  readonly status: 'accepted';
  readonly message_id: string;
  readonly transport: 'spool' | 'smtp';
}

export interface Notifier {
  readonly transport: 'spool' | 'smtp';
  send(request: NotificationRequest): Promise<DeliveryReceipt>;
}

export interface NotifierOptions {
  readonly transport: Transport;
  readonly from: ParsedAddress | string;
  /** Origin of recipient links, from deployment configuration. */
  readonly publicOrigin: string | null;
  readonly pilot?: PilotPolicy | null;
  readonly rateLimit?: RateLimitOptions;
  readonly logger?: Logger;
  /** Clock in epoch milliseconds (injectable for tests). */
  readonly now?: () => number;
}

const LEDGER_SIZE = 4096;
const KINDS = new Set(['recipient_invitation', 'recipient_challenge', 'envelope_status']);

/**
 * SHA-256 digests of the capability values mailed to recipients by this process (bounded,
 * oldest first out). Operator and service mail is refused if any token-character window
 * of it matches, which catches a capability passed where an identifier was expected.
 */
function capabilityLedger() {
  const digests = new Set<string>();
  const order: string[] = [];
  const lengths = new Map<number, number>();
  const digest = (value: string) => createHash('sha256').update(value, 'ascii').digest('hex');
  return {
    add(value: string): void {
      const key = `${value.length}:${digest(value)}`;
      if (digests.has(key)) return;
      digests.add(key);
      order.push(key);
      lengths.set(value.length, (lengths.get(value.length) ?? 0) + 1);
      if (order.length > LEDGER_SIZE) {
        const oldest = order.shift() as string;
        digests.delete(oldest);
        const length = Number(oldest.slice(0, oldest.indexOf(':')));
        const left = (lengths.get(length) ?? 1) - 1;
        if (left === 0) lengths.delete(length);
        else lengths.set(length, left);
      }
    },
    /** True when any window of a token run in `text` is a recorded capability. */
    seenIn(text: string): boolean {
      if (digests.size === 0) return false;
      for (const run of text.match(/[A-Za-z0-9_-]+/g) ?? []) {
        for (const length of lengths.keys()) {
          for (let start = 0; start + length <= run.length; start += 1) {
            if (digests.has(`${length}:${digest(run.slice(start, start + length))}`)) return true;
          }
        }
      }
      return false;
    },
  };
}

function knownKind(request: unknown): string | undefined {
  if (request === null || typeof request !== 'object') return undefined;
  const kind = (request as { kind?: unknown }).kind;
  return typeof kind === 'string' && KINDS.has(kind) ? kind : undefined;
}

export function createNotifier(options: NotifierOptions): Notifier {
  let from: ParsedAddress;
  try {
    from = typeof options.from === 'string' ? parseAddress(options.from, 'from') : parseAddress(options.from.address, 'from');
  } catch {
    throw new NotificationError('config_invalid', 'the sender address is not a plain mail address');
  }
  const publicOrigin = options.publicOrigin === null ? null : parsePublicOrigin(options.publicOrigin);
  const pilot = options.pilot ?? null;
  const now = options.now ?? Date.now;
  const limiter = createTenantRateLimiter(options.rateLimit ?? DEFAULT_TENANT_RATE_LIMIT, now);
  const logger = options.logger ?? createLogger(undefined, { component: 'notifications' });
  const transport = options.transport;
  const ledger = capabilityLedger();

  return Object.freeze({
    transport: transport.name,
    async send(request: NotificationRequest): Promise<DeliveryReceipt> {
      let composed: ComposedMessage | null = null;
      try {
        composed = composeNotification(request, publicOrigin);
        assertRecipientAllowed(composed.to, pilot);
        const date = new Date(now());
        const messageId = randomBytes(16).toString('hex');
        const data = renderMessage(composed, { from, messageId, date });
        assertContent(composed, data);
        if (composed.audience !== 'recipient' && ledger.seenIn(data.toString('ascii'))) {
          throw new NotificationError('content_refused', 'operator and service notifications must not contain a capability value mailed to a recipient');
        }
        const decision = limiter.take(composed.tenantId);
        if (!decision.ok) {
          throw new NotificationError('rate_limited', 'the tenant notification rate limit is exhausted', {
            retryAfterSeconds: Math.ceil(decision.retryAfterMs / 1000),
          });
        }
        for (const capability of composed.capabilities) ledger.add(capability);
        await transport.deliver({ from: from.address, to: composed.to.address, data, messageId, date });
        logger.info('notification_accepted', {
          kind: composed.kind,
          audience: composed.audience,
          tenant_id: composed.tenantId,
          transport: transport.name,
          message_id: messageId,
          recipient_domain: composed.to.domain,
        });
        return Object.freeze({ status: 'accepted' as const, message_id: messageId, transport: transport.name });
      } catch (error) {
        const failure =
          error instanceof NotificationError ? error : new NotificationError('delivery_failed', 'the notification could not be delivered', { cause: error });
        logger.warn('notification_refused', {
          reason: failure.code,
          field: failure.field,
          kind: composed?.kind ?? knownKind(request),
          audience: composed?.audience,
          tenant_id: composed?.tenantId,
          transport: transport.name,
          smtp_status: failure.smtpStatus,
          retry_after_seconds: failure.retryAfterSeconds,
        });
        throw failure;
      }
    },
  });
}

export interface NotifierRuntime {
  readonly logger?: Logger;
  readonly now?: () => number;
  /** Socket factory for the SMTP transport (tests only). */
  readonly connect?: ConnectFn;
  /** Repository root for the spool location rule. */
  readonly root?: string;
}

/** Build the configured transport and notifier. */
export function createNotifierFromConfig(config: NotificationConfig, runtime: NotifierRuntime = {}): Notifier {
  let transport: Transport;
  if (config.transport === 'spool') {
    if (config.spoolDir === null) throw new NotificationError('config_invalid', 'the spool transport needs a spool directory');
    transport = createSpoolTransport({ dir: config.spoolDir, ...(runtime.root === undefined ? {} : { root: runtime.root }) });
  } else {
    if (config.relay === null) throw new NotificationError('config_invalid', 'the smtp transport needs a relay');
    transport = createSmtpTransport({ relay: config.relay, pilot: config.pilot, ...(runtime.connect === undefined ? {} : { connect: runtime.connect }) });
  }
  return createNotifier({
    transport,
    from: config.from,
    publicOrigin: config.publicOrigin,
    pilot: config.pilot,
    rateLimit: config.rateLimit,
    ...(runtime.logger === undefined ? {} : { logger: runtime.logger }),
    ...(runtime.now === undefined ? {} : { now: runtime.now }),
  });
}
