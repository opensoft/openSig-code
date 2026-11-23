// SPDX-License-Identifier: Apache-2.0
//
// Guarded SMTP adapter (T032). It speaks plain SMTP (RFC 5321: EHLO, MAIL, RCPT, DATA,
// QUIT) to a loopback relay only:
//
// - The relay host must be a loopback IP literal. Anything else is refused when the
//   transport is created and again before every connection, so no socket is ever opened
//   toward another host. After connecting, the peer address is checked again.
// - Every recipient is re-checked against the reserved-domain / pilot policy before the
//   connection is opened (the notifier checks it too; this is the adapter's own guard).
// - No relay authentication and no STARTTLS: the MVP holds no SMTP credential, and the
//   loopback hop never leaves the host.
// - Replies are bounded (2 KiB per line, 100 lines per reply, 64 KiB per session) and the
//   whole session has one deadline. A refusal reports the reply code only, never the
//   reply text, which may echo an address.
// - The message is sent with dot-stuffing; it must already be 7-bit ASCII with CRLF line
//   endings (renderMessage guarantees this).

import { connect as netConnect } from 'node:net';
import type { Socket } from 'node:net';

import { NotificationError } from './errors.ts';
import { assertLoopbackRelay, assertRecipientAllowed, isHostName, isLoopbackAddress, parseAddress } from './policy.ts';
import type { PilotPolicy } from './policy.ts';
import type { OutboundMessage, Transport } from './transport.ts';

export interface SmtpRelay {
  /** Loopback IP literal. */
  readonly host: string;
  readonly port: number;
  /** Name sent in EHLO. */
  readonly heloName: string;
  /** Deadline for one whole delivery session. */
  readonly timeoutMs: number;
}

export interface SmtpRelayInput {
  readonly host: unknown;
  readonly port?: unknown;
  readonly heloName?: unknown;
  readonly timeoutMs?: unknown;
}

export type ConnectFn = (options: { host: string; port: number }) => Socket;

export const DEFAULT_SMTP_PORT = 25;
export const DEFAULT_HELO_NAME = 'opensig.test';
export const DEFAULT_SMTP_TIMEOUT_MS = 10_000;

const MAX_REPLY_LINE = 2048;
const MAX_REPLY_LINES = 100;
const MAX_SESSION_READ = 64 * 1024;

function configError(message: string): NotificationError {
  return new NotificationError('config_invalid', message);
}

/** Validate relay settings. The loopback rule is checked first and fails with relay_refused. */
export function validateRelay(input: SmtpRelayInput): SmtpRelay {
  assertLoopbackRelay(input.host);
  const port = input.port ?? DEFAULT_SMTP_PORT;
  if (typeof port !== 'number' || !Number.isSafeInteger(port) || port < 1 || port > 65535) throw configError('the SMTP port must be an integer from 1 to 65535');
  const heloName = input.heloName ?? DEFAULT_HELO_NAME;
  if (typeof heloName !== 'string' || !isHostName(heloName)) throw configError('the EHLO name must be a host name');
  const timeoutMs = input.timeoutMs ?? DEFAULT_SMTP_TIMEOUT_MS;
  if (typeof timeoutMs !== 'number' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) {
    throw configError('the SMTP timeout must be 100 to 120000 ms');
  }
  return Object.freeze({ host: input.host as string, port, heloName, timeoutMs });
}

function failed(message: string, smtpStatus?: number): NotificationError {
  return new NotificationError('delivery_failed', message, smtpStatus === undefined ? {} : { smtpStatus });
}

/** Dot-stuff a CRLF message (RFC 5321 §4.5.2). Throws on bare CR/LF or non-ASCII bytes. */
export function dotStuff(data: Buffer): Buffer {
  for (const byte of data) if (byte > 0x7e || (byte < 0x20 && byte !== 0x0d && byte !== 0x0a)) throw failed('the message is not 7-bit ASCII text');
  const text = data.toString('ascii');
  if (/\r(?!\n)|(?<!\r)\n/.test(text) || !text.endsWith('\r\n')) throw failed('the message must use CRLF line endings');
  const lines = text.slice(0, -2).split('\r\n');
  return Buffer.from(`${lines.map((line) => (line.startsWith('.') ? `.${line}` : line)).join('\r\n')}\r\n`, 'ascii');
}

interface ReplyReader {
  next(): Promise<number>;
  fail(error: NotificationError): void;
}

function replyReader(socket: Socket): ReplyReader {
  let buffer = '';
  let total = 0;
  let lines = 0;
  const codes: number[] = [];
  let failure: NotificationError | null = null;
  let waiter: { resolve: (code: number) => void; reject: (error: NotificationError) => void } | null = null;

  const fail = (error: NotificationError): void => {
    if (failure === null) failure = error;
    if (waiter !== null) {
      const pending = waiter;
      waiter = null;
      pending.reject(failure);
    }
    socket.destroy();
  };
  const flush = (): void => {
    if (waiter !== null && codes.length > 0) {
      const pending = waiter;
      waiter = null;
      pending.resolve(codes.shift() as number);
    }
  };

  socket.on('data', (chunk: Buffer) => {
    total += chunk.length;
    if (total > MAX_SESSION_READ) return fail(failed('the relay sent more data than a session allows'));
    buffer += chunk.toString('latin1');
    for (let newline = buffer.indexOf('\n'); newline !== -1; newline = buffer.indexOf('\n')) {
      const line = buffer.slice(0, newline).replace(/\r$/, '');
      buffer = buffer.slice(newline + 1);
      const match = /^([2-5]\d\d)(?:([ -])[\x20-\x7e]*)?$/.exec(line);
      if (match === null || line.length > MAX_REPLY_LINE) return fail(failed('the relay sent a malformed reply'));
      lines += 1;
      if (lines > MAX_REPLY_LINES) return fail(failed('the relay sent an overlong reply'));
      if (match[2] !== '-') {
        codes.push(Number(match[1]));
        lines = 0;
      }
    }
    if (buffer.length > MAX_REPLY_LINE) return fail(failed('the relay sent a malformed reply'));
    flush();
  });
  socket.on('error', () => fail(failed('the relay connection failed')));
  socket.on('close', () => fail(failed('the relay closed the connection')));

  return {
    next() {
      if (failure !== null) return Promise.reject(failure);
      if (codes.length > 0) return Promise.resolve(codes.shift() as number);
      return new Promise((resolve, reject) => {
        waiter = { resolve, reject };
      });
    },
    fail,
  };
}

export interface SmtpTransportOptions {
  readonly relay: SmtpRelayInput;
  readonly pilot: PilotPolicy | null;
  /** Socket factory (default node:net connect); injectable for tests. */
  readonly connect?: ConnectFn;
}

export function createSmtpTransport(options: SmtpTransportOptions): Transport {
  const relay = validateRelay(options.relay);
  const pilot = options.pilot;
  const connect: ConnectFn = options.connect ?? ((target) => netConnect(target));

  return Object.freeze({
    name: 'smtp' as const,
    async deliver(message: OutboundMessage): Promise<void> {
      const from = parseAddress(message.from, 'from');
      const to = parseAddress(message.to, 'to');
      assertRecipientAllowed(to, pilot);
      const payload = dotStuff(message.data);
      assertLoopbackRelay(relay.host);

      const socket = connect({ host: relay.host, port: relay.port });
      const reader = replyReader(socket);
      const timer = setTimeout(() => reader.fail(failed('the relay did not finish within the deadline')), relay.timeoutMs);
      timer.unref();
      socket.once('connect', () => {
        if (typeof socket.remoteAddress !== 'string' || !isLoopbackAddress(socket.remoteAddress)) {
          reader.fail(new NotificationError('relay_refused', 'the SMTP connection did not reach a loopback address'));
        }
      });
      const step = async (accepted: readonly number[], name: string): Promise<void> => {
        const code = await reader.next();
        if (!accepted.includes(code)) throw failed(`the relay refused the ${name} step`, code);
      };
      const send = (line: string): void => {
        socket.write(`${line}\r\n`, 'ascii');
      };
      try {
        await step([220], 'greeting');
        send(`EHLO ${relay.heloName}`);
        await step([250], 'EHLO');
        send(`MAIL FROM:<${from.address}>`);
        await step([250], 'MAIL');
        send(`RCPT TO:<${to.address}>`);
        await step([250, 251], 'RCPT');
        send('DATA');
        await step([354], 'DATA');
        socket.write(payload);
        socket.write('.\r\n', 'ascii');
        await step([250], 'message');
        send('QUIT');
        await step([221], 'QUIT').catch(() => undefined);
        socket.end();
      } catch (error) {
        socket.destroy();
        if (error instanceof NotificationError) throw error;
        throw failed('the relay session failed');
      } finally {
        clearTimeout(timer);
      }
    },
  });
}
