// SPDX-License-Identifier: Apache-2.0
//
// Test support for the notifications tests (T032). Everything is synthetic and local:
// invitation tokens and codes are generated at runtime, addresses use reserved domains
// (.test, example.com/.org; example.net and .invalid stand in for "non-reserved"), spool
// directories are mkdtemp directories removed by cleanup(), and the SMTP relay is an
// in-process sink bound to 127.0.0.1 with an OS-chosen port. Nothing leaves loopback.

import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createLogger } from '../../src/server/redact.ts';

export const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const identities = JSON.parse(readFileSync(join(REPO, 'fixtures', 'synthetic', 'identities', 'identities.json'), 'utf8'));
export const TENANT_A = identities.tenants[0].id;
export const TENANT_B = identities.tenants[1].id;
export const ORIGIN = 'https://sign.alpha.test';
export const FROM = 'no-reply@opensig.test';
export const ENVELOPE_ID = 'env_synthetic_00000001';
export const RECIPIENT = 'recipient.two@alpha.test';
export const OPERATOR = 'sender@alpha.test';
export const START = Date.UTC(2026, 10, 8, 10, 0, 0);

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const temps = [];

/** A fresh 256-bit invitation token (base64url, 43 characters). */
export const newInvitation = () => randomBytes(32).toString('base64url');

/** A fresh 10-character Crockford base32 challenge code. */
export function newCode() {
  let out = '';
  for (const byte of randomBytes(10)) out += CROCKFORD[byte & 31];
  return out;
}

export function tempDir(label = 'notify') {
  const dir = mkdtempSync(join(tmpdir(), `opensig-${label}-`));
  temps.push(dir);
  return dir;
}

export function cleanup() {
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
}

export function captureLogger() {
  const lines = [];
  return { logger: createLogger((line) => lines.push(line)), lines };
}

export const quietLogger = () => createLogger(() => {});

export function makeClock(start = START) {
  let now = start;
  return { now: () => now, advance: (ms) => (now += ms) };
}

export const invitationRequest = (invitation, overrides = {}) => ({
  kind: 'recipient_invitation',
  tenant_id: TENANT_A,
  to: RECIPIENT,
  invitation,
  expires_at: '2026-11-15T10:00:00Z',
  ...overrides,
});

export const challengeRequest = (code, overrides = {}) => ({
  kind: 'recipient_challenge',
  tenant_id: TENANT_A,
  to: RECIPIENT,
  code,
  expires_at: '2026-11-08T10:10:00Z',
  ...overrides,
});

export const statusRequest = (overrides = {}) => ({
  kind: 'envelope_status',
  audience: 'operator',
  tenant_id: TENANT_A,
  to: OPERATOR,
  envelope_id: ENVELOPE_ID,
  envelope_version: 4,
  state: 'completed',
  occurred_at: '2026-11-08T10:05:00Z',
  ...overrides,
});

export function occurrences(text, value) {
  let count = 0;
  for (let index = text.indexOf(value); index !== -1; index = text.indexOf(value, index + 1)) count += 1;
  return count;
}

/** Split a rendered message into { head, body }. */
export function splitMessage(text) {
  const index = text.indexOf('\r\n\r\n');
  return { head: text.slice(0, index), body: text.slice(index + 4) };
}

export const isCode = (code) => (error) => {
  if (error?.name !== 'NotificationError' || error.code !== code) throw new Error(`expected NotificationError ${code}, got ${error?.name} ${error?.code}`);
  return true;
};

/**
 * An in-process SMTP sink on 127.0.0.1. `behavior`: rcptReply (default 250), garbage
 * (send a non-SMTP greeting), silent (never reply). Each connection is a session
 * { commands, rawData, data }; `data` is the message after removing dot-stuffing.
 */
export async function startSink(behavior = {}) {
  const sessions = [];
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    const session = { commands: [], rawData: null, data: null };
    sessions.push(session);
    if (behavior.silent) return;
    if (behavior.garbage) {
      socket.write('this is not an smtp server\r\n');
      return;
    }
    socket.write('220 sink.test ESMTP synthetic\r\n');
    let buffer = '';
    let dataLines = null;
    socket.on('data', (chunk) => {
      buffer += chunk.toString('latin1');
      for (let index = buffer.indexOf('\r\n'); index !== -1; index = buffer.indexOf('\r\n')) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        if (dataLines !== null) {
          if (line === '.') {
            session.rawData = dataLines;
            session.data = `${dataLines.map((item) => (item.startsWith('.') ? item.slice(1) : item)).join('\r\n')}\r\n`;
            dataLines = null;
            socket.write('250 2.0.0 queued\r\n');
          } else dataLines.push(line);
          continue;
        }
        session.commands.push(line);
        const verb = line.slice(0, 4).toUpperCase();
        if (verb === 'EHLO') socket.write('250-sink.test\r\n250 8BITMIME\r\n');
        else if (verb === 'MAIL') socket.write('250 2.1.0 ok\r\n');
        else if (verb === 'RCPT') socket.write(`${behavior.rcptReply ?? '250 2.1.5 ok'}\r\n`);
        else if (verb === 'DATA') {
          dataLines = [];
          socket.write('354 end with <CRLF>.<CRLF>\r\n');
        } else if (verb === 'QUIT') socket.end('221 2.0.0 bye\r\n');
        else socket.write('500 5.5.1 unrecognized\r\n');
      }
    });
  });
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  return {
    port: server.address().port,
    sessions,
    close: () =>
      new Promise((resolveClose) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolveClose());
      }),
  };
}

/** A loopback port with nothing listening (bound, then released). */
export async function closedPort() {
  const server = createServer();
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  const { port } = server.address();
  await new Promise((resolveClose) => server.close(resolveClose));
  return port;
}

export const tick = (ms = 50) => new Promise((resolveTick) => setTimeout(resolveTick, ms));
