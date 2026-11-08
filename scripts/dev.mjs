#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig local development launcher (T004).
//
//   node scripts/dev.mjs [--port <n>] [--host 127.0.0.1] [--check]
//
// - Binds only 127.0.0.1. Any other bind address is refused, including non-loopback
//   addresses (0.0.0.0, ::, routable addresses, host names) and loopback aliases
//   (localhost, ::1, 127.0.0.2, ...). The address comes from --host or OPENSIG_HOST.
// - Refuses SMTP and mail-relay settings: any environment variable whose name contains
//   SMTP, the MAIL/MAILER/EMAIL relay variables, and an OPENSIG_MAIL_TRANSPORT other
//   than "spool". Development mail goes only to the gitignored file spool var/spool/.
//   Refusals name the variable, never its value.
// - Refuses to run on any Node version other than the pinned .node-version.
// - Starts src/server/main.ts (T031) once it exists, on the pinned runtime, with a
//   cleared environment: a small base allowlist, every OPENSIG_* variable whose name
//   does not look like a secret, and the launcher-controlled variables below. Secrets
//   are passed by 0600 file path or inherited descriptor, never through the environment.
//   Termination signals are forwarded to the server and its exit status is returned.
// - No container composition exists; this script is the whole dev launcher.
//
// Environment contract for src/server/main.ts (always set by this launcher):
//   OPENSIG_HOST=127.0.0.1         bind address
//   OPENSIG_PORT=<n>               bind port (default 8443; 0 asks the OS for a free port)
//   OPENSIG_ENV=development
//   OPENSIG_MAIL_TRANSPORT=spool   file spool only
//   OPENSIG_SPOOL_DIR=<root>/var/spool
//   OPENSIG_DATA_DIR=<root>/var/data
//   NODE_ENV=development
//
// Exit status: 0 server exited 0 (or --check/--help succeeded), 1 configuration refused,
// 2 usage error, 3 server entrypoint absent, otherwise the server's status (128 + signal
// number when it was killed by a signal).

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, realpathSync } from 'node:fs';
import { constants as osConstants } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const LOOPBACK_HOST = '127.0.0.1';
export const DEFAULT_PORT = 8443;
export const SERVER_ENTRY = 'src/server/main.ts';
export const STATUS = Object.freeze({ OK: 0, REFUSED: 1, USAGE: 2, NO_SERVER: 3 });

const BASE_ENV = Object.freeze(['PATH', 'HOME', 'LANG', 'LANGUAGE', 'TZ', 'TMPDIR', 'TERM']);
const CONTROLLED = Object.freeze([
  'OPENSIG_HOST',
  'OPENSIG_PORT',
  'OPENSIG_ENV',
  'OPENSIG_MAIL_TRANSPORT',
  'OPENSIG_SPOOL_DIR',
  'OPENSIG_DATA_DIR',
]);
const SECRET_NAME = /(?:SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|CREDENTIALS?|_KEY|_PEM|COOKIE)$/i;
const MAIL_RELAY_NAME = /^(?:OPENSIG_)?(?:MAIL|MAILER|EMAIL)_(?:URL|DSN|HOST|SERVER|RELAY|PORT|USER|USERNAME|PASS|PASSWORD)$/i;

class UsageError extends Error {}

function isLoopbackAlias(host) {
  const bare = host.replace(/^\[(.*)\]$/, '$1').toLowerCase();
  return (
    bare === 'localhost' ||
    bare.endsWith('.localhost') ||
    bare === '::1' ||
    /^0*:(?:0*:)*0*1$/.test(bare) ||
    /^127(?:\.\d{1,3}){3}$/.test(bare) ||
    /^::ffff:127(?:\.\d{1,3}){3}$/.test(bare)
  );
}

function hostProblem(source, host) {
  if (host === LOOPBACK_HOST) return null;
  const kind = isLoopbackAlias(host) ? 'loopback alias' : 'non-loopback bind address';
  return `${kind} ${JSON.stringify(host)} from ${source} is refused: the dev launcher binds only ${LOOPBACK_HOST}`;
}

function parsePort(text) {
  if (!/^\d{1,5}$/.test(text)) return null;
  const port = Number(text);
  return port <= 65535 ? port : null;
}

/** Parse argv into { host?, port?, check, help }. Throws UsageError. */
export function parseArgs(argv) {
  const options = { host: undefined, port: undefined, check: false, help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--check') options.check = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--host' || arg === '--port') {
      const key = arg.slice(2);
      if (options[key] !== undefined) throw new UsageError(`${arg} given more than once`);
      if (index + 1 >= argv.length) throw new UsageError(`${arg} needs a value`);
      const value = argv[index + 1];
      index += 1;
      if (key === 'port') {
        const port = parsePort(value);
        if (port === null) throw new UsageError(`--port must be an integer from 0 to 65535`);
        options.port = port;
      } else options.host = value;
    } else throw new UsageError(`unknown argument: ${arg}`);
  }
  return options;
}

/** Names of SMTP and mail-relay settings present in `env` (values are never returned). */
export function mailSettingProblems(env) {
  const problems = [];
  for (const name of Object.keys(env).sort()) {
    const value = env[name];
    if (value === undefined || String(value).trim() === '') continue;
    if (name === 'OPENSIG_MAIL_TRANSPORT') {
      if (value !== 'spool') problems.push(`${name} is refused unless it is "spool": the dev launcher uses only the file spool`);
    } else if (/SMTP/i.test(name) || MAIL_RELAY_NAME.test(name)) {
      problems.push(`${name} is set: SMTP and mail-relay settings are refused; development mail goes to the file spool only`);
    }
  }
  return problems;
}

/**
 * Resolve the launcher configuration.
 * Returns { ok: true, config } or { ok: false, status, problems }.
 */
export function resolveDevConfig({ argv = [], env = {}, root = ROOT, version = process.version } = {}) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    if (error instanceof UsageError) return { ok: false, status: STATUS.USAGE, problems: [error.message] };
    throw error;
  }
  const problems = [];

  let pinned = null;
  try {
    pinned = `v${readFileSync(join(root, '.node-version'), 'utf8').trim()}`;
  } catch {
    problems.push('.node-version is unreadable, so the pinned runtime cannot be checked');
  }
  if (pinned !== null && version !== pinned) {
    problems.push(`runtime ${version} differs from the pinned ${pinned}; put tools/node/bin first on PATH`);
  }

  if (options.host !== undefined) {
    const problem = hostProblem('--host', options.host);
    if (problem) problems.push(problem);
  }
  const envHost = env.OPENSIG_HOST;
  if (envHost !== undefined && envHost !== '') {
    const problem = hostProblem('OPENSIG_HOST', envHost);
    if (problem) problems.push(problem);
  }

  let port = DEFAULT_PORT;
  if (options.port !== undefined) port = options.port;
  else if (env.OPENSIG_PORT !== undefined && env.OPENSIG_PORT !== '') {
    const parsed = parsePort(env.OPENSIG_PORT);
    if (parsed === null) problems.push('OPENSIG_PORT must be an integer from 0 to 65535');
    else port = parsed;
  }

  problems.push(...mailSettingProblems(env));

  if (problems.length > 0) return { ok: false, status: STATUS.REFUSED, problems };
  return {
    ok: true,
    config: {
      root,
      host: LOOPBACK_HOST,
      port,
      check: options.check,
      help: options.help,
      mailTransport: 'spool',
      spoolDir: join(root, 'var', 'spool'),
      dataDir: join(root, 'var', 'data'),
      entry: join(root, SERVER_ENTRY),
    },
  };
}

/** The server environment: base allowlist, non-secret OPENSIG_* settings, controlled values. */
export function serverEnv(config, env) {
  const child = {};
  for (const name of BASE_ENV) if (env[name] !== undefined) child[name] = env[name];
  for (const name of Object.keys(env).sort()) if (name.startsWith('LC_')) child[name] = env[name];
  const dropped = [];
  for (const name of Object.keys(env).sort()) {
    if (!name.startsWith('OPENSIG_') || CONTROLLED.includes(name)) continue;
    if (SECRET_NAME.test(name)) dropped.push(name);
    else child[name] = env[name];
  }
  Object.assign(child, {
    OPENSIG_HOST: config.host,
    OPENSIG_PORT: String(config.port),
    OPENSIG_ENV: 'development',
    OPENSIG_MAIL_TRANSPORT: config.mailTransport,
    OPENSIG_SPOOL_DIR: config.spoolDir,
    OPENSIG_DATA_DIR: config.dataDir,
    NODE_ENV: 'development',
  });
  return { env: child, dropped };
}

const USAGE = 'usage: node scripts/dev.mjs [--port <n>] [--host 127.0.0.1] [--check]';

function out(line) {
  process.stdout.write(`dev: ${line}\n`);
}

function err(line) {
  process.stderr.write(`dev: ${line}\n`);
}

export function main(argv = process.argv.slice(2), env = process.env) {
  const resolved = resolveDevConfig({ argv, env });
  if (!resolved.ok) {
    for (const problem of resolved.problems) err(`${resolved.status === STATUS.USAGE ? 'usage error' : 'refused'}: ${problem}`);
    if (resolved.status === STATUS.USAGE) err(USAGE);
    process.exitCode = resolved.status;
    return;
  }
  const { config } = resolved;
  if (config.help) {
    out(USAGE);
    process.exitCode = STATUS.OK;
    return;
  }
  const present = existsSync(config.entry);
  if (config.check) {
    out(`bind ${config.host}:${config.port}`);
    out('mail transport spool -> var/spool');
    out(`server entrypoint ${SERVER_ENTRY} ${present ? 'present' : 'absent (created by T031)'}`);
    out('CHECK OK');
    process.exitCode = STATUS.OK;
    return;
  }
  if (!present) {
    err(`${SERVER_ENTRY} does not exist yet (created by T031); nothing was started`);
    process.exitCode = STATUS.NO_SERVER;
    return;
  }

  const { env: childEnv, dropped } = serverEnv(config, env);
  for (const name of dropped) err(`not passed to the server (secret-like name; use a 0600 file path instead): ${name}`);
  mkdirSync(config.spoolDir, { recursive: true, mode: 0o700 });
  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });

  out(`starting ${SERVER_ENTRY} on ${config.host}:${config.port} (mail: spool)`);
  const child = spawn(process.execPath, [config.entry], { cwd: config.root, env: childEnv, stdio: 'inherit' });
  const signals = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  const forward = (signal) => {
    if (child.exitCode === null && child.signalCode === null) child.kill(signal);
  };
  for (const signal of signals) process.on(signal, forward);
  const release = () => {
    for (const signal of signals) process.off(signal, forward);
  };
  child.on('error', (error) => {
    release();
    err(`could not start the server: ${error.message}`);
    process.exitCode = STATUS.REFUSED;
  });
  child.on('exit', (code, signal) => {
    release();
    process.exitCode = code ?? 128 + (osConstants.signals[signal] ?? 0);
  });
}

function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) main();
