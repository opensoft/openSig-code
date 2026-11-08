// SPDX-License-Identifier: Apache-2.0
//
// openSig HTTP server entrypoint (T031). Started by scripts/dev.mjs (T004) or directly:
//
//   node src/server/main.ts            (environment: see src/server/config.ts)
//
// - Binds OPENSIG_HOST:OPENSIG_PORT, default 127.0.0.1:8443 (loopback only unless the
//   owner opts in explicitly).
// - When OPENSIG_RELAY_SOCKET is set, also listens on that Unix-domain socket (mode 0600)
//   for the isolated Hermes relay. That listener serves operator routes only, so recipient
//   and anonymous routes (approval, sessions, the review shell) are unreachable through it.
// - Operator authentication uses the T005 configuration in OPENSIG_OPERATOR_AUTH_FILE;
//   without it every operator request is 401 (fail closed).
// - The review shell and static assets come from src/server/static.ts (T035) when that
//   module exists. It must export createStaticHandler({ config }) returning a
//   StaticHandler (src/server/types.ts).
// - Logs are JSON lines through the central redactor; the first is `listening`.
// - SIGINT and SIGTERM close both listeners, remove the socket file and exit 0.

import { chmodSync, existsSync, lstatSync, readFileSync, realpathSync, unlinkSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';

import { loadOperatorAuthConfig } from '../api/auth/config.ts';
import { createOperatorAuthenticator, type OperatorAuthenticator } from '../api/auth/operator.ts';
import { ROUTES } from '../api/routes.ts';
import { createApp } from './app.ts';
import { loadServerConfig, loopbackOrigin, ServerConfigError, type ServerConfig } from './config.ts';
import { createLogger, type LogSink, type Logger } from './redact.ts';
import type { StaticHandler } from './types.ts';

export interface RunningServer {
  readonly host: string;
  readonly port: number;
  readonly relaySocket: string | null;
  readonly allowedOrigins: ReadonlySet<string>;
  close(): Promise<void>;
}

function hardened(server: Server): Server {
  server.headersTimeout = 20_000;
  server.requestTimeout = 120_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 100;
  return server;
}

function listen(server: Server, target: { host: string; port: number } | { path: string }): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(target, () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });
}

function loadAuthenticator(config: ServerConfig, logger: Logger): OperatorAuthenticator | null {
  if (config.operatorAuthFile === null) {
    logger.warn('operator_auth_not_configured', { effect: 'every operator request is 401' });
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(config.operatorAuthFile, 'utf8'));
  } catch {
    throw new ServerConfigError('OPENSIG_OPERATOR_AUTH_FILE is not a readable JSON file');
  }
  return createOperatorAuthenticator(loadOperatorAuthConfig(parsed));
}

async function loadStaticHandler(config: ServerConfig): Promise<StaticHandler | null> {
  const url = new URL('./static.ts', import.meta.url);
  if (!existsSync(fileURLToPath(url))) return null;
  const module = (await import(url.href)) as { createStaticHandler?: (options: { config: ServerConfig }) => StaticHandler };
  return typeof module.createStaticHandler === 'function' ? module.createStaticHandler({ config }) : null;
}

function prepareSocketPath(path: string): void {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    return;
  }
  if (!stat.isSocket()) throw new ServerConfigError('OPENSIG_RELAY_SOCKET names an existing file that is not a socket');
  unlinkSync(path);
}

/** Start the server from `env`. Rejects on invalid configuration or a bind failure. */
export async function startServer(env: Readonly<Record<string, string | undefined>> = process.env, options: { logSink?: LogSink } = {}): Promise<RunningServer> {
  const config = loadServerConfig(env);
  const logger = createLogger(options.logSink);
  const authenticator = loadAuthenticator(config, logger);
  const staticHandler = await loadStaticHandler(config);
  const allowedOrigins = new Set<string>(config.allowedOrigins ?? []);

  if (config.relaySocket !== null) prepareSocketPath(config.relaySocket);

  const app = createApp({ routes: ROUTES, config, logger, authenticator, allowedOrigins, staticHandler });
  const server = hardened(createServer(app.handle));
  await listen(server, { host: config.host, port: config.port });
  const address = server.address() as AddressInfo;
  if (config.allowedOrigins === null) allowedOrigins.add(loopbackOrigin(address.address, address.port));

  let relay: Server | null = null;
  if (config.relaySocket !== null) {
    try {
      const relayApp = createApp({ routes: ROUTES, config, logger: logger.child({ listener: 'relay' }), authenticator, allowedOrigins, surface: 'relay' });
      relay = hardened(createServer(relayApp.handle));
      await listen(relay, { path: config.relaySocket });
      chmodSync(config.relaySocket, 0o600);
    } catch (error) {
      if (relay !== null) await closeServer(relay);
      await closeServer(server);
      throw error;
    }
  }

  logger.info('listening', {
    host: address.address,
    port: address.port,
    relay_socket: config.relaySocket !== null,
    operator_auth: authenticator !== null,
    static_shell: staticHandler !== null,
    environment: config.environment,
  });

  let closed = false;
  return {
    host: address.address,
    port: address.port,
    relaySocket: config.relaySocket,
    allowedOrigins,
    async close(): Promise<void> {
      if (closed) return;
      closed = true;
      await closeServer(server);
      if (relay !== null) {
        await closeServer(relay);
        try {
          unlinkSync(config.relaySocket as string);
        } catch {
          // already removed
        }
      }
      logger.info('closed', {});
    },
  };
}

async function main(): Promise<void> {
  let running: RunningServer;
  try {
    running = await startServer();
  } catch (error) {
    const message = error instanceof Error && error.name.endsWith('ConfigError') ? error.message : 'the server could not start';
    process.stderr.write(`opensig: ${message}\n`);
    process.exitCode = 1;
    return;
  }
  const stop = (): void => {
    running.close().then(
      () => {
        process.exitCode = 0;
      },
      () => {
        process.exitCode = 1;
      },
    );
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

function invokedDirectly(): boolean {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) await main();
