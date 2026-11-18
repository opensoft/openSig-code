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
//   without it every operator request is 401 (fail closed). With it, the tenant role policy
//   comes from the tenants table in OPENSIG_DATABASE (src/server/tenants.ts, SEC-07), and
//   the server refuses to start when the database is missing or disagrees with the file.
// - Startup logs the authenticator's policy state (`operator_auth`, and `operator_policy` on
//   the `listening` line; SEC-09): enforced or not configured, the policy source and the
//   tenant ids. Never a key, token, secret or the file contents.
// - The review shell and static assets come from src/server/static.ts (T035) when that
//   module exists. It must export createStaticHandler({ config, distDir? }) returning a
//   StaticHandler (src/server/types.ts). distDir is the directory of built assets it serves,
//   by default the repository's dist/; only a test sets it, through StartOptions.distDir (row
//   DIST-DIR, request #34). The entrypoint never sets it.
// - Both listeners are built with createAppServer (src/server/app.ts), so a parser error after
//   a complete request never replaces its pending response with Node's 400 (SEC-11, SEC-13).
// - Logs are JSON lines through the central redactor; the first is `listening`.
//
// US1 composition (A-010 row WIRE-US1; § Rulings, T008 deviations D1). One composition per
// process, built once, before either listener exists:
//   challenge key  OPENSIG_CHALLENGE_KEY_FILE, refused unless valid (loadKey below)
//   notifier       T032, from the OPENSIG_MAIL_* / OPENSIG_SMTP_* / OPENSIG_SPOOL_DIR settings
//   database       OPENSIG_DATABASE: existing and migrated, never created
//   blob store     T028, <OPENSIG_DATA_DIR>/blobs (created 0700 if absent)
//   ceremony       T008 RecipientCeremony(db, blobs, notifier, key, clock)
//   envelopes      T034 EnvelopeApi(db, blobs, ceremony, clock); its EnvelopeService announces
//                  the expiries it commits (T010's expiryAnnouncer; rows EXPIRED-EVT and
//                  UPLOAD-OVERDUE, the T034 follow-up)
//   approvals      T010 ApprovalApi(db, ceremony, clock)
//   sweeper        T010 ExpirySweeper(db, ceremony.onEnvelopeChange, clock), started once at its
//                  default interval when both listeners are bound (row SWEEP-SCHED). A run is
//                  synchronous, so a backlog after downtime holds the event loop for that run
//                  (accepted for the pilot; T024 documents it)
//   routes         ROUTES (src/api/routes.ts): the contract registry with the T008, T034 and
//                  T010 handler maps installed
// The TCP listener's app and the relay listener's app serve the same registry and get the
// same instances in their locals (install()): one ceremony, one EnvelopeApi, one ApprovalApi,
// never one per listener. T034's per-tenant upload cap (src/api/envelopes/uploads.ts) is
// module-level state, process-wide, so every listener draws on the one cap: at most
// UPLOADS_PER_TENANT uploads of a tenant in flight across both listeners together (request
// #16). The composition states it (uploadCap) and the `listening` line logs it.
//
// Parse counts (row PARSE-COUNTS): the parse service's process-wide parseOrphans() and
// parseStopsPastCap() are read at least once a minute; a rise since the last read logs
// `parse_counts_rose`, and the `closed` line carries both totals.
//
// Timeouts (row REQ-TIMEOUT; requests #30 and #32): SEC-10's per-request body timer is the body
// bound; Node's requestTimeout is only the outer backstop, computed from the SEC-10 constants so
// that it is never shorter than the longest request SEC-10 admits (REQUEST_TIMEOUT_MS below,
// 665 s today). Startup settles T033's sandbox plan before either listener exists, so no upload
// waits for the probe, and the `listening` line logs the plan; that line itself is a warning
// when the plan is not sandboxed, and the server still starts.
//
// Shutdown (SIGINT, SIGTERM; SEC-16, rows SHUTDOWN-INFLIGHT and T008FU-D9), in this order:
// 1. both listeners close and the socket file is removed;
// 2. every request handler already dispatched settles (each is bounded by its own deadlines),
//    and no queued request is dispatched;
// 3. the ceremony's pending post-response work (requestChallenge after its generic 202) is
//    drained, so no job is dropped silently: each finishes, or fails and is logged and counted.
//    Every step has its own deadline (the storage busy timeout of 5 s, the SMTP session
//    deadline of 10 s; a spool write rests on the local-filesystem assumption), so the drain is
//    bounded; T024 documents the bound;
// 4. the expiry sweeper stops;
// 5. the parse counts are read a last time;
// 6. the database closes, and `closed` is logged with the work counts and the parse totals.
// The process then exits 0. A second signal during shutdown ends the process at once (Node's
// default handling).
//
// Listener state (A-010 row SEC16-PROBE, request #47): each listener's view (ListenerView) also
// reads, live, whether its server is listening and how many connections it has accepted, so a
// test can see from the product itself that no listener accepts anything after step 1. Reading
// them changes nothing: no listener is added, no timing changes, and the close order is as above.

import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, unlinkSync, type Stats } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadOperatorAuthConfig } from '../api/auth/config.ts';
import { createOperatorAuthenticator, type OperatorAuthenticator } from '../api/auth/operator.ts';
import { ENVELOPE_API, EnvelopeApi } from '../api/envelopes/api.ts';
import { UPLOADS_PER_TENANT } from '../api/envelopes/uploads.ts';
import { APPROVAL_API, ApprovalApi } from '../api/recipients/approval.ts';
import { RecipientCeremony } from '../api/recipients/ceremony.ts';
import { ChallengeKeyError, loadChallengeKey, type ChallengeKey } from '../api/recipients/codes.ts';
import { RECIPIENT_CEREMONY } from '../api/recipients/handlers.ts';
import { ROUTES, type RouteDefinition } from '../api/routes.ts';
import { ExpirySweeper, type ExpirySweepReport } from '../jobs/expiry.ts';
import { createNotifierFromConfig, loadNotificationConfig, NotificationError, type Notifier } from '../notifications/index.ts';
import { parseOrphans, parseServicePlan, parseStopsPastCap, type ServicePlan } from '../pdf/service.ts';
import { openBlobStore, type BlobStore } from '../storage/blobs/index.ts';
import { DEFAULT_BUSY_TIMEOUT_MS, openDatabase, type Database } from '../storage/db/index.ts';
import { loadMigrations } from '../storage/schema/migrations.ts';
import { openTenantPolicy, type TenantPolicySource } from './tenants.ts';
import { createApp, createAppServer, type App } from './app.ts';
import { BODY_MIN_BYTES_PER_SECOND, loadServerConfig, loopbackOrigin, PDF_BODY_LIMIT, ServerConfigError, type ServerConfig } from './config.ts';
import { createLogger, type LogSink, type Logger } from './redact.ts';
import type { StaticHandler } from './types.ts';

/** The one US1 composition of a process (row WIRE-US1); every listener's app gets these instances. */
export interface Composition {
  /** The registry every listener serves: ROUTES, with the T008, T034 and T010 maps installed. */
  readonly routes: readonly RouteDefinition[];
  readonly db: Database;
  readonly blobs: BlobStore;
  readonly notifier: Notifier;
  readonly ceremony: RecipientCeremony;
  readonly envelopes: EnvelopeApi;
  readonly approvals: ApprovalApi;
  /**
   * T010's expiry sweeper over the composed database and the ceremony's onEnvelopeChange (row
   * SWEEP-SCHED): started once, at its default interval, when both listeners are bound; stopped
   * at shutdown after the ceremony drain and before the database closes.
   */
  readonly sweeper: ExpirySweeper;
  /**
   * T034's per-tenant upload cap as the composition states it (request #16): module-level in
   * src/api/envelopes/uploads.ts, so one cap per process, shared by every listener.
   */
  readonly uploadCap: { readonly scope: 'process'; readonly perTenant: number };
}

/** What one listener serves, and its state: read-only, for monitoring, SEC-12 and SEC-16. */
export interface ListenerView {
  readonly name: 'tcp' | 'relay';
  readonly routes: readonly RouteDefinition[];
  /** The app-scoped services in this listener's app (the composition's own instances). */
  readonly services: { readonly ceremony: unknown; readonly envelopes: unknown; readonly approvals: unknown };
  /** Node's timeouts on this listener's server (REQ-TIMEOUT). */
  readonly timeouts: { readonly headers: number; readonly request: number };
  /** Whether this listener's server is listening now (Node's `server.listening`, read live; row SEC16-PROBE). */
  readonly listening: boolean;
  /**
   * The connections this listener has accepted since it was built: its server's 'connection'
   * events, read live (row SEC16-PROBE). Counted from before the listener binds, so none is missed.
   */
  readonly acceptedConnections: number;
}

export interface StartOptions {
  readonly logSink?: LogSink;
  /** The parse-count reader (default: T033's process-wide counts); a monitoring seam (PARSE-COUNTS). */
  readonly parseCounts?: () => ParseCounts;
  /** How often the counts are read, 1 to PARSE_COUNT_INTERVAL_MS (default PARSE_COUNT_INTERVAL_MS). */
  readonly parseCountIntervalMs?: number;
  /**
   * The parse plan reader (default: T033's parseServicePlan(), the plan every upload's parsePdf()
   * uses). Setting it replaces the startup settle as well as the plan the `listening` line logs:
   * startup awaits this reader instead of parseServicePlan(), so T033's plan is then settled by
   * the first upload, which waits for the sandbox probe. Uploads keep T033's own plan either way.
   * A test seam, never set by the entrypoint (request #34, note 1).
   */
  readonly parsePlan?: () => Promise<ServicePlan>;
  /**
   * The directory of built assets that T035's static handler serves (an absolute path; default:
   * the static handler's own, the repository's dist/). A test seam, so a test builds into a
   * temporary directory and never into the shared dist/; never set by the entrypoint (row
   * DIST-DIR, request #34).
   */
  readonly distDir?: string;
}

export interface RunningServer {
  readonly host: string;
  readonly port: number;
  readonly relaySocket: string | null;
  readonly allowedOrigins: ReadonlySet<string>;
  readonly composition: Composition;
  readonly listeners: readonly ListenerView[];
  /**
   * Shutdown (SEC-16; rows SHUTDOWN-INFLIGHT, SWEEP-SCHED, PARSE-COUNTS): close both listeners,
   * let every dispatched handler settle, drain the ceremony's pending work, stop the sweeper,
   * read the parse counts once more, close the database, log `closed`. Idempotent.
   */
  close(): Promise<void>;
}

/** Node's header timeout on both listeners. */
export const HEADERS_TIMEOUT_MS = 20_000;
/** The longest request body SEC-10 admits: the PDF limit at the minimum rate (640 s today). */
export const LONGEST_BODY_MS = Math.ceil(PDF_BODY_LIMIT / BODY_MIN_BYTES_PER_SECOND) * 1000;
/**
 * The bound of the waits that can come before a body read starts (row REQ-TIMEOUT; A-010
 * request #32): a transaction run before the body is read (the recipient session guard of T008
 * and T010) waits at most the storage busy timeout for the write lock (DEFAULT_BUSY_TIMEOUT_MS,
 * 5 s). The T033 sandbox probe, which parsePdf() awaits (memoized per process) before it reads
 * an upload's body, is settled at startup (startServer awaits parseServicePlan() before either
 * listener exists), so no upload waits for it. A request pipelined behind another on the same
 * connection also waits for that one; that wait is bounded only by the earlier request's own
 * life and is not added (row PIPE-WAIT, a limit T024 documents).
 */
export const PRE_BODY_WAIT_MS = DEFAULT_BUSY_TIMEOUT_MS;
/**
 * Node's outer request backstop (row REQ-TIMEOUT): SEC-10's per-request body timer is the
 * intended body bound, so this is never shorter than the longest request SEC-10 admits.
 */
export const REQUEST_TIMEOUT_MS = HEADERS_TIMEOUT_MS + LONGEST_BODY_MS + PRE_BODY_WAIT_MS;
/** How often the parse service's process-wide counts are read (PARSE-COUNTS: at least once a minute). */
export const PARSE_COUNT_INTERVAL_MS = 60_000;

/** The parse service's process-wide counts (T033 parseOrphans(), parseStopsPastCap()). */
export interface ParseCounts {
  readonly orphans_ended: number;
  readonly stops_past_cap: number;
}

const readParseCounts = (): ParseCounts => ({ orphans_ended: parseOrphans().orphans_ended, stops_past_cap: parseStopsPastCap().stops_past_cap });

function hardened(server: Server): Server {
  server.headersTimeout = HEADERS_TIMEOUT_MS;
  server.requestTimeout = REQUEST_TIMEOUT_MS;
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

interface OperatorAuth {
  readonly authenticator: OperatorAuthenticator | null;
  readonly tenants: TenantPolicySource | null;
}

function loadAuthenticator(config: ServerConfig, logger: Logger): OperatorAuth {
  if (config.operatorAuthFile === null) {
    logger.warn('operator_auth_not_configured', { effect: 'every operator request is 401' });
    logger.info('operator_auth', { configured: false, policy: 'not-configured' });
    return { authenticator: null, tenants: null };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(config.operatorAuthFile, 'utf8'));
  } catch {
    throw new ServerConfigError('OPENSIG_OPERATOR_AUTH_FILE is not a readable JSON file');
  }
  const authConfig = loadOperatorAuthConfig(parsed);
  const tenants = openTenantPolicy(config.database, authConfig);
  const authenticator = createOperatorAuthenticator(authConfig, { tenantPolicy: tenants.policy });
  logger.info('operator_auth', { configured: true, policy: authenticator.policy, policy_source: 'tenants-table', tenants: tenants.tenantIds });
  return { authenticator, tenants };
}

/** T035's static handler, when src/server/static.ts exists; `distDir` reaches it only when a test set it (DIST-DIR). */
async function loadStaticHandler(config: ServerConfig, distDir: string | undefined): Promise<StaticHandler | null> {
  const url = new URL('./static.ts', import.meta.url);
  if (!existsSync(fileURLToPath(url))) return null;
  const module = (await import(url.href)) as { createStaticHandler?: (options: { config: ServerConfig; distDir?: string }) => StaticHandler };
  if (typeof module.createStaticHandler !== 'function') return null;
  return module.createStaticHandler(distDir === undefined ? { config } : { config, distDir });
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

function refuseKey(reason: string): never {
  throw new ServerConfigError(`OPENSIG_CHALLENGE_KEY_FILE refused: ${reason}`);
}

/**
 * The recipient challenge-HMAC key (WIRE-US1; the T031 line: startup refuses it unless it is a
 * regular file, not a symbolic link, owned by the server user, with no group or other
 * permission bit (for example 0600 or 0400), holding 32 to 4096 bytes). Who checks what:
 * - here, before anything opens the file: the setting is present (absolute: config.ts); the
 *   path exists; it is not a symbolic link; it names a regular file, which gives a FIFO or a
 *   device already at the path its clear refusal;
 * - T008's loadChallengeKey({ path }) on the opened descriptor: opened with O_NOFOLLOW (a link
 *   swapped in afterwards is ELOOP) and O_NONBLOCK (a FIFO or device swapped in afterwards opens
 *   at once and is refused; row KEY-FIFO); a regular file; owned by the server's user; no group
 *   or other permission bit (mode & 0o077); 32 to 4096 bytes; unchanged while read.
 * Refusals name the setting and the rule, never the path or any byte of the file.
 * The mode rule is an owner-only file, "no group or other permission bit" (for example 0600 or
 * 0400; A-010 request #30 (4), request #34 note 3): no other user can read or replace the key.
 */
function loadKey(path: string | null): ChallengeKey {
  if (path === null) refuseKey('the setting is required (an owner-only file, with no group or other permission bit, holding the recipient challenge-HMAC key)');
  let stat: Stats;
  try {
    stat = lstatSync(path);
  } catch {
    refuseKey('the file does not exist or cannot be inspected');
  }
  if (stat.isSymbolicLink()) refuseKey('the path must not be a symbolic link');
  if (!stat.isFile()) refuseKey('the path must name a regular file');
  try {
    return loadChallengeKey({ path });
  } catch (error) {
    if (error instanceof ChallengeKeyError) refuseKey(error.message);
    throw error;
  }
}

/** The service database: configured, existing (never created here) and migrated to the current schema. */
function openServiceDatabase(path: string | null): Database {
  if (path === null) throw new ServerConfigError('the service database is required: set OPENSIG_DATABASE (or OPENSIG_DATA_DIR)');
  if (!existsSync(path)) throw new ServerConfigError('the database named by OPENSIG_DATABASE does not exist');
  let db: Database;
  try {
    db = openDatabase({ path });
  } catch {
    throw new ServerConfigError('the database named by OPENSIG_DATABASE could not be opened (it must be a 0600 regular file)');
  }
  try {
    const expected = loadMigrations().length;
    const version = db.checkSchema();
    if (version !== expected) throw new ServerConfigError(`the database schema is at version ${version}, not ${expected}; migrate it first`);
    return db;
  } catch (error) {
    db.close();
    if (error instanceof ServerConfigError) throw error;
    throw new ServerConfigError('the database named by OPENSIG_DATABASE could not be read');
  }
}

/** The blob store at <OPENSIG_DATA_DIR>/blobs; the directory is created 0700 inside an existing data directory. */
function openServiceBlobs(root: string | null): BlobStore {
  if (root === null) throw new ServerConfigError('the blob store needs OPENSIG_DATA_DIR (an absolute path)');
  try {
    mkdirSync(root, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw new ServerConfigError('the blob store directory in OPENSIG_DATA_DIR could not be created');
  }
  try {
    return openBlobStore({ root });
  } catch {
    throw new ServerConfigError('the blob store directory in OPENSIG_DATA_DIR must be a directory, not a link');
  }
}

/** The T032 notifier from the mail settings; a refused setting is a startup refusal naming the setting. */
function createServiceNotifier(env: Readonly<Record<string, string | undefined>>, logger: Logger): Notifier {
  try {
    return createNotifierFromConfig(loadNotificationConfig(env), { logger: logger.child({ component: 'notifications' }) });
  } catch (error) {
    if (error instanceof NotificationError) throw new ServerConfigError(`mail configuration refused: ${error.message}`);
    throw error;
  }
}

/** Build the process's one composition (WIRE-US1). Nothing listens yet. */
function compose(config: ServerConfig, env: Readonly<Record<string, string | undefined>>, logger: Logger, challengeKey: ChallengeKey): Composition {
  const notifier = createServiceNotifier(env, logger);
  const db = openServiceDatabase(config.database);
  try {
    const blobs = openServiceBlobs(config.blobRoot);
    const clock = (): Date => new Date();
    const ceremony = new RecipientCeremony({ db, blobs, notifier, challengeKey, clock, logger: logger.child({ component: 'recipients' }) });
    const envelopes = new EnvelopeApi({ db, blobs, ceremony, clock });
    const approvals = new ApprovalApi({ db, ceremony, clock });
    const sweeper = new ExpirySweeper({
      db,
      onEnvelopeChange: ceremony.onEnvelopeChange,
      clock,
      onReport: (report: ExpirySweepReport) => {
        if (report.expired > 0 || report.purged > 0 || !report.complete) logger.info('expiry_sweep', { expired: report.expired, purged: report.purged, complete: report.complete, tenants: report.tenants });
      },
      onError: (error: unknown) => {
        logger.warn('expiry_sweep_failed', { error_name: error instanceof Error ? error.name : typeof error });
      },
    });
    return Object.freeze({
      routes: ROUTES,
      db,
      blobs,
      notifier,
      ceremony,
      envelopes,
      approvals,
      sweeper,
      uploadCap: Object.freeze({ scope: 'process' as const, perTenant: UPLOADS_PER_TENANT }),
    });
  } catch (error) {
    db.close();
    throw error;
  }
}

/** Put the composition's instances into `app`'s locals: the same objects for every listener. */
function install(app: App, composition: Composition): void {
  app.locals.set(RECIPIENT_CEREMONY, composition.ceremony);
  app.locals.set(ENVELOPE_API, composition.envelopes);
  app.locals.set(APPROVAL_API, composition.approvals);
}

/**
 * The read-only view of one listener. listenAll() builds it before that listener's listen(), for
 * the TCP listener and for the relay socket's, so the count sees every connection either ever
 * accepts. The count is an extra 'connection' listener that only adds one; Node's own HTTP
 * connection handling, registered when the server was created, runs first and is unchanged.
 */
function viewOf(name: 'tcp' | 'relay', app: App, server: Server): ListenerView {
  let accepted = 0;
  server.on('connection', () => {
    accepted += 1;
  });
  return Object.freeze({
    name,
    routes: app.routes,
    timeouts: Object.freeze({ headers: server.headersTimeout, request: server.requestTimeout }),
    services: Object.freeze({ ceremony: app.locals.get(RECIPIENT_CEREMONY), envelopes: app.locals.get(ENVELOPE_API), approvals: app.locals.get(APPROVAL_API) }),
    get listening(): boolean {
      return server.listening;
    },
    get acceptedConnections(): number {
      return accepted;
    },
  });
}

/** Start the server from `env`. Rejects on invalid configuration or a bind failure. */
export async function startServer(env: Readonly<Record<string, string | undefined>> = process.env, options: StartOptions = {}): Promise<RunningServer> {
  const interval = options.parseCountIntervalMs ?? PARSE_COUNT_INTERVAL_MS;
  if (!Number.isSafeInteger(interval) || interval < 1 || interval > PARSE_COUNT_INTERVAL_MS) throw new TypeError(`parseCountIntervalMs must be an integer in 1..${PARSE_COUNT_INTERVAL_MS}`);
  const distDir = options.distDir;
  if (distDir !== undefined && (typeof distDir !== 'string' || !isAbsolute(distDir))) throw new TypeError('distDir must be an absolute path');
  const parseCounts = options.parseCounts ?? readParseCounts;
  const readPlan = options.parsePlan ?? parseServicePlan;
  if (typeof readPlan !== 'function') throw new TypeError('parsePlan must be a function');
  const config = loadServerConfig(env);
  const logger = createLogger(options.logSink);
  const challengeKey = loadKey(config.challengeKeyFile);
  const { authenticator, tenants } = loadAuthenticator(config, logger);
  let composition: Composition | null = null;
  try {
    composition = compose(config, env, logger, challengeKey);
    // REQ-TIMEOUT (request #32): settle T033's sandbox plan now, with the same memo key as every
    // upload's parsePdf(), so no upload waits for the probe. The server starts whatever the plan
    // is; uploads keep T033's own answers (a refused plan is their 500 sandbox-unavailable).
    const plan = await readPlan();
    return await listenAll(config, logger, authenticator, tenants, composition, { read: parseCounts, intervalMs: interval }, plan, distDir);
  } catch (error) {
    composition?.db.close();
    tenants?.close();
    throw error;
  }
}

async function listenAll(
  config: ServerConfig,
  logger: Logger,
  authenticator: OperatorAuthenticator | null,
  tenants: TenantPolicySource | null,
  composition: Composition,
  counts: { readonly read: () => ParseCounts; readonly intervalMs: number },
  plan: ServicePlan,
  distDir: string | undefined,
): Promise<RunningServer> {
  const staticHandler = await loadStaticHandler(config, distDir);
  const allowedOrigins = new Set<string>(config.allowedOrigins ?? []);

  if (config.relaySocket !== null) prepareSocketPath(config.relaySocket);

  const app = createApp({ routes: composition.routes, config, logger, authenticator, allowedOrigins, staticHandler });
  install(app, composition);
  const apps: App[] = [app];
  const server = hardened(createAppServer(app));
  const listeners: ListenerView[] = [viewOf('tcp', app, server)];
  await listen(server, { host: config.host, port: config.port });
  const address = server.address() as AddressInfo;
  if (config.allowedOrigins === null) allowedOrigins.add(loopbackOrigin(address.address, address.port));

  let relay: Server | null = null;
  if (config.relaySocket !== null) {
    try {
      // The relay's app: operator routes of the same registry, the same composition, the same cap.
      const relayApp = createApp({ routes: composition.routes, config, logger: logger.child({ listener: 'relay' }), authenticator, allowedOrigins, surface: 'relay' });
      install(relayApp, composition);
      apps.push(relayApp);
      relay = hardened(createAppServer(relayApp));
      listeners.push(viewOf('relay', relayApp, relay));
      await listen(relay, { path: config.relaySocket });
      chmodSync(config.relaySocket, 0o600);
    } catch (error) {
      if (relay !== null) await closeServer(relay);
      await closeServer(server);
      throw error;
    }
  }

  // SWEEP-SCHED: one sweeper, at its default interval (its timer does not keep the process alive).
  composition.sweeper.start();
  // PARSE-COUNTS: read the parse service's process-wide counts at least once a minute, and warn
  // when either has risen since it was last read.
  let lastCounts = counts.read();
  const checkCounts = (): ParseCounts => {
    const now = counts.read();
    if (now.orphans_ended > lastCounts.orphans_ended || now.stops_past_cap > lastCounts.stops_past_cap) {
      logger.warn('parse_counts_rose', {
        orphans_ended: now.orphans_ended,
        stops_past_cap: now.stops_past_cap,
        orphans_ended_before: lastCounts.orphans_ended,
        stops_past_cap_before: lastCounts.stops_past_cap,
      });
    }
    lastCounts = now;
    return now;
  };
  const countTimer = setInterval(checkCounts, counts.intervalMs);
  countTimer.unref();

  // The settled parse plan (request #32): the `listening` line carries it, and is itself a warning
  // when uploads cannot run sandboxed on this host. The server still starts.
  const listening = {
    host: address.address,
    port: address.port,
    relay_socket: config.relaySocket !== null,
    operator_auth: authenticator !== null,
    operator_policy: authenticator === null ? 'not-configured' : authenticator.policy,
    static_shell: staticHandler !== null,
    environment: config.environment,
    upload_cap_scope: composition.uploadCap.scope,
    upload_cap_per_tenant: composition.uploadCap.perTenant,
    parse_mode: plan.mode,
    parse_launcher: plan.probe.launcher,
    network_sandbox: plan.network_sandbox,
  };
  if (plan.mode === 'sandboxed') logger.info('listening', listening);
  else logger.warn('listening', listening);

  let closing: Promise<void> | null = null;
  return Object.freeze({
    host: address.address,
    port: address.port,
    relaySocket: config.relaySocket,
    allowedOrigins,
    composition,
    listeners: Object.freeze(listeners),
    close(): Promise<void> {
      closing ??= (async (): Promise<void> => {
        // 1. No new connection or request: both listeners close.
        await closeServer(server);
        if (relay !== null) {
          await closeServer(relay);
          try {
            unlinkSync(config.relaySocket as string);
          } catch {
            // already removed
          }
        }
        // 2. SHUTDOWN-INFLIGHT: every dispatched handler settles (a handler can still schedule
        //    ceremony work, so this comes before the drain); nothing queued is dispatched.
        logger.info('shutdown', { handlers_in_flight: apps.reduce((total, each) => total + each.inFlight(), 0) });
        await Promise.all(apps.map((each) => each.settle()));
        // 3. SEC-16 (row T008FU-D9): the work scheduled after a generic 202 finishes, so none is
        //    dropped silently.
        logger.info('draining', { challenge_work_pending: composition.ceremony.challengeWorkStats().pending });
        await composition.ceremony.drain();
        // 4. SWEEP-SCHED: no sweep starts on the database from here on (a run is synchronous).
        composition.sweeper.stop();
        // 5. PARSE-COUNTS: a last read, so a rise since the last check is not missed.
        clearInterval(countTimer);
        const finalCounts = checkCounts();
        // 6. The database closes last.
        composition.db.close();
        tenants?.close();
        logger.info('closed', {
          challenge_work: composition.ceremony.challengeWorkStats(),
          parse_orphans_ended: finalCounts.orphans_ended,
          parse_stops_past_cap: finalCounts.stops_past_cap,
        });
      })();
      return closing;
    },
  });
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
