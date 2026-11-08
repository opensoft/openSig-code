// SPDX-License-Identifier: Apache-2.0
//
// node:sqlite connection for the single-instance service.
//
// - The database file is created with mode 0600, and an existing file must be
//   a regular file that is not group- or other-accessible. SQLite creates the
//   -wal and -shm files with the database file's mode.
// - WAL journal, synchronous=FULL, foreign keys on, trusted_schema off and the
//   defensive flag set.
// - Writes run in Database.transaction(), which starts with BEGIN IMMEDIATE and
//   waits for the write lock at most the bounded busy timeout.
// - Rows are reached only through tenant-scoped stores (forTenant). The only
//   reads without a tenant are the tenant registry (listTenantIds) and the
//   resolution of a presented capability hash to its tenant (resolveCapability).

import { closeSync, constants as fsConstants, lstatSync, openSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { tablePolicy } from '../schema/entities.ts';
import { loadMigrations, type Migration } from '../schema/migrations.ts';
import { StorageUsageError, translateSqliteError } from './errors.ts';
import { createExecutor, runImmediate, type Executor } from './executor.ts';
import { applyMigrations, checkMigrations, type MigrationResult } from './migrate.ts';
import { TENANT_ID_PATTERN, TenantStore } from './tenant-store.ts';

export const DEFAULT_BUSY_TIMEOUT_MS = 5_000;
export const MIN_BUSY_TIMEOUT_MS = 1;
export const MAX_BUSY_TIMEOUT_MS = 30_000;

export interface OpenOptions {
  /** Absolute path of the database file. */
  readonly path: string;
  /** Bounded wait for the write lock, in milliseconds (1..30000, default 5000). */
  readonly busyTimeoutMs?: number;
}

export interface CapabilityOwner {
  readonly tenantId: string;
  readonly id: string;
}

const DIGEST = /^[0-9a-f]{64}$/;

function checkPath(path: unknown): string {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) {
    throw new StorageUsageError('database path must be a non-empty string');
  }
  if (path === ':memory:' || path.startsWith('file:') || !isAbsolute(path)) {
    throw new StorageUsageError('database path must be an absolute filesystem path');
  }
  return path;
}

function checkBusyTimeout(value: unknown): number {
  const timeout = value ?? DEFAULT_BUSY_TIMEOUT_MS;
  if (
    typeof timeout !== 'number' ||
    !Number.isSafeInteger(timeout) ||
    timeout < MIN_BUSY_TIMEOUT_MS ||
    timeout > MAX_BUSY_TIMEOUT_MS
  ) {
    throw new StorageUsageError(`busy timeout must be an integer in ${MIN_BUSY_TIMEOUT_MS}..${MAX_BUSY_TIMEOUT_MS} ms`);
  }
  return timeout;
}

/** Create the file with mode 0600 if absent; refuse links, non-files and loose modes. */
function prepareFile(path: string): void {
  const parent = lstatSync(dirname(path), { throwIfNoEntry: false });
  if (parent === undefined || !parent.isDirectory()) {
    throw new StorageUsageError('database directory must exist');
  }
  try {
    closeSync(openSync(path, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW, 0o600));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  const stat = lstatSync(path);
  if (!stat.isFile()) throw new StorageUsageError('database path must be a regular file, not a link or directory');
  if ((stat.mode & 0o077) !== 0) {
    throw new StorageUsageError('database file must not be group- or other-accessible (expected mode 0600)');
  }
}

function pragmaValue(executor: Executor, pragma: string): unknown {
  const row = executor.statement(`PRAGMA ${pragma}`).get();
  return row === undefined ? undefined : Object.values(row)[0];
}

export class Database {
  readonly path: string;
  readonly busyTimeoutMs: number;
  readonly #connection: DatabaseSync;
  readonly #executor: Executor;

  /** Internal: use openDatabase(). */
  constructor(path: string, busyTimeoutMs: number, connection: DatabaseSync) {
    this.path = path;
    this.busyTimeoutMs = busyTimeoutMs;
    this.#connection = connection;
    this.#executor = createExecutor(connection);
    this.#configure();
  }

  /** Configure and check the connection's pragmas. */
  #configure(): void {
    const executor = this.#executor;
    const journal = executor.statement('PRAGMA journal_mode = WAL').get();
    if (journal?.['journal_mode'] !== 'wal') throw new StorageUsageError('the database could not enter WAL mode');
    executor.exec('PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;');
    const expected: ReadonlyArray<readonly [string, unknown]> = [
      ['synchronous', 2],
      ['foreign_keys', 1],
      ['trusted_schema', 0],
      ['busy_timeout', this.busyTimeoutMs],
    ];
    for (const [pragma, value] of expected) {
      if (pragmaValue(executor, pragma) !== value) throw new StorageUsageError(`PRAGMA ${pragma} is not ${String(value)}`);
    }
  }

  get inTransaction(): boolean {
    return this.#executor.inTransaction();
  }

  /**
   * Run `fn` in a BEGIN IMMEDIATE transaction and commit; any throw rolls back.
   * Waits for the write lock at most busyTimeoutMs, then throws
   * StorageBusyError. Nested and asynchronous callbacks are refused.
   */
  transaction<T>(fn: () => T): T {
    return runImmediate(this.#executor, fn);
  }

  /** A store whose every statement is filtered to `tenantId`. */
  forTenant(tenantId: string): TenantStore {
    return new TenantStore(this.#executor, tenantId);
  }

  /** The tenant registry: every tenant id, sorted. */
  listTenantIds(): string[] {
    try {
      return this.#executor
        .statement('SELECT tenant_id FROM tenants ORDER BY tenant_id')
        .all()
        .map((row) => String(row['tenant_id']));
    } catch (error) {
      throw translateSqliteError(error);
    }
  }

  /**
   * Resolve a presented capability's hash (an invitation token hash or a
   * recipient session value hash) to the owning tenant and row id. Only
   * columns declared as capability columns in the table policy map are
   * accepted.
   */
  resolveCapability(table: string, hash: string): CapabilityOwner | undefined {
    const column = tablePolicy(table)?.capabilityColumn;
    if (column === undefined || this.#executor.table(table)?.columns.has(column) !== true) {
      throw new StorageUsageError(`${JSON.stringify(table)} has no capability column`);
    }
    if (typeof hash !== 'string' || !DIGEST.test(hash)) {
      throw new StorageUsageError('capability hash must be lowercase hex SHA-256');
    }
    const row = this.#executor.statement(`SELECT tenant_id, id FROM "${table}" WHERE "${column}" = ?`).get(hash);
    if (row === undefined) return undefined;
    const tenantId = String(row['tenant_id']);
    if (!TENANT_ID_PATTERN.test(tenantId)) throw new StorageUsageError('stored tenant id is malformed');
    return { tenantId, id: String(row['id']) };
  }

  /** Apply pending migrations (default: the code's migration files). */
  migrate(migrations: readonly Migration[] = loadMigrations(), now?: () => string): MigrationResult {
    return applyMigrations(this.#executor, migrations, now);
  }

  /** Check the applied migrations against `migrations` without applying; returns the schema version. */
  checkSchema(migrations: readonly Migration[] = loadMigrations()): number {
    return checkMigrations(this.#executor, migrations);
  }

  close(): void {
    if (this.#connection.isOpen) this.#connection.close();
  }
}

export function openDatabase(options: OpenOptions): Database {
  if (typeof options !== 'object' || options === null) throw new StorageUsageError('open options are required');
  const path = checkPath(options.path);
  const busyTimeoutMs = checkBusyTimeout(options.busyTimeoutMs);
  prepareFile(path);
  let connection: DatabaseSync;
  try {
    connection = new DatabaseSync(path, {
      timeout: busyTimeoutMs,
      defensive: true,
      enableForeignKeyConstraints: true,
      enableDoubleQuotedStringLiterals: false,
      allowExtension: false,
    });
  } catch (error) {
    throw translateSqliteError(error);
  }
  try {
    return new Database(path, busyTimeoutMs, connection);
  } catch (error) {
    connection.close();
    throw error;
  }
}
