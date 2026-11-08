// SPDX-License-Identifier: Apache-2.0
//
// Migration runner. Each pending migration is applied in its own
// BEGIN IMMEDIATE transaction together with its schema_migrations record and
// PRAGMA user_version, so concurrent runners serialize and a failing migration
// leaves nothing behind. Before applying anything the runner checks, inside
// the same transaction, that the database's applied migrations are an exact
// prefix of the code's set (same version, name and SHA-256).

import { constants } from 'node:sqlite';

import { validateMigrationSet, type Migration } from '../schema/migrations.ts';
import { MigrationError, StorageError } from './errors.ts';
import { runImmediate, type Executor } from './executor.ts';

export interface MigrationResult {
  /** Versions applied by this call, in order. */
  readonly applied: readonly number[];
  /** The schema version after this call. */
  readonly version: number;
}

const SCHEMA_MIGRATIONS_DDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER NOT NULL PRIMARY KEY CHECK (version >= 1),
  name TEXT NOT NULL,
  sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
  applied_at TEXT NOT NULL
) STRICT`;

// Migration files may not control transactions, change pragmas or attach
// other databases; the runner owns all of that.
const DENIED_ACTIONS: ReadonlySet<number> = new Set([
  constants.SQLITE_TRANSACTION,
  constants.SQLITE_SAVEPOINT,
  constants.SQLITE_PRAGMA,
  constants.SQLITE_ATTACH,
  constants.SQLITE_DETACH,
]);

interface AppliedRow {
  readonly version: number;
  readonly name: string;
  readonly sha256: string;
}

function appliedRows(executor: Executor): AppliedRow[] {
  return executor
    .statement('SELECT version, name, sha256 FROM schema_migrations ORDER BY version')
    .all()
    .map((row) => ({ version: Number(row['version']), name: String(row['name']), sha256: String(row['sha256']) }));
}

function userVersion(executor: Executor): number {
  const row = executor.statement('PRAGMA user_version').get();
  return Number(row?.['user_version'] ?? 0);
}

/** Check the applied migrations against the code's set; return the applied version. */
function checkApplied(executor: Executor, migrations: readonly Migration[]): number {
  const rows = appliedRows(executor);
  rows.forEach((row, index) => {
    if (row.version !== index + 1) {
      throw new MigrationError(`applied migrations have a gap or duplicate at version ${row.version}`);
    }
  });
  if (rows.length > migrations.length) {
    throw new MigrationError(
      `database schema version ${rows.length} is newer than this code's migrations (${migrations.length})`,
    );
  }
  for (const row of rows) {
    const known = migrations[row.version - 1];
    if (known === undefined || known.name !== row.name || known.sha256 !== row.sha256) {
      throw new MigrationError(
        `applied migration ${row.version} (${row.name}) differs from the code: migrations are append-only`,
      );
    }
  }
  const recorded = userVersion(executor);
  if (recorded !== rows.length) {
    throw new MigrationError(`PRAGMA user_version ${recorded} disagrees with ${rows.length} applied migrations`);
  }
  return rows.length;
}

function execMigration(executor: Executor, migration: Migration): void {
  executor.setAuthorizer((action) => (DENIED_ACTIONS.has(action) ? constants.SQLITE_DENY : constants.SQLITE_OK));
  try {
    executor.exec(migration.sql);
  } finally {
    executor.setAuthorizer(null);
  }
}

export function applyMigrations(
  executor: Executor,
  migrations: readonly Migration[],
  now: () => string = () => new Date().toISOString(),
): MigrationResult {
  validateMigrationSet(migrations);
  const applied: number[] = [];
  try {
    runImmediate(executor, () => executor.exec(SCHEMA_MIGRATIONS_DDL));
    for (;;) {
      const next = runImmediate(executor, () => {
        const current = checkApplied(executor, migrations);
        const migration = migrations[current];
        if (migration === undefined) return undefined;
        try {
          execMigration(executor, migration);
        } catch (error) {
          throw new MigrationError(`migration ${migration.name} failed: ${(error as Error).message}`, {
            cause: error,
          });
        }
        executor
          .statement('INSERT INTO schema_migrations (version, name, sha256, applied_at) VALUES (?, ?, ?, ?)')
          .run(migration.version, migration.name, migration.sha256, now());
        executor.exec(`PRAGMA user_version = ${migration.version}`);
        const violations = executor.statement('PRAGMA foreign_key_check').all();
        if (violations.length > 0) {
          throw new MigrationError(`migration ${migration.name} leaves ${violations.length} foreign key violation(s)`);
        }
        return migration.version;
      });
      if (next === undefined) break;
      applied.push(next);
    }
  } catch (error) {
    if (error instanceof StorageError) throw error;
    throw new MigrationError(`migration run failed: ${(error as Error).message}`, { cause: error });
  } finally {
    executor.resetSchemaCache();
  }
  return { applied, version: migrations.length };
}

/** Verify without applying: the applied set must be a prefix of `migrations`. */
export function checkMigrations(executor: Executor, migrations: readonly Migration[]): number {
  validateMigrationSet(migrations);
  const exists = executor.statement(`SELECT 1 AS present FROM sqlite_schema WHERE type = 'table' AND name = 'schema_migrations'`).get();
  if (exists === undefined) return 0;
  return checkApplied(executor, migrations);
}
