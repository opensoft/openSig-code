// SPDX-License-Identifier: Apache-2.0
//
// Internal statement executor shared by the connection, the migration runner
// and the tenant-scoped store. Not exported from index.ts: the raw connection
// never leaves the storage layer.

import type { DatabaseSync, StatementSync } from 'node:sqlite';

import { StorageUsageError, translateSqliteError } from './errors.ts';

export interface TableInfo {
  readonly columns: ReadonlySet<string>;
  readonly primaryKey: readonly string[];
}

type Authorizer = Parameters<DatabaseSync['setAuthorizer']>[0];

export interface Executor {
  statement(sql: string): StatementSync;
  exec(sql: string): void;
  inTransaction(): boolean;
  table(name: string): TableInfo | undefined;
  resetSchemaCache(): void;
  setAuthorizer(authorizer: Authorizer): void;
}

const STATEMENT_CACHE_LIMIT = 256;
const IDENTIFIER = /^[a-z_][a-z0-9_]*$/;

export function createExecutor(connection: DatabaseSync): Executor {
  const statements = new Map<string, StatementSync>();
  const tables = new Map<string, TableInfo | undefined>();

  return {
    statement(sql) {
      let statement = statements.get(sql);
      if (statement === undefined) {
        try {
          statement = connection.prepare(sql);
        } catch (error) {
          throw translateSqliteError(error);
        }
        if (statements.size >= STATEMENT_CACHE_LIMIT) statements.clear();
        statements.set(sql, statement);
      }
      return statement;
    },
    exec(sql) {
      try {
        connection.exec(sql);
      } catch (error) {
        throw translateSqliteError(error);
      }
    },
    inTransaction() {
      return connection.isTransaction;
    },
    table(name) {
      if (!IDENTIFIER.test(name)) return undefined;
      if (!tables.has(name)) {
        const rows = connection.prepare(`SELECT name, pk FROM pragma_table_info(?) ORDER BY cid`).all(name);
        if (rows.length === 0) {
          tables.set(name, undefined);
        } else {
          const columns = new Set<string>();
          const keyed: { name: string; pk: number }[] = [];
          for (const row of rows) {
            const column = String(row['name']);
            columns.add(column);
            const pk = Number(row['pk']);
            if (pk > 0) keyed.push({ name: column, pk });
          }
          keyed.sort((a, b) => a.pk - b.pk);
          tables.set(name, { columns, primaryKey: keyed.map((entry) => entry.name) });
        }
      }
      return tables.get(name);
    },
    resetSchemaCache() {
      statements.clear();
      tables.clear();
    },
    setAuthorizer(authorizer) {
      connection.setAuthorizer(authorizer);
    },
  };
}

function isThenable(value: unknown): boolean {
  return (
    (typeof value === 'object' || typeof value === 'function') &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

/**
 * Run `fn` inside BEGIN IMMEDIATE ... COMMIT. The write lock is taken at BEGIN,
 * waiting at most the connection's busy timeout. Any throw rolls back. The
 * callback must be synchronous: a returned promise is refused and rolled back.
 */
export function runImmediate<T>(executor: Executor, fn: () => T): T {
  if (executor.inTransaction()) throw new StorageUsageError('nested transactions are not supported');
  executor.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    if (isThenable(result)) throw new StorageUsageError('transaction callbacks must be synchronous');
    executor.exec('COMMIT');
    return result;
  } catch (error) {
    if (executor.inTransaction()) {
      try {
        executor.exec('ROLLBACK');
      } catch (rollbackError) {
        throw new StorageUsageError('rollback failed after a transaction error', {
          cause: new AggregateError([translateSqliteError(error), rollbackError]),
        });
      }
    }
    throw translateSqliteError(error);
  }
}
