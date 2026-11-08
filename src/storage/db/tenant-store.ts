// SPDX-License-Identifier: Apache-2.0
//
// Tenant-scoped query helpers. Every statement built here filters on the
// store's tenant_id, so callers never add (or forget) the tenant filter. Table
// and column names are checked against the schema and the table policy map;
// values are always bound parameters. Writes require an open transaction,
// which Database.transaction() opens with BEGIN IMMEDIATE.

import type { SQLInputValue, SQLOutputValue } from 'node:sqlite';

import { tablePolicy, type TablePolicy } from '../schema/entities.ts';
import { StorageUsageError, translateSqliteError } from './errors.ts';
import type { Executor, TableInfo } from './executor.ts';

export type SqlValue = null | number | bigint | string | Uint8Array;
export type Row = Record<string, SQLOutputValue>;
export type Values = Readonly<Record<string, SqlValue>>;

export type Comparison =
  | { readonly op: '=' | '<>' | '<' | '<=' | '>' | '>='; readonly value: string | number | bigint }
  | { readonly op: 'in'; readonly values: readonly (string | number | bigint)[] }
  | { readonly op: 'is-null' }
  | { readonly op: 'is-not-null' };

/** Column conditions joined with AND. A plain value means equality; null means IS NULL. */
export type Where = Readonly<Record<string, SqlValue | Comparison>>;

export interface ListOptions {
  readonly orderBy?: readonly (readonly [column: string, direction: 'asc' | 'desc'])[];
  readonly limit?: number;
}

export const TENANT_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
export const MAX_LIST_LIMIT = 10_000;
const MAX_IN_VALUES = 500;
const TENANT_COLUMN = 'tenant_id';
const VERSION_COLUMN = 'version';
const COMPARISON_OPERATORS: ReadonlySet<string> = new Set(['=', '<>', '<', '<=', '>', '>=']);

interface ResolvedTable {
  readonly name: string;
  readonly policy: TablePolicy;
  readonly info: TableInfo;
}

function quote(identifier: string): string {
  return `"${identifier}"`;
}

function checkValue(table: string, column: string, value: unknown): SQLInputValue {
  if (value === null || typeof value === 'string' || typeof value === 'bigint' || value instanceof Uint8Array) {
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  throw new StorageUsageError(`${table}.${column}: unsupported value type ${value === undefined ? 'undefined' : typeof value}`);
}

function isComparison(value: unknown): value is Comparison {
  return typeof value === 'object' && value !== null && !(value instanceof Uint8Array) && 'op' in value;
}

// Set by TenantStore's static block; only restricted-writer.ts should use it.
let restrictedInsertHook: ((store: TenantStore, table: string, values: Values) => void) | undefined;

/** Internal: the restricted writer's insert path (see restricted-writer.ts). */
export function restrictedInsert(store: TenantStore, table: string, values: Values): void {
  if (restrictedInsertHook === undefined) throw new StorageUsageError('restricted writer is unavailable');
  restrictedInsertHook(store, table, values);
}

export class TenantStore {
  readonly tenantId: string;
  readonly #executor: Executor;

  static {
    restrictedInsertHook = (store, table, values) => store.#insertRow(table, values, true);
  }

  /** Internal: use Database.forTenant(). */
  constructor(executor: Executor, tenantId: string) {
    if (typeof tenantId !== 'string' || !TENANT_ID_PATTERN.test(tenantId)) {
      throw new StorageUsageError('tenant id must match ^[A-Za-z0-9_-]{16,64}$');
    }
    this.#executor = executor;
    this.tenantId = tenantId;
  }

  #table(name: string): ResolvedTable {
    const policy = tablePolicy(name);
    const info = policy === undefined ? undefined : this.#executor.table(name);
    if (policy === undefined || info === undefined) {
      throw new StorageUsageError(`unknown table: ${JSON.stringify(name)}`);
    }
    if (!info.columns.has(TENANT_COLUMN)) throw new StorageUsageError(`table ${name} has no tenant_id column`);
    return { name, policy, info };
  }

  #column(table: ResolvedTable, column: string): string {
    if (!table.info.columns.has(column)) {
      throw new StorageUsageError(`unknown column: ${table.name}.${JSON.stringify(column)}`);
    }
    return quote(column);
  }

  #requireTransaction(operation: string): void {
    if (!this.#executor.inTransaction()) {
      throw new StorageUsageError(`${operation} requires a transaction (Database.transaction)`);
    }
  }

  #refuseTenantColumn(table: ResolvedTable, values: Values): void {
    if (Object.hasOwn(values, TENANT_COLUMN)) {
      throw new StorageUsageError(`${table.name}: tenant_id is set by the storage layer, never by the caller`);
    }
  }

  #where(table: ResolvedTable, where: Where, params: SQLInputValue[]): string {
    const clauses = [`${quote(TENANT_COLUMN)} = ?`];
    params.push(this.tenantId);
    for (const [column, condition] of Object.entries(where)) {
      if (column === TENANT_COLUMN) {
        throw new StorageUsageError(`${table.name}: the tenant filter is applied by the storage layer`);
      }
      const name = this.#column(table, column);
      if (condition === null) {
        clauses.push(`${name} IS NULL`);
      } else if (!isComparison(condition)) {
        clauses.push(`${name} = ?`);
        params.push(checkValue(table.name, column, condition));
      } else if (condition.op === 'is-null') {
        clauses.push(`${name} IS NULL`);
      } else if (condition.op === 'is-not-null') {
        clauses.push(`${name} IS NOT NULL`);
      } else if (condition.op === 'in') {
        const values = condition.values;
        if (!Array.isArray(values) || values.length === 0 || values.length > MAX_IN_VALUES) {
          throw new StorageUsageError(`${table.name}.${column}: "in" needs 1..${MAX_IN_VALUES} values`);
        }
        clauses.push(`${name} IN (${values.map(() => '?').join(', ')})`);
        for (const value of values) params.push(checkValue(table.name, column, value));
      } else if (COMPARISON_OPERATORS.has(condition.op)) {
        clauses.push(`${name} ${condition.op} ?`);
        params.push(checkValue(table.name, column, condition.value));
      } else {
        throw new StorageUsageError(`${table.name}.${column}: unsupported operator`);
      }
    }
    return clauses.join(' AND ');
  }

  /** Update and delete must name the row(s) unless tenant_id alone is the key. */
  #requireNarrowing(table: ResolvedTable, where: Where, operation: string): void {
    const keyIsTenant = table.info.primaryKey.length === 1 && table.info.primaryKey[0] === TENANT_COLUMN;
    if (Object.keys(where).length === 0 && !keyIsTenant) {
      throw new StorageUsageError(`${operation} on ${table.name} needs a non-empty where`);
    }
  }

  #refuseImmutable(table: ResolvedTable, operation: string): void {
    if (table.policy.mutability === 'immutable') {
      throw new StorageUsageError(`${table.name} rows are immutable: ${operation} is refused`);
    }
  }

  #run(sql: string, params: SQLInputValue[]): number {
    try {
      return Number(this.#executor.statement(sql).run(...params).changes);
    } catch (error) {
      throw translateSqliteError(error);
    }
  }

  #all(sql: string, params: SQLInputValue[]): Row[] {
    try {
      return this.#executor.statement(sql).all(...params);
    } catch (error) {
      throw translateSqliteError(error);
    }
  }

  #insertRow(table: string, values: Values, restricted: boolean): void {
    const resolved = this.#table(table);
    if (resolved.policy.writer === 'restricted' && !restricted) {
      throw new StorageUsageError(`${table} is written only by the restricted writer`);
    }
    if (resolved.policy.writer !== 'restricted' && restricted) {
      throw new StorageUsageError(`${table} is not a restricted table`);
    }
    this.#requireTransaction(`insert into ${table}`);
    this.#refuseTenantColumn(resolved, values);
    const columns = [quote(TENANT_COLUMN)];
    const params: SQLInputValue[] = [this.tenantId];
    for (const [column, value] of Object.entries(values)) {
      columns.push(this.#column(resolved, column));
      params.push(checkValue(table, column, value));
    }
    const sql = `INSERT INTO ${quote(table)} (${columns.join(', ')}) VALUES (${params.map(() => '?').join(', ')})`;
    this.#run(sql, params);
  }

  /** Insert one row; tenant_id comes from this store. */
  insert(table: string, values: Values): void {
    this.#insertRow(table, values, false);
  }

  /** The single row matching `where`, or undefined. More than one match is an error. */
  get(table: string, where: Where): Row | undefined {
    const resolved = this.#table(table);
    const params: SQLInputValue[] = [];
    const rows = this.#all(`SELECT * FROM ${quote(table)} WHERE ${this.#where(resolved, where, params)} LIMIT 2`, params);
    if (rows.length > 1) throw new StorageUsageError(`get on ${table} matched more than one row`);
    return rows[0];
  }

  list(table: string, where: Where = {}, options: ListOptions = {}): Row[] {
    const resolved = this.#table(table);
    const params: SQLInputValue[] = [];
    let sql = `SELECT * FROM ${quote(table)} WHERE ${this.#where(resolved, where, params)}`;
    const order = options.orderBy ?? [];
    if (order.length > 0) {
      sql += ` ORDER BY ${order
        .map(([column, direction]) => {
          if (direction !== 'asc' && direction !== 'desc') throw new StorageUsageError('order direction must be asc or desc');
          return `${this.#column(resolved, column)} ${direction.toUpperCase()}`;
        })
        .join(', ')}`;
    }
    const limit = options.limit ?? MAX_LIST_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_LIST_LIMIT) {
      throw new StorageUsageError(`limit must be an integer in 1..${MAX_LIST_LIMIT}`);
    }
    sql += ` LIMIT ${limit}`;
    return this.#all(sql, params);
  }

  count(table: string, where: Where = {}): number {
    const resolved = this.#table(table);
    const params: SQLInputValue[] = [];
    const rows = this.#all(`SELECT count(*) AS n FROM ${quote(table)} WHERE ${this.#where(resolved, where, params)}`, params);
    return Number(rows[0]?.['n'] ?? 0);
  }

  /** Update matching rows; returns the number changed. */
  update(table: string, where: Where, values: Values): number {
    const resolved = this.#table(table);
    this.#refuseImmutable(resolved, 'update');
    this.#requireTransaction(`update of ${table}`);
    this.#requireNarrowing(resolved, where, 'update');
    this.#refuseTenantColumn(resolved, values);
    const entries = Object.entries(values);
    if (entries.length === 0) throw new StorageUsageError(`update of ${table} sets no columns`);
    const params: SQLInputValue[] = [];
    const sets = entries.map(([column, value]) => {
      const name = this.#column(resolved, column);
      params.push(checkValue(table, column, value));
      return `${name} = ?`;
    });
    return this.#run(`UPDATE ${quote(table)} SET ${sets.join(', ')} WHERE ${this.#where(resolved, where, params)}`, params);
  }

  /**
   * Compare and set: update the one row matching `where` whose version equals
   * `expectedVersion`, and increment its version. Returns false when the
   * version differs or no row matches; a match of more than one row throws.
   */
  compareAndSet(table: string, where: Where, expectedVersion: number, values: Values): boolean {
    const resolved = this.#table(table);
    this.#refuseImmutable(resolved, 'compare-and-set');
    this.#requireTransaction(`compare-and-set on ${table}`);
    this.#requireNarrowing(resolved, where, 'compare-and-set');
    this.#refuseTenantColumn(resolved, values);
    if (!resolved.info.columns.has(VERSION_COLUMN)) throw new StorageUsageError(`${table} has no version column`);
    if (Object.hasOwn(values, VERSION_COLUMN) || Object.hasOwn(where, VERSION_COLUMN)) {
      throw new StorageUsageError(`${table}: compare-and-set owns the version column`);
    }
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
      throw new StorageUsageError('expected version must be a positive integer');
    }
    const params: SQLInputValue[] = [];
    const sets = Object.entries(values).map(([column, value]) => {
      const name = this.#column(resolved, column);
      params.push(checkValue(table, column, value));
      return `${name} = ?`;
    });
    sets.push(`${quote(VERSION_COLUMN)} = ${quote(VERSION_COLUMN)} + 1`);
    const filter = this.#where(resolved, where, params);
    params.push(expectedVersion);
    const changed = this.#run(
      `UPDATE ${quote(table)} SET ${sets.join(', ')} WHERE ${filter} AND ${quote(VERSION_COLUMN)} = ?`,
      params,
    );
    if (changed > 1) throw new StorageUsageError(`compare-and-set on ${table} matched more than one row`);
    return changed === 1;
  }

  /** Delete matching rows; returns the number deleted. */
  delete(table: string, where: Where): number {
    const resolved = this.#table(table);
    this.#refuseImmutable(resolved, 'delete');
    this.#requireTransaction(`delete from ${table}`);
    this.#requireNarrowing(resolved, where, 'delete');
    const params: SQLInputValue[] = [];
    return this.#run(`DELETE FROM ${quote(table)} WHERE ${this.#where(resolved, where, params)}`, params);
  }
}
