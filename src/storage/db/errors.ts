// SPDX-License-Identifier: Apache-2.0
//
// Typed storage errors. Messages name tables, columns and constraints, never
// row values.

export class StorageError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
    this.code = code;
  }
}

/** The bounded busy timeout elapsed while another connection held the write lock. */
export class StorageBusyError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('storage_busy', message, options);
  }
}

export type ConstraintKind =
  | 'unique'
  | 'primary-key'
  | 'foreign-key'
  | 'check'
  | 'not-null'
  | 'trigger'
  | 'datatype'
  | 'other';

/** A schema constraint or trigger rejected the write. */
export class StorageConstraintError extends StorageError {
  readonly constraint: ConstraintKind;

  constructor(constraint: ConstraintKind, message: string, options?: { cause?: unknown }) {
    super('storage_constraint', message, options);
    this.constraint = constraint;
  }
}

/** The caller broke a storage-layer rule (scope, identifiers, transactions, options). */
export class StorageUsageError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('storage_usage', message, options);
  }
}

/** The migration set or the database's applied migrations were refused. */
export class MigrationError extends StorageError {
  constructor(message: string, options?: { cause?: unknown }) {
    super('migration_refused', message, options);
  }
}

const SQLITE_BUSY = 5;
const SQLITE_LOCKED = 6;
const SQLITE_CONSTRAINT = 19;

const CONSTRAINT_KINDS: ReadonlyMap<number, ConstraintKind> = new Map([
  [275, 'check'],
  [787, 'foreign-key'],
  [1299, 'not-null'],
  [1555, 'primary-key'],
  [1811, 'trigger'],
  [2067, 'unique'],
  [3091, 'datatype'],
]);

interface SqliteErrorShape {
  code?: unknown;
  errcode?: unknown;
  message?: unknown;
}

/** Map a node:sqlite error to a typed storage error; other values pass through. */
export function translateSqliteError(error: unknown): unknown {
  if (error instanceof StorageError || typeof error !== 'object' || error === null) return error;
  const shape = error as SqliteErrorShape;
  if (shape.code !== 'ERR_SQLITE_ERROR' || typeof shape.errcode !== 'number') return error;
  const message = typeof shape.message === 'string' ? shape.message : 'sqlite error';
  const primary = shape.errcode & 0xff;
  if (primary === SQLITE_BUSY || primary === SQLITE_LOCKED) {
    return new StorageBusyError(`database is busy: ${message}`, { cause: error });
  }
  if (primary === SQLITE_CONSTRAINT) {
    return new StorageConstraintError(CONSTRAINT_KINDS.get(shape.errcode) ?? 'other', message, { cause: error });
  }
  return error;
}
