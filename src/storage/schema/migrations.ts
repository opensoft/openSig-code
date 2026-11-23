// SPDX-License-Identifier: Apache-2.0
//
// Loads the versioned migration files in ./migrations/. File names are
// NNNN-name.sql with versions 1..N and no gaps. Migrations are append-only:
// each file's SHA-256 is recorded when it is applied, the migration runner
// refuses a database whose recorded digest differs, and tests/storage/ pins the
// digests of the T003 migrations.

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { MigrationError } from '../db/errors.ts';

export interface Migration {
  readonly version: number;
  readonly name: string;
  readonly sql: string;
  readonly sha256: string;
}

export const MIGRATIONS_DIRECTORY: string = fileURLToPath(new URL('./migrations/', import.meta.url));

const FILE_NAME = /^(\d{4})-([a-z0-9]+(?:-[a-z0-9]+)*)\.sql$/;

export function sha256Hex(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Read and validate the migration files of `directory`, ordered by version. */
export function loadMigrations(directory: string = MIGRATIONS_DIRECTORY): Migration[] {
  const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });
  const migrations: Migration[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const match = FILE_NAME.exec(entry.name);
    if (!entry.isFile() || match === null) {
      throw new MigrationError(`unexpected entry in the migrations directory: ${entry.name}`);
    }
    const bytes = readFileSync(join(directory, entry.name));
    let sql: string;
    try {
      sql = decoder.decode(bytes);
    } catch (error) {
      throw new MigrationError(`migration ${entry.name} is not valid UTF-8`, { cause: error });
    }
    if (sql.startsWith('﻿')) throw new MigrationError(`migration ${entry.name} starts with a byte order mark`);
    migrations.push({ version: Number(match[1]), name: entry.name, sql, sha256: sha256Hex(bytes) });
  }
  migrations.sort((a, b) => a.version - b.version);
  validateMigrationSet(migrations);
  return migrations;
}

/** Versions must run 1..N without gaps or duplicates, each digest must match its text. */
export function validateMigrationSet(migrations: readonly Migration[]): void {
  migrations.forEach((migration, index) => {
    if (migration.version !== index + 1) {
      throw new MigrationError(
        `migration versions must run 1..N without gaps or duplicates: expected ${index + 1}, found ${migration.version} (${migration.name})`,
      );
    }
    if (sha256Hex(Buffer.from(migration.sql, 'utf8')) !== migration.sha256) {
      throw new MigrationError(`migration ${migration.name} does not match its recorded digest`);
    }
  });
}
