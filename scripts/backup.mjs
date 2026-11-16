#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig backup and restore (T030).
//
//   node scripts/backup.mjs create  --db FILE --blobs DIR --out DIR  --ledger FILE [--first-backup]
//   node scripts/backup.mjs verify  --from DIR --ledger FILE [--first-restore]
//   node scripts/backup.mjs restore --from DIR --ledger FILE --db FILE --blobs DIR [--first-restore]
//
// All paths must be absolute. The ledger is the exported-head ledger kept
// outside the database; backup and restore refuse an audit chain that does
// not contain the head recorded there. A missing ledger is refused: only
// --first-backup (create the ledger) or --first-restore (nothing was ever
// exported) proceeds without one. Output is one summary line with counts and
// reasons only (no content, digests of secrets or capability values).
//
// Exit status: 0 success, 1 verification refused or backup failed, 2 usage.

import { createBackup, RestoreRefusedError, restoreBackup, verifyBackup } from '../src/storage/backup/index.ts';

const USAGE =
  'usage: backup.mjs create --db FILE --blobs DIR --out DIR --ledger FILE [--first-backup] | verify --from DIR --ledger FILE [--first-restore] | restore --from DIR --ledger FILE --db FILE --blobs DIR [--first-restore]';

const COMMANDS = {
  create: { values: ['db', 'blobs', 'out', 'ledger'], flags: ['first-backup'] },
  verify: { values: ['from', 'ledger'], flags: ['first-restore'] },
  restore: { values: ['from', 'ledger', 'db', 'blobs'], flags: ['first-restore'] },
};

function usage(message) {
  process.stderr.write(`backup: USAGE ${message}\n${USAGE}\n`);
  process.exitCode = 2;
}

function parse(argv) {
  const [command, ...rest] = argv;
  const spec = Object.hasOwn(COMMANDS, command ?? '') ? COMMANDS[command] : undefined;
  if (spec === undefined) return { error: `unknown command ${JSON.stringify(command ?? '')}` };
  const values = {};
  const flags = new Set();
  for (let i = 0; i < rest.length; ) {
    const flag = rest[i];
    const name = typeof flag === 'string' && flag.startsWith('--') ? flag.slice(2) : undefined;
    if (name !== undefined && spec.flags.includes(name)) {
      if (flags.has(name)) return { error: `repeated --${name}` };
      flags.add(name);
      i += 1;
      continue;
    }
    if (name === undefined || !spec.values.includes(name)) return { error: `unknown argument ${JSON.stringify(flag)}` };
    const value = rest[i + 1];
    if (value === undefined || value.startsWith('--')) return { error: `missing value for --${name}` };
    if (Object.hasOwn(values, name)) return { error: `repeated --${name}` };
    values[name] = value;
    i += 2;
  }
  const missing = spec.values.filter((name) => !Object.hasOwn(values, name));
  if (missing.length > 0) return { error: `missing --${missing.join(', --')}` };
  return { command, values, flags };
}

async function main() {
  const parsed = parse(process.argv.slice(2));
  if (parsed.error !== undefined) return usage(parsed.error);
  const { command, values, flags } = parsed;
  const firstRestore = flags.has('first-restore');
  const clock = () => new Date();
  try {
    if (command === 'create') {
      const manifest = await createBackup({
        databasePath: values.db,
        blobRoot: values.blobs,
        outDir: values.out,
        ledgerPath: values.ledger,
        clock,
        firstBackup: flags.has('first-backup'),
      });
      const blobs = manifest.tenants.reduce((sum, tenant) => sum + tenant.blob_count, 0);
      process.stdout.write(`backup: PASS created tenants=${manifest.tenants.length} blobs=${blobs} schema=${manifest.schema_version}\n`);
    } else {
      const report =
        command === 'verify'
          ? verifyBackup({ backupDir: values.from, ledgerPath: values.ledger, firstRestore })
          : restoreBackup({ backupDir: values.from, ledgerPath: values.ledger, databasePath: values.db, blobRoot: values.blobs, firstRestore });
      const blobs = report.tenants.reduce((sum, tenant) => sum + tenant.blobs, 0);
      const events = report.tenants.reduce((sum, tenant) => sum + tenant.events, 0);
      process.stdout.write(`backup: PASS ${command === 'verify' ? 'verified' : 'restored'} tenants=${report.tenants.length} events=${events} blobs=${blobs} schema=${report.schema_version}\n`);
    }
  } catch (error) {
    if (error instanceof RestoreRefusedError) {
      process.stdout.write(`backup: REFUSED ${error.reasons.length} reason(s): ${error.reasons.join('; ')}\n`);
      process.exitCode = 1;
      return;
    }
    if (error?.code === 'storage_usage') return usage(error.message);
    process.stdout.write(`backup: FAIL ${error?.code ?? 'error'}: ${error?.message ?? String(error)}\n`);
    process.exitCode = 1;
  }
}

await main();
