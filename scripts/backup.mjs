#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig backup and restore (T030; data-model.md § "Backups and the
// exported-head ledger").
//
//   node scripts/backup.mjs create  --db FILE --blobs DIR --out DIR --ledger FILE [--first-backup] [--max-blob-bytes N]
//   node scripts/backup.mjs verify  --from DIR --ledger FILE [--first-restore]
//   node scripts/backup.mjs restore --from DIR --ledger FILE --db FILE --blobs DIR [--first-restore]
//   node scripts/backup.mjs --complete-staged DIR --ledger FILE
//   node scripts/backup.mjs --discard-staged DIR --ledger FILE [--abandon-committed LEDGER_DIGEST]
//   node scripts/backup.mjs --retire-tenant TENANT_ID --db FILE --ledger FILE
//   node scripts/backup.mjs --resync-ledger LEDGER_DIGEST --ledger FILE
//   node scripts/backup.mjs --break-lock NONCE --ledger FILE
//   node scripts/backup.mjs --break-lock damaged --ledger FILE
//
// All paths must be absolute. The ledger is the exported-head ledger beside
// the backups, on the local filesystem of the single service host. A missing
// ledger is refused: only --first-backup (creates it) or --first-restore
// (writes the restored heads) proceeds without one. --max-blob-bytes carries
// the source blob store's configured size limit; it is recorded in the
// manifest and used by verify and restore. Output is one line with counts,
// directories and reasons only (no content, secrets or capability values).
//
// Status and exit code:
//   published                       0  backup or --complete-staged published (parent fsynced)
//   discarded                       0  uncommitted staging deleted (the path deleted is reported)
//   abandoned-committed             0  pending committed staging deleted; the ledger stays as committed
//   ledger-synced                   0  --resync-ledger re-committed the current ledger bytes
//   verified / restored / retired / lock-broken / damaged-lock-moved   0
//   refused                         1  pre-commit refusal or failure, or a refused recovery
//   committed-unsynced             74  a ledger write other than a backup passed the rename but its
//                                      directory fsync failed; recover with --resync-ledger
//   committed-pending-publication  75  the ledger is committed, the backup is not yet published
//   (usage errors exit 2; 74 and 75 mean only their own status)

import {
  breakDamagedLock,
  breakLedgerLock,
  completeStaged,
  createBackup,
  DAMAGED_LOCK,
  discardStaged,
  LedgerCommitUnsyncedError,
  PendingPublicationError,
  RestoreRefusedError,
  restoreBackup,
  resyncLedger,
  retireTenant,
  verifyBackup,
} from '../src/storage/backup/index.ts';

const USAGE = [
  'usage: backup.mjs create --db FILE --blobs DIR --out DIR --ledger FILE [--first-backup] [--max-blob-bytes N]',
  '     | backup.mjs verify --from DIR --ledger FILE [--first-restore]',
  '     | backup.mjs restore --from DIR --ledger FILE --db FILE --blobs DIR [--first-restore]',
  '     | backup.mjs --complete-staged DIR --ledger FILE',
  '     | backup.mjs --discard-staged DIR --ledger FILE [--abandon-committed LEDGER_DIGEST]',
  '     | backup.mjs --retire-tenant TENANT_ID --db FILE --ledger FILE',
  '     | backup.mjs --resync-ledger LEDGER_DIGEST --ledger FILE',
  '     | backup.mjs --break-lock NONCE|damaged --ledger FILE',
].join('\n');

const EXIT_UNSYNCED = 74;
const EXIT_PENDING = 75;

const COMMANDS = {
  create: { values: ['db', 'blobs', 'out', 'ledger'], optional: ['max-blob-bytes'], flags: ['first-backup'] },
  verify: { values: ['from', 'ledger'], optional: [], flags: ['first-restore'] },
  restore: { values: ['from', 'ledger', 'db', 'blobs'], optional: [], flags: ['first-restore'] },
  '--complete-staged': { values: ['ledger'], optional: [], flags: [] },
  '--discard-staged': { values: ['ledger'], optional: ['abandon-committed'], flags: [] },
  '--retire-tenant': { values: ['db', 'ledger'], optional: [], flags: [] },
  '--resync-ledger': { values: ['ledger'], optional: [], flags: [] },
  '--break-lock': { values: ['ledger'], optional: [], flags: [] },
};

function usage(message) {
  process.stderr.write(`backup: USAGE ${message}\n${USAGE}\n`);
  process.exitCode = 2;
}

function parse(argv) {
  const [command, ...args] = argv;
  const spec = Object.hasOwn(COMMANDS, command ?? '') ? COMMANDS[command] : undefined;
  if (spec === undefined) return { error: `unknown command ${JSON.stringify(command ?? '')}` };
  let rest = args;
  let target;
  if (command.startsWith('--')) {
    target = args[0];
    if (target === undefined || target.startsWith('--')) return { error: `missing value for ${command}` };
    rest = args.slice(1);
  }
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
    if (name === undefined || (!spec.values.includes(name) && !spec.optional.includes(name))) return { error: `unknown argument ${JSON.stringify(flag)}` };
    const value = rest[i + 1];
    if (value === undefined || value.startsWith('--')) return { error: `missing value for --${name}` };
    if (Object.hasOwn(values, name)) return { error: `repeated --${name}` };
    values[name] = value;
    i += 2;
  }
  const missing = spec.values.filter((name) => !Object.hasOwn(values, name));
  if (missing.length > 0) return { error: `missing --${missing.join(', --')}` };
  if (Object.hasOwn(values, 'max-blob-bytes') && !/^[1-9][0-9]{0,15}$/.test(values['max-blob-bytes'])) {
    return { error: '--max-blob-bytes must be a positive integer' };
  }
  return { command, target, values, flags };
}

function line(text) {
  process.stdout.write(`backup: ${text}\n`);
}

async function run({ command, target, values, flags }) {
  const clock = () => new Date();
  const firstRestore = flags.has('first-restore');
  switch (command) {
    case 'create': {
      const manifest = await createBackup({
        databasePath: values.db,
        blobRoot: values.blobs,
        outDir: values.out,
        ledgerPath: values.ledger,
        clock,
        firstBackup: flags.has('first-backup'),
        ...(Object.hasOwn(values, 'max-blob-bytes') ? { maxBlobBytes: Number(values['max-blob-bytes']) } : {}),
      });
      const blobs = manifest.tenants.reduce((sum, tenant) => sum + tenant.blob_count, 0);
      return line(`published directory=${values.out} tenants=${manifest.tenants.length} blobs=${blobs} schema=${manifest.schema_version}`);
    }
    case 'verify':
    case 'restore': {
      const report =
        command === 'verify'
          ? verifyBackup({ backupDir: values.from, ledgerPath: values.ledger, firstRestore })
          : restoreBackup({ backupDir: values.from, ledgerPath: values.ledger, databasePath: values.db, blobRoot: values.blobs, firstRestore });
      const blobs = report.tenants.reduce((sum, tenant) => sum + tenant.blobs, 0);
      const events = report.tenants.reduce((sum, tenant) => sum + tenant.events, 0);
      return line(`${command === 'verify' ? 'verified' : 'restored'} tenants=${report.tenants.length} events=${events} blobs=${blobs} schema=${report.schema_version}`);
    }
    case '--complete-staged': {
      const result = completeStaged(target, { ledgerPath: values.ledger });
      return line(`published directory=${result.directory}`);
    }
    case '--discard-staged': {
      const result = discardStaged(target, {
        ledgerPath: values.ledger,
        ...(Object.hasOwn(values, 'abandon-committed') ? { abandonCommitted: values['abandon-committed'] } : {}),
      });
      if (result.status === 'discarded') return line(`discarded directory=${result.directory}`);
      const consequence =
        result.headsChanged === true
          ? 'the ledger stays as committed, ahead of every published backup; every restore refuses until a backup carrying the committed heads is published'
          : result.headsChanged === false
            ? 'the ledger stays as committed; this backup did not change the ledger heads, so a published backup that carries them stays restorable'
            : 'the ledger stays as committed';
      return line(`abandoned-committed directory=${result.directory} ledger-digest=${result.ledgerDigest}: the staged backup was deleted; ${consequence}`);
    }
    case '--retire-tenant': {
      const retired = retireTenant({ databasePath: values.db, ledgerPath: values.ledger, tenantId: target, clock });
      return line(`retired tenant=${target} seq=${retired.seq}`);
    }
    case '--resync-ledger': {
      const synced = resyncLedger(target, { ledgerPath: values.ledger });
      return line(`ledger-synced ledger=${synced.ledgerPath} ledger-digest=${synced.ledgerDigest}`);
    }
    case '--break-lock': {
      if (target === DAMAGED_LOCK) {
        const moved = breakDamagedLock(values.ledger);
        return line(`damaged-lock-moved path=${moved.movedTo}`);
      }
      const holder = breakLedgerLock(values.ledger, target);
      return line(`lock-broken pid=${holder.pid} host=${holder.hostname}`);
    }
    default:
      throw new Error(`unhandled command ${command}`);
  }
}

async function main() {
  const parsed = parse(process.argv.slice(2));
  if (parsed.error !== undefined) return usage(parsed.error);
  try {
    await run(parsed);
  } catch (error) {
    if (error instanceof PendingPublicationError) {
      line(`committed-pending-publication directory=${error.directory} ledger-digest=${error.ledgerDigest} recover="${error.recovery}": ${error.message}`);
      process.exitCode = EXIT_PENDING;
      return;
    }
    if (error instanceof RestoreRefusedError) {
      line(`refused ${error.reasons.length} reason(s): ${error.reasons.join('; ')}`);
      process.exitCode = 1;
      return;
    }
    if (error instanceof LedgerCommitUnsyncedError) {
      line(
        `committed-unsynced ledger=${error.ledgerPath} previous-digest=${error.previousDigest ?? 'none'} ledger-digest=${error.ledgerDigest} recover="${error.recovery}": ${error.message}`,
      );
      process.exitCode = EXIT_UNSYNCED;
      return;
    }
    if (error?.code === 'storage_usage') return usage(error.message);
    line(`refused ${error?.code ?? 'error'}: ${error?.message ?? String(error)}`);
    process.exitCode = 1;
  }
}

await main();
