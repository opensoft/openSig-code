// SPDX-License-Identifier: Apache-2.0
//
// Child process for the cross-process write test (DB-05). It opens the shared
// database and performs read-then-compare-and-set increments of the tenant
// row's version, each inside one BEGIN IMMEDIATE transaction. Because the
// write lock is taken before the read, every compare-and-set must succeed.
// Exit status: 0 when every increment succeeded, 1 otherwise.
//
// Arguments: <database path> <tenant id> <iterations>

import { openDatabase } from '../../../src/storage/db/index.ts';

const [path, tenantId, iterationsArg] = process.argv.slice(2);
const iterations = Number(iterationsArg);
const db = openDatabase({ path, busyTimeoutMs: 30_000 });
const store = db.forTenant(tenantId);
let lost = 0;
try {
  for (let i = 0; i < iterations; i += 1) {
    db.transaction(() => {
      const row = store.get('tenants', {});
      if (row === undefined) throw new Error('tenant row missing');
      if (!store.compareAndSet('tenants', {}, Number(row.version), { updated_at: row.updated_at })) lost += 1;
    });
  }
} finally {
  db.close();
}
process.stdout.write(JSON.stringify({ iterations, lost }));
process.exitCode = lost === 0 ? 0 : 1;
