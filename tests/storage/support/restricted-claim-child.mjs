// SPDX-License-Identifier: Apache-2.0
//
// DB-23 child process: in a fresh process, the first claimRestrictedInsert()
// returns a working insert for the audit tables and every later claim throws.
// Prints one JSON line. All data is synthetic.

import { claimRestrictedInsert } from '../../../src/storage/db/tenant-store.ts';
import { auditEvent, createTenant, makeScratch, openTemp, sid } from './fixtures.mjs';

const scratch = makeScratch();
const out = {};
try {
  const hook = claimRestrictedInsert();
  out.first = typeof hook;
  for (const label of ['second', 'third']) {
    try {
      claimRestrictedInsert();
      out[label] = 'returned';
    } catch (error) {
      out[label] = `${error.code}: ${error.message}`;
    }
  }
  const { db } = openTemp(scratch);
  try {
    const tenant = sid('tenant');
    createTenant(db, tenant);
    const store = db.forTenant(tenant);
    db.transaction(() => hook(store, 'audit_events', auditEvent(1, null)));
    out.appended = store.count('audit_events');
    try {
      db.transaction(() => hook(store, 'envelopes', { id: sid('env') }));
      out.nonRestricted = 'accepted';
    } catch (error) {
      out.nonRestricted = `${error.code}: ${error.message}`;
    }
  } finally {
    db.close();
  }
} finally {
  scratch.cleanup();
}
process.stdout.write(`${JSON.stringify(out)}\n`);
