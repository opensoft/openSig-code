// SPDX-License-Identifier: Apache-2.0
//
// JCS-08 child process. "writer-first": load the audit writer, then try to
// obtain the restricted insert from outside it. "outsider-first": claim the
// restricted insert before the audit writer loads. Prints one JSON line. All
// data is synthetic.

import { auditEvent, createTenant, makeScratch, openTemp, sid } from '../../storage/support/fixtures.mjs';

const order = process.argv[2];
const out = {};
const scratch = makeScratch();
try {
  if (order === 'writer-first') {
    const { AuditWriter, verifyChain } = await import('../../../src/storage/audit/index.ts');
    const tenantStore = await import('../../../src/storage/db/tenant-store.ts');
    out.exportedInsert = Object.keys(tenantStore).some((name) => /restrictedInsert$/.test(name) && name !== 'claimRestrictedInsert');
    const { db } = openTemp(scratch);
    try {
      const tenant = sid('tenant');
      createTenant(db, tenant);
      const store = db.forTenant(tenant);
      let insert;
      try {
        insert = tenantStore.claimRestrictedInsert();
        out.outsideClaim = 'function';
      } catch (error) {
        out.outsideClaim = `${error.code}: ${error.message}`;
      }
      if (insert !== undefined) db.transaction(() => insert(store, 'audit_events', auditEvent(1, null)));
      out.outsideAppends = store.count('audit_events');
      const audit = new AuditWriter(db, { clock: () => new Date(Date.UTC(2026, 10, 8, 12)) });
      db.transaction(() => audit.append(tenant, { type: 'probe.event', actor: { kind: 'system', ref: 'probe' } }));
      out.writerAppends = store.count('audit_events');
      out.chainOk = verifyChain(db, tenant).ok;
    } finally {
      db.close();
    }
  } else if (order === 'outsider-first') {
    const tenantStore = await import('../../../src/storage/db/tenant-store.ts');
    out.outsideClaim = typeof tenantStore.claimRestrictedInsert();
    try {
      await import('../../../src/storage/audit/writer.ts');
      out.writerLoad = 'loaded';
    } catch (error) {
      out.writerLoad = `${error.code}: ${error.message}`;
    }
  } else {
    throw new Error(`unknown order ${order}`);
  }
} finally {
  scratch.cleanup();
}
process.stdout.write(`${JSON.stringify(out)}\n`);
