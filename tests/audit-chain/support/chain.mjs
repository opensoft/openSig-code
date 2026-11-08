// SPDX-License-Identifier: Apache-2.0
//
// Shared helpers for the audit-chain tests (T029): a stepping clock, tenants
// with envelopes, and terminal envelopes whose blob refs point at real blobs.
// All content is synthetic.

import { randomBytes } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { AuditWriter } from '../../../src/storage/audit/index.ts';
import { openBlobStore } from '../../../src/storage/blobs/index.ts';
import { syntheticBytes } from '../../blobs/support/synthetic.mjs';
import { BASE_TIME, createTenant, envelopeRow, hex, openTemp, sid, ts } from '../../storage/support/fixtures.mjs';

export { BASE_TIME, createTenant, envelopeRow, hex, sid, syntheticBytes, ts };

/** A clock that advances one second per call, from the fixed base time. */
export function steppingClock(start = BASE_TIME) {
  let now = start;
  return () => new Date((now += 1000));
}

export function fixedClock(iso) {
  return () => new Date(iso);
}

/** A migrated database, a blob store and an audit writer in one scratch area. */
export function environment(scratch, clock = steppingClock()) {
  const { db, path, dir } = openTemp(scratch);
  const root = join(dir, 'blobs');
  mkdirSync(root, { mode: 0o700 });
  const blobs = openBlobStore({ root });
  return { db, path, dir, blobs, audit: new AuditWriter(db, { clock }), clock };
}

export function addEnvelope(db, tenant) {
  const id = sid('env');
  db.transaction(() => db.forTenant(tenant).insert('envelopes', envelopeRow(id)));
  return id;
}

/** A raw connection for simulating tampering (foreign keys off, as an attacker would). */
export function rawConnection(path) {
  return new DatabaseSync(path, { enableForeignKeyConstraints: false });
}

/**
 * An envelope taken directly to a terminal state, with a real document blob
 * and, for a completed envelope, real final PDF and evidence blobs.
 */
export function terminalEnvelope(db, blobs, tenant, { state = 'completed', updatedMinutes = 10, documentSeed } = {}) {
  const store = db.forTenant(tenant);
  const env = sid('env');
  const rev = sid('rev');
  const doc = blobs.put(tenant, syntheticBytes(documentSeed ?? `document-${randomBytes(6).toString('hex')}`, 2048));
  const completed = state === 'completed';
  const pdf = completed ? blobs.put(tenant, syntheticBytes(`final-${env}`, 4096)) : undefined;
  const evidence = completed ? blobs.put(tenant, syntheticBytes(`evidence-${env}`, 512)) : undefined;
  db.transaction(() => {
    store.insert('envelopes', envelopeRow(env));
    store.insert('document_revisions', {
      id: rev,
      envelope_id: env,
      content_digest: doc.digest,
      blob_ref: doc.ref,
      bytes: 2048,
      pages: 1,
      page_geometry_json: '[]',
      parse_report_json: '{}',
      created_at: ts(2),
      frozen_at: ts(3),
    });
    store.compareAndSet('envelopes', { id: env }, 1, {
      state,
      base_revision_id: rev,
      manifest_digest: hex(`manifest-${env}`),
      recipients_digest: hex(`recipients-${env}`),
      approvals_complete: completed ? 1 : 0,
      updated_at: ts(updatedMinutes),
    });
    if (completed) {
      store.insert('signing_jobs', {
        envelope_id: env,
        reserved_version: 2,
        status: 'succeeded',
        attempt_count: 1,
        max_attempts: 3,
        fencing_token: 1,
        created_at: ts(4),
        updated_at: ts(5),
      });
      store.insert('final_artifacts', {
        artifact_id: sid('art'),
        envelope_id: env,
        artifact_digest: pdf.digest,
        approved_composition_digest: hex(`composition-${env}`),
        pdf_blob_ref: pdf.ref,
        evidence_blob_ref: evidence.ref,
        signer_certificate_sha256: hex('certificate'),
        development_certificate: 1,
        verifier_name: 'opensig-verifier',
        verifier_version: '0.0.0',
        verification_json: '{"integrity":"valid"}',
        fencing_token: 1,
        completed_at: ts(5),
      });
    }
  });
  return { env, rev, doc, pdf, evidence };
}
