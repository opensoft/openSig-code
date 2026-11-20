// SPDX-License-Identifier: Apache-2.0
//
// A sealable seed with one or two recipients (the T038 correction FV-DIGEST;
// A-010 request #85 (1)). Each recipient has a typed signature field and a
// date field. The approvals are built with T010's buildApproval at the world
// clock's instant (their server_time) and chained in ordinal order: ordinal
// 2's prior_approval_digest is ordinal 1's stored approval_digest, as
// migration 0003's approvals_sequence trigger requires.
//
// `forge` stores, at one ordinal, either
// - `fieldValuesDigestAt`: a field_values_digest that is not the digest of the
//   stored values, with an approval_digest recomputed over that forged record
//   (the trace's S2), or
// - `approvalDigestAt`: an approval_digest that is not the digest of its
//   record, with a consistent field_values_digest.
// Every value is synthetic: digests hash fixed labels, and addresses use
// example.test.

import { buildApproval } from '../../../src/domain/approval/index.ts';
import { canonicalBytes, canonicalDigest, canonicalize } from '../../../src/domain/canonical/index.ts';
import { insertApproval, insertFinalizationReservation } from '../../../src/storage/repositories/approvals.ts';
import { insertManifest, insertRecipient } from '../../../src/storage/repositories/envelopes.ts';
import { draftEnvelope, hex, RESERVED_VERSION, revisionRow, sha256, sid, syntheticBytes, walkToFinalizing } from './world.mjs';

const CONSENT_TEXT = 'Synthetic consent wording for tests.';

/** A finalizing envelope with real seal records for `recipients` (1 or 2) recipients, each with a signature and a date field. */
export function seedSealableWith(world, { recipients = 1, forge = {}, maxAttempts = 5 } = {}) {
  if (recipients !== 1 && recipients !== 2) throw new Error(`seed: one or two recipients (got ${recipients})`);
  const { db, store, clock, blobs, tenantId } = world;
  const envelopeId = sid('env');
  const revisionId = sid('rev');
  const consentId = sid('cons');
  const now = clock.iso();
  const people = Array.from({ length: recipients }, (_, index) => ({ id: sid('rcp'), ordinal: index + 1, email: `recipient-${index + 1}@example.test`, role: 'approver' }));
  const document = blobs.put(tenantId, syntheticBytes(`document-${envelopeId}`, 2048));
  const fieldManifest = {
    schema: 'opensig.field-manifest/1',
    envelope_id: envelopeId,
    document_digest: document.digest,
    fields: people.flatMap((person) => [
      { key: `sig-${person.ordinal}`, recipient_id: person.id, recipient_ordinal: person.ordinal, page: 1, type: 'signature', rect: { x: 0.1, y: 0.1 + 0.3 * (person.ordinal - 1), width: 0.3, height: 0.1 } },
      { key: `date-${person.ordinal}`, recipient_id: person.id, recipient_ordinal: person.ordinal, page: 1, type: 'date', rect: { x: 0.5, y: 0.1 + 0.3 * (person.ordinal - 1), width: 0.2, height: 0.05 } },
    ]),
  };
  const manifestBytes = canonicalBytes(fieldManifest);
  const manifestDigest = sha256(manifestBytes);
  const consentDigest = sha256(Buffer.from(CONSENT_TEXT, 'utf8'));
  const approvals = [];
  db.transaction(() => {
    draftEnvelope(world, envelopeId, now, { recipientsCount: recipients });
    store.insert('document_revisions', revisionRow(world, envelopeId, revisionId, document.digest, 2048, now));
    for (const person of people) insertRecipient(store, { id: person.id, envelopeId, ordinal: person.ordinal, email: person.email, role: person.role, now });
    store.insert('consent_texts', { id: consentId, version: 'v1', locale: 'en', text: CONSENT_TEXT, text_digest: consentDigest, effective_from: now, created_at: now });
    insertManifest(store, envelopeId, { revisionId, schema: 'opensig.field-manifest/1', digest: manifestDigest, bytes: manifestBytes }, now);
    walkToFinalizing(store, envelopeId, revisionId, manifestDigest, now);
    let prior = null;
    for (const person of people) {
      const approvalId = sid('appr');
      const built = buildApproval({
        approvalId,
        recipient: { id: person.id, ordinal: person.ordinal, role: person.role, email: person.email },
        consentVersion: 'v1',
        consentTextDigest: consentDigest,
        documentDigest: document.digest,
        manifestDigest,
        priorApprovalDigest: prior,
        fieldValues: [
          { key: `sig-${person.ordinal}`, type: 'signature', mode: 'typed', text: `Synthetic Signer ${person.ordinal}` },
          { key: `date-${person.ordinal}`, type: 'date' },
        ],
        serverTime: now,
      });
      let fieldValuesDigest = built.fieldValuesDigest;
      let approvalDigest = built.approvalDigest;
      if (forge.fieldValuesDigestAt === person.ordinal) {
        fieldValuesDigest = hex(`forged-field-values-${person.ordinal}`);
        approvalDigest = canonicalDigest({ ...built.record, field_values_digest: fieldValuesDigest });
      }
      if (forge.approvalDigestAt === person.ordinal) approvalDigest = hex(`forged-approval-${person.ordinal}`);
      insertApproval(store, {
        id: approvalId,
        envelopeId,
        recipientId: person.id,
        documentDigest: document.digest,
        manifestDigest,
        priorApprovalDigest: prior,
        consentTextId: consentId,
        consentVersion: 'v1',
        consentTextDigest: consentDigest,
        fieldValuesJson: canonicalize(built.fieldValues),
        fieldValuesDigest,
        serverTime: now,
        approvalDigest,
      });
      approvals.push({ ordinal: person.ordinal, recipientId: person.id, storedFieldValuesDigest: fieldValuesDigest, valuesDigest: built.fieldValuesDigest, storedApprovalDigest: approvalDigest, recordDigest: built.approvalDigest });
      prior = approvalDigest;
    }
    insertFinalizationReservation(store, { envelopeId, reservedVersion: RESERVED_VERSION, maxAttempts, now });
  });
  return { envelopeId, reservedVersion: RESERVED_VERSION, serverTime: now, serverDay: now.slice(0, 10), approvals, documentDigest: document.digest, manifestDigest };
}
