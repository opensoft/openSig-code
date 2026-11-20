// SPDX-License-Identifier: Apache-2.0
//
// The envelope.expired announcement (T010; A-010, request #24, ruling (6)).
// The contract's WebhookEvent types include envelope.expired, and an outbox
// event is inserted in the same transaction as the change it announces
// (src/storage/outbox). T007's expiry (EnvelopeService.expireIfDue and its
// refusal path) writes no outbox event, so every expiry T010 drives is
// announced here: the sweeper's (src/jobs/expiry.ts) and the one an approval or
// decline commits when it finds expires_at passed (src/api/recipients/
// approval.ts). The listener runs as the EnvelopeService's onChange, inside the
// expiry's own transaction, after the compare-and-set wrote the new version, so
// the event exists exactly when the expiry committed, once per expiry, and a
// refused or rolled-back expiry announces nothing. Every other change goes to
// the wrapped listener (the recipient ceremony's) unchanged and first.

import type { EnvelopeChange } from '../envelopes/service.ts';
import type { Database, TenantStore } from '../../storage/db/index.ts';
import { enqueueOutboxEvent } from '../../storage/outbox/index.ts';

export type EnvelopeChangeListener = (change: EnvelopeChange, store: TenantStore) => void;

/** `inner` (the ceremony's onEnvelopeChange), then envelope.expired for an expiry, in the same transaction. */
export function expiryAnnouncer(db: Database, clock: () => Date, inner: EnvelopeChangeListener): EnvelopeChangeListener {
  if (typeof inner !== 'function') throw new TypeError('the expiry announcer wraps the recipient ceremony’s change listener');
  if (typeof clock !== 'function') throw new TypeError('the expiry announcer needs an injected clock');
  return (change, store) => {
    inner(change, store);
    if (change.operation === 'expire') {
      enqueueOutboxEvent(db, store.tenantId, { type: 'envelope.expired', envelopeId: change.envelopeId, envelopeVersion: change.version }, { clock });
    }
  };
}
