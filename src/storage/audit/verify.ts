// SPDX-License-Identifier: Apache-2.0
//
// Audit chain verification: recompute every event digest from its row, check
// seq continuity from 1 and prev_digest links, check every checkpoint against
// the chain, and detect a truncated tail against checkpoints and against an
// externally recorded head (for example the last exported head or a receipt's
// chain head). The chain is tamper-evident, not tamper-proof: an attacker who
// rewrites every row and checkpoint consistently is caught only by a head
// recorded outside the database.
//
// Events and checkpoints are read with the store's keyset iterator, so every
// row is seen exactly once however many there are, including several
// checkpoints at the same seq (a cadence and completion checkpoints).

import type { Database } from '../db/connection.ts';
import { eventDigest, eventFromRow, recordFromRow, type AuditEventRecord } from './event.ts';
import type { AuditHead } from './writer.ts';

export type ChainProblemKind =
  | 'malformed-row'
  | 'seq-gap'
  | 'link-break'
  | 'digest-mismatch'
  | 'checkpoint-mismatch'
  | 'truncated'
  | 'head-mismatch';

export interface ChainProblem {
  readonly kind: ChainProblemKind;
  readonly seq: number;
  readonly detail: string;
}

export interface ChainReport {
  readonly ok: boolean;
  readonly events: number;
  readonly checkpoints: number;
  readonly head: AuditHead | null;
  readonly problems: readonly ChainProblem[];
}

export interface VerifyOptions {
  /** A head recorded outside the database; the chain must contain it unchanged. */
  readonly expectedHead?: AuditHead;
}

export function verifyChain(db: Database, tenantId: string, options: VerifyOptions = {}): ChainReport {
  const problems: ChainProblem[] = [];
  const digests = new Map<number, string>();
  let expectedSeq = 1;
  let previous: string | null = null;
  let head: AuditHead | null = null;
  let events = 0;

  const store = db.forTenant(tenantId);
  for (const row of store.iterate('audit_events', {}, { orderBy: [['seq', 'asc']] })) {
    events += 1;
    const seq = Number(row['seq']);
    const stored = String(row['event_digest']);
    if (seq !== expectedSeq) {
      problems.push({ kind: 'seq-gap', seq, detail: `expected seq ${expectedSeq}` });
      previous = null;
    }
    expectedSeq = seq + 1;
    digests.set(seq, stored);
    head = { seq, digest: stored };
    let event;
    try {
      event = eventFromRow(row);
    } catch (error) {
      problems.push({ kind: 'malformed-row', seq, detail: (error as Error).message });
      previous = stored;
      continue;
    }
    if (seq === 1 ? event.prevDigest !== null : previous !== null && event.prevDigest !== previous) {
      problems.push({ kind: 'link-break', seq, detail: 'prev_digest does not equal the previous event_digest' });
    }
    if (eventDigest(event) !== stored) {
      problems.push({ kind: 'digest-mismatch', seq, detail: 'event_digest does not match the recomputed digest' });
    }
    previous = stored;
  }

  let checkpoints = 0;
  for (const checkpoint of store.iterate('audit_checkpoints', {}, { orderBy: [['seq', 'asc']] })) {
    checkpoints += 1;
    const seq = Number(checkpoint['seq']);
    const digest = digests.get(seq);
    if (digest === undefined) {
      problems.push({
        kind: head === null || seq > head.seq ? 'truncated' : 'seq-gap',
        seq,
        detail: `${String(checkpoint['kind'])} checkpoint refers to an event that is missing`,
      });
    } else if (digest !== checkpoint['event_digest']) {
      problems.push({ kind: 'checkpoint-mismatch', seq, detail: `${String(checkpoint['kind'])} checkpoint digest differs from the chain` });
    }
  }

  const expected = options.expectedHead;
  if (expected !== undefined) {
    const digest = digests.get(expected.seq);
    if (head === null || expected.seq > head.seq) {
      problems.push({ kind: 'truncated', seq: expected.seq, detail: 'the chain ends before the recorded head' });
    } else if (digest !== expected.digest) {
      problems.push({ kind: 'head-mismatch', seq: expected.seq, detail: 'the event at the recorded head has a different digest' });
    }
  }

  return { ok: problems.length === 0, events, checkpoints, head, problems };
}

/** The tenant's events of one envelope as contract AuditEventRecords, in seq order (for receipts). */
export function envelopeAuditRecords(db: Database, tenantId: string, envelopeId: string): AuditEventRecord[] {
  const records: AuditEventRecord[] = [];
  for (const row of db.forTenant(tenantId).iterate('audit_events', { envelope_id: envelopeId }, { orderBy: [['seq', 'asc']] })) {
    records.push(recordFromRow(row));
  }
  return records;
}
