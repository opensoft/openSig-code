// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006): two deliberately non-conforming subjects.
//
//   accept-everything  answers every request with the operation's declared 2xx
//                      status and a contract-shaped body; it never rejects.
//   reject-everything  answers every request with 400 invalid_request.
//
// Each must fail at least one case in every fixture (tests/contract/envelopes/
// stubs.test.mjs). They prove the manifest discriminates; they are not, and
// never stand in for, an implementation.

import { createHash } from 'node:crypto';

import { operationIndex, successStatus } from './contract.mjs';
import { matchOperation } from './harness.mjs';

export const STUB_ENVELOPE_ID = 'stubEnvelope0000000001';
const STUB_TIME = '2026-11-16T00:00:00Z';
const STUB_DIGEST = 'a'.repeat(64);

function json(status, value) {
  return { status, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(value), 'utf8') };
}

/** Synthetic arrange: an envelope at the version its given implies (create = 1, +1 per upload, +1 per prepare). */
function stubArrange(given) {
  return { envelope_id: STUB_ENVELOPE_ID, version: 1 + (given.document ? 1 : 0) + (given.prepare ? 1 : 0) };
}

function parseJson(request) {
  try {
    return JSON.parse(Buffer.from(request.body ?? []).toString('utf8'));
  } catch {
    return null;
  }
}

function priorVersion(request, body) {
  if (Number.isInteger(body?.expected_version)) return body.expected_version;
  const m = /^"(\d+)"$/.exec(String(request.headers?.['if-match'] ?? ''));
  return m ? Number(m[1]) : 0;
}

const STATE_AFTER = Object.freeze({
  createEnvelope: 'draft',
  readEnvelope: 'draft',
  uploadDocument: 'draft',
  prepareEnvelope: 'prepared',
  sendEnvelope: 'sent',
  voidEnvelope: 'voided',
});

function recipientViews(body) {
  const declared = Array.isArray(body?.recipients) ? body.recipients.slice(0, 2) : [];
  const list = declared.length > 0 ? declared : [{ email: 'signer.one@example.test', role: 'approver', ordinal: 1 }];
  return list.map((r, i) => ({
    id: `stubRecipient000000000${i + 1}`,
    ordinal: i + 1,
    role: typeof r?.role === 'string' && r.role.length > 0 ? r.role.slice(0, 80) : 'approver',
    email: typeof r?.email === 'string' ? r.email : 'signer.one@example.test',
    status: 'pending',
    invited_at: null,
    approved_at: null,
    approval_digest: null,
  }));
}

function stubEnvelope(operationId, request, pathValues) {
  const body = parseJson(request);
  const id = /^[A-Za-z0-9_-]{16,64}$/.test(pathValues.envelope_id ?? '') ? pathValues.envelope_id : STUB_ENVELOPE_ID;
  const service = request.principal === 'service';
  let document = null;
  if (operationId === 'uploadDocument') {
    const bytes = Buffer.from(request.body ?? []);
    document = {
      digest: createHash('sha256').update(bytes).digest('hex'),
      bytes: Math.min(Math.max(bytes.length, 1), 10485760),
      pages: [{ number: 1, width: 612, height: 792, rotate: 0 }],
    };
  } else if (['prepareEnvelope', 'sendEnvelope', 'voidEnvelope'].includes(operationId)) {
    document = { digest: STUB_DIGEST, bytes: 1024, pages: [{ number: 1, width: 612, height: 792, rotate: 0 }] };
  }
  const prepared = ['prepareEnvelope', 'sendEnvelope', 'voidEnvelope'].includes(operationId);
  const recipients = recipientViews(operationId === 'createEnvelope' ? body : null);
  const fields =
    operationId === 'prepareEnvelope' && Array.isArray(body?.fields)
      ? body.fields.slice(0, 20).map((f) => ({
          key: typeof f?.key === 'string' && /^[a-z0-9_-]{1,40}$/.test(f.key) ? f.key : 'sig_1',
          recipient_id: recipients[0].id,
          recipient_ordinal: 1,
          page: 1,
          type: f?.type === 'date' ? 'date' : 'signature',
          rect: { x: 0.1, y: 0.1, width: 0.2, height: 0.05 },
        }))
      : [];
  return {
    id,
    version: priorVersion(request, body) + 1,
    state: STATE_AFTER[operationId] ?? 'draft',
    created_by: { kind: service ? 'service' : 'human-operator', ref: service ? 'stub-service' : 'stub-operator' },
    source: { app: 'manual', record: 'stub-record', version: '1' },
    expires_at: STUB_TIME,
    reissue_of: null,
    reissued_as: null,
    document,
    manifest_digest: prepared ? STUB_DIGEST : null,
    fields,
    recipients,
    approvals_complete: false,
    send_confirmation: { required: service, authorization_reference: null },
    finalization: null,
    artifact: null,
    anchor_status: 'disabled',
    created_at: STUB_TIME,
    updated_at: STUB_TIME,
  };
}

/** Build the accept-everything subject for a contract document. */
export function acceptEverything(doc) {
  const index = operationIndex(doc);
  return {
    name: 'accept-everything',
    async arrange(given) {
      return stubArrange(given);
    },
    async handle(request) {
      const match = matchOperation(index, request.method, request.path);
      if (!match) return json(200, {});
      const status = successStatus(match.entry);
      const operationId = match.entry.operationId;
      if (Object.hasOwn(STATE_AFTER, operationId)) return json(status, stubEnvelope(operationId, request, match.pathValues));
      return json(status, { status: 'accepted' });
    },
  };
}

/** Build the reject-everything subject. */
export function rejectEverything() {
  return {
    name: 'reject-everything',
    async arrange(given) {
      return stubArrange(given);
    },
    async handle() {
      return json(400, { code: 'invalid_request', correlation_id: 'rejectstub0000' });
    },
  };
}
