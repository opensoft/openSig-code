// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// The recipient-facing shapes of contract 0.2.3 (contracts/http-api.json, components.schemas)
// that the review shell (T009) reads and sends. Only the members the shell uses are typed.

export type EnvelopeState = 'sent' | 'in-progress' | 'finalizing' | 'completed' | 'declined' | 'expired' | 'voided';
export type Turn = 'yours' | 'waiting-for-prior' | 'done' | 'closed';

/** Displayed page size in PDF points, with /Rotate already applied (PageGeometry). */
export interface PageGeometry {
  readonly number: number;
  readonly width: number;
  readonly height: number;
  readonly rotate: 0 | 90 | 180 | 270;
}

/** Normalized to the displayed page: origin top-left, each value in [0, 1] (Rect). */
export interface Rect {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export interface Field {
  readonly key: string;
  readonly recipient_id: string;
  readonly recipient_ordinal: number;
  readonly page: number;
  readonly type: 'signature' | 'date';
  readonly rect: Rect;
}

export interface ConsentText {
  readonly version: string;
  readonly text_digest: string;
  readonly text: string;
}

/** readRecipientSession and createRecipientSession (RecipientSessionState). */
export interface SessionState {
  readonly envelope_id: string;
  readonly envelope_version: number;
  readonly envelope_state: EnvelopeState;
  readonly recipient: {
    readonly id: string;
    readonly ordinal: number;
    readonly role: string;
    readonly email_masked: string;
    readonly status: 'pending' | 'invited' | 'approved' | 'declined' | 'expired' | 'revoked';
  };
  readonly turn: Turn;
  readonly document: { readonly digest: string; readonly bytes: number; readonly pages: readonly PageGeometry[] };
  readonly manifest_digest: string;
  readonly fields: readonly Field[];
  readonly prior_approval_digest: string | null;
  readonly consent: ConsentText;
  readonly assurance: { readonly method: 'mailbox-challenge'; readonly level: 'mailbox-control'; readonly statement: string };
  readonly seal_notice: string;
  readonly csrf_token: string;
  readonly session_expires_at: string;
}

/** A field-local fixed-point point: [x, y], integers 0..10000. */
export type Point = readonly [number, number];
export type Stroke = readonly Point[];

export interface DrawnSignatureValue {
  readonly key: string;
  readonly type: 'signature';
  readonly mode: 'drawn';
  readonly strokes: readonly Stroke[];
}

export interface TypedSignatureValue {
  readonly key: string;
  readonly type: 'signature';
  readonly mode: 'typed';
  readonly text: string;
}

/** No client value: the server fills the date at approval. */
export interface DateFieldValue {
  readonly key: string;
  readonly type: 'date';
}

export type FieldValue = DrawnSignatureValue | TypedSignatureValue | DateFieldValue;

/** approveAsHuman's request body (Approval). */
export interface ApprovalBody {
  readonly expected_version: number;
  readonly document_digest: string;
  readonly manifest_digest: string;
  readonly prior_approval_digest: string | null;
  readonly consent_version: string;
  readonly consent_text_digest: string;
  readonly consent: true;
  readonly field_values: readonly FieldValue[];
}

/** approveAsHuman's 200 response (ApprovalReceipt). */
export interface ApprovalReceipt {
  readonly approval_id: string;
  readonly approval_digest: string;
  readonly recipient_id: string;
  readonly envelope_version: number;
  readonly envelope_state: 'in-progress' | 'finalizing';
  readonly date_values: readonly { readonly key: string; readonly value: string }[];
  readonly server_time: string;
}

export type DeclineReason = 'not-my-document' | 'disagree' | 'other';

/** declineAsRecipient's request body (Decline). */
export interface DeclineBody {
  readonly expected_version: number;
  readonly reason_code?: DeclineReason;
}
