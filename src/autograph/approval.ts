// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// The approval the shell submits (approveAsHuman; contract Approval, 0.2.3). Every binding
// comes from the session state the server returned: expected_version, manifest_digest,
// prior_approval_digest and the consent version and digest. document_digest is the SHA-256
// of the PDF bytes this browser received, checked equal to the session's document digest.
// Exactly one value per field of this recipient: a drawn or typed signature for each
// signature field, and {key, type: date} with no value for each date field (the server sets
// the date at approval). The checks below mirror the contract before anything is sent:
// typed text 1..80 code points, WinAnsi only; drawn values 1..50 strokes of 2..1000 integer
// points in 0..10000, at most 10,000 points per value and 15,000 per approval; the compact
// JSON body under the 256 KiB server limit (which the point budget guarantees).

import { COORDINATE_MAX, MAX_POINTS_PER_APPROVAL, MAX_POINTS_PER_STROKE, MAX_POINTS_PER_VALUE, MAX_STROKES_PER_VALUE, MIN_POINTS_PER_STROKE, countPoints } from './strokes.js';
import type { ApprovalBody, FieldValue, SessionState, Stroke } from './types.js';
import { codePointLength, unsupportedCharacters } from './winansi.js';

export const JSON_BODY_LIMIT = 256 * 1024;
export const MAX_TYPED_LENGTH = 80;

export type SignatureInput = { readonly mode: 'typed'; readonly text: string } | { readonly mode: 'drawn'; readonly strokes: readonly Stroke[] };

export interface Problem {
  /** The field the problem belongs to, or null for the approval as a whole. */
  readonly key: string | null;
  readonly message: string;
}

/** The typed text as submitted: surrounding spaces removed. */
export function typedText(text: string): string {
  return text.trim();
}

function strokesValid(strokes: readonly Stroke[]): boolean {
  if (strokes.length < 1 || strokes.length > MAX_STROKES_PER_VALUE || countPoints(strokes) > MAX_POINTS_PER_VALUE) return false;
  return strokes.every(
    (stroke) =>
      stroke.length >= MIN_POINTS_PER_STROKE &&
      stroke.length <= MAX_POINTS_PER_STROKE &&
      stroke.every((point) => point.length === 2 && point.every((value) => Number.isInteger(value) && value >= 0 && value <= COORDINATE_MAX)),
  );
}

export function signatureProblems(key: string, input: SignatureInput | undefined): Problem[] {
  if (input === undefined) return [{ key, message: 'Sign this field: type your name or draw your signature.' }];
  if (input.mode === 'typed') {
    const text = typedText(input.text);
    if (text === '') return [{ key, message: 'Type your name in this field.' }];
    if (codePointLength(text) > MAX_TYPED_LENGTH) return [{ key, message: `A typed signature has at most ${MAX_TYPED_LENGTH} characters.` }];
    const unsupported = unsupportedCharacters(text);
    if (unsupported.length > 0) return [{ key, message: `These characters cannot be shown in the document's font: ${unsupported.join(' ')}. Use letters, digits and common punctuation.` }];
    return [];
  }
  if (input.strokes.length === 0) return [{ key, message: 'Draw your signature in this field, or choose Type my name.' }];
  if (!strokesValid(input.strokes)) return [{ key, message: 'This drawing exceeds the limits of a signature. Clear it and draw again.' }];
  return [];
}

/** The approval body; every signature field must have an input (see approvalProblems). */
export function approvalBody(state: SessionState, documentDigest: string, inputs: ReadonlyMap<string, SignatureInput>): ApprovalBody {
  const fieldValues: FieldValue[] = state.fields.map((field): FieldValue => {
    if (field.type === 'date') return { key: field.key, type: 'date' };
    const input = inputs.get(field.key);
    if (input === undefined) throw new Error(`no input for field ${field.key}`);
    if (input.mode === 'typed') return { key: field.key, type: 'signature', mode: 'typed', text: typedText(input.text) };
    return { key: field.key, type: 'signature', mode: 'drawn', strokes: input.strokes.map((stroke) => stroke.map((point): readonly [number, number] => [point[0], point[1]])) };
  });
  return {
    expected_version: state.envelope_version,
    document_digest: documentDigest,
    manifest_digest: state.manifest_digest,
    prior_approval_digest: state.prior_approval_digest,
    consent_version: state.consent.version,
    consent_text_digest: state.consent.text_digest,
    consent: true,
    field_values: fieldValues,
  };
}

/** Compact JSON size of the body, in bytes, as the browser sends it. */
export function bodyBytes(body: ApprovalBody): number {
  return new TextEncoder().encode(JSON.stringify(body)).length;
}

/** Everything that stops an approval from being sent; empty when it may be sent. */
export function approvalProblems(state: SessionState, documentDigest: string | null, consented: boolean, inputs: ReadonlyMap<string, SignatureInput>): Problem[] {
  const problems: Problem[] = [];
  if (documentDigest === null) problems.push({ key: null, message: 'The document has not been verified. Do not approve it until it is.' });
  for (const field of state.fields) if (field.type === 'signature') problems.push(...signatureProblems(field.key, inputs.get(field.key)));
  if (!consented) problems.push({ key: null, message: 'Confirm that you have read and agree to the consent text.' });
  let drawn = 0;
  for (const input of inputs.values()) if (input.mode === 'drawn') drawn += countPoints(input.strokes);
  if (drawn > MAX_POINTS_PER_APPROVAL) problems.push({ key: null, message: 'The drawings together exceed the limit of a signature. Clear one and draw again.' });
  if (problems.length === 0 && documentDigest !== null && bodyBytes(approvalBody(state, documentDigest, inputs)) > JSON_BODY_LIMIT) {
    problems.push({ key: null, message: 'The approval is too large to send. Clear a drawing and draw again.' });
  }
  return problems;
}
