// SPDX-License-Identifier: Apache-2.0
//
// The Approval and Decline request bodies (T010), checked against the vendored
// contract (contracts/http-api.json, components.schemas Approval,
// DrawnSignatureValue, TypedSignatureValue, DateFieldValue and Decline, contract
// 0.2.3) before any storage is read. The server (src/server/body.ts) has
// already enforced the media type, the 256 KiB JSON limit and valid JSON.
//
// Approval, in this order, every violation a 400 invalid_request whose details
// name the member, never its value:
// - exactly the contract's members (additionalProperties false), each present:
//   expected_version (integer >= 1), document_digest, manifest_digest and
//   consent_text_digest (lowercase hex SHA-256), prior_approval_digest (one of
//   those or null), consent_version (^[a-z0-9.-]{1,40}$) and consent, which is
//   exactly true;
// - field_values: 1..20 values with distinct keys (^[a-z0-9_-]{1,40}$), each
//   exactly one of
//   - a drawn signature {key, type: signature, mode: drawn, strokes}: 1..50
//     strokes of 2..1000 points, each point exactly two integer coordinates in
//     0..10000 (field-local fixed point: 1/10000 of the field's width and
//     height, origin top-left), at most 10,000 points in the value. A number
//     with a fraction, a negative or larger number, a numeric string, a boolean
//     or null is refused;
//   - a typed signature {key, type: signature, mode: typed, text}: 1..80
//     characters (code points, as JSON Schema counts them);
//   - a date {key, type: date}: no client value; the server fills it;
// - the approval point budget: all drawn strokes together hold at most 15,000
//   points (contract 0.2.3, A-010 S5). Any approval within the schema then fits
//   the 256 KiB JSON limit as compact JSON; one point more is refused.
// Then 422 unsupported_characters: a typed text with a character that
// WinAnsiEncoding cannot represent (winansi.ts). It is decided after every 400
// rule, so a request is refused for its shape before its characters.
//
// The checked values are returned as fresh plain data, sorted by key, which is
// the order in which they are digested and stored. Matching them against the
// recipient's frozen fields (exactly one value per field, of the field's type)
// needs the manifest and is done by the service (service.ts).

import { ApprovalError, invalid } from './errors.ts';
import { isWinAnsiText } from './winansi.ts';

export const MAX_FIELD_VALUES = 20;
export const MAX_STROKES_PER_VALUE = 50;
export const MIN_POINTS_PER_STROKE = 2;
export const MAX_POINTS_PER_STROKE = 1000;
export const MAX_POINTS_PER_VALUE = 10_000;
/** The approval point budget (contract 0.2.3): all drawn strokes of one approval together. */
export const MAX_POINTS_PER_APPROVAL = 15_000;
export const MAX_COORDINATE = 10_000;
export const MAX_TYPED_TEXT_LENGTH = 80;

export const FIELD_KEY_PATTERN = /^[a-z0-9_-]{1,40}$/;
export const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
export const CONSENT_VERSION_PATTERN = /^[a-z0-9.-]{1,40}$/;
export const DECLINE_REASONS = Object.freeze(['not-my-document', 'disagree', 'other'] as const);

/**
 * Stands for a request body that is not JSON (or not UTF-8). The handlers pass
 * it in place of the body, so the service still decides the session and an
 * earlier receipt first (401, then 409 for any request after an approval) and
 * only then refuses the body itself (400): it is not an object.
 */
export const MALFORMED_BODY: unique symbol = Symbol('opensig.malformed-body');

export type DeclineReason = (typeof DECLINE_REASONS)[number];

/** A field-local fixed-point coordinate pair: [x, y], integers 0..10000. */
export type Point = readonly [number, number];

export interface DrawnSignatureValue {
  readonly key: string;
  readonly type: 'signature';
  readonly mode: 'drawn';
  readonly strokes: readonly (readonly Point[])[];
}

export interface TypedSignatureValue {
  readonly key: string;
  readonly type: 'signature';
  readonly mode: 'typed';
  readonly text: string;
}

export interface DateFieldValue {
  readonly key: string;
  readonly type: 'date';
}

export type FieldValue = DrawnSignatureValue | TypedSignatureValue | DateFieldValue;

export interface ApprovalRequest {
  readonly expectedVersion: number;
  readonly documentDigest: string;
  readonly manifestDigest: string;
  readonly priorApprovalDigest: string | null;
  readonly consentVersion: string;
  readonly consentTextDigest: string;
  /** Sorted by key. */
  readonly fieldValues: readonly FieldValue[];
  /** Drawn points in the whole approval (at most MAX_POINTS_PER_APPROVAL). */
  readonly points: number;
}

export interface DeclineRequest {
  readonly expectedVersion: number;
  readonly reason: DeclineReason | null;
}

const APPROVAL_MEMBERS = Object.freeze([
  'expected_version',
  'document_digest',
  'manifest_digest',
  'prior_approval_digest',
  'consent_version',
  'consent_text_digest',
  'consent',
  'field_values',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Every member is one of `allowed` and every `required` member is present. */
function members(value: Record<string, unknown>, allowed: readonly string[], required: readonly string[], at: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw invalid(at === '' ? key.slice(0, 100) : `${at}.${key}`.slice(0, 100), 'unknown_property');
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw invalid(at === '' ? key : `${at}.${key}`, 'required');
  }
}

function expectedVersion(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) throw invalid('expected_version', 'invalid_integer');
  return value;
}

function digest(value: unknown, at: string): string {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) throw invalid(at, 'invalid_digest');
  return value;
}

/** A coordinate: a JSON integer in 0..10000 (a fraction, a string or a boolean never is one). */
function coordinate(value: unknown, at: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > MAX_COORDINATE) throw invalid(at, 'invalid_coordinate');
  // -0 is the integer 0; store it as 0 so the stored and digested forms agree.
  return value === 0 ? 0 : value;
}

function drawnValue(value: Record<string, unknown>, key: string, at: string): { readonly value: DrawnSignatureValue; readonly points: number } {
  members(value, ['key', 'type', 'mode', 'strokes'], ['key', 'type', 'mode', 'strokes'], at);
  const strokes = value['strokes'];
  if (!Array.isArray(strokes) || strokes.length < 1 || strokes.length > MAX_STROKES_PER_VALUE) throw invalid(`${at}.strokes`, 'stroke_count');
  let points = 0;
  const checked = strokes.map((stroke: unknown, strokeIndex): Point[] => {
    const strokeAt = `${at}.strokes[${strokeIndex}]`;
    if (!Array.isArray(stroke) || stroke.length < MIN_POINTS_PER_STROKE || stroke.length > MAX_POINTS_PER_STROKE) throw invalid(strokeAt, 'point_count');
    points += stroke.length;
    if (points > MAX_POINTS_PER_VALUE) throw invalid(`${at}.strokes`, 'value_point_count');
    return stroke.map((point: unknown, pointIndex): Point => {
      const pointAt = `${strokeAt}[${pointIndex}]`;
      if (!Array.isArray(point) || point.length !== 2) throw invalid(pointAt, 'invalid_point');
      return [coordinate(point[0], pointAt), coordinate(point[1], pointAt)];
    });
  });
  return { value: { key, type: 'signature', mode: 'drawn', strokes: checked }, points };
}

function typedValue(value: Record<string, unknown>, key: string, at: string): TypedSignatureValue {
  members(value, ['key', 'type', 'mode', 'text'], ['key', 'type', 'mode', 'text'], at);
  const text = value['text'];
  if (typeof text !== 'string') throw invalid(`${at}.text`, 'invalid_string');
  const length = [...text].length;
  if (length < 1 || length > MAX_TYPED_TEXT_LENGTH) throw invalid(`${at}.text`, 'invalid_length');
  return { key, type: 'signature', mode: 'typed', text };
}

/**
 * Check an Approval body. Throws ApprovalError: 400 invalid_request for any
 * shape, cap or budget violation, then 422 unsupported_characters for a typed
 * text outside WinAnsiEncoding.
 */
export function checkApprovalRequest(body: unknown): ApprovalRequest {
  if (!isRecord(body)) throw invalid('', 'invalid_type');
  members(body, APPROVAL_MEMBERS, APPROVAL_MEMBERS, '');
  const version = expectedVersion(body['expected_version']);
  const documentDigest = digest(body['document_digest'], 'document_digest');
  const manifestDigest = digest(body['manifest_digest'], 'manifest_digest');
  const prior = body['prior_approval_digest'];
  const priorApprovalDigest = prior === null ? null : digest(prior, 'prior_approval_digest');
  const consentVersion = body['consent_version'];
  if (typeof consentVersion !== 'string' || !CONSENT_VERSION_PATTERN.test(consentVersion)) throw invalid('consent_version', 'invalid_version');
  const consentTextDigest = digest(body['consent_text_digest'], 'consent_text_digest');
  if (body['consent'] !== true) throw invalid('consent', 'consent_required');
  const list = body['field_values'];
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_FIELD_VALUES) throw invalid('field_values', 'invalid_count');

  const keys = new Set<string>();
  const values: FieldValue[] = [];
  let points = 0;
  let unsupported: string | null = null;
  for (let index = 0; index < list.length; index += 1) {
    const entry: unknown = list[index];
    const at = `field_values[${index}]`;
    if (!isRecord(entry)) throw invalid(at, 'invalid_type');
    const key = entry['key'];
    if (typeof key !== 'string' || !FIELD_KEY_PATTERN.test(key)) throw invalid(`${at}.key`, 'invalid_key');
    if (keys.has(key)) throw invalid(`${at}.key`, 'duplicate_key');
    keys.add(key);
    const type = entry['type'];
    const mode = entry['mode'];
    if (type === 'date') {
      members(entry, ['key', 'type'], ['key', 'type'], at);
      values.push({ key, type: 'date' });
    } else if (type !== 'signature') {
      throw invalid(`${at}.type`, 'invalid_enum');
    } else if (mode === 'drawn') {
      const drawn = drawnValue(entry, key, at);
      points += drawn.points;
      values.push(drawn.value);
    } else if (mode === 'typed') {
      const typed = typedValue(entry, key, at);
      if (unsupported === null && !isWinAnsiText(typed.text)) unsupported = `${at}.text`;
      values.push(typed);
    } else {
      throw invalid(`${at}.mode`, 'invalid_enum');
    }
  }
  // The approval point budget (contract 0.2.3): MAX_POINTS_PER_APPROVAL is allowed, one more is not.
  if (points > MAX_POINTS_PER_APPROVAL) throw invalid('field_values', 'point_budget');
  if (unsupported !== null) {
    throw new ApprovalError('unsupported_characters', 'a typed value holds characters the document font cannot show', [{ field: unsupported, code: 'unsupported_characters' }]);
  }
  values.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
  return {
    expectedVersion: version,
    documentDigest,
    manifestDigest,
    priorApprovalDigest,
    consentVersion,
    consentTextDigest,
    fieldValues: Object.freeze(values),
    points,
  };
}

/** Check a Decline body: {expected_version, reason_code?}, nothing else (400 invalid_request). */
export function checkDeclineRequest(body: unknown): DeclineRequest {
  if (!isRecord(body)) throw invalid('', 'invalid_type');
  members(body, ['expected_version', 'reason_code'], ['expected_version'], '');
  const version = expectedVersion(body['expected_version']);
  const reason = body['reason_code'];
  if (reason !== undefined && (typeof reason !== 'string' || !(DECLINE_REASONS as readonly string[]).includes(reason))) throw invalid('reason_code', 'invalid_enum');
  return { expectedVersion: version, reason: reason === undefined ? null : (reason as DeclineReason) };
}
