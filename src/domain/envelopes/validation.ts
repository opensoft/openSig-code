// SPDX-License-Identifier: Apache-2.0
//
// Input rules of the envelope domain. The operator handlers (T034) validate the
// request schema first; these checks are the domain's own rules (recipient
// ordinals, expiry bounds, field placement, the parse-service document
// summary) and a defensive repeat of the shapes they depend on. Each failure is
// an EnvelopeError with the contract's code: rule and shape violations are
// invalid_request (400), a field outside its page, or one the composer could not
// place on it (detail field_too_small, placement.ts), is field_out_of_bounds (422).

import type { JsonValue } from '../../domain/canonical/index.ts';
import { EnvelopeError, invalid } from './errors.ts';
import { placeable, type StoredPage } from './placement.ts';

export const ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
export const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
export const FIELD_KEY_PATTERN = /^[a-z0-9_-]{1,40}$/;
export const SOURCE_APPS = Object.freeze(['hermes', 'openchart', 'openpractice', 'manual'] as const);
export const VOID_REASONS = Object.freeze(['sender-cancelled', 'superseded', 'error-in-document', 'other'] as const);
export const ROTATIONS = Object.freeze([0, 90, 180, 270] as const);
export const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;
export const MAX_PAGES = 50;
export const MAX_FIELDS = 20;
export const DEFAULT_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;

const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const EMAIL = /^[^\s@]+@[^\s@]+$/;

export type PrincipalKind = 'human-operator' | 'service';

/** The verified operator principal of a request: kind and opaque tenant-scoped reference. */
export interface Actor {
  readonly kind: PrincipalKind;
  readonly ref: string;
}

export interface Source {
  readonly app: (typeof SOURCE_APPS)[number];
  readonly record: string;
  readonly version: string;
}

export interface RecipientInput {
  readonly email: string;
  readonly role: string;
  readonly ordinal: number;
}

export interface EnvelopeCreateInput {
  readonly source: Source;
  readonly recipients: readonly RecipientInput[];
  readonly expires_at?: string;
}

export interface PageGeometry {
  readonly number: number;
  readonly width: number;
  readonly height: number;
  readonly rotate: (typeof ROTATIONS)[number];
}

/** What the isolated parse service (T033) reports for an accepted upload. */
export interface DocumentInput {
  readonly digest: string;
  readonly bytes: number;
  readonly pages: readonly PageGeometry[];
  readonly parseReport: { readonly [key: string]: JsonValue };
}

export interface Rect {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export interface FieldInput {
  readonly key: string;
  readonly recipient_ordinal: number;
  readonly page: number;
  readonly type: 'signature' | 'date';
  readonly rect: Rect;
}

export interface PrepareInput {
  readonly expected_version: number;
  readonly fields: readonly FieldInput[];
}

export interface SendConfirmationInput {
  readonly expected_version: number;
  readonly document_digest: string;
  readonly manifest_digest: string;
  readonly recipients_digest: string;
}

export interface SendInput {
  readonly expected_version: number;
  readonly authorization_reference?: string;
}

export interface VoidInput {
  readonly expected_version: number;
  readonly reason_code: (typeof VOID_REASONS)[number];
}

export interface VersionInput {
  readonly expected_version: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[], at: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw invalid(at === '' ? key : `${at}.${key}`, 'unknown_property');
  }
}

function text(value: unknown, at: string, min: number, max: number): string {
  if (typeof value !== 'string' || value.length < min || value.length > max) throw invalid(at, 'invalid_string');
  return value;
}

function integer(value: unknown, at: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) throw invalid(at, 'invalid_integer');
  return value;
}

export function checkId(value: unknown, at = 'envelope_id'): string {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) throw invalid(at, 'invalid_id');
  return value;
}

export function checkDigest(value: unknown, at: string): string {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) throw invalid(at, 'invalid_digest');
  return value;
}

export function checkActor(actor: unknown): Actor {
  if (!isRecord(actor) || (actor['kind'] !== 'human-operator' && actor['kind'] !== 'service')) {
    throw new EnvelopeError('forbidden', 'the principal is not an operator principal');
  }
  const ref = actor['ref'];
  if (typeof ref !== 'string' || ref.length < 1 || ref.length > 100) {
    throw new EnvelopeError('forbidden', 'the principal reference is malformed');
  }
  return { kind: actor['kind'], ref };
}

export function checkExpectedVersion(value: unknown): number {
  return integer(value, 'expected_version', 1, Number.MAX_SAFE_INTEGER);
}

function checkSource(value: unknown): Source {
  if (!isRecord(value)) throw invalid('source', 'required');
  onlyKeys(value, ['app', 'record', 'version'], 'source');
  const app = value['app'];
  if (typeof app !== 'string' || !(SOURCE_APPS as readonly string[]).includes(app)) throw invalid('source.app', 'invalid_enum');
  return {
    app: app as Source['app'],
    record: text(value['record'], 'source.record', 1, 200),
    version: text(value['version'], 'source.version', 1, 100),
  };
}

function checkRecipient(value: unknown, at: string): RecipientInput {
  if (!isRecord(value)) throw invalid(at, 'required');
  onlyKeys(value, ['email', 'role', 'ordinal'], at);
  const email = text(value['email'], `${at}.email`, 3, 254);
  if (!EMAIL.test(email)) throw invalid(`${at}.email`, 'invalid_email');
  return { email, role: text(value['role'], `${at}.role`, 1, 80), ordinal: integer(value['ordinal'], `${at}.ordinal`, 1, 2) };
}

/** Parse an RFC 3339 date-time into its toISOString() form, or undefined when malformed. */
export function parseDateTime(value: unknown): string | undefined {
  if (typeof value !== 'string' || !DATE_TIME.test(value)) return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
}

export interface CheckedCreate {
  readonly source: Source;
  readonly recipients: readonly RecipientInput[];
  readonly expiresAt: string;
}

/**
 * Create input: one recipient with ordinal 1, or two with ordinals 1 and 2
 * (duplicates and gaps are invalid_request, T006 reading (a)). expires_at
 * defaults to now + 7 days and may not pass now + 30 days.
 */
export function checkCreate(input: unknown, now: Date): CheckedCreate {
  if (!isRecord(input)) throw invalid('', 'required');
  onlyKeys(input, ['source', 'recipients', 'expires_at'], '');
  const source = checkSource(input['source']);
  const list = input['recipients'];
  if (!Array.isArray(list) || list.length < 1 || list.length > 2) throw invalid('recipients', 'invalid_count');
  const recipients = list.map((entry, index) => checkRecipient(entry, `recipients[${index}]`));
  const ordinals = recipients.map((recipient) => recipient.ordinal).sort((a, b) => a - b);
  if (!ordinals.every((ordinal, index) => ordinal === index + 1)) throw invalid('recipients', 'ordinal_rule');
  let expiresAt = new Date(now.getTime() + DEFAULT_EXPIRY_MS).toISOString();
  if (input['expires_at'] !== undefined) {
    const parsed = parseDateTime(input['expires_at']);
    if (parsed === undefined) throw invalid('expires_at', 'invalid_date_time');
    const ms = Date.parse(parsed);
    if (ms <= now.getTime() || ms > now.getTime() + MAX_EXPIRY_MS) throw invalid('expires_at', 'out_of_range');
    expiresAt = parsed;
  }
  return { source, recipients: [...recipients].sort((a, b) => a.ordinal - b.ordinal), expiresAt };
}

/** The parse service's document summary: digest, byte count, 1..50 pages with displayed geometry. */
export function checkDocument(input: unknown): DocumentInput {
  if (!isRecord(input)) throw invalid('document', 'required');
  onlyKeys(input, ['digest', 'bytes', 'pages', 'parseReport'], 'document');
  const digest = checkDigest(input['digest'], 'document.digest');
  const bytes = integer(input['bytes'], 'document.bytes', 1, MAX_DOCUMENT_BYTES);
  const pages = input['pages'];
  if (!Array.isArray(pages) || pages.length < 1 || pages.length > MAX_PAGES) throw invalid('document.pages', 'invalid_count');
  const geometry = pages.map((page, index): PageGeometry => {
    const at = `document.pages[${index}]`;
    if (!isRecord(page)) throw invalid(at, 'required');
    onlyKeys(page, ['number', 'width', 'height', 'rotate'], at);
    if (page['number'] !== index + 1) throw invalid(`${at}.number`, 'page_order');
    for (const side of ['width', 'height'] as const) {
      const size = page[side];
      if (typeof size !== 'number' || !Number.isFinite(size) || size <= 0) throw invalid(`${at}.${side}`, 'invalid_size');
    }
    const rotate = page['rotate'];
    if (!(ROTATIONS as readonly unknown[]).includes(rotate)) throw invalid(`${at}.rotate`, 'invalid_enum');
    return { number: index + 1, width: page['width'] as number, height: page['height'] as number, rotate: rotate as PageGeometry['rotate'] };
  });
  const report = input['parseReport'];
  if (!isRecord(report)) throw invalid('document.parseReport', 'required');
  return { digest, bytes, pages: geometry, parseReport: report as DocumentInput['parseReport'] };
}

export interface FieldContext {
  readonly recipientsCount: number;
  /** The revision's stored page geometry, one entry per page (placement.ts storedPages). */
  readonly pages: readonly StoredPage[];
}

/**
 * Prepare's fields: 1..20, unique keys, each on a page of the document and
 * inside it (x + width <= 1, y + height <= 1; otherwise field_out_of_bounds),
 * placeable by the composer's own rule over the stored page geometry
 * (otherwise field_out_of_bounds, detail field_too_small; requests #46 and
 * #49), each for a declared recipient, and at least one signature field per
 * recipient.
 *
 * First refusal wins, one detail. Fields are judged in request order. Within a
 * field: its shape and rules (400 invalid_request, ending with empty_rect for
 * a width or height of 0), then page_out_of_range (422), then outside_page
 * (422), then field_too_small (422). The per-recipient signature rule (400)
 * comes after every field. A field is placed only once it is known to be on a
 * page and inside it, as the composer places only such fields.
 */
export function checkFields(value: unknown, context: FieldContext): FieldInput[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_FIELDS) throw invalid('fields', 'invalid_count');
  const keys = new Set<string>();
  const fields = value.map((entry, index): FieldInput => {
    const at = `fields[${index}]`;
    if (!isRecord(entry)) throw invalid(at, 'required');
    onlyKeys(entry, ['key', 'recipient_ordinal', 'page', 'type', 'rect'], at);
    const key = entry['key'];
    if (typeof key !== 'string' || !FIELD_KEY_PATTERN.test(key)) throw invalid(`${at}.key`, 'invalid_key');
    if (keys.has(key)) throw invalid(`${at}.key`, 'duplicate_key');
    keys.add(key);
    const ordinal = integer(entry['recipient_ordinal'], `${at}.recipient_ordinal`, 1, 2);
    if (ordinal > context.recipientsCount) throw invalid(`${at}.recipient_ordinal`, 'unknown_recipient');
    const page = integer(entry['page'], `${at}.page`, 1, MAX_PAGES);
    const type = entry['type'];
    if (type !== 'signature' && type !== 'date') throw invalid(`${at}.type`, 'invalid_enum');
    const rect = entry['rect'];
    if (!isRecord(rect)) throw invalid(`${at}.rect`, 'required');
    onlyKeys(rect, ['x', 'y', 'width', 'height'], `${at}.rect`);
    const [x, y, width, height] = (['x', 'y', 'width', 'height'] as const).map((name) => {
      const n = rect[name];
      if (typeof n !== 'number' || !Number.isFinite(n) || n < 0 || n > 1) throw invalid(`${at}.rect.${name}`, 'invalid_number');
      return n;
    }) as [number, number, number, number];
    if (width <= 0 || height <= 0) throw invalid(`${at}.rect`, 'empty_rect');
    const stored = context.pages[page - 1];
    if (stored === undefined) {
      throw new EnvelopeError('field_out_of_bounds', 'a field is outside the document', [{ field: `${at}.page`, code: 'page_out_of_range' }]);
    }
    if (x + width > 1 || y + height > 1) {
      throw new EnvelopeError('field_out_of_bounds', 'a field is outside its page', [{ field: `${at}.rect`, code: 'outside_page' }]);
    }
    if (!placeable(stored, { x, y, width, height })) {
      throw new EnvelopeError('field_out_of_bounds', 'a field is too small to place on its page', [{ field: `${at}.rect`, code: 'field_too_small' }]);
    }
    return { key, recipient_ordinal: ordinal, page, type, rect: { x, y, width, height } };
  });
  for (let ordinal = 1; ordinal <= context.recipientsCount; ordinal += 1) {
    if (!fields.some((field) => field.recipient_ordinal === ordinal && field.type === 'signature')) {
      throw invalid('fields', 'signature_field_required');
    }
  }
  return fields;
}

export function checkPrepare(input: unknown): { expectedVersion: number; fields: unknown } {
  if (!isRecord(input)) throw invalid('', 'required');
  onlyKeys(input, ['expected_version', 'fields'], '');
  return { expectedVersion: checkExpectedVersion(input['expected_version']), fields: input['fields'] };
}

export function checkSendConfirmation(input: unknown): {
  expectedVersion: number;
  documentDigest: string;
  manifestDigest: string;
  recipientsDigest: string;
} {
  if (!isRecord(input)) throw invalid('', 'required');
  onlyKeys(input, ['expected_version', 'document_digest', 'manifest_digest', 'recipients_digest'], '');
  return {
    expectedVersion: checkExpectedVersion(input['expected_version']),
    documentDigest: checkDigest(input['document_digest'], 'document_digest'),
    manifestDigest: checkDigest(input['manifest_digest'], 'manifest_digest'),
    recipientsDigest: checkDigest(input['recipients_digest'], 'recipients_digest'),
  };
}

export function checkSend(input: unknown): { expectedVersion: number; authorizationReference: string | undefined } {
  if (!isRecord(input)) throw invalid('', 'required');
  onlyKeys(input, ['expected_version', 'authorization_reference'], '');
  const reference = input['authorization_reference'];
  return {
    expectedVersion: checkExpectedVersion(input['expected_version']),
    authorizationReference: reference === undefined ? undefined : checkId(reference, 'authorization_reference'),
  };
}

export function checkVoid(input: unknown): { expectedVersion: number; reasonCode: VoidInput['reason_code'] } {
  if (!isRecord(input)) throw invalid('', 'required');
  onlyKeys(input, ['expected_version', 'reason_code'], '');
  const reason = input['reason_code'];
  if (typeof reason !== 'string' || !(VOID_REASONS as readonly string[]).includes(reason)) throw invalid('reason_code', 'invalid_enum');
  return { expectedVersion: checkExpectedVersion(input['expected_version']), reasonCode: reason as VoidInput['reason_code'] };
}

export function checkVersionOnly(input: unknown): { expectedVersion: number } {
  if (!isRecord(input)) throw invalid('', 'required');
  onlyKeys(input, ['expected_version'], '');
  return { expectedVersion: checkExpectedVersion(input['expected_version']) };
}
