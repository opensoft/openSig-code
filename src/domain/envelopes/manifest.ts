// SPDX-License-Identifier: Apache-2.0
//
// Freeze at prepare (data-model.md § Entities, FieldManifest; contract
// FieldManifest and RecipientPreview). The field manifest and the recipients
// digest are computed through the project's single RFC 8785 module,
// src/domain/canonical/index.ts (T029); this module only arranges the values.
//
// - FieldManifest = {schema, envelope_id, document_digest, fields}, fields in
//   key order; manifest_digest = SHA-256 of its canonical bytes, which are
//   stored as frozen and served to recipients unchanged.
// - recipients_digest = SHA-256 of the canonical JSON of
//   [{ordinal, role, email}] in ordinal order.

import { createHash } from 'node:crypto';

import { canonicalBytes, canonicalDigest, type JsonValue } from '../../domain/canonical/index.ts';
import type { Rect } from './validation.ts';

export const FIELD_MANIFEST_SCHEMA = 'opensig.field-manifest/1';

export interface ManifestField {
  readonly key: string;
  readonly recipient_id: string;
  readonly recipient_ordinal: number;
  readonly page: number;
  readonly type: 'signature' | 'date';
  readonly rect: Rect;
}

export interface FieldManifest {
  readonly schema: typeof FIELD_MANIFEST_SCHEMA;
  readonly envelope_id: string;
  readonly document_digest: string;
  readonly fields: readonly ManifestField[];
}

export interface FrozenManifest {
  readonly manifest: FieldManifest;
  readonly bytes: Buffer;
  readonly digest: string;
}

function byKey(a: ManifestField, b: ManifestField): number {
  return a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
}

export function buildFieldManifest(envelopeId: string, documentDigest: string, fields: readonly ManifestField[]): FrozenManifest {
  const manifest: FieldManifest = {
    schema: FIELD_MANIFEST_SCHEMA,
    envelope_id: envelopeId,
    document_digest: documentDigest,
    fields: [...fields].sort(byKey).map((field) => ({
      key: field.key,
      recipient_id: field.recipient_id,
      recipient_ordinal: field.recipient_ordinal,
      page: field.page,
      type: field.type,
      rect: { x: field.rect.x, y: field.rect.y, width: field.rect.width, height: field.rect.height },
    })),
  };
  const bytes = canonicalBytes(manifest);
  return { manifest, bytes, digest: createHash('sha256').update(bytes).digest('hex') };
}

export interface DigestRecipient {
  readonly ordinal: number;
  readonly role: string;
  readonly email: string;
}

/** The recipients preview a human confirms: [{ordinal, role, email}] in ordinal order. */
export function recipientsPreview(recipients: readonly DigestRecipient[]): JsonValue[] {
  return [...recipients]
    .sort((a, b) => a.ordinal - b.ordinal)
    .map((recipient) => ({ ordinal: recipient.ordinal, role: recipient.role, email: recipient.email }));
}

export function recipientsDigest(recipients: readonly DigestRecipient[]): string {
  return canonicalDigest(recipientsPreview(recipients));
}
