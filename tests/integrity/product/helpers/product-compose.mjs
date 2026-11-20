// SPDX-License-Identifier: Apache-2.0
//
// Product composition only (T036's composeSealRevision, landed at b47c4ef,
// which parses the base through T033's parse service). It imports nothing from
// T037, so the composed VB-06 cases (request #49) depend on T033 and T036 alone.
//
// CONFIRMED (P1, request #56 B7) from the type extract of T036's exported
// ComposeRequest, ComposedRevision, FieldManifestInput, FieldInput,
// ApprovalInput and FieldValueInput (compose.ts at code b47c4ef, as recorded by
// the orchestrator; compose.ts itself is not read):
// - the request has exactly five members: `document` (the base bytes),
//   `fieldManifest`, `approvals` (in ordinal order), `sealTime` (UTC ISO 8601,
//   YYYY-MM-DDTHH:mm:ss[.sss]Z, written to /M) and `certificateDer` (sizes the
//   /Contents placeholder);
// - the manifest is a contract FieldManifest (schema opensig.field-manifest/1,
//   envelope_id, document_digest as lowercase hex SHA-256 of the base, fields);
//   each field has key, recipient_id, recipient_ordinal, page, type and a rect
//   normalized to the page (origin top-left, each value in [0, 1]);
// - an approval carries recipient.id, field_values (here one typed signature
//   value) and date_values;
// - the result is a ComposedRevision with `bytes`, `digest`, `documentDigest`,
//   `documentLength`, `byteRange` [0, o1, o2, l2], `contents` { offset,
//   hexLength }, `signedDataLength`, `xrefKind` and `objects`.
// Every value below is synthetic. Composing needs T033's parse sandbox
// (bubblewrap or unshare), which the `verification` mode does not declare:
// without it the callers FAIL, never CAPABILITY_ABSENT and never skipped
// (request #56 B5). This helper catches nothing.

import { createHash } from 'node:crypto';
import { composeSealRevision } from '../../../../src/cryptograph/compose/index.ts';

/** A fixed seal time: composition is deterministic and reads no clock. */
export const SEAL_TIME = '2026-11-18T09:30:00Z';

const ENVELOPE_ID = 'env_synthetic_0000000001';
const RECIPIENT_ID = 'rcpt_synthetic_000000001';
const FIELD_KEY = 'seal_sig_1';

/** P1: a one-field manifest for recipient 1 on page 1, and that recipient's typed approval. */
export function composeRequestFor({ document, certificateDer, sealTime }) {
  return {
    document,
    fieldManifest: {
      schema: 'opensig.field-manifest/1',
      envelope_id: ENVELOPE_ID,
      document_digest: createHash('sha256').update(document).digest('hex'),
      fields: [
        {
          key: FIELD_KEY,
          recipient_id: RECIPIENT_ID,
          recipient_ordinal: 1,
          page: 1,
          type: 'signature',
          rect: { x: 0.1, y: 0.8, width: 0.4, height: 0.08 },
        },
      ],
    },
    approvals: [
      {
        recipient: { id: RECIPIENT_ID },
        field_values: [{ key: FIELD_KEY, type: 'signature', mode: 'typed', text: 'Synthetic Signer' }],
        date_values: [],
      },
    ],
    sealTime,
    certificateDer,
  };
}

/** Compose the seal revision of `document` through T033's parser and T036's composer (no key, no worker). */
export async function composeWithProduct({ document, certificateDer, sealTime = SEAL_TIME }) {
  return composeSealRevision(
    composeRequestFor({ document: new Uint8Array(document), certificateDer: new Uint8Array(certificateDer), sealTime }),
  );
}
