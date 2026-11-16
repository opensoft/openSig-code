<!-- SPDX-License-Identifier: Apache-2.0 -->

# Envelope conformance manifest (T006)

This directory holds the conformance manifest for the operator envelope API.
It covers envelope, version, upload-limit and unsupported-PDF cases. Every case
states the expected status and error code. All of it is derived from the
vendored spec-leg contract, `contracts/http-api.json`.

**Kind: harness.** A run of this manifest is never success-criterion evidence
and never runtime acceptance. Runtime acceptance of the handlers belongs to
T034's own cases.

**Acceptance is provisional** (amendment A-009). It was accepted on branch
`001-corporate-signing-mvp-us1-t006` before Phase 2 closed. Final acceptance
comes after Phase 2 closes and before T007:

1. cherry-pick this work onto the feature branch;
2. re-vendor the contract if the spec contract changed (see "Changing the manifest");
3. re-run `envelope-contract` on the integrated head, together with every Phase 1 and Phase 2 mode.

All data here is synthetic. It holds no document files: PDF cases are
structural descriptors, and the documents are built in-test by
`tests/contract/envelopes/lib/pdf.mjs`. There are no keys, no signature images,
no real signatures and no real identities; addresses are on `example.test`.

## Files

| Path | Role |
|---|---|
| `manifest.json` | Index: schema, kind, contract digest, limits, principals, fixture list with counts, total, named preconditions (`givens`) |
| `envelope.json`, `version.json`, `upload-limit.json`, `unsupported-pdf.json` | One fixture per category (schema `opensig.envelope-conformance-fixture/1`) |
| `contracts/http-api.json` | Byte-exact copy of spec-leg `specs/001-corporate-signing-mvp/contracts/http-api.yaml` (OpenAPI 3.1 written as JSON) |
| `contracts/http-api.source.json` | `{repo, commit, path, sha256}` of the vendored bytes |
| `tests/contract/envelopes/lib/` | Harness library: `contract.mjs`, `schema.mjs` (validator), `pdf.mjs` (builder and inspector), `manifest.mjs`, `harness.mjs` (runner and verdict), `stubs.mjs` |
| `tests/contract/envelopes/*.test.mjs` | Harness self-tests, run by `npm run verify -- envelope-contract` |

Nothing here imports from `src/`.

## Frozen counts

T034 consumes the manifest with a count check. These numbers are frozen in
`tests/contract/envelopes/manifest.test.mjs` (EC-04).

| Fixture | File | Cases | Accepting (2xx) | Rejecting | Case ids |
|---|---|---|---|---|---|
| envelope | `envelope.json` | 29 | 5 | 24 | `EC-ENV-01`..`EC-ENV-29` |
| version | `version.json` | 17 | 3 | 14 | `EC-VER-01`..`EC-VER-17` |
| upload-limit | `upload-limit.json` | 7 | 4 | 3 | `EC-LIM-01`..`EC-LIM-07` |
| unsupported-pdf | `unsupported-pdf.json` | 19 | 6 | 13 | `EC-PDF-01`..`EC-PDF-19` |
| **total** | | **72** | 18 | 54 | |

Every fixture has at least one accepting and one rejecting case. That is why
both stubs fail at least one case per fixture: accept-everything and
reject-everything (`tests/contract/envelopes/stubs.test.mjs`).

## Case format

```json
{
  "id": "EC-PDF-07",
  "title": "a page crop box that differs from its media box is rejected",
  "given": "draft-1",
  "request": {
    "operationId": "uploadDocument",
    "principal": "sender",
    "path": { "envelope_id": { "$ctx": "envelope_id" } },
    "headers": { "If-Match": null },
    "body": { "pdf": { "pages": 1, "cropBox": [36, 36, 576, 756] } }
  },
  "defect": { "kind": "pdf-content", "feature": "cropbox-differs" },
  "expect": { "status": 422, "code": "unsupported_pdf", "detailCodes": ["cropbox_differs"] },
  "basis": [{ "pointer": "#/components/responses/Unprocessable/description", "text": "effective CropBox different from MediaBox [details code cropbox_differs]" }]
}
```

- **`given`** is `null` or the name of a precondition in `manifest.json`.
  - `draft-1`: one recipient, draft.
  - `draft-1-document`: draft with a one-page document uploaded.
  - `prepared-1`: prepared, with one signature field.

  Each given lists its own steps: `create` (an `EnvelopeCreate` body),
  `document` (a PDF descriptor) and `prepare` (`FieldInput[]`). Create, upload
  and prepare are each a versioned mutation. A subject therefore arranges
  `prepared-1` at version 2 or above, which the stale-version cases rely on
  (`previous_version`).
- **`request.operationId`** names the contract operation. The method and path
  template come from the vendored contract.
- **`request.principal`** is `sender` (a human operator with role `sender`) or
  `service` (role `service`). The default is `sender`. The subject maps it to a
  credential.
- **Default headers.** The harness adds:
  - a fresh valid `Idempotency-Key` when the operation declares one;
  - `If-Match: "<arranged version>"` when it declares one;
  - `Content-Type` from the body form.

  `request.headers` overrides a default, and `null` removes it.
- **Body forms:**
  - `{"json": value}`, optionally with `"padTo": n`, which adds trailing
    insignificant whitespace up to exactly n bytes;
  - `{"text": "...", "contentType": "..."}`;
  - `{"pdf": descriptor, "contentType"?: "..."}`.
- **Placeholders.** `{"$ctx": name}` takes one of: `envelope_id`, `version`,
  `next_version`, `previous_version`, `version_text`, `if_match_current`,
  `if_match_next`, `if_match_weak`, `absent_envelope_id`, `upload_sha256`,
  `upload_bytes`.
- **Generators.** `{"$gen": name}` takes `idempotency-key` or
  `idempotency-key-short`.
- **`expect`** for an accepting case is the operation's declared 2xx status,
  plus `body` assertions. Each assertion is `{path, equals | notEquals |
  greaterThan | length}`; values may be placeholders.
- **`expect`** for a rejecting case is the status, the `Error.code`, and any
  `detailCodes`.
- **`basis`** quotes the vendored contract. Each entry is `{pointer, text}`,
  where the text appears verbatim at the pointer, or `{pointer, value}`, where
  the value deep-equals what the pointer holds.

## Single-defect rule and outcomes

A rejecting case carries exactly one defect, and the rest of the request is
contract-valid. The case's derivation test proves this against the contract
itself (headers, path, media type, size, body schema, and PDF structure through
the independent inspector). The outcome for each defect comes from the
contract. Each test also checks:

- that the status is declared for the operation;
- that the code is named by that response's component description;
- that the expected body validates as `Error`.

| Defect | Status | Code | Contract basis |
|---|---|---|---|
| `body-schema`, `body-syntax` | 400 | `invalid_request` | BadRequest: "malformed JSON, schema violation or unknown property" |
| `body-rule` (EnvelopeCreate "Ordinals must be exactly 1 or 1..2 without gaps.") | 400 | `invalid_request` | The rule is part of the request schema's text, and no other `Error.code` names it |
| `header-missing` (`Idempotency-Key`), `header-invalid` | 400 | `invalid_request` | Required header parameter and its pattern |
| `header-missing` (`If-Match`) | 428 | `precondition_required` | PreconditionRequired: "If-Match missing on upload" |
| `path-parameter` | 400 | `invalid_request` | EnvelopeId pattern; readEnvelope declares 400, and the path parameter is its only validated input |
| `absent-resource` | 404 | `not_found` | NotFound: "absent or inaccessible" |
| `version-mismatch` | 409 | `version_conflict` | Conflict |
| `state` (upload on a prepared envelope) | 409 | `state_conflict` | uploadDocument: "draft only" |
| `body-too-large` | 413 | `payload_too_large` | PayloadTooLarge: "10 MiB for PDF upload, enforced while streaming; 256 KiB for JSON" |
| `media-type` | 415 | `unsupported_media_type` | uploadDocument accepts `application/pdf` only |
| `pdf-content` | 422 | `unsupported_pdf` (+ `cropbox_differs` detail for a differing effective CropBox) | Unprocessable: malformed, encrypted, already signed, over 50 pages, active content, unsupported features |
| `field-bounds` | 422 | `field_out_of_bounds` | Rect: "x+width<=1 and y+height<=1 are enforced by the server" |

The boundary cases follow "over the route limit": a body exactly at a limit is
accepted. That means 10 MiB = 10485760 bytes, which equals
`DocumentSummary.bytes.maximum`, and 256 KiB = 262144 bytes.

## Verdict

`judge()` in `tests/contract/envelopes/lib/harness.mjs` passes a response only
when all of the following hold:

- the status equals `expect.status`;
- the media type is `application/json`;
- the body parses;
- the body validates against the contract's response schema for that operation
  and status: `Envelope` for 2xx, `Error` for 4xx;
- for 2xx: every body assertion holds;
- for 4xx: `code` equals the expected code, and every expected detail code is
  present.

## Subject interface

```js
const subject = {
  name: 'opensig',
  async arrange(given, tools, givenName) { return { envelope_id, version }; },
  async handle(request) { return { status, headers, body }; },
};
```

- **`request`** is `{ operationId, method, path, principal, headers, body }`:
  - `path` is concrete and percent-encoded;
  - `headers` names are lower-case;
  - `body` is a `Buffer` or `null`.
- **`response.body`** is a `Buffer`, a `Uint8Array` or a string.
- **`makeApiSubject(name, handle, doc)`** builds `arrange()` from contract
  operations: `createEnvelope`, then `uploadDocument`, then `prepareEnvelope`,
  as the given requires. A real implementation therefore supplies only
  `handle()`.

## Consuming the manifest (T034)

```js
import { loadVendoredContract, operationIndex } from '../../contract/envelopes/lib/contract.mjs';
import { makeApiSubject, runManifest, summarize } from '../../contract/envelopes/lib/harness.mjs';
import { loadManifest } from '../../contract/envelopes/lib/manifest.mjs';

const { doc } = loadVendoredContract();
const manifest = loadManifest();
const results = await runManifest(makeApiSubject('opensig', handle, doc), { doc, index: operationIndex(doc), manifest });
assert.equal(manifest.total, 72);
assert.equal(results.length, 72);
assert.deepEqual(
  Object.fromEntries(Object.entries(summarize(results)).map(([k, v]) => [k, v.cases])),
  { envelope: 29, version: 17, 'upload-limit': 7, 'unsupported-pdf': 19 },
);
assert.deepEqual(results.filter((r) => !r.pass), []);
```

T034 must not label these results as success-criterion evidence.

## Changing the manifest

- **Contract change.** Re-vendor byte-exact from the new spec commit, then
  update `contracts/http-api.source.json`. Then re-derive every affected case
  and set `manifest.json` `contract.sha256` to the new digest. EC-03 fails until
  the manifest names the vendored digest.
- **Case ids** run without gaps in file order within each fixture. New cases
  are appended to a fixture.
- **A count change** updates all four of these together:
  - `manifest.json`;
  - the frozen counts in `tests/contract/envelopes/manifest.test.mjs`;
  - this README;
  - every consumer's count check.

## Limits

The manifest covers only its four categories. It does not exercise:

- authentication or role refusal (401/403);
- idempotent replay (`idempotency_conflict`);
- cross-tenant 404s;
- send confirmation;
- recipient routes or webhooks.

T034, T008, T010 and T019 own those.

The PDF inspector is a structural checker for the synthetic documents built
here. It is not a general PDF parser.

`format` keywords (`email`, `date-time`) are annotations in JSON Schema 2020-12
and are not asserted.
