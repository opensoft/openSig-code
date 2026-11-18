<!-- SPDX-License-Identifier: Apache-2.0 -->
# Integrity oracle case descriptors (T012)

`cases.json` holds structural descriptors and expected outcomes for the independent integrity oracle in `tests/integrity/oracle/`. It holds no PDF, key or certificate.

The cases are defined in plan.md § Case catalogs (OC), A-010 request #39. OC-01..OC-08 are the registry's required cases; OC-09 is an extra case from A-008 S1.

## How a case runs

At test runtime the oracle:

1. builds every document with its own deterministic minimal PDF builder. The base uses one of three forms:
   - a classic xref table;
   - a cross-reference stream with an object stream, either uncompressed or FlateDecode with the PNG Up predictor;
   - a hybrid table whose trailer carries `/XRefStm`.

   The signature update uses the kind of the base's last section, so it appends a table after a hybrid base;
2. generates RSA-3072 development keys and certificates with the OpenSSL CLI, in an owner-only (0700) `mkdtemp` directory. Private key files are 0600, and the directory is removed in `finally`;
3. signs the exact ByteRange bytes with `openssl cms -sign`;
4. builds the whole corpus before any case runs. A failed build stops the run, and no case is skipped.

## Descriptor fields

- `case`: the case ID.
- `signer` and `anchors`.
- `base`: `xref` (`table` by default, `stream`, `stream-flate` or `hybrid`) and an optional base `defect`.
- An optional `byte_range_defect` or `structure_defect`, written before signing so the signature over the stated ranges stays valid.
- An optional `signing.approval_evidence`, for OC-09. The attribute is inserted by the oracle's own DER code and re-signed with `openssl dgst -sha256 -sign`. It is kept only if `openssl cms -verify` passes on it, and only if the same CMS still carrying the old signature fails.
- A post-signing `mutation`.
- `expected`: the report fields, plus selected check results and detail codes. Acceptance requires `artifact_match` to be true.

`case_count` is the count check that T014 repeats.

Each entry from `buildCorpus` carries two expected digests, so consumers never re-derive them (request #41):

- `originalDigest`: the signed file before any mutation;
- `expectedApprovalEvidenceDigest`: lowercase hex, or `null` when the case requests no evidence check.

`checkPdf` refuses an `anchors` value that is not an array of certificate paths. An omitted value means no anchors.

When the structure check fails, the ByteRange's revision boundary falls back to the end of the file (plan.md OC-08). A second range that ends exactly at the file length passes; any other end fails.

## Mutants for Phase B, and the cases that kill them

| Mutant | Killed by |
|---|---|
| Coverage ignores an appended revision | OC-03-a, OC-03-b |
| ByteRange not checked against `/Contents` or the file length | OC-06-a..c, OC-07-a |
| Verification over the whole file instead of the ranges | OC-01-a and every valid case; OC-01-c explicitly |
| Integrity from messageDigest alone, without OpenSSL | OC-04-b |
| Trust checked with `-noverify` | OC-05-a, OC-05-c |
| Classic xref, `startxref` or `/Prev` not checked | OC-08-a..c |
| Acceptance with `artifact_match !== false` instead of `=== true` | every accepted case, re-checked without its recorded digest |
| Artifact digest or `/Contents` padding not checked | OC-04-a |
| A wrong, absent or malformed approval-evidence digest accepted | OC-09-b, OC-09-c, OC-09-d |
| Cross-reference streams not read | OC-01-d, OC-01-e |
| The xref-stream reader skips type-1 or type-2 checks | OC-08-d, OC-08-e; structure unit test |
| The PNG predictor not applied, or its filter byte unchecked | OC-01-e; the predictor unit test (unknown filter byte) |
| A splice without the negative control | the OC-09 tests assert both splice controls |
| Hybrid files rejected as unsupported | OC-01-f; the hybrid unit test |
| The `/XRefStm` ignored, or its offset left unchecked | OC-08-f; the hybrid unit test |
| The hidden stream's entries not merged or not checked | the hybrid unit test (a bad type-2 entry in the hidden stream) |
| The shared range concatenation drops the last byte (R2) | OC-02-f (the range edges, request #41) |
| `anchors: null` falls through to `-noverify` | the OC-05 refusal subtest |
| The entry's expected evidence digest is missing, or wrong | OC-09-a, OC-09-b; the OC-09 entry subtest |
| The end-of-file fallback accepts a range ending one byte short | OC-08-g |

No test shows that trust ignores the default CA stores. A mutant that drops `-no-CApath` or `-no-CAstore` is equivalent on any bench whose default stores lack the runtime CA. The guard is the fixed arguments of the trust call: `-CAfile` with only the case's anchors (or `-no-CAfile`), plus `-no-CApath`, `-no-CAstore` and `-purpose any`.
