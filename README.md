# openSig-code

The **code leg** of the `opensig` project: the implementation and its
tests. The requirements it implements live in
[`opensoft/openSig-spec`](https://github.com/opensoft/openSig-spec).

**Clone the assembly root, not this repository.** This leg is mounted as a
submodule at `code/` inside
[`opensoft/openSig`](https://github.com/opensoft/openSig), which
is what pins the commit of this repository that the project currently is:

```sh
git clone --recurse-submodules https://github.com/opensoft/openSig.git
cd openSig
make bootstrap
```

Working here directly is fine — it is an ordinary repository with an ordinary
branch. What advancing this leg does NOT do is advance the project: that is a
commit in the assembly root moving the gitlink, `contracts/code-pin.yaml` and
any workflow `@<sha>` reference together.

Being the code leg confers no authority over the implementation. The split is
navigation; authority travels in grants, and a project that keeps spec and
code in one repository is reviewed identically.

Topic: `xf-project-opensig`.

## Intended components

- **openSig**: envelope workflow, API, permissions and evidence.
- **openAutograph**: review, consent, authenticated human approval and visible signatures.
- **openCryptograph**: certificate-backed signatures, organizational seals, timestamps and verification.
- Consumer adapters for Hermes, openChart and openPractice; optional ledger adapters.

All original implementation will use Apache-2.0, with MIT/Apache-only shipped third-party materials. This repository currently contains a scaffold, not a signing runtime. Canonical architecture, OpenSpec changes and Speckit feature plans belong in the spec leg; do not duplicate their task lists here. See the [implementation plan](https://github.com/opensoft/openSig-spec/blob/docs/opensig-foundation/ideation/brainstorm/opensig-implementation-plan.md).

## Local development

Run these with the pinned runtime first on `PATH` (see `AGENTS.md`: `sh scripts/fetch-node.sh`, then
`PATH="$PWD/tools/node/bin:$PATH"`). The `dev` verify mode (`npm run verify -- dev`) tests both tools.

### Synthetic fixtures

```sh
node scripts/gen-fixtures.mjs                              # rewrite fixtures/synthetic/{documents,identities}/
node scripts/gen-fixtures.mjs --check                      # exit 1 naming any changed, missing or extra file
node scripts/gen-fixtures.mjs --out <dir> --with-large     # full set, including the on-demand size-boundary documents
```

The generator is deterministic: the same bytes on every run, with no clock, randomness, locale or
compression input. `fixtures/synthetic/documents/manifest.json` records, for every document, its
kind, size, SHA-256, cross-reference form, displayed page geometry (after `/Rotate`), expected
outcome and, for malformed variants, the single structural defect.

| Kind | Documents |
|---|---|
| Valid | `agreement-multipage.pdf` (3 pages), `agreement-xref-stream.pdf` (the same agreement with an object stream and a cross-reference stream), `rotated-pages.pdf` (inherited, overridden and negative `/Rotate`, inherited and offset `/MediaBox`), `single-page.pdf`, `pages-50.pdf` |
| Rejected | `pages-51.pdf`, `encrypted-flag.pdf`, `already-signed.pdf` (signature field with a real `/ByteRange` and zero-filled `/Contents`), eight `malformed-*.pdf` variants |
| On demand (not committed) | `size-at-limit.pdf` (exactly 10 MiB), `oversized.pdf` (10 MiB + 1 byte) |

`fixtures/synthetic/identities/identities.json` holds two synthetic tenants, each with a sender,
a tenant admin, a Hermes service principal and two recipients, on `.test` and `example.com`
addresses only. Fixtures contain no keys, credentials, signature values, images or embedded fonts.
Tests that need keys or certificates generate them at run time outside the tree.

### Dev launcher

```sh
node scripts/dev.mjs [--port <n>] [--check]
```

- Binds only `127.0.0.1` (default port 8443). It refuses any other `--host` or `OPENSIG_HOST`,
  including non-loopback addresses and loopback aliases such as `localhost` and `::1`.
- Refuses SMTP and mail-relay settings: any variable whose name contains `SMTP`, the
  `MAIL_*`/`MAILER_*`/`EMAIL_*` relay variables, and `OPENSIG_MAIL_TRANSPORT` other than `spool`.
  Development mail goes only to the gitignored file spool `var/spool/`.
- Refuses any Node version other than `.node-version`.
- Starts `src/server/main.ts` once it exists (T031); until then it exits 3 and starts nothing.
  `--check` validates the configuration without starting anything.

The server receives a cleared environment: `PATH`, `HOME`, `LANG`, `LANGUAGE`, `TZ`, `TMPDIR`,
`TERM`, `LC_*`, every `OPENSIG_*` setting without a secret-like name, and these launcher-set values:

| Variable | Value |
|---|---|
| `OPENSIG_HOST` | `127.0.0.1` |
| `OPENSIG_PORT` | the port (`0` lets the OS choose) |
| `OPENSIG_ENV`, `NODE_ENV` | `development` |
| `OPENSIG_MAIL_TRANSPORT` | `spool` |
| `OPENSIG_SPOOL_DIR`, `OPENSIG_DATA_DIR` | `var/spool`, `var/data` (absolute paths, created with mode 0700) |

Secrets are passed by 0600 file path or inherited descriptor, never through the environment. A
container composition is deferred, so there is no `compose.yaml`.
