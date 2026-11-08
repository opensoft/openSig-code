# Platform inventory

**Status: POLICY-PENDING.** Every item below, and the inventory as a whole, stays POLICY-PENDING until the owner decides the platform license scope. That decision is recorded in spec leg `specs/001-corporate-signing-mvp/plan.md` § Pending owner decision: platform license scope. This record does not pass, waive or reinterpret anything. The release gate (`npm run verify -- acceptance`) lists `platform-inventory(POLICY-PENDING)` as an open gate and fails while it is open.

The platform is what this code runs on but does not ship as an npm package. The strict MIT/Apache-2.0 application gate ([qualification.md](qualification.md)) covers the shipped npm closure and the assets in `dist/`. It does not decide these items.

## How it is produced

`node scripts/platform-inventory.mjs [--root DIR] [--out DIR]` writes `platform-inventory.json`, by default to `.verify-out/platform-inventory/`. `node scripts/license-inventory.mjs` writes the same record next to the SBOM. The tool's exit status only says whether the record was written. Its status field is always `POLICY-PENDING`, and no option changes that.

## Items

| Id | Item | Role | What is recorded |
|---|---|---|---|
| `node-runtime` | Node.js 24.22.2 (`tools/node`, from `scripts/fetch-node.sh`) | Application runtime | Receipt fields (version, tarball, `bin/node` and npm-tree digests, signer fingerprint) and `node --version`. Recorded licenses, from the plan: Node.js MIT. Inside the binary: V8 BSD-3-Clause, ICU Unicode-3.0, zlib Zlib, zstd BSD, ittapi and inspector_protocol BSD, SipHash CC0, HdrHistogram BSD-2/CC0, minimatch BlueOak-1.0.0, rimraf and node-heapdump ISC, the SQLite public-domain blessing, and root CA certificates of unverified provenance. In the tarball: npm Artistic-2.0 |
| `linked-libraries` | Libraries the Node binary links dynamically (`ldd`) | Platform libraries | Each soname and resolved path (load addresses dropped). From the plan: glibc LGPL-2.1; libstdc++ and libgcc_s GPL-3+ with the GCC Runtime Library Exception |
| `openssl-cli` | OpenSSL command-line tool | Non-shipped test oracle and development-certificate tool | `openssl version` |
| `chromium` | Chromium build used by Playwright | Non-shipped test-time browser | The revision pinned by playwright-core (once T027 installs it), and the builds found under `PLAYWRIGHT_BROWSERS_PATH` and in the default cache |
| `hermes-image` | `docker.io/nousresearch/hermes-agent@sha256:adb7890916de63245523492be8f68f9d2095fecbec4e2a6dab7960381f0fc002` (v0.23.0) | Non-shipped isolated SC-006 test runtime, run with `--network none` | The pinned reference. Local presence is probed by `scripts/capabilities/hermes-runtime.mjs` (T040) |

## Snapshot measured on 2026-11-08 (T002)

- **node-runtime:**
  - `v24.22.2`
  - tarball `48cc0e21…aaf75`
  - `bin/node` `904a6d34…2a52`
  - npm tree `dfae9505…14f9`
  - signer `5BE8A3F6C8A5C01D106C0AD820B1A390B168D356`
- **linked-libraries:**
  - `linux-vdso.so.1`
  - `libdl.so.2`
  - `libstdc++.so.6`
  - `libm.so.6`
  - `libgcc_s.so.1`
  - `libpthread.so.0`
  - `libc.so.6`
  - `/lib64/ld-linux-x86-64.so.2`
  - Libraries resolve under `/lib/x86_64-linux-gnu/`.
- **openssl-cli:** `OpenSSL 3.0.13 30 Jan 2024`.
- **chromium:** no pinned revision yet, because Playwright arrives in T027. This environment sets `PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`, which holds `chromium-1228` and `chromium_headless_shell-1228`. The default cache `~/.cache/ms-playwright` holds `chromium-1234`, `chromium-1243` and their headless shells. T027 must pin a Playwright version whose revision is present in the location Playwright will actually use.
- **hermes-image:** the pinned reference above. Local presence was not probed here.

All items: **POLICY-PENDING**.
