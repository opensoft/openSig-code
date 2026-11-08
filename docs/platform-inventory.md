# Platform inventory

**Status: INVENTORIED.** Owner decision (2026-11-08), verbatim: "MIT/Apache application and libraries; inventory platform licenses separately". It is recorded in spec leg `specs/001-corporate-signing-mvp/plan.md` § Owner decision: platform license scope (resolved 2026-11-08), and tracked in opensoft/openSig-spec#3.

- **Application artifacts** stay under the strict MIT/Apache-2.0 allowlist with no waiver: distributed code, libraries, bundled assets and transitive application dependencies. That is the application gate ([qualification.md](qualification.md)): the shipped npm closure and every asset copied into `dist/`.
- **Pre-existing platforms** are recorded here, separately, with their own licenses, and are **not** required to be MIT/Apache-only: the Node runtime binary and its embedded components, the OS/base image, the browser, any JVM and test-time platform tools.
- **No platform entry ever affects the application gate.** `scripts/license-inventory.mjs` computes the gate from the npm inventory and `dist/` alone; the platform record is written beside it and never read back.

This record passes, waives and reinterprets nothing. The decision closes the platform question only; it closes no deployment, trust, real-CI, production-Hermes or real-model gate. The release gate's list of open gates is defined by the frozen runner (`scripts/verify.mjs`); amendment A-007 removes the platform entry from it. The release gate (`npm run verify -- acceptance`) keeps failing on its other open gates.

The platform is what this code runs on but does not ship as an npm package.

## How it is produced

`node scripts/platform-inventory.mjs [--root DIR] [--out DIR]` writes `platform-inventory.json`, by default to `.verify-out/platform-inventory/`. `node scripts/license-inventory.mjs` writes the same record next to the SBOM. The tool's exit status only says whether the record was written. Its status field is always `INVENTORIED`, and no option changes that.

## Items

| Id | Item | Role | What is recorded |
|---|---|---|---|
| `node-runtime` | Node.js 24.22.2 (`tools/node`, from `scripts/fetch-node.sh`) | Application runtime | Receipt fields (version, tarball, `bin/node` and npm-tree digests, signer fingerprint) and `node --version`. Recorded licenses, from the plan: Node.js MIT. Inside the binary: V8 BSD-3-Clause, ICU Unicode-3.0, zlib Zlib, zstd BSD, ittapi and inspector_protocol BSD, SipHash CC0, HdrHistogram BSD-2/CC0, minimatch BlueOak-1.0.0, rimraf and node-heapdump ISC, the SQLite public-domain blessing, and root CA certificates of unverified provenance. In the tarball: npm Artistic-2.0 |
| `linked-libraries` | Libraries the Node binary links dynamically (`ldd`) | Platform libraries | Each soname and resolved path (load addresses dropped). From the plan: glibc LGPL-2.1; libstdc++ and libgcc_s GPL-3+ with the GCC Runtime Library Exception |
| `openssl-cli` | OpenSSL command-line tool | Non-shipped test oracle and development-certificate tool | `openssl version` |
| `unshare` | util-linux `unshare` | Platform tool: launches the PDF parse worker in a new user and network namespace (T033 parser sandbox, amendment A-007) | `unshare --version`. Recorded licenses: util-linux has no single license; GPL-2.0-or-later by default, with LGPL-2.1-or-later, BSD and public-domain parts (util-linux `README.licensing`; recorded, not re-measured here) |
| `chromium` | Chromium build used by Playwright | Non-shipped test-time browser | The revision pinned by playwright-core and the builds found at the effective browsers path, plus the default cache when it differs. The effective path is resolved exactly as the frozen runner's `chromium` probe resolves it: `PLAYWRIGHT_BROWSERS_PATH=0` means `<playwright-core>/.local-browsers`, any other non-empty value is that path, and unset or empty means `~/.cache/ms-playwright` |
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
- **unshare:** `unshare from util-linux 2.39.3` (added by the A-007 T002 follow-up).
- **chromium:** at T002 there was no pinned revision yet. T027 pinned playwright 1.61.1 (revision 1228). This environment sets `PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`, the effective path, which holds `chromium-1228` and `chromium_headless_shell-1228`. The default cache `~/.cache/ms-playwright` holds `chromium-1234`, `chromium-1243` and their headless shells.
- **hermes-image:** the pinned reference above. Local presence was not probed here.

All items: **INVENTORIED** (recorded separately; never gating the application).
