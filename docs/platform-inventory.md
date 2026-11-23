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
| `bwrap` | `bwrap`, at `/usr/bin/bwrap` or `/bin/bwrap` | Platform tool: the preferred PDF parse-sandbox launcher (T033) | Sandbox tool record (below) |
| `unshare` | util-linux `unshare`, at `/usr/bin/unshare` or `/bin/unshare` | Platform tool: launches the PDF parse worker in a new user and network namespace (T033 parser sandbox, amendment A-007); the util-linux launcher | Sandbox tool record (below). Also kept from A-007, an upstream statement and not a package record: util-linux has no single license; GPL-2.0-or-later by default, with LGPL-2.1-or-later, BSD and public-domain parts (util-linux `README.licensing`; recorded, not re-measured here) |
| `mount` | `mount`, at `/usr/bin/mount` or `/bin/mount` | Platform tool: the util-linux launcher mounts the tmpfs sandbox root and its read-only binds with it | Sandbox tool record (below) |
| `chroot` | `chroot`, at `/usr/sbin/chroot`, `/usr/bin/chroot` or `/sbin/chroot` | Platform tool: the util-linux launcher enters the sandbox root with it | Sandbox tool record (below) |
| `setpriv` | `setpriv`, at `/usr/bin/setpriv` or `/bin/setpriv` | Platform tool: bound into the sandbox root, it drops every capability before the worker runs (util-linux launcher) | Sandbox tool record (below) |
| `sh` | `/bin/sh` | Platform tool: runs the util-linux launcher's setup script inside `unshare`, and the service's `ulimit` wrapper around either launcher | Sandbox tool record (below) |
| `mkdir` | `mkdir`, run by name | Platform tool: the util-linux setup script creates the bind targets in the sandbox root with it. The service starts the launcher with an empty environment, so `/bin/sh` finds `mkdir` on its own default search path | Sandbox tool record (below), with the shell's search path as the candidate list |
| `chromium` | Chromium build used by Playwright | Non-shipped test-time browser | The revision pinned by playwright-core and the builds found at the effective browsers path, plus the default cache when it differs. The effective path is resolved exactly as the frozen runner's `chromium` probe resolves it: `PLAYWRIGHT_BROWSERS_PATH=0` means `<playwright-core>/.local-browsers`, any other non-empty value is that path, and unset or empty means `~/.cache/ms-playwright` |
| `hermes-image` | `docker.io/nousresearch/hermes-agent@sha256:adb7890916de63245523492be8f68f9d2095fecbec4e2a6dab7960381f0fc002` (v0.23.0) | Non-shipped isolated SC-006 test runtime, run with `--network none` | The pinned reference. Local presence is probed by `scripts/capabilities/hermes-runtime.mjs` (T040) |

### Parse-sandbox tools (A-009, A-010 LI-11)

The seven rows from `bwrap` to `mkdir` cover every platform tool the PDF parse-sandbox launcher (`src/pdf/sandbox.ts`, T033) can run. They are in the launcher's order: its fixed `TOOL_PATHS`, then the shell it runs under, then the programs its setup script calls by name. Test LI-11 takes the same list from the launcher itself and fails when the two differ. Each sandbox tool record holds:

- **Where the tool is.** Every candidate path the launcher checks, whether it exists and what it resolves to through its symbolic links. Then the path the launcher would run (the first existing candidate, or for `mkdir` the path `/bin/sh` reports with an empty environment), and that path resolved through its symbolic links. For example, `/bin/sh` resolves to the real shell, and merged-`/usr` links resolve to the file under `/usr`.
- **Its version:** the first line of `--version` where the tool prints one; otherwise why there is none.
- **Its package:** only from the package manager, `dpkg -S <resolved path>`, with the installed version from `dpkg-query`.
- **Its license:** only from that package's own record, `/usr/share/doc/<package>/copyright`. The license is the `License` of the paragraph whose `Files` patterns include `*`, read only from a machine-readable (DEP-5) file. The licenses the record's other `Files` paragraphs name are listed as recorded. Free text is never interpreted.

When a record is missing, the record says so and no value is filled in. That covers no package manager, no owning package, more than one owner, no copyright file, and a copyright file that is not machine-readable or has no `Files: *` license. A tool absent from the host is recorded as absent, with every candidate path, and is never left out. No license is invented, guessed or relaxed. None is evaluated against the allowlist, and none affects the application gate.

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
- **unshare:** `unshare from util-linux 2.39.3` (added by the A-007 T002 follow-up). Its full sandbox tool record is in the next section.
- **chromium:** at T002 there was no pinned revision yet. T027 pinned playwright 1.61.1 (revision 1228). This environment sets `PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`, the effective path, which holds `chromium-1228` and `chromium_headless_shell-1228`. The default cache `~/.cache/ms-playwright` holds `chromium-1234`, `chromium-1243` and their headless shells.
- **hermes-image:** the pinned reference above. Local presence was not probed here.

## Parse-sandbox tools measured on 2026-11-16 (A-010 LI-11)

Measured on the development host with `node scripts/platform-inventory.mjs`. Every tool was present. Among the launcher's fixed candidate paths only `/usr/bin/chroot` is absent; of `mkdir`'s search-path candidates only `/usr/bin/mkdir` and `/bin/mkdir` exist. `/bin`, `/sbin` and `/lib` are merged-`/usr` links, so every `/bin/...` and `/sbin/...` candidate resolves to the file under `/usr`.

| Tool | Runs, and resolves to | `--version` | Package (`dpkg -S`), version | License (`Files: *`) |
|---|---|---|---|---|
| `bwrap` | `/usr/bin/bwrap` | `bubblewrap 0.9.0` | `bubblewrap` 0.9.0-1ubuntu0.3 | LGPL-2+ |
| `unshare` | `/usr/bin/unshare` | `unshare from util-linux 2.39.3` | `util-linux` 2.39.3-9ubuntu6.6 | GPL-2+ |
| `mount` | `/usr/bin/mount` | `mount from util-linux 2.39.3 (libmount 2.39.3: …)` | `mount` 2.39.3-9ubuntu6.6 (a package of its own; its record names `Upstream-Name: util-linux`) | GPL-2+ |
| `chroot` | `/usr/sbin/chroot` | `chroot (GNU coreutils) 9.4` | `coreutils` 9.4-3ubuntu6.3 | GPL-3+ |
| `setpriv` | `/usr/bin/setpriv` | `setpriv from util-linux 2.39.3` | `util-linux` 2.39.3-9ubuntu6.6 | GPL-2+ |
| `sh` | `/bin/sh` → `/usr/bin/dash` | none: dash has no `--version` (it exits 2) | `dash` 0.5.12-6ubuntu5 | BSD-3-Clause |
| `mkdir` | `/usr/bin/mkdir`, found on dash's default search path `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | `mkdir (GNU coreutils) 9.4` | `coreutils` 9.4-3ubuntu6.3 | GPL-3+ |

Every license above is read from `/usr/share/doc/<package>/copyright`, and they match the bench record (bubblewrap LGPL-2+, util-linux GPL-2+, coreutils GPL-3+). The other `Files` paragraphs of the same records also name these licenses, as recorded:

- **bubblewrap:** `pd-bubblewrap.jpg`, `permissive-git.mk`, `GPL-2+ with Autoconf exception`.
- **util-linux and mount (one shared text):** `GPL-2`, `GPL-3+`, `public-domain`, `BSD-4-clause`, `MIT`, `BSD-3-clause`, `BSLA`, `LGPL-2+`, `LGPL-2.1+`, `LGPL`, `LGPL-3+`.
- **coreutils:** `GPL-3+ and BSD-4-clause-UC`, `GPL-3+ and ISC`, `FSFULLR`, `GFDL-NIV-1.3`.
- **dash:** `public-domain`, `GPL-2+`, `BSD-3-clause`.

These licenses are platform licenses, recorded and not gated. A host that lacks a tool, the package manager or a copyright record produces a record that says so.

All items: **INVENTORIED** (recorded separately; never gating the application).
