# Dependency qualification

Status: qualified for the complete package set (T027). The license inventory gate (T002) passes against the real lockfile. T027 added playwright 1.61.1 as a non-shipped development tool. **No later task may add a package.** Nothing here waives anything. The platform inventory is a separate record with status POLICY-PENDING; see [platform-inventory.md](platform-inventory.md).

Authority: spec leg `specs/001-corporate-signing-mvp/plan.md` § Technical Context (Dependencies, A-002) and § Pending owner decision: platform license scope; FR-011.

## The gate

`node scripts/license-inventory.mjs [--root DIR] [--out DIR] [--write-notice]`

- **Policy.** `scripts/license-policy.json` allows exactly `MIT` and `Apache-2.0`.
- **Classification.** Every package in `package-lock.json` is either `shipped` or `non-shipped`.
  - `shipped`: the production closure, plus any package owning a file copied byte for byte into `dist/`. The closure starts from the `dependencies` and `optionalDependencies` in `package.json`. It follows each package's `dependencies`, `optionalDependencies` and `peerDependencies`, using Node module resolution over the lockfile. The tool computes the closure itself and does not trust the lockfile's `dev` flags.
  - `non-shipped`: every other package, meaning the `devDependencies` tree. These are inventoried with full license data and reported, but not gated.
- **SPDX evaluation** applies to shipped packages:
  - An `OR` passes when one alternative is fully allowed, and an `AND` needs every term allowed.
  - `WITH` exceptions and `+` are not allowed.
  - Operators must be upper case.
  - Identifiers match case-insensitively.
  - A missing license fails. So does an unknown one: `SEE LICENSE IN …`, `UNLICENSED`, `LicenseRef-…`, or a malformed expression.
  - A legacy `licenses` array with several entries means all of them: `[MIT, GPL-3.0]` is read as `(MIT) AND (GPL-3.0)` and fails, never as an `OR`. An unreadable entry makes the license unknown. A package declaring both `license` and `licenses` is held to both.
- **License files.** A license text is any file whose name contains `licence`, `license`, `notice`, `copying`, `copyright`, `third-party` or `thirdparty` (case-insensitive), and any file under a `licenses/` or `licences/` directory. Source-code files (`.js`, `.mjs`, `.cjs`, `.ts`, `.mts`, `.cts`, `.jsx`, `.tsx`, `.map`) such as `license.js` are code, not license texts.
  - A shipped package may carry one root license text (`LICENSE*`, `LICENCE*` or `COPYING*`) and one root `NOTICE*`. A package that declares exactly `MIT` and `Apache-2.0` (`MIT OR Apache-2.0` or `MIT AND Apache-2.0`) may carry one root license text for each, such as `LICENSE-MIT` and `LICENSE-APACHE`. Each is matched to its license by its recognised text, or else by its name.
  - Every other license text anywhere in a shipped package fails as an extra license file. Examples: a bundle's `<bundle>.js.LICENSE` sidecar, `ThirdPartyNotices.txt`, `licenses/OFL.txt`, `fonts/COPYRIGHT`, or a separately licensed font or wasm asset.
  - A root license text that is recognisably a different license from the declared one fails as `license-text-mismatch`, for example a package declared `MIT` whose `LICENSE` is the Apache-2.0 text. A text the tool cannot recognise is not reported as a mismatch.
  - A symbolic link inside a shipped package fails (`package-symlink`).
- **`dist/`.** Every regular file in `dist/` is compared byte for byte with the installed package files. A symbolic link anywhere in `dist/`, or `dist` itself as a link, fails the gate (`dist-symlink`); links are never followed. Read errors stop the run with exit 2; they are never skipped.
- **Outputs** go to `--out`, by default `.verify-out/license-inventory/`, which is gitignored:
  - `sbom.cdx.json`: CycloneDX 1.6. Shipped packages have `scope: required`, non-shipped ones `excluded`. Each component carries its classification, policy result and SHA-512 lockfile integrity. Its `opensig:application-gate` value is the run's final gate, `NOTICE` check included, the same value as `inventory.json`. Its serial number is derived from the lockfile, the policy, the gate and a digest of every classification, license-file split and finding (`opensig:classification-sha256`).
  - `inventory.json`, which records the SBOM serial number and the classification digest.
  - `platform-inventory.json`
- **NOTICE.** `NOTICE` at the repository root is regenerated with `--write-notice`. Without that flag, a stale `NOTICE` fails the run.
- **Exit status:**
  - 0: the gate passes and `NOTICE` is current.
  - 1: a policy failure or a stale `NOTICE`.
  - 2: a usage error, a read error (an unreadable package file or `dist/` entry, or a `dist` that is not a directory), or an incomplete or inconsistent install (a package locked but not installed, a version drift, an unresolvable dependency, or a missing lockfile).
- **Verification.** `npm run verify -- license-inventory` runs cases LI-01..LI-10 on synthetic `node_modules` trees, plus the gate on this repository.

## Current result (T027: complete package set)

Application gate: **PASS**. The shipped closure is **empty**: `package.json` declares no `dependencies`, and no third-party asset is copied into `dist/` (there is no `dist/` yet). `NOTICE` therefore lists no third-party material. `npm run verify -- qualification` re-checks five things:
- QL-01: the gate;
- QL-02: exact pins;
- QL-03: the "dev bytes not in distributable" check, which fails on a synthetic `dist/` holding dev-package bytes;
- QL-04: the browser revision, by launching it;
- QL-05: an offline install with `ignore-scripts`. It runs `npm ci --offline --ignore-scripts` on a copy of `package.json`, `package-lock.json`, `.npmrc` and `.node-version` in a temporary directory. It drops the `npm_*` variables that the enclosing `npm run` exports, so only the `.npmrc` files configure that install. It needs the npm cache that an earlier `npm ci` of this lockfile filled, and it downloads nothing.

It also writes `.verify-out/qualification/inventory.json`, bound to the tree digest.

| Package | Version | License | Policy result | Classification | Notes |
|---|---|---|---|---|---|
| typescript | 6.0.3 | Apache-2.0 | allowed | non-shipped | `LICENSE.txt`; third-party notices below |
| @types/node | 24.19.2 | MIT | allowed | non-shipped | `LICENSE` |
| undici-types | 7.24.6 | MIT | allowed | non-shipped | `LICENSE` (dependency of @types/node) |
| playwright | 1.61.1 | Apache-2.0 | allowed | non-shipped | `LICENSE`, `NOTICE`; third-party notices below |
| playwright-core | 1.61.1 | Apache-2.0 | allowed | non-shipped | `LICENSE`, `NOTICE`; third-party notices below |
| fsevents | 2.3.2 | MIT | allowed | non-shipped | Optional, darwin-only dependency of playwright. It is locked but not installed on linux. Its install script is the only one in the lockfile, so `ignore-scripts` loses nothing on linux |

### Third-party notices of the development tools (recorded for the owner, not waived)

These packages are build- or test-time tools. They contribute no bytes to any distributable, as QL-03 checks.

- **`typescript/ThirdPartyNoticeText.txt`** covers DefinitelyTyped (MIT), Unicode, W3C and CC-BY-4.0 material in typescript's `lib` files.
- **`playwright-core/ThirdPartyNotices.txt`** explains that npm packages are inlined into bundles under `lib/`, each listed in a sidecar file with its full license text:
  - `playwright-core/lib/utilsBundle.js.LICENSE`: 83 inlined packages. The license texts are mostly MIT, plus 11 ISC and 5 BSD-style texts.
  - `playwright-core/lib/serverRegistry.js.LICENSE`: 14 inlined packages, MIT and ISC.
- **`playwright/ThirdPartyNotices.txt`** describes the same arrangement, with these sidecars:
  - `playwright/lib/matchers/expect.js.LICENSE`: 29 packages, MIT and ISC.
  - `playwright/lib/transform/babelBundle.js.LICENSE`: 68 packages, mostly MIT with ISC, and Apache mentions.
  - `playwright/lib/transform/esmLoader.js.LICENSE`: 13 packages, MIT, ISC and one BSD-style text.

The T002 gate's license-file rule matches these `<bundle>.js.LICENSE` sidecars and the `ThirdPartyNotices.txt`/`ThirdPartyNoticeText.txt` files: `inventory.json` records them as `extra_license_files` of playwright (4), playwright-core (3) and typescript (1). They fail nothing here, because all three packages are non-shipped. If a package carrying them were ever shipped, each would fail the gate as an extra license file.

### Playwright pin and browser revision

The effective browsers path is the one Playwright and the frozen runner's `chromium` probe both use: `PLAYWRIGHT_BROWSERS_PATH` when set, otherwise `~/.cache/ms-playwright`.

| Location | Source | Builds present (2026-11-08) |
|---|---|---|
| `/ms-playwright` | `PLAYWRIGHT_BROWSERS_PATH` (set in this environment): **effective** | `chromium-1228`, `chromium_headless_shell-1228`, `ffmpeg-1011` |
| `~/.cache/ms-playwright` | default cache (not used while the variable is set) | `chromium-1234`, `chromium-1243` and their headless shells, `ffmpeg-1011` |

The version-to-revision mapping was read from each candidate's own `playwright-core/browsers.json` (tarballs fetched with `npm pack`):

| playwright-core | chromium revision |
|---|---|
| 1.60.0 | 1223 |
| 1.61.0 | 1228 |
| 1.61.1 | 1228 |
| 1.62.0 | 1234 |
| 1.62.1 | 1234 |
| 1.63.0 | 1243 |
| 1.64.x | 1248 |
| 1.65.0 | 1254 |

Chosen: **playwright 1.61.1**, with playwright-core 1.61.1. It names `chromium` and `chromium-headless-shell` revision **1228** (browserVersion 149.0.7827.55), which matches `chromium-1228` at the effective path. That is the later patch release of the two versions with this revision. No browser was downloaded. QL-04 launches the headless shell once, on `about:blank` only, and checks that `browser.version()` equals the pinned browserVersion.

Flagged for final reconciliation: the T027 task line says "the cache currently holds `chromium-1243` and `chromium-1234`". That describes `~/.cache/ms-playwright`, not the effective path, and is a stale environment note. Matching it would mean pinning 1.62.x (1234) or 1.63.0 (1243). The frozen probe would then look for those revisions under `/ms-playwright` and find them absent.

Platform items (the Node runtime and its bundled components, linked system libraries, the OpenSSL CLI, the Chromium build and the Hermes image) are outside this gate. They have status POLICY-PENDING until the owner decides the platform license scope, and the release gate stays OPEN.
