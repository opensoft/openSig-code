# Dependency qualification

Status: the license inventory gate exists (T002). T027 lands the complete package set (it adds playwright as a non-shipped development tool) and re-runs this qualification against the real lockfile. Nothing here waives anything. The platform inventory is a separate record with status POLICY-PENDING; see [platform-inventory.md](platform-inventory.md).

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
- **License files.** A shipped package may carry at most one root license text (`LICENSE*`, `LICENCE*` or `COPYING*`) and at most one root `NOTICE*`. Any other such file anywhere in the package fails as an extra license file, for example a separately licensed font or wasm asset. Source files such as `license.js` are not license files.
- **Outputs** go to `--out`, by default `.verify-out/license-inventory/`, which is gitignored:
  - `sbom.cdx.json`: CycloneDX 1.6. Shipped packages have `scope: required`, non-shipped ones `excluded`. Each component carries its classification, policy result and SHA-512 lockfile integrity.
  - `inventory.json`
  - `platform-inventory.json`
- **NOTICE.** `NOTICE` at the repository root is regenerated with `--write-notice`. Without that flag, a stale `NOTICE` fails the run.
- **Exit status:**
  - 0: the gate passes and `NOTICE` is current.
  - 1: a policy failure or a stale `NOTICE`.
  - 2: a usage error, or an incomplete or inconsistent install (a package locked but not installed, a version drift, an unresolvable dependency, or a missing lockfile).
- **Verification.** `npm run verify -- license-inventory` runs cases LI-01..LI-10 on synthetic `node_modules` trees, plus the gate on this repository.

## Current result (T002 commit, lockfile with typescript and @types/node)

Application gate: **PASS**. The shipped closure is **empty**, and no third-party asset is copied into `dist/` (there is no `dist/` yet). `NOTICE` therefore lists no third-party material.

| Package | Version | License | Policy result | Classification | License files |
|---|---|---|---|---|---|
| typescript | 6.0.3 | Apache-2.0 | allowed | non-shipped | `LICENSE.txt` |
| @types/node | 24.19.2 | MIT | allowed | non-shipped | `LICENSE` |
| undici-types | 7.24.6 | MIT | allowed | non-shipped | `LICENSE` |

Recorded for the owner, not waived: typescript 6.0.3 also carries `ThirdPartyNoticeText.txt`. That file covers DefinitelyTyped (MIT), Unicode, W3C and CC-BY-4.0 material in its `lib` files. typescript is a build-time type checker that emits nothing into any distributable, so it is a non-shipped tool and not an application dependency.

Platform items (the Node runtime and its bundled components, linked system libraries, the OpenSSL CLI, the Chromium build and the Hermes image) are outside this gate. They have status POLICY-PENDING until the owner decides the platform license scope, and the release gate stays OPEN.
