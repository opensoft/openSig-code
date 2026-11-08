This is the **code leg** of openSig (`opensig`): the implementation
and its tests.

**The project's rules are not here.** They are in the assembly root
`opensoft/openSig`, in `AGENTS-shape.md` — read that before touching anything
that spans the legs. This leg is mounted there at `code/`, and the other leg,
`opensoft/openSig-spec`, beside it at `../spec/`, once the root is cloned with
`--recurse-submodules`.

Working here is ordinary — an ordinary repository on an ordinary branch. What
advancing this leg does NOT do is advance the project: that is ONE commit in
`opensoft/openSig` moving the gitlink, `contracts/code-pin.yaml` and every
workflow `@<sha>` for this leg together.

Being the code leg confers no authority over the implementation. The split is
navigation.

## openSig project rules

All original project work is Apache-2.0. Third-party shipped code, assets and dependencies must pass an MIT/Apache license allowlist. Never commit real patient data, signature images, credentials, private keys or wallet secrets. Use synthetic fixtures.

Keep clinical attestation and amendments in openChart, financial authority in openPractice, and human personal approval outside Hermes service credentials. Optional anchoring publishes commitments only and does not block ordinary signing.

Use the shared user-level OpenSpec/Speckit protocol. Canonical governance and feature plans live in the spec leg; implementation and tests live in the code leg. Shape rules live in the assembly root's AGENTS-shape.md.

## Runtime and verification commands

Established by T001 of feature 001-corporate-signing-mvp (spec leg `plan.md` § Technical Context and § Verification runner contract).

```sh
sh scripts/fetch-node.sh                  # pinned Node 24.22.2 into gitignored tools/
PATH="$PWD/tools/node/bin:$PATH"; export PATH
npm ci --no-audit --no-fund               # exactly the lockfile
npm run verify -- <mode>                  # the only acceptance signal
```

- `scripts/fetch-node.sh` verifies the clearsigned `SHASUMS256.txt.asc` with gpg against the embedded release key and fingerprint, requires the tarball SHA-256 to equal both the signed line and the embedded constant, extracts to `tools/`, and writes `tools/node.receipt.json`. It is idempotent, fails closed, and never uses the host Node.
- `npm run verify -- <mode>` takes exactly one mode name from `scripts/verify-modes.mjs` and has no flags. It prints one final stdout line, `verify: <mode> <STATUS> exit=<n> ...`, and writes `.verify-out/<mode>/result.json`. Exit statuses: 0 PASS, 1 FAIL, 2 USAGE, 3 CAPABILITY_ABSENT (environment-blocked, never a pass), 4 VACUOUS, 5 EVIDENCE_MISSING, 6 ENV_MISMATCH, 7 RUNNER_ERROR. Treat any non-zero exit as failure.
- `npm test` runs `verify -- all-unit`. `npm run typecheck` runs the pinned TypeScript compiler; never use `npx tsc`. Raw `node --test` is not an acceptance signal.
- Tests live in one directory per mode under `tests/`, matching the registry globs. Every `tests/**/*.test.mjs` must be claimed by exactly one mode. A test that satisfies a required case starts its name with `[CASE-ID]`. A test that produces evidence writes it under `$OPENSIG_VERIFY_OUT/`, with labels as top-level string properties and `tree_digest` set to `$OPENSIG_VERIFY_TREE_DIGEST`.
- Dependencies are exact pins (`.npmrc`: `engine-strict`, `save-exact`, `ignore-scripts`). They change only in a task whose `files:` list names `package.json` and `package-lock.json`.

**Freeze rule.** `scripts/verify.mjs`, `scripts/verify-modes.mjs` and `tests/tooling/verification-runner.test.mjs` are frozen at T001's commit. No later task lists or edits them. Before accepting any later task, the orchestrator runs `git diff --quiet <T001-sha> HEAD -- scripts/verify.mjs scripts/verify-modes.mjs tests/tooling/verification-runner.test.mjs`. Only a recorded architect amendment can change them, through a new `[O]` task that lists the three files, re-runs `npm run verify -- tooling` and re-freezes at that task's commit.
