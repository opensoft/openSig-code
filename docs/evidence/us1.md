# US1 acceptance evidence (T011)

Every value below comes from the final `npm run verify -- us1` run, made on the exact tree of the T011 commit
before it was committed: that run's `.verify-out/us1/result.json` and `.verify-out/us1/evidence.json`.

## Run

| Item | Value |
|---|---|
| Mode | `us1` (T011, kind `acceptance`) |
| Runner final status line | `verify: us1 PASS exit=0 files=6 tests=7 pass=7 fail=0 skip=0 todo=0 cases=6/6` |
| Tree digest (`tree_digest`) | `9ea3e8ee02924c81791867dd73b91d1d6d1e90506d822c823701ae46746b3fbe` |
| Code commit the run was made on | the T011 commit's own tree (parent `d10ca658782f3b30bb7bea448541fdc24bd83906`), identified by the tree digest above |
| Run started (UTC) | 2026-11-18T07:47:43.315Z |
| Tests (passed / total) | 7 / 7 (minimum 6) |
| Test files | 6 |
| Required cases found | 6 of 6 (SC004-01, SC004-02, SC004-03, SC004-04, US1-01, US1-02) |

The tree digest is the runner's (`scripts/verify.mjs`, plan.md "Tree digest"): SHA-256 over sorted
`path\0sha256(content)\n` lines of the tracked and untracked-but-not-ignored files under `src/`, `tests/`,
`scripts/`, `fixtures/` and `contracts/`, plus `package.json`, `package-lock.json`, `.node-version` and
`tsconfig*.json`. Paths under `docs/evidence/` are outside it, so committing this file does not change the digest
it records.

## Browser

| Label | Value |
|---|---|
| `browser_engine` | chromium |
| `browser_version` | 149.0.7827.55 |
| Chromium revision | 1228 |
| Executable, relative to the browsers directory | `chromium-1228/chrome-linux64/chrome` |
| Browsers directory source | `PLAYWRIGHT_BROWSERS_PATH` |
| Playwright | 1.61.1 |
| Headless; launch arguments | true; none |

## Session cookie (row LOOPBACK-COOKIE)

| Item | Value |
|---|---|
| Transport | plain loopback http (`http://127.0.0.1`) |
| `__Host-opensig_rs` attributes as the browser holds them (jar read unfiltered; exact host, name and path) | host-only `127.0.0.1`, Path=/, Secure, HttpOnly, SameSite=Strict, a session cookie |
| Sent by the browser and accepted by the server | yes: `readRecipientSession` answered 200 with it and 401 without it, both matched in the server's request log |
| Bypass flags | none |

## Cases

| Case | What it shows | Result |
|---|---|---|
| SC004-01 | Keyboard-only completion with zero pointer events; Tab reaches the document links, then signature and consent; the viewer iframe is never entered; no trap | PASS |
| SC004-02 | Galaxy S9+ (320 px) and Pixel 7 (412 px) emulation: no horizontal overflow at any step; one CDP touch path, with a 120 ms finger rest at the end of each stroke, completes the approval | PASS |
| SC004-03 | The exact consent text and version, the assurance statement and the organization-seal notice are visible before Approve; the approval binds them | PASS |
| SC004-04 | Opening, reloading and prefetching the link, each matched by correlation id in the server's request log before the comparison, change nothing in the server's record; a positive control shows the comparison sees a change | PASS |
| SC004-04 browser `<link rel=prefetch>` | Observed or not observed at the server | observed, and counted: 7 counted requests (3 by the scanner, 3 browser opens and reloads, 1 browser prefetch) |
| US1-01 | Two sequential recipients; recipient 2 has no invitation, challenge or session and gets 401 from its own browser until recipient 1's approval commits; the sender's bearer beside recipient 2's session gets 401; fully approved, shown distinct from completed | PASS |
| US1-01 viewer iframe | The iframe's own request: status, content type, disposition, `frame-ancestors`, body SHA-256 against the document digest; the viewer drawing the PDF | 200, `application/pdf`, `inline`, `frame-ancestors 'self'`, body SHA-256 equal to the session's document digest; the drawing is not observed (headless) |
| Receipt wording | T009's exact `FULLY_APPROVED` text (`src/autograph/flow.ts:48-49`), no "sealed", no affirmative completion claim | PASS (US1-01, US1-02, SC004-01, SC004-02, SC004-03) |
| US1-02 | One recipient, fully approved distinct from completed; the sender's and the service principal's bearer tokens, alone and beside the recipient's cookie and CSRF token, with the allowlisted Origin, get 401 `unauthenticated` attributed to approveAsHuman, with no approval and no version change | PASS |

## Limits (carried, not results)

- "Fully approved" is the `finalizing` state; completion needs the organization seal (US2), which this run does not exercise.
- Whether the browser's viewer draws the PDF is not observable in a headless run.
- Row FLICK-TAP (a stroke ending in an instant lift) is a recorded limit; this run models a realistic 120 ms finger rest and does not test it.
- Local, loopback-only run; no production deployment, mail relay, identity provider or certificate is involved.
