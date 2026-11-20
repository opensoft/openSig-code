# US2 local acceptance (T017): measured R7 writer evidence

<!-- SPDX-License-Identifier: Apache-2.0 -->

This record comes from the single final R7 writer run below. It binds to the measured precommit source on the known base, as permitted by A-010 requests #89 and #90; docs/evidence is excluded from the frozen source digest. A literal SHA of the commit containing this document would be circular. The orchestrator's postcommit acceptance record must name the resulting full commit SHA and independently match its source digest. This record does not complete independent acceptance, fresh recheck, publication or the Phase 4 checkpoint.

## The final run

| Item | Observed value |
|---|---|
| Measured source | R7 working tree on base `1950bfb0e06182251cba27807e82e170bd2447d3` |
| Runner source digest before and after | `ee2b5f8639de8f94b11bcb315bc67accc2bc583d2967e1d2f1f2ba6260cbc0af` (equal before/after and in evidence.json) |
| Decisive line, verbatim | `verify: us2-local PASS exit=0 files=4 tests=16 pass=16 fail=0 skip=0 todo=0 cases=12/12` |
| Passed required IDs | `SC001-01`, `SC001-02`, `SC001-03`, `SC001-04`, `SC001-05`, `SC001-06`, `SC001-07`, `SC001-08`, `SC001-09`, `SC001-10`, `SC005-01`, `SC005-02` |
| Extra passing IDs, outside the 12 | `US2-ANCHOR-CONTROL`, `US2-RECORD`, `US2-STATIC`, `US2-TAMPER` |
| Capabilities | OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024); Chromium 149.0.7827.55 revision 1228, headless, no launch arguments |
| Pinned Node | v24.22.2; binary SHA-256 `904a6d3484241d466989f9df9ba3aab822b1496191bdb28230eb491a55c32a52`; linux-x64 |
| Runner window UTC | 2026-11-20T18:50:11.569Z to 2026-11-20T18:53:58.326Z |
| Outer command window UTC | 2026-11-20T18:49:46+00:00 to 2026-11-20T18:53:58+00:00; 32 CPUs; load1m 27.85 to 23.41 |
| Parse sandbox listening metadata | UNCONFIRMED in the retained final-run artifacts: the frozen runner does not retain successful test stdout or the server listening line. No observed parse_mode or parse_launcher value is invented here. |

The frozen runner emits the aggregate decisive line above and records passed IDs and per-file totals. It does not retain individual successful test lines, so verbatim per-flow, tamper and full-run control pass lines are unavailable. Their evidence below is copied from the actual result/evidence records and passing assertions, not reconstructed stdout.

## Evidence labels, verbatim

| Label | Value |
|---|---|
| `verifier_name` | `opensig-product-verifier` |
| `verifier_version` | `0.1.0` |
| `oracle_name` | `opensig-integrity-oracle` |
| `oracle_version` | `0.1.0` |
| `timing_scope` | `indicative-local` |
| `tree_digest` | `ee2b5f8639de8f94b11bcb315bc67accc2bc583d2967e1d2f1f2ba6260cbc0af` |

The external PDF reader and declared single-instance pilot hardware remain OPEN. Every timing figure is indicative-local and makes no claim of SC-005.

## Ten flow records

Each row is copied from flows.json. Every flow used the unrelated anchor and remains untrusted. The actual passing flow assertions bind every browser-captured document body to the posted approval, session, stored approval, frozen fixture and packaged manifest; compare the product and independent oracle through T014's AGREEMENT_FIELDS; and validate all four package JSON schemas. The complete final-run browser-captures.json has 60 responses across 15 recipients: initial review and reload each include the checked read and viewer. All required request/frame correlations and every body hash and length passed.

| Case | Recipients | Document digest match | Product integrity / coverage / trust / evidence | Oracle integrity / trust / coverage / artifact match / evidence | Oracle artifact digest | Package digest |
|---|---|---|---|---|---|---|
| SC001-01 | 1 | true | valid / complete / untrusted / pass | valid / untrusted / complete / true / match | `82cc11a20c66a61845104e2f72dcafed24b4ca42de699c0bf92619780becf574` | `7d912786ec4bcf5288306dc73b2234d4650e723cca2c4c819f76423aeca5b5d7` |
| SC001-02 | 2 | true | valid / complete / untrusted / pass | valid / untrusted / complete / true / match | `8ef1f011f303d131f2954bfa0c5f712e41ee5f51b8d670c526ac298ebac57c3a` | `bf5be178d1872a43395c2d31257498a199777fc3543392132db1765dcfe2923e` |
| SC001-03 | 1 | true | valid / complete / untrusted / pass | valid / untrusted / complete / true / match | `6092f7732336214d4bac3fb0dda34503f70ca3ec3d7a045fd2ba9f52680b4470` | `a12bbf19d94046e894b8efdcda561599af339d47af2545ebb30cabf5b9bdd009` |
| SC001-04 | 2 | true | valid / complete / untrusted / pass | valid / untrusted / complete / true / match | `b7d43684dc926ab49143fb60fe9f900fec2557580b004d30a5fa6ba7ed2cd397` | `8d201295751a138c36a9874a5960935aee25fec9ab8a8e1b9f165fe9cc0db5a3` |
| SC001-05 | 1 | true | valid / complete / untrusted / pass | valid / untrusted / complete / true / match | `24b9c53c118ae3053fd29aac9454485b6042679cc3cc6cb240c604480422b2d1` | `d85c1c0d740c5a8ce760ece5a4cae1fef9bdf7c152ce771206b01e9dc75aa3b9` |
| SC001-06 | 2 | true | valid / complete / untrusted / pass | valid / untrusted / complete / true / match | `fc1b32235cc450400ae9324c2934b77e21bdd2ecd85dc7e4acb3887158038fd9` | `4698b862684997c137d2894dc0337517523a34c543c0cd0b3f00f91f85680500` |
| SC001-07 | 1 | true | valid / complete / untrusted / pass | valid / untrusted / complete / true / match | `ce5db37c2c64ff614ada96c06d34bd3f69dc9cb8a7016b5bb8aa15312b40ad30` | `19f9b984379d761df4f8eb330c1c73660b6672e058059ab034acb27e1bc88696` |
| SC001-08 | 2 | true | valid / complete / untrusted / pass | valid / untrusted / complete / true / match | `3b03dc464b1bd5937425e3c6a5997bf02cc2a6b64e5d8bc3f59052a5cc1b46d8` | `9d849726cfa775c1ae689df077e87cf9db06ef3da4391814395fd967245f1b75` |
| SC001-09 | 1 | true | valid / complete / untrusted / pass | valid / untrusted / complete / true / match | `601c82908e1e77f7ef7a36df989ba56c8bfae3a73b93c65fc2b50fe512e32f64` | `f23586e47bebcd04ee1021db8af87abe8072e4497eb1ccdc5073d1bab707084d` |
| SC001-10 | 2 | true | valid / complete / untrusted / pass | valid / untrusted / complete / true / match | `358f394a042d6aba5f9e47fbac241086178e4463f466809311f7214ba1f897dd` | `29366679801af482fde27b655d6b1a504bcba97accfc63a5c47606ee1cd8ee24` |

All ten finalizations succeeded after exactly one attempt; no final-run flow required an operator retry, rerun or replacement. All ten passing flow assertions validated ApprovalManifest, AuditReceipt, VerificationReport and PackageIndex against the vendored contract schemas. Individual pass stdout was not retained; result.json lists every SC001 ID and 13/13 passing tests in the flows file.

## Tamper controls (US2-TAMPER, outside required IDs)

Source: `SC001-01`. Each actual runBoth probe recorded zero disagreements.

| Probe | Product | Oracle |
|---|---|---|
| Untouched copy | integrity valid, coverage complete, trust untrusted, accepted true | integrity valid, coverage complete, trust untrusted; disagreements 0 |
| Seal certificate as only anchor | integrity valid, coverage complete, trust trusted, accepted true | integrity valid, coverage complete, trust trusted; disagreements 0 |
| Changed byte in first signed range offset 395 | integrity invalid, coverage complete, trust indeterminate, accepted false | integrity invalid, coverage complete, trust indeterminate; disagreements 0 |
| Changed byte in second signed range offset 8096 | integrity invalid, coverage complete, trust indeterminate, accepted false | integrity invalid, coverage complete, trust indeterminate; disagreements 0 |
| Appended revision | integrity valid, coverage incomplete, trust untrusted, accepted false | integrity valid, coverage incomplete, trust untrusted; disagreements 0 |

The appended revision left both verifiers' integrity valid and coverage incomplete; the product refused acceptance. The recorded T014 agreement check passed. This record does not invent a separate oracle acceptance field absent from the artifact.

## Actual composed-runner anchor control

This separate server/envelope/recipient ran after the concurrent burst, outside flows.json and every SC005 figure. Its anchors file contained the matching development seal certificate; the assertion reads the actual composed runner's stored report, not only reported options or a checker-only override.

| Item | Observed value |
|---|---|
| Seal certificate DER SHA-256 | `2ff85e4ba64a8358614a69feeeed31eb3d0a39c781d464c8cdb7d8c69e6e38c4` |
| Reported anchor SHA-256 | `2ff85e4ba64a8358614a69feeeed31eb3d0a39c781d464c8cdb7d8c69e6e38c4` |
| Stored report | trusted; pass/anchor-direct; trust_anchor_ref `2ff85e4ba64a8358614a69feeeed31eb3d0a39c781d464c8cdb7d8c69e6e38c4` |
| Stored integrity / coverage / served equals packaged | valid / complete / true |
| Artifact summary | valid / trusted |
| Finalization | succeeded after 1 attempt; waited 14973.4 ms |
| Awaited server close | 25.3 ms; runner stopped; closed logged true; historical ended 1 equals actual service total 1; running 0, waiting 0; stops past cap 0; run failures 0 |

Observed sorted runner order (control index 3, burst index 0):

| File | Tests / passes | Elapsed ms |
|---|---|---|
| `tests/acceptance/us2/concurrent.test.mjs` | 1 / 1 | 29289 |
| `tests/acceptance/us2/flows.test.mjs` | 13 / 13 | 179031 |
| `tests/acceptance/us2/static.test.mjs` | 1 / 1 | 287 |
| `tests/acceptance/us2/trust-anchor-control.test.mjs` | 1 / 1 | 18090 |

A separate corrected R6 unmutated targeted control passed before the full runs. It is component-only evidence on base `1950bfb0e06182251cba27807e82e170bd2447d3` with R6 source digest `e0c824e25867fbe401065299b315c03f31c521521a947b3bc574c51510f73a26`; it is not final R7 evidence. Its actual retained stdout is:

```text
✔ [US2-ANCHOR-CONTROL] an extra control, never one of the 12 required IDs, run after the SC005-02 burst: on its own composed server whose anchors file holds the matching anchor (the development seal certificate), one flow through T038's composed runner completes and the stored verification report says trusted through anchor-direct; the server is then closed, awaited and reaped (17186.300891ms)
```

Its companion isolated capacity mutant was killed by the idle-capacity assertion with running 1/waiting 0. M-R3 is reserved for exactly one run by the fresh independent recheck; the writer has not run it or claimed a kill.

## Indicative-local navigation

Authentication and mail were excluded; package retrieval was not counted. Bound 2000 ms.

| Category | Samples | p50 ms | p95 ms | Max ms |
|---|---|---|---|---|
| combined | 65 | 9.2 | 258.8 | 332.3 |
| status | 35 | 4.8 | 10.8 | 12.7 |
| link_open | 15 | 227.9 | 332.3 | 332.3 |
| review_reload | 15 | 181.4 | 323.7 | 323.7 |

## Indicative-local concurrent finalization

Ten normal synthetic envelopes were prepared serially, then their final approvals were released in one burst. Server time includes queueing for the default 15000 ms runner interval. The runner performs one attempt at a time. The measured peaks are recorded, not asserted, and do not mean ten simultaneous attempts.

| Figure | Value |
|---|---|
| Server maximum / bound | 21027 / 60000 ms |
| Client maximum | 21030.3 ms |
| Burst spread | 267 ms |
| Peak envelopes finalizing / attempts in progress | 10 / 1 |
| CPUs; burst load1m before/after | 32; 26.34 / 24.74 |

| Envelope ordinal | Server ms | Wait before attempt ms | Attempt window ms | Client ms | Base bytes | Final bytes | Attempts |
|---|---|---|---|---|---|---|---|
| 1 | 12743 | 9772 | 2971 | 12776.21 | 2921 | 8643 | 1 |
| 2 | 13742 | 12729 | 1013 | 13787.5 | 2921 | 8643 | 1 |
| 3 | 14650 | 13738 | 912 | 14694.88 | 2921 | 8643 | 1 |
| 4 | 15612 | 14645 | 967 | 15699.72 | 2921 | 8643 | 1 |
| 5 | 16628 | 15619 | 1009 | 16708.1 | 2921 | 8643 | 1 |
| 6 | 17553 | 16655 | 898 | 17582.82 | 2921 | 8643 | 1 |
| 7 | 18282 | 17539 | 743 | 18369.27 | 2921 | 8643 | 1 |
| 8 | 19040 | 18276 | 764 | 19070.44 | 2921 | 8643 | 1 |
| 9 | 19900 | 19033 | 867 | 19938.15 | 2921 | 8643 | 1 |
| 10 | 21027 | 19890 | 1137 | 21030.28 | 2921 | 8645 | 1 |

## Writer validation and preserved findings

The actual run ledger contains 25 invocations: 24 planned commands plus the first explicitly adjudicated launch-environment spare. The second spare remains unused. Full us2-local ran exactly twice; both optional absent-capability probes were omitted. No accepted historical gates were rerun.

| Validation | Actual result |
|---|---|
| Typecheck | PASS (first writer invocation, before R6/R7 test-only corrections) |
| no-secrets | PASS 29 tests, 7/7 cases |
| artifacts | PASS 19 tests, 5/5 cases |
| completion | PASS 44 tests, 3/3 cases |
| server | PASS 54 tests, 6/6 cases |
| UB-06 | PASS 2 tests |
| M1 | Extra package-index member rejected by PackageIndex schema assertion |
| M2 | Default matching anchor caught by required untrusted-flow assertion |
| M3 | 120000 ms runner interval caught by unchanged 60000 ms bound (124258 ms) |
| M4 | 1 ms mutant bound caught by timing assertion (19911 ms) |
| M5 / M6 / M7 | Product import in oracle adapter / literal fault flag / oracle directory name caught by intended static assertions |
| M8 | Product-built positive record recomputed; dropped-date self-consistent forgery caught by date_values assertion (component evidence) |
| M9 / M10 | Unauthorized oracle importer / control sorting before burst caught by intended static assertions |
| R7 transport A/B | One fresh review/reload with four actual captured bodies passed; actual guard accepted that record and rejected 22 named metadata corruptions. No consent/check/approval; component evidence, not a flow replacement |

Preserved failures and limits:

- The original R5 targeted control FAILED on a mistaken zero-history orphan assertion. Source and established T033 semantics show the counter counts historical children ended, not live survivors. R6 compares the actual historical count, retains stop-cap 0 and awaited shutdown, and asserts actual idle capacity 0/0.
- The first full R6 candidate remains FAILED: files 4 / tests 16 / pass 3 / fail 13 / cases 1/12, before digest `e0c824e25867fbe401065299b315c03f31c521521a947b3bc574c51510f73a26`, after digest null. Its SC005-02 pass is partial indicative-local evidence only.
- R6 SC001-01 failed with `Clicking the checkbox did not change its state`. The original cause remains UNCONFIRMED. One authorized passive diagnostic did not reproduce it; no approval was posted. R7 made no consent, readiness, focus, retry, force or sleep change and makes no claim to fix that finding. Request #90 permits only the separately bound corrected candidate; this passing run does not erase the original failure.
- R6 SC001-02..10 failed on an unsupported Fetch-only resource-type assertion. Actual same-request CDP evidence showed Network Fetch and Fetch-domain XHR for the checked read. R7 correlates exact origin/path/GET/networkId/frame roles, checks status/PDF and viewer inline/CSP, retains raw types, and preserves every body SHA/length/approval binding.
- Original targeted M1 invocation 14 FAILED before its intended assertion because the launch supplied an evidence-output directory without the runner source-digest environment. It is preserved as launch-environment spare 1, not an M1 kill or product failure. The corrected raw target uses the supported in-memory evidence branch and reached the intended schema failure; normal frozen verify launches were unchanged.
- A preflight lock-path error occurred before any gate/test invocation and consumed no runtime invocation or spare. Its original wrapper/setup record remains preserved.

## Cleanup, artifact hashes and remaining gates

All runtime identities/documents and keys were synthetic. The final command's captured known descendants, own session and direct-child checks were empty; its temp-name count was 109 before and after. One descendant snapshot at +3 seconds does not individually observe later detached drivers; the frozen runner reaping contract and awaited server/control shutdown provide the additional cleanup evidence. No global-process cleanliness claim is made.

| Final-run artifact | SHA-256 |
|---|---|
| `result.json` | `a4647e9981f548bc6bb864388acced0538fafb841c0f494be1c6a89761f305e9` |
| `evidence.json` | `18f5df238e10649b9718f551da3e333579abb7afeb860d23ef8dfa0a3f061e20` |
| `flows.json` | `229ee2372dfaa3f40e1f868947f71aee3ae93e4272d94246c075b4a4a6485850` |
| `anchor-control.json` | `3d47c8b6172aa79b7862543d9202be9a2d7a65f10781cd0df6e8ee781288c498` |
| `browser-captures.json` | `849a2bf03d25776e94d44f2f3b4e377af97e9427ca8b8dedcc282d80281c8297` |

Raw failures, diagnostic observations, ledger, wrappers and manifests remain in the orchestration scratch receipt; no secrets, links, request bodies, credentials or host paths are committed here. The exact postcommit SHA, full independent acceptance, fresh bounded recheck (including the reserved M-R3) and published-head independent Phase 4 checkpoint remain the orchestrator's gates. External PDF-reader acceptance and declared-hardware SC-005 remain OPEN. No merge, deployment or real signature was performed.
