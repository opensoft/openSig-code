// SPDX-License-Identifier: Apache-2.0
//
// openSig verification mode registry.
//
// Source: spec leg specs/001-corporate-signing-mvp/plan.md, section
// "Verification runner contract" > "Mode registry" (43 modes).
//
// FROZEN at the T001 hardening commit (amendment A-006) together with
// scripts/verify.mjs and tests/tooling/verification-runner.test.mjs. Only a
// recorded architect amendment can add or change a mode, through a new [O] task
// that lists these three files, re-runs the self-tests and re-freezes at that
// task's commit.
//
// Every mode is pre-registered. Before a mode's own task lands, its globs match
// nothing and the runner returns VACUOUS (exit 4), never PASS.
//
// Field meanings (all fields are required on every mode):
//   task          owning task id, or "(npm test)" / "(release gate)"
//   kind          tooling | unit | harness | contract | acceptance | aggregate | release
//   files         explicit globs the runner expands itself (never passed to node --test)
//   minTests      minimum number of executed tests
//   requiredCases case ids that must appear as the leading "[ID]" of a passing test
//   capabilities  probe names; absent capability -> CAPABILITY_ABSENT (exit 3), no test runs
//   evidence      files the run must write under .verify-out/<mode>/ (labels are
//                 top-level string properties; tree_digest must equal the run's
//                 tree digest). Aggregates use { receipt: true } for the receipt the
//                 runner writes and { committed: true } for a committed file.
//   typecheck     run `npm run typecheck` first (aggregates: once for the whole run)
//   contract      require contracts/http-api.json plus contracts/http-api.source.json
//                 with a matching sha256
//   components    member modes of an aggregate or release mode, in run order

/** Expand a case-id range: caseRange('NS', 1, 3) -> ['NS-01', 'NS-02', 'NS-03']. */
export function caseRange(prefix, from, to) {
  const ids = [];
  for (let i = from; i <= to; i += 1) ids.push(`${prefix}-${String(i).padStart(2, '0')}`);
  return ids;
}

// Pinned Hermes image (plan.md, hermes-runtime capability). Evidence label
// hermes_upstream must name this digest.
const HERMES_IMAGE_DIGEST = 'sha256:adb7890916de63245523492be8f68f9d2095fecbec4e2a6dab7960381f0fc002';
const HERMES_UPSTREAM = { pattern: `${HERMES_IMAGE_DIGEST}$` };

function mode(fields) {
  return Object.freeze({
    task: fields.task,
    kind: fields.kind,
    files: Object.freeze(fields.files ?? []),
    minTests: fields.minTests ?? 0,
    requiredCases: Object.freeze(fields.requiredCases ?? []),
    capabilities: Object.freeze(fields.capabilities ?? []),
    evidence: Object.freeze((fields.evidence ?? []).map((e) => Object.freeze({ ...e }))),
    typecheck: fields.typecheck ?? true,
    contract: fields.contract ?? false,
    components: Object.freeze(fields.components ?? []),
  });
}

const unit = (task, dir, minTests, requiredCases, extra = {}) =>
  mode({ task, kind: 'unit', files: [`tests/${dir}/**/*.test.mjs`], minTests, requiredCases, ...extra });

const LEAF_MODES = {
  tooling: mode({
    task: 'T001',
    kind: 'tooling',
    files: ['tests/tooling/verification-runner.test.mjs'],
    minTests: 26,
  }),
  'no-secrets': unit('T026', 'no-secrets', 8, caseRange('NS', 1, 7)),
  'license-inventory': unit('T002', 'license-inventory', 14, caseRange('LI', 1, 10)),
  qualification: unit('T027', 'qualification', 6, caseRange('QL', 1, 5), {
    evidence: [{ path: '.verify-out/qualification/inventory.json', labels: { tree_digest: true } }],
  }),
  storage: unit('T003', 'storage', 12, []),
  blobs: unit('T028', 'blobs', 8, caseRange('BL', 1, 4)),
  'audit-chain': unit('T029', 'audit-chain', 8, caseRange('AC', 1, 5)),
  'outbox-restore': unit('T030', 'outbox-restore', 8, caseRange('OR', 1, 4)),
  dev: unit('T004', 'dev', 5, caseRange('DV', 1, 3)),
  auth: unit('T005', 'auth', 14, caseRange('AU', 1, 10)),
  server: unit('T031', 'server', 12, caseRange('SEC', 1, 6)),
  notifications: unit('T032', 'notifications', 8, caseRange('NT', 1, 5)),
  'parser-limits': unit('T033', 'pdf-parse', 16, caseRange('PL', 1, 12)),
  'envelope-contract': mode({
    task: 'T006',
    kind: 'harness',
    files: ['tests/contract/envelopes/**/*.test.mjs'],
    minTests: 12,
    contract: true,
  }),
  envelopes: unit('T007', 'domain/envelopes', 16, caseRange('ST', 1, 8)),
  'envelope-api': unit('T034', 'api/envelopes', 16, ['SC002-07', 'SC002-08', 'SC002-23', 'SC002-24', 'SC002-26'], {
    contract: true,
  }),
  recipients: unit('T008', 'recipients', 18, [...caseRange('SC002', 10, 16), 'SC002-25', ...caseRange('CH', 1, 3)], {
    contract: true,
  }),
  approval: unit('T010', 'approval', 16, [...caseRange('SC002', 1, 6), 'SC002-17', 'SC002-18'], { contract: true }),
  'ui-build': unit('T035', 'ui-build', 6, caseRange('UB', 1, 4)),
  autograph: unit('T009', 'browser/autograph', 10, caseRange('AG', 1, 6), { capabilities: ['chromium'] }),
  us1: mode({
    task: 'T011',
    kind: 'acceptance',
    files: ['tests/acceptance/us1/**/*.test.mjs'],
    minTests: 6,
    requiredCases: [...caseRange('SC004', 1, 4), 'US1-01', 'US1-02'],
    capabilities: ['chromium'],
    evidence: [
      {
        path: '.verify-out/us1/evidence.json',
        labels: { browser_engine: true, browser_version: true, tree_digest: true },
      },
    ],
  }),
  'integrity-contract': mode({
    task: 'T012',
    kind: 'harness',
    files: ['tests/integrity/oracle/**/*.test.mjs'],
    minTests: 12,
    requiredCases: caseRange('OC', 1, 8),
    capabilities: ['openssl'],
  }),
  cms: unit('T013', 'cms', 10, ['KEY-01', 'KEY-02'], { capabilities: ['openssl'] }),
  compose: unit('T036', 'compose', 10, caseRange('CP', 1, 6)),
  cryptograph: unit('T037', 'cryptograph', 8, caseRange('WK', 1, 4)),
  verification: unit('T014', 'integrity/product', 14, [...caseRange('SC002', 19, 22), 'VB-01'], {
    capabilities: ['openssl'],
  }),
  completion: unit('T038', 'completion', 8, caseRange('FEN', 1, 3)),
  recovery: unit('T015', 'recovery', 20, caseRange('SC003', 1, 20)),
  zip: unit('T039', 'zip', 6, []),
  artifacts: unit('T016', 'artifacts', 10, ['SC002-09', ...caseRange('PK', 1, 4)], { contract: true }),
  'us2-local': mode({
    task: 'T017',
    kind: 'acceptance',
    files: ['tests/acceptance/us2/**/*.test.mjs'],
    minTests: 12,
    requiredCases: [...caseRange('SC001', 1, 10), 'SC005-01', 'SC005-02'],
    capabilities: ['openssl', 'chromium'],
    evidence: [
      {
        path: '.verify-out/us2-local/evidence.json',
        labels: {
          verifier_name: true,
          verifier_version: true,
          oracle_name: true,
          oracle_version: true,
          timing_scope: 'indicative-local',
          tree_digest: true,
        },
      },
    ],
  }),
  'hermes-contract': mode({
    task: 'T018',
    kind: 'contract',
    files: ['tests/integrations/hermes/**/*.test.mjs'],
    minTests: 10,
    requiredCases: caseRange('HM', 1, 6),
    contract: true,
  }),
  webhooks: unit('T019', 'webhooks', 14, caseRange('WH', 1, 8), { contract: true }),
  'healthcare-contracts': mode({
    task: 'T020',
    kind: 'contract',
    files: ['tests/integrations/healthcare/**/*.test.mjs'],
    minTests: 8,
    requiredCases: caseRange('HC', 1, 4),
  }),
  'anchoring-disabled': unit('T021', 'anchoring', 6, caseRange('AN', 1, 3)),
  'hermes-runtime': unit('T040', 'hermes-runtime', 4, caseRange('HR', 1, 3), { capabilities: ['hermes-runtime'] }),
  us3: mode({
    task: 'T022',
    kind: 'acceptance',
    files: ['tests/acceptance/us3/**/*.test.mjs'],
    minTests: 9,
    requiredCases: caseRange('SC006', 1, 9),
    capabilities: ['hermes-runtime', 'chromium'],
    evidence: [
      {
        path: '.verify-out/us3/evidence.json',
        labels: {
          hermes_runtime: 'isolated-local',
          hermes_upstream: HERMES_UPSTREAM,
          hermes_version: 'v0.23.0',
          network: 'none',
          provider: 'scripted-deterministic',
          tool_search: ['on', 'off'],
          production_hermes: 'not-exercised',
          notification: 'local-spool',
          tree_digest: true,
        },
      },
    ],
  }),
  // Supplementary, separately labeled real-model attempt (spec commit 1246f37).
  // It belongs to no aggregate; its CAPABILITY_ABSENT never blocks us3.
  'us3-real-model': mode({
    task: 'T041',
    kind: 'acceptance',
    files: ['tests/acceptance/us3-real-model/**/*.test.mjs'],
    minTests: 4,
    requiredCases: caseRange('RM', 1, 4),
    capabilities: ['hermes-runtime', 'claude-sdk-transport'],
    evidence: [
      {
        path: '.verify-out/us3-real-model/evidence.json',
        labels: {
          provider: 'claude-sdk-max001-local',
          credentials: 'host-only',
          hermes_upstream: HERMES_UPSTREAM,
          hermes_version: 'v0.23.0',
          production_hermes: 'not-exercised',
          tree_digest: true,
        },
        noCredentials: true,
      },
    ],
  }),
  'release-gates': unit('T023', 'release-gates', 10, caseRange('RG', 1, 6)),
  operations: unit('T024', 'operations', 6, caseRange('OP', 1, 3)),
};

const LEAF_NAMES = Object.keys(LEAF_MODES);

// all-unit (npm test): every unit, harness and contract mode without capabilities.
const ALL_UNIT_COMPONENTS = LEAF_NAMES.filter((name) => {
  const m = LEAF_MODES[name];
  return ['unit', 'harness', 'contract'].includes(m.kind) && m.capabilities.length === 0;
});

// acceptance-local: every leaf mode except tooling and us3-real-model, in the
// order of the task lines in tasks.md at spec e35b968 (amendment A-006 L7:
// recipients, T008, runs before envelope-api, T034, which depends on it).
const ACCEPTANCE_LOCAL_COMPONENTS = [
  'no-secrets',
  'license-inventory',
  'qualification',
  'storage',
  'blobs',
  'audit-chain',
  'outbox-restore',
  'dev',
  'auth',
  'server',
  'notifications',
  'parser-limits',
  'envelope-contract',
  'envelopes',
  'recipients',
  'envelope-api',
  'approval',
  'ui-build',
  'autograph',
  'us1',
  'integrity-contract',
  'cms',
  'compose',
  'cryptograph',
  'verification',
  'completion',
  'recovery',
  'zip',
  'artifacts',
  'us2-local',
  'hermes-contract',
  'webhooks',
  'healthcare-contracts',
  'anchoring-disabled',
  'hermes-runtime',
  'us3',
  'release-gates',
  'operations',
];

const ACCEPTANCE_LOCAL_REQUIRED = [
  ...caseRange('SC001', 1, 10),
  ...caseRange('SC002', 1, 26),
  ...caseRange('SC003', 1, 20),
  ...caseRange('SC004', 1, 4),
  ...caseRange('SC005', 1, 2),
  ...caseRange('SC006', 1, 9),
];

export const MODES = Object.freeze({
  ...LEAF_MODES,
  'all-unit': mode({
    task: '(npm test)',
    kind: 'aggregate',
    components: ALL_UNIT_COMPONENTS,
  }),
  'acceptance-local': mode({
    task: 'T025',
    kind: 'aggregate',
    components: ACCEPTANCE_LOCAL_COMPONENTS,
    requiredCases: ACCEPTANCE_LOCAL_REQUIRED,
    capabilities: ['openssl', 'chromium', 'hermes-runtime'],
    evidence: [
      { path: '.verify-out/acceptance-local/receipt.json', receipt: true },
      { path: 'docs/evidence/acceptance.json', committed: true, labels: { tree_digest: true } },
    ],
  }),
  acceptance: mode({
    task: '(release gate)',
    kind: 'release',
    components: ['acceptance-local'],
    capabilities: ['external-pdf-reader', 'declared-hardware', 'ci-run'],
    evidence: [{ path: '.verify-out/acceptance/receipt.json', receipt: true }],
  }),
});
