// SPDX-License-Identifier: Apache-2.0
//
// Self-tests of the frozen verification runner (plan.md "Self-tests", cases 1-26;
// case 27: preload flags in NODE_OPTIONS -> ENV_MISMATCH; cases 28-38: the
// amendment A-006 hardening items M1, M2, M3, L1, L3, L4 and L6; L7 is checked
// in case 20).
//
// FROZEN at the T001 hardening commit (A-006) together with scripts/verify.mjs
// and scripts/verify-modes.mjs.
//
// Fixture suites are generated in temp directories at run time. Engine behaviour
// is tested by importing runMode() with synthetic registries, so the CLI needs no
// override path; CLI argument handling is tested by spawning scripts/verify.mjs.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, test } from 'node:test';

import {
  CAPABILITY_NAMES,
  FROZEN_MODE_NAMES,
  FROZEN_NODE_VERSION,
  FROZEN_NPMRC,
  FROZEN_PACKAGE_SCRIPTS,
  FROZEN_TSCONFIG,
  MODE_KINDS,
  STATUS,
  computeTreeDigest,
  findClaimProblems,
  formatStatusLine,
  frozenConfigProblems,
  runMode,
  validateRegistry,
} from '../../scripts/verify.mjs';
import { MODES, caseRange } from '../../scripts/verify-modes.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const VERIFY_CLI = join(REPO_ROOT, 'scripts', 'verify.mjs');

// Count guard: every declared self-test must execute (case 22).
const EXPECTED_TESTS = 38;
let executed = 0;
after(() => {
  assert.equal(executed, EXPECTED_TESTS, `executed ${executed} self-tests but ${EXPECTED_TESTS} are declared`);
});

// The frozen mode list of plan.md "Mode registry" (43 modes), written out here
// independently of the runner and the registry.
const FROZEN_LIST = [
  'tooling',
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
  'envelope-api',
  'recipients',
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
  'us3-real-model',
  'release-gates',
  'operations',
  'all-unit',
  'acceptance-local',
  'acceptance',
];

const scratchDirs = [];
after(() => {
  for (const dir of scratchDirs) rmSync(dir, { recursive: true, force: true });
});

function scratch(label) {
  const dir = mkdtempSync(join(tmpdir(), `opensig-verify-${label}-`));
  scratchDirs.push(dir);
  return dir;
}

const EMPTY_LOCK = { name: 'fixture', lockfileVersion: 3, requires: true, packages: { '': { name: 'fixture' } } };

// Temp roots carry the A-006 frozen configuration so only the case under test differs.
const FROZEN_FILES = {
  'package.json': JSON.stringify({
    name: 'fixture',
    private: true,
    type: 'module',
    engines: { node: FROZEN_NODE_VERSION },
    scripts: { ...FROZEN_PACKAGE_SCRIPTS },
  }),
  '.npmrc': `${Object.entries(FROZEN_NPMRC)
    .map(([key, value]) => `${key}=${value}`)
    .join('\n')}\n`,
  'tsconfig.json': JSON.stringify(FROZEN_TSCONFIG, null, 2),
};

const GIT_COMMIT_ENV = (() => {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (key.startsWith('GIT_')) delete env[key];
  return {
    ...env,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_AUTHOR_NAME: 'Synthetic Author',
    GIT_AUTHOR_EMAIL: 'author@example.test',
    GIT_COMMITTER_NAME: 'Synthetic Committer',
    GIT_COMMITTER_EMAIL: 'committer@example.test',
  };
})();

function commitAll(root) {
  for (const args of [['add', '-A', '-f', '--', '.'], ['commit', '-q', '--no-gpg-sign', '-m', 'synthetic']]) {
    const run = spawnSync('git', args, { cwd: root, env: GIT_COMMIT_ENV, encoding: 'utf8' });
    assert.equal(run.status, 0, `git ${args[0]} failed: ${run.stderr}`);
  }
}

function writeTree(root, files) {
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(root, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
}

function makeRoot(files = {}, { nodeVersion = process.version.slice(1), lock = EMPTY_LOCK } = {}) {
  const root = scratch('root');
  writeTree(root, { ...FROZEN_FILES, '.node-version': `${nodeVersion}\n`, 'package-lock.json': JSON.stringify(lock), ...files });
  const init = spawnSync('git', ['init', '-q'], { cwd: root, encoding: 'utf8' });
  assert.equal(init.status, 0, `git init failed: ${init.stderr}`);
  return root;
}

function leaf(fields) {
  return {
    task: 'TX',
    kind: 'unit',
    files: [],
    minTests: 1,
    requiredCases: [],
    capabilities: [],
    evidence: [],
    typecheck: false,
    contract: false,
    components: [],
    ...fields,
  };
}

function aggregate(fields) {
  return leaf({ kind: 'aggregate', minTests: 0, ...fields });
}

const ENGINE_ENV = (() => {
  const env = { ...process.env };
  delete env.NODE_OPTIONS;
  delete env.NODE_TEST_CONTEXT;
  return env;
})();

function engine(root, registry, name, extra = {}) {
  return runMode(name, { root, registry, modeNames: Object.keys(registry), env: ENGINE_ENV, execArgv: [], ...extra });
}

function expectStatus(result, code, note) {
  assert.equal(result.exit, code, `${note}: expected exit ${code}, got ${result.exit} ${result.status}; reasons: ${result.reasons.join(' | ')}`);
}

function cli(args) {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  delete env.NODE_OPTIONS;
  const run = spawnSync(process.execPath, [VERIFY_CLI, ...args], { cwd: REPO_ROOT, env, encoding: 'utf8', timeout: 60_000 });
  const lines = run.stdout.split('\n').filter(Boolean);
  return { code: run.status, lines, last: lines.at(-1) ?? '', stderr: run.stderr };
}

function sleepMs(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function processGone(pid) {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    return error.code === 'ESRCH';
  }
}

const HEAD = "import { test } from 'node:test';\n";
const passing = (...ids) => HEAD + ids.map((id) => `test('[${id}] passes', () => {});\n`).join('');
const markerWriter = (marker, id = 'M-01') =>
  `${HEAD}import { writeFileSync } from 'node:fs';\ntest('[${id}] writes a marker', () => { writeFileSync(${JSON.stringify(marker)}, 'ran'); });\n`;
const evidenceWriter = (labels, { id = 'E-01', digest = null, when = null } = {}) =>
  `${HEAD}import { existsSync, mkdirSync, writeFileSync } from 'node:fs';\n` +
  `test('[${id}] writes evidence', () => {\n` +
  (when ? `  if (!existsSync(${JSON.stringify(when)})) return;\n` : '') +
  '  const out = process.env.OPENSIG_VERIFY_OUT;\n' +
  '  mkdirSync(out, { recursive: true });\n' +
  `  const labels = ${JSON.stringify(labels)};\n` +
  `  labels.tree_digest = ${digest === null ? 'process.env.OPENSIG_VERIFY_TREE_DIGEST' : JSON.stringify(digest)};\n` +
  "  writeFileSync(out + '/evidence.json', JSON.stringify(labels));\n" +
  '});\n';

// ---------------------------------------------------------------------------

test('[RT-01] no mode -> USAGE (2)', () => {
  executed += 1;
  const run = cli([]);
  assert.equal(run.code, 2);
  assert.equal(run.lines.length, 1, 'exactly one stdout line');
  assert.equal(run.last, 'verify: - USAGE exit=2 files=0 tests=0 pass=0 fail=0 skip=0 todo=0 cases=0/0');
});

test('[RT-02] unknown mode -> USAGE (2)', async () => {
  executed += 1;
  const run = cli(['__no_such_mode__']);
  assert.equal(run.code, 2);
  assert.equal(run.last, 'verify: __no_such_mode__ USAGE exit=2 files=0 tests=0 pass=0 fail=0 skip=0 todo=0 cases=0/0');
  assert.equal(cli(['us2']).code, 2, 'a name that is not in the frozen list is unknown');
  assert.equal(cli(['tooling', 'storage']).code, 2, 'more than one mode is a usage error');
  const root = makeRoot();
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  expectStatus(await engine(root, registry, 'nope'), STATUS.USAGE, 'engine, unknown mode');
});

test('[RT-03] --allow-skip and any other flag -> USAGE (2)', () => {
  executed += 1;
  for (const args of [['--allow-skip'], ['tooling', '--allow-skip'], ['--allow-skip=1', 'tooling'], ['-h'], ['--', 'tooling']]) {
    const run = cli(args);
    assert.equal(run.code, 2, `args ${args.join(' ')}`);
    assert.match(run.last, / USAGE exit=2 files=0 tests=0 /, `args ${args.join(' ')} must not start any mode`);
  }
});

test('[RT-04] zero files -> VACUOUS (4)', async () => {
  executed += 1;
  const root = makeRoot();
  const result = await engine(root, { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) }, 'm');
  expectStatus(result, STATUS.VACUOUS, 'no file matches');
  assert.equal(result.files, 0);
  assert.equal(result.tests, 0);
});

test('[RT-05] empty file -> VACUOUS (4)', async () => {
  executed += 1;
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  const alone = await engine(makeRoot({ 'tests/m/empty.test.mjs': '' }), registry, 'm');
  expectStatus(alone, STATUS.VACUOUS, 'empty file alone');
  assert.equal(alone.tests, 0, 'the file-level entry of an empty file is not a test');
  const mixed = await engine(makeRoot({ 'tests/m/a.test.mjs': passing('A-01'), 'tests/m/empty.test.mjs': '' }), registry, 'm');
  expectStatus(mixed, STATUS.VACUOUS, 'empty file next to a passing file');
  assert.equal(mixed.pass, 1);
  assert.ok(mixed.reasons.some((reason) => reason.includes('tests/m/empty.test.mjs')), 'the silent file is named');
});

test('[RT-06] skip option -> VACUOUS (4)', async () => {
  executed += 1;
  const source = `${passing('A-01')}test('skipped', { skip: true }, () => {});\n`;
  const result = await engine(makeRoot({ 'tests/m/a.test.mjs': source }), { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) }, 'm');
  expectStatus(result, STATUS.VACUOUS, 'skip option');
  assert.equal(result.skip, 1);
});

test('[RT-07] runtime t.skip() -> VACUOUS (4)', async () => {
  executed += 1;
  const source = `${passing('A-01')}test('skips at runtime', (t) => { t.skip('not today'); });\n`;
  const result = await engine(makeRoot({ 'tests/m/a.test.mjs': source }), { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) }, 'm');
  expectStatus(result, STATUS.VACUOUS, 'runtime skip');
  assert.equal(result.skip, 1);
});

test('[RT-08] passing todo and failing todo -> VACUOUS (4)', async () => {
  executed += 1;
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  const passingTodo = await engine(
    makeRoot({ 'tests/m/a.test.mjs': `${passing('A-01')}test('later', { todo: true }, () => {});\n` }),
    registry,
    'm',
  );
  expectStatus(passingTodo, STATUS.VACUOUS, 'passing todo');
  assert.equal(passingTodo.todo, 1);
  const failingTodo = await engine(
    makeRoot({ 'tests/m/a.test.mjs': `${passing('A-01')}test('later', { todo: true }, () => { throw new Error('not yet'); });\n` }),
    registry,
    'm',
  );
  expectStatus(failingTodo, STATUS.VACUOUS, 'failing todo');
  assert.equal(failingTodo.todo, 1);
  assert.equal(failingTodo.fail, 0);
});

test('[RT-09] only -> VACUOUS (4)', async () => {
  executed += 1;
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  const dotOnly = await engine(makeRoot({ 'tests/m/a.test.mjs': `${HEAD}test.only('[A-01] only', () => {});\ntest('[A-02] other', () => {});\n` }), registry, 'm');
  expectStatus(dotOnly, STATUS.VACUOUS, 'test.only');
  assert.ok(dotOnly.only >= 1);
  const optionOnly = await engine(makeRoot({ 'tests/m/a.test.mjs': `${HEAD}test('[A-01] only', { only: true }, () => {});\n` }), registry, 'm');
  expectStatus(optionOnly, STATUS.VACUOUS, 'only option');
  assert.ok(optionOnly.only >= 1);
});

test('[RT-10] failing test -> FAIL (1)', async () => {
  executed += 1;
  const source = `${passing('A-01')}test('[A-02] fails', () => { throw new Error('deliberate'); });\n`;
  const result = await engine(makeRoot({ 'tests/m/a.test.mjs': source }), { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) }, 'm');
  expectStatus(result, STATUS.FAIL, 'failing test');
  assert.equal(result.fail, 1);
});

test('[RT-11] syntax or import error -> FAIL (1)', async () => {
  executed += 1;
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  const syntax = await engine(makeRoot({ 'tests/m/a.test.mjs': `${HEAD}test('[A-01] broken', () => {\n` }), registry, 'm');
  expectStatus(syntax, STATUS.FAIL, 'syntax error');
  const missingImport = await engine(makeRoot({ 'tests/m/a.test.mjs': "import './does-not-exist.mjs';\n" }), registry, 'm');
  expectStatus(missingImport, STATUS.FAIL, 'import error');
});

test('[RT-12] timeout -> FAIL (1) and the process group is killed', async () => {
  executed += 1;
  const pidFile = join(scratch('pid'), 'pid');
  const source =
    `${HEAD}import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(pidFile)}, String(process.pid));\n` +
    "test('[A-01] never settles', () => new Promise(() => { setInterval(() => {}, 1000); }));\n";
  const started = Date.now();
  const result = await engine(makeRoot({ 'tests/m/a.test.mjs': source }), { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) }, 'm', {
    fileTimeoutMs: 2000,
  });
  expectStatus(result, STATUS.FAIL, 'per-file timeout');
  assert.ok(Date.now() - started < 60_000, 'the timeout is enforced');
  assert.ok(result.per_file[0].timed_out, 'the file is marked timed out');
  const pid = Number(readFileSync(pidFile, 'utf8'));
  for (let i = 0; i < 50 && !processGone(pid); i += 1) sleepMs(100);
  assert.ok(processGone(pid), `test process ${pid} was killed with its group`);
});

test('[RT-13] below minTests -> VACUOUS (4)', async () => {
  executed += 1;
  const result = await engine(
    makeRoot({ 'tests/m/a.test.mjs': passing('A-01', 'A-02') }),
    { m: leaf({ files: ['tests/m/**/*.test.mjs'], minTests: 3 }) },
    'm',
  );
  expectStatus(result, STATUS.VACUOUS, 'two tests, minTests 3');
  assert.equal(result.pass, 2);
});

test('[RT-14] missing required case -> VACUOUS (4)', async () => {
  executed += 1;
  const result = await engine(
    makeRoot({ 'tests/m/a.test.mjs': passing('A-01', 'A-03') }),
    { m: leaf({ files: ['tests/m/**/*.test.mjs'], requiredCases: ['A-01', 'A-02'] }) },
    'm',
  );
  expectStatus(result, STATUS.VACUOUS, 'A-02 missing');
  assert.deepEqual(result.cases.missing, ['A-02']);
  assert.match(formatStatusLine(result), / cases=1\/2$/);
});

test('[RT-15] absent capability -> CAPABILITY_ABSENT (3) with zero tests executed', async () => {
  executed += 1;
  const markerDir = scratch('marker');
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'], capabilities: ['hermes-runtime'], requiredCases: ['M-01'] }) };

  const absentMarker = join(markerDir, 'absent');
  const absent = await engine(makeRoot({ 'tests/m/a.test.mjs': markerWriter(absentMarker) }), registry, 'm');
  expectStatus(absent, STATUS.CAPABILITY_ABSENT, 'probe file absent');
  assert.equal(absent.tests, 0);
  assert.equal(existsSync(absentMarker), false, 'no test ran');

  const failingMarker = join(markerDir, 'failing');
  const failing = await engine(
    makeRoot({ 'tests/m/a.test.mjs': markerWriter(failingMarker), 'scripts/capabilities/hermes-runtime.mjs': 'process.exit(1);\n' }),
    registry,
    'm',
  );
  expectStatus(failing, STATUS.CAPABILITY_ABSENT, 'probe exits 1');
  assert.equal(existsSync(failingMarker), false, 'no test ran');

  const presentMarker = join(markerDir, 'present');
  const present = await engine(
    makeRoot({ 'tests/m/a.test.mjs': markerWriter(presentMarker), 'scripts/capabilities/hermes-runtime.mjs': 'process.exit(0);\n' }),
    registry,
    'm',
  );
  expectStatus(present, STATUS.PASS, 'probe exits 0');
  assert.equal(existsSync(presentMarker), true, 'tests run once the capability is present');
});

test('[RT-16] missing evidence -> EVIDENCE_MISSING (5), and stale tree digest -> 5', async () => {
  executed += 1;
  const registry = {
    m: leaf({
      files: ['tests/m/**/*.test.mjs'],
      evidence: [{ path: '.verify-out/m/evidence.json', labels: { scope: 'synthetic', tree_digest: true } }],
    }),
  };
  const none = await engine(makeRoot({ 'tests/m/a.test.mjs': passing('E-01') }), registry, 'm');
  expectStatus(none, STATUS.EVIDENCE_MISSING, 'evidence never written');

  const stale = await engine(makeRoot({ 'tests/m/a.test.mjs': evidenceWriter({ scope: 'synthetic' }, { digest: 'f'.repeat(64) }) }), registry, 'm');
  expectStatus(stale, STATUS.EVIDENCE_MISSING, 'stale tree digest');

  const unlabeled = await engine(makeRoot({ 'tests/m/a.test.mjs': evidenceWriter({ other: 'x' }) }), registry, 'm');
  expectStatus(unlabeled, STATUS.EVIDENCE_MISSING, 'required label missing');

  // Evidence left by an earlier run never satisfies a later run.
  const flag = join(scratch('flag'), 'write-evidence');
  writeFileSync(flag, 'yes');
  const root = makeRoot({ 'tests/m/a.test.mjs': evidenceWriter({ scope: 'synthetic' }, { when: flag }) });
  expectStatus(await engine(root, registry, 'm'), STATUS.PASS, 'run that writes evidence');
  rmSync(flag);
  expectStatus(await engine(root, registry, 'm'), STATUS.EVIDENCE_MISSING, 'later run that writes nothing');
});

test('[RT-17] runtime mismatch -> ENV_MISMATCH (6)', async () => {
  executed += 1;
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  const runtime = await engine(makeRoot({ 'tests/m/a.test.mjs': passing('A-01') }, { nodeVersion: '0.0.1' }), registry, 'm');
  expectStatus(runtime, STATUS.ENV_MISMATCH, '.node-version differs from the running node');
  assert.equal(runtime.tests, 0);
  const lock = {
    ...EMPTY_LOCK,
    packages: {
      '': { name: 'fixture' },
      'node_modules/left-pad': { version: '1.3.0', resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz', integrity: 'sha512-AAAA' },
    },
  };
  const tree = await engine(makeRoot({ 'tests/m/a.test.mjs': passing('A-01') }, { lock }), registry, 'm');
  expectStatus(tree, STATUS.ENV_MISMATCH, 'installed tree differs from the lockfile');
});

test('[RT-18] a harness component cannot satisfy a success-criterion gate', async () => {
  executed += 1;
  const root = makeRoot({
    'tests/h/a.test.mjs': passing('SC9-01'),
    'tests/c/a.test.mjs': passing('SC9-01'),
    'tests/u/a.test.mjs': passing('SC9-01'),
  });
  const registry = {
    h: leaf({ kind: 'harness', files: ['tests/h/**/*.test.mjs'] }),
    c: leaf({ kind: 'contract', files: ['tests/c/**/*.test.mjs'] }),
    u: leaf({ kind: 'unit', files: ['tests/u/**/*.test.mjs'] }),
    'agg-h': aggregate({ components: ['h'], requiredCases: ['SC9-01'] }),
    'agg-c': aggregate({ components: ['c'], requiredCases: ['SC9-01'] }),
    'agg-u': aggregate({ components: ['u'], requiredCases: ['SC9-01'] }),
  };
  const harness = await engine(root, registry, 'agg-h');
  expectStatus(harness, STATUS.VACUOUS, 'harness-only coverage');
  assert.deepEqual(harness.cases.missing, ['SC9-01']);
  expectStatus(await engine(root, registry, 'agg-c'), STATUS.VACUOUS, 'contract-only coverage');
  expectStatus(await engine(root, registry, 'agg-u'), STATUS.PASS, 'unit coverage counts');
});

test('[RT-19] positive control -> PASS (0) with counts recorded', async () => {
  executed += 1;
  const root = makeRoot({
    'tests/m/a.test.mjs': passing('P-01', 'P-02'),
    'tests/m/b.test.mjs':
      "import { describe, it } from 'node:test';\nimport { mkdirSync, writeFileSync } from 'node:fs';\n" +
      "describe('suite', () => {\n  it('[P-03] writes evidence', () => {\n" +
      '    mkdirSync(process.env.OPENSIG_VERIFY_OUT, { recursive: true });\n' +
      "    writeFileSync(process.env.OPENSIG_VERIFY_OUT + '/evidence.json', JSON.stringify({ scope: 'synthetic', tree_digest: process.env.OPENSIG_VERIFY_TREE_DIGEST }));\n" +
      '  });\n});\n',
  });
  const registry = {
    m: leaf({
      files: ['tests/m/**/*.test.mjs'],
      minTests: 3,
      requiredCases: ['P-01', 'P-02', 'P-03'],
      evidence: [{ path: '.verify-out/m/evidence.json', labels: { scope: 'synthetic', tree_digest: true } }],
    }),
  };
  const result = await engine(root, registry, 'm');
  expectStatus(result, STATUS.PASS, 'positive control');
  assert.equal(formatStatusLine(result), 'verify: m PASS exit=0 files=2 tests=3 pass=3 fail=0 skip=0 todo=0 cases=3/3');
  assert.equal(result.tree_digest, computeTreeDigest(root));
  const recorded = JSON.parse(readFileSync(join(root, '.verify-out', 'm', 'result.json'), 'utf8'));
  for (const key of ['status', 'exit', 'files', 'tests', 'pass', 'fail', 'skip', 'todo', 'tree_digest']) {
    assert.equal(recorded[key], result[key], `result.json ${key}`);
  }
  assert.deepEqual(recorded.cases, { found: 3, required: 3, missing: [] });
});

test('[RT-20] registry names equal the frozen list and every test file is claimed exactly once', async () => {
  executed += 1;
  assert.equal(FROZEN_LIST.length, 43);
  assert.deepEqual(Object.keys(MODES), FROZEN_LIST);
  assert.deepEqual([...FROZEN_MODE_NAMES], FROZEN_LIST);
  assert.deepEqual(validateRegistry(MODES, FROZEN_MODE_NAMES), []);
  assert.deepEqual(findClaimProblems(REPO_ROOT, MODES), []);

  const leafNames = FROZEN_LIST.filter((name) => !['aggregate', 'release'].includes(MODES[name].kind));
  assert.equal(leafNames.length, 40);
  for (const name of FROZEN_LIST) {
    const def = MODES[name];
    assert.ok(MODE_KINDS.includes(def.kind), `${name} kind`);
    for (const capability of def.capabilities) assert.ok(CAPABILITY_NAMES.includes(capability), `${name} capability ${capability}`);
    if (leafNames.includes(name)) assert.equal(def.typecheck, true, `${name} typechecks`);
  }
  const expectedAllUnit = leafNames.filter(
    (name) => ['unit', 'harness', 'contract'].includes(MODES[name].kind) && MODES[name].capabilities.length === 0,
  );
  assert.deepEqual([...MODES['all-unit'].components], expectedAllUnit);
  // A-006 L7: acceptance-local runs in the order of the task lines in tasks.md (spec e35b968).
  const taskOrder = [
    'no-secrets', 'license-inventory', 'qualification', 'storage', 'blobs', 'audit-chain', 'outbox-restore', 'dev', 'auth',
    'server', 'notifications', 'parser-limits', 'envelope-contract', 'envelopes', 'recipients', 'envelope-api', 'approval',
    'ui-build', 'autograph', 'us1', 'integrity-contract', 'cms', 'compose', 'cryptograph', 'verification', 'completion',
    'recovery', 'zip', 'artifacts', 'us2-local', 'hermes-contract', 'webhooks', 'healthcare-contracts', 'anchoring-disabled',
    'hermes-runtime', 'us3', 'release-gates', 'operations',
  ];
  assert.deepEqual([...MODES['acceptance-local'].components], taskOrder);
  assert.deepEqual(
    [...taskOrder].sort(),
    leafNames.filter((name) => name !== 'tooling' && name !== 'us3-real-model').sort(),
    'acceptance-local holds every leaf mode except tooling and us3-real-model',
  );
  for (const name of ['all-unit', 'acceptance-local']) {
    assert.ok(!MODES[name].components.includes('us3-real-model'), `${name} excludes us3-real-model`);
    assert.ok(!MODES[name].components.includes('tooling'), `${name} excludes tooling`);
  }
  assert.equal(MODES['acceptance-local'].requiredCases.length, 71);
  assert.deepEqual([...MODES.acceptance.components], ['acceptance-local']);
  assert.equal(MODES.tooling.minTests, 26);
  assert.deepEqual([...MODES['us3-real-model'].requiredCases], caseRange('RM', 1, 4));
  assert.deepEqual([...MODES['us3-real-model'].capabilities], ['hermes-runtime', 'claude-sdk-transport']);
  assert.deepEqual([...MODES.recovery.requiredCases], caseRange('SC003', 1, 20));

  const unclaimed = makeRoot({ 'tests/a/x.test.mjs': passing('A-01') });
  expectStatus(await engine(unclaimed, { m: leaf({ files: ['tests/b/**/*.test.mjs'] }) }, 'm'), STATUS.RUNNER_ERROR, 'unclaimed test file');
  const doubled = makeRoot({ 'tests/a/x.test.mjs': passing('A-01') });
  const doubleRegistry = { m: leaf({ files: ['tests/a/**/*.test.mjs'] }), n: leaf({ files: ['tests/**/*.test.mjs'] }) };
  expectStatus(await engine(doubled, doubleRegistry, 'm'), STATUS.RUNNER_ERROR, 'test file claimed twice');
  const renamed = makeRoot({ 'tests/a/x.test.mjs': passing('A-01') });
  expectStatus(
    await engine(renamed, { m: leaf({ files: ['tests/a/**/*.test.mjs'] }) }, 'm', { modeNames: ['m', 'extra'] }),
    STATUS.RUNNER_ERROR,
    'registry names differ from the frozen list',
  );
});

test('[RT-21] test-filter flags in NODE_OPTIONS -> ENV_MISMATCH (6)', async () => {
  executed += 1;
  const root = makeRoot({ 'tests/m/a.test.mjs': passing('A-01') });
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  expectStatus(await engine(root, registry, 'm'), STATUS.PASS, 'control without flags');
  for (const flag of ['--test-name-pattern=A', '--test-only', '--test-skip-pattern=B', '--test-shard=1/2']) {
    expectStatus(await engine(root, registry, 'm', { env: { ...ENGINE_ENV, NODE_OPTIONS: flag } }), STATUS.ENV_MISMATCH, `NODE_OPTIONS ${flag}`);
  }
  expectStatus(await engine(root, registry, 'm', { execArgv: ['--test-name-pattern=A'] }), STATUS.ENV_MISMATCH, 'runner argv filter');
});

test('[RT-22] the after() count guard fails a file whose executed count differs', async () => {
  executed += 1;
  const guarded = (declared) =>
    "import { test, after } from 'node:test';\nimport assert from 'node:assert/strict';\nlet n = 0;\n" +
    `after(() => { assert.equal(n, ${declared}); });\n` +
    "test('[G-01] one', () => { n += 1; });\ntest('[G-02] two', () => { n += 1; });\n";
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'], minTests: 2 }) };
  expectStatus(await engine(makeRoot({ 'tests/m/a.test.mjs': guarded(3) }), registry, 'm'), STATUS.FAIL, 'guard declares 3, 2 ran');
  expectStatus(await engine(makeRoot({ 'tests/m/a.test.mjs': guarded(2) }), registry, 'm'), STATUS.PASS, 'guard declares 2, 2 ran');
});

test('[RT-23] mock-identity label in acceptance evidence -> FAIL (1)', async () => {
  executed += 1;
  const evidence = [{ path: '.verify-out/m/evidence.json', labels: { verifier_name: true, tree_digest: true } }];
  const acceptance = { m: leaf({ kind: 'acceptance', files: ['tests/m/**/*.test.mjs'], evidence }) };
  const unit = { m: leaf({ kind: 'unit', files: ['tests/m/**/*.test.mjs'], evidence }) };
  const fake = { 'tests/m/a.test.mjs': evidenceWriter({ verifier_name: 'fake-verifier' }) };
  expectStatus(await engine(makeRoot(fake), acceptance, 'm'), STATUS.FAIL, 'fake-verifier in acceptance evidence');
  expectStatus(
    await engine(makeRoot({ 'tests/m/a.test.mjs': evidenceWriter({ verifier_name: 'jsdom 26' }) }), acceptance, 'm'),
    STATUS.FAIL,
    'jsdom in acceptance evidence',
  );
  expectStatus(
    await engine(makeRoot({ 'tests/m/a.test.mjs': evidenceWriter({ verifier_name: 'openssl-cms 3.0' }) }), acceptance, 'm'),
    STATUS.PASS,
    'a real verifier name passes',
  );
  expectStatus(await engine(makeRoot(fake), unit, 'm'), STATUS.PASS, 'the mock rule applies to acceptance modes');
});

test('[RT-24] vendored contract digest mismatch -> ENV_MISMATCH (6)', async () => {
  executed += 1;
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'], contract: true }) };
  const contract = '{"openapi":"3.1.0","info":{"title":"synthetic","version":"0"}}\n';
  const source = (sha256) => JSON.stringify({ repo: 'opensoft/openSig-spec', commit: '0'.repeat(40), path: 'contracts/http-api.yaml', sha256 });
  const goodDigest = createHash('sha256').update(contract).digest('hex');
  expectStatus(await engine(makeRoot({ 'tests/m/a.test.mjs': passing('A-01') }), registry, 'm'), STATUS.ENV_MISMATCH, 'contract missing');
  expectStatus(
    await engine(
      makeRoot({ 'tests/m/a.test.mjs': passing('A-01'), 'contracts/http-api.json': contract, 'contracts/http-api.source.json': source('a'.repeat(64)) }),
      registry,
      'm',
    ),
    STATUS.ENV_MISMATCH,
    'digest mismatch',
  );
  expectStatus(
    await engine(
      makeRoot({ 'tests/m/a.test.mjs': passing('A-01'), 'contracts/http-api.json': contract, 'contracts/http-api.source.json': source(goodDigest) }),
      registry,
      'm',
    ),
    STATUS.PASS,
    'matching digest',
  );
});

test('[RT-25] an aggregate stops at the first non-PASS component and reports it', async () => {
  executed += 1;
  const marker = join(scratch('agg'), 'third-ran');
  const root = makeRoot({
    'tests/p1/a.test.mjs': passing('A-01'),
    'tests/f/a.test.mjs': `${HEAD}test('[F-01] fails', () => { throw new Error('deliberate'); });\n`,
    'tests/p2/a.test.mjs': markerWriter(marker),
  });
  const registry = {
    p1: leaf({ files: ['tests/p1/**/*.test.mjs'] }),
    v: leaf({ files: ['tests/v/**/*.test.mjs'] }),
    f: leaf({ files: ['tests/f/**/*.test.mjs'] }),
    p2: leaf({ files: ['tests/p2/**/*.test.mjs'] }),
    'agg-v': aggregate({ components: ['p1', 'v', 'p2'] }),
    'agg-f': aggregate({ components: ['p1', 'f', 'p2'] }),
  };
  const vacuous = await engine(root, registry, 'agg-v');
  expectStatus(vacuous, STATUS.VACUOUS, 'second component is vacuous');
  assert.deepEqual(
    vacuous.components.map((c) => [c.mode, c.status]),
    [
      ['p1', 'PASS'],
      ['v', 'VACUOUS'],
    ],
  );
  assert.ok(vacuous.reasons[0].includes('component v returned VACUOUS'));
  const failing = await engine(root, registry, 'agg-f');
  expectStatus(failing, STATUS.FAIL, 'second component fails');
  assert.equal(failing.components.length, 2);
  assert.equal(existsSync(marker), false, 'the component after the first non-PASS never ran');
});

test('[RT-26] sentinel failure -> RUNNER_ERROR (7)', async () => {
  executed += 1;
  const root = makeRoot({ 'tests/m/a.test.mjs': passing('A-01') });
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  const brokenPass = `${HEAD}test('sentinel fails', () => { throw new Error('broken'); });\n`;
  expectStatus(await engine(root, registry, 'm', { sentinelSources: { pass: brokenPass } }), STATUS.RUNNER_ERROR, 'pass sentinel fails');
  expectStatus(await engine(root, registry, 'm', { sentinelSources: { pass: passing('S-01', 'S-02') } }), STATUS.RUNNER_ERROR, 'pass sentinel counts 2');
  expectStatus(await engine(root, registry, 'm', { sentinelSources: { skip: passing('S-01') } }), STATUS.RUNNER_ERROR, 'skip sentinel passes');
});

test('[RT-27] preload flags in NODE_OPTIONS -> ENV_MISMATCH (6)', async () => {
  executed += 1;
  const root = makeRoot({ 'tests/m/a.test.mjs': passing('A-01') });
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  for (const options of ['--import ./x.mjs', '--import=./x.mjs', '--require ./x.cjs', '-r ./x.cjs', '--loader ./x.mjs', '--experimental-loader=./x.mjs']) {
    expectStatus(await engine(root, registry, 'm', { env: { ...ENGINE_ENV, NODE_OPTIONS: options } }), STATUS.ENV_MISMATCH, `NODE_OPTIONS ${options}`);
  }
  expectStatus(await engine(root, registry, 'm', { env: { ...ENGINE_ENV, NODE_OPTIONS: '--max-old-space-size=256' } }), STATUS.PASS, 'benign NODE_OPTIONS');
});

// --- Amendment A-006 hardening cases -----------------------------------------

const ALL_GATES_OPEN =
  'open=platform-inventory(POLICY-PENDING),trusted-certificate-key-custody,validated-oidc-smtp,external-pdf-reader,declared-hardware,real-ci,production-hermes';

test('[RT-28] the release gate returns FAIL naming all 7 open gates (M3)', async () => {
  executed += 1;
  const marker = join(scratch('release'), 'component-ran');
  const capabilities = ['external-pdf-reader', 'declared-hardware', 'ci-run'];
  const registry = {
    u: leaf({ files: ['tests/u/**/*.test.mjs'] }),
    agg: aggregate({ components: ['u'] }),
    rel: leaf({
      kind: 'release',
      minTests: 0,
      components: ['agg'],
      capabilities,
      evidence: [{ path: '.verify-out/rel/receipt.json', receipt: true }],
    }),
  };
  for (const probesPresent of [false, true]) {
    const files = { 'tests/u/a.test.mjs': markerWriter(marker) };
    if (probesPresent) for (const name of capabilities) files[`scripts/capabilities/${name}.mjs`] = 'process.exit(0);\n';
    const root = makeRoot(files);
    const result = await engine(root, registry, 'rel');
    expectStatus(result, STATUS.FAIL, `release gate with capability probes ${probesPresent ? 'present' : 'absent'}`);
    assert.equal(formatStatusLine(result), `verify: rel FAIL exit=1 files=0 tests=0 pass=0 fail=0 skip=0 todo=0 cases=0/0 ${ALL_GATES_OPEN}`);
    assert.equal(result.gates.length, 7);
    const receipt = JSON.parse(readFileSync(join(root, '.verify-out', 'rel', 'receipt.json'), 'utf8'));
    assert.equal(receipt.release_ready, false);
    assert.equal(receipt.gates.length, 7);
    assert.ok(receipt.gates.every((gate) => gate.status === 'OPEN' || gate.status === 'POLICY-PENDING'));
    assert.equal(existsSync(marker), false, 'no component runs while a gate is open');
  }
});

test('[RT-29] an aggregate returns CAPABILITY_ABSENT at top level before any component runs (M3)', async () => {
  executed += 1;
  const marker = join(scratch('agg-capability'), 'component-ran');
  const registry = {
    u: leaf({ files: ['tests/u/**/*.test.mjs'] }),
    'acceptance-local': aggregate({ components: ['u'], capabilities: ['hermes-runtime'], requiredCases: ['M-01'] }),
  };
  const result = await engine(makeRoot({ 'tests/u/a.test.mjs': markerWriter(marker) }), registry, 'acceptance-local');
  expectStatus(result, STATUS.CAPABILITY_ABSENT, 'aggregate capability absent');
  assert.equal(result.tests, 0);
  assert.deepEqual(result.components, []);
  assert.equal(existsSync(marker), false, 'no component ran');
});

test('[RT-30] the aggregate receipt says release_ready false; committed evidence must match the tree (M3)', async () => {
  executed += 1;
  const registry = {
    u: leaf({ files: ['tests/u/**/*.test.mjs'] }),
    agg: aggregate({
      components: ['u'],
      requiredCases: ['SC9-01'],
      evidence: [
        { path: '.verify-out/agg/receipt.json', receipt: true },
        { path: 'docs/evidence/acceptance.json', committed: true, labels: { tree_digest: true } },
      ],
    }),
  };
  const root = makeRoot({ 'tests/u/a.test.mjs': passing('SC9-01') });
  commitAll(root);
  const digest = computeTreeDigest(root);

  expectStatus(await engine(root, registry, 'agg'), STATUS.EVIDENCE_MISSING, 'committed evidence absent');
  const receipt = JSON.parse(readFileSync(join(root, '.verify-out', 'agg', 'receipt.json'), 'utf8'));
  assert.equal(receipt.release_ready, false);
  assert.equal(receipt.tree_digest, digest);
  assert.deepEqual(receipt.covered_cases, ['SC9-01']);
  assert.equal(receipt.external_gates.length, 7);
  assert.ok(receipt.external_gates.every((gate) => gate.status === 'OPEN' || gate.status === 'POLICY-PENDING'));

  writeTree(root, { 'docs/evidence/acceptance.json': JSON.stringify({ tree_digest: digest }) });
  expectStatus(await engine(root, registry, 'agg'), STATUS.EVIDENCE_MISSING, 'evidence written but not committed');
  commitAll(root);
  expectStatus(await engine(root, registry, 'agg'), STATUS.PASS, 'committed evidence carries the tree digest');

  writeTree(root, { 'docs/evidence/acceptance.json': JSON.stringify({ tree_digest: 'e'.repeat(64) }) });
  expectStatus(await engine(root, registry, 'agg'), STATUS.EVIDENCE_MISSING, 'working copy differs from HEAD');
  commitAll(root);
  expectStatus(await engine(root, registry, 'agg'), STATUS.EVIDENCE_MISSING, 'committed tree digest mismatch');
});

test('[RT-31] a typecheck error returns FAIL (M3)', async () => {
  executed += 1;
  const lock = JSON.parse(readFileSync(join(REPO_ROOT, 'package-lock.json'), 'utf8'));
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'], typecheck: true }) };
  const build = (source) => {
    const root = makeRoot({ 'tests/m/a.test.mjs': passing('A-01'), 'src/sample.ts': source }, { lock });
    symlinkSync(join(REPO_ROOT, 'node_modules'), join(root, 'node_modules'));
    symlinkSync(join(REPO_ROOT, 'tools'), join(root, 'tools'));
    return root;
  };
  const broken = await engine(build("export const count: number = 'not a number';\n"), registry, 'm');
  expectStatus(broken, STATUS.FAIL, 'type error');
  assert.ok(broken.reasons.some((reason) => reason.startsWith('typecheck failed')), 'the typecheck is named');
  assert.equal(broken.tests, 0, 'no test runs after a failed typecheck');
  expectStatus(await engine(build('export const count: number = 1;\n'), registry, 'm'), STATUS.PASS, 'clean typecheck');
});

test('[RT-32] a cancelled test returns FAIL (M3)', async () => {
  executed += 1;
  // The test's own signal aborts while it runs, so node:test cancels it.
  const source =
    `${HEAD}const controller = new AbortController();\n` +
    "test('[C-01] cancelled while running', { signal: controller.signal }, async () => {\n" +
    '  setTimeout(() => controller.abort(), 20);\n' +
    '  await new Promise((resolve) => setTimeout(resolve, 2000));\n' +
    '});\n';
  const result = await engine(makeRoot({ 'tests/m/a.test.mjs': source }), { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) }, 'm');
  expectStatus(result, STATUS.FAIL, 'cancelled subtest');
  assert.ok(result.cancelled >= 1, `the cancellation is counted (cancelled=${result.cancelled})`);
});

test('[RT-33] a tree changed during the run returns EVIDENCE_MISSING (M1)', async () => {
  executed += 1;
  const mutator =
    `${HEAD}import { mkdirSync, writeFileSync } from 'node:fs';\n` +
    "test('[T-01] writes into src/', () => {\n  mkdirSync('src', { recursive: true });\n  writeFileSync('src/written-during-run.ts', 'export {};\\n');\n});\n";
  const plain = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  const leafResult = await engine(makeRoot({ 'tests/m/a.test.mjs': mutator }), plain, 'm');
  expectStatus(leafResult, STATUS.EVIDENCE_MISSING, 'leaf mode');
  assert.ok(leafResult.reasons.some((reason) => reason.startsWith('tree changed during run')));
  assert.notEqual(leafResult.tree_digest_after, leafResult.tree_digest);

  const evidenceThenMutate =
    `${HEAD}import { mkdirSync, writeFileSync } from 'node:fs';\n` +
    "test('[T-01] writes evidence, then changes the tree', () => {\n" +
    '  mkdirSync(process.env.OPENSIG_VERIFY_OUT, { recursive: true });\n' +
    "  writeFileSync(process.env.OPENSIG_VERIFY_OUT + '/evidence.json', JSON.stringify({ tree_digest: process.env.OPENSIG_VERIFY_TREE_DIGEST }));\n" +
    "  mkdirSync('fixtures', { recursive: true });\n  writeFileSync('fixtures/generated.txt', 'changed');\n});\n";
  const withEvidence = {
    m: leaf({ files: ['tests/m/**/*.test.mjs'], evidence: [{ path: '.verify-out/m/evidence.json', labels: { tree_digest: true } }] }),
  };
  expectStatus(await engine(makeRoot({ 'tests/m/a.test.mjs': evidenceThenMutate }), withEvidence, 'm'), STATUS.EVIDENCE_MISSING, 'evidence-bearing mode');

  const aggregateRegistry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }), agg: aggregate({ components: ['m'] }) };
  expectStatus(await engine(makeRoot({ 'tests/m/a.test.mjs': mutator }), aggregateRegistry, 'agg'), STATUS.EVIDENCE_MISSING, 'aggregate component');
});

test('[RT-34] frozen package.json, .npmrc and tsconfig.json values are enforced (M2)', async () => {
  executed += 1;
  assert.deepEqual(frozenConfigProblems(REPO_ROOT), [], 'the code leg carries the frozen configuration');
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  const pkg = JSON.parse(FROZEN_FILES['package.json']);
  const tsconfig = JSON.parse(FROZEN_FILES['tsconfig.json']);
  const withScripts = (scripts) => JSON.stringify({ ...pkg, scripts: { ...pkg.scripts, ...scripts } });
  const mutations = {
    'scripts.typecheck replaced': { 'package.json': withScripts({ typecheck: 'exit 0' }) },
    'scripts.verify rerouted': { 'package.json': withScripts({ verify: 'node scripts/other.mjs' }) },
    'scripts.test changed': { 'package.json': withScripts({ test: 'tools/node/bin/node scripts/verify.mjs tooling' }) },
    'engines.node widened': { 'package.json': JSON.stringify({ ...pkg, engines: { node: '>=24' } }) },
    '.npmrc ignore-scripts false': { '.npmrc': 'engine-strict=true\nsave-exact=true\nignore-scripts=false\n' },
    '.npmrc save-exact missing': { '.npmrc': 'engine-strict=true\nignore-scripts=true\n' },
    '.npmrc key overridden later': { '.npmrc': 'engine-strict=true\nsave-exact=true\nignore-scripts=true\nengine-strict=false\n' },
    'tsconfig noCheck': { 'tsconfig.json': JSON.stringify({ ...tsconfig, compilerOptions: { ...tsconfig.compilerOptions, noCheck: true } }) },
    'tsconfig include narrowed': { 'tsconfig.json': JSON.stringify({ ...tsconfig, include: ['src'] }) },
  };
  for (const [label, files] of Object.entries(mutations)) {
    expectStatus(await engine(makeRoot({ 'tests/m/a.test.mjs': passing('A-01'), ...files }), registry, 'm'), STATUS.ENV_MISMATCH, label);
  }
  const noPackage = makeRoot({ 'tests/m/a.test.mjs': passing('A-01') });
  rmSync(join(noPackage, 'package.json'));
  expectStatus(await engine(noPackage, registry, 'm'), STATUS.ENV_MISMATCH, 'package.json missing');
  expectStatus(await engine(makeRoot({ 'tests/m/a.test.mjs': passing('A-01') }), registry, 'm'), STATUS.PASS, 'frozen configuration');
});

test('[RT-35] a mock identity at any depth of acceptance evidence returns FAIL (L1)', async () => {
  executed += 1;
  const registry = {
    m: leaf({
      kind: 'acceptance',
      files: ['tests/m/**/*.test.mjs'],
      evidence: [{ path: '.verify-out/m/evidence.json', labels: { verifier_name: true, tree_digest: true } }],
    }),
  };
  const run = (labels) => engine(makeRoot({ 'tests/m/a.test.mjs': evidenceWriter(labels) }), registry, 'm');
  expectStatus(await run({ verifier_name: 'openssl-cms 3.0', reader: { name: 'fake-verifier' } }), STATUS.FAIL, 'nested object');
  expectStatus(await run({ verifier_name: 'openssl-cms 3.0', tools: ['chromium 140', 'jsdom 26'] }), STATUS.FAIL, 'array element');
  expectStatus(await run({ verifier_name: 'openssl-cms 3.0', runs: [{ steps: [{ runtime: 'hermes-stub v1' }] }] }), STATUS.FAIL, 'deep nesting');
  expectStatus(await run({ verifier_name: 'openssl-cms 3.0', reader: { name: 'external reader' }, tools: ['chromium 140'] }), STATUS.PASS, 'no mock anywhere');
});

test('[RT-36] any node flag on the runner itself returns ENV_MISMATCH (L3)', async () => {
  executed += 1;
  const root = makeRoot({ 'tests/m/a.test.mjs': passing('A-01') });
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  for (const flags of [['--max-old-space-size=128'], ['--experimental-config-file=node.config.json'], ['--no-warnings']]) {
    expectStatus(await engine(root, registry, 'm', { execArgv: flags }), STATUS.ENV_MISMATCH, `runner flags ${flags.join(' ')}`);
  }
  expectStatus(await engine(root, registry, 'm', { execArgv: [] }), STATUS.PASS, 'no runner flags');
});

test('[RT-37] a symlink under tests/ returns RUNNER_ERROR (L4)', async () => {
  executed += 1;
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }), n: leaf({ files: ['tests/n/**/*.test.mjs'] }) };
  const fileLink = makeRoot({ 'tests/m/a.test.mjs': passing('A-01') });
  symlinkSync('a.test.mjs', join(fileLink, 'tests', 'm', 'b.test.mjs'));
  const linked = await engine(fileLink, registry, 'm');
  expectStatus(linked, STATUS.RUNNER_ERROR, 'symlinked test file');
  assert.ok(linked.reasons.some((reason) => reason.includes('tests/m/b.test.mjs')), 'the symlink is named');
  const dirLink = makeRoot({ 'tests/m/a.test.mjs': passing('A-01') });
  symlinkSync(join(dirLink, 'tests', 'm'), join(dirLink, 'tests', 'n'));
  expectStatus(await engine(dirLink, registry, 'm'), STATUS.RUNNER_ERROR, 'symlinked test directory');
});

test('[RT-38] lockfile version or integrity drift and unlisted installed packages return ENV_MISMATCH (L6)', async () => {
  executed += 1;
  const registry = { m: leaf({ files: ['tests/m/**/*.test.mjs'] }) };
  const entry = {
    version: '1.0.0',
    resolved: 'https://registry.npmjs.org/pkg-a/-/pkg-a-1.0.0.tgz',
    integrity: `sha512-${'A'.repeat(86)}==`,
    dev: true,
    license: 'MIT',
  };
  const lock = { ...EMPTY_LOCK, packages: { '': { name: 'fixture' }, 'node_modules/pkg-a': entry } };
  const tree = (overrides = {}, extra = {}) => ({
    'tests/m/a.test.mjs': passing('A-01'),
    'node_modules/.package-lock.json': JSON.stringify({ name: 'fixture', lockfileVersion: 3, requires: true, packages: { 'node_modules/pkg-a': { ...entry, ...overrides } } }),
    'node_modules/pkg-a/package.json': JSON.stringify({ name: 'pkg-a', version: '1.0.0' }),
    ...extra,
  });
  expectStatus(await engine(makeRoot(tree(), { lock }), registry, 'm'), STATUS.PASS, 'installed tree equals the lockfile');
  expectStatus(await engine(makeRoot(tree({ version: '1.0.1' }), { lock }), registry, 'm'), STATUS.ENV_MISMATCH, 'version drift');
  expectStatus(await engine(makeRoot(tree({ integrity: `sha512-${'B'.repeat(86)}==` }), { lock }), registry, 'm'), STATUS.ENV_MISMATCH, 'integrity drift');
  expectStatus(
    await engine(makeRoot(tree({}, { 'node_modules/pkg-a/package.json': JSON.stringify({ name: 'pkg-a', version: '1.0.2' }) }), { lock }), registry, 'm'),
    STATUS.ENV_MISMATCH,
    'installed package.json differs',
  );
  const rogue = await engine(makeRoot(tree({}, { 'node_modules/rogue/package.json': '{"name":"rogue","version":"0.0.1"}' }), { lock }), registry, 'm');
  expectStatus(rogue, STATUS.ENV_MISMATCH, 'unlisted top-level package');
  assert.ok(rogue.reasons.some((reason) => reason.includes('node_modules/rogue')), 'the unlisted package is named');
  expectStatus(
    await engine(makeRoot(tree({}, { 'node_modules/@scope/rogue/package.json': '{"name":"@scope/rogue","version":"0.0.1"}' }), { lock }), registry, 'm'),
    STATUS.ENV_MISMATCH,
    'unlisted scoped package',
  );
});
