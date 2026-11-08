#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig frozen fail-closed verification runner: engine and CLI.
//
//   npm run verify -- <mode>
//
// Contract: spec leg specs/001-corporate-signing-mvp/plan.md, section
// "Verification runner contract", including amendment A-006 (T001 hardening
// round). This file, scripts/verify-modes.mjs and
// tests/tooling/verification-runner.test.mjs are FROZEN at the T001 hardening
// commit. Only a recorded architect amendment may change them, through a new
// [O] task that lists these three files, re-runs the self-tests and re-freezes.
//
// Exit statuses (one final stdout line, plus .verify-out/<mode>/result.json):
//   0 PASS  1 FAIL  2 USAGE  3 CAPABILITY_ABSENT  4 VACUOUS
//   5 EVIDENCE_MISSING  6 ENV_MISMATCH  7 RUNNER_ERROR
//
// There is no flag and no environment variable that relaxes any rule.
//
// Execution model: each test file runs through node:test run() with process
// isolation inside a short-lived driver process placed in its own process
// group. The driver forwards the event stream over IPC; this engine counts it.
// A file that exceeds the per-file timeout has its whole process group killed
// and counts as FAIL. Tests are never retried.

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  accessSync,
  constants as fsConstants,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const STATUS = Object.freeze({
  PASS: 0,
  FAIL: 1,
  USAGE: 2,
  CAPABILITY_ABSENT: 3,
  VACUOUS: 4,
  EVIDENCE_MISSING: 5,
  ENV_MISMATCH: 6,
  RUNNER_ERROR: 7,
});

export const STATUS_NAMES = Object.freeze(Object.fromEntries(Object.entries(STATUS).map(([name, code]) => [code, name])));

/** The 43 mode names of plan.md "Mode registry", in table order. */
export const FROZEN_MODE_NAMES = Object.freeze([
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
]);

export const MODE_KINDS = Object.freeze(['tooling', 'unit', 'harness', 'contract', 'acceptance', 'aggregate', 'release']);

export const CAPABILITY_NAMES = Object.freeze([
  'openssl',
  'chromium',
  'hermes-runtime',
  'claude-sdk-transport',
  'external-pdf-reader',
  'declared-hardware',
  'ci-run',
]);

export const KNOWN_MOCKS = Object.freeze(['hermes-stub', 'fake-verifier', 'jsdom', 'mock-browser']);

/**
 * Release gates outside the local acceptance run. None has a closing mechanism
 * in the plan yet, so the release mode `acceptance` can only return FAIL.
 */
export const EXTERNAL_GATES = Object.freeze([
  Object.freeze({
    gate: 'platform-inventory',
    status: 'POLICY-PENDING',
    detail: 'owner decision on platform license scope (plan.md "Pending owner decision")',
  }),
  Object.freeze({ gate: 'trusted-certificate-key-custody', status: 'OPEN', detail: 'trusted organization certificate and managed key custody' }),
  Object.freeze({ gate: 'validated-oidc-smtp', status: 'OPEN', detail: 'validated real operator OIDC issuer and SMTP relay' }),
  Object.freeze({
    gate: 'external-pdf-reader',
    status: 'OPEN',
    capability: 'external-pdf-reader',
    detail: 'independent external PDF reader validation of the sealed artifact',
  }),
  Object.freeze({
    gate: 'declared-hardware',
    status: 'OPEN',
    capability: 'declared-hardware',
    detail: 'SC-005 timing on the declared pilot hardware',
  }),
  Object.freeze({ gate: 'real-ci', status: 'OPEN', capability: 'ci-run', detail: 'a real CI run of the release gates' }),
  Object.freeze({ gate: 'production-hermes', status: 'OPEN', detail: 'production Hermes (only isolated-local Hermes is exercised)' }),
]);

/**
 * Configuration frozen by amendment A-006 (M2). The runner returns
 * ENV_MISMATCH when the tree differs from any of these values.
 */
export const FROZEN_PACKAGE_SCRIPTS = Object.freeze({
  verify: 'tools/node/bin/node scripts/verify.mjs',
  test: 'tools/node/bin/node scripts/verify.mjs all-unit',
  typecheck: 'tools/node/bin/node node_modules/typescript/bin/tsc --noEmit -p tsconfig.json',
});
export const FROZEN_NODE_VERSION = '24.22.2';
export const FROZEN_NPMRC = Object.freeze({ 'engine-strict': 'true', 'save-exact': 'true', 'ignore-scripts': 'true' });
export const FROZEN_TSCONFIG = Object.freeze({
  compilerOptions: Object.freeze({
    target: 'es2024',
    lib: Object.freeze(['es2024']),
    module: 'nodenext',
    moduleResolution: 'nodenext',
    strict: true,
    noUncheckedIndexedAccess: true,
    noEmit: true,
    allowImportingTsExtensions: true,
    erasableSyntaxOnly: true,
    verbatimModuleSyntax: true,
    types: Object.freeze(['node']),
    allowJs: true,
    checkJs: false,
  }),
  include: Object.freeze(['src', 'tests', 'scripts']),
});

export const FILE_TIMEOUT_MS = 10 * 60 * 1000;
const SENTINEL_TIMEOUT_MS = 2 * 60 * 1000;
const PROBE_TIMEOUT_MS = 2 * 60 * 1000;
const TYPECHECK_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_BUFFER = 64 * 1024 * 1024;

const REGISTRY_FIELDS = Object.freeze(
  ['task', 'kind', 'files', 'minTests', 'requiredCases', 'capabilities', 'evidence', 'typecheck', 'contract', 'components'].sort(),
);
const MODE_NAME = /^[a-z0-9][a-z0-9-]*$/;
const CASE_ID_SHAPE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const CASE_ID = /^\[([A-Za-z0-9][A-Za-z0-9._-]*)\]/;
const NON_EVIDENCE_KINDS = new Set(['harness', 'contract']);
const LEAF_KINDS = new Set(['tooling', 'unit', 'harness', 'contract', 'acceptance']);
const ONLY_DIAGNOSTIC = "'only' and 'runOnly' require the --test-only";

// Test-filter flags change which tests run; preload flags can rewrite node:test
// itself. Either one in NODE_OPTIONS is ENV_MISMATCH. The runner's own argv must
// carry no node flag at all (A-006 L3).
const FORBIDDEN_NODE_FLAG =
  /^(?:--test(?:$|[-=])|--experimental-test|--import(?:$|=)|--require(?:$|=)|-r|--loader(?:$|=)|--experimental-loader(?:$|=))/;

const TREE_DIGEST_DIRS = Object.freeze(['src/', 'tests/', 'scripts/', 'fixtures/', 'contracts/']);
const TREE_DIGEST_FILES = new Set(['package.json', 'package-lock.json', '.node-version']);

const CREDENTIAL_PATTERNS = Object.freeze([
  /sk-ant-[A-Za-z0-9_-]{8,}/,
  /\bsk-[A-Za-z0-9]{20,}/,
  /\bBearer\s+[A-Za-z0-9._~+/-]{16,}/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|secret|client[_-]?secret|password|authorization)"\s*:\s*"[^"]{6,}"/i,
]);

const SENTINEL_PASS = "import { test } from 'node:test';\ntest('sentinel passes', () => {});\n";
const SENTINEL_SKIP = "import { test } from 'node:test';\ntest('sentinel is skipped', { skip: true }, () => {});\n";

// The driver runs one test file through node:test run() and forwards a compact
// copy of each event over IPC. It is written to a private temp directory per run.
const DRIVER_SOURCE = [
  "import { run } from 'node:test';",
  'const file = process.argv[2];',
  'const send = (message) => new Promise((done) => { process.send(message, () => done()); });',
  "const flag = (value) => value !== undefined && value !== null && value !== false;",
  'const text = (error) => {',
  "  if (error === undefined || error === null) return '';",
  '  const cause = error.cause !== undefined && error.cause !== null ? error.cause : error;',
  "  const message = typeof cause === 'object' && cause !== null && 'message' in cause ? cause.message : cause;",
  '  return String(message).slice(0, 2000);',
  '};',
  'try {',
  "  for await (const event of run({ files: [file], isolation: 'process', concurrency: 1 })) {",
  '    const data = event.data || {};',
  "    if (event.type === 'test:pass' || event.type === 'test:fail') {",
  '      const details = data.details || {};',
  '      await send({',
  '        t: event.type,',
  '        name: String(data.name),',
  '        nesting: data.nesting,',
  '        file: data.file || null,',
  '        skip: flag(data.skip),',
  '        todo: flag(data.todo),',
  '        kind: details.type || null,',
  '        failureType: (details.error && details.error.failureType) || null,',
  "        message: event.type === 'test:fail' ? text(details.error) : '',",
  '      });',
  "    } else if (event.type === 'test:diagnostic') {",
  '      await send({ t: event.type, message: String(data.message), file: data.file || null });',
  "    } else if (event.type === 'test:summary' && data.file) {",
  '      await send({ t: event.type, file: data.file, counts: data.counts || {} });',
  '    }',
  '  }',
  "  await send({ t: 'end' });",
  '} catch (error) {',
  "  await send({ t: 'driver-error', message: String((error && error.stack) || error) });",
  '}',
  'process.disconnect();',
  '',
].join('\n');

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// Process groups of live drivers, killed on timeout, on exit and on signals.
const liveGroups = new Set();
function killGroup(pid) {
  if (!Number.isInteger(pid)) return;
  try {
    process.kill(-pid, 'SIGKILL');
  } catch {
    // The group has already exited.
  }
}
process.on('exit', () => {
  for (const pid of liveGroups) killGroup(pid);
});

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

function isRegularFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function preview(list, max = 8) {
  return list.length <= max ? list.join(', ') : `${list.slice(0, max).join(', ')} ... (+${list.length - max} more)`;
}

function tail(text, max = 3000) {
  return text.length <= max ? text : `...${text.slice(-max)}`;
}

function sanitizeModeName(name) {
  const text = String(name ?? '');
  const clean = text.replace(/[^A-Za-z0-9._-]/g, '?').slice(0, 64);
  return clean === '' ? '-' : clean;
}

function displayPath(root, abs) {
  const rel = relative(root, abs);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel) ? rel.split(sep).join('/') : abs;
}

function newResult(mode, def) {
  return {
    mode,
    status: 'RUNNER_ERROR',
    exit: STATUS.RUNNER_ERROR,
    task: def?.task ?? null,
    kind: def?.kind ?? null,
    files: 0,
    tests: 0,
    pass: 0,
    fail: 0,
    skip: 0,
    todo: 0,
    cancelled: 0,
    only: 0,
    cases: { found: 0, required: Array.isArray(def?.requiredCases) ? def.requiredCases.length : 0, missing: [] },
    passed_case_ids: [],
    file_list: [],
    per_file: [],
    failures: [],
    capabilities: [],
    evidence: [],
    components: [],
    gates: [],
    reasons: [],
    tree_digest: null,
    tree_digest_after: null,
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    started_at: new Date().toISOString(),
    finished_at: null,
  };
}

function settle(result, code, ...reasons) {
  result.exit = code;
  result.status = STATUS_NAMES[code];
  for (const reason of reasons) if (reason) result.reasons.push(reason);
  return result;
}

/** The single final stdout line. */
export function formatStatusLine(result) {
  let line =
    `verify: ${sanitizeModeName(result.mode)} ${result.status} exit=${result.exit} files=${result.files} ` +
    `tests=${result.tests} pass=${result.pass} fail=${result.fail} skip=${result.skip} todo=${result.todo} ` +
    `cases=${result.cases.found}/${result.cases.required}`;
  const open = (result.gates ?? []).filter((gate) => gate.status !== 'CLOSED');
  if (open.length > 0) {
    line += ` open=${open.map((gate) => (gate.status === 'OPEN' ? gate.gate : `${gate.gate}(${gate.status})`)).join(',')}`;
  }
  return line;
}

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

/** Parse CLI arguments: exactly one known mode name, no flags of any kind. */
export function parseArgs(argv) {
  if (argv.length === 0) return { error: 'no mode given; usage: npm run verify -- <mode>' };
  const flag = argv.find((arg) => arg.startsWith('-'));
  if (flag !== undefined) {
    return {
      mode: argv.find((arg) => !arg.startsWith('-')),
      error: `unknown flag ${flag}: the runner has no flags and no way to relax its rules`,
    };
  }
  if (argv.length > 1) return { error: `exactly one mode is accepted, got ${argv.length}: ${argv.join(' ')}` };
  const [mode] = argv;
  if (!FROZEN_MODE_NAMES.includes(mode)) return { mode, error: `unknown mode ${mode}` };
  return { mode };
}

// ---------------------------------------------------------------------------
// Globs (expanded by the runner itself; never handed to node --test)
// ---------------------------------------------------------------------------

function globProblem(glob) {
  if (typeof glob !== 'string' || glob === '') return 'empty glob';
  if (glob.startsWith('/') || glob.startsWith('./') || glob.includes('\\')) return `glob ${glob} must be a plain relative path`;
  if (glob.split('/').some((segment) => segment === '..' || segment === '.' || segment === '')) {
    return `glob ${glob} has an empty, "." or ".." segment`;
  }
  return null;
}

export function globToRegExp(glob) {
  let source = '';
  for (let i = 0; i < glob.length; i += 1) {
    const char = glob[i];
    if (char === '*') {
      if (glob[i + 1] === '*') {
        if (glob[i + 2] === '/') {
          source += '(?:[^/]+/)*';
          i += 2;
        } else {
          source += '.*';
          i += 1;
        }
      } else {
        source += '[^/]*';
      }
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${source}$`);
}

function walkFiles(root, relDir, out) {
  let entries;
  try {
    entries = readdirSync(relDir === '' ? root : join(root, relDir), { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const rel = relDir === '' ? entry.name : `${relDir}/${entry.name}`;
    if (entry.isDirectory()) walkFiles(root, rel, out);
    else if (entry.isFile()) out.push(rel);
  }
}

/** Expand registry globs to a sorted list of regular files relative to root. */
export function expandGlobs(root, globs) {
  const found = new Set();
  for (const glob of globs) {
    const problem = globProblem(glob);
    if (problem) throw new Error(problem);
    if (!/[*?]/.test(glob)) {
      if (lstatSafe(join(root, glob))?.isFile()) found.add(glob);
      continue;
    }
    const segments = glob.split('/');
    const base = [];
    for (const segment of segments) {
      if (/[*?]/.test(segment)) break;
      base.push(segment);
    }
    const pattern = globToRegExp(glob);
    const files = [];
    walkFiles(root, base.join('/'), files);
    for (const file of files) if (pattern.test(file)) found.add(file);
  }
  return [...found].sort();
}

function lstatSafe(path) {
  try {
    return lstatSync(path);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Registry validation and completeness
// ---------------------------------------------------------------------------

function labelRequirementProblem(requirement) {
  if (requirement === true || typeof requirement === 'string') return null;
  if (Array.isArray(requirement) && requirement.length > 0 && requirement.every((v) => typeof v === 'string')) return null;
  if (requirement && typeof requirement === 'object' && typeof requirement.pattern === 'string') {
    try {
      new RegExp(requirement.pattern);
      return null;
    } catch {
      return 'invalid label pattern';
    }
  }
  return 'label requirement must be true, a string, a string list or { pattern }';
}

/** Structural validation of a registry against the frozen name list. */
export function validateRegistry(registry, modeNames) {
  const problems = [];
  if (!registry || typeof registry !== 'object') return ['registry is not an object'];
  const names = Object.keys(registry);
  if (JSON.stringify(names) !== JSON.stringify([...modeNames])) {
    const extra = names.filter((n) => !modeNames.includes(n));
    const missing = modeNames.filter((n) => !names.includes(n));
    problems.push(
      `registry mode names differ from the frozen list (registry ${names.length}, frozen ${modeNames.length}; ` +
        `extra: ${preview(extra) || 'none'}; missing: ${preview(missing) || 'none'}; or order differs)`,
    );
  }
  for (const name of names) {
    const def = registry[name];
    const at = `mode ${name}:`;
    if (!MODE_NAME.test(name)) problems.push(`${at} invalid mode name`);
    if (!def || typeof def !== 'object') {
      problems.push(`${at} not an object`);
      continue;
    }
    if (JSON.stringify(Object.keys(def).sort()) !== JSON.stringify(REGISTRY_FIELDS)) {
      problems.push(`${at} fields must be exactly ${REGISTRY_FIELDS.join(', ')}`);
      continue;
    }
    if (typeof def.task !== 'string' || def.task === '') problems.push(`${at} task must be a non-empty string`);
    if (!MODE_KINDS.includes(def.kind)) problems.push(`${at} unknown kind ${def.kind}`);
    const nonArrays = ['files', 'requiredCases', 'capabilities', 'evidence', 'components'].filter((field) => !Array.isArray(def[field]));
    if (nonArrays.length > 0) {
      problems.push(`${at} ${nonArrays.join(', ')} must be arrays`);
      continue;
    }
    if (!Number.isInteger(def.minTests) || def.minTests < 0) problems.push(`${at} minTests must be a non-negative integer`);
    if (typeof def.typecheck !== 'boolean') problems.push(`${at} typecheck must be a boolean`);
    if (typeof def.contract !== 'boolean') problems.push(`${at} contract must be a boolean`);
    for (const cap of def.capabilities) if (!CAPABILITY_NAMES.includes(cap)) problems.push(`${at} unknown capability ${cap}`);
    if (new Set(def.requiredCases).size !== def.requiredCases.length) problems.push(`${at} duplicate required case ids`);
    for (const id of def.requiredCases) if (!CASE_ID_SHAPE.test(String(id))) problems.push(`${at} malformed case id ${id}`);

    if (LEAF_KINDS.has(def.kind)) {
      if (def.files.length === 0) problems.push(`${at} needs at least one test glob`);
      for (const glob of def.files) {
        const problem = globProblem(glob);
        if (problem) problems.push(`${at} ${problem}`);
        else if (!glob.startsWith('tests/') || !glob.endsWith('.test.mjs')) problems.push(`${at} glob ${glob} must match tests/**/*.test.mjs`);
      }
      if (def.minTests < 1) problems.push(`${at} minTests must be at least 1`);
      if (def.components.length > 0) problems.push(`${at} only aggregate and release modes have components`);
      for (const ev of def.evidence) {
        if (!ev || typeof ev.path !== 'string' || !ev.path.startsWith(`.verify-out/${name}/`)) {
          problems.push(`${at} evidence must live under .verify-out/${name}/`);
        } else if (ev.receipt || ev.committed) {
          problems.push(`${at} receipt and committed evidence belong to aggregate or release modes`);
        }
        for (const [label, requirement] of Object.entries(ev?.labels ?? {})) {
          const problem = labelRequirementProblem(requirement);
          if (problem) problems.push(`${at} label ${label}: ${problem}`);
        }
      }
    } else {
      if (def.files.length > 0) problems.push(`${at} ${def.kind} modes have no test files of their own`);
      if (def.components.length === 0) problems.push(`${at} ${def.kind} modes need components`);
      if (new Set(def.components).size !== def.components.length) problems.push(`${at} duplicate components`);
      for (const component of def.components) {
        const member = registry[component];
        if (component === name || !member) problems.push(`${at} unknown component ${component}`);
        else if (def.kind === 'aggregate' && !LEAF_KINDS.has(member.kind)) problems.push(`${at} aggregate components must be leaf modes`);
      }
      for (const ev of def.evidence) {
        if (!ev || typeof ev.path !== 'string' || globProblem(ev.path)) problems.push(`${at} invalid evidence path`);
        else if (ev.receipt && !ev.path.startsWith(`.verify-out/${name}/`)) problems.push(`${at} receipts live under .verify-out/${name}/`);
        else if (!ev.receipt && !ev.committed) problems.push(`${at} evidence must be a receipt or a committed file`);
      }
    }
  }
  return problems;
}

function walkTree(root, relDir, files, links) {
  let entries;
  try {
    entries = readdirSync(join(root, relDir), { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const rel = `${relDir}/${entry.name}`;
    if (entry.isSymbolicLink()) links.push(rel);
    else if (entry.isDirectory()) walkTree(root, rel, files, links);
    else if (entry.isFile()) files.push(rel);
  }
}

/**
 * Every tests/**\/*.test.mjs file must be claimed by exactly one mode, and no
 * symlink may exist under tests/ (it would be neither run nor claimed).
 */
export function findClaimProblems(root, registry) {
  const matchers = Object.entries(registry)
    .filter(([, def]) => Array.isArray(def?.files) && def.files.length > 0)
    .map(([name, def]) => [name, def.files.map(globToRegExp)]);
  const problems = [];
  if (lstatSafe(join(root, 'tests'))?.isSymbolicLink()) return ['tests/ itself is a symlink'];
  const all = [];
  const links = [];
  walkTree(root, 'tests', all, links);
  for (const link of links.sort()) problems.push(`symlink under tests/ is not allowed: ${link}`);
  for (const file of all.filter((f) => f.endsWith('.test.mjs')).sort()) {
    const owners = matchers.filter(([, patterns]) => patterns.some((p) => p.test(file))).map(([name]) => name);
    if (owners.length === 0) problems.push(`test file ${file} is claimed by no mode`);
    else if (owners.length > 1) problems.push(`test file ${file} is claimed by ${owners.length} modes (${owners.join(', ')})`);
  }
  return problems;
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

function forbiddenFlags(tokens) {
  return tokens.filter((token) => FORBIDDEN_NODE_FLAG.test(token));
}

function nodeOptionTokens(env) {
  return String(env.NODE_OPTIONS ?? '')
    .split(/\s+/)
    .filter(Boolean);
}

function childEnvFrom(env) {
  const child = { ...env };
  delete child.NODE_TEST_CONTEXT;
  const kept = nodeOptionTokens(env).filter((token) => !FORBIDDEN_NODE_FLAG.test(token));
  if (kept.length > 0) child.NODE_OPTIONS = kept.join(' ');
  else delete child.NODE_OPTIONS;
  return child;
}

/** Top-level package directories under node_modules (scoped as "@scope/name"). */
function topLevelPackages(root) {
  const dir = join(root, 'node_modules');
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const names = [];
  for (const entry of entries) {
    if (entry.name.startsWith('.') || !(entry.isDirectory() || entry.isSymbolicLink())) continue;
    if (!entry.name.startsWith('@')) {
      names.push(entry.name);
      continue;
    }
    let scoped = [];
    try {
      scoped = readdirSync(join(dir, entry.name), { withFileTypes: true });
    } catch {
      scoped = [];
    }
    for (const member of scoped) {
      if (!member.name.startsWith('.') && (member.isDirectory() || member.isSymbolicLink())) names.push(`${entry.name}/${member.name}`);
    }
  }
  return names.sort();
}

function lockfileProblems(root) {
  let lock;
  try {
    lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  } catch {
    return ['package-lock.json is missing or unreadable'];
  }
  const locked = lock && typeof lock.packages === 'object' && lock.packages !== null ? lock.packages : null;
  if (!locked) return ['package-lock.json has no "packages" map (lockfileVersion 3 is required)'];
  const lockedKeys = Object.keys(locked).filter((key) => key !== '');
  let installed = null;
  const hiddenPath = join(root, 'node_modules', '.package-lock.json');
  if (lstatSafe(hiddenPath)) {
    try {
      installed = JSON.parse(readFileSync(hiddenPath, 'utf8')).packages ?? null;
    } catch {
      return ['node_modules/.package-lock.json is unreadable; run npm ci'];
    }
    if (!installed || typeof installed !== 'object') return ['node_modules/.package-lock.json has no "packages" map; run npm ci'];
  }
  const present = topLevelPackages(root);
  if (installed === null) {
    if (lockedKeys.length === 0 && present.length === 0) return [];
    return ['node_modules/.package-lock.json is missing; run npm ci'];
  }
  const problems = [];
  for (const name of present) {
    if (!Object.hasOwn(installed, `node_modules/${name}`)) problems.push(`node_modules/${name} is installed but missing from node_modules/.package-lock.json`);
  }
  const same = (a, b) => a.version === b.version && a.resolved === b.resolved && a.integrity === b.integrity;
  for (const key of lockedKeys) {
    const want = locked[key];
    const have = installed[key];
    if (!have) {
      if (!want.optional) problems.push(`${key} is locked but not installed`);
    } else if (!same(want, have)) {
      problems.push(`${key} is installed as ${have.version} but locked as ${want.version}`);
    }
  }
  for (const key of Object.keys(installed)) {
    if (key === '') continue;
    if (!Object.hasOwn(locked, key)) {
      problems.push(`${key} is installed but not locked`);
      continue;
    }
    if (installed[key].link) continue;
    let version = null;
    try {
      version = JSON.parse(readFileSync(join(root, key, 'package.json'), 'utf8')).version ?? null;
    } catch {
      version = null;
    }
    if (version !== installed[key].version) problems.push(`${key}/package.json reports ${version ?? 'nothing'}, expected ${installed[key].version}`);
  }
  const shown = problems.length > 6 ? [...problems.slice(0, 6), `... and ${problems.length - 6} more`] : problems;
  return shown.map((problem) => `installed tree differs from package-lock.json: ${problem}`);
}

function environmentProblems(ctx) {
  const problems = [];
  let pinned = null;
  try {
    pinned = readFileSync(join(ctx.root, '.node-version'), 'utf8').trim();
  } catch {
    problems.push('.node-version is missing');
  }
  if (pinned !== null && process.version !== `v${pinned}`) {
    problems.push(`runtime ${process.version} does not match .node-version v${pinned}; use PATH="$PWD/tools/node/bin:$PATH"`);
  }
  if (process.platform !== 'linux' || process.arch !== 'x64') {
    problems.push(`platform ${process.platform}-${process.arch} is not linux-x64`);
  }
  problems.push(...frozenConfigProblems(ctx.root));
  problems.push(...lockfileProblems(ctx.root));
  const fromOptions = forbiddenFlags(nodeOptionTokens(ctx.env));
  if (fromOptions.length > 0) problems.push(`NODE_OPTIONS carries test-filter or preload flags: ${fromOptions.join(' ')}`);
  if (ctx.execArgv.length > 0) problems.push(`the runner must be started without node flags; got: ${ctx.execArgv.join(' ')}`);
  return problems;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function parseNpmrc(text) {
  const values = new Map();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#') || line.startsWith(';')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) {
      values.set(line, 'true');
      continue;
    }
    let value = line.slice(eq + 1).trim();
    if (/^(["']).*\1$/.test(value)) value = value.slice(1, -1);
    values.set(line.slice(0, eq).trim(), value); // the last assignment wins, as in npm
  }
  return values;
}

/**
 * A-006 M2: package.json scripts.verify/test/typecheck and engines.node,
 * .node-version, the three .npmrc keys and the whole tsconfig.json (so any
 * noCheck) must equal the frozen values.
 */
export function frozenConfigProblems(root) {
  const problems = [];
  let pkg = null;
  try {
    pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  } catch {
    problems.push('package.json is missing or not valid JSON');
  }
  if (pkg !== null) {
    for (const [name, expected] of Object.entries(FROZEN_PACKAGE_SCRIPTS)) {
      const actual = pkg?.scripts?.[name];
      if (actual !== expected) problems.push(`package.json scripts.${name} is ${JSON.stringify(actual ?? null)}; frozen value ${JSON.stringify(expected)}`);
    }
    const engine = pkg?.engines?.node;
    if (engine !== FROZEN_NODE_VERSION) problems.push(`package.json engines.node is ${JSON.stringify(engine ?? null)}; frozen value "${FROZEN_NODE_VERSION}"`);
  }
  let pinned = null;
  try {
    pinned = readFileSync(join(root, '.node-version'), 'utf8').trim();
  } catch {
    pinned = null;
  }
  if (pinned !== null && pinned !== FROZEN_NODE_VERSION) problems.push(`.node-version is ${pinned}; frozen value ${FROZEN_NODE_VERSION}`);
  let npmrc = null;
  try {
    npmrc = readFileSync(join(root, '.npmrc'), 'utf8');
  } catch {
    problems.push('.npmrc is missing');
  }
  if (npmrc !== null) {
    const values = parseNpmrc(npmrc);
    for (const [key, expected] of Object.entries(FROZEN_NPMRC)) {
      if (values.get(key) !== expected) problems.push(`.npmrc ${key} is ${values.has(key) ? JSON.stringify(values.get(key)) : 'unset'}; frozen value ${expected}`);
    }
  }
  let tsconfig;
  try {
    tsconfig = JSON.parse(readFileSync(join(root, 'tsconfig.json'), 'utf8'));
  } catch {
    problems.push('tsconfig.json is missing or not plain JSON');
    return problems;
  }
  if (canonicalJson(tsconfig) !== canonicalJson(FROZEN_TSCONFIG)) {
    const noCheck = tsconfig?.compilerOptions?.noCheck !== undefined ? ' (compilerOptions.noCheck is set)' : '';
    problems.push(`tsconfig.json differs from the frozen configuration${noCheck}`);
  }
  return problems;
}

/** contract: true requires the vendored contract and a matching source digest. */
function contractProblem(root) {
  const contractPath = join(root, 'contracts', 'http-api.json');
  const sourcePath = join(root, 'contracts', 'http-api.source.json');
  if (!isRegularFile(contractPath)) return 'vendored contract contracts/http-api.json is missing';
  if (!isRegularFile(sourcePath)) return 'contract source record contracts/http-api.source.json is missing';
  let source;
  try {
    source = JSON.parse(readFileSync(sourcePath, 'utf8'));
  } catch {
    return 'contracts/http-api.source.json is not valid JSON';
  }
  for (const field of ['repo', 'commit', 'path', 'sha256']) {
    if (typeof source?.[field] !== 'string' || source[field] === '') return `contracts/http-api.source.json lacks ${field}`;
  }
  if (!/^[0-9a-f]{64}$/.test(source.sha256)) return 'contracts/http-api.source.json sha256 is not a lowercase SHA-256 hex digest';
  const actual = sha256Hex(readFileSync(contractPath));
  if (actual !== source.sha256) return `vendored contract digest ${actual} does not match the source record ${source.sha256}`;
  return null;
}

// ---------------------------------------------------------------------------
// Tree digest
// ---------------------------------------------------------------------------

function inDigestScope(path) {
  if (path.startsWith('docs/evidence/')) return false;
  return TREE_DIGEST_DIRS.some((dir) => path.startsWith(dir)) || TREE_DIGEST_FILES.has(path) || /^tsconfig[^/]*\.json$/.test(path);
}

/**
 * SHA-256 over sorted `path\0sha256(content)\n` lines for the tracked and
 * untracked-but-not-ignored files in scope (plan.md "Tree digest").
 */
export function computeTreeDigest(root) {
  const listed = spawnSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
    cwd: root,
    encoding: 'buffer',
    maxBuffer: MAX_BUFFER,
  });
  if (listed.error || listed.status !== 0) {
    throw new Error(`git ls-files failed in ${root}: ${listed.error?.message ?? listed.stderr.toString().trim()}`);
  }
  const paths = [...new Set(listed.stdout.toString('utf8').split('\0').filter(Boolean))].filter(inDigestScope).sort();
  const hash = createHash('sha256');
  for (const path of paths) {
    const abs = join(root, path);
    const stat = lstatSafe(abs);
    if (!stat) continue; // listed in the index but deleted from the working tree
    let content;
    if (stat.isSymbolicLink()) content = Buffer.from(`symlink:${readlinkSync(abs)}`);
    else if (stat.isFile()) content = readFileSync(abs);
    else continue;
    hash.update(`${path}\0${sha256Hex(content)}\n`);
  }
  return hash.digest('hex');
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

function probeOpenssl(env) {
  const version = spawnSync('openssl', ['version'], { encoding: 'utf8', env, timeout: PROBE_TIMEOUT_MS });
  if (version.error || version.status !== 0) return { present: false, detail: 'openssl is not runnable' };
  const text = version.stdout.trim();
  const match = /^OpenSSL (\d+)\.(\d+)/.exec(text);
  if (!match || Number(match[1]) < 3) return { present: false, detail: `OpenSSL >= 3.0 required, found "${text}"` };
  const commands = spawnSync('openssl', ['list', '-commands'], { encoding: 'utf8', env, timeout: PROBE_TIMEOUT_MS });
  if (commands.error || commands.status !== 0 || !/(^|\s)cms(\s|$)/m.test(commands.stdout)) {
    return { present: false, detail: `${text} lacks the cms command` };
  }
  return { present: true, detail: text };
}

function probeChromium(root, env) {
  let packageDir = null;
  for (const name of ['playwright-core', 'playwright']) {
    const dir = join(root, 'node_modules', name);
    if (isRegularFile(join(dir, 'browsers.json'))) {
      packageDir = dir;
      break;
    }
  }
  if (!packageDir) return { present: false, detail: 'pinned Playwright (playwright-core) is not installed' };
  let revision;
  try {
    const browsers = JSON.parse(readFileSync(join(packageDir, 'browsers.json'), 'utf8')).browsers ?? [];
    revision = browsers.find((browser) => browser.name === 'chromium')?.revision;
  } catch {
    return { present: false, detail: 'playwright-core browsers.json is unreadable' };
  }
  if (!revision) return { present: false, detail: 'playwright-core browsers.json names no chromium revision' };
  const configured = env.PLAYWRIGHT_BROWSERS_PATH;
  const base =
    configured === '0' ? join(packageDir, '.local-browsers') : configured ? resolve(configured) : join(homedir(), '.cache', 'ms-playwright');
  const dir = join(base, `chromium-${revision}`);
  let entries = [];
  try {
    entries = readdirSync(dir).filter((entry) => entry.startsWith('chrome-linux'));
  } catch {
    return { present: false, detail: `chromium revision ${revision} is not installed under ${base}` };
  }
  for (const entry of entries) {
    const executable = join(dir, entry, 'chrome');
    try {
      accessSync(executable, fsConstants.X_OK);
      return { present: true, detail: `chromium revision ${revision} at ${executable}` };
    } catch {
      // Try the next layout.
    }
  }
  return { present: false, detail: `chromium revision ${revision} has no executable under ${dir}` };
}

function probeDelegated(root, name, env) {
  const probe = join(root, 'scripts', 'capabilities', `${name}.mjs`);
  if (!isRegularFile(probe)) return { present: false, detail: `probe scripts/capabilities/${name}.mjs is absent` };
  const run = spawnSync(process.execPath, [probe], { cwd: root, env, encoding: 'utf8', timeout: PROBE_TIMEOUT_MS, maxBuffer: MAX_BUFFER });
  if (run.error) return { present: false, detail: `probe scripts/capabilities/${name}.mjs failed to run: ${run.error.message}` };
  if (run.status !== 0) return { present: false, detail: `probe scripts/capabilities/${name}.mjs exited ${run.status ?? run.signal}` };
  return { present: true, detail: `probe scripts/capabilities/${name}.mjs exited 0` };
}

function probeCapabilities(ctx, names) {
  return names.map((name) => {
    let outcome;
    if (name === 'openssl') outcome = probeOpenssl(ctx.childEnv);
    else if (name === 'chromium') outcome = probeChromium(ctx.root, ctx.childEnv);
    else outcome = probeDelegated(ctx.root, name, ctx.childEnv);
    return { name, ...outcome };
  });
}

function absentReason(capabilities) {
  const absent = capabilities.filter((capability) => !capability.present);
  if (absent.length === 0) return null;
  return `capability absent, no test was run: ${absent.map((capability) => `${capability.name} (${capability.detail})`).join('; ')}`;
}

// ---------------------------------------------------------------------------
// Typecheck
// ---------------------------------------------------------------------------

function runTypecheck(ctx) {
  const pinnedNpm = join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');
  let command;
  let args;
  if (isRegularFile(pinnedNpm)) {
    command = process.execPath;
    args = [pinnedNpm, 'run', '--silent', 'typecheck'];
  } else if (ctx.env.npm_execpath && isRegularFile(ctx.env.npm_execpath)) {
    command = process.execPath;
    args = [ctx.env.npm_execpath, 'run', '--silent', 'typecheck'];
  } else {
    command = 'npm';
    args = ['run', '--silent', 'typecheck'];
  }
  const run = spawnSync(command, args, {
    cwd: ctx.root,
    env: ctx.childEnv,
    encoding: 'utf8',
    timeout: TYPECHECK_TIMEOUT_MS,
    maxBuffer: MAX_BUFFER,
  });
  if (run.error) return { ok: false, detail: `npm run typecheck could not run: ${run.error.message}` };
  if (run.status !== 0) {
    const output = `${run.stdout ?? ''}${run.stderr ?? ''}`.trim();
    return { ok: false, detail: `npm run typecheck exited ${run.status ?? run.signal}: ${tail(output, 1500)}` };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Test execution and counting
// ---------------------------------------------------------------------------

function runFile(ctx, absFile, timeoutMs, env) {
  return new Promise((resolveRun) => {
    const started = Date.now();
    const events = [];
    let stderr = '';
    let timedOut = false;
    let settled = false;
    let child;
    try {
      child = spawn(process.execPath, [ctx.driverPath, absFile], {
        cwd: ctx.root,
        env,
        detached: true,
        stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
      });
    } catch (error) {
      resolveRun({ events, timedOut, elapsedMs: 0, driverError: `cannot start the test driver: ${error.message}` });
      return;
    }
    if (Number.isInteger(child.pid)) liveGroups.add(child.pid);
    child.on('message', (message) => events.push(message));
    child.stderr.on('data', (chunk) => {
      stderr = (stderr + chunk.toString()).slice(-4000);
    });
    const timer = setTimeout(() => {
      timedOut = true;
      killGroup(child.pid);
    }, timeoutMs);
    const finish = (code, signal, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      killGroup(child.pid); // reap anything the test left running in its group
      liveGroups.delete(child.pid);
      const ended = events.some((event) => event?.t === 'end');
      const driverFailure = events.find((event) => event?.t === 'driver-error');
      let driverError = null;
      if (!timedOut) {
        if (error) driverError = `test driver error: ${error.message}`;
        else if (driverFailure) driverError = `test driver error: ${tail(String(driverFailure.message), 1500)}`;
        else if (!ended) driverError = `test driver exited (${code ?? signal}) before the run completed: ${tail(stderr.trim(), 800)}`;
      }
      resolveRun({ events, timedOut, elapsedMs: Date.now() - started, driverError });
    };
    child.on('error', (error) => finish(null, null, error));
    child.on('close', (code, signal) => finish(code, signal, null));
  });
}

function tally(events, absFile, root) {
  // node:test reports a file-level entry named after the file itself when a
  // file yields no tests (an empty file counts as "tests 1" in Node's own
  // summary) or fails as a whole. It is never counted as a test.
  const wrapperNames = new Set([absFile, relative(root, absFile)]);
  const counts = {
    file: displayPath(root, absFile),
    tests: 0,
    pass: 0,
    fail: 0,
    skip: 0,
    todo: 0,
    cancelled: 0,
    only: 0,
    timed_out: false,
    elapsed_ms: 0,
    failures: [],
    passedIds: [],
  };
  // A cancellation error can lose its failureType when it crosses the process
  // boundary, so the child's own per-file summary count is also consulted.
  let summaryCancelled = 0;
  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    if (event.t === 'test:summary') {
      summaryCancelled = Math.max(summaryCancelled, Number(event.counts?.cancelled ?? 0) || 0);
      continue;
    }
    if (event.t === 'test:diagnostic') {
      if (typeof event.message === 'string' && event.message.includes(ONLY_DIAGNOSTIC)) counts.only += 1;
      continue;
    }
    if (event.t !== 'test:pass' && event.t !== 'test:fail') continue;
    const wrapper = event.nesting === 0 && wrapperNames.has(event.name);
    const isTest = event.kind === 'test' && !wrapper;
    if (event.todo) {
      counts.todo += 1;
      if (isTest) counts.tests += 1;
      continue;
    }
    if (event.t === 'test:fail') {
      counts.fail += 1;
      if (event.failureType === 'cancelledByParent' || event.failureType === 'testAborted') counts.cancelled += 1;
      if (isTest) counts.tests += 1;
      counts.failures.push({ name: wrapper ? '(file)' : event.name, failureType: event.failureType, message: event.message });
      continue;
    }
    if (wrapper) continue;
    if (event.skip) {
      counts.skip += 1;
      if (isTest) counts.tests += 1;
      continue;
    }
    if (!isTest) continue; // a passing suite is a container, not a test
    counts.tests += 1;
    counts.pass += 1;
    const match = CASE_ID.exec(event.name);
    if (match) counts.passedIds.push(match[1]);
  }
  counts.cancelled = Math.max(counts.cancelled, summaryCancelled);
  return counts;
}

async function executeFiles(ctx, absFiles, timeoutMs, env) {
  const totals = { tests: 0, pass: 0, fail: 0, skip: 0, todo: 0, cancelled: 0, only: 0 };
  const perFile = [];
  const failures = [];
  const passedIds = new Set();
  const driverProblems = [];
  for (const absFile of absFiles) {
    const run = await runFile(ctx, absFile, timeoutMs, env);
    const counts = tally(run.events, absFile, ctx.root);
    counts.elapsed_ms = run.elapsedMs;
    if (run.timedOut) {
      counts.timed_out = true;
      counts.fail += 1;
      counts.failures.push({ name: '(file)', failureType: 'fileTimeout', message: `process group killed after the ${timeoutMs} ms per-file timeout` });
    }
    if (run.driverError) driverProblems.push(`${counts.file}: ${run.driverError}`);
    for (const key of Object.keys(totals)) totals[key] += counts[key];
    for (const failure of counts.failures) failures.push({ file: counts.file, ...failure });
    for (const id of counts.passedIds) passedIds.add(id);
    const { failures: _f, passedIds: _p, ...summary } = counts;
    perFile.push(summary);
  }
  return { totals, perFile, failures, passedIds, driverProblems };
}

function classify(spec, executed, fileCount) {
  const t = executed.totals;
  const missing = spec.requiredCases.filter((id) => !executed.passedIds.has(id));
  const found = spec.requiredCases.length - missing.length;
  if (executed.driverProblems.length > 0) return { code: STATUS.RUNNER_ERROR, reasons: executed.driverProblems, found, missing };
  if (t.fail > 0) {
    const shown = executed.failures.slice(0, 10).map((f) => `${f.file} > ${f.name} [${f.failureType ?? 'failure'}]: ${tail(String(f.message ?? ''), 300)}`);
    return {
      code: STATUS.FAIL,
      reasons: [`${t.fail} failure(s)${t.cancelled > 0 ? ` including ${t.cancelled} cancelled` : ''}`, ...shown],
      found,
      missing,
    };
  }
  const reasons = [];
  if (fileCount === 0) reasons.push('zero test files');
  if (t.tests === 0) reasons.push('zero tests executed');
  const silent = executed.perFile.filter((f) => f.tests === 0).map((f) => f.file);
  if (silent.length > 0 && t.tests > 0) reasons.push(`file(s) reported no tests: ${preview(silent)}`);
  if (t.skip > 0) reasons.push(`${t.skip} skipped test(s)`);
  if (t.todo > 0) reasons.push(`${t.todo} todo test(s)`);
  if (t.only > 0) reasons.push(`${t.only} use(s) of "only"`);
  if (t.tests < spec.minTests) reasons.push(`${t.tests} test(s) is below minTests ${spec.minTests}`);
  if (missing.length > 0) reasons.push(`missing required case ids: ${preview(missing)}`);
  return reasons.length > 0 ? { code: STATUS.VACUOUS, reasons, found, missing } : { code: STATUS.PASS, reasons: [], found, missing };
}

async function runSentinels(ctx) {
  const dir = join(ctx.workDir, 'sentinels');
  mkdirSync(dir, { recursive: true });
  const passFile = join(dir, 'pass.test.mjs');
  const skipFile = join(dir, 'skip.test.mjs');
  writeFileSync(passFile, ctx.sentinelSources.pass);
  writeFileSync(skipFile, ctx.sentinelSources.skip);
  const spec = { minTests: 1, requiredCases: [] };

  const passRun = await executeFiles(ctx, [passFile], SENTINEL_TIMEOUT_MS, ctx.childEnv);
  const passVerdict = classify(spec, passRun, 1);
  if (!(passVerdict.code === STATUS.PASS && passRun.totals.tests === 1 && passRun.totals.pass === 1)) {
    return `pass sentinel gave ${STATUS_NAMES[passVerdict.code]} tests=${passRun.totals.tests} pass=${passRun.totals.pass} (expected PASS with exactly one passing test)`;
  }
  const skipRun = await executeFiles(ctx, [skipFile], SENTINEL_TIMEOUT_MS, ctx.childEnv);
  const skipVerdict = classify(spec, skipRun, 1);
  if (!(skipVerdict.code === STATUS.VACUOUS && skipRun.totals.skip === 1 && skipRun.totals.fail === 0)) {
    return `skip sentinel gave ${STATUS_NAMES[skipVerdict.code]} skip=${skipRun.totals.skip} fail=${skipRun.totals.fail} (expected VACUOUS with one skip)`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

function labelSatisfied(requirement, value) {
  if (typeof value !== 'string' || value.trim() === '') return false;
  if (requirement === true) return true;
  if (typeof requirement === 'string') return value === requirement;
  if (Array.isArray(requirement)) return requirement.includes(value);
  if (requirement && typeof requirement.pattern === 'string') return new RegExp(requirement.pattern).test(value);
  return false;
}

function describeRequirement(requirement) {
  if (requirement === true) return 'must be a non-empty string';
  if (typeof requirement === 'string') return `must equal ${requirement}`;
  if (Array.isArray(requirement)) return `must be one of ${requirement.join('|')}`;
  return `must match /${requirement.pattern}/`;
}

/** Every string value in a parsed JSON document, at any depth (A-006 L1). */
function stringLeaves(value, where, out) {
  if (typeof value === 'string') out.push([where || '(root)', value]);
  else if (Array.isArray(value)) value.forEach((item, index) => stringLeaves(item, `${where}[${index}]`, out));
  else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) stringLeaves(item, where ? `${where}.${key}` : key, out);
  }
  return out;
}

function checkEvidence(ctx, def, runStartMs) {
  const checks = [];
  const missing = [];
  const false_claims = [];
  for (const ev of def.evidence) {
    const abs = join(ctx.root, ev.path);
    const check = { path: ev.path, ok: false, problems: [] };
    checks.push(check);
    const note = (problem, list = missing) => {
      check.problems.push(problem);
      list.push(`${ev.path}: ${problem}`);
    };
    const stat = lstatSafe(abs);
    if (!stat || !stat.isFile()) {
      note('absent (evidence must be written by this run)');
      continue;
    }
    if (stat.mtimeMs < runStartMs - 2000) {
      note('not written by this run');
      continue;
    }
    let raw;
    let data;
    try {
      raw = readFileSync(abs, 'utf8');
      data = JSON.parse(raw);
    } catch {
      note('not valid JSON');
      continue;
    }
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      note('not a JSON object');
      continue;
    }
    if (data.tree_digest !== ctx.treeDigest) note(`tree_digest ${JSON.stringify(data.tree_digest ?? null)} is stale (current ${ctx.treeDigest})`);
    for (const [label, requirement] of Object.entries(ev.labels ?? {})) {
      if (label === 'tree_digest') continue;
      if (!labelSatisfied(requirement, data[label])) note(`label ${label} ${describeRequirement(requirement)} (found ${JSON.stringify(data[label] ?? null)})`);
    }
    if (def.kind === 'acceptance') {
      for (const [where, value] of stringLeaves(data, '', [])) {
        const mock = KNOWN_MOCKS.find((name) => value.toLowerCase().includes(name));
        if (mock) note(`value at ${where} names the known mock ${mock}`, false_claims);
      }
    }
    if (ev.noCredentials) {
      for (const pattern of CREDENTIAL_PATTERNS) {
        if (pattern.test(raw)) note(`contains a credential-like value (pattern /${pattern.source.slice(0, 32)}/)`, false_claims);
      }
    }
    check.ok = check.problems.length === 0;
  }
  if (false_claims.length > 0) return { code: STATUS.FAIL, reasons: false_claims, checks };
  if (missing.length > 0) return { code: STATUS.EVIDENCE_MISSING, reasons: missing, checks };
  return { code: STATUS.PASS, reasons: [], checks };
}

function committedEvidenceProblem(ctx, ev) {
  const listed = spawnSync('git', ['ls-files', '--error-unmatch', '--', ev.path], { cwd: ctx.root, encoding: 'utf8' });
  if (listed.status !== 0) return `${ev.path} is not committed`;
  const diff = spawnSync('git', ['diff', '--quiet', 'HEAD', '--', ev.path], { cwd: ctx.root, encoding: 'utf8' });
  if (diff.status !== 0) return `${ev.path} differs from HEAD (commit it)`;
  let data;
  try {
    data = JSON.parse(readFileSync(join(ctx.root, ev.path), 'utf8'));
  } catch {
    return `${ev.path} is not valid JSON`;
  }
  if (data?.tree_digest !== ctx.treeDigest) return `${ev.path} tree_digest ${JSON.stringify(data?.tree_digest ?? null)} does not match the current tree digest ${ctx.treeDigest}`;
  for (const [label, requirement] of Object.entries(ev.labels ?? {})) {
    if (label === 'tree_digest') continue;
    if (!labelSatisfied(requirement, data[label])) return `${ev.path} label ${label} ${describeRequirement(requirement)}`;
  }
  return null;
}

function writeJson(path, data) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`);
}

function gateRecords(capabilities) {
  return EXTERNAL_GATES.map((gate) => {
    const probe = gate.capability ? capabilities.find((capability) => capability.name === gate.capability) : undefined;
    return {
      gate: gate.gate,
      status: gate.status,
      detail: gate.detail,
      ...(gate.capability ? { capability: gate.capability, probe: probe ? (probe.present ? 'present' : 'absent') : 'not-probed' } : {}),
    };
  });
}

// ---------------------------------------------------------------------------
// Mode execution
// ---------------------------------------------------------------------------

function outDir(ctx, name) {
  return join(ctx.root, '.verify-out', name);
}

function clearOutDir(ctx, name) {
  if (!MODE_NAME.test(name)) return;
  const dir = outDir(ctx, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
}

function writeResult(ctx, result) {
  if (!ctx.writeResults) return;
  const dirName = result.exit === STATUS.USAGE ? '_usage' : MODE_NAME.test(result.mode) ? result.mode : '_invalid';
  writeJson(join(ctx.root, '.verify-out', dirName, 'result.json'), result);
}

/**
 * A-006 M1: recompute the tree digest after the tests and before any evidence
 * or committed-receipt check. Results and evidence bind to one tree only.
 */
function treeChangedReason(ctx, result) {
  const after = computeTreeDigest(ctx.root);
  result.tree_digest_after = after;
  if (after === ctx.treeDigest) return null;
  return `tree changed during run: the tree digest was ${ctx.treeDigest} before the tests and ${after} after`;
}

async function runLeaf(ctx, name, def, { standalone }) {
  const result = newResult(name, def);
  result.tree_digest = ctx.treeDigest;
  clearOutDir(ctx, name);
  if (!standalone) {
    if (def.contract) {
      const problem = contractProblem(ctx.root);
      if (problem) return settle(result, STATUS.ENV_MISMATCH, problem);
    }
    result.capabilities = probeCapabilities(ctx, def.capabilities);
    const absent = absentReason(result.capabilities);
    if (absent) return settle(result, STATUS.CAPABILITY_ABSENT, absent);
  }
  const files = expandGlobs(ctx.root, def.files);
  result.file_list = files;
  result.files = files.length;
  if (files.length === 0) return settle(result, STATUS.VACUOUS, `zero test files: nothing matches ${def.files.join(', ')}`);

  const env = {
    ...ctx.childEnv,
    OPENSIG_VERIFY_MODE: name,
    OPENSIG_VERIFY_OUT: outDir(ctx, name),
    OPENSIG_VERIFY_TREE_DIGEST: ctx.treeDigest,
  };
  const runStartMs = Date.now();
  const executed = await executeFiles(
    ctx,
    files.map((file) => join(ctx.root, file)),
    ctx.fileTimeoutMs,
    env,
  );
  Object.assign(result, {
    tests: executed.totals.tests,
    pass: executed.totals.pass,
    fail: executed.totals.fail,
    skip: executed.totals.skip,
    todo: executed.totals.todo,
    cancelled: executed.totals.cancelled,
    only: executed.totals.only,
    per_file: executed.perFile,
    failures: executed.failures.slice(0, 50),
    passed_case_ids: [...executed.passedIds].sort(),
  });
  const verdict = classify(def, executed, files.length);
  result.cases = { found: verdict.found, required: def.requiredCases.length, missing: verdict.missing };
  if (verdict.code !== STATUS.PASS) return settle(result, verdict.code, ...verdict.reasons);
  const changed = treeChangedReason(ctx, result);
  if (changed) return settle(result, STATUS.EVIDENCE_MISSING, changed);
  if (def.evidence.length > 0) {
    const evidence = checkEvidence(ctx, def, runStartMs);
    result.evidence = evidence.checks;
    if (evidence.code !== STATUS.PASS) return settle(result, evidence.code, ...evidence.reasons);
  }
  return settle(result, STATUS.PASS);
}

async function runAggregate(ctx, name, def) {
  const result = newResult(name, def);
  result.tree_digest = ctx.treeDigest;
  clearOutDir(ctx, name);
  const covered = new Set();
  for (const component of def.components) {
    const member = ctx.registry[component];
    const componentResult = await runLeaf(ctx, component, member, { standalone: false });
    componentResult.finished_at = new Date().toISOString();
    writeResult(ctx, componentResult);
    ctx.log(`component ${formatStatusLine(componentResult)}`);
    result.components.push({
      mode: component,
      kind: member.kind,
      status: componentResult.status,
      exit: componentResult.exit,
      files: componentResult.files,
      tests: componentResult.tests,
      reasons: componentResult.reasons,
    });
    for (const key of ['files', 'tests', 'pass', 'fail', 'skip', 'todo', 'cancelled', 'only']) result[key] += componentResult[key];
    if (componentResult.exit !== STATUS.PASS) {
      return settle(
        result,
        componentResult.exit,
        `component ${component} returned ${componentResult.status}; the aggregate stops at the first non-PASS component`,
        ...componentResult.reasons.map((reason) => `${component}: ${reason}`),
      );
    }
    // A harness or contract component never counts as success-criterion evidence.
    if (!NON_EVIDENCE_KINDS.has(member.kind)) for (const id of componentResult.passed_case_ids) covered.add(id);
  }
  const changed = treeChangedReason(ctx, result);
  if (changed) return settle(result, STATUS.EVIDENCE_MISSING, changed);
  const missing = def.requiredCases.filter((id) => !covered.has(id));
  result.cases = { found: def.requiredCases.length - missing.length, required: def.requiredCases.length, missing };
  result.passed_case_ids = [...covered].sort();
  if (missing.length > 0) {
    return settle(result, STATUS.VACUOUS, `success-criterion coverage is missing ${missing.length} case id(s) (harness and contract components never count): ${preview(missing)}`);
  }
  for (const ev of def.evidence.filter((entry) => entry.receipt)) {
    writeJson(join(ctx.root, ev.path), {
      mode: name,
      release_ready: false,
      tree_digest: ctx.treeDigest,
      node: process.version,
      platform: `${process.platform}-${process.arch}`,
      generated_at: new Date().toISOString(),
      components: result.components.map(({ mode, kind, status, tests }) => ({ mode, kind, status, tests })),
      covered_cases: result.passed_case_ids,
      external_gates: gateRecords([]),
    });
  }
  for (const ev of def.evidence.filter((entry) => entry.committed)) {
    const problem = committedEvidenceProblem(ctx, ev);
    if (problem) return settle(result, STATUS.EVIDENCE_MISSING, problem);
  }
  return settle(result, STATUS.PASS);
}

function runRelease(ctx, name, def) {
  const result = newResult(name, def);
  result.tree_digest = ctx.treeDigest;
  clearOutDir(ctx, name);
  result.capabilities = probeCapabilities(ctx, def.capabilities);
  result.gates = gateRecords(result.capabilities);
  for (const ev of def.evidence.filter((entry) => entry.receipt)) {
    writeJson(join(ctx.root, ev.path), {
      mode: name,
      release_ready: false,
      tree_digest: ctx.treeDigest,
      node: process.version,
      platform: `${process.platform}-${process.arch}`,
      generated_at: new Date().toISOString(),
      components_not_run: def.components,
      gates: result.gates,
    });
  }
  const open = result.gates.filter((gate) => gate.status !== 'CLOSED');
  return settle(
    result,
    STATUS.FAIL,
    `release gate: ${open.length} gate(s) are not closed, so the release gate fails: ${open.map((gate) => `${gate.gate} ${gate.status}`).join(', ')}`,
    `components (${def.components.join(', ')}) were not run: no local result can close an external gate`,
  );
}

async function runModeInner(ctx, name) {
  if (ctx.registry === null) {
    const loaded = await import('./verify-modes.mjs');
    ctx.registry = loaded.MODES;
  }
  if (typeof name !== 'string' || !Object.hasOwn(ctx.registry, name)) {
    return settle(newResult(sanitizeModeName(name), null), STATUS.USAGE, `unknown mode ${sanitizeModeName(name)}`);
  }
  const def = ctx.registry[name];
  const result = newResult(name, def);
  clearOutDir(ctx, name);

  const registryProblems = validateRegistry(ctx.registry, ctx.modeNames);
  if (registryProblems.length > 0) return settle(result, STATUS.RUNNER_ERROR, ...registryProblems.map((p) => `registry: ${p}`));
  const claimProblems = findClaimProblems(ctx.root, ctx.registry);
  if (claimProblems.length > 0) return settle(result, STATUS.RUNNER_ERROR, ...claimProblems.map((p) => `registry completeness: ${p}`));

  const envProblems = environmentProblems(ctx);
  if (def.contract) {
    const problem = contractProblem(ctx.root);
    if (problem) envProblems.push(problem);
  }
  if (envProblems.length > 0) return settle(result, STATUS.ENV_MISMATCH, ...envProblems);

  ctx.treeDigest = computeTreeDigest(ctx.root);
  result.tree_digest = ctx.treeDigest;
  ctx.workDir = mkdtempSync(join(tmpdir(), 'opensig-verify-'));
  ctx.driverPath = join(ctx.workDir, 'driver.mjs');
  writeFileSync(ctx.driverPath, DRIVER_SOURCE);

  const sentinelProblem = await runSentinels(ctx);
  if (sentinelProblem) return settle(result, STATUS.RUNNER_ERROR, `sentinel control failed: ${sentinelProblem}`);

  if (def.kind === 'release') return runRelease(ctx, name, def);

  result.capabilities = probeCapabilities(ctx, def.capabilities);
  const absent = absentReason(result.capabilities);
  if (absent) return settle(result, STATUS.CAPABILITY_ABSENT, absent);

  if (def.typecheck) {
    const typecheck = runTypecheck(ctx);
    if (!typecheck.ok) return settle(result, STATUS.FAIL, `typecheck failed: ${typecheck.detail}`);
  }

  const outcome = def.kind === 'aggregate' ? await runAggregate(ctx, name, def) : await runLeaf(ctx, name, def, { standalone: true });
  outcome.capabilities = result.capabilities;
  return outcome;
}

/**
 * Run one mode. Options exist for the self-tests (synthetic registries in temp
 * roots); the CLI passes none of them and exposes no override.
 */
export async function runMode(name, options = {}) {
  const env = options.env ?? process.env;
  const ctx = {
    root: resolve(options.root ?? REPO_ROOT),
    registry: options.registry ?? null,
    modeNames: options.modeNames ?? FROZEN_MODE_NAMES,
    env,
    childEnv: childEnvFrom(env),
    execArgv: options.execArgv ?? process.execArgv,
    fileTimeoutMs: options.fileTimeoutMs ?? FILE_TIMEOUT_MS,
    sentinelSources: { pass: SENTINEL_PASS, skip: SENTINEL_SKIP, ...(options.sentinelSources ?? {}) },
    writeResults: options.writeResults ?? true,
    log: options.log ?? (() => {}),
    treeDigest: null,
    workDir: null,
    driverPath: null,
  };
  let result;
  try {
    result = await runModeInner(ctx, name);
  } catch (error) {
    result = settle(newResult(sanitizeModeName(name), null), STATUS.RUNNER_ERROR, `internal error: ${error?.stack ?? error}`);
  } finally {
    if (ctx.workDir) rmSync(ctx.workDir, { recursive: true, force: true });
  }
  result.finished_at = new Date().toISOString();
  try {
    writeResult(ctx, result);
  } catch (error) {
    settle(result, STATUS.RUNNER_ERROR, `cannot write result.json: ${error.message}`);
  }
  return result;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function emit(result) {
  for (const reason of result.reasons) process.stderr.write(`verify: - ${reason}\n`);
  process.exitCode = result.exit; // set before writing (A-006 L5)
  process.stdout.write(`${formatStatusLine(result)}\n`, () => process.exit(result.exit));
}

async function main(argv) {
  const parsed = parseArgs(argv);
  if (parsed.error) {
    const result = settle(newResult(sanitizeModeName(parsed.mode ?? '-'), null), STATUS.USAGE, parsed.error);
    result.finished_at = new Date().toISOString();
    try {
      writeJson(join(REPO_ROOT, '.verify-out', '_usage', 'result.json'), result);
    } catch {
      // A read-only tree does not change the USAGE outcome.
    }
    emit(result);
    return;
  }
  const onSignal = (signal) => {
    for (const pid of liveGroups) killGroup(pid);
    emit(settle(newResult(parsed.mode, null), STATUS.RUNNER_ERROR, `interrupted by ${signal}`));
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  const result = await runMode(parsed.mode, { log: (line) => process.stderr.write(`verify: ${line}\n`) });
  emit(result);
}

function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  main(process.argv.slice(2)).catch((error) => {
    emit(settle(newResult('-', null), STATUS.RUNNER_ERROR, `internal error: ${error?.stack ?? error}`));
  });
}
