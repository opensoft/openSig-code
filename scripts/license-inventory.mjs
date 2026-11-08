#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig license inventory and SBOM (T002): the strict application-dependency gate.
//
//   node scripts/license-inventory.mjs [--root DIR] [--out DIR] [--write-notice]
//
// Classification. Every package in package-lock.json is `shipped` or
// `non-shipped`. Shipped means the production closure (dependencies and
// optionalDependencies of package.json, followed through each package's
// dependencies, optionalDependencies and peerDependencies by Node module
// resolution over the lockfile) plus every package that owns a file copied
// byte-for-byte into dist/. Everything else (devDependencies) is non-shipped.
// The closure is computed here; the lockfile's own `dev` flags are not trusted.
//
// Gate. Each shipped package's SPDX expression must satisfy
// scripts/license-policy.json (exactly MIT and Apache-2.0): an OR passes when
// one alternative is fully allowed, an AND needs every term allowed, WITH
// exceptions and `+` are not allowed. Missing or unknown licenses fail. A
// shipped package may carry at most one root license file (LICENSE*, LICENCE*
// or COPYING*) and at most one root NOTICE*; any other such file anywhere in
// the package is an extra license file and fails.
//
// Outputs (in --out, default .verify-out/license-inventory/): sbom.cdx.json
// (CycloneDX 1.6), inventory.json, and platform-inventory.json (status
// POLICY-PENDING). NOTICE at the repository root is regenerated with
// --write-notice; without it, a stale NOTICE fails the run.
//
// Exit status: 0 gate passes and NOTICE is current, 1 policy failure or stale
// NOTICE, 2 usage error or an incomplete or inconsistent install.

import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { collectPlatformInventory, PLATFORM_STATUS, writePlatformInventory } from './platform-inventory.mjs';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..');
export const POLICY_PATH = join(SCRIPT_DIR, 'license-policy.json');

export class InventoryError extends Error {}

// ---------------------------------------------------------------------------
// Policy and SPDX expressions
// ---------------------------------------------------------------------------

export function loadPolicy(path = POLICY_PATH) {
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    throw new InventoryError(`license policy ${path} is missing`);
  }
  const policy = JSON.parse(raw);
  if (!Array.isArray(policy.allowed) || policy.allowed.length === 0 || !policy.allowed.every((id) => typeof id === 'string')) {
    throw new InventoryError('license policy must list allowed SPDX identifiers');
  }
  return {
    allowed: [...policy.allowed],
    allowedLower: new Set(policy.allowed.map((id) => id.toLowerCase())),
    allowedExceptions: new Set((policy.allowedExceptions ?? []).map((id) => String(id).toLowerCase())),
    sha256: createHash('sha256').update(raw).digest('hex'),
  };
}

const OPERATORS = new Set(['AND', 'OR', 'WITH']);
const LICENSE_ID = /^[A-Za-z0-9][A-Za-z0-9.-]*\+?$/;
const LICENSE_REF = /^(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$/;

function tokenize(text) {
  const tokens = [];
  const pattern = /\s*(\(|\)|[^\s()]+)/y;
  let pos = 0;
  for (;;) {
    pattern.lastIndex = pos; // a failed sticky match resets lastIndex, so track the position here
    const match = pattern.exec(text);
    if (match === null) break;
    tokens.push(match[1]);
    pos = pattern.lastIndex;
  }
  if (text.slice(pos).trim() !== '') throw new SyntaxError('unexpected characters');
  return tokens;
}

/** Parse an SPDX license expression (WITH binds tighter than AND, AND than OR). */
export function parseSpdx(text) {
  if (typeof text !== 'string' || text.trim() === '') throw new SyntaxError('empty license expression');
  const tokens = tokenize(text.trim());
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];
  const isLicense = (token) => token !== undefined && !OPERATORS.has(token) && (LICENSE_ID.test(token) || LICENSE_REF.test(token));

  function primary() {
    const token = next();
    if (token === '(') {
      const inner = orExpr();
      if (next() !== ')') throw new SyntaxError('missing closing parenthesis');
      return inner;
    }
    if (!isLicense(token)) throw new SyntaxError(`expected a license identifier, found ${token ?? 'end of expression'}`);
    return { license: token };
  }
  function withExpr() {
    const left = primary();
    if (peek() !== 'WITH') return left;
    next();
    if (!left.license) throw new SyntaxError('WITH must follow a single license identifier');
    const exception = next();
    if (!isLicense(exception)) throw new SyntaxError('WITH needs an exception identifier');
    return { op: 'WITH', license: left.license, exception };
  }
  function andExpr() {
    let left = withExpr();
    while (peek() === 'AND') {
      next();
      left = { op: 'AND', left, right: withExpr() };
    }
    return left;
  }
  function orExpr() {
    let left = andExpr();
    while (peek() === 'OR') {
      next();
      left = { op: 'OR', left, right: andExpr() };
    }
    return left;
  }
  const tree = orExpr();
  if (pos !== tokens.length) throw new SyntaxError(`unexpected token ${tokens[pos]}`);
  return tree;
}

function hasReference(node) {
  if (node.op === 'AND' || node.op === 'OR') return hasReference(node.left) || hasReference(node.right);
  return LICENSE_REF.test(node.license);
}

function satisfies(node, policy) {
  if (node.op === 'OR') return satisfies(node.left, policy) || satisfies(node.right, policy);
  if (node.op === 'AND') return satisfies(node.left, policy) && satisfies(node.right, policy);
  const id = node.license;
  if (id.endsWith('+') || LICENSE_REF.test(id) || !policy.allowedLower.has(id.toLowerCase())) return false;
  if (node.op === 'WITH') return policy.allowedExceptions.has(node.exception.toLowerCase());
  return true;
}

/**
 * Evaluate a declared license against the policy.
 * Returns { expression, status: allowed | disallowed | unknown | missing, detail }.
 */
export function evaluateLicense(value, policy) {
  if (value === undefined || value === null || (typeof value === 'string' && value.trim() === '')) {
    return { expression: null, status: 'missing', detail: 'no license declared' };
  }
  if (typeof value !== 'string') return { expression: null, status: 'unknown', detail: 'license field is not a string' };
  const expression = value.trim();
  if (/^SEE LICEN[CS]E IN\b/i.test(expression)) return { expression, status: 'unknown', detail: 'license deferred to a file' };
  if (/^UNLICENSED$/i.test(expression)) return { expression, status: 'unknown', detail: 'UNLICENSED (no license granted)' };
  let tree;
  try {
    tree = parseSpdx(expression);
  } catch (error) {
    return { expression, status: 'unknown', detail: `not a valid SPDX expression: ${error.message}` };
  }
  if (hasReference(tree) && !satisfies(tree, policy)) return { expression, status: 'unknown', detail: 'custom LicenseRef' };
  return satisfies(tree, policy)
    ? { expression, status: 'allowed', detail: null }
    : { expression, status: 'disallowed', detail: `does not satisfy ${policy.allowed.join(' / ')}` };
}

function declaredLicense(pkg) {
  if (typeof pkg.license === 'string') return pkg.license;
  if (pkg.license && typeof pkg.license === 'object' && typeof pkg.license.type === 'string') return pkg.license.type;
  if (Array.isArray(pkg.licenses) && pkg.licenses.length > 0) {
    const types = pkg.licenses.map((entry) => (typeof entry === 'string' ? entry : entry?.type));
    if (types.every((type) => typeof type === 'string' && type !== '')) return types.length === 1 ? types[0] : `(${types.join(' OR ')})`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Lockfile, closure and package files
// ---------------------------------------------------------------------------

function readJsonFile(path, what) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new InventoryError(`${what} is missing`);
  }
  try {
    return { data: JSON.parse(text), text };
  } catch {
    throw new InventoryError(`${what} is not valid JSON`);
  }
}

function packageName(path) {
  return path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
}

/** Node module resolution over lockfile paths. */
function resolveDependency(packages, fromPath, name) {
  let base = fromPath;
  for (;;) {
    const candidate = base === '' ? `node_modules/${name}` : `${base}/node_modules/${name}`;
    if (Object.hasOwn(packages, candidate)) return candidate;
    if (base === '') return null;
    const index = base.lastIndexOf('/node_modules/');
    base = index === -1 ? '' : base.slice(0, index);
  }
}

function dependencyNames(entry, { includePeers }) {
  const names = [];
  for (const name of Object.keys(entry.dependencies ?? {})) names.push([name, false]);
  for (const name of Object.keys(entry.optionalDependencies ?? {})) names.push([name, true]);
  if (includePeers) {
    const meta = entry.peerDependenciesMeta ?? {};
    for (const name of Object.keys(entry.peerDependencies ?? {})) names.push([name, meta[name]?.optional === true]);
  }
  return names;
}

function productionClosure(rootPkg, packages) {
  const shipped = new Set();
  const queue = [];
  const visit = (fromPath, entry, label, includePeers) => {
    for (const [name, optional] of dependencyNames(entry, { includePeers })) {
      const path = resolveDependency(packages, fromPath, name);
      if (path === null) {
        if (optional) continue;
        throw new InventoryError(`${label} depends on ${name}, which package-lock.json does not contain`);
      }
      if (packages[path].link) throw new InventoryError(`${path} is a linked package, which the inventory does not support`);
      if (!shipped.has(path)) {
        shipped.add(path);
        queue.push(path);
      }
    }
  };
  visit('', rootPkg, 'package.json', false);
  while (queue.length > 0) {
    const path = queue.shift();
    visit(path, packages[path], path, true);
  }
  return shipped;
}

const LICENSE_FILE = /^(?:licen[cs]e|notice|copying)/i;
const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx', '.map', '.json']);

function walkPackage(dir, rel, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const path = rel === '' ? entry.name : `${rel}/${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules') walkPackage(join(dir, entry.name), path, out);
    } else if (entry.isFile()) {
      out.push(path);
    }
  }
}

/** License-like files of an installed package, split into its own texts and extras. */
function licenseFiles(dir) {
  const files = [];
  walkPackage(dir, '', files);
  const matching = files.filter((file) => LICENSE_FILE.test(basename(file)) && !CODE_EXTENSIONS.has(extname(file).toLowerCase())).sort();
  const root = matching.filter((file) => !file.includes('/'));
  const ownLicense = root.find((file) => !/^notice/i.test(file)) ?? null;
  const ownNotice = root.find((file) => /^notice/i.test(file)) ?? null;
  const extra = matching.filter((file) => file !== ownLicense && file !== ownNotice);
  return { all: matching, ownLicense, ownNotice, extra, files };
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function walkAll(dir, rel, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const path = rel === '' ? entry.name : `${rel}/${entry.name}`;
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) walkAll(abs, path, out);
    else if (entry.isFile() || entry.isSymbolicLink()) out.push(path);
  }
}

/** Packages owning a file copied byte-for-byte into dist/: Map(lockPath -> [dist files]). */
function distAssetOwners(root, records) {
  const owners = new Map();
  const distFiles = [];
  walkAll(join(root, 'dist'), '', distFiles);
  if (distFiles.length === 0) return owners;
  const byDigest = new Map();
  for (const record of records) {
    if (!record.installed) continue;
    for (const file of record.files) {
      const abs = join(root, record.path, file);
      let size;
      try {
        size = statSync(abs).size;
      } catch {
        continue;
      }
      if (size === 0) continue;
      const digest = sha256File(abs);
      if (!byDigest.has(digest)) byDigest.set(digest, new Set());
      byDigest.get(digest).add(record.path);
    }
  }
  for (const file of distFiles.sort()) {
    let digest;
    try {
      if (statSync(join(root, 'dist', file)).size === 0) continue;
      digest = sha256File(join(root, 'dist', file));
    } catch {
      continue;
    }
    for (const path of byDigest.get(digest) ?? []) {
      if (!owners.has(path)) owners.set(path, []);
      owners.get(path).push(`dist/${file}`);
    }
  }
  return owners;
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

/**
 * Build the inventory for the project at `root`.
 * Throws InventoryError for an incomplete or inconsistent install.
 */
export function buildInventory(root = REPO_ROOT, { policy = loadPolicy() } = {}) {
  const { data: rootPkg } = readJsonFile(join(root, 'package.json'), 'package.json');
  const { data: lock, text: lockText } = readJsonFile(join(root, 'package-lock.json'), 'package-lock.json');
  if (!lock || typeof lock.packages !== 'object' || lock.packages === null || !(lock.lockfileVersion >= 2)) {
    throw new InventoryError('package-lock.json must be lockfileVersion 2 or 3 with a "packages" map');
  }
  const packages = lock.packages;
  const closure = productionClosure(rootPkg, packages);

  const records = [];
  for (const path of Object.keys(packages).sort()) {
    if (path === '') continue;
    const entry = packages[path];
    if (entry.link) throw new InventoryError(`${path} is a linked package, which the inventory does not support`);
    const dir = join(root, path);
    let installed = null;
    try {
      installed = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    } catch {
      installed = null;
    }
    if (installed === null && !entry.optional) throw new InventoryError(`${path} is locked but not installed; run npm ci`);
    if (installed !== null && installed.version !== entry.version) {
      throw new InventoryError(`${path} is installed as ${installed.version} but locked as ${entry.version}`);
    }
    const files = installed ? licenseFiles(dir) : { all: [], ownLicense: null, ownNotice: null, extra: [], files: [] };
    const license = evaluateLicense(installed ? declaredLicense(installed) : entry.license ?? null, policy);
    records.push({
      path,
      name: installed?.name ?? entry.name ?? packageName(path),
      version: entry.version,
      installed: installed !== null,
      classification: closure.has(path) ? 'shipped' : 'non-shipped',
      reasons: closure.has(path) ? ['production-closure'] : ['not in the production closure (devDependencies)'],
      license: license.expression,
      policy: license.status,
      policy_detail: license.detail,
      license_files: files.all,
      own_license_file: files.ownLicense,
      own_notice_file: files.ownNotice,
      extra_license_files: files.extra,
      lockfile_dev: entry.dev === true,
      integrity: entry.integrity ?? null,
      resolved: entry.resolved ?? null,
      files: files.files,
    });
  }

  for (const [path, distFiles] of distAssetOwners(root, records)) {
    const record = records.find((candidate) => candidate.path === path);
    if (record.classification !== 'shipped') {
      record.classification = 'shipped';
      record.reasons = [];
    }
    for (const file of distFiles) record.reasons.push(`asset copied into ${file}`);
  }

  const findings = [];
  for (const record of records.filter((r) => r.classification === 'shipped')) {
    if (record.policy !== 'allowed') findings.push({ rule: `license-${record.policy}`, record, detail: record.policy_detail });
    for (const file of record.extra_license_files) findings.push({ rule: 'extra-license-file', record, file, detail: 'separately licensed material inside a shipped package' });
  }
  for (const record of records) delete record.files;

  return {
    root,
    rootPkg,
    packages,
    records,
    findings,
    gate: findings.length === 0 ? 'PASS' : 'FAIL',
    policy,
    lockfileSha256: createHash('sha256').update(lockText).digest('hex'),
  };
}

// ---------------------------------------------------------------------------
// NOTICE and CycloneDX
// ---------------------------------------------------------------------------

function readText(path) {
  try {
    return readFileSync(path, 'utf8').replace(/\r\n/g, '\n').trimEnd();
  } catch {
    return null;
  }
}

/** Deterministic NOTICE text for the shipped materials. */
export function renderNotice(inventory) {
  const lines = [
    'openSig',
    'Copyright 2026 The openSig Authors',
    '',
    'Licensed under the Apache License, Version 2.0 (see LICENSE).',
    '',
    'Third-party materials shipped in this distribution',
    '--------------------------------------------------',
    '',
  ];
  const shipped = inventory.records
    .filter((record) => record.classification === 'shipped')
    .sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`) || a.path.localeCompare(b.path));
  if (shipped.length === 0) {
    lines.push(
      'None. The shipped npm closure is empty and no third-party asset is copied into',
      'dist/. Development and test tools are not distributed; they are inventoried as',
      'non-shipped in the SBOM and in docs/qualification.md.',
    );
  }
  for (const record of shipped) {
    lines.push(`${record.name} ${record.version} (${record.license ?? 'no license declared'})`, `  location: ${record.path}`);
    for (const file of [record.own_notice_file, record.own_license_file]) {
      if (!file) continue;
      const text = readText(join(inventory.root, record.path, file));
      if (text === null) continue;
      lines.push(`  --- ${file} ---`, ...text.split('\n').map((line) => (line === '' ? '' : `  ${line}`)));
    }
    lines.push('');
  }
  return `${lines.join('\n').trimEnd()}\n`;
}

function purl(name, version) {
  const encoded = name.startsWith('@') ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encoded}@${version}`;
}

function cdxLicenses(expression) {
  if (!expression) return undefined;
  return LICENSE_ID.test(expression) && !expression.endsWith('+') ? [{ license: { id: expression } }] : [{ expression }];
}

function integrityHashes(integrity) {
  const match = /^sha512-([A-Za-z0-9+/=]+)$/.exec(integrity ?? '');
  return match ? [{ alg: 'SHA-512', content: Buffer.from(match[1], 'base64').toString('hex') }] : undefined;
}

function deterministicUuid(seed) {
  const hex = createHash('sha256').update(seed).digest('hex');
  const variant = '89ab'[parseInt(hex[16], 16) % 4];
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

/** CycloneDX 1.6 JSON SBOM for every locked package, with its classification. */
export function renderCycloneDx(inventory) {
  const ref = (path) => `npm:${path}`;
  const components = inventory.records.map((record) => {
    const scoped = record.name.startsWith('@') ? record.name.split('/') : null;
    const component = {
      type: 'library',
      'bom-ref': ref(record.path),
      ...(scoped ? { group: scoped[0], name: scoped.slice(1).join('/') } : { name: record.name }),
      version: record.version,
      purl: purl(record.name, record.version),
      scope: record.classification === 'shipped' ? 'required' : 'excluded',
      licenses: cdxLicenses(record.license),
      hashes: integrityHashes(record.integrity),
      properties: [
        { name: 'opensig:classification', value: record.classification },
        { name: 'opensig:license-policy', value: record.policy },
        { name: 'opensig:lockfile-path', value: record.path },
        ...record.reasons.map((reason) => ({ name: 'opensig:classification-reason', value: reason })),
        ...record.extra_license_files.map((file) => ({ name: 'opensig:extra-license-file', value: file })),
      ],
    };
    for (const key of Object.keys(component)) if (component[key] === undefined) delete component[key];
    return component;
  });
  const dependencies = [];
  const direct = [
    ...Object.keys(inventory.rootPkg.dependencies ?? {}),
    ...Object.keys(inventory.rootPkg.optionalDependencies ?? {}),
    ...Object.keys(inventory.rootPkg.devDependencies ?? {}),
  ];
  dependencies.push({
    ref: 'root',
    dependsOn: [...new Set(direct.map((name) => resolveDependency(inventory.packages, '', name)).filter(Boolean))].sort().map(ref),
  });
  for (const record of inventory.records) {
    const entry = inventory.packages[record.path];
    const dependsOn = dependencyNames(entry, { includePeers: true })
      .map(([name]) => resolveDependency(inventory.packages, record.path, name))
      .filter(Boolean);
    dependencies.push({ ref: ref(record.path), dependsOn: [...new Set(dependsOn)].sort().map(ref) });
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${deterministicUuid(`${inventory.lockfileSha256}:${inventory.policy.sha256}:${inventory.gate}`)}`,
    version: 1,
    metadata: {
      tools: { components: [{ type: 'application', name: 'opensig-license-inventory', version: '1' }] },
      component: {
        type: 'application',
        'bom-ref': 'root',
        name: inventory.rootPkg.name ?? 'opensig',
        version: inventory.rootPkg.version ?? '0.0.0',
        ...(inventory.rootPkg.license ? { licenses: cdxLicenses(inventory.rootPkg.license) } : {}),
      },
      properties: [
        { name: 'opensig:lockfile-sha256', value: inventory.lockfileSha256 },
        { name: 'opensig:license-policy-sha256', value: inventory.policy.sha256 },
        { name: 'opensig:application-gate', value: inventory.gate },
        { name: 'opensig:platform-status', value: PLATFORM_STATUS },
      ],
    },
    components,
    dependencies,
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const options = { root: REPO_ROOT, out: null, writeNotice: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if ((arg === '--root' || arg === '--out') && i + 1 < argv.length) options[arg.slice(2)] = resolve(argv[(i += 1)]);
    else if (arg === '--write-notice') options.writeNotice = true;
    else return { error: `unknown or incomplete argument ${arg}` };
  }
  options.out ??= join(options.root, '.verify-out', 'license-inventory');
  return options;
}

function writeJson(path, data) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`);
}

function describe(record) {
  return `package=${record.name}@${record.version} path=${record.path}`;
}

function main(argv) {
  const options = parseArgs(argv);
  if (options.error) {
    process.stderr.write(`license-inventory: ${options.error}\nusage: node scripts/license-inventory.mjs [--root DIR] [--out DIR] [--write-notice]\n`);
    process.stdout.write('license-inventory: ERROR usage\n');
    process.exitCode = 2;
    return;
  }
  let inventory;
  try {
    inventory = buildInventory(options.root);
  } catch (error) {
    if (!(error instanceof InventoryError)) throw error;
    process.stdout.write(`license-inventory: ERROR ${error.message}\n`);
    process.exitCode = 2;
    return;
  }

  const findings = [...inventory.findings];
  const noticePath = join(options.root, 'NOTICE');
  const notice = renderNotice(inventory);
  let noticeStatus;
  if (options.writeNotice) {
    writeFileSync(noticePath, notice);
    noticeStatus = 'written';
  } else {
    noticeStatus = readText(noticePath) === notice.trimEnd() ? 'current' : 'stale';
    if (noticeStatus === 'stale') findings.push({ rule: 'notice-stale', record: null, detail: 'NOTICE differs from the regenerated text; run with --write-notice' });
  }
  const gate = findings.length === 0 ? 'PASS' : 'FAIL';

  const platform = collectPlatformInventory(options.root);
  writePlatformInventory(options.out, platform);
  writeJson(join(options.out, 'sbom.cdx.json'), renderCycloneDx(inventory));
  writeJson(join(options.out, 'inventory.json'), {
    kind: 'opensig-license-inventory',
    application_gate: gate,
    platform_status: platform.status,
    policy: { file: 'scripts/license-policy.json', allowed: inventory.policy.allowed, sha256: inventory.policy.sha256 },
    lockfile_sha256: inventory.lockfileSha256,
    notice: { path: 'NOTICE', status: noticeStatus },
    shipped: inventory.records.filter((r) => r.classification === 'shipped').length,
    non_shipped: inventory.records.filter((r) => r.classification === 'non-shipped').length,
    packages: inventory.records,
    findings: findings.map(({ record, ...rest }) => ({ ...rest, package: record ? `${record.name}@${record.version}` : null, path: record?.path ?? null })),
  });

  for (const record of inventory.records) {
    process.stdout.write(
      `license-inventory: ${describe(record)} class=${record.classification} license=${JSON.stringify(record.license ?? 'none')} policy=${record.policy}\n`,
    );
  }
  for (const finding of findings) {
    const where = finding.record ? ` ${describe(finding.record)}` : '';
    const file = finding.file ? ` file=${finding.file}` : '';
    process.stdout.write(`license-inventory: FAIL rule=${finding.rule}${where}${file}\n`);
  }
  const shipped = inventory.records.filter((r) => r.classification === 'shipped').length;
  const summary = `shipped=${shipped} non-shipped=${inventory.records.length - shipped} notice=${noticeStatus} platform=${platform.status}`;
  process.stdout.write(
    gate === 'PASS'
      ? `license-inventory: PASS application-gate ${summary}\n`
      : `license-inventory: FAIL application-gate findings=${findings.length} ${summary}\n`,
  );
  process.exitCode = gate === 'PASS' ? 0 : 1;
}

function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) main(process.argv.slice(2));
