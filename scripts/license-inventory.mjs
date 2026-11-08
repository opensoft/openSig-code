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
// legacy `licenses` array with several entries means all of them (AND), and
// a package declaring both `license` and `licenses` is held to both.
//
// License texts. A license text is any file whose name contains licence,
// license, notice, copying, copyright or third-party/thirdparty (source-code
// files such as license.js excepted), and any file under a licenses/ or
// licences/ directory. A shipped package may carry one root license file
// (LICENSE*, LICENCE* or COPYING*) and one root NOTICE*; a package declaring
// exactly MIT and Apache-2.0 (with OR or AND) may carry one root license file
// for each. Every other license text anywhere in the package (a bundle's
// .LICENSE sidecar, ThirdPartyNotices.txt, licenses/OFL.txt, fonts/COPYRIGHT)
// is an extra license file and fails. A root license text that is recognisably
// a different license from the declared one fails as a text mismatch.
//
// dist/. Every regular file in dist/ is compared with the installed package
// files. A symbolic link anywhere in dist/ fails the gate; read errors stop the
// run (exit 2) rather than being skipped.
//
// Outputs (in --out, default .verify-out/license-inventory/): sbom.cdx.json
// (CycloneDX 1.6), inventory.json, and platform-inventory.json (status
// POLICY-PENDING). Both files carry the same application-gate value, NOTICE
// check included, and the SBOM serial number covers every classification.
// NOTICE at the repository root is regenerated with --write-notice; without
// it, a stale NOTICE fails the run.
//
// Exit status: 0 gate passes and NOTICE is current, 1 policy failure or stale
// NOTICE, 2 usage error, a read error, or an incomplete or inconsistent install.

import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
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

/**
 * The declared license of an installed package.json. The legacy `licenses`
 * array lists licenses that all apply, so several entries are joined with AND
 * (never OR); an entry that is not a non-empty string or { type } makes the
 * declaration unknown. A package declaring both `license` and `licenses` is
 * held to both (AND).
 */
function declaredLicense(pkg) {
  let primary = null;
  if (typeof pkg.license === 'string') primary = pkg.license.trim() === '' ? null : pkg.license;
  else if (pkg.license && typeof pkg.license === 'object' && typeof pkg.license.type === 'string') primary = pkg.license.type;
  else if (pkg.license !== undefined && pkg.license !== null) return { unknown: 'license field is neither a string nor { type }' };
  let legacy = null;
  if (Array.isArray(pkg.licenses) && pkg.licenses.length > 0) {
    const types = pkg.licenses.map((entry) => (typeof entry === 'string' ? entry : entry?.type));
    if (!types.every((type) => typeof type === 'string' && type.trim() !== '')) return { unknown: 'legacy licenses array has an unreadable entry' };
    legacy = types.length === 1 ? types[0].trim() : types.map((type) => `(${type.trim()})`).join(' AND ');
  } else if (pkg.licenses !== undefined && pkg.licenses !== null && !(Array.isArray(pkg.licenses) && pkg.licenses.length === 0)) {
    return { unknown: 'legacy licenses field is not an array' };
  }
  if (primary !== null && legacy !== null && primary.trim() !== legacy) return `(${primary.trim()}) AND (${legacy})`;
  return primary ?? legacy;
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

// A license, notice or copyright text: the file name contains one of these
// words (source-code files such as license.js excepted), or the file lies
// under a licenses/ (licences/) directory.
const LICENSE_NAME = /licen[cs]e|notice|copying|copyright|third[-_ ]?party/i;
const LICENSE_DIRECTORY = /^licen[cs]es$/i;
const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx', '.map']);
// The package's own texts: at most one root license file and one root NOTICE.
const ROOT_LICENSE = /^(?:licen[cs]e|copying)/i;
const ROOT_NOTICE = /^notice/i;
const THIRD_PARTY = /third[-_ ]?party/i;

export function isLicenseText(file) {
  const parts = file.split('/');
  if (parts.slice(0, -1).some((dir) => LICENSE_DIRECTORY.test(dir))) return true;
  return LICENSE_NAME.test(parts.at(-1)) && !CODE_EXTENSIONS.has(extname(file).toLowerCase());
}

// Recognisable license texts, matched on lower-cased text with whitespace
// collapsed. `ids` are the declared SPDX identifiers (lower case, prefix match
// when ending in "-") that agree with the text.
const LICENSE_TEXTS = [
  { family: 'Apache-2.0', ids: ['apache-2.0'], test: (t) => t.includes('apache license') && t.includes('version 2.0') },
  {
    family: 'MIT',
    ids: ['mit'],
    test: (t) => t.includes('permission is hereby granted, free of charge, to any person obtaining a copy') && t.includes('the above copyright notice and this permission notice shall be included'),
  },
  {
    family: 'MIT-0',
    ids: ['mit-0'],
    test: (t) => t.includes('permission is hereby granted, free of charge, to any person obtaining a copy') && !t.includes('the above copyright notice and this permission notice shall be included'),
  },
  { family: 'ISC-or-0BSD', ids: ['isc', '0bsd'], test: (t) => t.includes('permission to use, copy, modify, and/or distribute this software for any purpose') },
  { family: 'BSD', ids: ['bsd-'], test: (t) => t.includes('redistribution and use in source and binary forms') },
  { family: 'AGPL', ids: ['agpl-'], test: (t) => t.includes('gnu affero general public license') },
  { family: 'LGPL', ids: ['lgpl-'], test: (t) => t.includes('gnu lesser general public license') || t.includes('gnu library general public license') },
  {
    family: 'GPL',
    ids: ['gpl-'],
    test: (t) => t.includes('gnu general public license') && !t.includes('gnu lesser general public license') && !t.includes('gnu affero general public license'),
  },
  { family: 'MPL', ids: ['mpl-'], test: (t) => t.includes('mozilla public license') },
  { family: 'BlueOak', ids: ['blueoak-'], test: (t) => t.includes('blue oak model license') },
  { family: 'Unlicense', ids: ['unlicense'], test: (t) => t.includes('this is free and unencumbered software released into the public domain') },
  { family: 'CC0', ids: ['cc0-'], test: (t) => t.includes('cc0 1.0 universal') },
  { family: 'Zlib', ids: ['zlib'], test: (t) => t.includes("this software is provided 'as-is'") && t.includes('altered source versions must be plainly marked') },
  { family: 'OFL', ids: ['ofl-'], test: (t) => t.includes('sil open font license') },
];

/** License families recognisable in a text file (an empty list when none is recognised). */
export function recognizeLicenseText(text) {
  const normalized = text.toLowerCase().replace(/\s+/g, ' ');
  return LICENSE_TEXTS.filter((entry) => entry.test(normalized)).map((entry) => entry.family);
}

function familyAgrees(family, declaredIds) {
  const { ids } = LICENSE_TEXTS.find((entry) => entry.family === family);
  return declaredIds.some((id) => ids.some((accepted) => (accepted.endsWith('-') ? id.startsWith(accepted) : id === accepted)));
}

/** Lower-cased license identifiers of a parsed SPDX tree, or null if it does not parse. */
function declaredIds(expression) {
  if (typeof expression !== 'string') return null;
  let tree;
  try {
    tree = parseSpdx(expression);
  } catch {
    return null;
  }
  const ids = [];
  const visit = (node) => {
    if (node.op === 'AND' || node.op === 'OR') {
      visit(node.left);
      visit(node.right);
    } else {
      ids.push({ id: node.license.toLowerCase(), withException: node.op === 'WITH' });
    }
  };
  visit(tree);
  return ids;
}

/** Exactly MIT and Apache-2.0, combined with OR or AND (no WITH). */
function isMitApacheDual(expression) {
  const ids = declaredIds(expression);
  if (ids === null || ids.some((entry) => entry.withException)) return false;
  const set = new Set(ids.map((entry) => entry.id));
  return set.size === 2 && set.has('mit') && set.has('apache-2.0');
}

function readPackageText(dir, file) {
  try {
    return readFileSync(join(dir, file), 'latin1');
  } catch (error) {
    throw new InventoryError(`${join(dir, file)} could not be read: ${error.code ?? error.message}`);
  }
}

function readDirectory(dir, what) {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch (error) {
    throw new InventoryError(`${what} could not be read: ${error.code ?? error.message}`);
  }
}

/** Files of an installed package (nested node_modules excluded), with its symbolic links listed apart. */
function walkPackage(dir, rel, out) {
  for (const entry of readDirectory(dir, `${dir}`)) {
    const path = rel === '' ? entry.name : `${rel}/${entry.name}`;
    if (entry.isSymbolicLink()) out.symlinks.push(path);
    else if (entry.isDirectory()) {
      if (entry.name !== 'node_modules') walkPackage(join(dir, entry.name), path, out);
    } else if (entry.isFile()) out.files.push(path);
    else out.symlinks.push(path); // sockets, FIFOs, devices: not ordinary package content
  }
  return out;
}

/**
 * License texts of an installed package, split into its own texts and extras,
 * with the recognised license family of each own license file.
 */
function licenseFiles(dir, expression) {
  const { files, symlinks } = walkPackage(dir, '', { files: [], symlinks: [] });
  const matching = files.filter(isLicenseText).sort();
  const root = matching.filter((file) => !file.includes('/'));
  const rootLicenses = root.filter((file) => ROOT_LICENSE.test(file) && !THIRD_PARTY.test(file));
  const ownNotice = root.find((file) => ROOT_NOTICE.test(file)) ?? null;
  const families = new Map(rootLicenses.map((file) => [file, recognizeLicenseText(readPackageText(dir, file))]));

  let ownLicenses = rootLicenses.slice(0, 1);
  if (rootLicenses.length === 2 && isMitApacheDual(expression)) {
    // One text for each license of a dual MIT / Apache-2.0 package: by the
    // recognised text, else by the file name (LICENSE-MIT, LICENSE-APACHE).
    const kind = (file) => {
      const found = families.get(file);
      if (found.length === 1 && (found[0] === 'MIT' || found[0] === 'Apache-2.0')) return found[0];
      if (found.length === 0 && /mit/i.test(file) && !/apache/i.test(file)) return 'MIT';
      if (found.length === 0 && /apache/i.test(file) && !/mit/i.test(file)) return 'Apache-2.0';
      return null;
    };
    const kinds = rootLicenses.map(kind);
    if (kinds.includes('MIT') && kinds.includes('Apache-2.0')) ownLicenses = rootLicenses;
  }
  const own = new Set([...ownLicenses, ownNotice].filter(Boolean));
  const extra = matching.filter((file) => !own.has(file));

  const ids = declaredIds(expression);
  const texts = ownLicenses.map((file) => ({ file, recognized: families.get(file) }));
  const mismatched =
    ids === null
      ? []
      : texts.filter((text) => text.recognized.some((family) => !familyAgrees(family, ids.map((entry) => entry.id)))).map((text) => text.file);
  return { all: matching, ownLicenses, ownNotice, extra, texts, mismatched, files, symlinks };
}

function sha256File(path) {
  try {
    return createHash('sha256').update(readFileSync(path)).digest('hex');
  } catch (error) {
    throw new InventoryError(`${path} could not be read: ${error.code ?? error.message}`);
  }
}

/** Regular files and symbolic links under dist/ (an absent dist/ is empty; other read errors stop the run). */
function walkDist(root) {
  const dist = join(root, 'dist');
  const out = { files: [], symlinks: [] };
  let top;
  try {
    top = lstatSync(dist);
  } catch (error) {
    if (error.code === 'ENOENT') return out;
    throw new InventoryError(`dist/ could not be read: ${error.code ?? error.message}`);
  }
  if (top.isSymbolicLink()) {
    out.symlinks.push('dist');
    return out;
  }
  if (!top.isDirectory()) throw new InventoryError('dist is not a directory');
  const walk = (dir, rel) => {
    for (const entry of readDirectory(dir, `dist/${rel}`)) {
      const path = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isSymbolicLink()) out.symlinks.push(`dist/${path}`);
      else if (entry.isDirectory()) walk(join(dir, entry.name), path);
      else if (entry.isFile()) out.files.push(path);
      else out.symlinks.push(`dist/${path}`); // not a regular file: reported with the links
    }
  };
  walk(dist, '');
  out.files.sort();
  out.symlinks.sort();
  return out;
}

/** Packages owning a file copied byte-for-byte into dist/: Map(lockPath -> [dist files]). */
function distAssetOwners(root, records, distFiles) {
  const owners = new Map();
  if (distFiles.length === 0) return owners;
  const byDigest = new Map();
  for (const record of records) {
    if (!record.installed) continue;
    for (const file of record.files) {
      const abs = join(root, record.path, file);
      let size;
      try {
        size = statSync(abs).size;
      } catch (error) {
        throw new InventoryError(`${abs} could not be read: ${error.code ?? error.message}`);
      }
      if (size === 0) continue;
      const digest = sha256File(abs);
      if (!byDigest.has(digest)) byDigest.set(digest, new Set());
      byDigest.get(digest).add(record.path);
    }
  }
  for (const file of distFiles) {
    const abs = join(root, 'dist', file);
    let size;
    try {
      size = statSync(abs).size;
    } catch (error) {
      throw new InventoryError(`dist/${file} could not be read: ${error.code ?? error.message}`);
    }
    if (size === 0) continue;
    for (const path of byDigest.get(sha256File(abs)) ?? []) {
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
 * Throws InventoryError for an incomplete or inconsistent install or a read error.
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
    let manifest = null;
    try {
      manifest = readFileSync(join(dir, 'package.json'), 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') throw new InventoryError(`${path}/package.json could not be read: ${error.code ?? error.message}`);
    }
    if (manifest !== null) {
      try {
        installed = JSON.parse(manifest);
      } catch {
        throw new InventoryError(`${path}/package.json is not valid JSON`);
      }
    }
    if (installed === null && !entry.optional) throw new InventoryError(`${path} is locked but not installed; run npm ci`);
    if (installed !== null && installed.version !== entry.version) {
      throw new InventoryError(`${path} is installed as ${installed.version} but locked as ${entry.version}`);
    }
    const declared = installed ? declaredLicense(installed) : entry.license ?? null;
    const license =
      declared !== null && typeof declared === 'object' ? { expression: null, status: 'unknown', detail: declared.unknown } : evaluateLicense(declared, policy);
    const files = installed
      ? licenseFiles(dir, license.expression)
      : { all: [], ownLicenses: [], ownNotice: null, extra: [], texts: [], mismatched: [], files: [], symlinks: [] };
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
      own_license_file: files.ownLicenses[0] ?? null,
      own_license_files: files.ownLicenses,
      own_notice_file: files.ownNotice,
      extra_license_files: files.extra,
      license_texts: files.texts,
      license_text_mismatch: files.mismatched,
      symlinks: files.symlinks,
      lockfile_dev: entry.dev === true,
      integrity: entry.integrity ?? null,
      resolved: entry.resolved ?? null,
      files: files.files,
    });
  }

  const dist = walkDist(root);
  for (const [path, distFiles] of distAssetOwners(root, records, dist.files)) {
    const record = records.find((candidate) => candidate.path === path);
    if (record.classification !== 'shipped') {
      record.classification = 'shipped';
      record.reasons = [];
    }
    for (const file of distFiles) record.reasons.push(`asset copied into ${file}`);
  }

  const findings = [];
  for (const link of dist.symlinks) {
    findings.push({ rule: 'dist-symlink', record: null, file: link, detail: 'dist/ holds a symbolic link or other non-regular file; its target is not inventoried' });
  }
  for (const record of records.filter((r) => r.classification === 'shipped')) {
    if (record.policy !== 'allowed') findings.push({ rule: `license-${record.policy}`, record, detail: record.policy_detail });
    for (const file of record.extra_license_files) findings.push({ rule: 'extra-license-file', record, file, detail: 'separately licensed material inside a shipped package' });
    for (const file of record.license_text_mismatch) findings.push({ rule: 'license-text-mismatch', record, file, detail: 'the license text is not the declared license' });
    for (const file of record.symlinks) findings.push({ rule: 'package-symlink', record, file, detail: 'a shipped package holds a symbolic link or other non-regular file' });
  }
  for (const record of records) delete record.files;

  return {
    root,
    rootPkg,
    packages,
    records,
    dist,
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
    for (const file of [record.own_notice_file, ...record.own_license_files]) {
      if (!file) continue;
      const text = readText(join(inventory.root, record.path, file));
      if (text === null) throw new InventoryError(`${record.path}/${file} could not be read for NOTICE`);
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

/** Digest of every classification, license result, license-file split and finding. */
export function classificationDigest(inventory) {
  const records = inventory.records.map((record) => [
    record.path,
    record.classification,
    record.reasons,
    record.license,
    record.policy,
    record.own_license_files,
    record.own_notice_file,
    record.extra_license_files,
    record.license_text_mismatch,
    record.symlinks,
  ]);
  const findings = inventory.findings.map((finding) => [finding.rule, finding.record?.path ?? null, finding.file ?? null]);
  return createHash('sha256').update(JSON.stringify({ records, findings })).digest('hex');
}

/**
 * CycloneDX 1.6 JSON SBOM for every locked package, with its classification.
 * `inventory.gate` and `inventory.findings` are the run's final values (the
 * CLI passes them with the NOTICE check included), so the SBOM and
 * inventory.json carry the same application-gate value.
 */
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
        ...record.license_text_mismatch.map((file) => ({ name: 'opensig:license-text-mismatch', value: file })),
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
  const classification = classificationDigest(inventory);
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${deterministicUuid(`${inventory.lockfileSha256}:${inventory.policy.sha256}:${inventory.gate}:${classification}`)}`,
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
        { name: 'opensig:classification-sha256', value: classification },
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
  let notice;
  try {
    inventory = buildInventory(options.root);
    notice = renderNotice(inventory);
  } catch (error) {
    if (!(error instanceof InventoryError)) throw error;
    process.stdout.write(`license-inventory: ERROR ${error.message}\n`);
    process.exitCode = 2;
    return;
  }

  const findings = [...inventory.findings];
  const noticePath = join(options.root, 'NOTICE');
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
  // One gate value for both outputs: the SBOM carries the NOTICE check too.
  const sbom = renderCycloneDx({ ...inventory, findings, gate });
  writeJson(join(options.out, 'sbom.cdx.json'), sbom);
  writeJson(join(options.out, 'inventory.json'), {
    kind: 'opensig-license-inventory',
    application_gate: gate,
    platform_status: platform.status,
    policy: { file: 'scripts/license-policy.json', allowed: inventory.policy.allowed, sha256: inventory.policy.sha256 },
    lockfile_sha256: inventory.lockfileSha256,
    sbom_serial_number: sbom.serialNumber,
    classification_sha256: classificationDigest({ ...inventory, findings }),
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
