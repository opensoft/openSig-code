// SPDX-License-Identifier: Apache-2.0
//
// License inventory and SBOM gate (T002), cases LI-01..LI-10.
//
// Every project below is synthetic: package.json, package-lock.json and the
// node_modules tree are generated at runtime in a temporary directory.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { evaluateLicense, loadPolicy } from '../../scripts/license-inventory.mjs';
import { collectPlatformInventory, PLATFORM_STATUS } from '../../scripts/platform-inventory.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const TOOL = join(REPO_ROOT, 'scripts', 'license-inventory.mjs');
const PLATFORM_TOOL = join(REPO_ROOT, 'scripts', 'platform-inventory.mjs');
const PLATFORM_ITEMS = ['node-runtime', 'linked-libraries', 'openssl-cli', 'chromium', 'hermes-image'];

const scratch = [];
after(() => {
  for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});

function write(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function nameOf(path) {
  return path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
}

/**
 * Build a synthetic project. `packages` maps lockfile paths to
 * { version, license (null = none declared), licenses, dependencies, dev,
 *   optional, files, installed, installedVersion }.
 */
function project({ dependencies = {}, devDependencies = {}, packages = {}, dist = {} } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'opensig-license-'));
  scratch.push(root);
  const rootPkg = { name: 'fixture-app', version: '1.0.0', license: 'Apache-2.0', dependencies, devDependencies };
  write(join(root, 'package.json'), JSON.stringify(rootPkg, null, 2));
  const lockPackages = { '': { ...rootPkg } };
  for (const [path, spec] of Object.entries(packages)) {
    const name = nameOf(path);
    const declared = spec.license === null || spec.license === undefined ? {} : { license: spec.license };
    lockPackages[path] = {
      version: spec.version,
      resolved: `https://registry.npmjs.org/${name}/-/${name.split('/').pop()}-${spec.version}.tgz`,
      integrity: `sha512-${createHash('sha512').update(`${name}@${spec.version}`).digest('base64')}`,
      ...(spec.dev ? { dev: true } : {}),
      ...(spec.optional ? { optional: true } : {}),
      ...declared,
      ...(spec.dependencies ? { dependencies: spec.dependencies } : {}),
    };
    if (spec.installed === false) continue;
    const manifest = {
      name,
      version: spec.installedVersion ?? spec.version,
      ...declared,
      ...(spec.licenses ? { licenses: spec.licenses } : {}),
      ...(spec.dependencies ? { dependencies: spec.dependencies } : {}),
    };
    write(join(root, path, 'package.json'), JSON.stringify(manifest, null, 2));
    const files = spec.files ?? { LICENSE: `Synthetic license text for ${name} (${spec.license ?? 'none'}).\n` };
    for (const [file, content] of Object.entries(files)) write(join(root, path, file), content);
  }
  write(join(root, 'package-lock.json'), JSON.stringify({ name: 'fixture-app', version: '1.0.0', lockfileVersion: 3, requires: true, packages: lockPackages }, null, 2));
  for (const [file, content] of Object.entries(dist)) write(join(root, 'dist', file), content);
  return root;
}

function inventory(root, args = ['--write-notice']) {
  const out = join(root, '.inventory-out');
  const run = spawnSync(process.execPath, [TOOL, '--root', root, '--out', out, ...args], { encoding: 'utf8', timeout: 120_000 });
  const lines = run.stdout.split('\n').filter(Boolean);
  return {
    code: run.status,
    stdout: run.stdout,
    stderr: run.stderr,
    lines,
    last: lines.at(-1) ?? '',
    out,
    json: () => JSON.parse(readFileSync(join(out, 'inventory.json'), 'utf8')),
    sbom: () => JSON.parse(readFileSync(join(out, 'sbom.cdx.json'), 'utf8')),
  };
}

function record(result, name) {
  const found = result.json().packages.find((pkg) => pkg.name === name);
  assert.ok(found, `package ${name} is inventoried`);
  return found;
}

function expectFinding(result, rule, pkg) {
  assert.equal(result.code, 1, `expected exit 1; output:\n${result.stdout}${result.stderr}`);
  assert.ok(
    result.lines.some((line) => line.startsWith(`license-inventory: FAIL rule=${rule} package=${pkg} `)),
    `expected ${rule} for ${pkg}; output:\n${result.stdout}`,
  );
  assert.match(result.last, /^license-inventory: FAIL application-gate findings=\d+ /);
}

function shippedOnly(license, extra = {}) {
  return project({ dependencies: { 'pkg-a': '1.0.0' }, packages: { 'node_modules/pkg-a': { version: '1.0.0', license, ...extra } } });
}

// --- cases -----------------------------------------------------------------------

test('[LI-01] a shipped 0BSD package fails the gate', () => {
  const result = inventory(shippedOnly('0BSD'));
  expectFinding(result, 'license-disallowed', 'pkg-a@1.0.0');
  const pkg = record(result, 'pkg-a');
  assert.equal(pkg.classification, 'shipped');
  assert.equal(pkg.policy, 'disallowed');
});

test('[LI-02] a shipped (MIT AND Zlib) package fails: an AND needs every term allowed', () => {
  const result = inventory(shippedOnly('(MIT AND Zlib)'));
  expectFinding(result, 'license-disallowed', 'pkg-a@1.0.0');
});

test('[LI-03] a shipped BSD-3-Clause OR GPL-2.0 package fails: no alternative is allowed', () => {
  const result = inventory(shippedOnly('BSD-3-Clause OR GPL-2.0'));
  expectFinding(result, 'license-disallowed', 'pkg-a@1.0.0');
});

test('[LI-04] a shipped BlueOak-1.0.0 package fails the gate', () => {
  const result = inventory(shippedOnly('BlueOak-1.0.0'));
  expectFinding(result, 'license-disallowed', 'pkg-a@1.0.0');
});

test('[LI-05] shipped MIT, Apache-2.0 and MIT OR Apache-2.0 packages pass', () => {
  const root = project({
    dependencies: { 'pkg-mit': '1.0.0', 'pkg-apache': '2.0.0', 'pkg-dual': '3.0.0' },
    packages: {
      'node_modules/pkg-mit': { version: '1.0.0', license: 'MIT' },
      'node_modules/pkg-apache': { version: '2.0.0', license: 'Apache-2.0' },
      'node_modules/pkg-dual': { version: '3.0.0', license: 'MIT OR Apache-2.0' },
    },
  });
  const result = inventory(root);
  assert.equal(result.code, 0, result.stdout);
  assert.match(result.last, /^license-inventory: PASS application-gate shipped=3 non-shipped=0 notice=written platform=POLICY-PENDING$/);
  for (const name of ['pkg-mit', 'pkg-apache', 'pkg-dual']) {
    const pkg = record(result, name);
    assert.equal(pkg.classification, 'shipped');
    assert.equal(pkg.policy, 'allowed');
  }
});

test('[LI-06] missing and unknown licenses fail', () => {
  expectFinding(inventory(shippedOnly(null)), 'license-missing', 'pkg-a@1.0.0');
  expectFinding(inventory(shippedOnly('SEE LICENSE IN LICENSE.txt')), 'license-unknown', 'pkg-a@1.0.0');
  expectFinding(inventory(shippedOnly('UNLICENSED')), 'license-unknown', 'pkg-a@1.0.0');
  expectFinding(inventory(shippedOnly('MIT OR')), 'license-unknown', 'pkg-a@1.0.0');
  expectFinding(inventory(shippedOnly('LicenseRef-Proprietary')), 'license-unknown', 'pkg-a@1.0.0');
  const legacy = inventory(shippedOnly(null, { licenses: [{ type: 'MIT', url: 'https://example.test/mit' }] }));
  assert.equal(legacy.code, 0, `the legacy "licenses" array is read: ${legacy.stdout}`);
});

test('[LI-07] an extra asset license inside a shipped package fails', () => {
  const asset = inventory(
    shippedOnly('MIT', {
      files: { LICENSE: 'Synthetic MIT text.\n', 'fonts/LICENSE_FOXIT': 'Separately licensed font asset.\n', 'fonts/glyphs.bin': 'bytes\n' },
    }),
  );
  expectFinding(asset, 'extra-license-file', 'pkg-a@1.0.0');
  assert.ok(asset.lines.some((line) => line.includes('rule=extra-license-file') && line.endsWith('file=fonts/LICENSE_FOXIT')));

  const twoTexts = inventory(shippedOnly('MIT', { files: { LICENSE: 'Synthetic MIT text.\n', COPYING: 'Another license text.\n' } }));
  expectFinding(twoTexts, 'extra-license-file', 'pkg-a@1.0.0');

  const apacheWithNotice = project({
    dependencies: { 'pkg-apache': '1.0.0' },
    packages: {
      'node_modules/pkg-apache': {
        version: '1.0.0',
        license: 'Apache-2.0',
        files: { LICENSE: 'Synthetic Apache text.\n', NOTICE: 'pkg-apache synthetic notice line.\n', 'lib/license.js': 'export const id = 1;\n' },
      },
    },
  });
  const allowed = inventory(apacheWithNotice);
  assert.equal(allowed.code, 0, `one root LICENSE and one root NOTICE are the package's own texts: ${allowed.stdout}`);
  assert.ok(readFileSync(join(apacheWithNotice, 'NOTICE'), 'utf8').includes('pkg-apache synthetic notice line.'), 'NOTICE retains the shipped notice');
});

test('[LI-08] a disallowed dev-only package is reported as non-shipped and does not fail the gate', () => {
  const root = project({
    dependencies: { 'pkg-a': '1.0.0' },
    devDependencies: { 'dev-tool': '1.0.0' },
    packages: {
      'node_modules/pkg-a': { version: '1.0.0', license: 'MIT' },
      'node_modules/dev-tool': { version: '1.0.0', license: '0BSD', dev: true },
    },
  });
  const result = inventory(root);
  assert.equal(result.code, 0, result.stdout);
  assert.ok(result.lines.includes('license-inventory: package=dev-tool@1.0.0 path=node_modules/dev-tool class=non-shipped license="0BSD" policy=disallowed'));
  assert.equal(record(result, 'dev-tool').classification, 'non-shipped');

  // The production closure is computed, not read from the lockfile's dev flags,
  // and it follows transitive dependencies.
  const mislabeled = project({
    dependencies: { 'pkg-a': '1.0.0' },
    packages: {
      'node_modules/pkg-a': { version: '1.0.0', license: 'MIT', dependencies: { 'pkg-b': '1.0.0' }, dev: true },
      'node_modules/pkg-b': { version: '1.0.0', license: '0BSD', dev: true },
    },
  });
  const closure = inventory(mislabeled);
  expectFinding(closure, 'license-disallowed', 'pkg-b@1.0.0');
  assert.equal(record(closure, 'pkg-a').classification, 'shipped');
  assert.equal(record(closure, 'pkg-b').classification, 'shipped');
});

test('[LI-09] platform status is always POLICY-PENDING', () => {
  const bare = mkdtempSync(join(tmpdir(), 'opensig-platform-'));
  scratch.push(bare);
  for (const root of [REPO_ROOT, bare]) {
    const platform = collectPlatformInventory(root);
    assert.equal(platform.status, 'POLICY-PENDING');
    assert.equal(PLATFORM_STATUS, 'POLICY-PENDING');
    assert.deepEqual(
      platform.items.map((item) => item.id),
      PLATFORM_ITEMS,
    );
    for (const item of platform.items) assert.equal(item.status, 'POLICY-PENDING', `${item.id} status`);
    assert.ok(!/"status":"PASS"/.test(JSON.stringify(platform)), 'no platform status is PASS');
  }
  assert.equal(collectPlatformInventory(REPO_ROOT).items[0].observed.receipt.version, '24.22.2', 'the pinned runtime is recorded');

  const out = join(bare, 'out');
  const cli = spawnSync(process.execPath, [PLATFORM_TOOL, '--root', REPO_ROOT, '--out', out], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(cli.status, 0);
  assert.match(cli.stdout, /^platform-inventory: POLICY-PENDING items=5 written=.* \(recorded, not passed\)\n$/);
  assert.equal(JSON.parse(readFileSync(join(out, 'platform-inventory.json'), 'utf8')).status, 'POLICY-PENDING');

  const gate = inventory(shippedOnly('MIT'));
  assert.match(gate.last, / platform=POLICY-PENDING$/);
  assert.equal(JSON.parse(readFileSync(join(gate.out, 'platform-inventory.json'), 'utf8')).status, 'POLICY-PENDING');
  assert.equal(gate.json().platform_status, 'POLICY-PENDING');
});

test('[LI-10] the CycloneDX SBOM classifies every package and NOTICE is regenerated and checked', () => {
  const root = project({
    dependencies: { 'pkg-a': '1.0.0', '@scope/lib': '2.1.0' },
    devDependencies: { 'dev-tool': '0.5.0' },
    packages: {
      'node_modules/pkg-a': { version: '1.0.0', license: 'MIT', files: { LICENSE: 'Synthetic MIT text for pkg-a.\n' } },
      'node_modules/@scope/lib': { version: '2.1.0', license: 'Apache-2.0' },
      'node_modules/dev-tool': { version: '0.5.0', license: 'MIT', dev: true },
    },
  });
  const first = inventory(root);
  assert.equal(first.code, 0, first.stdout);
  const sbom = first.sbom();
  assert.equal(sbom.bomFormat, 'CycloneDX');
  assert.equal(sbom.specVersion, '1.6');
  assert.match(sbom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(sbom.components.length, 3);
  const byPurl = Object.fromEntries(sbom.components.map((component) => [component.purl, component]));
  assert.equal(byPurl['pkg:npm/pkg-a@1.0.0'].scope, 'required');
  assert.equal(byPurl['pkg:npm/%40scope/lib@2.1.0'].group, '@scope');
  assert.equal(byPurl['pkg:npm/%40scope/lib@2.1.0'].scope, 'required');
  assert.equal(byPurl['pkg:npm/dev-tool@0.5.0'].scope, 'excluded');
  assert.deepEqual(byPurl['pkg:npm/pkg-a@1.0.0'].licenses, [{ license: { id: 'MIT' } }]);
  for (const component of sbom.components) {
    assert.equal(component.hashes[0].alg, 'SHA-512');
    assert.match(component.hashes[0].content, /^[0-9a-f]{128}$/);
    assert.ok(component.properties.some((p) => p.name === 'opensig:classification'));
  }
  assert.ok(sbom.metadata.properties.some((p) => p.name === 'opensig:platform-status' && p.value === 'POLICY-PENDING'));

  const notice = readFileSync(join(root, 'NOTICE'), 'utf8');
  assert.ok(notice.includes('pkg-a 1.0.0 (MIT)') && notice.includes('Synthetic MIT text for pkg-a.'));
  assert.ok(!notice.includes('dev-tool'), 'non-shipped packages are not in NOTICE');

  const check = inventory(root, []);
  assert.equal(check.code, 0, check.stdout);
  assert.match(check.last, / notice=current /);
  assert.equal(readFileSync(join(check.out, 'sbom.cdx.json'), 'utf8'), JSON.stringify(sbom, null, 2) + '\n', 'the SBOM is deterministic');

  writeFileSync(join(root, 'NOTICE'), `${notice}edited by hand\n`);
  const stale = inventory(root, []);
  assert.equal(stale.code, 1);
  assert.ok(stale.lines.includes('license-inventory: FAIL rule=notice-stale'));
});

test('SPDX expressions follow operator precedence and the exact allowlist', () => {
  const policy = loadPolicy();
  assert.deepEqual(policy.allowed, ['MIT', 'Apache-2.0'], 'scripts/license-policy.json allows exactly MIT and Apache-2.0');
  const cases = {
    MIT: 'allowed',
    'Apache-2.0': 'allowed',
    mit: 'allowed',
    '((MIT))': 'allowed',
    'MIT AND Apache-2.0': 'allowed',
    '(MIT OR GPL-2.0) AND Apache-2.0': 'allowed',
    'MIT OR GPL-2.0 AND BSD-3-Clause': 'allowed',
    'GPL-2.0 OR BSD-3-Clause AND MIT': 'disallowed',
    'Apache-2.0 WITH LLVM-exception': 'disallowed',
    'MIT+': 'disallowed',
    ISC: 'disallowed',
    'MIT and Apache-2.0': 'unknown',
    '(MIT': 'unknown',
    '': 'missing',
  };
  for (const [expression, status] of Object.entries(cases)) {
    assert.equal(evaluateLicense(expression, policy).status, status, JSON.stringify(expression));
  }
});

test('a package that owns a file copied into dist/ is shipped', () => {
  const asset = randomBytes(256);
  const devAsset = {
    dependencies: {},
    devDependencies: { 'font-kit': '1.0.0' },
    packages: { 'node_modules/font-kit': { version: '1.0.0', license: '0BSD', dev: true, files: { LICENSE: 'Synthetic 0BSD text.\n', 'fonts/glyphs.bin': asset } } },
  };
  const copied = inventory(project({ ...devAsset, dist: { 'static/glyphs.bin': asset } }));
  expectFinding(copied, 'license-disallowed', 'font-kit@1.0.0');
  assert.deepEqual(record(copied, 'font-kit').reasons, ['asset copied into dist/static/glyphs.bin']);
  const original = inventory(project({ ...devAsset, dist: { 'static/app.bin': randomBytes(256) } }));
  assert.equal(original.code, 0, original.stdout);
  assert.equal(record(original, 'font-kit').classification, 'non-shipped');
});

test('an incomplete or inconsistent install exits 2', () => {
  const notInstalled = inventory(shippedOnly('MIT', { installed: false }));
  assert.equal(notInstalled.code, 2);
  assert.match(notInstalled.last, /^license-inventory: ERROR node_modules\/pkg-a is locked but not installed/);
  const drifted = inventory(shippedOnly('MIT', { installedVersion: '1.0.1' }));
  assert.equal(drifted.code, 2);
  const unresolved = inventory(project({ dependencies: { 'pkg-a': '1.0.0' }, packages: { 'node_modules/pkg-a': { version: '1.0.0', license: 'MIT', dependencies: { 'pkg-gone': '1.0.0' } } } }));
  assert.equal(unresolved.code, 2);
  assert.match(unresolved.last, /depends on pkg-gone/);
  const noLock = shippedOnly('MIT');
  rmSync(join(noLock, 'package-lock.json'));
  assert.equal(inventory(noLock).code, 2);
});

test('the code-leg inventory passes with an empty shipped closure and a current NOTICE', () => {
  const out = mkdtempSync(join(tmpdir(), 'opensig-license-repo-'));
  scratch.push(out);
  const run = spawnSync(process.execPath, [TOOL, '--root', REPO_ROOT, '--out', out], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.match(run.stdout, /license-inventory: PASS application-gate shipped=0 non-shipped=\d+ notice=current platform=POLICY-PENDING\n$/);
  const packages = JSON.parse(readFileSync(join(out, 'inventory.json'), 'utf8')).packages;
  assert.ok(packages.length >= 3);
  for (const pkg of packages) assert.equal(pkg.classification, 'non-shipped', `${pkg.name} is a development tool`);
  for (const name of ['typescript', '@types/node', 'undici-types']) assert.ok(packages.some((pkg) => pkg.name === name && pkg.policy === 'allowed'), name);
});

test('usage errors exit 2', () => {
  const run = spawnSync(process.execPath, [TOOL, '--allow', 'BSD-3-Clause'], { encoding: 'utf8' });
  assert.equal(run.status, 2);
  assert.equal(run.stdout, 'license-inventory: ERROR usage\n');
  const platform = spawnSync(process.execPath, [PLATFORM_TOOL, '--status', 'PASS'], { encoding: 'utf8' });
  assert.equal(platform.status, 2);
});
