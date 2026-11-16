// SPDX-License-Identifier: Apache-2.0
//
// License inventory and SBOM gate (T002), cases LI-01..LI-11.
//
// Every project below is synthetic: package.json, package-lock.json and the
// node_modules tree are generated at runtime in a temporary directory. LI-11
// reads the host's own platform tools and package records, and checks each
// value against the host independently.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { evaluateLicense, loadPolicy } from '../../scripts/license-inventory.mjs';
import { collectPlatformInventory, effectiveBrowsersPath, PLATFORM_DECISION, PLATFORM_STATUS } from '../../scripts/platform-inventory.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const TOOL = join(REPO_ROOT, 'scripts', 'license-inventory.mjs');
const PLATFORM_TOOL = join(REPO_ROOT, 'scripts', 'platform-inventory.mjs');
const PLATFORM_ITEMS = ['node-runtime', 'linked-libraries', 'openssl-cli', 'bwrap', 'unshare', 'mount', 'chroot', 'setpriv', 'sh', 'mkdir', 'chromium', 'hermes-image'];

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
  assert.match(result.last, /^license-inventory: PASS application-gate shipped=3 non-shipped=0 notice=written platform=INVENTORIED$/);
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

test('[LI-09] platforms are INVENTORIED separately and never affect the application gate', () => {
  const bare = mkdtempSync(join(tmpdir(), 'opensig-platform-'));
  scratch.push(bare);
  assert.equal(PLATFORM_STATUS, 'INVENTORIED');
  assert.ok(PLATFORM_DECISION.includes('"MIT/Apache application and libraries; inventory platform licenses separately"'), 'the owner decision is stated verbatim');
  for (const root of [REPO_ROOT, bare]) {
    const platform = collectPlatformInventory(root);
    assert.equal(platform.status, 'INVENTORIED');
    assert.equal(platform.decision, PLATFORM_DECISION);
    assert.deepEqual(
      platform.items.map((item) => item.id),
      PLATFORM_ITEMS,
    );
    for (const item of platform.items) assert.equal(item.status, 'INVENTORIED', `${item.id} status`);
    assert.ok(!/"status":"(?:PASS|POLICY-PENDING)"/.test(JSON.stringify(platform)), 'no platform status is PASS or POLICY-PENDING');
  }
  const runtime = collectPlatformInventory(REPO_ROOT).items[0];
  assert.equal(runtime.observed.receipt.version, '24.22.2', 'the pinned runtime is recorded');
  assert.match(runtime.recorded_licenses, /BlueOak-1\.0\.0/, 'platform licenses outside the allowlist are recorded, not gated');
  const unshare = collectPlatformInventory(REPO_ROOT).items.find((item) => item.id === 'unshare');
  assert.match(unshare.name, /util-linux unshare/);
  assert.match(unshare.recorded_licenses, /GPL-2\.0-or-later/, 'the parser sandbox launcher is inventoried with its own licenses');
  assert.ok(unshare.observed.version === null ? typeof unshare.observed.detail === 'string' : /util-linux/.test(unshare.observed.version), 'its version, or why it is absent, is recorded');

  const out = join(bare, 'out');
  const cli = spawnSync(process.execPath, [PLATFORM_TOOL, '--root', REPO_ROOT, '--out', out], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(cli.status, 0);
  assert.match(cli.stdout, /^platform-inventory: INVENTORIED items=12 written=.* \(recorded separately; never gates the application\)\n$/);
  assert.equal(JSON.parse(readFileSync(join(out, 'platform-inventory.json'), 'utf8')).status, 'INVENTORIED');

  // The application gate is the same whatever the platform probes find: with
  // ldd, openssl and the browser cache all unavailable, a passing project still
  // passes and a failing one still fails, with identical findings and SBOM gate.
  const noPlatform = { PATH: '', HOME: bare, PLAYWRIGHT_BROWSERS_PATH: join(bare, 'no-browsers') };
  for (const [license, expected] of [
    ['MIT', 0],
    ['0BSD', 1],
  ]) {
    const root = shippedOnly(license);
    inventory(root); // writes NOTICE, so both runs below are check runs on the same tree
    const normal = inventory(root, []);
    const stripped = spawnSync(process.execPath, [TOOL, '--root', root, '--out', join(root, '.stripped-out')], { encoding: 'utf8', timeout: 120_000, env: noPlatform });
    assert.equal(normal.code, expected, normal.stdout);
    assert.equal(stripped.status, expected, stripped.stdout + stripped.stderr);
    assert.equal(stripped.stdout, normal.stdout, 'identical gate output with and without platform tools');
    const strippedJson = JSON.parse(readFileSync(join(root, '.stripped-out', 'inventory.json'), 'utf8'));
    const strippedPlatform = JSON.parse(readFileSync(join(root, '.stripped-out', 'platform-inventory.json'), 'utf8'));
    assert.notDeepEqual(strippedPlatform.items, JSON.parse(readFileSync(join(normal.out, 'platform-inventory.json'), 'utf8')).items, 'the platform record itself differs');
    for (const field of ['application_gate', 'findings', 'classification_sha256', 'sbom_serial_number', 'platform_status']) {
      assert.deepEqual(strippedJson[field], normal.json()[field], field);
    }
    assert.equal(normal.json().platform_status, 'INVENTORIED');
    assert.ok(!normal.json().findings.some((finding) => /platform/.test(finding.rule)), 'no platform finding exists');
    assert.match(normal.last, / platform=INVENTORIED$/);
  }

  // The browsers path is resolved exactly as the frozen runner's chromium probe resolves it.
  const coreDir = join(REPO_ROOT, 'node_modules', 'playwright-core');
  const cases = [
    [undefined, join(homedir(), '.cache', 'ms-playwright')],
    ['', join(homedir(), '.cache', 'ms-playwright')],
    ['0', join(coreDir, '.local-browsers')],
    ['/opt/synthetic-browsers', '/opt/synthetic-browsers'],
    ['relative/browsers', resolve('relative/browsers')],
  ];
  const base = Object.fromEntries(Object.entries(process.env).filter(([key]) => key !== 'PLAYWRIGHT_BROWSERS_PATH'));
  for (const [value, expected] of cases) {
    const env = value === undefined ? base : { ...base, PLAYWRIGHT_BROWSERS_PATH: value };
    assert.equal(effectiveBrowsersPath(REPO_ROOT, env).path, expected, `PLAYWRIGHT_BROWSERS_PATH=${JSON.stringify(value)}`);
    const chromium = collectPlatformInventory(REPO_ROOT, { env }).items.find((item) => item.id === 'chromium');
    assert.equal(chromium.observed.active_location, expected);
    assert.equal(chromium.observed.locations[0].path, expected);
  }
  const runner = readFileSync(join(REPO_ROOT, 'scripts', 'verify.mjs'), 'utf8');
  assert.ok(
    runner.includes("configured === '0' ? join(packageDir, '.local-browsers') : configured ? resolve(configured) : join(homedir(), '.cache', 'ms-playwright');"),
    'the frozen runner still resolves the browsers path this way',
  );
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
  assert.ok(sbom.metadata.properties.some((p) => p.name === 'opensig:platform-status' && p.value === 'INVENTORIED'));

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

// Opening phrases of well-known license texts (enough to recognise each one).
const MIT_TEXT = [
  'MIT License',
  '',
  'Copyright (c) 2026 Synthetic Authors',
  '',
  'Permission is hereby granted, free of charge, to any person obtaining a copy',
  'of this software and associated documentation files (the "Software").',
  '',
  'The above copyright notice and this permission notice shall be included in all',
  'copies or substantial portions of the Software.',
  '',
].join('\n');
const APACHE_TEXT = '                                 Apache License\n                           Version 2.0, January 2004\n\n   Synthetic terms.\n';
const GPL_TEXT = '                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n';
const BSD_TEXT = 'Redistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the conditions are met.\n';

test('[LI-07] bundled license texts anywhere in a shipped package fail: sidecars, notices, licenses/ and COPYRIGHT', () => {
  const bundled = [
    'lib/bundle.js.LICENSE',
    'lib/vendor.js.LICENSE.txt',
    'ThirdPartyNotices.txt',
    'docs/third_party_licenses.json',
    'licenses/OFL.txt',
    'LICENSES/Apache-2.0.txt',
    'fonts/COPYRIGHT',
    'COPYRIGHT',
    'assets/notices.html',
  ];
  for (const file of bundled) {
    const result = inventory(shippedOnly('MIT', { files: { LICENSE: MIT_TEXT, [file]: 'Separately licensed material.\n', 'lib/index.js': 'module.exports = 1;\n' } }));
    expectFinding(result, 'extra-license-file', 'pkg-a@1.0.0');
    assert.ok(result.lines.some((line) => line.includes('rule=extra-license-file') && line.endsWith(`file=${file}`)), `${file} is reported: ${result.stdout}`);
  }
  const code = inventory(
    shippedOnly('MIT', { files: { LICENSE: MIT_TEXT, 'lib/license.js': 'export const id = 1;\n', 'lib/notice-banner.ts': 'export const banner = 1;\n' } }),
  );
  assert.equal(code.code, 0, `source files named after licenses are code, not license texts: ${code.stdout}`);
});

test('[LI-06] a multi-entry legacy licenses array means all of them (AND), never OR', () => {
  const mixed = inventory(shippedOnly(null, { licenses: ['MIT', { type: 'GPL-3.0' }] }));
  expectFinding(mixed, 'license-disallowed', 'pkg-a@1.0.0');
  assert.equal(record(mixed, 'pkg-a').license, '(MIT) AND (GPL-3.0)');

  const allowed = inventory(shippedOnly(null, { licenses: [{ type: 'MIT' }, { type: 'Apache-2.0' }] }));
  assert.equal(allowed.code, 0, allowed.stdout);
  assert.equal(record(allowed, 'pkg-a').license, '(MIT) AND (Apache-2.0)');

  const both = inventory(shippedOnly('MIT', { licenses: [{ type: 'GPL-3.0' }] }));
  expectFinding(both, 'license-disallowed', 'pkg-a@1.0.0');
  assert.equal(record(both, 'pkg-a').license, '(MIT) AND (GPL-3.0)', 'a package declaring license and licenses is held to both');

  expectFinding(inventory(shippedOnly(null, { licenses: [{ type: 'MIT' }, { url: 'https://example.test/terms' }] })), 'license-unknown', 'pkg-a@1.0.0');
});

test('[LI-06] a root license text that is recognisably not the declared license fails', () => {
  const apacheText = inventory(shippedOnly('MIT', { files: { LICENSE: APACHE_TEXT } }));
  expectFinding(apacheText, 'license-text-mismatch', 'pkg-a@1.0.0');
  assert.deepEqual(record(apacheText, 'pkg-a').license_texts, [{ file: 'LICENSE', recognized: ['Apache-2.0'] }]);
  expectFinding(inventory(shippedOnly('Apache-2.0', { files: { 'LICENSE.md': GPL_TEXT } })), 'license-text-mismatch', 'pkg-a@1.0.0');
  expectFinding(inventory(shippedOnly('MIT', { files: { LICENSE: `${MIT_TEXT}\n${BSD_TEXT}` } })), 'license-text-mismatch', 'pkg-a@1.0.0');

  const matching = inventory(shippedOnly('Apache-2.0', { files: { LICENSE: APACHE_TEXT } }));
  assert.equal(matching.code, 0, matching.stdout);
  const unrecognised = inventory(shippedOnly('MIT', { files: { LICENSE: 'Synthetic license text.\n' } }));
  assert.equal(unrecognised.code, 0, `an unrecognisable text is not a detectable mismatch: ${unrecognised.stdout}`);
});

test('[LI-05] a dual MIT / Apache-2.0 package may carry LICENSE-MIT and LICENSE-APACHE', () => {
  const dualFiles = { 'LICENSE-MIT': MIT_TEXT, 'LICENSE-APACHE': APACHE_TEXT };
  for (const expression of ['MIT OR Apache-2.0', '(MIT AND Apache-2.0)', 'Apache-2.0 OR MIT']) {
    const root = shippedOnly(expression, { files: dualFiles });
    const result = inventory(root);
    assert.equal(result.code, 0, `${expression}: ${result.stdout}`);
    assert.deepEqual(record(result, 'pkg-a').own_license_files, ['LICENSE-APACHE', 'LICENSE-MIT']);
    const notice = readFileSync(join(root, 'NOTICE'), 'utf8');
    assert.ok(notice.includes('--- LICENSE-MIT ---') && notice.includes('--- LICENSE-APACHE ---'), 'NOTICE carries both texts');
  }
  // Recognised by text when the names do not say which is which.
  assert.equal(inventory(shippedOnly('MIT OR Apache-2.0', { files: { 'LICENSE.txt': MIT_TEXT, LICENSE: APACHE_TEXT } })).code, 0);
  // Not a dual declaration, or not one text for each license: the second file is an extra.
  expectFinding(inventory(shippedOnly('MIT', { files: dualFiles })), 'extra-license-file', 'pkg-a@1.0.0');
  expectFinding(inventory(shippedOnly('MIT OR Apache-2.0', { files: { 'LICENSE-MIT': MIT_TEXT, 'LICENSE-BSD': BSD_TEXT } })), 'extra-license-file', 'pkg-a@1.0.0');
  expectFinding(inventory(shippedOnly('MIT OR Apache-2.0', { files: { 'LICENSE-MIT': MIT_TEXT, 'LICENSE-MIT.txt': MIT_TEXT } })), 'extra-license-file', 'pkg-a@1.0.0');
});

test('a symbolic link in dist/ fails the gate and read errors stop the run', () => {
  const devKit = {
    devDependencies: { 'dev-kit': '1.0.0' },
    packages: { 'node_modules/dev-kit': { version: '1.0.0', license: '0BSD', dev: true, files: { LICENSE: 'Synthetic 0BSD text.\n', 'lib/runtime.js': `${randomBytes(64).toString('hex')}\n` } } },
  };
  const directory = project({ ...devKit, dist: { 'app.js': 'export const app = 1;\n' } });
  symlinkSync('../node_modules/dev-kit', join(directory, 'dist', 'vendor'));
  const linkedDirectory = inventory(directory);
  assert.equal(linkedDirectory.code, 1, linkedDirectory.stdout);
  assert.ok(linkedDirectory.lines.includes('license-inventory: FAIL rule=dist-symlink file=dist/vendor'), linkedDirectory.stdout);
  assert.equal(linkedDirectory.json().application_gate, 'FAIL');

  const file = project({ ...devKit, dist: { 'app.js': 'export const app = 1;\n' } });
  symlinkSync('../../node_modules/dev-kit/lib/runtime.js', join(file, 'dist', 'runtime.js'));
  assert.ok(inventory(file).lines.includes('license-inventory: FAIL rule=dist-symlink file=dist/runtime.js'));

  const whole = project(devKit);
  symlinkSync('node_modules/dev-kit', join(whole, 'dist'));
  assert.ok(inventory(whole).lines.includes('license-inventory: FAIL rule=dist-symlink file=dist'));

  const notDirectory = project(devKit);
  writeFileSync(join(notDirectory, 'dist'), 'not a directory\n');
  const unreadable = inventory(notDirectory);
  assert.equal(unreadable.code, 2, unreadable.stdout);
  assert.match(unreadable.last, /^license-inventory: ERROR dist is not a directory/);
});

test('[LI-10] the SBOM and inventory.json carry one gate value, and the SBOM serial covers classifications', () => {
  const root = project({ dependencies: { 'pkg-a': '1.0.0' }, packages: { 'node_modules/pkg-a': { version: '1.0.0', license: 'MIT' } } });
  const current = inventory(root);
  assert.equal(current.code, 0, current.stdout);
  const gateOf = (result) => result.sbom().metadata.properties.find((p) => p.name === 'opensig:application-gate').value;
  assert.equal(gateOf(current), 'PASS');
  assert.equal(current.json().sbom_serial_number, current.sbom().serialNumber);

  writeFileSync(join(root, 'NOTICE'), 'edited by hand\n');
  const stale = inventory(root, []);
  assert.equal(stale.code, 1);
  assert.equal(stale.json().application_gate, 'FAIL');
  assert.equal(gateOf(stale), 'FAIL', 'a stale NOTICE fails the SBOM gate value too');

  // Same lockfile and policy; only the dist/ classification differs.
  const asset = randomBytes(256);
  const devAsset = (dist) =>
    project({
      devDependencies: { 'font-kit': '1.0.0' },
      packages: { 'node_modules/font-kit': { version: '1.0.0', license: 'MIT', dev: true, files: { LICENSE: 'Synthetic MIT text.\n', 'fonts/glyphs.bin': asset } } },
      dist,
    });
  const unshipped = inventory(devAsset({ 'app.bin': randomBytes(64) }));
  const shipped = inventory(devAsset({ 'glyphs.bin': asset }));
  assert.equal(unshipped.code, 0, unshipped.stdout);
  assert.equal(shipped.code, 0, shipped.stdout);
  assert.equal(record(unshipped, 'font-kit').classification, 'non-shipped');
  assert.equal(record(shipped, 'font-kit').classification, 'shipped');
  assert.equal(unshipped.json().lockfile_sha256, shipped.json().lockfile_sha256);
  assert.notEqual(unshipped.sbom().serialNumber, shipped.sbom().serialNumber, 'the serial number covers the classification');
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
  assert.match(run.stdout, /license-inventory: PASS application-gate shipped=0 non-shipped=\d+ notice=current platform=INVENTORIED\n$/);
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

// --- LI-11: every platform tool the parse sandbox can launch (A-010) ---------------------

/** POSIX special built-ins, plus `[` and `test` (dash built-ins). Every other command word counts as a program. */
const SHELL_BUILTINS = new Set([':', '.', 'break', 'continue', 'eval', 'exec', 'exit', 'export', 'readonly', 'return', 'set', 'shift', 'times', 'trap', 'unset', '[', 'test']);
const SHELL_RESERVED = new Set(['!', '{', '}', 'case', 'do', 'done', 'elif', 'else', 'esac', 'fi', 'for', 'if', 'in', 'then', 'until', 'while']);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** The commands an `sh -c` script runs: programs called by name, and "$variable" commands. */
function scriptCommands(script) {
  const programs = new Set();
  const variables = new Set();
  for (const segment of script.replace(/\\\n/g, ' ').split(/\n|;|&&|\|\|?/)) {
    const words = segment.trim().split(/\s+/).filter(Boolean);
    while (words.length > 0 && (SHELL_RESERVED.has(words[0]) || ASSIGNMENT.test(words[0]) || words[0] === 'exec')) words.shift();
    const word = words[0];
    if (word === undefined) continue;
    const variable = /^"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?$/.exec(word);
    if (variable) variables.add(variable[1]);
    else if (!SHELL_BUILTINS.has(word)) programs.add(word);
  }
  return { programs: [...programs], variables: [...variables] };
}

/** What the launcher runs for a fixed-path tool: the first candidate that exists (src/pdf/sandbox.ts launcherTools). */
function expectedFixed(candidates) {
  const states = candidates.map((path) => (existsSync(path) ? { path, present: true, resolved: realpathSync(path) } : { path, present: false, resolved: null }));
  return { candidates: states, selected: states.find((state) => state.present)?.path ?? null };
}

/** What `shell`, started with the launcher's empty environment, runs for `command`. */
function expectedShellPath(shell, command) {
  if (!existsSync(shell)) return { selected: null };
  const found = spawnSync(shell, ['-c', 'command -v "$1" || :', 'li-11', command], { encoding: 'utf8', env: {} }).stdout.trim();
  return { selected: found.startsWith('/') ? found : null };
}

/** The single dpkg owner of `path`, or null, looked up independently of the tool under test. */
function dpkgOwnerOf(path, env = process.env) {
  const run = spawnSync('dpkg', ['-S', path], { encoding: 'utf8', env });
  if (run.status !== 0) return null;
  const owners = run.stdout
    .split('\n')
    .filter((line) => line.endsWith(`: ${path}`) && !/^(?:local )?diversion /.test(line))
    .map((line) => line.slice(0, -(path.length + 2)));
  return owners.length === 1 && !owners[0].includes(', ') ? owners[0] : null;
}

/** The License synopsis of the Files: * paragraph of a machine-readable Debian copyright file, or null. */
function filesStarLicense(text) {
  if (!text.startsWith('Format:')) return null;
  for (const paragraph of text.split(/\n[ \t]*\n/)) {
    const files = /^Files:(.*(?:\n[ \t].*)*)/m.exec(paragraph);
    if (!files || !files[1].trim().split(/\s+/).includes('*')) continue;
    return /^License:[ \t]*(\S.*?)[ \t]*$/m.exec(paragraph)?.[1] ?? null;
  }
  return null;
}

/** One sandbox tool's record, checked against the host independently of the tool under test. */
function assertToolRecord(item, expected, env = process.env) {
  const { observed, package_record: record } = item;
  assert.equal(item.status, 'INVENTORIED', `${item.id} status`);
  if (expected.candidates) assert.deepEqual(observed.candidates, expected.candidates, `${item.id}: every candidate path, with its resolved target`);
  assert.equal(observed.selected, expected.selected, `${item.id}: the path the launcher runs`);
  for (const field of ['policy', 'status', 'passed', 'waived']) assert.ok(!(field in record), `${item.id}: the package record evaluates nothing (${field})`);
  if (expected.selected === null) {
    assert.equal(observed.present, false, `${item.id} is recorded as absent`);
    for (const value of [observed.resolved_path, observed.version, record.query, record.package, record.license, record.license_source]) assert.equal(value, null, `${item.id}: nothing is filled in for an absent tool`);
    assert.match(observed.detail, /^absent/);
    assert.match(record.detail, /^absent/);
    return;
  }
  assert.equal(observed.present, true);
  assert.equal(observed.detail, null);
  assert.equal(observed.resolved_path, realpathSync(expected.selected), `${item.id} is resolved through its symlinks`);
  const version = spawnSync(expected.selected, ['--version'], { encoding: 'utf8', env, timeout: 30_000 });
  if (version.status === 0 && version.stdout.trim() !== '') assert.equal(observed.version, version.stdout.trim().split('\n')[0], `${item.id} --version`);
  else {
    assert.equal(observed.version, null);
    assert.match(observed.version_detail, /^--version gave no version: /);
  }
  assert.equal(record.query, `dpkg -S ${observed.resolved_path}`, `${item.id}: the package manager is asked about the resolved file`);
  const owner = dpkgOwnerOf(observed.resolved_path, env);
  assert.equal(record.package, owner, `${item.id} package, from the package records`);
  if (owner === null) {
    assert.equal(record.license, null, `${item.id}: no package record, so no license is filled in`);
    assert.equal(record.license_source, null);
    assert.match(record.detail, /^no (?:single )?package record/);
    return;
  }
  const copyright = `/usr/share/doc/${owner.split(':')[0]}/copyright`;
  if (!existsSync(copyright)) {
    assert.equal(record.license, null, `${item.id}: no copyright record, so no license is filled in`);
    assert.equal(record.license_source, null);
    assert.match(record.detail, /^no license record/);
    return;
  }
  const text = readFileSync(copyright, 'utf8');
  assert.equal(record.license_source, copyright);
  assert.equal(record.license, filesStarLicense(text), `${item.id}: the license is the record's own Files: * license`);
  if (record.license === null) assert.match(record.detail, /^no license record/);
  else assert.ok(text.includes(`\nLicense: ${record.license}\n`), `${item.id}: ${record.license} appears verbatim in ${copyright}`);
  for (const other of record.other_licenses) assert.ok(text.includes(`\nLicense: ${other}\n`), `${item.id}: ${other} appears verbatim in ${copyright}`);
}

test('[LI-11] the platform inventory records every tool the parse sandbox can launch, from package records', async () => {
  const sandbox = await import('../../src/pdf/sandbox.ts');
  const { workerCommand } = await import('../../src/pdf/service.ts');
  const { DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS } = await import('../../src/pdf/limits.ts');

  // The launcher's own tool list. The placeholder tool paths are never run: only the
  // command lines the launcher builds are read.
  const placeholder = process.execPath;
  const utilLinux = sandbox.launcherCommand(
    { available: true, launcher: 'util-linux', tools: { unshare: placeholder, mount: placeholder, chroot: placeholder, setpriv: placeholder } },
    [],
    placeholder,
    [],
  );
  const shellAt = utilLinux.args.indexOf('--') + 1;
  const shell = utilLinux.args[shellAt];
  assert.equal(utilLinux.args[shellAt + 1], '-c', 'the util-linux launcher runs a shell script');
  const setup = scriptCommands(utilLinux.args[shellAt + 2]);
  assert.ok(setup.variables.length > 0 && setup.variables.every((name) => Object.hasOwn(sandbox.TOOL_PATHS, name)), `the setup script runs fixed launcher tools: ${setup.variables}`);
  const bwrap = sandbox.launcherCommand({ available: true, launcher: 'bwrap', tools: { bwrap: placeholder } }, [], placeholder, []);
  assert.equal(bwrap.file, placeholder, 'the bwrap launcher runs bwrap itself, then the worker');
  assert.equal(workerCommand(DEFAULT_PARSER_LIMITS, DEFAULT_SERVICE_LIMITS).file, shell, 'the service wraps either launcher in the same shell');

  const expected = [
    ...Object.entries(sandbox.TOOL_PATHS).map(([id, candidates]) => ({ id, lookup: 'fixed', candidates: [...candidates] })),
    { id: 'sh', lookup: 'fixed', candidates: [shell] },
    ...setup.programs.map((command) => ({ id: command, lookup: 'shell-path', command })),
  ];
  const platform = collectPlatformInventory(REPO_ROOT);
  const missing = expected.map((tool) => tool.id).filter((id) => !platform.items.some((item) => item.id === id));
  assert.deepEqual(missing, [], `the platform inventory is missing parse-sandbox tools: ${missing.join(', ')}`);
  for (const tool of expected) {
    const item = platform.items.find((entry) => entry.id === tool.id);
    assert.equal(item.parse_sandbox?.lookup, tool.lookup, `${tool.id} lookup`);
    if (tool.lookup === 'fixed') {
      assert.deepEqual(item.parse_sandbox.candidates, tool.candidates, `${tool.id}: the launcher's candidate paths, in its order`);
      assertToolRecord(item, expectedFixed(tool.candidates));
    } else {
      assert.equal(item.parse_sandbox.command, tool.command);
      assert.equal(item.parse_sandbox.shell, shell, `${tool.id} is looked up by the launcher's shell`);
      assertToolRecord(item, expectedShellPath(shell, tool.command));
    }
  }
  assert.equal(platform.items.filter((item) => item.parse_sandbox).length, expected.length, 'no other item claims to be a parse-sandbox tool');
  assert.equal(platform.status, 'INVENTORIED');
  const unshare = platform.items.find((item) => item.id === 'unshare');
  assert.match(unshare.recorded_licenses, /GPL-2\.0-or-later/, 'the upstream license statement is kept beside the package record');
});

test('[LI-11] an absent sandbox tool is recorded as absent, and a tool with no package record gets no license', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'opensig-li11-'));
  scratch.push(dir);
  mkdirSync(join(dir, 'bin'));
  mkdirSync(join(dir, 'real'));
  writeFileSync(join(dir, 'real', 'unowned-tool'), 'synthetic file: no package owns it, and it is not a program\n');
  symlinkSync(join(dir, 'real', 'unowned-tool'), join(dir, 'bin', 'unowned-tool'));
  symlinkSync(process.execPath, join(dir, 'bin', 'linked-runtime'));
  const synthetic = [
    { id: 'synthetic-absent', name: 'synthetic absent tool', role: 'LI-11 synthetic', lookup: 'fixed', candidates: [join(dir, 'gone', 'tool'), join(dir, 'bin', 'tool')] },
    { id: 'synthetic-unowned', name: 'synthetic unowned file', role: 'LI-11 synthetic', lookup: 'fixed', candidates: [join(dir, 'gone', 'unowned-tool'), join(dir, 'bin', 'unowned-tool')] },
    { id: 'synthetic-linked', name: 'synthetic link to the runtime', role: 'LI-11 synthetic', lookup: 'fixed', candidates: [join(dir, 'bin', 'linked-runtime')] },
    { id: 'synthetic-command', name: 'synthetic absent command', role: 'LI-11 synthetic', lookup: 'shell-path', command: `opensig-li11-${randomBytes(8).toString('hex')}` },
  ];
  const platform = collectPlatformInventory(REPO_ROOT, { sandboxTools: synthetic });
  const listed = platform.items.filter((item) => item.parse_sandbox);
  assert.deepEqual(
    listed.map((item) => item.id),
    synthetic.map((tool) => tool.id),
    'every sandbox tool is listed, absent ones included',
  );
  const byId = Object.fromEntries(listed.map((item) => [item.id, item]));
  for (const tool of synthetic) assertToolRecord(byId[tool.id], tool.lookup === 'fixed' ? expectedFixed(tool.candidates) : expectedShellPath('/bin/sh', tool.command));

  const absent = byId['synthetic-absent'];
  assert.equal(absent.observed.present, false);
  assert.deepEqual(absent.observed.candidates, synthetic[0].candidates.map((path) => ({ path, present: false, resolved: null })), 'each candidate is recorded as absent');
  assert.equal(byId['synthetic-command'].observed.present, false, 'a command the shell cannot find is recorded as absent');
  const unowned = byId['synthetic-unowned'];
  assert.equal(unowned.observed.selected, join(dir, 'bin', 'unowned-tool'));
  assert.equal(unowned.observed.resolved_path, realpathSync(join(dir, 'real', 'unowned-tool')), 'the symbolic link is resolved to the real file');
  assert.equal(unowned.observed.version, null);
  assert.match(unowned.observed.version_detail, /^--version gave no version: /);
  assert.equal(unowned.package_record.package, null);
  assert.equal(unowned.package_record.license, null, 'no package record: no license is invented');
  assert.match(unowned.package_record.detail, /^no package record/);
  const linked = byId['synthetic-linked'];
  assert.equal(linked.observed.resolved_path, realpathSync(process.execPath));
  assert.equal(linked.observed.version, process.version, 'the --version output is recorded');
  assert.equal(platform.status, 'INVENTORIED');

  // Without the package manager no package is named and no license is filled in.
  const noDpkg = collectPlatformInventory(REPO_ROOT, { env: { PATH: '' } });
  const tools = noDpkg.items.filter((item) => item.parse_sandbox);
  assert.ok(tools.length > 0);
  for (const item of tools) {
    assert.equal(item.package_record.package, null, `${item.id} package`);
    assert.equal(item.package_record.license, null, `${item.id} license`);
    assert.match(item.package_record.detail, item.observed.present ? /^no package record: dpkg could not run/ : /^absent/, item.id);
  }

  // A license is read only from a machine-readable record's Files: * paragraph, never from free text.
  const { debianCopyrightLicense } = await import('../../scripts/platform-inventory.mjs');
  const header = 'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: synthetic\n';
  const extra = 'Files: lib/extra.c\nCopyright: 2026 Synthetic Authors\nLicense: BSD-3-Clause\n';
  const main = 'Files: *\nCopyright: 2026 Synthetic Authors\nLicense: GPL-2+\n';
  const text = 'License: GPL-2+\n Synthetic license text.\n .\n More synthetic text.\n';
  assert.deepEqual(debianCopyrightLicense([header, extra, main, text].join('\n')), { license: 'GPL-2+', other_licenses: ['BSD-3-Clause'], detail: null });
  const noDefault = debianCopyrightLicense([header, extra, text].join('\n'));
  assert.equal(noDefault.license, null);
  assert.deepEqual(noDefault.other_licenses, ['BSD-3-Clause']);
  assert.match(noDefault.detail, /Files: \*/);
  const noLicense = debianCopyrightLicense([header, 'Files: *\nCopyright: 2026 Synthetic Authors\n'].join('\n'));
  assert.equal(noLicense.license, null);
  assert.match(noLicense.detail, /License/);
  const freeText = debianCopyrightLicense('This package was debianized by a synthetic maintainer.\nIt is distributed under the GNU GPL.\n');
  assert.equal(freeText.license, null, 'no license is read from free text');
  assert.match(freeText.detail, /machine-readable/);
});
