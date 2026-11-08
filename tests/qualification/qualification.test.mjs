// SPDX-License-Identifier: Apache-2.0
//
// Qualification of the complete third-party package set (T027), QL-01..QL-05.
//
// The qualification run writes the registry evidence
// $OPENSIG_VERIFY_OUT/inventory.json (.verify-out/qualification/inventory.json)
// bound to the run's tree digest.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { accessSync, constants, copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { findDevBytesInDist } from './dev-bytes.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const INVENTORY_TOOL = join(REPO_ROOT, 'scripts', 'license-inventory.mjs');
const PLAYWRIGHT_VERSION = '1.61.1';
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

const scratch = [];
after(() => {
  for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});

function tempDir(label) {
  const dir = mkdtempSync(join(tmpdir(), `opensig-qualification-${label}-`));
  scratch.push(dir);
  return dir;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function write(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

// --- QL-01 ------------------------------------------------------------------------

test('[QL-01] the shipped-package gate passes on the complete package set and the shipped closure is empty', () => {
  const out = tempDir('inventory');
  const run = spawnSync(process.execPath, [INVENTORY_TOOL, '--root', REPO_ROOT, '--out', out], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.match(run.stdout, /license-inventory: PASS application-gate shipped=0 non-shipped=6 notice=current platform=POLICY-PENDING\n$/);
  const inventory = readJson(join(out, 'inventory.json'));
  assert.equal(inventory.application_gate, 'PASS');
  assert.equal(inventory.shipped, 0);
  assert.deepEqual(readJson(join(REPO_ROOT, 'package.json')).dependencies ?? {}, {}, 'package.json declares no shipped dependency');

  // Registry evidence for the qualification mode, bound to this run's tree.
  const evidenceDir = process.env.OPENSIG_VERIFY_OUT;
  if (evidenceDir) {
    const sbom = readFileSync(join(out, 'sbom.cdx.json'));
    write(
      join(evidenceDir, 'inventory.json'),
      `${JSON.stringify(
        {
          ...inventory,
          tree_digest: process.env.OPENSIG_VERIFY_TREE_DIGEST,
          sbom_sha256: createHash('sha256').update(sbom).digest('hex'),
          playwright_version: PLAYWRIGHT_VERSION,
        },
        null,
        2,
      )}\n`,
    );
  }
});

// --- QL-02 ------------------------------------------------------------------------

test('[QL-02] every package.json version is an exact pin and matches the lockfile', () => {
  const pkg = readJson(join(REPO_ROOT, 'package.json'));
  const lock = readJson(join(REPO_ROOT, 'package-lock.json'));
  const npmrc = readFileSync(join(REPO_ROOT, '.npmrc'), 'utf8');
  assert.match(npmrc, /^save-exact=true$/m);
  let checked = 0;
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, spec] of Object.entries(pkg[field] ?? {})) {
      assert.match(spec, EXACT_VERSION, `${field}.${name} must be an exact version, found ${spec}`);
      assert.equal(lock.packages[`node_modules/${name}`]?.version, spec, `${name} is locked at its pinned version`);
      checked += 1;
    }
  }
  assert.deepEqual(Object.keys(pkg.devDependencies).sort(), ['@types/node', 'playwright', 'typescript']);
  assert.equal(pkg.devDependencies.playwright, PLAYWRIGHT_VERSION);
  assert.equal(lock.packages['node_modules/playwright-core'].version, PLAYWRIGHT_VERSION, 'playwright-core matches playwright exactly');
  assert.equal(checked, 3);
});

// --- QL-03 ------------------------------------------------------------------------

function syntheticProject({ dist }) {
  const root = tempDir('dist');
  const runtime = `export function devHelper() { return ${JSON.stringify(randomBytes(48).toString('hex'))}; }\n`;
  const rootPkg = { name: 'fixture-app', version: '1.0.0', license: 'Apache-2.0', dependencies: {}, devDependencies: { 'dev-kit': '1.0.0' } };
  write(join(root, 'package.json'), JSON.stringify(rootPkg));
  write(
    join(root, 'package-lock.json'),
    JSON.stringify({
      name: 'fixture-app',
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': rootPkg,
        'node_modules/dev-kit': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/dev-kit/-/dev-kit-1.0.0.tgz',
          integrity: `sha512-${createHash('sha512').update('dev-kit@1.0.0').digest('base64')}`,
          dev: true,
          license: 'MIT',
        },
      },
    }),
  );
  write(join(root, 'node_modules', 'dev-kit', 'package.json'), JSON.stringify({ name: 'dev-kit', version: '1.0.0', license: 'MIT' }));
  write(join(root, 'node_modules', 'dev-kit', 'LICENSE'), 'Synthetic MIT text for dev-kit.\n');
  write(join(root, 'node_modules', 'dev-kit', 'lib', 'runtime.js'), runtime);
  for (const [file, content] of Object.entries(dist(runtime))) write(join(root, 'dist', file), content);
  return root;
}

test('[QL-03] the "dev bytes not in distributable" check fails on a dist that contains dev-package bytes', () => {
  const embedded = findDevBytesInDist(syntheticProject({ dist: (runtime) => ({ 'app.js': `// original application code\n${runtime}// end\n` }) }));
  assert.deepEqual(
    embedded.map((f) => [f.rule, f.package, f.file, f.dist]),
    [['embedded-bytes', 'dev-kit@1.0.0', 'lib/runtime.js', 'dist/app.js']],
  );
  const copied = findDevBytesInDist(syntheticProject({ dist: (runtime) => ({ 'vendor/runtime.js': runtime }) }));
  assert.deepEqual(
    copied.map((f) => [f.rule, f.package, f.dist]),
    [['asset-copy', 'dev-kit@1.0.0', 'dist/vendor/runtime.js']],
  );
  const clean = findDevBytesInDist(syntheticProject({ dist: () => ({ 'app.js': `export const build = ${JSON.stringify(randomBytes(40).toString('hex'))};\n` }) }));
  assert.deepEqual(clean, [], 'original bytes only');
  assert.deepEqual(findDevBytesInDist(REPO_ROOT), [], 'the code leg has no dev bytes in dist/');
});

// --- QL-04 ------------------------------------------------------------------------

test('[QL-04] the pinned Playwright Chromium revision is present at the effective browsers path and launches headless', async () => {
  const browsers = readJson(join(REPO_ROOT, 'node_modules', 'playwright-core', 'browsers.json')).browsers;
  const chromium = browsers.find((browser) => browser.name === 'chromium');
  const shell = browsers.find((browser) => browser.name === 'chromium-headless-shell');
  assert.ok(chromium && shell, 'playwright-core names chromium and its headless shell');
  assert.equal(shell.revision, chromium.revision);

  const configured = process.env.PLAYWRIGHT_BROWSERS_PATH;
  const effective = configured && configured !== '0' ? resolve(configured) : join(homedir(), '.cache', 'ms-playwright');
  for (const dir of [`chromium-${chromium.revision}`, `chromium_headless_shell-${shell.revision}`]) {
    assert.ok(existsSync(join(effective, dir, 'INSTALLATION_COMPLETE')), `${dir} is installed under ${effective} (revision must match the pinned Playwright)`);
  }
  // The same layout the frozen runner's chromium probe accepts.
  const layouts = readdirSync(join(effective, `chromium-${chromium.revision}`)).filter((entry) => entry.startsWith('chrome-linux'));
  assert.ok(
    layouts.some((entry) => {
      try {
        accessSync(join(effective, `chromium-${chromium.revision}`, entry, 'chrome'), constants.X_OK);
        return true;
      } catch {
        return false;
      }
    }),
    'an executable chrome-linux*/chrome exists for the pinned revision',
  );

  // A non-literal specifier keeps Playwright's DOM-typed declarations out of the
  // frozen typecheck program (tsconfig lib es2024, no skipLibCheck).
  const playwrightModule = 'playwright';
  const { chromium: launcher } = await import(playwrightModule);
  assert.ok(launcher.executablePath().startsWith(join(effective, `chromium-${chromium.revision}`)), `Playwright resolves ${launcher.executablePath()}`);
  const browser = await launcher.launch({ headless: true, timeout: 60_000 });
  try {
    assert.equal(browser.version(), chromium.browserVersion, 'the launched build is the pinned revision');
    const page = await browser.newPage();
    await page.goto('about:blank');
    assert.equal(page.url(), 'about:blank');
    assert.equal(await page.evaluate(() => 6 * 7), 42);
  } finally {
    await browser.close();
  }
});

// --- QL-05 ------------------------------------------------------------------------

test('[QL-05] the locked package set installs with ignore-scripts and loses nothing on linux', () => {
  assert.match(readFileSync(join(REPO_ROOT, '.npmrc'), 'utf8'), /^ignore-scripts=true$/m);
  const lock = readJson(join(REPO_ROOT, 'package-lock.json'));
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!entry.hasInstallScript) continue;
    assert.ok(entry.optional && Array.isArray(entry.os) && !entry.os.includes('linux'), `${path} needs an install script on linux`);
  }

  const dir = tempDir('install');
  for (const file of ['package.json', 'package-lock.json', '.npmrc', '.node-version']) copyFileSync(join(REPO_ROOT, file), join(dir, file));
  const npmCli = join(dirname(process.execPath), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');
  // A fresh install: drop the npm_* variables an enclosing `npm run` exports,
  // so only the project and user .npmrc files configure it.
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^npm_/i.test(key)));
  const install = spawnSync(process.execPath, [npmCli, 'ci', '--offline', '--ignore-scripts', '--no-audit', '--no-fund'], {
    cwd: dir,
    env,
    encoding: 'utf8',
    timeout: 300_000,
  });
  assert.equal(install.status, 0, `offline npm ci --ignore-scripts failed:\n${install.stdout}${install.stderr}`);
  assert.equal(readJson(join(dir, 'node_modules', 'playwright', 'package.json')).version, PLAYWRIGHT_VERSION);
  assert.equal(readJson(join(dir, 'node_modules', 'playwright-core', 'package.json')).version, PLAYWRIGHT_VERSION);
  assert.equal(readJson(join(dir, 'node_modules', 'typescript', 'package.json')).version, '6.0.3');
  assert.equal(existsSync(join(dir, 'node_modules', 'fsevents')), false, 'the darwin-only optional package is not installed on linux');
});

// --- non-shipped inventory and notices ---------------------------------------------

test('the non-shipped inventory and the third-party notices of the development tools are recorded', () => {
  const out = tempDir('notices');
  const run = spawnSync(process.execPath, [INVENTORY_TOOL, '--root', REPO_ROOT, '--out', out], { encoding: 'utf8', timeout: 120_000 });
  assert.equal(run.status, 0, run.stdout);
  const packages = readJson(join(out, 'inventory.json')).packages;
  assert.deepEqual(
    packages.map((pkg) => `${pkg.name}@${pkg.version}:${pkg.classification}:${pkg.policy}`).sort(),
    [
      '@types/node@24.19.2:non-shipped:allowed',
      'fsevents@2.3.2:non-shipped:allowed',
      `playwright-core@${PLAYWRIGHT_VERSION}:non-shipped:allowed`,
      `playwright@${PLAYWRIGHT_VERSION}:non-shipped:allowed`,
      'typescript@6.0.3:non-shipped:allowed',
      'undici-types@7.24.6:non-shipped:allowed',
    ],
  );
  const notices = [
    'node_modules/typescript/ThirdPartyNoticeText.txt',
    'node_modules/playwright-core/ThirdPartyNotices.txt',
    'node_modules/playwright-core/lib/utilsBundle.js.LICENSE',
    'node_modules/playwright-core/lib/serverRegistry.js.LICENSE',
    'node_modules/playwright/ThirdPartyNotices.txt',
    'node_modules/playwright/lib/matchers/expect.js.LICENSE',
    'node_modules/playwright/lib/transform/babelBundle.js.LICENSE',
    'node_modules/playwright/lib/transform/esmLoader.js.LICENSE',
  ];
  const doc = readFileSync(join(REPO_ROOT, 'docs', 'qualification.md'), 'utf8');
  for (const notice of notices) {
    assert.ok(existsSync(join(REPO_ROOT, notice)), `${notice} exists`);
    assert.ok(doc.includes(notice.replace('node_modules/', '')), `docs/qualification.md records ${notice}`);
  }
  assert.ok(doc.includes(`playwright ${PLAYWRIGHT_VERSION}`) && doc.includes('chromium-1228'), 'the pinned version and revision are recorded');
});
