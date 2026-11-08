#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig platform inventory (T002).
//
//   node scripts/platform-inventory.mjs [--root DIR] [--out DIR]
//
// Records the platform this code runs on but does not ship as an npm package:
// the pinned Node.js runtime, the libraries its binary links, the OpenSSL CLI,
// util-linux unshare (the PDF parser's namespace sandbox launcher), the
// Chromium build used by browser tests, and the isolated Hermes image.
//
// Owner decision (2026-11-08, verbatim): "MIT/Apache application and
// libraries; inventory platform licenses separately" (spec plan.md, "Owner
// decision: platform license scope (resolved 2026-11-08)"). Platforms are
// therefore recorded separately, with their own licenses, under status
// INVENTORIED: they are not held to the MIT/Apache-2.0 allowlist, and no
// platform entry ever affects the application gate (scripts/license-inventory.mjs),
// which stays strictly MIT/Apache-2.0. This tool never reports PASS and waives
// nothing. Its exit status says only whether the inventory was written.

import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PLATFORM_STATUS = 'INVENTORIED';
export const OWNER_DECISION = 'MIT/Apache application and libraries; inventory platform licenses separately';
export const PLATFORM_DECISION =
  `Owner decision (2026-11-08): "${OWNER_DECISION}" (spec plan.md "Owner decision: platform license scope (resolved 2026-11-08)"). Platform items are recorded separately with their own licenses; they are not held to the MIT/Apache-2.0 allowlist and never affect the application gate. No platform item is passed or waived.`;
export const HERMES_IMAGE =
  'docker.io/nousresearch/hermes-agent@sha256:adb7890916de63245523492be8f68f9d2095fecbec4e2a6dab7960381f0fc002';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PROBE_TIMEOUT_MS = 30_000;

function run(command, args, env) {
  const result = spawnSync(command, args, { encoding: 'utf8', env, timeout: PROBE_TIMEOUT_MS });
  if (result.error) return { ok: false, detail: `${command} could not run: ${result.error.code ?? result.error.message}` };
  if (result.status !== 0) return { ok: false, detail: `${command} exited ${result.status ?? result.signal}` };
  return { ok: true, stdout: result.stdout };
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

function nodeRuntimeItem(root, env) {
  const receipt = readJson(join(root, 'tools', 'node.receipt.json'));
  const binary = join(root, 'tools', 'node', 'bin', 'node');
  const version = run(binary, ['--version'], env);
  return {
    id: 'node-runtime',
    name: 'Node.js runtime (pinned, tools/node)',
    role: 'application runtime; its binary and bundled npm are platform, not npm dependencies',
    observed: {
      receipt: receipt
        ? {
            version: receipt.version ?? null,
            tarball_sha256: receipt.tarball_sha256 ?? null,
            node_sha256: receipt.node_sha256 ?? null,
            npm_tree_sha256: receipt.npm_tree_sha256 ?? null,
            signer_fingerprint: receipt.signer_fingerprint ?? null,
          }
        : null,
      version: version.ok ? version.stdout.trim() : null,
      detail: receipt ? null : 'tools/node.receipt.json is absent; run sh scripts/fetch-node.sh',
    },
    recorded_licenses:
      'Node.js MIT; inside the binary V8 BSD-3-Clause, ICU Unicode-3.0, zlib Zlib, zstd BSD, ittapi and inspector_protocol BSD, SipHash CC0, HdrHistogram BSD-2/CC0, minimatch BlueOak-1.0.0, rimraf and node-heapdump ISC, SQLite public-domain blessing, root CA certificates (provenance unverified); in the tarball npm Artistic-2.0 (recorded from spec plan.md, not re-measured here)',
  };
}

function linkedLibrariesItem(root, env) {
  const binary = join(root, 'tools', 'node', 'bin', 'node');
  const ldd = run('ldd', [binary], env);
  const libraries = [];
  if (ldd.ok) {
    for (const raw of ldd.stdout.split('\n')) {
      const line = raw.trim().replace(/\s*\(0x[0-9a-f]+\)$/, ''); // load addresses vary per run
      if (line === '') continue;
      const arrow = line.indexOf(' => ');
      if (arrow >= 0) libraries.push({ soname: line.slice(0, arrow), path: line.slice(arrow + 4) || null });
      else libraries.push({ soname: line, path: null });
    }
  }
  return {
    id: 'linked-libraries',
    name: 'Dynamically linked system libraries of the Node.js binary (ldd)',
    role: 'platform libraries resolved at run time (glibc LGPL-2.1, libstdc++/libgcc_s GPL-3+ with the GCC Runtime Library Exception, per spec plan.md)',
    observed: { libraries, detail: ldd.ok ? null : ldd.detail },
  };
}

function opensslItem(env) {
  const version = run('openssl', ['version'], env);
  return {
    id: 'openssl-cli',
    name: 'OpenSSL command-line tool',
    role: 'non-shipped test oracle and development-certificate tool',
    observed: { version: version.ok ? version.stdout.trim() : null, detail: version.ok ? null : version.detail },
  };
}

function unshareItem(env) {
  const version = run('unshare', ['--version'], env);
  return {
    id: 'unshare',
    name: 'util-linux unshare',
    role: 'platform tool: launches the PDF parse worker in a new user and network namespace (T033 parser sandbox, plan.md amendment A-007)',
    observed: { version: version.ok ? version.stdout.trim().split('\n')[0] : null, detail: version.ok ? null : version.detail },
    recorded_licenses:
      'util-linux: no single license; GPL-2.0-or-later by default, with LGPL-2.1-or-later, BSD and public-domain parts (util-linux README.licensing; recorded, not re-measured here)',
  };
}

function isRegularFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * The browsers directory exactly as the frozen runner's chromium probe
 * (scripts/verify.mjs probeChromium) resolves it: the first of playwright-core
 * and playwright with a browsers.json is the package; PLAYWRIGHT_BROWSERS_PATH=0
 * means <package>/.local-browsers, any other non-empty value is resolved, and
 * unset or empty means the default cache. Returns { packageDir, path, source }.
 */
export function effectiveBrowsersPath(root, env) {
  let packageDir = null;
  for (const name of ['playwright-core', 'playwright']) {
    const dir = join(root, 'node_modules', name);
    if (isRegularFile(join(dir, 'browsers.json'))) {
      packageDir = dir;
      break;
    }
  }
  const configured = env.PLAYWRIGHT_BROWSERS_PATH;
  if (configured === '0') {
    return packageDir
      ? { packageDir, path: join(packageDir, '.local-browsers'), source: 'PLAYWRIGHT_BROWSERS_PATH=0 (package-local)' }
      : { packageDir, path: null, source: 'PLAYWRIGHT_BROWSERS_PATH=0, but Playwright is not installed' };
  }
  if (configured) return { packageDir, path: resolve(configured), source: 'PLAYWRIGHT_BROWSERS_PATH' };
  return { packageDir, path: join(homedir(), '.cache', 'ms-playwright'), source: 'default cache' };
}

function chromiumItem(root, env) {
  const effective = effectiveBrowsersPath(root, env);
  let pinnedRevision = null;
  if (effective.packageDir) {
    const browsers = readJson(join(effective.packageDir, 'browsers.json'));
    const chromium = browsers?.browsers?.find?.((browser) => browser.name === 'chromium');
    if (chromium?.revision) pinnedRevision = String(chromium.revision);
  }
  // The effective location comes first; the default cache is listed too when
  // it differs, so a mismatch between the two is visible.
  const defaultCache = join(homedir(), '.cache', 'ms-playwright');
  const paths = [];
  if (effective.path) paths.push({ path: effective.path, source: `${effective.source} (effective)` });
  if (effective.path !== defaultCache) paths.push({ path: defaultCache, source: 'default cache' });
  const locations = paths.map(({ path, source }) => {
    let builds = [];
    try {
      builds = readdirSync(path)
        .filter((entry) => /^chromium(?:_headless_shell)?-\d+$/.test(entry))
        .sort();
    } catch {
      builds = [];
    }
    return { path, source, builds };
  });
  return {
    id: 'chromium',
    name: 'Chromium build for browser tests (Playwright)',
    role: 'non-shipped test-time browser',
    observed: {
      pinned_revision: pinnedRevision,
      active_location: effective.path,
      active_source: effective.source,
      locations,
      detail: pinnedRevision ? null : 'Playwright is not installed; cached builds are listed as found',
    },
  };
}

function hermesItem() {
  return {
    id: 'hermes-image',
    name: 'Isolated Hermes agent image',
    role: 'non-shipped SC-006 test runtime, run with --network none',
    observed: {
      reference: HERMES_IMAGE,
      version: 'v0.23.0',
      detail: 'pinned reference from spec plan.md; local presence is probed by scripts/capabilities/hermes-runtime.mjs (T040)',
    },
  };
}

/** Collect the platform inventory. Every item's status is INVENTORIED (recorded separately, never gating). */
export function collectPlatformInventory(root = REPO_ROOT, { env = process.env } = {}) {
  const items = [nodeRuntimeItem(root, env), linkedLibrariesItem(root, env), opensslItem(env), unshareItem(env), chromiumItem(root, env), hermesItem()];
  return {
    kind: 'opensig-platform-inventory',
    status: PLATFORM_STATUS,
    decision: PLATFORM_DECISION,
    items: items.map((item) => ({ ...item, status: PLATFORM_STATUS })),
  };
}

export function writePlatformInventory(outDir, inventory) {
  mkdirSync(outDir, { recursive: true });
  const path = join(outDir, 'platform-inventory.json');
  writeFileSync(path, `${JSON.stringify(inventory, null, 2)}\n`);
  return path;
}

function parseArgs(argv) {
  const options = { root: REPO_ROOT, out: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if ((arg === '--root' || arg === '--out') && i + 1 < argv.length) options[arg.slice(2)] = resolve(argv[(i += 1)]);
    else return { error: `unknown or incomplete argument ${arg}` };
  }
  options.out ??= join(options.root, '.verify-out', 'platform-inventory');
  return options;
}

function main(argv) {
  const options = parseArgs(argv);
  if (options.error) {
    process.stderr.write(`platform-inventory: ${options.error}\nusage: node scripts/platform-inventory.mjs [--root DIR] [--out DIR]\n`);
    process.exitCode = 2;
    return;
  }
  const inventory = collectPlatformInventory(options.root);
  const path = writePlatformInventory(options.out, inventory);
  process.stdout.write(`platform-inventory: ${PLATFORM_STATUS} items=${inventory.items.length} written=${path} (recorded separately; never gates the application)\n`);
  process.exitCode = 0;
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
