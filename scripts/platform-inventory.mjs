#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig platform inventory (T002).
//
//   node scripts/platform-inventory.mjs [--root DIR] [--out DIR]
//
// Records the platform this code runs on but does not ship as an npm package:
// the pinned Node.js runtime, the libraries its binary links, the OpenSSL CLI,
// the Chromium build used by browser tests, and the isolated Hermes image.
//
// Every item, and the inventory as a whole, carries status POLICY-PENDING: the
// owner has not yet decided the platform license scope (spec plan.md, "Pending
// owner decision: platform license scope"). This tool never reports PASS and
// waives nothing. Its exit status says only whether the inventory was written.

import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PLATFORM_STATUS = 'POLICY-PENDING';
export const PLATFORM_DECISION =
  'Owner decision on platform license scope is pending (spec plan.md "Pending owner decision: platform license scope"). No platform item is passed or waived.';
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

function chromiumItem(root, env) {
  let pinnedRevision = null;
  for (const name of ['playwright-core', 'playwright']) {
    const browsers = readJson(join(root, 'node_modules', name, 'browsers.json'));
    const chromium = browsers?.browsers?.find?.((browser) => browser.name === 'chromium');
    if (chromium?.revision) {
      pinnedRevision = String(chromium.revision);
      break;
    }
  }
  // Playwright reads PLAYWRIGHT_BROWSERS_PATH when set, else the default cache;
  // both locations are recorded so the build that would run is visible.
  const configured = env.PLAYWRIGHT_BROWSERS_PATH;
  const defaultCache = join(homedir(), '.cache', 'ms-playwright');
  const paths = [];
  if (configured && configured !== '0') paths.push({ path: resolve(configured), source: 'PLAYWRIGHT_BROWSERS_PATH' });
  paths.push({ path: defaultCache, source: 'default cache' });
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
      active_location: locations[0].path,
      locations,
      detail: pinnedRevision ? null : 'Playwright is not installed yet (T027 pins it); cached builds are listed as found',
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

/** Collect the platform inventory. Every item's status is POLICY-PENDING. */
export function collectPlatformInventory(root = REPO_ROOT, { env = process.env } = {}) {
  const items = [nodeRuntimeItem(root, env), linkedLibrariesItem(root, env), opensslItem(env), chromiumItem(root, env), hermesItem()];
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
  process.stdout.write(`platform-inventory: ${PLATFORM_STATUS} items=${inventory.items.length} written=${path} (recorded, not passed)\n`);
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
