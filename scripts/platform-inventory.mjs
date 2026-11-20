#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig platform inventory (T002).
//
//   node scripts/platform-inventory.mjs [--root DIR] [--out DIR]
//
// Records the platform this code runs on but does not ship as an npm package:
// the pinned Node.js runtime, the libraries its binary links, the OpenSSL CLI,
// every platform tool the PDF parse sandbox can launch (A-009 and A-010 LI-11:
// bwrap, unshare, mount, chroot, setpriv, /bin/sh and the programs its setup
// script runs by name), the Chromium build used by browser tests, and the
// isolated Hermes image.
//
// Each sandbox tool is recorded with the candidate paths the launcher checks,
// the path it would run, that path resolved through its symbolic links, and
// its --version output where it gives one. The owning package comes only from
// the package manager (`dpkg -S <resolved path>`) and the license only from
// that package's Debian copyright record (the License of its `Files: *`
// paragraph). A tool with no package record, or a package with no readable
// license record, is reported as such with no license filled in, and a tool
// absent from the host is recorded as absent. Nothing is guessed or relaxed.
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
import { existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PLATFORM_STATUS = 'INVENTORIED';
export const OWNER_DECISION = 'MIT/Apache application and libraries; inventory platform licenses separately';
export const PLATFORM_DECISION =
  `Owner decision (2026-11-08): "${OWNER_DECISION}" (spec plan.md "Owner decision: platform license scope (resolved 2026-11-08)"). Platform items are recorded separately with their own licenses; they are not held to the MIT/Apache-2.0 allowlist and never affect the application gate. No platform item is passed or waived.`;
export const HERMES_IMAGE =
  'docker.io/nousresearch/hermes-agent@sha256:adb7890916de63245523492be8f68f9d2095fecbec4e2a6dab7960381f0fc002';

/** The shell the sandbox launchers run under (src/pdf/sandbox.ts and src/pdf/service.ts SHELL). */
export const SANDBOX_SHELL = '/bin/sh';

/**
 * Every platform tool the PDF parse sandbox launcher can run (src/pdf/sandbox.ts, T033), in
 * the launcher's order. LI-11 derives the same list from the launcher itself and fails when
 * the two differ.
 * - `fixed`: found at fixed absolute candidate paths, the first existing one winning, as
 *   sandbox.ts TOOL_PATHS and launcherTools() pick it. PATH is never searched.
 * - /bin/sh: runs the util-linux setup script inside unshare, and the service's ulimit
 *   wrapper around either launcher.
 * - `shell-path`: run by name from that setup script. The service starts the launcher with
 *   an empty environment, so /bin/sh finds the program on its own default search path.
 */
export const PARSE_SANDBOX_TOOLS = Object.freeze(
  [
    {
      id: 'bwrap',
      name: 'bwrap',
      lookup: 'fixed',
      candidates: ['/usr/bin/bwrap', '/bin/bwrap'],
      role: 'platform tool: the preferred PDF parse-sandbox launcher (T033; src/pdf/sandbox.ts TOOL_PATHS.bwrap)',
    },
    {
      id: 'unshare',
      name: 'util-linux unshare',
      lookup: 'fixed',
      candidates: ['/usr/bin/unshare', '/bin/unshare'],
      role: 'platform tool: launches the PDF parse worker in a new user and network namespace (T033 parser sandbox, plan.md amendment A-007); the util-linux launcher (src/pdf/sandbox.ts TOOL_PATHS.unshare)',
      recorded_licenses:
        'util-linux: no single license; GPL-2.0-or-later by default, with LGPL-2.1-or-later, BSD and public-domain parts (util-linux README.licensing; recorded, not re-measured here)',
    },
    {
      id: 'mount',
      name: 'mount',
      lookup: 'fixed',
      candidates: ['/usr/bin/mount', '/bin/mount'],
      role: 'platform tool: the util-linux launcher mounts the tmpfs sandbox root and its read-only binds with it (src/pdf/sandbox.ts TOOL_PATHS.mount)',
    },
    {
      id: 'chroot',
      name: 'chroot',
      lookup: 'fixed',
      candidates: ['/usr/sbin/chroot', '/usr/bin/chroot', '/sbin/chroot'],
      role: 'platform tool: the util-linux launcher enters the sandbox root with it (src/pdf/sandbox.ts TOOL_PATHS.chroot)',
    },
    {
      id: 'setpriv',
      name: 'setpriv',
      lookup: 'fixed',
      candidates: ['/usr/bin/setpriv', '/bin/setpriv'],
      role: 'platform tool: bound into the sandbox root, it drops every capability before the worker runs, under the util-linux launcher (src/pdf/sandbox.ts TOOL_PATHS.setpriv)',
    },
    {
      id: 'sh',
      name: SANDBOX_SHELL,
      lookup: 'fixed',
      candidates: [SANDBOX_SHELL],
      role: "platform tool: runs the util-linux launcher's setup script inside unshare, and the service's ulimit wrapper around either launcher (src/pdf/sandbox.ts and src/pdf/service.ts SHELL)",
    },
    {
      id: 'mkdir',
      name: 'mkdir',
      lookup: 'shell-path',
      command: 'mkdir',
      role: "platform tool: the util-linux launcher's setup script creates the bind targets in the sandbox root with it, by name, found on /bin/sh's default search path",
    },
  ].map((tool) => Object.freeze({ ...tool, ...(tool.candidates ? { candidates: Object.freeze(tool.candidates) } : {}) })),
);

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PROBE_TIMEOUT_MS = 30_000;
const DEBIAN_DOC_ROOT = '/usr/share/doc';

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

// --- parse-sandbox tools (A-009, A-010 LI-11) ---------------------------------------------

function pathState(path) {
  if (!existsSync(path)) return { path, present: false, resolved: null };
  try {
    return { path, present: true, resolved: realpathSync(path) };
  } catch {
    return { path, present: true, resolved: null };
  }
}

/** Where the launcher finds `tool`: its candidates, the path it runs, and why none is found. */
function locateTool(tool) {
  if (tool.lookup === 'fixed') {
    const candidates = tool.candidates.map(pathState);
    const selected = candidates.find((state) => state.present) ?? null;
    return {
      candidates,
      selected: selected?.path ?? null,
      detail: selected ? null : `absent: none of the launcher's candidate paths exists (${tool.candidates.join(', ')})`,
    };
  }
  // The launcher's environment is empty (src/pdf/service.ts spawns it with env {}), so the
  // shell searches its own default PATH. The same shell, run the same way, reports it.
  if (!existsSync(SANDBOX_SHELL)) return { search_path: null, candidates: [], selected: null, detail: `absent: ${SANDBOX_SHELL} is absent, so nothing runs ${tool.command}` };
  const lookup = spawnSync(SANDBOX_SHELL, ['-c', 'printf "%s\\n" "$PATH"; command -v "$1" || :', 'opensig-platform-inventory', tool.command], {
    encoding: 'utf8',
    env: {},
    timeout: PROBE_TIMEOUT_MS,
  });
  if (lookup.error || lookup.status !== 0) {
    const why = lookup.error ? `could not run: ${lookup.error.code ?? lookup.error.message}` : `exited ${lookup.status ?? lookup.signal}`;
    return { search_path: null, candidates: [], selected: null, detail: `absent: ${SANDBOX_SHELL} could not look up ${tool.command} (${why})` };
  }
  const [searchPath = '', found = ''] = lookup.stdout.split('\n');
  const candidates = searchPath
    .split(':')
    .filter((dir) => dir.startsWith('/'))
    .map((dir) => pathState(join(dir, tool.command)));
  if (found.startsWith('/')) return { search_path: searchPath, candidates, selected: found, detail: null };
  const detail = found
    ? `absent: ${tool.command} is a ${SANDBOX_SHELL} built-in here, not a separate program`
    : `absent: ${SANDBOX_SHELL} finds no ${tool.command} on its default search path ${searchPath}`;
  return { search_path: searchPath, candidates, selected: null, detail };
}

function versionOf(path, env) {
  const result = run(path, ['--version'], env);
  if (!result.ok) return { version: null, version_detail: `--version gave no version: ${result.detail}` };
  const first = result.stdout.trim().split('\n')[0];
  return first ? { version: first, version_detail: null } : { version: null, version_detail: '--version gave no version: it printed nothing' };
}

/**
 * The dpkg owners of exact absolute `paths` (one `dpkg -S` run). Returns { owners: Map path ->
 * [package...] } or { owners: null, detail } when the package manager cannot be asked. dpkg
 * exits 1 when some path has no owner and still prints the others.
 */
function dpkgOwners(paths, env) {
  if (paths.length === 0) return { owners: new Map(), detail: null };
  const escaped = paths.map((path) => path.replace(/[*?[\\]/g, '\\$&')); // dpkg patterns: match each path literally
  const result = spawnSync('dpkg', ['-S', ...escaped], { encoding: 'utf8', env, timeout: PROBE_TIMEOUT_MS });
  if (result.error) return { owners: null, detail: `dpkg could not run: ${result.error.code ?? result.error.message}` };
  if (result.status !== 0 && result.status !== 1) return { owners: null, detail: `dpkg -S exited ${result.status ?? result.signal}` };
  const owners = new Map();
  for (const line of result.stdout.split('\n')) {
    if (line === '' || /^(?:local )?diversion /.test(line)) continue;
    for (const path of paths) if (line.endsWith(`: ${path}`)) owners.set(path, line.slice(0, -(path.length + 2)).split(', '));
  }
  return { owners, detail: null };
}

/** Installed versions of `packages` from the package records (one `dpkg-query -W` run). */
function dpkgVersions(packages, env) {
  const versions = new Map();
  if (packages.length === 0) return versions;
  const result = spawnSync('dpkg-query', ['-W', '-f=${binary:Package}\t${Version}\n', ...packages], { encoding: 'utf8', env, timeout: PROBE_TIMEOUT_MS });
  if (result.error || (result.status !== 0 && result.status !== 1)) return versions;
  for (const line of result.stdout.split('\n')) {
    const tab = line.indexOf('\t');
    if (tab > 0 && line.slice(tab + 1)) versions.set(line.slice(0, tab), line.slice(tab + 1));
  }
  return versions;
}

function parseParagraph(text) {
  const fields = new Map();
  let current = null;
  for (const line of text.split('\n')) {
    if (line.startsWith('#')) continue;
    if (/^[ \t]/.test(line)) {
      if (current !== null) fields.set(current, `${fields.get(current)}\n${line.trim()}`);
      continue;
    }
    const field = /^([A-Za-z0-9][A-Za-z0-9-]*):[ \t]*(.*)$/.exec(line);
    if (field === null) continue;
    current = field[1].toLowerCase();
    fields.set(current, field[2].trim());
  }
  return fields;
}

/**
 * The license a Debian copyright record states: the License of the paragraph whose Files
 * patterns include `*`, read only from a machine-readable (DEP-5) file. Licenses named by its
 * other Files paragraphs are listed as recorded. Free text is never interpreted, so a record
 * in another form yields no license, with the reason.
 */
export function debianCopyrightLicense(text) {
  if (!/^Format:[ \t]*\S/.test(text)) {
    return { license: null, other_licenses: [], detail: 'no license record: the copyright file is not machine-readable (no leading Format field), and no license is read from free text' };
  }
  let main = null;
  const others = [];
  for (const fields of text.split(/\n[ \t]*\n/).map(parseParagraph)) {
    if (!fields.has('files')) continue;
    const license = (fields.get('license') ?? '').split('\n')[0].trim() || null;
    if (main === null && fields.get('files').split(/\s+/).includes('*')) {
      main = { license };
      continue;
    }
    if (license !== null && !others.includes(license)) others.push(license);
  }
  if (main === null) return { license: null, other_licenses: others, detail: 'no license record: the copyright file has no Files: * paragraph' };
  if (main.license === null) return { license: null, other_licenses: others, detail: 'no license record: the Files: * paragraph has no License field' };
  return { license: main.license, other_licenses: others.filter((license) => license !== main.license), detail: null };
}

function packageRecord(resolvedPath, dpkg, versions) {
  const record = { query: `dpkg -S ${resolvedPath}`, package: null, package_version: null, license: null, license_source: null, other_licenses: [], detail: null };
  if (dpkg.owners === null) return { ...record, detail: `no package record: ${dpkg.detail}` };
  const owners = dpkg.owners.get(resolvedPath) ?? [];
  if (owners.length === 0) return { ...record, detail: `no package record: dpkg -S finds no package owning ${resolvedPath}` };
  if (owners.length > 1) return { ...record, detail: `no single package record: dpkg -S names ${owners.join(', ')}` };
  const owner = owners[0];
  const copyright = join(DEBIAN_DOC_ROOT, owner.split(':')[0], 'copyright');
  const found = { ...record, package: owner, package_version: versions.get(owner) ?? null };
  let text;
  try {
    text = readFileSync(copyright, 'utf8');
  } catch (error) {
    return { ...found, detail: `no license record: ${copyright} could not be read (${error.code ?? error.message})` };
  }
  return { ...found, license_source: copyright, ...debianCopyrightLicense(text) };
}

const ABSENT_PACKAGE_RECORD = Object.freeze({
  query: null,
  package: null,
  package_version: null,
  license: null,
  license_source: null,
  other_licenses: Object.freeze([]),
  detail: 'absent: the tool is not on this host, so no package record is looked up',
});

/** One INVENTORIED item per parse-sandbox tool, absent tools included. */
function sandboxToolItems(tools, env) {
  const located = tools.map((tool) => {
    const where = locateTool(tool);
    let resolved = null;
    if (where.selected !== null) {
      try {
        resolved = realpathSync(where.selected);
      } catch {
        resolved = null;
      }
    }
    return { tool, where, resolved };
  });
  const queried = [...new Set(located.map((entry) => entry.resolved).filter((path) => path !== null && path.startsWith('/')))];
  const dpkg = dpkgOwners(queried, env);
  const owned = dpkg.owners === null ? [] : [...new Set([...dpkg.owners.values()].filter((owners) => owners.length === 1).map((owners) => owners[0]))];
  const versions = dpkgVersions(owned, env);
  return located.map(({ tool, where, resolved }) => {
    const present = where.selected !== null;
    const version = present ? versionOf(where.selected, env) : { version: null, version_detail: null };
    const item = {
      id: tool.id,
      name: tool.name,
      role: tool.role,
      parse_sandbox: tool.lookup === 'fixed' ? { lookup: 'fixed', candidates: [...tool.candidates] } : { lookup: 'shell-path', command: tool.command, shell: SANDBOX_SHELL },
      observed: {
        present,
        candidates: where.candidates,
        ...(tool.lookup === 'shell-path' ? { search_path: where.search_path } : {}),
        selected: where.selected,
        resolved_path: resolved,
        ...version,
        detail: present && resolved === null ? `${where.selected} could not be resolved through its symbolic links` : where.detail,
      },
      package_record: !present
        ? { ...ABSENT_PACKAGE_RECORD, other_licenses: [] }
        : resolved === null
          ? { ...ABSENT_PACKAGE_RECORD, other_licenses: [], detail: 'no package record: the tool path could not be resolved' }
          : packageRecord(resolved, dpkg, versions),
    };
    if (tool.recorded_licenses) item.recorded_licenses = tool.recorded_licenses;
    return item;
  });
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

/**
 * Collect the platform inventory. Every item's status is INVENTORIED (recorded separately,
 * never gating). `sandboxTools` replaces PARSE_SANDBOX_TOOLS, for tests with synthetic tools.
 */
export function collectPlatformInventory(root = REPO_ROOT, { env = process.env, sandboxTools = PARSE_SANDBOX_TOOLS } = {}) {
  const items = [nodeRuntimeItem(root, env), linkedLibrariesItem(root, env), opensslItem(env), ...sandboxToolItems(sandboxTools, env), chromiumItem(root, env), hermesItem()];
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
