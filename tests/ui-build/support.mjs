// SPDX-License-Identifier: Apache-2.0
//
// Support for the T035 ui-build tests (UB-01..UB-06). Every source tree is synthetic,
// generated at run time in a mkdtemp directory and removed by cleanup(). Nothing is written
// inside the repository except under the gitignored .verify-out/ui-build/ (the server-only
// typecheck configuration), so the runner's tree digest is unchanged by a run; every build,
// including the one the composed server serves (StartOptions.distDir, row DIST-DIR), goes to a
// temporary directory, never the repository's dist/. Builds run as child processes of the
// pinned runtime (process.execPath) or in-process through buildUi(); servers bind 127.0.0.1
// with an OS-chosen port. The composed server's key file and migrated database are synthetic,
// made at test runtime (composedEnvironment()).

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { ROUTES } from '../../src/api/routes.ts';
import { createApp, createAppServer } from '../../src/server/app.ts';
import { loadServerConfig } from '../../src/server/config.ts';
import { createLogger } from '../../src/server/redact.ts';
import { createStaticHandler } from '../../src/server/static.ts';
import { openDatabase } from '../../src/storage/db/index.ts';

export const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
export const BUILDER = join(REPO, 'scripts', 'build-ui.mjs');
export const TRACE_PRELOAD = join(REPO, 'tests', 'ui-build', 'read-trace.mjs');
export const ASSET_TOKEN = '__OPENSIG_ASSET_DIGEST__';
export const IMMUTABLE_CACHE_CONTROL = 'public, max-age=31536000, immutable';

// Written by concatenation so that no line of this file starts with the directive itself.
export const DOM_DIRECTIVE = '/' + '// <reference lib="dom" />';
const SPDX_LINE = '// SPDX-License-Identifier: Apache-2.0';

const temps = [];

export function tempDir(label = 'ui') {
  const dir = mkdtempSync(join(tmpdir(), `opensig-ub-${label}-`));
  temps.push(dir);
  return dir;
}

export function cleanup() {
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** SHA-256 over sorted `name\0sha256\n` lines, computed here independently of the builder. */
export function digestLines(pairs) {
  const hash = createHash('sha256');
  for (const [name, digest] of [...pairs].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) hash.update(`${name}\0${digest}\n`);
  return hash.digest('hex');
}

/** The synthetic browser sources: every kind the build accepts, nested modules included. */
export function syntheticSources() {
  return {
    'package.json': `${JSON.stringify({ name: 'synthetic-ui', private: true, type: 'module' }, null, 2)}\n`,
    'tsconfig.json': readFileSync(join(REPO, 'tsconfig.json'), 'utf8'),
    'tsconfig.browser.json': readFileSync(join(REPO, 'tsconfig.browser.json'), 'utf8'),
    'src/autograph/index.html': [
      '<!-- SPDX-License-Identifier: Apache-2.0 -->',
      '<!doctype html>',
      '<html lang="en">',
      '<head>',
      '<meta charset="utf-8">',
      '<meta name="viewport" content="width=device-width, initial-scale=1">',
      '<title>Synthetic review shell</title>',
      `<link rel="stylesheet" href="/assets/${ASSET_TOKEN}/review.css">`,
      `<link rel="icon" href="/assets/${ASSET_TOKEN}/icons/seal.svg">`,
      `<script type="module" src="/assets/${ASSET_TOKEN}/main.js"></script>`,
      '</head>',
      '<body>',
      '<main id="app" aria-live="polite"></main>',
      '<a href="#app">Skip to the document</a>',
      '</body>',
      '</html>',
      '',
    ].join('\n'),
    'src/autograph/main.ts': [
      SPDX_LINE,
      DOM_DIRECTIVE,
      '//',
      '// Synthetic review-shell entry for the T035 build tests.',
      '',
      "import { scale, type Point } from './geometry/scale.js';",
      "import type { Stroke } from './types.js';",
      '',
      'export interface ShellState {',
      '  readonly strokes: readonly Stroke[];',
      '  label?: string;',
      '}',
      '',
      "export const LABEL = 'Synthetic signer \u00e9 \u2713';",
      '',
      'export function quantize(points: readonly Point[], range: number = 10000): Point[] {',
      '  return points.map((point: Point): Point => scale(point, range));',
      '}',
      '',
      'class Counter<T extends object> {',
      '  private count: number = 0;',
      '  add(item: T): number {',
      '    void item;',
      '    this.count += 1;',
      '    return this.count;',
      '  }',
      '}',
      '',
      'export function countAll<T extends object>(items: readonly T[]): number {',
      '  const counter = new Counter<T>();',
      '  let total: number = 0;',
      '  for (const item of items) total = counter.add(item);',
      '  return total;',
      '}',
      '',
      'export function describe(state: ShellState): string {',
      '  return `${state.label ?? LABEL}: ${state.strokes.length} stroke(s)` as string;',
      '}',
      '',
      'function start(root: Document): void {',
      "  const main = root.querySelector<HTMLElement>('main');",
      '  if (main !== null) main.textContent = describe({ strokes: [] } satisfies ShellState);',
      '}',
      '',
      "if (typeof document !== 'undefined') start(document);",
      '',
    ].join('\n'),
    'src/autograph/geometry/scale.ts': [
      SPDX_LINE,
      DOM_DIRECTIVE,
      '',
      "import type { Point } from '../types.js';",
      '',
      'export type { Point };',
      '',
      'export function scale(point: Point, range: number): Point {',
      '  const clamp = (value: number): number => Math.min(range, Math.max(0, Math.round(value * range)));',
      '  return { x: clamp(point.x), y: clamp(point.y) } as Point;',
      '}',
      '',
    ].join('\n'),
    'src/autograph/types.ts': [SPDX_LINE, DOM_DIRECTIVE, '', 'export interface Point {', '  readonly x: number;', '  readonly y: number;', '}', '', 'export type Stroke = readonly Point[];', ''].join('\n'),
    'src/autograph/review.css': ['/* SPDX-License-Identifier: Apache-2.0 */', 'main { max-width: 40rem; margin: 0 auto; }', '.seal { background: url("icons/seal.svg") no-repeat; }', ''].join('\n'),
    'src/autograph/icons/seal.svg': [
      '<!-- SPDX-License-Identifier: Apache-2.0 -->',
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2"/></svg>',
      '',
    ].join('\n'),
  };
}

/** Write `files` (relative path -> content) under `root`. */
export function writeFiles(root, files) {
  for (const [rel, content] of Object.entries(files)) {
    const target = join(root, ...rel.split('/'));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
}

/** A synthetic project root; `overrides` replace sources (null removes one). */
export function syntheticRoot(overrides = {}, label = 'root') {
  const root = tempDir(label);
  const files = { ...syntheticSources(), ...overrides };
  for (const [rel, content] of Object.entries(files)) if (content === null) delete files[rel];
  writeFiles(root, files);
  return root;
}

/** A decoy package under <root>/node_modules/decoy whose files carry `marker`. */
export function addDecoyPackage(root, marker) {
  writeFiles(root, {
    'node_modules/decoy/package.json': `${JSON.stringify({ name: 'decoy', version: '1.0.0', license: 'MIT' })}\n`,
    'node_modules/decoy/index.ts': `${SPDX_LINE}\n${DOM_DIRECTIVE}\nexport const decoy = '${marker}';\n`,
    'node_modules/decoy/style.css': `/* SPDX-License-Identifier: Apache-2.0 */\n.decoy::after { content: "${marker}"; }\n`,
  });
  return join(root, 'node_modules', 'decoy');
}

export function link(target, path) {
  mkdirSync(dirname(path), { recursive: true });
  symlinkSync(target, path);
}

/**
 * Run the builder as its own process. With `trace`, the UB-05 read-trace preload is loaded
 * into that process and its records are returned. Never throws for a refusal.
 */
export function runBuild({ root, out, trace = false }) {
  const args = [];
  let tracePath = null;
  if (trace) {
    tracePath = join(tempDir('trace'), 'trace.json');
    args.push('--import', pathToFileURL(TRACE_PRELOAD).href);
  }
  args.push(BUILDER);
  if (root !== undefined) args.push('--root', root);
  if (out !== undefined) args.push('--out', out);
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  delete env.NODE_OPTIONS;
  if (tracePath !== null) env.OPENSIG_UI_READ_TRACE = tracePath;
  const run = spawnSync(process.execPath, args, { cwd: REPO, env, encoding: 'utf8', timeout: 120_000 });
  const outRoot = out ?? (root === undefined ? join(REPO, 'dist') : join(root, 'dist'));
  const manifestPath = join(outRoot, 'build-provenance.json');
  return {
    status: run.status,
    signal: run.signal,
    stdout: run.stdout ?? '',
    stderr: run.stderr ?? '',
    out: outRoot,
    manifest: existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : null,
    manifestText: existsSync(manifestPath) ? readFileSync(manifestPath, 'utf8') : null,
    trace: tracePath !== null && existsSync(tracePath) ? JSON.parse(readFileSync(tracePath, 'utf8')) : null,
  };
}

/** A successful CLI build: exit 0, and the provenance manifest written to the output root. */
export function assertBuilt(run, label = 'the build') {
  assert.equal(run.status, 0, `${label} exits 0: ${run.stderr.trim()}`);
  assert.ok(run.manifest !== null && Array.isArray(run.manifest.outputs), `${label} wrote its provenance manifest`);
}

/** Every entry under `dir`: regular files, directories, links and other entries, as relative paths. */
export function listTree(dir) {
  const files = [];
  const dirs = [];
  const links = [];
  const others = [];
  const walk = (rel) => {
    for (const entry of readdirSync(rel === '' ? dir : join(dir, rel), { withFileTypes: true })) {
      const child = rel === '' ? entry.name : `${rel}/${entry.name}`;
      if (entry.isSymbolicLink()) links.push(child);
      else if (entry.isDirectory()) {
        dirs.push(child);
        walk(child);
      } else if (entry.isFile()) files.push(child);
      else others.push(child);
    }
  };
  walk('');
  return { files: files.sort(), dirs: dirs.sort(), links: links.sort(), others: others.sort() };
}

/**
 * Position-aligned derivation (UB-01): the output has the source's length (in UTF-8 bytes,
 * or else in UTF-16 units), keeps every line break, and differs from the source only where
 * the stripper wrote whitespace or an ASI-guard ';' or a moved ')'. So every other output
 * byte is the source's own byte at the same place: nothing foreign was added.
 */
export function derivationProblem(sourceText, outputText) {
  const aligned = (source, output, unit) => {
    if (source.length !== output.length) return `${unit} lengths differ (${source.length} and ${output.length})`;
    for (let i = 0; i < source.length; i += 1) {
      if (source[i] === output[i]) continue;
      if (source[i] === 0x0a || source[i] === 0x0d) return `a line break was replaced at ${unit} ${i}`;
      if (![0x20, 0x09, 0x3b, 0x29].includes(output[i])) return `${unit} ${i} holds ${output[i]}, which is not the source's there`;
    }
    return null;
  };
  const sourceBytes = Buffer.from(sourceText, 'utf8');
  const outputBytes = Buffer.from(outputText, 'utf8');
  if (sourceBytes.length === outputBytes.length) return aligned(sourceBytes, outputBytes, 'byte');
  const units = (text) => Array.from({ length: text.length }, (_, i) => text.charCodeAt(i));
  return aligned(units(sourceText), units(outputText), 'UTF-16 unit');
}

/** Inline script or style findings for one output, checked independently of the builder. */
export function inlineFindings(kind, text) {
  const findings = [];
  const flag = (condition, label) => {
    if (condition) findings.push(label);
  };
  if (kind === 'html') {
    const body = text.replace(/<!--[\s\S]*?-->/g, '');
    for (const match of body.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
      flag(match[2] !== '', 'a script element with inline content');
      flag(!/\bsrc\s*=/.test(match[1]), 'a script element without src');
    }
    flag(/<style\b/i.test(body), 'a style element');
    flag(/\sstyle\s*=/i.test(body), 'a style attribute');
    flag(/\son[a-z]+\s*=/i.test(body), 'an event-handler attribute');
    flag(/javascript:/i.test(body), 'a javascript: URL');
    flag(/\s(?:src|href|srcset|action|formaction)\s*=\s*["']?\s*(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(body), 'an external or scheme URL');
  } else if (kind === 'js') {
    flag(/\beval\s*\(/.test(text), 'eval()');
    flag(/\bnew\s+Function\s*\(/.test(text), 'new Function()');
    flag(/\bset(?:Timeout|Interval)\s*\(\s*['"`]/.test(text), 'a timer with string code');
    flag(/\.\s*(?:innerHTML|outerHTML)\s*\+?=(?!=)/.test(text), 'an HTML string sink');
    flag(/\bsetAttribute\s*\(\s*['"`](?:style|on[a-z]+)['"`]/i.test(text), 'an inline attribute set from script');
    flag(/javascript:/i.test(text), 'a javascript: URL');
  } else if (kind === 'css') {
    const body = text.replace(/\/\*[\s\S]*?\*\//g, '');
    flag(/@import\b/i.test(body), 'an @import');
    flag(/url\(\s*['"]?\s*(?:[a-z][a-z0-9+.-]*:|\/\/|\/)/i.test(body), 'a url() that is external, a scheme or absolute');
    flag(/expression\s*\(/i.test(body), 'a CSS expression()');
    flag(/(?:^|[{;\s])[*_]*(?:-[a-z]+-)?(?:behavior|binding)\s*:/im.test(body), 'a legacy behavior or binding property');
  } else if (kind === 'svg') {
    const body = text.replace(/<!--[\s\S]*?-->/g, '');
    flag(/<script\b/i.test(body), 'a script element');
    flag(/<style\b/i.test(body), 'a style element');
    flag(/\son[a-z]+\s*=/i.test(body), 'an event-handler attribute');
    flag(/\sstyle\s*=/i.test(body), 'a style attribute');
    flag(/<foreignObject\b/i.test(body), 'a foreignObject element');
  } else {
    findings.push(`an unexpected output kind ${kind}`);
  }
  return findings;
}

export function kindOfOutput(path) {
  return { '.html': 'html', '.js': 'js', '.css': 'css', '.svg': 'svg' }[path.slice(path.lastIndexOf('.'))] ?? 'unknown';
}

/** The install directories of every locked package: all of them are non-shipped (the shipped closure is empty). */
export function nonShippedPackageDirs(root = REPO) {
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  return Object.keys(lock.packages ?? {})
    .filter((key) => key !== '')
    .map((key) => join(root, ...key.split('/')));
}

export function isWithin(parent, child) {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !rel.startsWith(sep) && resolve(parent, rel) === resolve(child));
}

/** The trace's records split by kind; a record without a path (a descriptor) is reported. */
export function traceSummary(trace) {
  const reads = new Set();
  const lists = new Set();
  const writes = new Set();
  const unattributed = [];
  for (const record of trace) {
    if (record.path === null) unattributed.push(record.op);
    else if (record.op === 'read') reads.add(record.path);
    else if (record.op === 'list') lists.add(record.path);
    else if (record.op === 'write') writes.add(record.path);
    else unattributed.push(record.op);
  }
  return { reads, lists, writes, unattributed };
}

export function builderRealPath() {
  return realpathSync(BUILDER);
}

/** Copy a whole tree to a new path (links copied as links, never followed). */
export function copyTree(from, to) {
  if (existsSync(to)) throw new Error('copyTree needs a new destination');
  mkdirSync(dirname(to), { recursive: true });
  cpSync(from, to, { recursive: true, verbatimSymlinks: true });
}

export function isSymlink(path) {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

export function marker(label) {
  return `UB-${label}-${randomBytes(8).toString('hex')}`;
}

/**
 * The environment of the composed server (src/server/main.ts startServer) on 127.0.0.1 with an
 * OS-chosen port: a data directory, a migrated temporary database, a synthetic 0600 key file of
 * 32 random bytes (generated now, never printed) and a mkdtemp mail spool. No operator
 * authentication is configured, so no tenant row is needed.
 */
export function composedEnvironment() {
  const dataDir = tempDir('data');
  const database = join(dataDir, 'opensig.db');
  const db = openDatabase({ path: database });
  try {
    db.migrate();
  } finally {
    db.close();
  }
  const keyPath = join(tempDir('key'), 'challenge-hmac.key');
  writeFileSync(keyPath, randomBytes(32), { mode: 0o600 });
  chmodSync(keyPath, 0o600);
  return {
    OPENSIG_HOST: '127.0.0.1',
    OPENSIG_PORT: '0',
    OPENSIG_DATA_DIR: dataDir,
    OPENSIG_DATABASE: database,
    OPENSIG_CHALLENGE_KEY_FILE: keyPath,
    OPENSIG_MAIL_TRANSPORT: 'spool',
    OPENSIG_SPOOL_DIR: join(tempDir('spool'), 'spool'),
  };
}

/** Serve the real application (T031's createApp) with the real T035 static handler. */
export async function serveStatic({ distDir, handler } = {}) {
  const lines = [];
  const logger = createLogger((line) => lines.push(line));
  const config = loadServerConfig({ OPENSIG_PORT: '0' });
  const staticHandler = handler ?? createStaticHandler({ config, distDir });
  const app = createApp({ routes: ROUTES, config, logger, authenticator: null, allowedOrigins: new Set(['http://127.0.0.1:1']), staticHandler });
  const server = createAppServer(app);
  await new Promise((resolveListen) => server.listen({ host: '127.0.0.1', port: 0 }, resolveListen));
  const { port } = server.address();
  return {
    port,
    lines,
    close: () =>
      new Promise((resolveClose) => {
        server.close(() => resolveClose());
        server.closeAllConnections();
      }),
  };
}

function parseResponse(raw, method) {
  const end = raw.indexOf('\r\n\r\n');
  if (end < 0) return { status: 0, headers: {}, body: Buffer.alloc(0), text: '', raw };
  const head = raw.subarray(0, end).toString('latin1').split('\r\n');
  const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(head[0] ?? '')?.[1] ?? 0);
  const headers = {};
  for (const line of head.slice(1)) {
    const colon = line.indexOf(':');
    if (colon > 0) headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
  }
  let body = raw.subarray(end + 4);
  if (method !== 'HEAD' && headers['content-length'] !== undefined) body = body.subarray(0, Number(headers['content-length']));
  if (method === 'HEAD') body = Buffer.alloc(0);
  return { status, headers, body, text: body.toString('utf8'), raw };
}

/**
 * One raw HTTP/1.1 request with the request-target sent byte for byte (no client-side
 * normalization of "..", percent escapes or backslashes).
 */
export function rawRequest(port, method, target, headers = {}) {
  return new Promise((resolveRequest, reject) => {
    const socket = connect({ host: '127.0.0.1', port });
    const chunks = [];
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`no response to ${method} ${target} within 10 s`));
    }, 10_000);
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', (error) => {
      if (chunks.length === 0) {
        clearTimeout(timer);
        reject(error);
      }
    });
    socket.on('close', () => {
      clearTimeout(timer);
      resolveRequest(parseResponse(Buffer.concat(chunks), method));
    });
    const lines = [`${method} ${target} HTTP/1.1`, 'Host: 127.0.0.1', 'Connection: close', ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`), '', ''];
    socket.write(lines.join('\r\n'), 'latin1');
  });
}

/** Run the pinned TypeScript compiler (a non-shipped dev tool) on one project; never throws. */
export function runTsc(project) {
  const run = spawnSync(process.execPath, [join(REPO, 'node_modules', 'typescript', 'bin', 'tsc'), '--noEmit', '--pretty', 'false', '-p', project], {
    cwd: REPO,
    encoding: 'utf8',
    timeout: 300_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  return { status: run.status, output: `${run.stdout ?? ''}${run.stderr ?? ''}` };
}

/** The ignored scratch directory for configuration this mode generates inside the tree. */
export function verifyOutDir() {
  const dir = process.env.OPENSIG_VERIFY_OUT ?? join(REPO, '.verify-out', 'ui-build');
  mkdirSync(dir, { recursive: true });
  return dir;
}
