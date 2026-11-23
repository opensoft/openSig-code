#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig browser build (T035): the review shell sources in src/autograph/ (T009) into the
// gitignored dist/, with no bundler and no third-party bytes.
//
//   tools/node/bin/node scripts/build-ui.mjs [--root <dir>] [--out <dir>]
//
// --root is the project root holding tsconfig.browser.json (default: this repository).
// --out is the output root (default: <root>/dist). Exit 0 builds and prints one line
// `build-ui: OK build_digest=<hex> asset_digest=<hex> inputs=<n> outputs=<n>`; exit 1 refuses
// (`build-ui: REFUSED <code>: <reason>` on stderr) and writes nothing; exit 2 is a usage
// error. Reasons name repository-relative paths, never file contents. Node prints an
// ExperimentalWarning for stripTypeScriptTypes on stderr; it never reaches <out>.
//
// How it builds:
// - Configuration. tsconfig.browser.json maps rootDir src/autograph to outDir dist/autograph
//   and is read as plain JSON; any other mapping is refused. It is also the browser program
//   for `tsc --noEmit -p tsconfig.browser.json` (DOM lib, no Node types).
// - Inputs. Only tsconfig.browser.json and the files under src/autograph/. The walk never
//   follows a link, refuses node_modules/ and any nested package.json (an input that belongs
//   to another package, which is never openSig's own Apache-2.0 source), and accepts only
//   .ts scripts, .css stylesheets, .svg images and the shell src/autograph/index.html. Every
//   input carries `SPDX-License-Identifier: Apache-2.0` and no other license identifier.
// - Type stripping. Each .ts source goes through Node's built-in
//   `module.stripTypeScriptTypes(code, { mode: 'strip' })`: erasable TypeScript only, type
//   syntax replaced by whitespace, nothing else added (no helpers, no source map, no
//   sourceURL). The runtime is a platform, inventoried separately; no package is loaded.
//   Each script starts with `/// <reference lib="dom" />` (T009 typing rule).
// - Modules. Relative imports name the built file with a .js extension (TypeScript resolves
//   `./capture.js` to `./capture.ts`), so the stripped text is the shipped text; any other
//   specifier is refused, because only built modules exist in the browser. The source's own
//   specifiers are checked before stripping as well, so a type-only import, which stripping
//   erases, cannot name a package either (no browser source imports Playwright types).
// - Shell. index.html refers to assets as /assets/__OPENSIG_ASSET_DIGEST__/<path>; the build
//   replaces that token with the asset digest (SHA-256 over every non-HTML output's path and
//   digest), so a changed asset has a new URL and assets can be cached as immutable.
// - Inline policy (CSP: script-src and style-src 'self'). Refused: inline <script> or
//   <style>, style attributes, event-handler attributes, javascript: URLs, external URLs,
//   eval and its relatives, and HTML-string sinks.
// - Provenance. <out>/build-provenance.json lists every input read (repository-relative path,
//   SHA-256, size, role), the builder's own digest, and every output (path relative to <out>,
//   SHA-256, size, source, transform, URL, content type), plus the asset and build digests.
//   Every file read goes through readInput() or the builder's own digest; T035's UB-05
//   compares that self-report with a read trace taken inside this process.
// - Determinism. Sorted walks, fixed key order, no time, no absolute path, no environment
//   value other than the runtime version, so identical inputs give identical bytes.
// - Output. The new tree is written to <out>/.staging-*, then swapped in: the old manifest is
//   moved away first and the new manifest is moved in last, so a reader never sees a
//   manifest that disagrees with the outputs. <out> may hold only this build's files.
//
// This script imports only node: builtins (UB-05 asserts it).

import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { dirname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SCHEMA = 'opensig.ui-build-provenance/1';
export const CONFIG_FILE = 'tsconfig.browser.json';
export const SOURCE_ROOT = 'src/autograph';
export const OUTPUT_DIR = 'autograph';
export const MANIFEST_FILE = 'build-provenance.json';
export const SHELL_SOURCE = `${SOURCE_ROOT}/index.html`;
export const SHELL_OUTPUT = `${OUTPUT_DIR}/index.html`;
export const SHELL_URL = '/sign';
export const ASSET_TOKEN = '__OPENSIG_ASSET_DIGEST__';
export const ASSET_PREFIX = '/assets/';
export const BUILDER_PATH = 'scripts/build-ui.mjs';
export const STRIP_ENGINE = 'node:module stripTypeScriptTypes (mode strip)';
export const LIMITS = Object.freeze({ files: 512, depth: 8, fileBytes: 2 * 1024 * 1024, totalBytes: 16 * 1024 * 1024 });

export const CONTENT_TYPES = Object.freeze({
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.html': 'text/html; charset=utf-8',
});

const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const BUILDER_FILE = fileURLToPath(import.meta.url);
const REPO_ROOT = resolve(dirname(BUILDER_FILE), '..');
const ALLOWED_REFERENCE = /^\/\/\/[ \t]*<reference[ \t]+lib="dom(?:\.iterable|\.asynciterable)?"[ \t]*\/>[ \t]*$/;
const DOM_REFERENCE = /^\/\/\/[ \t]*<reference[ \t]+lib="dom"[ \t]*\/>[ \t]*$/;
const SPDX_ID = /SPDX-License-Identifier:[ \t]*([A-Za-z0-9.+()-]+(?:[ \t]+(?:AND|OR|WITH)[ \t]+[A-Za-z0-9.+()-]+)*)/g;
const THIRD_PARTY_MARKER = /@license\b|@preserve\b|\/\*!/;
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

const SCRIPT_RULES = Object.freeze([
  [/\beval\s*\(/, 'eval'],
  [/\bnew\s+Function\b/, 'new Function'],
  [/\bFunction\s*\(\s*['"`]/, 'Function() from a string'],
  [/\bset(?:Timeout|Interval)\s*\(\s*['"`]/, 'a timer with string code'],
  [/\bdocument\s*\.\s*write(?:ln)?\s*\(/, 'document.write()'],
  [/\.\s*(?:innerHTML|outerHTML)\s*\+?=(?!=)/, 'an innerHTML or outerHTML assignment'],
  [/\binsertAdjacentHTML\s*\(/, 'insertAdjacentHTML()'],
  [/\bsetAttribute\s*\(\s*['"`](?:style|on[a-z]+|srcdoc)['"`]/i, 'setAttribute() of a style, event-handler or srcdoc attribute'],
  [/\bcreateElement\s*\(\s*['"`](?:script|style)['"`]/i, 'createElement() of a script or style element'],
  [/javascript:/i, 'a javascript: URL'],
  [/\/\/[#@][ \t]*source(?:Mapping)?URL=/, 'a source map or sourceURL comment'],
]);

/** A refusal: nothing is written, and the CLI exits 1. */
export class BuildRefused extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BuildRefused';
    this.code = code;
  }
}

function refuse(code, message) {
  throw new BuildRefused(code, message);
}

const byString = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** SHA-256 over sorted `name\0sha256\n` lines (the tree-digest format of scripts/verify.mjs). */
export function digestLines(pairs) {
  const hash = createHash('sha256');
  for (const [name, digest] of [...pairs].sort((a, b) => byString(a[0], b[0]))) hash.update(`${name}\0${digest}\n`);
  return hash.digest('hex');
}

function lstatOrNull(path) {
  try {
    return lstatSync(path);
  } catch {
    return null;
  }
}

function absolute(ctx, rel) {
  return join(ctx.root, ...rel.split('/'));
}

/** The single gateway for reading an input: checked, bounded, digested and recorded. */
function readInput(ctx, rel, role) {
  const segments = rel.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) refuse('input-path', `${rel} is not a plain relative path`);
  if (segments.includes('node_modules')) refuse('non-shipped-input', `${rel} lies under node_modules/; inputs from packages are refused`);
  if (rel !== CONFIG_FILE && !rel.startsWith(`${SOURCE_ROOT}/`)) refuse('input-path', `${rel} is outside ${SOURCE_ROOT}/`);
  const abs = absolute(ctx, rel);
  const stat = lstatOrNull(abs);
  if (stat === null || stat.isSymbolicLink() || !stat.isFile()) refuse('input-not-regular', `${rel} is not a regular file`);
  if (stat.size > LIMITS.fileBytes) refuse('input-too-large', `${rel} is larger than ${LIMITS.fileBytes} bytes`);
  const bytes = readFileSync(abs);
  ctx.totalBytes += bytes.length;
  if (ctx.totalBytes > LIMITS.totalBytes) refuse('inputs-too-large', `the inputs exceed ${LIMITS.totalBytes} bytes`);
  ctx.inputs.push({ path: rel, sha256: sha256Hex(bytes), bytes: bytes.length, role });
  return bytes;
}

function decodeText(rel, bytes) {
  let text;
  try {
    text = UTF8.decode(bytes);
  } catch {
    refuse('encoding', `${rel} is not valid UTF-8`);
  }
  if (text.startsWith('\uFEFF')) refuse('encoding', `${rel} starts with a byte order mark`);
  if (text.includes('\u0000')) refuse('encoding', `${rel} holds a NUL character`);
  return text;
}

function readConfig(ctx) {
  const stat = lstatOrNull(absolute(ctx, CONFIG_FILE));
  if (stat === null) refuse('config', `${CONFIG_FILE} is missing`);
  const text = decodeText(CONFIG_FILE, readInput(ctx, CONFIG_FILE, 'config'));
  let config;
  try {
    config = JSON.parse(text);
  } catch {
    refuse('config', `${CONFIG_FILE} is not plain JSON`);
  }
  const options = config?.compilerOptions ?? {};
  const mapped =
    Array.isArray(config?.include) &&
    config.include.length === 1 &&
    config.include[0] === SOURCE_ROOT &&
    options.rootDir === SOURCE_ROOT &&
    options.outDir === `dist/${OUTPUT_DIR}` &&
    Array.isArray(options.lib) &&
    options.lib.includes('dom') &&
    config.files === undefined &&
    config.exclude === undefined &&
    config.references === undefined;
  if (!mapped) refuse('config', `${CONFIG_FILE} must build exactly ${SOURCE_ROOT} (rootDir, include) into dist/${OUTPUT_DIR} (outDir) with the DOM lib`);
}

function walk(ctx, rel, depth, files) {
  if (depth > LIMITS.depth) refuse('source-depth', `${rel} is nested deeper than ${LIMITS.depth} directories`);
  const entries = readdirSync(absolute(ctx, rel), { withFileTypes: true }).sort((a, b) => byString(a.name, b.name));
  for (const entry of entries) {
    const child = `${rel}/${entry.name}`;
    if (entry.name === 'node_modules') refuse('non-shipped-input', `${child}: inputs under node_modules/ are refused`);
    if (entry.name === 'package.json') refuse('package-boundary', `${child} starts a nested package; inputs that belong to another package are refused`);
    if (!SEGMENT.test(entry.name)) refuse('unsafe-name', `${child}: source names must match ${SEGMENT.source}`);
    if (entry.isSymbolicLink()) refuse('symlink', `${child} is a symbolic link; links are never followed`);
    if (entry.isDirectory()) walk(ctx, child, depth + 1, files);
    else if (entry.isFile()) {
      files.push(child);
      if (files.length > LIMITS.files) refuse('source-count', `more than ${LIMITS.files} source files`);
    } else refuse('special-file', `${child} is not a regular file or directory`);
  }
}

function collectSources(ctx) {
  let dir = ctx.root;
  for (const segment of SOURCE_ROOT.split('/')) {
    dir = join(dir, segment);
    const stat = lstatOrNull(dir);
    if (stat === null) refuse('no-sources', `${SOURCE_ROOT}/ does not exist: there are no browser sources to build`);
    if (stat.isSymbolicLink() || !stat.isDirectory()) refuse('source-root', `${relative(ctx.root, dir).split(sep).join('/')} must be a real directory, not a link`);
  }
  const files = [];
  walk(ctx, SOURCE_ROOT, 0, files);
  if (files.length === 0) refuse('no-sources', `${SOURCE_ROOT}/ holds no files: there are no browser sources to build`);
  return files.sort(byString);
}

function kindOf(rel) {
  if (rel === SHELL_SOURCE) return 'shell';
  if (rel.endsWith('.d.ts')) return null;
  if (rel.endsWith('.ts')) return 'script';
  if (rel.endsWith('.css')) return 'stylesheet';
  if (rel.endsWith('.svg')) return 'image';
  return null;
}

function checkLicense(rel, text) {
  const ids = [...text.matchAll(SPDX_ID)].map((match) => match[1]);
  if (ids.length === 0) refuse('license-header', `${rel} has no SPDX-License-Identifier: Apache-2.0 header`);
  if (ids.some((id) => id !== 'Apache-2.0')) refuse('foreign-license', `${rel} declares a license other than Apache-2.0; only original openSig sources are built`);
  if (!text.split('\n', 5).join('\n').includes('SPDX-License-Identifier: Apache-2.0')) refuse('license-header', `${rel}: the SPDX header must be within the first five lines`);
  if (THIRD_PARTY_MARKER.test(text)) refuse('third-party-marker', `${rel} carries a third-party preservation marker (@license, @preserve or /*!)`);
}

function checkReferences(rel, text) {
  let dom = false;
  let inBlock = false;
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (inBlock) {
      if (trimmed.includes('*/')) inBlock = false;
      continue;
    }
    if (trimmed === '') continue;
    if (trimmed.startsWith('/*')) {
      inBlock = !trimmed.includes('*/', 2);
      continue;
    }
    if (trimmed.startsWith('///')) {
      if (!ALLOWED_REFERENCE.test(trimmed)) refuse('reference-directive', `${rel}: only /// <reference lib="dom" /> (and dom.iterable, dom.asynciterable) are allowed in browser sources`);
      if (DOM_REFERENCE.test(trimmed)) dom = true;
      continue;
    }
    if (trimmed.startsWith('//')) continue;
    break;
  }
  if (!dom) refuse('dom-reference', `${rel} must start with /// <reference lib="dom" /> (after its SPDX header)`);
}

/** Module specifiers of import and export declarations in stripped JavaScript, with line numbers. */
export function moduleSpecifiers(js) {
  const found = [];
  const lines = js.split('\n');
  lines.forEach((line, index) => {
    const sideEffect = /^[ \t]*import[ \t]*(['"])([^'"\r\n]*)\1/.exec(line);
    const from = /\bfrom[ \t]*(['"])([^'"\r\n]*)\1[ \t]*;?[ \t]*(?:\/\/.*)?\r?$/.exec(line);
    const match = sideEffect ?? from;
    if (match) found.push({ line: index + 1, specifier: match[2] });
  });
  return found;
}

function checkSpecifiers(rel, js, scripts) {
  for (const { line, specifier } of moduleSpecifiers(js)) {
    const shown = `${rel}:${line}`;
    if (!/^\.\.?\//.test(specifier) || !specifier.endsWith('.js')) {
      refuse('module-specifier', `${shown}: imports must be relative and name the built .js module (TypeScript resolves ./x.js to ./x.ts); only built modules exist in the browser`);
    }
    const target = posix.normalize(posix.join(posix.dirname(rel), specifier));
    if (!target.startsWith(`${SOURCE_ROOT}/`) || !scripts.has(`${target.slice(0, -'.js'.length)}.ts`)) {
      refuse('module-specifier', `${shown}: the import names no script under ${SOURCE_ROOT}/`);
    }
  }
}

function scriptProblem(js) {
  for (const [pattern, label] of SCRIPT_RULES) if (pattern.test(js)) return label;
  return null;
}

function cssProblem(text, within, assets) {
  const body = text.replace(/\/\*[\s\S]*?\*\//g, '');
  if (/@import\b/i.test(body)) return 'an @import (stylesheets are linked from the shell)';
  if (/expression\s*\(/i.test(body)) return 'a CSS expression()';
  if (/javascript:/i.test(body)) return 'a javascript: URL';
  // The legacy script-from-CSS properties: behavior (with IE's -ms- prefix or * and _ hacks)
  // and -moz-binding, as declarations only. A longer property that ends in behavior, such as
  // scroll-behavior or overscroll-behavior, is ordinary CSS (A-010 request #34 B5).
  if (/(?:^|[{;\s])[*_]*(?:-[a-z]+-)?(?:behavior|binding)\s*:/im.test(body)) return 'a behavior or binding property (script from CSS)';
  for (const match of body.matchAll(/url\(\s*(['"]?)([^'")]*)\1\s*\)/gi)) {
    const target = match[2] ?? '';
    if (target === '' || /^(?:[A-Za-z][A-Za-z0-9+.-]*:|\/)/.test(target)) return 'a url() that is not a relative path to a built asset';
    if (!assets.has(posix.normalize(posix.join(posix.dirname(within), target)))) return 'a url() that names no built asset';
  }
  return null;
}

function svgProblem(text) {
  const body = text.replace(/<!--[\s\S]*?-->/g, '');
  if (/<script\b/i.test(body)) return 'a <script> element (inline script)';
  if (/<style\b/i.test(body)) return 'a <style> element (inline style)';
  if (/<foreignObject\b/i.test(body)) return 'a <foreignObject> element';
  if (/<!(?:DOCTYPE|ENTITY)\b/i.test(body)) return 'a DOCTYPE or ENTITY declaration';
  if (/\son[a-z]+\s*=/i.test(body)) return 'an event-handler attribute (inline script)';
  if (/\sstyle\s*=/i.test(body)) return 'a style attribute (inline style)';
  if (/javascript:/i.test(body)) return 'a javascript: URL';
  if (/\s(?:xlink:)?href\s*=\s*["']\s*(?:[A-Za-z][A-Za-z0-9+.-]*:|\/\/)/i.test(body)) return 'an external or scheme URL';
  return null;
}

function parseAttributes(source) {
  const map = new Map();
  let duplicate = false;
  for (const match of source.matchAll(/([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g)) {
    const name = match[1].toLowerCase();
    if (map.has(name)) duplicate = true;
    map.set(name, match[2] ?? match[3] ?? match[4] ?? null);
  }
  return { map, duplicate };
}

const URL_ATTRIBUTES = new Set(['src', 'href', 'action', 'formaction', 'poster', 'data', 'xlink:href', 'srcset', 'ping', 'background', 'manifest']);

function urlProblem(value, assets) {
  if (value === null || value === '') return 'an empty URL';
  if (value.startsWith('#')) return null;
  const prefix = `${ASSET_PREFIX}${ASSET_TOKEN}/`;
  if (value.startsWith(prefix)) return assets.has(value.slice(prefix.length)) ? null : 'it names no built asset';
  if (value.startsWith(ASSET_PREFIX)) return `assets are named through ${prefix}`;
  if (/^\/(?!\/)[A-Za-z0-9._~/-]*$/.test(value)) return null;
  return 'only same-origin paths and built assets are allowed';
}

function shellProblem(text, assets) {
  const body = text.replace(/<!--[\s\S]*?-->/g, '');
  if (!/^\s*<!doctype html>/i.test(body)) return 'the shell must start with <!doctype html> (after its SPDX comment)';
  if (/<style\b/i.test(body)) return 'a <style> element (inline style)';
  if (/<(?:object|embed|applet|base|frame|frameset)\b/i.test(body)) return 'an object, embed, applet, base or frame element';
  if (/<meta\b[^>]*\bhttp-equiv\b/i.test(body)) return 'a meta http-equiv element';
  if (/javascript:/i.test(body)) return 'a javascript: URL';
  const scripts = [...body.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  if (scripts.length !== (body.match(/<script\b/gi) ?? []).length) return 'a script element that is not closed by </script>';
  for (const [, attributeText, inner] of scripts) {
    if ((inner ?? '') !== '') return 'an inline script (a <script> element with content)';
    const { map } = parseAttributes(attributeText ?? '');
    if (map.get('type') !== 'module' || !map.has('src')) return 'a script that is not an external module (type="module" src="...")';
    for (const name of map.keys()) if (name !== 'type' && name !== 'src') return `a script attribute ${name}`;
  }
  for (const tag of body.matchAll(/<([A-Za-z][A-Za-z0-9-]*)(\s[^<>]*)?>/g)) {
    const { map, duplicate } = parseAttributes(tag[2] ?? '');
    if (duplicate) return `a duplicated attribute on <${tag[1]}>`;
    for (const [name, value] of map) {
      if (name === 'style') return 'a style attribute (inline style)';
      if (name.startsWith('on')) return `an event-handler attribute ${name} (inline script)`;
      if (name === 'srcdoc') return 'an iframe srcdoc (inline document)';
      if (URL_ATTRIBUTES.has(name)) {
        const problem = urlProblem(value, assets);
        if (problem) return `${name} on <${tag[1]}>: ${problem}`;
      }
    }
  }
  return null;
}

function outputFor(rel, kind) {
  const within = rel.slice(SOURCE_ROOT.length + 1);
  if (kind === 'script') return `${within.slice(0, -'.ts'.length)}.js`;
  return within;
}

function extensionOf(path) {
  return path.slice(path.lastIndexOf('.'));
}

function checkOutRoot(root, out) {
  const sources = join(root, ...SOURCE_ROOT.split('/'));
  const inside = (parent, child) => {
    const rel = relative(parent, child);
    return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
  };
  if (inside(out, root) || inside(sources, out) || inside(out, sources)) refuse('output-root', 'the output root must not contain the project root or the sources, or lie inside the sources');
}

function prepareOutRoot(out) {
  const stat = lstatOrNull(out);
  if (stat === null) {
    mkdirSync(out, { recursive: true });
    return;
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) refuse('output-root', 'the output root is not a real directory');
  for (const name of readdirSync(out).sort(byString)) {
    if (name === MANIFEST_FILE || name === OUTPUT_DIR) continue;
    if (name.startsWith('.staging-') || name.startsWith('.old-')) {
      rmSync(join(out, name), { recursive: true, force: true });
      continue;
    }
    refuse('foreign-output', `the output root holds ${name}, which this build did not write; remove it first`);
  }
}

function writeTree(out, outputs, manifestText) {
  const staging = mkdtempSync(join(out, '.staging-'));
  try {
    for (const output of outputs) {
      const target = join(staging, ...output.path.split('/'));
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, output.data, { flag: 'wx', mode: 0o644 });
    }
    writeFileSync(join(staging, MANIFEST_FILE), manifestText, { flag: 'wx', mode: 0o644 });
    const old = mkdtempSync(join(out, '.old-'));
    if (lstatOrNull(join(out, MANIFEST_FILE)) !== null) renameSync(join(out, MANIFEST_FILE), join(old, MANIFEST_FILE));
    if (lstatOrNull(join(out, OUTPUT_DIR)) !== null) renameSync(join(out, OUTPUT_DIR), join(old, OUTPUT_DIR));
    renameSync(join(staging, OUTPUT_DIR), join(out, OUTPUT_DIR));
    renameSync(join(staging, MANIFEST_FILE), join(out, MANIFEST_FILE));
    rmSync(old, { recursive: true, force: true });
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

/**
 * Build the browser sources under `root` into `out`; returns the provenance manifest.
 * Throws BuildRefused (nothing written) when an input, the configuration or the output root
 * breaks a rule.
 */
export function buildUi({ root = REPO_ROOT, out } = {}) {
  const ctx = { root: resolve(root), inputs: [], totalBytes: 0 };
  const outRoot = resolve(out ?? join(ctx.root, 'dist'));
  checkOutRoot(ctx.root, outRoot);
  const builderSha256 = sha256Hex(readFileSync(BUILDER_FILE));

  readConfig(ctx);
  const files = collectSources(ctx);
  const kinds = new Map();
  for (const rel of files) {
    const kind = kindOf(rel);
    if (kind === null) refuse('unsupported-source', `${rel}: only .ts scripts, .css stylesheets, .svg images and ${SHELL_SOURCE} are built`);
    kinds.set(rel, kind);
  }
  if (!kinds.has(SHELL_SOURCE)) refuse('no-shell', `${SHELL_SOURCE} is missing`);
  const scripts = new Set(files.filter((rel) => kinds.get(rel) === 'script'));
  const assets = new Set(files.filter((rel) => kinds.get(rel) !== 'shell').map((rel) => outputFor(rel, kinds.get(rel))));

  const texts = new Map();
  for (const rel of files) {
    const kind = kinds.get(rel);
    const text = decodeText(rel, readInput(ctx, rel, kind));
    checkLicense(rel, text);
    texts.set(rel, text);
  }

  const outputs = [];
  for (const rel of files) {
    const kind = kinds.get(rel);
    if (kind === 'shell') continue;
    const text = texts.get(rel);
    const within = outputFor(rel, kind);
    let data;
    let transform;
    if (kind === 'script') {
      checkReferences(rel, text);
      checkSpecifiers(rel, text, scripts);
      let js;
      try {
        js = stripTypeScriptTypes(text, { mode: 'strip' });
      } catch (error) {
        refuse('typescript-syntax', `${rel}: ${error?.code ?? 'ERR_INVALID_TYPESCRIPT_SYNTAX'} (only erasable TypeScript syntax is built)`);
      }
      checkSpecifiers(rel, js, scripts);
      const problem = scriptProblem(js);
      if (problem) refuse('inline-script', `${rel}: ${problem}`);
      data = Buffer.from(js, 'utf8');
      transform = 'strip-types';
    } else {
      const problem = kind === 'stylesheet' ? cssProblem(text, within, assets) : svgProblem(text);
      if (problem) refuse(kind === 'stylesheet' ? 'inline-style' : 'inline-image', `${rel}: ${problem}`);
      data = Buffer.from(text, 'utf8');
      transform = 'copy';
    }
    outputs.push({ path: `${OUTPUT_DIR}/${within}`, within, from: rel, transform, data });
  }

  const assetDigest = digestLines(outputs.map((output) => [output.within, sha256Hex(output.data)]));
  const shellText = texts.get(SHELL_SOURCE);
  const shellIssue = shellProblem(shellText, assets);
  if (shellIssue) refuse('inline-shell', `${SHELL_SOURCE}: ${shellIssue}`);
  outputs.push({ path: SHELL_OUTPUT, within: 'index.html', from: SHELL_SOURCE, transform: 'asset-digest', data: Buffer.from(shellText.split(ASSET_TOKEN).join(assetDigest), 'utf8') });
  outputs.sort((a, b) => byString(a.path, b.path));

  const records = outputs.map((output) => ({
    path: output.path,
    sha256: sha256Hex(output.data),
    bytes: output.data.length,
    from: output.from,
    transform: output.transform,
    url: output.path === SHELL_OUTPUT ? SHELL_URL : `${ASSET_PREFIX}${assetDigest}/${output.within}`,
    content_type: CONTENT_TYPES[extensionOf(output.path)],
  }));
  const manifest = {
    schema: SCHEMA,
    builder: { path: BUILDER_PATH, sha256: builderSha256 },
    runtime: { node: process.version, strip: STRIP_ENGINE },
    config: CONFIG_FILE,
    source_root: SOURCE_ROOT,
    inputs: [...ctx.inputs].sort((a, b) => byString(a.path, b.path)),
    outputs: records,
    asset_digest: assetDigest,
    build_digest: digestLines(records.map((record) => [record.path, record.sha256])),
  };

  prepareOutRoot(outRoot);
  writeTree(outRoot, outputs, `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    const value = argv[i + 1];
    if ((flag !== '--root' && flag !== '--out') || value === undefined || value === '' || value.startsWith('--')) return null;
    const key = flag.slice(2);
    if (options[key] !== undefined) return null;
    options[key] = value;
  }
  return options;
}

function main(argv) {
  const options = parseArgs(argv);
  if (options === null) {
    process.stderr.write('build-ui: USAGE build-ui.mjs [--root <dir>] [--out <dir>]\n');
    return 2;
  }
  try {
    const manifest = buildUi({ root: options.root, out: options.out });
    process.stdout.write(`build-ui: OK build_digest=${manifest.build_digest} asset_digest=${manifest.asset_digest} inputs=${manifest.inputs.length} outputs=${manifest.outputs.length}\n`);
    return 0;
  } catch (error) {
    if (error instanceof BuildRefused) process.stderr.write(`build-ui: REFUSED ${error.code}: ${error.message}\n`);
    else process.stderr.write(`build-ui: ERROR ${error?.code ?? error?.name ?? 'unknown'}\n`);
    return 1;
  }
}

function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(BUILDER_FILE);
  } catch {
    return false;
  }
}

if (invokedDirectly()) process.exitCode = main(process.argv.slice(2));
