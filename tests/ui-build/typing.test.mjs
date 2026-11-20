// SPDX-License-Identifier: Apache-2.0
//
// T035 ui-build: the browser typing boundary. The frozen tsconfig.json has no DOM lib, so
// browser sources bring it in with `/// <reference lib="dom" />`, which widens the globals
// of the whole program.
//   UB-06 (A-010 request #33 (2)): the DOM lib directive appears only in src/autograph/, every
//          browser source there starts with it (and the build refuses one that does not, or
//          that brings in any other reference), and the server program type-checks with no
//          DOM at all (with a control showing the directive is what admits a DOM global).
//   UB-01: browser code stays original and correctly scoped: no .ts file imports Playwright
//          or its types (and the build refuses a browser module that names it, even for
//          types only), no TypeScript outside src/autograph/ imports it, and
//          tsconfig.browser.json checks browser code with the DOM and without Node types.
//
// The pinned TypeScript compiler (a non-shipped dev tool) runs as a child process. Its only
// file inside the tree is the generated server-only configuration in the gitignored
// .verify-out/ui-build/.

import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { after, test } from 'node:test';

import { buildUi, BuildRefused } from '../../scripts/build-ui.mjs';
import { cleanup, DOM_DIRECTIVE, REPO, runTsc, syntheticRoot, tempDir, verifyOutDir, writeFiles } from './support.mjs';

after(cleanup);

const DIRECTIVE_LINE = /^[ \t]*\/\/\/[ \t]*<reference[ \t]+lib[ \t]*=[ \t]*["']dom(?:\.[a-z]+)?["']/m;
const SPDX = '// SPDX-License-Identifier: Apache-2.0';

/** The build refuses `overrides` of the synthetic sources with `code`, and writes nothing. */
function assertBuildRefuses(label, overrides, code) {
  const root = syntheticRoot(overrides, 'typing');
  const out = join(tempDir('out'), 'dist');
  assert.throws(() => buildUi({ root, out }), (error) => error instanceof BuildRefused && error.code === code, `${label}: refused as ${code}`);
  assert.equal(existsSync(out), false, `${label}: nothing written`);
}

const CODE_FILE = /\.(?:ts|mts|cts|js|mjs|cjs)$/;
const TS_FILE = /\.(?:ts|mts|cts)$/;

function codeFiles(top) {
  const found = [];
  const walk = (rel) => {
    const dir = join(REPO, ...rel.split('/'));
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const child = `${rel}/${entry.name}`;
      if (entry.isDirectory() && entry.name !== 'node_modules') walk(child);
      else if (entry.isFile() && CODE_FILE.test(entry.name)) found.push(child);
    }
  };
  walk(top);
  return found.sort();
}

/** Whether the leading comment block of a source holds the DOM lib directive. */
function headerHasDomDirective(text) {
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
    if (trimmed === DOM_DIRECTIVE) return true;
    if (trimmed.startsWith('//')) continue;
    return false;
  }
  return false;
}

test('[UB-06] the DOM lib directive appears only in src/autograph/, every browser source starts with it, and the server type-checks without the DOM', () => {
  const files = ['src', 'tests', 'scripts'].flatMap(codeFiles);
  assert.ok(files.length > 100, 'the repository code was found');
  for (const rel of files) {
    if (DIRECTIVE_LINE.test(readFileSync(join(REPO, ...rel.split('/')), 'utf8'))) {
      assert.ok(rel.startsWith('src/autograph/'), `${rel}: the DOM lib directive belongs only to browser sources under src/autograph/`);
    }
  }
  for (const rel of files.filter((path) => path.startsWith('src/autograph/') && path.endsWith('.ts'))) {
    assert.ok(headerHasDomDirective(readFileSync(join(REPO, ...rel.split('/')), 'utf8')), `${rel} starts with the DOM lib directive`);
  }

  // The build keeps the rule for every browser source it ships: the directive leads the source,
  // and no other reference directive (Node types included) comes in beside it.
  assertBuildRefuses('a browser source without the DOM lib directive', { 'src/autograph/types.ts': `${SPDX}\nexport type T = string;\n` }, 'dom-reference');
  assertBuildRefuses('the DOM lib directive after code', { 'src/autograph/types.ts': `${SPDX}\nexport type T = string;\n${DOM_DIRECTIVE}\n` }, 'dom-reference');
  assertBuildRefuses('a Node types directive beside it', { 'src/autograph/types.ts': `${SPDX}\n${DOM_DIRECTIVE}\n/` + `// <reference types="node" />\nexport type T = string;\n` }, 'reference-directive');

  // The server program, without src/autograph/ and its directive: no DOM global may appear in it.
  const dir = verifyOutDir();
  const fromDir = (path) => relative(dir, path).split(sep).join('/');
  const config = join(dir, 'tsconfig.server-only.json');
  writeFileSync(config, `${JSON.stringify({ extends: fromDir(join(REPO, 'tsconfig.json')), compilerOptions: { allowJs: false }, include: [fromDir(join(REPO, 'src'))], exclude: [fromDir(join(REPO, 'src', 'autograph'))] }, null, 2)}\n`);
  const server = runTsc(config);
  assert.equal(server.status, 0, `the server program type-checks with no DOM lib: ${server.output.slice(-2000)}`);

  // Control: in a program without the DOM lib, a DOM global is an error, and the directive is what admits it.
  const control = tempDir('control');
  const program = { compilerOptions: { target: 'es2024', lib: ['es2024'], module: 'nodenext', moduleResolution: 'nodenext', strict: true, noEmit: true, types: [] }, files: ['uses-dom.ts'] };
  writeFiles(control, { 'package.json': '{ "type": "module" }\n', 'tsconfig.json': `${JSON.stringify(program)}\n`, 'uses-dom.ts': 'export const title = (): string => document.title;\n' });
  const without = runTsc(join(control, 'tsconfig.json'));
  assert.notEqual(without.status, 0, 'a DOM global without the directive is a type error');
  assert.match(without.output, /error TS(?:2584|2304)\b[^\n]*document/, 'the error names the DOM global');
  writeFiles(control, { 'uses-dom.ts': `${DOM_DIRECTIVE}\nexport const title = (): string => document.title;\n` });
  const admitted = runTsc(join(control, 'tsconfig.json'));
  assert.equal(admitted.status, 0, `the directive admits the DOM: ${admitted.output.slice(-1000)}`);
});

test('[UB-01] browser code stays original and scoped: no .ts file imports Playwright or its types, nothing outside src/autograph/ imports it, and tsconfig.browser.json checks it with the DOM lib and without Node types', () => {
  const files = ['src', 'tests', 'scripts'].flatMap(codeFiles);
  assert.ok(files.length > 100, 'the repository code was found');
  for (const rel of files.filter((path) => TS_FILE.test(path))) {
    const text = readFileSync(join(REPO, ...rel.split('/')), 'utf8');
    assert.doesNotMatch(text, /(?:from|import)\s*\(?\s*['"](?:playwright|playwright-core|@playwright\/[^'"]*)['"]/, `${rel}: no .ts file imports Playwright or its types`);
    assert.doesNotMatch(text, /<reference\s+types\s*=\s*["'](?:playwright|@playwright)/, `${rel}: no Playwright type reference`);
    if (!rel.startsWith('src/autograph/')) {
      assert.doesNotMatch(text, /(?:from|import)\s*\(?\s*['"][^'"]*\/autograph\/[^'"]*['"]/, `${rel}: no TypeScript outside the browser sources imports them (the server serves built bytes)`);
    }
  }

  // The build refuses a browser module that names Playwright, as a value or for its types only.
  assertBuildRefuses('a browser module importing Playwright', { 'src/autograph/types.ts': `${SPDX}\n${DOM_DIRECTIVE}\nimport { chromium } from 'playwright';\nexport const c = chromium;\n` }, 'module-specifier');
  assertBuildRefuses('a browser module importing Playwright types', { 'src/autograph/types.ts': `${SPDX}\n${DOM_DIRECTIVE}\nimport type { Page } from 'playwright';\nexport type P = Page;\n` }, 'module-specifier');

  const root = syntheticRoot({}, 'browser-tsc');
  const clean = runTsc(join(root, 'tsconfig.browser.json'));
  assert.equal(clean.status, 0, `the synthetic browser sources type-check: ${clean.output.slice(-2000)}`);
  writeFiles(root, { 'src/autograph/node-only.ts': `// SPDX-License-Identifier: Apache-2.0\n${DOM_DIRECTIVE}\nexport const cwd = (): string => process.cwd();\n` });
  const nodeGlobal = runTsc(join(root, 'tsconfig.browser.json'));
  assert.notEqual(nodeGlobal.status, 0, 'a Node global in browser code is a type error');
  assert.match(nodeGlobal.output, /node-only\.ts[^\n]*error TS\d+[^\n]*process/, 'the error names the Node global');
});
