// SPDX-License-Identifier: Apache-2.0
//
// T035 ui-build UB-05: the provenance manifest and the build's own read trace show no input
// from a non-shipped package, and every dist/ file is in the manifest's outputs with its
// SHA-256, with nothing else in dist/ (A-010 request #33 (3)). The trace is taken inside the
// build process by tests/ui-build/read-trace.mjs (loaded with --import), independently of
// the manifest the build writes. A synthetic decoy package sits under the synthetic root's
// node_modules/, and links, nested packages and configuration try to pull it in.

import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { assertAccounted, assertProvenance, assertUntouched } from './checks.mjs';
import { addDecoyPackage, assertBuilt, BUILDER, builderRealPath, cleanup, copyTree, DOM_DIRECTIVE, link, marker, nonShippedPackageDirs, REPO, runBuild, syntheticRoot, syntheticSources, tempDir, traceSummary, writeFiles } from './support.mjs';

after(cleanup);

const SPDX = '// SPDX-License-Identifier: Apache-2.0';

test('[UB-05] the manifest lists every file the build read and wrote, and the build process read nothing else: no node_modules/, no non-shipped package', () => {
  const root = syntheticRoot({}, 'provenance');
  const secret = marker('decoy');
  const decoy = addDecoyPackage(root, secret);
  const out = join(tempDir('out'), 'dist');
  const run = runBuild({ root, out, trace: true });
  assertBuilt(run);
  assertProvenance({ root, out, manifest: run.manifest, trace: run.trace, forbidden: [decoy] });
  assert.deepEqual(
    run.manifest.inputs.map((input) => [input.path, input.role]),
    [
      ['src/autograph/geometry/scale.ts', 'script'],
      ['src/autograph/icons/seal.svg', 'image'],
      ['src/autograph/index.html', 'shell'],
      ['src/autograph/main.ts', 'script'],
      ['src/autograph/review.css', 'stylesheet'],
      ['src/autograph/types.ts', 'script'],
      ['tsconfig.browser.json', 'config'],
    ],
    'every input, by repository-relative path and role',
  );
  for (const output of run.manifest.outputs) assert.ok(!readFileSync(join(out, ...output.path.split('/'))).includes(secret), `${output.path}: no decoy byte`);
  assert.deepEqual(run.manifest.runtime, { node: process.version, strip: 'node:module stripTypeScriptTypes (mode strip)' }, 'the stripper is the runtime itself');
  assert.ok(nonShippedPackageDirs().some((dir) => dir.endsWith(join('node_modules', 'typescript'))), 'typescript is among the non-shipped packages the trace is checked against');
});

test('[UB-05] the build refuses inputs from node_modules/, through links, inside a nested package or by configuration, and never reads them', () => {
  const sourceFiles = () => Object.fromEntries(Object.entries(syntheticSources()).filter(([rel]) => rel.startsWith('src/autograph/')).map(([rel, content]) => [rel.slice('src/autograph/'.length), content]));
  const cases = {
    'a source directory linked into the decoy package': [(root, decoy) => link(decoy, join(root, 'src', 'autograph', 'vendor')), 'symlink'],
    'a source file linked to a decoy file': [(root, decoy) => link(join(decoy, 'index.ts'), join(root, 'src', 'autograph', 'decoy.ts')), 'symlink'],
    'the source root itself a link to a copy inside the decoy package': [
      (root, decoy) => {
        writeFiles(join(decoy, 'autograph'), sourceFiles());
        rmSync(join(root, 'src', 'autograph'), { recursive: true, force: true });
        link(join(decoy, 'autograph'), join(root, 'src', 'autograph'));
      },
      'source-root',
    ],
    'a node_modules directory inside the sources': [(root) => writeFiles(root, { 'src/autograph/node_modules/decoy/index.ts': `${SPDX}\n${DOM_DIRECTIVE}\nexport const d = 1;\n` }), 'non-shipped-input'],
    'a nested package inside the sources': [(root) => writeFiles(root, { 'src/autograph/lib/package.json': '{ "name": "decoy" }\n', 'src/autograph/lib/x.ts': `${SPDX}\n${DOM_DIRECTIVE}\nexport const x = 1;\n` }), 'package-boundary'],
    'a configuration that points into the decoy package': [
      (root) => writeFiles(root, { 'tsconfig.browser.json': `${JSON.stringify({ extends: './tsconfig.json', compilerOptions: { lib: ['es2024', 'dom'], types: [], rootDir: 'node_modules/decoy', outDir: 'dist/autograph' }, include: ['node_modules/decoy'] })}\n` }),
      'config',
    ],
    'a configuration file that is a link into the decoy package': [
      (root, decoy) => {
        writeFiles(decoy, { 'tsconfig.browser.json': readFileSync(join(root, 'tsconfig.browser.json'), 'utf8') });
        rmSync(join(root, 'tsconfig.browser.json'));
        link(join(decoy, 'tsconfig.browser.json'), join(root, 'tsconfig.browser.json'));
      },
      'input-not-regular',
    ],
  };
  for (const [label, [arrange, code]] of Object.entries(cases)) {
    const root = syntheticRoot({}, 'refuse');
    const decoy = addDecoyPackage(root, marker('decoy'));
    arrange(root, decoy);
    const run = runBuild({ root, out: join(tempDir('out'), 'dist'), trace: true });
    assert.equal(run.status, 1, `${label}: refused (${run.stderr.trim()})`);
    assert.match(run.stderr, new RegExp(`^build-ui: REFUSED ${code}: `, 'm'), `${label}: refused as ${code}`);
    assert.equal(run.manifest, null, `${label}: no manifest`);
    const { reads, lists, writes, unattributed } = traceSummary(run.trace);
    assert.deepEqual(unattributed, [], `${label}: every traced call names a path`);
    assert.deepEqual([...writes], [], `${label}: nothing written`);
    assertUntouched([...reads, ...lists], [...nonShippedPackageDirs(REPO), decoy]);
    assert.ok(reads.has(builderRealPath()), `${label}: the trace was taken inside the build process`);
  }
});

test('[UB-05] the builder can load nothing but node: builtins, so the trace covers every way it can read', () => {
  const source = readFileSync(BUILDER, 'utf8');
  const imports = [...source.matchAll(/^import\s+(?:\{([^}]*)\}|[\w$]+|\*\s+as\s+[\w$]+)\s+from\s+'([^']+)';$/gm)].map((match) => ({ names: (match[1] ?? '').split(',').map((name) => name.trim()).filter(Boolean), specifier: match[2] }));
  const allImportLines = source.split('\n').filter((line) => /^import\b/.test(line));
  assert.equal(imports.length, allImportLines.length, 'every import of the builder is a plain static import');
  assert.deepEqual(imports.map((entry) => entry.specifier).sort(), ['node:crypto', 'node:fs', 'node:module', 'node:path', 'node:url'], 'node: builtins only; no package, no relative module');
  const fsNames = imports.find((entry) => entry.specifier === 'node:fs').names;
  assert.deepEqual(fsNames.sort(), ['lstatSync', 'mkdirSync', 'mkdtempSync', 'readFileSync', 'readdirSync', 'realpathSync', 'renameSync', 'rmSync', 'writeFileSync'].sort(), 'its only content reader is readFileSync and its only lister readdirSync, both traced');
  assert.deepEqual(imports.find((entry) => entry.specifier === 'node:module').names, ['stripTypeScriptTypes'], 'no module hooks and no require');
  for (const [pattern, label] of [
    // A dynamic import() is never preceded by '@' (the builder names CSS's @import rule in a refusal).
    [/(?<!@)\bimport\s*\(/, 'dynamic import()'],
    [/\brequire\s*\(/, 'require()'],
    [/createRequire/, 'createRequire'],
    [/process\s*\.\s*(?:binding|dlopen)/, 'process.binding or dlopen'],
    [/internalBinding/, 'internalBinding'],
    [/child_process|worker_threads|node:vm|node:wasi|node:net|node:http/, 'a process, thread, VM or network module'],
    [/\beval\s*\(|new Function\s*\(/, 'code from strings'],
  ]) {
    assert.doesNotMatch(source, pattern, `the builder uses no ${label}`);
  }
});

test('[UB-05] every dist/ file is accounted for: the manifest lists each with its SHA-256, and a stray, changed, missing or linked file is caught', () => {
  const root = syntheticRoot({}, 'accounted');
  const good = join(tempDir('out'), 'dist');
  const run = runBuild({ root, out: good });
  assertBuilt(run);
  assertAccounted(good, run.manifest);
  assert.equal(run.manifest.outputs.length, 6, 'the shell and five assets');

  const damages = {
    'a stray file beside the outputs': (dir) => writeFileSync(join(dir, 'autograph', 'stray.js'), 'export const stray = 1;\n'),
    'a stray file at the output root': (dir) => writeFileSync(join(dir, 'notes.txt'), 'not built\n'),
    'a stray hidden file': (dir) => writeFileSync(join(dir, 'autograph', '.cache'), ''),
    'a stray directory with a file in it': (dir) => {
      mkdirSync(join(dir, 'autograph', 'extra'));
      writeFileSync(join(dir, 'autograph', 'extra', 'x.css'), '');
    },
    'a stray empty directory (such as a staging leftover)': (dir) => mkdirSync(join(dir, '.staging-leftover')),
    'an output changed by one byte': (dir) => {
      const path = join(dir, 'autograph', 'main.js');
      const bytes = readFileSync(path);
      bytes[bytes.length - 2] ^= 0x01;
      writeFileSync(path, bytes);
    },
    'an output missing': (dir) => rmSync(join(dir, 'autograph', 'types.js')),
    'a link among the outputs': (dir) => symlinkSync(join(dir, 'autograph', 'main.js'), join(dir, 'autograph', 'alias.js')),
  };
  for (const [label, damage] of Object.entries(damages)) {
    const dir = join(tempDir('damaged'), 'dist');
    copyTree(good, dir);
    damage(dir);
    assert.throws(() => assertAccounted(dir, run.manifest), assert.AssertionError, `${label}: caught`);
  }
});
