// SPDX-License-Identifier: Apache-2.0
//
// The UB-01, UB-02 and UB-05 assertions on one finished build, shared by the synthetic-tree
// tests and the repository test (T035). They read the build's files and the manifest and
// recompute everything themselves; none of them calls into scripts/build-ui.mjs.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { isAbsolute, join, sep } from 'node:path';

import { ASSET_TOKEN, BUILDER, builderRealPath, derivationProblem, inlineFindings, isWithin, kindOfOutput, listTree, nonShippedPackageDirs, REPO, sha256, traceSummary } from './support.mjs';

const SCHEMA = 'opensig.ui-build-provenance/1';

/**
 * UB-05 (A-010 request #33 (3)): every file in the output root is accounted for. It holds no
 * link and nothing but regular files and directories; its files are exactly the manifest and
 * the outputs the manifest lists; and each output's bytes have the recorded SHA-256 and size.
 * The forward requirement of docs/qualification.md, checked inside T035's own mode.
 */
export function assertAccounted(out, manifest) {
  const tree = listTree(out);
  assert.deepEqual(tree.links, [], 'dist/ holds no symbolic link');
  assert.deepEqual(tree.others, [], 'dist/ holds only regular files and directories');
  assert.deepEqual(tree.files, ['build-provenance.json', ...manifest.outputs.map((output) => output.path)].sort(), 'every dist/ file is the manifest or an output it lists, and nothing else is in dist/');
  const parents = new Set();
  for (const output of manifest.outputs) {
    const segments = output.path.split('/');
    for (let depth = 1; depth < segments.length; depth += 1) parents.add(segments.slice(0, depth).join('/'));
  }
  assert.deepEqual(tree.dirs, [...parents].sort(), 'dist/ has no directory but those holding the outputs');
  for (const output of manifest.outputs) {
    const bytes = readFileSync(join(out, ...output.path.split('/')));
    assert.equal(sha256(bytes), output.sha256, `${output.path}: its SHA-256 is the one the manifest records`);
    assert.equal(bytes.length, output.bytes, `${output.path}: its size is the one the manifest records`);
  }
}

/** UB-01: dist/ holds only the manifest and outputs derived from original Apache-2.0 sources. */
export function assertOnlyOriginalBytes(root, out, manifest) {
  assertAccounted(out, manifest);

  const inputs = new Map(manifest.inputs.map((input) => [input.path, input]));
  for (const input of manifest.inputs) {
    assert.ok(input.path === 'tsconfig.browser.json' || input.path.startsWith('src/autograph/'), `${input.path}: an input of this build`);
    const bytes = readFileSync(join(root, ...input.path.split('/')));
    assert.equal(sha256(bytes), input.sha256, `${input.path}: the recorded digest is the file's`);
    if (input.role === 'config') continue;
    const ids = [...bytes.toString('utf8').matchAll(/SPDX-License-Identifier:[ \t]*([A-Za-z0-9.+()-]+)/g)].map((match) => match[1]);
    assert.deepEqual([...new Set(ids)], ['Apache-2.0'], `${input.path}: an original Apache-2.0 source`);
  }

  for (const output of manifest.outputs) {
    const bytes = readFileSync(join(out, ...output.path.split('/')));
    assert.equal(sha256(bytes), output.sha256, `${output.path}: digest`);
    assert.equal(bytes.length, output.bytes, `${output.path}: size`);
    const source = inputs.get(output.from);
    assert.ok(source !== undefined && source.role !== 'config', `${output.path} comes from one listed source`);
    const sourceBytes = readFileSync(join(root, ...output.from.split('/')));
    const sourceText = sourceBytes.toString('utf8');
    const text = bytes.toString('utf8');
    if (output.transform === 'strip-types') {
      assert.ok(output.from.endsWith('.ts') && output.path.endsWith('.js'), `${output.path}: a stripped script`);
      assert.equal(text, stripTypeScriptTypes(sourceText, { mode: 'strip' }), `${output.path}: exactly Node's type stripping of its source`);
      assert.equal(derivationProblem(sourceText, text), null, `${output.path}: every non-blank byte is the source's own byte at the same place`);
    } else if (output.transform === 'copy') {
      assert.ok(bytes.equals(sourceBytes), `${output.path}: a byte-for-byte copy`);
    } else if (output.transform === 'asset-digest') {
      assert.equal(output.path, 'autograph/index.html');
      assert.equal(text, sourceText.split(ASSET_TOKEN).join(manifest.asset_digest), 'the shell is its source with the asset digest filled in');
    } else {
      assert.fail(`${output.path}: unknown transform ${output.transform}`);
    }
    for (const foreign of ['sourceMappingURL', 'sourceURL', 'node_modules', '__awaiter', '__decorate', 'tslib', '@license', '/*!', 'require(', root, REPO]) {
      assert.ok(!text.includes(foreign), `${output.path} carries no ${foreign}`);
    }
  }
}

/** UB-02: no output carries an inline script or style; the shell loads only this build's assets. */
export function assertNoInline(out, manifest) {
  for (const output of manifest.outputs) {
    const text = readFileSync(join(out, ...output.path.split('/')), 'utf8');
    assert.deepEqual(inlineFindings(kindOfOutput(output.path), text), [], `${output.path}: no inline script or style`);
  }
  const shell = readFileSync(join(out, 'autograph', 'index.html'), 'utf8');
  const urls = new Set(manifest.outputs.map((output) => output.url));
  const references = [...shell.matchAll(/<(?:script|link)\b[^>]*?\s(?:src|href)="([^"]+)"/g)].map((match) => match[1]);
  assert.ok(references.length > 0, 'the shell loads its script and styles from files');
  for (const reference of references) {
    assert.ok(reference.startsWith(`/assets/${manifest.asset_digest}/`) && urls.has(reference), `${reference}: an asset of this very build`);
  }
  for (const match of shell.matchAll(/<script\b([^>]*)>/g)) assert.match(match[1], /\stype="module"/, 'every script is an external module');
}

/**
 * UB-05: the manifest and the build process's own read trace agree, and neither shows an
 * input from node_modules/ or from a non-shipped package; and every dist/ file is accounted
 * for (assertAccounted). `forbidden` adds directories (for example a synthetic decoy
 * package) that must never be touched.
 */
export function assertProvenance({ root, out, manifest, trace, forbidden = [] }) {
  assert.equal(manifest.schema, SCHEMA);
  assert.deepEqual(manifest.builder, { path: 'scripts/build-ui.mjs', sha256: sha256(readFileSync(BUILDER)) }, 'the manifest names the builder by digest');
  const packageDirs = [...nonShippedPackageDirs(REPO), ...forbidden];
  assert.ok(packageDirs.length > forbidden.length, 'the non-shipped packages are known from package-lock.json');

  const inputPaths = new Set();
  for (const input of manifest.inputs) {
    const segments = input.path.split('/');
    assert.ok(!isAbsolute(input.path) && !segments.includes('..') && !segments.includes('.'), `${input.path}: repository-relative`);
    assert.ok(!segments.includes('node_modules'), `${input.path}: not under node_modules/`);
    assert.ok(input.path === 'tsconfig.browser.json' || input.path.startsWith('src/autograph/'), `${input.path}: an input of the browser build only`);
    assert.match(input.sha256, /^[0-9a-f]{64}$/);
    const path = join(root, ...segments);
    for (const dir of packageDirs) assert.ok(!isWithin(dir, path), `${input.path}: not inside a non-shipped package`);
    assert.equal(sha256(readFileSync(path)), input.sha256, `${input.path}: the digest is the file's`);
    inputPaths.add(path);
  }
  for (const output of manifest.outputs) assert.match(output.sha256, /^[0-9a-f]{64}$/, `${output.path}: an output digest`);
  assertAccounted(out, manifest);

  assert.ok(Array.isArray(trace), 'the build process wrote its read trace');
  const { reads, lists, writes, unattributed } = traceSummary(trace);
  assert.deepEqual(unattributed, [], 'every traced call names a path');
  assert.deepEqual([...reads].sort(), [...inputPaths, builderRealPath()].sort(), 'the build read exactly the inputs its manifest lists, plus its own source for its digest');
  const sources = join(root, 'src', 'autograph');
  for (const dir of lists) assert.ok(isWithin(sources, dir) || isWithin(out, dir), `${dir}: listed only inside the sources or the output root`);
  for (const path of writes) assert.ok(isWithin(out, path), `${path}: written only inside the output root`);
  assertUntouched([...reads, ...lists, ...writes], packageDirs);
}

/** Nothing in `paths` lies under node_modules/ or inside any of `packageDirs`. */
export function assertUntouched(paths, packageDirs) {
  for (const path of paths) {
    assert.ok(!path.split(sep).includes('node_modules'), `${path}: nothing under node_modules/ was touched`);
    for (const dir of packageDirs) assert.ok(!isWithin(dir, path), `${path}: nothing inside a non-shipped package was touched`);
  }
}
