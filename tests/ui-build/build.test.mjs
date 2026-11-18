// SPDX-License-Identifier: Apache-2.0
//
// T035 ui-build UB-01 (only original bytes in dist/) and UB-04 (a deterministic build
// digest). The sources are synthetic and generated at run time; the build's output goes
// to temporary output roots, never to the repository's dist/.

import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { pathToFileURL } from 'node:url';

import { buildUi, BuildRefused } from '../../scripts/build-ui.mjs';
import { assertOnlyOriginalBytes } from './checks.mjs';
import { assertBuilt, cleanup, copyTree, digestLines, DOM_DIRECTIVE, listTree, runBuild, syntheticRoot, tempDir, writeFiles } from './support.mjs';

after(cleanup);

const SPDX = '// SPDX-License-Identifier: Apache-2.0';

test('[UB-01] every byte in dist/ is an original Apache-2.0 source byte: stripped, copied or digest-filled, and the stripped modules run', async () => {
  const root = syntheticRoot();
  const out = join(tempDir('out'), 'dist');
  const run = runBuild({ root, out });
  assertBuilt(run);
  assert.match(run.stdout, /^build-ui: OK build_digest=[0-9a-f]{64} asset_digest=[0-9a-f]{64} inputs=7 outputs=6\n$/);
  assert.deepEqual(
    run.manifest.outputs.map((output) => [output.path, output.transform]),
    [
      ['autograph/geometry/scale.js', 'strip-types'],
      ['autograph/icons/seal.svg', 'copy'],
      ['autograph/index.html', 'asset-digest'],
      ['autograph/main.js', 'strip-types'],
      ['autograph/review.css', 'copy'],
      ['autograph/types.js', 'strip-types'],
    ],
  );
  assertOnlyOriginalBytes(root, out, run.manifest);

  // The stripped output is plain JavaScript whose relative .js imports resolve: import it.
  const check = join(tempDir('import'), 'autograph');
  copyTree(join(out, 'autograph'), check);
  writeFileSync(join(check, 'package.json'), '{ "type": "module" }\n');
  const main = await import(pathToFileURL(join(check, 'main.js')).href);
  assert.deepEqual(main.quantize([{ x: 0.5, y: 0.25 }, { x: 2, y: -1 }]), [{ x: 5000, y: 2500 }, { x: 10000, y: 0 }]);
  assert.equal(main.countAll([{}, {}, {}]), 3);
  assert.equal(main.LABEL, 'Synthetic signer \u00e9 \u2713', 'non-ASCII text survives byte for byte');
});

test('[UB-01] sources that are not original openSig browser code are refused and nothing is written', () => {
  const cases = {
    'a vendored JavaScript file': [{ 'src/autograph/vendor/lib.js': `${SPDX}\nexport const x = 1;\n` }, 'unsupported-source'],
    'a declaration file': [{ 'src/autograph/globals.d.ts': `${SPDX}\n${DOM_DIRECTIVE}\ndeclare const x: number;\n` }, 'unsupported-source'],
    'a second HTML page': [{ 'src/autograph/other.html': '<!-- SPDX-License-Identifier: Apache-2.0 -->\n<!doctype html>\n' }, 'unsupported-source'],
    'a binary asset': [{ 'src/autograph/logo.png': 'synthetic-not-an-image' }, 'unsupported-source'],
    'a dotfile': [{ 'src/autograph/.hidden.ts': `${SPDX}\n${DOM_DIRECTIVE}\n` }, 'unsafe-name'],
    'no SPDX header': [{ 'src/autograph/types.ts': `${DOM_DIRECTIVE}\nexport type T = string;\n` }, 'license-header'],
    'a foreign license': [{ 'src/autograph/types.ts': `// SPDX-License-Identifier: MIT\n${DOM_DIRECTIVE}\nexport type T = string;\n` }, 'foreign-license'],
    'a preserved third-party banner': [{ 'src/autograph/review.css': '/* SPDX-License-Identifier: Apache-2.0 */\n/*! Library v1 | synthetic banner */\nmain {}\n' }, 'third-party-marker'],
    'a non-erasable enum': [{ 'src/autograph/types.ts': `${SPDX}\n${DOM_DIRECTIVE}\nexport enum Mode { Draw, Type }\n` }, 'typescript-syntax'],
    'a bare package import': [{ 'src/autograph/types.ts': `${SPDX}\n${DOM_DIRECTIVE}\nimport { decoy } from 'decoy';\nexport const d = decoy;\n` }, 'module-specifier'],
    'a .ts module specifier': [{ 'src/autograph/types.ts': `${SPDX}\n${DOM_DIRECTIVE}\nimport { scale } from './geometry/scale.ts';\nexport const s = scale;\n` }, 'module-specifier'],
    'an import of a missing module': [{ 'src/autograph/types.ts': `${SPDX}\n${DOM_DIRECTIVE}\nimport { gone } from './gone.js';\nexport const g = gone;\n` }, 'module-specifier'],
    'no shell': [{ 'src/autograph/index.html': null }, 'no-shell'],
  };
  for (const [label, [overrides, code]] of Object.entries(cases)) {
    const root = syntheticRoot(overrides, 'refused');
    const out = join(tempDir('out'), 'dist');
    assert.throws(() => buildUi({ root, out }), (error) => error instanceof BuildRefused && error.code === code, `${label}: refused as ${code}`);
    assert.throws(() => readFileSync(join(out, 'build-provenance.json')), /ENOENT/, `${label}: no manifest`);
  }
  // Through the CLI: exit 1, one REFUSED line, nothing written.
  const root = syntheticRoot({ 'src/autograph/vendor/lib.js': `${SPDX}\nexport const x = 1;\n` }, 'refused-cli');
  const run = runBuild({ root, out: join(tempDir('out'), 'dist') });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /^build-ui: REFUSED unsupported-source: src\/autograph\/vendor\/lib\.js: /m);
  assert.equal(run.manifest, null);
  assert.equal(run.stdout, '');
});

test('[UB-04] the build digest is deterministic: same sources, same bytes, wherever and however often they are built', (t) => {
  const root = syntheticRoot({}, 'det');
  const first = runBuild({ root, out: join(tempDir('out'), 'dist') });
  const second = runBuild({ root, out: join(tempDir('out'), 'dist') });
  assertBuilt(first, 'the first build');
  assertBuilt(second, 'the second build');
  assert.equal(second.manifestText, first.manifestText, 'byte-identical manifests');

  // Node's stripTypeScriptTypes may print an ExperimentalWarning. It goes to the builder's stderr
  // only: stdout is the one OK line, and no warning text reaches the manifest or any output.
  t.diagnostic(`builder stderr carries an ExperimentalWarning: ${/ExperimentalWarning/.test(first.stderr)}`);
  for (const run of [first, second]) {
    assert.match(run.stdout, /^build-ui: OK [^\n]*\n$/, 'stdout is the single OK line');
    assert.doesNotMatch(run.manifestText, /ExperimentalWarning|experimental feature|trace-warnings/, 'no warning text in the manifest');
    for (const output of run.manifest.outputs) {
      assert.doesNotMatch(readFileSync(join(run.out, output.path), 'utf8'), /ExperimentalWarning|experimental feature|trace-warnings/, `${output.path}: no warning text`);
    }
  }
  for (const output of first.manifest.outputs) {
    assert.ok(readFileSync(join(first.out, output.path)).equals(readFileSync(join(second.out, output.path))), `${output.path}: identical bytes`);
  }
  assert.equal(first.manifest.build_digest, digestLines(first.manifest.outputs.map((output) => [output.path, output.sha256])), 'the build digest is the digest of the outputs');
  assert.equal(
    first.manifest.asset_digest,
    digestLines(first.manifest.outputs.filter((output) => output.path !== 'autograph/index.html').map((output) => [output.path.slice('autograph/'.length), output.sha256])),
    'the asset digest is the digest of the assets',
  );

  // Relocated: the same sources under another absolute path give the same manifest.
  const moved = join(tempDir('moved'), 'deeper', 'project');
  copyTree(root, moved);
  const relocated = runBuild({ root: moved, out: join(tempDir('out'), 'nested', 'dist') });
  assertBuilt(relocated, 'the relocated build');
  assert.equal(relocated.manifestText, first.manifestText, 'no absolute path reaches the manifest or the outputs');
  for (const leak of [root, moved, tmpdir(), homedir()]) assert.ok(!first.manifestText.includes(leak), 'the manifest names no host path');
  assert.doesNotMatch(first.manifestText, /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/, 'the manifest records no time');

  // Rebuilding over a previous build replaces it cleanly; the default output root is <root>/dist.
  const again = runBuild({ root, out: first.out });
  assertBuilt(again, 'the rebuild');
  assert.equal(again.manifestText, first.manifestText);
  assert.deepEqual(listTree(first.out).files, ['build-provenance.json', ...first.manifest.outputs.map((output) => output.path)].sort(), 'no staging or previous files remain');
  const byDefault = runBuild({ root });
  assertBuilt(byDefault, 'the default-output build');
  assert.equal(byDefault.out, join(root, 'dist'));
  assert.equal(byDefault.manifestText, first.manifestText);

  // Sensitivity: one changed asset byte changes the asset digest, the build digest and the shell's URLs, and nothing else.
  writeFiles(root, { 'src/autograph/review.css': readFileSync(join(root, 'src', 'autograph', 'review.css'), 'utf8').replace('40rem', '41rem') });
  const changed = runBuild({ root, out: join(tempDir('out'), 'dist') });
  assertBuilt(changed, 'the changed build');
  assert.notEqual(changed.manifest.build_digest, first.manifest.build_digest);
  assert.notEqual(changed.manifest.asset_digest, first.manifest.asset_digest);
  const digestOf = (manifest, path) => manifest.outputs.find((output) => output.path === path).sha256;
  assert.notEqual(digestOf(changed.manifest, 'autograph/index.html'), digestOf(first.manifest, 'autograph/index.html'), 'the shell points at the new asset URLs');
  assert.equal(digestOf(changed.manifest, 'autograph/main.js'), digestOf(first.manifest, 'autograph/main.js'), 'an unchanged module keeps its bytes');
  assert.ok(readFileSync(join(changed.out, 'autograph', 'index.html'), 'utf8').includes(`/assets/${changed.manifest.asset_digest}/review.css`));

  // A foreign file in the output root is never deleted: the build refuses instead.
  writeFileSync(join(first.out, 'notes.txt'), 'not written by the build\n');
  const foreign = runBuild({ root, out: first.out });
  assert.equal(foreign.status, 1);
  assert.match(foreign.stderr, /REFUSED foreign-output/);
  assert.equal(readFileSync(join(first.out, 'notes.txt'), 'utf8'), 'not written by the build\n');
});
