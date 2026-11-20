// SPDX-License-Identifier: Apache-2.0
//
// T035 ui-build on the repository's own browser sources (src/autograph/, written by T009).
// The build runs with the UB-05 read trace into a temporary output root, never into the
// repository's dist/. Once the sources exist, every UB-01, UB-02 and UB-05 check applies to
// them and tsconfig.browser.json must type-check them. Before T009 lands there are none,
// and the build must refuse with `no-sources` after reading only its configuration: the
// fail-closed half of the same rule, so both states assert real behaviour.

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';

import { assertNoInline, assertOnlyOriginalBytes, assertProvenance, assertUntouched } from './checks.mjs';
import { assertBuilt, builderRealPath, cleanup, nonShippedPackageDirs, REPO, runBuild, runTsc, tempDir, traceSummary } from './support.mjs';

after(cleanup);

test('[UB-05] the repository build reads only its own browser sources and keeps every UB rule, or refuses when there are none', (t) => {
  const out = join(tempDir('repo'), 'dist');
  const run = runBuild({ root: REPO, out, trace: true });
  if (existsSync(join(REPO, 'src', 'autograph'))) {
    t.diagnostic('src/autograph/ exists: the repository sources are built and checked');
    assertBuilt(run, 'the repository build');
    assertOnlyOriginalBytes(REPO, out, run.manifest);
    assertNoInline(out, run.manifest);
    assertProvenance({ root: REPO, out, manifest: run.manifest, trace: run.trace });
    const typed = runTsc(join(REPO, 'tsconfig.browser.json'));
    assert.equal(typed.status, 0, `tsconfig.browser.json type-checks the browser sources: ${typed.output.slice(-2000)}`);
  } else {
    t.diagnostic('src/autograph/ does not exist yet (T009): the build must refuse');
    assert.equal(run.status, 1);
    assert.match(run.stderr, /^build-ui: REFUSED no-sources: src\/autograph\/ does not exist/m);
    assert.equal(run.manifest, null);
    assert.equal(existsSync(out), false, 'nothing was written');
    const { reads, lists, writes, unattributed } = traceSummary(run.trace);
    assert.deepEqual(unattributed, []);
    assert.deepEqual([...reads].sort(), [builderRealPath(), join(REPO, 'tsconfig.browser.json')].sort(), 'only the builder and tsconfig.browser.json were read');
    assert.deepEqual([...lists], []);
    assert.deepEqual([...writes], []);
    assertUntouched([...reads], nonShippedPackageDirs(REPO));
  }
});
