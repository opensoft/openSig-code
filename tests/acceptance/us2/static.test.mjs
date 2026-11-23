// SPDX-License-Identifier: Apache-2.0
//
// T017 [US2-STATIC] (an extra ID, never required; browser-free). It guards, in every us2-local run,
// the import rules the T017 preparation set for tests/acceptance/us2/:
// - only oracle.mjs names T014's oracle adapter and agreement helper (request #78 (1)), and no file
//   names the oracle's own directory or its fixtures (the oracle stays independent of T017);
// - oracle.mjs imports nothing from src/, so the product can never stand in for the oracle (the
//   caller injects verifyPdf into runBoth);
// - the only modules imported from other tasks' test directories are those two helpers (in
//   oracle.mjs) and the contract validator with its sibling (in harness.mjs; requests #76 (3) and
//   #78 (5));
// - no file uses skip, todo or only, or the DOM lib directive (UB-06 keeps that one to
//   src/autograph/);
// - no file spells T015's fault-hook flag (request #86 (4)): the harness only imports the
//   constant to check that its own process carries no such argument, and passes it to nothing;
// - only the two files that run the oracle or record evidence import oracle.mjs, so harness.mjs
//   and [US2-ANCHOR-CONTROL]'s file, trust-anchor-control.test.mjs, load in a tree without the
//   oracle's directory (A-010 request #88 item 2, N2: M-R3's one targeted run, in T017's fresh
//   recheck). That file also imports, read-only, the frozen runner's scripts/verify.mjs
//   (expandGlobs) and scripts/verify-modes.mjs (MODES), which import no oracle module. Its only
//   direct product import is the public read-only parseCapacity/parseOrphans pair from
//   src/pdf/service.ts; that exact path is allowed for this file only;
// - first, the order (request #88: the control runs AFTER the SC005-02 burst): the frozen runner
//   runs expandGlobs(MODES['us2-local'].files) in that sorted order, one file at a time, so the
//   file declaring [US2-ANCHOR-CONTROL] must sort strictly after the one declaring [SC005-02].

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { expandGlobs } from '../../../scripts/verify.mjs';
import { MODES } from '../../../scripts/verify-modes.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const SELF = 'static.test.mjs';
/** A test declaration of `id` (built from pieces, so no file's own text matches by accident). */
const declares = (id) => new RegExp(['\\btest\\(\\s*', "'\\[", id, '\\]'].join(''));
// Built from pieces, so this file's own text never matches what it looks for.
const ORACLE_DIRECTORY = ['integrity', 'oracle', ''].join('/');
const ORACLE_FIXTURES = ['synthetic', 'integrity', ''].join('/');
const FAULT_FLAG_TEXT = ['--opensig', 'test', 'fault', 'hook'].join('-');
const HELPERS = Object.freeze([['integrity', 'product', 'helpers', 'oracle.mjs'].join('/'), ['integrity', 'product', 'helpers', 'agreement.mjs'].join('/')]);
/** The only files that may import oracle.mjs: they run the oracle or record evidence with its labels. */
const ORACLE_IMPORTERS = Object.freeze(['concurrent.test.mjs', 'flows.test.mjs']);
const ALLOWED_FOREIGN = Object.freeze({
  'oracle.mjs': ['../../integrity/product/helpers/agreement.mjs', '../../integrity/product/helpers/oracle.mjs'],
  'harness.mjs': ['../../contract/envelopes/lib/contract.mjs', '../../contract/envelopes/lib/schema.mjs'],
  'trust-anchor-control.test.mjs': ['../../../scripts/verify-modes.mjs', '../../../scripts/verify.mjs', '../../../src/pdf/service.ts'],
});
const CONTROL_FILE = 'trust-anchor-control.test.mjs';

function sources() {
  return readdirSync(HERE)
    .filter((name) => name.endsWith('.mjs') && name !== SELF)
    .sort()
    .map((name) => ({ name, text: readFileSync(join(HERE, name), 'utf8') }));
}

function specifiers(text) {
  return [...text.matchAll(/\bfrom\s+'([^']+)'|\bimport\(\s*'([^']+)'\s*\)/g)].map((match) => match[1] ?? match[2]);
}

test('[US2-STATIC] tests/acceptance/us2/ keeps its import rules and its run order: the anchor control sorts after the SC005-02 burst, only oracle.mjs reaches the oracle through T014\'s two helpers, oracle.mjs imports nothing from src/, and only the named foreign modules are imported', () => {
  // The order first (request #88), on the frozen runner's own sorted list for us2-local.
  const list = expandGlobs(REPO, MODES['us2-local'].files);
  const declaring = (id) => list.filter((file) => declares(id).test(readFileSync(join(REPO, file), 'utf8')));
  const burst = declaring('SC005-02');
  const control = declaring('US2-ANCHOR-CONTROL');
  assert.deepEqual([burst.length, control.length], [1, 1], `exactly one us2-local file declares SC005-02 (${burst.join(', ') || 'none'}) and exactly one declares US2-ANCHOR-CONTROL (${control.join(', ') || 'none'}); the runner's sorted list: ${list.join(', ')}`);
  const at = { control: list.indexOf(control[0]), burst: list.indexOf(burst[0]) };
  assert.ok(at.control > at.burst, `the frozen runner runs us2-local's files in this sorted order, one at a time: ${list.join(', ')}. ${control[0]} (index ${at.control}, [US2-ANCHOR-CONTROL]) must sort strictly after ${burst[0]} (index ${at.burst}, [SC005-02]) (request #88)`);
  const files = sources();
  assert.ok(files.some((file) => file.name === 'oracle.mjs') && files.some((file) => file.name === 'harness.mjs'), `the us2 sources were found (${files.map((file) => file.name).join(', ')})`);
  for (const { name, text } of files) {
    assert.equal(text.includes(ORACLE_DIRECTORY), false, `${name} names the oracle's own directory`);
    assert.equal(text.includes(ORACLE_FIXTURES), false, `${name} names the oracle's fixtures`);
    if (name !== 'oracle.mjs') {
      for (const helper of HELPERS) assert.equal(text.includes(helper), false, `${name} names T014's ${helper.split('/').at(-1)}; only oracle.mjs may`);
    }
    for (const specifier of specifiers(text)) {
      if (!specifier.startsWith('.')) continue;
      const local = specifier.startsWith('./') && !specifier.slice(2).includes('/');
      const product = specifier.startsWith('../../../src/') && name !== CONTROL_FILE;
      const allowed = (ALLOWED_FOREIGN[name] ?? []).includes(specifier);
      assert.ok(local || allowed || (product && name !== 'oracle.mjs'), `${name} imports ${specifier}, which is neither a us2 module, an allowed foreign module nor (outside oracle.mjs) a product module`);
    }
    assert.doesNotMatch(text, /\b(?:test|it|describe)\.(?:skip|todo|only)\b|\{\s*(?:skip|todo|only)\s*:/, `${name} uses skip, todo or only`);
    assert.doesNotMatch(text, /^\s*\/\/\/\s*<reference\s+lib=/m, `${name} carries a lib reference directive`);
    assert.equal(text.includes(FAULT_FLAG_TEXT), false, `${name} spells T015's fault-hook flag; the acceptance never arms the hook`);
    if (specifiers(text).includes('./oracle.mjs')) assert.ok(ORACLE_IMPORTERS.includes(name), `${name} imports oracle.mjs; only ${ORACLE_IMPORTERS.join(' and ')} may, so harness.mjs and the anchor control load without the oracle's directory`);
  }
  assert.ok(files.some((file) => file.name === CONTROL_FILE), `the anchor control file ${CONTROL_FILE} is present (found ${files.map((file) => file.name).join(', ')})`);
  const oracleText = files.find((file) => file.name === 'oracle.mjs').text;
  assert.deepEqual(specifiers(oracleText).filter((specifier) => specifier.includes('/src/')), [], 'oracle.mjs imports nothing from src/');
});
