// SPDX-License-Identifier: Apache-2.0
//
// T004 DV-01: the synthetic fixture generator is deterministic, and the committed set under
// fixtures/synthetic/ is exactly its output (no missing, changed or extra files).

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  DEFAULT_OUT,
  DOCUMENT_SPECS,
  generateDocument,
  generateFixtureSet,
} from '../../scripts/gen-fixtures.mjs';

const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const GENERATOR = join(REPO, 'scripts', 'gen-fixtures.mjs');
const temps = [];

after(() => {
  for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

function tempDir(label) {
  const dir = mkdtempSync(join(tmpdir(), `opensig-dv01-${label}-`));
  temps.push(dir);
  return dir;
}

function listFiles(dir) {
  const files = [];
  const walk = (current) => {
    for (const entry of readdirSync(current).sort()) {
      const abs = join(current, entry);
      if (statSync(abs).isDirectory()) walk(abs);
      else files.push(relative(dir, abs).split('\\').join('/'));
    }
  };
  walk(dir);
  return files.sort();
}

function runGenerator(args, extraEnv = {}) {
  return spawnSync(process.execPath, [GENERATOR, ...args], {
    cwd: REPO,
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '', ...extraEnv },
    timeout: 120_000,
  });
}

const sha256 = (buffer) => createHash('sha256').update(buffer).digest('hex');

test('[DV-01] two independent generator runs write byte-identical fixture sets', () => {
  const first = tempDir('a');
  const second = tempDir('b');
  const runA = runGenerator(['--out', first, '--with-large'], { TZ: 'UTC', LANG: 'C' });
  const runB = runGenerator(['--out', second, '--with-large'], { TZ: 'Pacific/Kiritimati', LANG: 'de_DE.UTF-8', LC_ALL: 'de_DE.UTF-8' });
  assert.equal(runA.status, 0, runA.stderr);
  assert.equal(runB.status, 0, runB.stderr);

  const filesA = listFiles(first);
  const expected = [
    ...DOCUMENT_SPECS.map((spec) => `documents/${spec.file}`),
    'documents/manifest.json',
    'identities/identities.json',
  ].sort();
  assert.deepEqual(filesA, expected, 'the run writes every document, the manifest and the identities');
  assert.deepEqual(listFiles(second), filesA);
  for (const path of filesA) {
    assert.ok(readFileSync(join(first, path)).equals(readFileSync(join(second, path))), `${path} differs between runs`);
  }

  // The in-process API yields the same bytes as the CLI.
  for (const [path, buffer] of generateFixtureSet({ includeLarge: true })) {
    assert.ok(readFileSync(join(first, path)).equals(buffer), `${path} differs between the CLI and the module API`);
  }
});

test('[DV-01] the committed fixture set equals the generator output and its manifest', () => {
  assert.equal(DEFAULT_OUT, join(REPO, 'fixtures', 'synthetic'));
  const check = runGenerator(['--check']);
  assert.equal(check.status, 0, `${check.stdout}\n${check.stderr}`);
  assert.match(check.stdout, /^gen-fixtures: PASS problems=0 expected=\d+$/m);

  const committed = generateFixtureSet();
  assert.deepEqual(
    [...listFiles(join(DEFAULT_OUT, 'documents')).map((p) => `documents/${p}`), ...listFiles(join(DEFAULT_OUT, 'identities')).map((p) => `identities/${p}`)].sort(),
    [...committed.keys()].sort(),
    'fixtures/synthetic/ holds exactly the committed set',
  );
  for (const [path, buffer] of committed) {
    assert.ok(readFileSync(join(DEFAULT_OUT, path)).equals(buffer), `${path} is stale`);
  }

  const manifest = JSON.parse(readFileSync(join(DEFAULT_OUT, 'documents', 'manifest.json'), 'utf8'));
  assert.equal(manifest.synthetic, true);
  assert.deepEqual(manifest.documents.map((doc) => doc.file), DOCUMENT_SPECS.map((spec) => spec.file));
  for (const doc of manifest.documents) {
    const onDisk = join(DEFAULT_OUT, 'documents', doc.file);
    if (doc.committed) {
      const bytes = readFileSync(onDisk);
      assert.equal(bytes.length, doc.bytes, `${doc.file} size`);
      assert.equal(sha256(bytes), doc.sha256, `${doc.file} digest`);
    } else {
      assert.equal(existsSync(onDisk), false, `${doc.file} is generated on demand and must not be committed`);
      const bytes = generateDocument(doc.file);
      assert.equal(bytes.length, doc.bytes, `${doc.file} on-demand size`);
      assert.equal(sha256(bytes), doc.sha256, `${doc.file} on-demand digest`);
    }
  }
});

test('[DV-01] the check mode reports changed, missing and unexpected files by name only', () => {
  const copy = tempDir('drift');
  cpSync(join(DEFAULT_OUT, 'documents'), join(copy, 'documents'), { recursive: true });
  cpSync(join(DEFAULT_OUT, 'identities'), join(copy, 'identities'), { recursive: true });
  const clean = runGenerator(['--check', '--out', copy]);
  assert.equal(clean.status, 0, clean.stdout);

  const changed = join(copy, 'documents', 'rotated-pages.pdf');
  const bytes = readFileSync(changed);
  bytes[bytes.length - 10] ^= 0x01;
  writeFileSync(changed, bytes);
  rmSync(join(copy, 'identities', 'identities.json'));
  writeFileSync(join(copy, 'documents', 'unlisted.pdf'), '%PDF-1.7\n');

  const drift = runGenerator(['--check', '--out', copy]);
  assert.equal(drift.status, 1);
  assert.match(drift.stdout, /^gen-fixtures: differs documents\/rotated-pages\.pdf$/m);
  assert.match(drift.stdout, /^gen-fixtures: missing identities\/identities\.json$/m);
  assert.match(drift.stdout, /^gen-fixtures: unexpected documents\/unlisted\.pdf$/m);
  assert.match(drift.stdout, /^gen-fixtures: FAIL problems=3 /m);
  assert.doesNotMatch(drift.stdout + drift.stderr, /%PDF|obj|stream/, 'output names files, never content');

  const refused = runGenerator(['--with-large']);
  assert.equal(refused.status, 2, 'on-demand documents are never written into the committed set');
  assert.equal(runGenerator(['--bogus']).status, 2);
});
