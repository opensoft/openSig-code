// SPDX-License-Identifier: Apache-2.0
//
// The version-step trigger names the envelope columns it covers (T007; A-010
// IDEMP-N4; data-model.md § Transitions and races, item 1, migration rule).
// Any migration that adds an envelopes column must update that trigger in the
// same migration. ST-15 reads the trigger as stored, derives the columns it
// compares, and fails naming every column of PRAGMA table_info(envelopes) it
// leaves uncovered, other than updated_at.

import assert from 'node:assert/strict';
import { after, test } from 'node:test';

import { makeScratch, rawConnection, setup } from './support.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

const TRIGGER = 'envelopes_version_step';
/** The one column a storage update may change without the version step (DB-28). */
const EXEMPT = 'updated_at';
const IDENTIFIER = String.raw`(?:"([^"]+)"|\[([^\]]+)\]|\x60([^\x60]+)\x60|([A-Za-z_][A-Za-z0-9_$]*)(?![A-Za-z0-9_$]))`;

function identifier(match, offset) {
  return (match[offset] ?? match[offset + 1] ?? match[offset + 2] ?? match[offset + 3]).toLowerCase();
}

/**
 * The columns the stored version-step trigger covers: each `NEW.c IS NOT OLD.c`
 * comparison of one column with itself in its WHEN condition (a comparison
 * with arithmetic, such as `OLD.version + 1`, is not a change test), limited to
 * the trigger's `UPDATE OF` list when it has one.
 */
function versionStepCoverage(raw) {
  const stored = raw.prepare("SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ? AND tbl_name = 'envelopes'").get(TRIGGER);
  assert.ok(stored, `the ${TRIGGER} trigger exists on envelopes`);
  const sql = stored.sql.replace(/--[^\n]*/g, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');
  const header = /^([\s\S]*?)\bON\s+/i.exec(sql)?.[1] ?? '';
  const updateOf = /\bUPDATE\s+OF\s+([\s\S]*)$/i.exec(header)?.[1];
  const firesOn = updateOf === undefined ? null : new Set(updateOf.split(',').map((name) => name.trim().replace(/^["[\x60]|["\]\x60]$/g, '').toLowerCase()));
  const when = /\bWHEN\b([\s\S]*?)\bBEGIN\b/i.exec(sql)?.[1];
  assert.ok(when, `the ${TRIGGER} trigger has a WHEN condition`);
  const comparison = new RegExp(String.raw`\bNEW\s*\.\s*${IDENTIFIER}\s+IS\s+NOT\s+OLD\s*\.\s*${IDENTIFIER}(?!\s*[-+*/%|&<>=])`, 'gi');
  const covered = new Set();
  for (const match of when.matchAll(comparison)) {
    const left = identifier(match, 1);
    if (left === identifier(match, 5) && (firesOn === null || firesOn.has(left))) covered.add(left);
  }
  const columns = raw.prepare('SELECT name FROM pragma_table_info(?) ORDER BY cid').all('envelopes').map((row) => row.name);
  const uncovered = columns.filter((name) => name.toLowerCase() !== EXEMPT && !covered.has(name.toLowerCase()));
  return { columns, covered: [...covered], uncovered };
}

/** Fail, naming every uncovered column other than updated_at. */
function assertCovered(coverage) {
  assert.deepEqual(
    coverage.uncovered,
    [],
    `${TRIGGER} leaves envelopes column(s) uncovered: ${coverage.uncovered.join(', ')}. A migration that adds an envelopes column must update ${TRIGGER} in the same migration`,
  );
}

test('[ST-15] the version-step trigger covers every envelopes column of PRAGMA table_info except updated_at', () => {
  const ctx = setup(scratch);
  const raw = rawConnection(ctx.path);
  try {
    const coverage = versionStepCoverage(raw);
    assertCovered(coverage);
    assert.ok(coverage.columns.includes(EXEMPT), 'updated_at is an envelopes column');
    assert.equal(coverage.covered.includes(EXEMPT), false, 'and the trigger leaves it out (DB-28)');
    const known = new Set(coverage.columns.map((name) => name.toLowerCase()));
    assert.deepEqual(coverage.covered.filter((name) => !known.has(name)), [], 'the trigger names no column the table lacks');
    assert.equal(coverage.covered.length, coverage.columns.length - 1, 'every column but updated_at, each once');
  } finally {
    raw.close();
    ctx.db.close();
  }
});

test('[ST-15] the coverage check is not vacuous: a column added without updating the trigger is reported, by name', (t) => {
  const ctx = setup(scratch);
  const raw = rawConnection(ctx.path);
  try {
    const before = versionStepCoverage(raw);
    assert.deepEqual(before.uncovered, []);

    raw.exec('ALTER TABLE envelopes ADD COLUMN st15_probe TEXT');
    const probed = versionStepCoverage(raw);
    t.diagnostic(`after ADD COLUMN st15_probe: uncovered = ${JSON.stringify(probed.uncovered)}`);
    assert.deepEqual(probed.uncovered, ['st15_probe'], 'exactly the probe column is uncovered');
    assert.deepEqual(probed.covered, before.covered, 'the trigger itself is unchanged');
    assert.throws(() => assertCovered(probed), (error) => error instanceof assert.AssertionError && /uncovered: st15_probe\./.test(error.message), 'ST-15 fails naming it');

    raw.exec('ALTER TABLE envelopes ADD COLUMN st15_probe_second INTEGER');
    const twice = versionStepCoverage(raw);
    t.diagnostic(`after ADD COLUMN st15_probe_second: uncovered = ${JSON.stringify(twice.uncovered)}`);
    assert.deepEqual(twice.uncovered, ['st15_probe', 'st15_probe_second'], 'every uncovered column is reported');
    assert.throws(() => assertCovered(twice), /uncovered: st15_probe, st15_probe_second\./, 'and named');

    // The coverage is read from the trigger as stored: a trigger that drops one comparison leaves that column uncovered.
    const original = raw.prepare("SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = 'envelopes_version_step'").get().sql;
    const narrowed = original.replace(/\n\s*OR NEW\.created_at IS NOT OLD\.created_at/, '');
    assert.notEqual(narrowed, original, 'the created_at comparison was removed');
    raw.exec(`DROP TRIGGER envelopes_version_step; ${narrowed};`);
    const narrowedCoverage = versionStepCoverage(raw);
    t.diagnostic(`with created_at removed from the trigger: uncovered = ${JSON.stringify(narrowedCoverage.uncovered)}`);
    assert.deepEqual(narrowedCoverage.uncovered, ['created_at', 'st15_probe', 'st15_probe_second'], 'in table column order');
  } finally {
    raw.close();
    ctx.db.close();
  }
});
