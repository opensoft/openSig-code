// SPDX-License-Identifier: Apache-2.0
//
// The version-step trigger names the envelope columns it covers (T007; A-010
// IDEMP-N4; data-model.md § Transitions and races, item 1, migration rule).
// Any migration that adds an envelopes column must update that trigger in the
// same migration. ST-15 reads the trigger as stored, derives the columns it
// compares, and fails naming every column of PRAGMA table_info(envelopes) it
// leaves uncovered, other than updated_at.
//
// A-010 I1: that syntactic check counts a dead-branch comparison such as
// `OR (0 AND NEW.c IS NOT OLD.c)` as covered, so ST-15 also checks the
// behaviour. For every column of PRAGMA table_info(envelopes) except
// updated_at, a raw UPDATE that changes only that column, to a type-valid new
// value, without the +1 version step is refused and leaves the row unchanged:
// on the full schema (by any guard), and with the other update guards (0010's
// state graph and frozen columns, 0015's fixed key) removed on a savepoint, by
// the version-step trigger itself, whose message is asserted, while the same
// change with the step passes.

import assert from 'node:assert/strict';
import { isDeepStrictEqual } from 'node:util';
import { after, test } from 'node:test';

import { createTenant, envelopeRow, hex, makeScratch, rawConnection, setup, sid, ts } from './support.mjs';

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

/** The version-step trigger's own refusal (0010). */
const VERSION_STEP_MESSAGE = 'envelopes version must be old + 1 on every change of state or content';
/** SQLite's extended result code for a RAISE(ABORT) in a trigger. */
const SQLITE_CONSTRAINT_TRIGGER = 1811;

function thrown(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  return undefined;
}

function quoted(name) {
  return `"${name.replaceAll('"', '""')}"`;
}

function insertRaw(raw, table, values) {
  const columns = Object.keys(values);
  raw.prepare(`INSERT INTO ${quoted(table)} (${columns.map(quoted).join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`).run(...columns.map((name) => values[name]));
}

function envelopeOf(raw, tenant, id) {
  const row = raw.prepare('SELECT * FROM envelopes WHERE tenant_id = ? AND id = ?').get(tenant, id);
  return row === undefined ? undefined : { ...row };
}

/** A draft envelope at version 1, plus what the column's new value must reference. */
function seedFor(raw, tenant, column) {
  const id = sid('st15-env');
  insertRaw(raw, 'envelopes', { tenant_id: tenant, ...envelopeRow(id) });
  const refs = {};
  if (column === 'base_revision_id') {
    refs.revision = sid('st15-rev');
    const digest = hex(`st15-document-${refs.revision}`);
    insertRaw(raw, 'document_revisions', {
      tenant_id: tenant,
      id: refs.revision,
      envelope_id: id,
      content_digest: digest,
      blob_ref: `tenants/${tenant}/sha256/${digest}`,
      bytes: 2048,
      pages: 1,
      page_geometry_json: '[{"number":1,"width":612,"height":792,"rotate":0}]',
      parse_report_json: '{"pages":1}',
      created_at: ts(1),
    });
  }
  if (column === 'reissue_of' || column === 'reissued_as') {
    refs.sibling = sid('st15-sibling');
    insertRaw(raw, 'envelopes', { tenant_id: tenant, ...envelopeRow(refs.sibling) });
  }
  return { id, refs };
}

/**
 * A type-valid new value for one envelopes column of a draft envelope at
 * version 1: it satisfies the column's type, its CHECKs and its foreign keys,
 * so only a guard on the change itself can refuse it. The columns come from
 * PRAGMA table_info; one with no value here is reported by name, so a column
 * added later cannot be skipped. approvals_complete is bound to state by a
 * CHECK, so no update can change it alone; its case runs with CHECKs ignored on
 * the isolated connection (`checks: false`).
 */
function newValue(column, row, refs, otherTenant) {
  switch (column) {
    case 'tenant_id':
      return { value: otherTenant };
    case 'id':
      return { value: sid('st15-renamed') };
    case 'source_app':
      return { value: row.source_app === 'hermes' ? 'manual' : 'hermes' };
    case 'source_record':
      return { value: `${row.source_record}-changed` };
    case 'source_version':
      return { value: `${row.source_version}-changed` };
    case 'state':
      return { value: 'voided' }; // draft -> voided: in the graph, and valid with approvals_complete 0
    case 'version':
      return { value: row.version + 2, stepped: row.version + 1 }; // any change of the version but the +1 step
    case 'created_by_kind':
      return { value: row.created_by_kind === 'service' ? 'human-operator' : 'service' };
    case 'created_by_ref':
      return { value: `${row.created_by_ref}-changed` };
    case 'expires_at':
      return { value: ts(14 * 24 * 60) };
    case 'recipients_count':
      return { value: row.recipients_count === 2 ? 1 : 2 };
    case 'base_revision_id':
      return { value: refs.revision };
    case 'manifest_digest':
      return { value: hex('st15-manifest') };
    case 'recipients_digest':
      return { value: hex('st15-recipients') };
    case 'approvals_complete':
      return { value: row.approvals_complete === 1 ? 0 : 1, checks: false };
    case 'reissue_of':
      return { value: refs.sibling };
    case 'reissued_as':
      return { value: refs.sibling };
    case 'created_at':
      return { value: ts(0) }; // earlier, so expires_at > created_at and updated_at >= created_at still hold
    default:
      return undefined;
  }
}

/**
 * For every envelopes column of PRAGMA table_info except updated_at, a fresh
 * draft envelope gets a raw UPDATE that changes only that column without the
 * version step. Everything runs on a savepoint that is rolled back. Returns one
 * entry per column the check finds unguarded:
 * - full schema (isolated false): the update was accepted, or the row changed;
 * - isolated: the 0010 state-graph and frozen-column triggers and the 0015
 *   key-fixed trigger are dropped on the savepoint, so the update must be
 *   refused by the version-step trigger with its message, and the same change
 *   with the +1 step must pass.
 * `extra` supplies values for columns this test does not know (probe columns).
 */
function behaviouralGaps(raw, { tenant, otherTenant, isolated, extra = {} }) {
  const columns = raw
    .prepare('SELECT name FROM pragma_table_info(?) ORDER BY cid')
    .all('envelopes')
    .map((row) => row.name)
    .filter((name) => name.toLowerCase() !== EXEMPT);
  const gaps = [];
  raw.exec('SAVEPOINT st15_behaviour');
  try {
    // envelopes_key_fixed (0015) refuses a change of the key before any AFTER trigger runs; absent before 0015.
    if (isolated) raw.exec('DROP TRIGGER envelopes_state_graph; DROP TRIGGER envelopes_frozen_columns; DROP TRIGGER IF EXISTS envelopes_key_fixed;');
    for (const column of columns) {
      const { id, refs } = seedFor(raw, tenant, column);
      const before = envelopeOf(raw, tenant, id);
      const change = Object.hasOwn(extra, column) ? { value: extra[column] } : newValue(column, before, refs, otherTenant);
      if (change === undefined || change.value === undefined) {
        gaps.push(`${column}: no type-valid value in ST-15; add one`);
        continue;
      }
      const ignoreChecks = isolated && change.checks === false;
      if (ignoreChecks) raw.exec('PRAGMA ignore_check_constraints = ON');
      try {
        const error = thrown(() => raw.prepare(`UPDATE envelopes SET ${quoted(column)} = ? WHERE tenant_id = ? AND id = ?`).run(change.value, tenant, id));
        const after = envelopeOf(raw, tenant, id);
        if (error === undefined) {
          gaps.push(`${column}: accepted`);
          continue;
        }
        if (!isDeepStrictEqual(after, before)) {
          gaps.push(`${column}: refused, but the row changed`);
          continue;
        }
        if (!isolated) continue;
        if (error.errcode !== SQLITE_CONSTRAINT_TRIGGER || !String(error.message).includes(VERSION_STEP_MESSAGE)) {
          gaps.push(`${column}: refused by another guard (${error.errcode} ${error.message})`);
          continue;
        }
        const stepped = column === 'version' ? `${quoted(column)} = ?` : `${quoted(column)} = ?, version = version + 1`;
        const control = thrown(() =>
          raw.prepare(`UPDATE envelopes SET ${stepped} WHERE tenant_id = ? AND id = ?`).run(change.stepped ?? change.value, tenant, id),
        );
        if (control !== undefined) gaps.push(`${column}: the same change with the +1 step was refused too (${control.errcode} ${control.message})`);
      } finally {
        if (ignoreChecks) raw.exec('PRAGMA ignore_check_constraints = OFF');
      }
    }
  } finally {
    raw.exec('ROLLBACK TO st15_behaviour; RELEASE st15_behaviour;');
  }
  return gaps;
}

/** Fail, naming every column whose single-column, no-step update is not refused. */
function assertBehaviourallyGuarded(gaps, how) {
  assert.deepEqual(gaps, [], `${how}: an update changing only these envelopes columns without the version step is not refused: ${gaps.join('; ')}`);
}

/** The version-step trigger with one column's comparison turned into a dead branch: `(0 AND NEW.c IS NOT OLD.c)`. */
function deadBranch(sql, column) {
  let replaced = 0;
  const comparison = new RegExp(String.raw`\bNEW\.${column}\s+IS\s+NOT\s+OLD\.${column}\b(?!\s*[-+*/%|&<>=])`, 'g');
  const mutated = sql.replace(comparison, (match) => {
    replaced += 1;
    return `(0 AND ${match})`;
  });
  assert.equal(replaced, 1, `${TRIGGER} compares ${column} exactly once`);
  return mutated;
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

test('[ST-15] behaviourally, an update that changes only one envelopes column without the version step is refused for every column but updated_at, by the version-step trigger itself', (t) => {
  const ctx = setup(scratch);
  const raw = rawConnection(ctx.path);
  try {
    const otherTenant = sid('st15-tenant');
    createTenant(ctx.db, otherTenant);
    const columns = raw.prepare('SELECT name FROM pragma_table_info(?) ORDER BY cid').all('envelopes').map((row) => row.name);
    t.diagnostic(`columns checked: ${columns.filter((name) => name !== EXEMPT).join(', ')}`);
    assert.ok(columns.length > 1 && columns.includes(EXEMPT));
    assertBehaviourallyGuarded(behaviouralGaps(raw, { tenant: ctx.tenant, otherTenant, isolated: false }), 'full schema');
    assertBehaviourallyGuarded(behaviouralGaps(raw, { tenant: ctx.tenant, otherTenant, isolated: true }), `${TRIGGER} alone`);
    assert.deepEqual(
      raw.prepare("SELECT name FROM sqlite_schema WHERE type = 'trigger' AND tbl_name = 'envelopes' AND name IN ('envelopes_state_graph', 'envelopes_frozen_columns') ORDER BY name").all().map((row) => row.name),
      ['envelopes_frozen_columns', 'envelopes_state_graph'],
      'the isolated check removed the other guards only on its rolled-back savepoint',
    );
  } finally {
    raw.close();
    ctx.db.close();
  }
});

test('[ST-15] the behavioural check is not vacuous: a dead-branch comparison of any one column is caught for exactly that column, which the syntactic check misses', (t) => {
  const ctx = setup(scratch);
  const raw = rawConnection(ctx.path);
  try {
    const otherTenant = sid('st15-tenant');
    createTenant(ctx.db, otherTenant);
    const original = raw.prepare("SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?").get(TRIGGER).sql;
    const columns = raw.prepare('SELECT name FROM pragma_table_info(?) ORDER BY cid').all('envelopes').map((row) => row.name).filter((name) => name !== EXEMPT);
    const caught = [];
    for (const column of columns) {
      raw.exec('BEGIN');
      try {
        raw.exec(`DROP TRIGGER ${TRIGGER}; ${deadBranch(original, column)};`);
        assert.deepEqual(versionStepCoverage(raw).uncovered, [], `${column}: the syntactic check counts the dead branch as covered`);
        const gaps = behaviouralGaps(raw, { tenant: ctx.tenant, otherTenant, isolated: true });
        assert.deepEqual(gaps, [`${column}: accepted`], `${column}: the behavioural check reports exactly this column`);
        caught.push(column);
      } finally {
        raw.exec('ROLLBACK');
      }
    }
    t.diagnostic(`dead branch caught for exactly its column: ${caught.length} of ${columns.length} (${caught.join(', ')})`);
    assert.deepEqual(caught, columns);
    assert.equal(raw.prepare("SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?").get(TRIGGER).sql, original, 'every mutant was rolled back');
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
    // The behavioural check reports it too: by name when it has no value for it, and as accepted when given one.
    const otherTenant = sid('st15-tenant');
    createTenant(ctx.db, otherTenant);
    assert.deepEqual(behaviouralGaps(raw, { tenant: ctx.tenant, otherTenant, isolated: true }), ['st15_probe: no type-valid value in ST-15; add one']);
    const probeGaps = behaviouralGaps(raw, { tenant: ctx.tenant, otherTenant, isolated: true, extra: { st15_probe: 'probe-value' } });
    t.diagnostic(`behavioural check after ADD COLUMN st15_probe: ${JSON.stringify(probeGaps)}`);
    assert.deepEqual(probeGaps, ['st15_probe: accepted']);

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
