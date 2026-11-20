// SPDX-License-Identifier: Apache-2.0
//
// Field placement at prepare (T007 follow-up; A-010 requests #46, #49 and #53, row
// T036-RESIDUAL (6)); extra case ID ST-18. Prepare refuses, with 422
// field_out_of_bounds and detail field_too_small naming the field, a field the
// composer could not place: placeField({ rotate, box: centipointBox(media_box) },
// rect) === null over the STORED page geometry (the revision's parse summary),
// never the PDF and never the stored width and height. The check is part of
// prepare's field validation, before any write, so a refusal writes nothing and
// records no idempotency response. Request #53: a missing stored page list, or a
// stored page that disagrees with the stored displayed geometry in number, rotation
// or displayed size, is a broken invariant (500 internal, logged), with a case per
// kind; width and height only detect it.
//
// The two halves of the agreement. This file proves that prepare refuses exactly
// when T036's exported placeField, over the stored MediaBox and rotation, returns
// null, and that the domain calls that very function (no local copy). CP-03
// (tests/compose/residual.test.mjs, T036) proves through the parse service that
// the composer refuses exactly those fields with field_too_small, so prepare and
// composition apply one rule.
//
// Hand-computed rounding in the case tables is written out independently of the
// module under test; each table row also asserts that T036's own function gives
// the verdict the row states, so a table that stopped meaning what it says fails
// rather than passes. Every value is synthetic.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { httpErrorOf } from '../../../src/api/envelopes/request.ts';
import { placeField } from '../../../src/cryptograph/compose/appearance.ts';
import { centipointBox } from '../../../src/cryptograph/compose/bounds.ts';
import { EnvelopeError, EnvelopeService } from '../../../src/domain/envelopes/index.ts';
import { HttpError } from '../../../src/server/types.ts';
import { StorageUsageError } from '../../../src/storage/db/index.ts';
import { createInput, documentWithBoxes, fieldsFor, HUMAN, makeScratch, rejectsWith, req, setup } from './support.mjs';

const scratch = makeScratch();
after(() => scratch.cleanup());

const DAY = 24 * 60 * 60 * 1000;

/** The composer's verdict for `rect` on a page of `mediaBox` turned by `rotate`: T036's own exports. */
const composerPlaces = (rotate, mediaBox, rect) => placeField({ rotate, box: centipointBox(mediaBox) }, rect) !== null;

/** The verdict a page would get from its displayed width and height instead (the request #49 hazard). */
function placesByWidthAndHeight(rotate, page, rect) {
  const upright = rotate % 180 === 0;
  const box = [0, 0, upright ? page.width : page.height, upright ? page.height : page.width];
  return placeField({ rotate, box: centipointBox(box) }, rect) !== null;
}

function count(ctx, table, where = {}) {
  return ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).count(table, where));
}

function row(ctx, table, where) {
  return ctx.db.transaction(() => ctx.db.forTenant(ctx.tenant).get(table, where));
}

/** A draft with an uploaded document of the given page boxes: { id, version, document }. */
function draftWith(ctx, boxes, recipients = 1) {
  const created = ctx.service.create(req(ctx.tenant), createInput(recipients)).body;
  const document = documentWithBoxes(boxes);
  const uploaded = ctx.service.uploadDocument(req(ctx.tenant), created.id, created.version, document).body;
  return { id: created.id, version: uploaded.version, document };
}

const field = (key, rect, overrides = {}) => ({ key, recipient_ordinal: 1, page: 1, type: 'signature', rect, ...overrides });

/**
 * Assert the contract refusal for a field the composer could not place: 422
 * field_out_of_bounds with one detail naming it, which T034's handlers turn into the
 * contract Error unchanged.
 */
function assertTooSmall(error, index = 0) {
  const details = [{ field: `fields[${index}].rect`, code: 'field_too_small' }];
  assert.equal(error.code, 'field_out_of_bounds');
  assert.equal(error.status, 422);
  assert.deepEqual(error.details, details);
  const http = httpErrorOf(error);
  assert.ok(http instanceof HttpError, 'the handlers answer it as a contract Error');
  assert.deepEqual([http.status, http.code, http.details], [422, 'field_out_of_bounds', details]);
}

/** Assert the draft is exactly as it was: draft, same version, nothing frozen or defined. */
function assertUntouched(ctx, draft) {
  const envelope = row(ctx, 'envelopes', { id: draft.id });
  assert.deepEqual([envelope.state, envelope.version, envelope.manifest_digest, envelope.recipients_digest], ['draft', draft.version, null, null]);
  assert.equal(row(ctx, 'document_revisions', { envelope_id: draft.id }).frozen_at, null, 'the revision is not frozen');
  assert.equal(count(ctx, 'field_definitions', { envelope_id: draft.id }), 0, 'no field definition');
  assert.equal(count(ctx, 'field_manifests', { envelope_id: draft.id }), 0, 'no field manifest');
}

// A tall page, 100 x 1000 points: 10,000 x 100,000 centipoints. Upright (0, 180) it
// shows 10,000 across and 100,000 down; turned (90, 270) 100,000 across and 10,000
// down. Each rect starts at the displayed edge, so its rounded side is
// round(fraction x shown side): 1.0 centipoint is just placeable and 0.4 rounds to
// nothing. Turned a quarter, a side that was the long one becomes the short one, so
// a just-placeable rect on the long side and a too-small rect on the short side flip
// their verdict (`flips`); the other two rows keep theirs. Each rotation has one
// flipping row of each verdict, so a check that ignores the rotation fails both ways.
const TALL = Object.freeze([0, 0, 100, 1000]);
const WIDE = Object.freeze({ x: 0.1, y: 0.1, width: 0.5, height: 0.2 });
const SMALL = Object.freeze({ x: 0, y: 0.25, width: 0.4 / 10_000, height: 0.5 });
const JUST = Object.freeze({ x: 0, y: 0.25, width: 1 / 10_000, height: 0.5 });

const ROTATION_CASES = [
  // [rotate, label, rect, placeable, flips]
  ...[0, 180].flatMap((rotate) => [
    [rotate, 'one centipoint across', JUST, true, false],
    [rotate, '0.4 centipoint across', SMALL, false, true],
    [rotate, 'one centipoint down', { x: 0.25, y: 0, width: 0.5, height: 1 / 100_000 }, true, true],
    [rotate, '0.4 centipoint down', { x: 0.25, y: 0, width: 0.5, height: 0.4 / 100_000 }, false, false],
  ]),
  ...[90, 270].flatMap((rotate) => [
    [rotate, 'one centipoint across', { x: 0, y: 0.25, width: 1 / 100_000, height: 0.5 }, true, true],
    [rotate, '0.4 centipoint across', { x: 0, y: 0.25, width: 0.4 / 100_000, height: 0.5 }, false, false],
    [rotate, 'one centipoint down', { x: 0.25, y: 0, width: 0.5, height: 1 / 10_000 }, true, false],
    [rotate, '0.4 centipoint down', { x: 0.25, y: 0, width: 0.5, height: 0.4 / 10_000 }, false, true],
  ]),
];

test('[ST-18] prepare allows a field just placeable and refuses one just too small, with 422 field_out_of_bounds and detail field_too_small, on pages rotated 0, 90, 180 and 270', () => {
  const ctx = setup(scratch);
  try {
    for (const [rotate, label, rect, placeable, flips] of ROTATION_CASES) {
      const what = `rotate ${rotate}, ${label}`;
      assert.equal(composerPlaces(rotate, TALL, rect), placeable, `${what}: the table states the composer's verdict`);
      assert.equal(composerPlaces((rotate + 90) % 360, TALL, rect), flips ? !placeable : placeable, `${what}: and states whether a quarter turn flips it`);
      const draft = draftWith(ctx, [{ rotate, media_box: TALL }]);
      const body = { expected_version: draft.version, fields: [field('sig_1', rect)] };
      if (placeable) {
        const prepared = ctx.service.prepare(req(ctx.tenant), draft.id, body).body;
        assert.equal(prepared.state, 'prepared', what);
        assert.deepEqual(prepared.fields[0].rect, rect, `${what}: the rect is frozen as given`);
      } else {
        assertTooSmall(rejectsWith(() => ctx.service.prepare(req(ctx.tenant), draft.id, body), 'field_out_of_bounds', 422));
        assertUntouched(ctx, draft);
      }
    }
  } finally {
    ctx.db.close();
  }
});

// The stored MediaBox decides (request #49). [0.006, 0, 100.004, 50] has corners at 1
// and 10,000 centipoints, a side of 9,999, while its displayed width, 100.004 - 0.006 =
// 99.998 points, rounds to 10,000. Across 9,999, x = 0.500045 and x + width = 0.500055
// both round to 5,000 (nothing left); across 10,000 they round to 5,000 and 5,001. With
// x = 0.499995 it is the reverse: 4,999 and 5,000 across 9,999, both 5,000 across 10,000.
const SKEWED = Object.freeze([0.006, 0, 100.004, 50]);
const SKEWED_TURNED = Object.freeze([0, 0.006, 50, 100.004]);
const BY_BOX_REFUSED = Object.freeze({ x: 0.500045, y: 0.25, width: 0.00001, height: 0.5 });
const BY_BOX_PLACED = Object.freeze({ x: 0.499995, y: 0.25, width: 0.00001, height: 0.5 });

test('[ST-18] the stored media_box decides, not the stored width and height: where the two round to different sides, prepare follows centipointBox(media_box) both ways', () => {
  const ctx = setup(scratch);
  try {
    for (const [rotate, box] of [[0, SKEWED], [90, SKEWED_TURNED]]) {
      for (const [rect, placeable] of [[BY_BOX_REFUSED, false], [BY_BOX_PLACED, true]]) {
        const draft = draftWith(ctx, [{ rotate, media_box: box }]);
        const page = draft.document.pages[0];
        const what = `rotate ${rotate}, x = ${rect.x}`;
        assert.equal(composerPlaces(rotate, box, rect), placeable, `${what}: the MediaBox verdict`);
        assert.equal(placesByWidthAndHeight(rotate, page, rect), !placeable, `${what}: the width-and-height verdict is the opposite`);
        const body = { expected_version: draft.version, fields: [field('sig_1', rect)] };
        if (placeable) {
          assert.equal(ctx.service.prepare(req(ctx.tenant), draft.id, body).body.state, 'prepared', what);
        } else {
          assertTooSmall(rejectsWith(() => ctx.service.prepare(req(ctx.tenant), draft.id, body), 'field_out_of_bounds', 422));
          assertUntouched(ctx, draft);
        }
      }
    }
  } finally {
    ctx.db.close();
  }
});

/** A service on the same database whose stores log, in order, every write and read, and whose hook logs each change. */
function spied(ctx) {
  const log = [];
  const writes = new Set(['insert', 'update', 'compareAndSet', 'delete']);
  const reads = new Set(['get', 'list', 'iterate', 'count']);
  const db = {
    transaction: (fn) => ctx.db.transaction(fn),
    forTenant: (tenantId) =>
      new Proxy(ctx.db.forTenant(tenantId), {
        get(target, property) {
          const value = Reflect.get(target, property, target);
          if (typeof value !== 'function') return value;
          return (...args) => {
            if (writes.has(property)) log.push(`${String(property)}:${args[0]}`);
            else if (reads.has(property)) log.push(`read:${args[0]}`);
            return value.apply(target, args);
          };
        },
      }),
  };
  const service = new EnvelopeService({ db, clock: ctx.time.clock, onChange: (change) => log.push(`change:${change.operation}`) });
  return {
    service,
    log,
    writes: () => log.filter((entry) => !entry.startsWith('read:')),
    reads: () => log.filter((entry) => entry.startsWith('read:')),
  };
}

test('[ST-18] a refused prepare writes nothing before or after the check: no field definition, manifest, freeze, state or version change, change event or idempotency record', () => {
  const ctx = setup(scratch);
  try {
    const draft = draftWith(ctx, [{ rotate: 0, media_box: TALL }]);
    const spy = spied(ctx);
    // The too-small field comes second, after a valid one, so writing the first before judging the second would show.
    const refused = { expected_version: draft.version, fields: [field('sig_1', WIDE), field('sig_2', SMALL)] };
    const key = 'st18-refused-000000001';
    assertTooSmall(rejectsWith(() => spy.service.prepare(req(ctx.tenant, HUMAN, { key, request: refused }), draft.id, refused), 'field_out_of_bounds', 422), 1);
    assert.deepEqual(spy.writes(), [], 'no write and no change, even one rolled back');
    assert.equal(spy.reads()[0], 'read:idempotency_records', 'the key and its record are looked up first');
    assert.ok(spy.reads().includes('read:document_revisions'), 'the stored revision was read');
    assertUntouched(ctx, draft);
    assert.equal(count(ctx, 'idempotency_records'), 0, 'no idempotency record');

    // The same spy sees every write of a successful prepare, in the existing order: fields,
    // manifest, freeze, compare-and-set, the change, and the idempotency record last.
    spy.log.length = 0;
    const fixed = { expected_version: draft.version, fields: [field('sig_1', WIDE), field('sig_2', JUST)] };
    spy.service.prepare(req(ctx.tenant, HUMAN, { key: 'st18-control-000000001', request: fixed }), draft.id, fixed);
    assert.deepEqual(spy.writes(), [
      'insert:field_definitions',
      'insert:field_definitions',
      'insert:field_manifests',
      'update:document_revisions',
      'compareAndSet:envelopes',
      'change:prepare',
      'insert:idempotency_records',
    ]);
  } finally {
    ctx.db.close();
  }
});

test('[ST-18] the receipt: a refused prepare records no response, so the same key and body is refused again identically and the key stays fresh; a recorded key resolves before any field rule', () => {
  const ctx = setup(scratch);
  try {
    const draft = draftWith(ctx, [{ rotate: 0, media_box: TALL }]);
    const key = 'st18-receipt-000000001';
    const refused = { expected_version: draft.version, fields: [field('sig_1', SMALL)] };
    const attempt = (body) => ctx.service.prepare(req(ctx.tenant, HUMAN, { key, request: body }), draft.id, body);
    const first = rejectsWith(() => attempt(refused), 'field_out_of_bounds', 422);
    assertTooSmall(first);
    assert.equal(count(ctx, 'idempotency_records'), 0, 'a refusal records no response');
    const again = rejectsWith(() => attempt(refused), 'field_out_of_bounds', 422);
    assert.deepEqual([again.status, again.details], [first.status, first.details], 'the retry runs again and is refused again identically');
    assert.equal(count(ctx, 'idempotency_records'), 0);
    assertUntouched(ctx, draft);

    // Nothing was recorded, so the same key with a corrected body is a new request, not a conflict.
    const fixed = { expected_version: draft.version, fields: [field('sig_1', JUST)] };
    const prepared = attempt(fixed);
    assert.deepEqual([prepared.status, prepared.replayed, prepared.body.state], [200, false, 'prepared']);
    assert.equal(count(ctx, 'idempotency_records'), 1);

    // Once recorded, the key resolves before the field rules: a changed body holding a
    // too-small field is idempotency_conflict, never field_too_small, and the recorded
    // body replays byte for byte with no second mutation.
    rejectsWith(() => attempt(refused), 'idempotency_conflict', 409);
    const replay = attempt(fixed);
    assert.equal(replay.replayed, true);
    assert.deepEqual(replay.bytes, prepared.bytes);
    assert.equal(ctx.service.read(req(ctx.tenant), draft.id).version, prepared.body.version, 'no second mutation');
  } finally {
    ctx.db.close();
  }
});

test('[ST-18] first refusal: field_too_small follows the expiry, state, version and shape rules and its field\'s page_out_of_range and outside_page; fields go in request order; the per-recipient signature rule comes last', () => {
  const ctx = setup(scratch);
  try {
    const draft = draftWith(ctx, [{ rotate: 0, media_box: TALL }], 2);
    const second = (rect, overrides = {}) => field('sig_2', rect, { recipient_ordinal: 2, ...overrides });
    const cases = [
      ['the first field too small, the second on a missing page', [field('sig_1', SMALL), second(WIDE, { page: 2 })], 'field_out_of_bounds', 422, [{ field: 'fields[0].rect', code: 'field_too_small' }]],
      ['a too-small rect on a missing page', [field('sig_1', SMALL, { page: 2 }), second(WIDE)], 'field_out_of_bounds', 422, [{ field: 'fields[0].page', code: 'page_out_of_range' }]],
      ['a too-small width past the page edge', [field('sig_1', { x: 0.99999, y: 0.25, width: 0.4 / 10_000, height: 0.5 }), second(WIDE)], 'field_out_of_bounds', 422, [{ field: 'fields[0].rect', code: 'outside_page' }]],
      ['a width of zero', [field('sig_1', { ...SMALL, width: 0 }), second(WIDE)], 'invalid_request', 400, [{ field: 'fields[0].rect', code: 'empty_rect' }]],
      ['a too-small rect with an unknown type', [field('sig_1', SMALL, { type: 'initials' }), second(WIDE)], 'invalid_request', 400, [{ field: 'fields[0].type', code: 'invalid_enum' }]],
      ['recipient 2 without a signature field and a too-small date', [field('sig_1', WIDE), field('date_1', SMALL, { type: 'date' })], 'field_out_of_bounds', 422, [{ field: 'fields[1].rect', code: 'field_too_small' }]],
    ];
    for (const [label, fields, code, status, details] of cases) {
      const error = rejectsWith(() => ctx.service.prepare(req(ctx.tenant), draft.id, { expected_version: draft.version, fields }), code, status);
      assert.deepEqual(error.details, details, label);
    }
    rejectsWith(() => ctx.service.prepare(req(ctx.tenant), draft.id, { expected_version: draft.version - 1, fields: [field('sig_1', SMALL), second(WIDE)] }), 'version_conflict', 409);
    assertUntouched(ctx, draft);

    // Expiry is judged before the fields: the envelope expires and the request is refused as expired.
    ctx.time.advance(8 * DAY);
    rejectsWith(() => ctx.service.prepare(req(ctx.tenant), draft.id, { expected_version: draft.version, fields: [field('sig_1', SMALL), second(WIDE)] }), 'state_conflict', 409);
    assert.equal(row(ctx, 'envelopes', { id: draft.id }).state, 'expired');
  } finally {
    ctx.db.close();
  }
});

// The agreement table: pages of three MediaBoxes (letter at the origin, letter off the
// origin with negative corners, and the skewed box), each at every rotation, and rects
// from comfortably inside to below a centipoint, including the two the MediaBox and the
// width round differently.
const BOXES = [[0, 0, 612, 792], [-30.25, 10.5, 581.75, 802.5], SKEWED];
const RECTS = [
  { x: 0, y: 0, width: 1, height: 1 },
  { x: 0.1, y: 0.8, width: 0.3, height: 0.08 },
  { x: 0.5, y: 0.6, width: 0.000001, height: 0.05 },
  { x: 0, y: 0.9, width: 0.999999, height: 0.000001 },
  { x: 0.25, y: 0.25, width: 1 / 61_200, height: 0.5 },
  { x: 0.999, y: 0.999, width: 0.001, height: 0.001 },
  BY_BOX_REFUSED,
  BY_BOX_PLACED,
];

test('[ST-18] agreement: over a table of rects on every rotation of three MediaBoxes, prepare refuses with field_too_small exactly when placeField over centipointBox(media_box) returns null', () => {
  const ctx = setup(scratch);
  try {
    const verdicts = new Set();
    for (const box of BOXES) {
      for (const rotate of [0, 90, 180, 270]) {
        const draft = draftWith(ctx, [{ rotate, media_box: box }]);
        const placed = [];
        RECTS.forEach((rect, index) => {
          const placeable = composerPlaces(rotate, box, rect);
          verdicts.add(`${rotate}:${placeable}`);
          if (placeable) {
            placed.push(field(`f_${index}`, rect));
            return;
          }
          const body = { expected_version: draft.version, fields: [field(`f_${index}`, rect)] };
          assertTooSmall(rejectsWith(() => ctx.service.prepare(req(ctx.tenant), draft.id, body), 'field_out_of_bounds', 422));
        });
        assertUntouched(ctx, draft);
        const prepared = ctx.service.prepare(req(ctx.tenant), draft.id, { expected_version: draft.version, fields: placed }).body;
        assert.equal(prepared.state, 'prepared', `box ${JSON.stringify(box)}, rotate ${rotate}: every placeable rect is accepted`);
        assert.equal(prepared.fields.length, placed.length);
      }
    }
    for (const rotate of [0, 90, 180, 270]) {
      assert.ok(verdicts.has(`${rotate}:true`) && verdicts.has(`${rotate}:false`), `rotate ${rotate}: the table holds both verdicts`);
    }
  } finally {
    ctx.db.close();
  }
});

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const strip = (text) => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');

/** The relative value imports of a source file (type-only imports are erased and skipped). */
function valueImports(file) {
  const text = strip(readFileSync(file, 'utf8'));
  const found = [];
  for (const match of text.matchAll(/^import\s+(?!type\s)[\s\S]*?\sfrom\s+'([^']+)';/gm)) found.push(match[1]);
  for (const match of text.matchAll(/^import\s+'([^']+)';/gm)) found.push(match[1]);
  return found;
}

test('[ST-18] one rule: the envelope domain calls the composer\'s own placeField over centipointBox(media_box), imported from appearance.ts and bounds.ts only, with no local copy, and the closure never reaches the parse service', () => {
  const domain = join(ROOT, 'src/domain/envelopes');
  const sources = Object.fromEntries(
    readdirSync(domain)
      .filter((name) => name.endsWith('.ts'))
      .map((name) => [name, strip(readFileSync(join(domain, name), 'utf8'))]),
  );
  const placement = sources['placement.ts'];
  assert.ok(placement !== undefined, 'placement.ts holds the check');
  assert.match(placement, /^import \{ placeField \} from '\.\.\/\.\.\/cryptograph\/compose\/appearance\.ts';$/m);
  assert.match(placement, /^import \{ centipointBox \} from '\.\.\/\.\.\/cryptograph\/compose\/bounds\.ts';$/m);
  assert.match(placement, /placeField\(\{ rotate: page\.rotate, box: centipointBox\(page\.media_box\) \}, rect\)/, 'the composer\'s call over the stored MediaBox and rotation');
  assert.match(sources['validation.ts'] ?? '', /if \(!placeable\(stored, \{ x, y, width, height \}\)\)/, 'checkFields applies it to every field');
  assert.match(sources['service.ts'] ?? '', /const pages = storedPageGeometry\(revision\);/, 'prepare reads the stored geometry');
  for (const [name, text] of Object.entries(sources)) {
    assert.doesNotMatch(text, /\b(?:function|const|let|var)\s+(?:placeField|centipointBox)\b/, `${name}: no local copy of the rule`);
    assert.doesNotMatch(text, /Math\.round\(/, `${name}: no placement arithmetic of its own`);
    assert.doesNotMatch(text, /from '[^']*cryptograph\/compose(?:\/index\.ts)?'/, `${name}: never the compose index`);
    if (name !== 'placement.ts') assert.doesNotMatch(text, /from '[^']*cryptograph\//, `${name}: placement.ts is the domain's only import from src/cryptograph/`);
  }

  // The runtime closure of placement.ts outside the envelope domain (request #49 N3).
  const seen = new Set();
  const bare = [];
  const walk = (file) => {
    if (seen.has(file)) return;
    seen.add(file);
    for (const specifier of valueImports(file)) {
      if (specifier.startsWith('.')) walk(resolve(dirname(file), specifier));
      else bare.push(`${relative(ROOT, file)} -> ${specifier}`);
    }
  };
  walk(join(domain, 'placement.ts'));
  const outside = [...seen].map((file) => relative(ROOT, file).split('\\').join('/')).filter((path) => !path.startsWith('src/domain/envelopes/')).sort();
  assert.deepEqual(
    outside,
    ['src/cryptograph/compose/appearance.ts', 'src/cryptograph/compose/bounds.ts', 'src/cryptograph/compose/errors.ts', 'src/cryptograph/compose/syntax.ts', 'src/domain/approval/winansi.ts'],
    'five pure modules, none of them the parse service, the compose index, the composer or CMS',
  );
  assert.deepEqual(bare, [], 'no built-in or package import in the closure');
});

// The consistency check (request #53). The stored report's page list must agree with the
// stored displayed geometry in number, rotation and displayed size, the size being the
// MediaBox's width and height under the rotation, exactly (the composer's report.ts rule).
// One case or more per kind; each is a StorageUsageError, which T034's handlers pass on
// unchanged, so T031's server answers 500 internal and logs handler_exception.
const LETTER = Object.freeze([{ rotate: 0, media_box: [0, 0, 612, 792] }]);
const LETTER_TURNED = Object.freeze([{ rotate: 90, media_box: [0, 0, 792, 612] }]);
const SANDBOX = 'netns+fs-enforced (local)';
const pagesOf = (document, map) => ({ ...document, parseReport: { ...document.parseReport, pages: map(document.parseReport.pages) } });
const eachPage = (patch) => (document) => pagesOf(document, (pages) => pages.map((page) => ({ ...page, ...patch })));
const BROKEN = [
  // [kind, label, boxes, alter, message]
  ['missing page list', 'a page count instead of the list (the fixtures\' shape before request #53)', LETTER, (document) => ({ ...document, parseReport: { pages: 1, network_sandbox: SANDBOX } }), /holds no page list/],
  ['missing page list', 'no pages member at all', LETTER, (document) => ({ ...document, parseReport: { network_sandbox: SANDBOX } }), /holds no page list/],
  ['number', 'one page too few', LETTER, (document) => pagesOf(document, () => []), /in number of pages/],
  ['number', 'a page numbered out of its place', LETTER, eachPage({ number: 2 }), /page 1 disagrees with the stored geometry in number$/],
  ['rotation', 'an upright page reported half-turned', LETTER, eachPage({ rotate: 180 }), /page 1 disagrees with the stored geometry in rotation/],
  ['rotation', 'a quarter-turned page reported upright', LETTER_TURNED, eachPage({ rotate: 0 }), /page 1 disagrees with the stored geometry in rotation/],
  ['displayed size', 'the report page\'s width differs', LETTER, eachPage({ width: 613 }), /page 1 disagrees with the stored geometry in displayed size/],
  ['displayed size', 'an upright page with the quarter-turned box', LETTER, eachPage({ media_box: [0, 0, 792, 612], crop_box: [0, 0, 792, 612] }), /displayed size/],
  ['displayed size', 'a quarter-turned page with the upright box', LETTER_TURNED, eachPage({ media_box: [0, 0, 612, 792], crop_box: [0, 0, 612, 792] }), /displayed size/],
  ['displayed size', 'a box a hundredth of a point too wide (no tolerance)', LETTER, eachPage({ media_box: [0, 0, 612.01, 792], crop_box: [0, 0, 612.01, 792] }), /displayed size/],
  ['box', 'no media_box', LETTER, (document) => pagesOf(document, (pages) => pages.map(({ media_box: _box, ...rest }) => rest)), /page 1 holds no usable media_box/],
  ['box', 'a corner that is not a number', LETTER, eachPage({ media_box: [0, 0, null, 792] }), /page 1 holds no usable media_box/],
  ['box', 'an inverted box', LETTER, eachPage({ media_box: [612, 0, 0, 792] }), /page 1 holds no usable media_box/],
];

test('[ST-18] a missing or inconsistent stored page list is a broken invariant, one case per kind: 500 internal through the server, logged, nothing written, and never a fallback to the width and height', () => {
  const ctx = setup(scratch);
  try {
    const kinds = new Set();
    for (const [kind, label, boxes, alter, message] of BROKEN) {
      kinds.add(kind);
      const created = ctx.service.create(req(ctx.tenant), createInput(1)).body;
      const uploaded = ctx.service.uploadDocument(req(ctx.tenant), created.id, created.version, alter(documentWithBoxes(boxes))).body;
      let caught;
      try {
        ctx.service.prepare(req(ctx.tenant), created.id, { expected_version: uploaded.version, fields: fieldsFor(1) });
      } catch (error) {
        caught = error;
      }
      assert.ok(caught instanceof StorageUsageError, `${kind}, ${label}: a broken invariant, got ${caught}`);
      assert.ok(!(caught instanceof EnvelopeError), `${kind}, ${label}: not a refusal of the request`);
      assert.match(caught.message, message, `${kind}, ${label}`);
      assert.equal(httpErrorOf(caught), caught, `${kind}, ${label}: the handlers pass it to the server unchanged (500 internal, handler_exception)`);
      assertUntouched(ctx, { id: created.id, version: uploaded.version });
    }
    assert.deepEqual([...kinds].sort(), ['box', 'displayed size', 'missing page list', 'number', 'rotation'], 'every kind has a case');

    // Control: the page lists the owners' fixtures and T034's upload store are consistent,
    // including the quarter turns and a MediaBox off the origin (rotated-pages.pdf page 5).
    const draft = draftWith(ctx, [
      { rotate: 0, media_box: [0, 0, 612, 792] },
      { rotate: 90, media_box: [0, 0, 792, 612] },
      { rotate: 270, media_box: [36, 36, 648, 828] },
      { rotate: 180, media_box: [0, 0, 612, 792] },
    ]);
    const fields = [1, 2, 3, 4].map((page) => field(`sig_${page}`, WIDE, { page }));
    assert.equal(ctx.service.prepare(req(ctx.tenant), draft.id, { expected_version: draft.version, fields }).body.state, 'prepared');
  } finally {
    ctx.db.close();
  }
});
