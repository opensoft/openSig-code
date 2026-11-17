// SPDX-License-Identifier: Apache-2.0
//
// T010 field values at the server boundary (A-010 S5, contract 0.2.3; AP-01, AP-08):
// - AP-01: integer stroke coordinates and the 15,000-point approval budget. The worst case
//   within the schema (15,000 points at the widest coordinates, 20 values, the longest keys,
//   typed texts of 80 characters each written as six-byte \uXXXX escapes) is sent through the
//   real server as compact JSON: it fits the 256 KiB JSON limit and is accepted. 15,001 points
//   (still under the limit) is 400 invalid_request; the same schema-maximal body with typed
//   texts of 80 characters outside the BMP (twelve-byte surrogate-pair escapes) still fits and
//   is decided by the approval (422), never by the limit; only a body padded past 256 KiB is
//   413. Fractional, negative, too large, string, boolean and null coordinates are 400.
// - AP-08: the stroke, point, value, text and count caps; WinAnsiEncoding (422
//   unsupported_characters, decided after every 400 rule); matching the recipient's frozen
//   fields; and the server-filled UTC date.
// Every refusal records nothing. Everything is synthetic (see support.mjs).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { JSON_BODY_LIMIT } from '../../src/server/config.ts';
import {
  GUARD_TOUCH,
  approvalBody,
  assertError,
  contractErrors,
  createWorld,
  envelopeRow,
  openSession,
  postApproval,
  sentEnvelope,
} from './support.mjs';

/** Twenty field keys of the longest allowed length (40), in sorting order. */
const KEYS = Object.freeze(Array.from({ length: 20 }, (_, index) => `k${String(index).padStart(2, '0')}${'x'.repeat(37)}`));

/** Twenty signature fields for recipient 1, all inside page 1. */
const TWENTY_FIELDS = Object.freeze(
  KEYS.map((key, index) => ({
    key,
    recipient_ordinal: 1,
    page: 1,
    type: 'signature',
    rect: { x: 0.02 + (index % 4) * 0.24, y: 0.02 + Math.floor(index / 4) * 0.18, width: 0.2, height: 0.1 },
  })),
);

/** `count` points at the widest coordinates, split into `strokes` strokes as evenly as allowed. */
function strokesOf(count, strokes) {
  const out = [];
  const base = Math.floor(count / strokes);
  let extra = count % strokes;
  for (let index = 0; index < strokes; index += 1) {
    const length = base + (extra > 0 ? 1 : 0);
    if (extra > 0) extra -= 1;
    out.push(Array.from({ length }, () => [10000, 10000]));
  }
  return out;
}

/** Compact JSON with every character outside ASCII written as a \uXXXX escape (six bytes per UTF-16 unit). */
function escapedJson(value) {
  return JSON.stringify(value).replace(/[\u0080-￿]/g, (unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function pointsOf(fieldValues) {
  return fieldValues.filter((value) => value.mode === 'drawn').reduce((sum, value) => sum + value.strokes.reduce((n, stroke) => n + stroke.length, 0), 0);
}

/**
 * The schema-maximal body for the twenty-field envelope: two drawn values of 10,000 and
 * `secondPoints` points (50 strokes each) and eighteen typed values of 80 copies of `glyph`.
 */
function maximalBody(state, glyph, secondPoints = 5000) {
  const fieldValues = KEYS.map((key, index) => {
    if (index === 0) return { key, type: 'signature', mode: 'drawn', strokes: strokesOf(10_000, 50) };
    if (index === 1) return { key, type: 'signature', mode: 'drawn', strokes: strokesOf(secondPoints, 50) };
    return { key, type: 'signature', mode: 'typed', text: glyph.repeat(80) };
  });
  return approvalBody(state, { overrides: { field_values: fieldValues } });
}

async function twentyFieldSession(world) {
  const { envelope, token } = await sentEnvelope(world, { fields: TWENTY_FIELDS });
  return { envelope, session: await openSession(world, token) };
}

test('[AP-01] the worst-case approval within the schema fits the 256 KiB JSON limit and is accepted; 15,001 points is 400; coordinates must be integers in 0..10000', async () => {
  const world = await createWorld();
  try {
    // 1. The worst case is accepted, end to end.
    const accepted = await twentyFieldSession(world);
    const worst = maximalBody(accepted.session.state, '€');
    assert.equal(worst.field_values.length, 20, 'twenty values');
    assert.equal(pointsOf(worst.field_values), 15_000, 'exactly the 15,000-point budget');
    assert.deepEqual(contractErrors('Approval', worst), [], 'the worst case is a contract Approval');
    const worstText = escapedJson(worst);
    const worstBytes = Buffer.byteLength(worstText, 'utf8');
    assert.ok(worstBytes <= JSON_BODY_LIMIT, `the worst case fits the limit (${worstBytes} of ${JSON_BODY_LIMIT} bytes)`);
    assert.ok(worstBytes > 200 * 1024, `the worst case is near the limit (${worstBytes} bytes)`);
    assert.ok(worstText.includes('\\u20ac'), 'premise: the typed texts are sent as six-byte escapes');
    const response = await postApproval(world, accepted.session, worstText);
    assert.equal(response.status, 200, `the worst case is accepted: ${response.status} ${response.json?.code ?? ''}`);
    assert.deepEqual(contractErrors('ApprovalReceipt', response.json), [], 'a contract receipt');
    assert.equal(response.json.envelope_state, 'finalizing');
    const [stored] = world.rows('approvals', 'WHERE envelope_id = ?', [accepted.envelope.id]);
    const values = JSON.parse(stored.field_values_json);
    assert.equal(values.length, 20, 'all twenty values are stored');
    assert.equal(pointsOf(values), 15_000, 'every point is stored');
    assert.equal(values[2].text, '€'.repeat(80), 'the escaped text is stored as its characters');

    // 2. One point more is 400 invalid_request, though the body is still under the limit.
    const over = await twentyFieldSession(world);
    const overBody = maximalBody(over.session.state, '€', 5001);
    assert.equal(pointsOf(overBody.field_values), 15_001);
    const overText = escapedJson(overBody);
    assert.ok(Buffer.byteLength(overText, 'utf8') <= JSON_BODY_LIMIT, 'premise: 15,001 points is still under the limit');
    let before = world.snapshot(GUARD_TOUCH);
    const refused = await postApproval(world, over.session, overText);
    assertError(refused, 400, 'invalid_request', '15,001 points');
    assert.deepEqual(refused.json.details, [{ field: 'field_values', code: 'point_budget' }], 'the detail names the budget');
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');

    // 3. The schema-maximal body with twelve-byte escapes still fits: the approval decides it (422).
    const astral = maximalBody(over.session.state, '\u{1F600}');
    assert.deepEqual(contractErrors('Approval', astral), [], 'premise: 80 code points outside the BMP are within the schema');
    const astralText = escapedJson(astral);
    const astralBytes = Buffer.byteLength(astralText, 'utf8');
    assert.ok(astralBytes <= JSON_BODY_LIMIT, `the schema-maximal body fits the limit (${astralBytes} bytes)`);
    assertError(await postApproval(world, over.session, astralText), 422, 'unsupported_characters', 'typed text outside WinAnsiEncoding');

    // 4. Only a body past 256 KiB is 413.
    const padded = worstText + ' '.repeat(JSON_BODY_LIMIT + 1 - worstBytes);
    assert.equal(Buffer.byteLength(padded, 'utf8'), JSON_BODY_LIMIT + 1);
    assertError(await postApproval(world, over.session, padded), 413, 'payload_too_large', 'a body one byte past the limit');
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');

    // 5. Coordinates are JSON integers in 0..10000.
    const { session } = await (async () => {
      const sent = await sentEnvelope(world);
      return { session: await openSession(world, sent.token) };
    })();
    before = world.snapshot(GUARD_TOUCH);
    for (const [label, bad] of [
      ['a fraction', 5000.5],
      ['a small fraction', 1.000001],
      ['a numeric string', '5000'],
      ['a negative number', -1],
      ['one past the maximum', 10001],
      ['a boolean', true],
      ['null', null],
    ]) {
      const body = approvalBody(session.state, { drawn: true });
      const signature = body.field_values.find((value) => value.type === 'signature');
      signature.strokes = [[[0, 0], [bad, 0], [10000, 10000]]];
      const response = await postApproval(world, session, body);
      assertError(response, 400, 'invalid_request', `coordinate: ${label}`);
      assert.equal(response.json.details?.[0]?.code, 'invalid_coordinate', `coordinate: ${label}: the detail code`);
      assert.match(String(response.json.details?.[0]?.field), /^field_values\[\d\]\.strokes\[0\]\[1\]$/, `coordinate: ${label}: the detail names the point`);
    }
    for (const [label, point] of [
      ['three numbers', [1, 2, 3]],
      ['one number', [1]],
      ['an object', { x: 1, y: 2 }],
    ]) {
      const body = approvalBody(session.state, { drawn: true });
      body.field_values.find((value) => value.type === 'signature').strokes = [[[0, 0], point]];
      assertError(await postApproval(world, session, body), 400, 'invalid_request', `point: ${label}`);
    }
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');
    const edges = approvalBody(session.state, { drawn: true });
    edges.field_values.find((value) => value.type === 'signature').strokes = [[[0, 0], [10000, 0], [0, 10000], [10000, 10000]]];
    assert.equal((await postApproval(world, session, edges)).status, 200, 'the edges 0 and 10000 are accepted');
  } finally {
    await world.close();
  }
});

test('[AP-08] stroke, point, text and count caps are 400; text outside WinAnsiEncoding is 422 after every 400 rule; values must match the recipient’s fields; the date is filled by the server in UTC', async () => {
  const world = await createWorld();
  try {
    const { envelope, token } = await sentEnvelope(world);
    const session = await openSession(world, token);
    const state = session.state;
    const signatureKey = state.fields.find((field) => field.type === 'signature').key;
    const dateKey = state.fields.find((field) => field.type === 'date').key;
    const withSignature = (value) => approvalBody(state, { overrides: { field_values: [{ key: dateKey, type: 'date' }, { key: signatureKey, type: 'signature', ...value }] } });
    const drawn = (strokes) => withSignature({ mode: 'drawn', strokes });
    const typed = (text) => withSignature({ mode: 'typed', text });
    const line = (n) => Array.from({ length: n }, (_, index) => [index % 10001, 0]);

    const before = world.snapshot(GUARD_TOUCH);
    const refusals = [
      ['51 strokes', drawn(Array.from({ length: 51 }, () => line(2))), 'stroke_count'],
      ['no stroke', drawn([]), 'stroke_count'],
      ['a stroke of 1,001 points', drawn([line(1001)]), 'point_count'],
      ['a stroke of one point', drawn([line(1)]), 'point_count'],
      ['10,002 points in one value', drawn([...Array.from({ length: 10 }, () => line(1000)), line(2)]), 'value_point_count'],
      ['a typed text of 81 characters', typed('A'.repeat(81)), 'invalid_length'],
      ['81 characters outside the BMP', typed('\u{1F600}'.repeat(81)), 'invalid_length'],
      ['an empty typed text', typed(''), 'invalid_length'],
      ['a typed text that is not a string', withSignature({ mode: 'typed', text: 42 }), 'invalid_string'],
      ['an unknown mode', withSignature({ mode: 'image', strokes: [line(2)] }), 'invalid_enum'],
      ['a drawn value with a text member', withSignature({ mode: 'drawn', strokes: [line(2)], text: 'A' }), 'unknown_property'],
      ['a date with a client value', approvalBody(state, { overrides: { field_values: [{ key: dateKey, type: 'date', value: '2026-01-01' }, { key: signatureKey, type: 'signature', mode: 'typed', text: 'A' }] } }), 'unknown_property'],
      ['21 values', approvalBody(state, { overrides: { field_values: Array.from({ length: 21 }, (_, index) => ({ key: `extra_${index}`, type: 'date' })) } }), 'invalid_count'],
      ['no values', approvalBody(state, { overrides: { field_values: [] } }), 'invalid_count'],
      ['a duplicate key', approvalBody(state, { overrides: { field_values: [{ key: dateKey, type: 'date' }, { key: dateKey, type: 'date' }] } }), 'duplicate_key'],
      ['a key outside the pattern', approvalBody(state, { overrides: { field_values: [{ key: 'Sig 1', type: 'date' }] } }), 'invalid_key'],
      ['an unknown member', { ...approvalBody(state), extra: true }, 'unknown_property'],
      ['JSON that does not parse', '{"expected_version":', 'invalid_type'],
      ['a body that is no object', '42', 'invalid_type'],
      ['expected_version zero', approvalBody(state, { overrides: { expected_version: 0 } }), 'invalid_integer'],
      ['expected_version as a string', approvalBody(state, { overrides: { expected_version: String(state.envelope_version) } }), 'invalid_integer'],
      ['an uppercase digest', approvalBody(state, { overrides: { document_digest: state.document.digest.toUpperCase() } }), 'invalid_digest'],
      // 400 is decided before 422: a text outside WinAnsiEncoding beside a shape violation.
      ['a non-WinAnsi text beside a bad coordinate', approvalBody(state, { overrides: { field_values: [{ key: signatureKey, type: 'signature', mode: 'typed', text: 'Ā' }, { key: 'extra', type: 'signature', mode: 'drawn', strokes: [[[0, 0], [0.5, 0]]] }] } }), 'invalid_coordinate'],
    ];
    for (const [label, body, code] of refusals) {
      const response = await postApproval(world, session, body);
      assertError(response, 400, 'invalid_request', label);
      assert.equal(response.json.details?.[0]?.code, code, `${label}: detail code`);
    }

    // WinAnsiEncoding: 422 unsupported_characters, naming the member, never the text.
    for (const [label, text] of [
      ['Latin Extended-A (U+0100)', 'Synthetic Ā'],
      ['a C0 control (U+0007)', 'Synthetic \u0007'],
      ['a C1 control (U+0081)', 'Synthetic \u0081'],
      ['a lone surrogate', 'Synthetic \ud800'],
      ['a character outside the BMP', 'Synthetic \u{1F600}'],
      ['CJK', 'Synthetic 中'],
      ['a combining mark (U+0301)', 'Synthetic é'],
    ]) {
      const response = await postApproval(world, session, escapedJson(typed(text)));
      assertError(response, 422, 'unsupported_characters', label);
      assert.equal(response.json.details?.[0]?.code, 'unsupported_characters');
      assert.match(String(response.json.details?.[0]?.field), /^field_values\[\d\]\.text$/, `${label}: the detail names the member`);
      assert.ok(!response.text.includes('Synthetic'), `${label}: the refusal does not echo the text`);
    }

    // Matching the recipient's frozen fields: exactly one value per field, of its type.
    for (const [label, fieldValues, code] of [
      ['an unknown field', [{ key: dateKey, type: 'date' }, { key: signatureKey, type: 'signature', mode: 'typed', text: 'A' }, { key: 'sig_9', type: 'date' }], 'unknown_field'],
      ['a signature value for the date field', [{ key: dateKey, type: 'signature', mode: 'typed', text: 'A' }, { key: signatureKey, type: 'signature', mode: 'typed', text: 'A' }], 'type_mismatch'],
      ['a date value for the signature field', [{ key: dateKey, type: 'date' }, { key: signatureKey, type: 'date' }], 'type_mismatch'],
      ['the date field missing', [{ key: signatureKey, type: 'signature', mode: 'typed', text: 'A' }], 'missing_field'],
      ['the signature field missing', [{ key: dateKey, type: 'date' }], 'missing_field'],
    ]) {
      const response = await postApproval(world, session, approvalBody(state, { overrides: { field_values: fieldValues } }));
      assertError(response, 400, 'invalid_request', label);
      assert.deepEqual(response.json.details, [{ field: 'field_values', code }], `${label}: detail`);
    }
    assert.deepEqual(world.snapshot(GUARD_TOUCH), before, 'nothing is recorded');

    // Every WinAnsiEncoding range is accepted (printable ASCII, Latin-1 and the 27 code points of
    // 0x80..0x9F), and the server fills the date from its own UTC clock: one millisecond before
    // midnight UTC is still that day.
    world.time.set(Date.UTC(2026, 10, 9, 23, 59, 59, 999));
    const late = await sentEnvelope(world);
    const lateSession = await openSession(world, late.token);
    const text = 'Synthetic ~  éÿ €ŒŸ™Ž';
    const accepted = await postApproval(world, lateSession, escapedJson(approvalBody(lateSession.state, { text })));
    assert.equal(accepted.status, 200, `every WinAnsiEncoding range is accepted: ${accepted.status} ${accepted.json?.code ?? ''}`);
    assert.deepEqual(accepted.json.date_values, [{ key: dateKey, value: '2026-11-09' }], 'the date is the server’s UTC date');
    assert.equal(accepted.json.server_time, '2026-11-09T23:59:59.999Z');
    const [stored] = world.rows('approvals', 'WHERE envelope_id = ?', [late.envelope.id]);
    assert.ok(JSON.parse(stored.field_values_json).some((value) => value.text === text), 'the typed text is stored exactly');
    assert.ok(JSON.parse(stored.field_values_json).some((value) => value.key === dateKey && value.type === 'date' && Object.keys(value).length === 2), 'the date value carries no client value');
    world.time.set(Date.UTC(2026, 10, 10, 0, 0, 0, 0));
    const next = await sentEnvelope(world);
    const nextSession = await openSession(world, next.token);
    const nextDay = await postApproval(world, nextSession, approvalBody(nextSession.state));
    assert.equal(nextDay.status, 200);
    assert.deepEqual(nextDay.json.date_values, [{ key: dateKey, value: '2026-11-10' }], 'midnight UTC is the next day');
    assert.equal(envelopeRow(world, envelope.id).state, 'sent', 'the first envelope, whose requests were all refused, is untouched');
  } finally {
    await world.close();
  }
});
