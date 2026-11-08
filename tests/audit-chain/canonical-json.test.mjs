// SPDX-License-Identifier: Apache-2.0
//
// RFC 8785 (JCS) vector cases for the single canonical JSON module (T029).
// The vectors are written from the RFC's own examples and rules: the
// section 3.2.4 example, the section 3.2.3 sorting example, the Appendix B
// number table (IEEE 754 bit patterns), and the string escaping rules of
// section 3.2.2.2. Nothing is downloaded.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  CanonicalJsonError,
  canonicalBytes,
  canonicalDigest,
  canonicalize,
  MAX_DEPTH,
  parseJson,
  serializeNumber,
} from '../../src/domain/canonical/index.ts';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const refuses = (fn, label) => assert.throws(fn, CanonicalJsonError, label);

function doubleFromBits(hex) {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt(`0x${hex}`));
  return view.getFloat64(0);
}

test('[JCS-01] the RFC 8785 section 3.2.4 example and the section 3.2.3 sorting example canonicalize exactly', () => {
  const input = [
    '{',
    '  "numbers": [333333333.33333329, 1E30, 4.50,',
    '              2e-3, 0.000000000000000000000000001],',
    '  "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",',
    '  "literals": [null, true, false]',
    '}',
  ].join('\n');
  const expected = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';
  const value = parseJson(input);
  assert.equal(canonicalize(value), expected);
  const bytes = canonicalBytes(value);
  assert.deepEqual(bytes, Buffer.from(expected, 'utf8'));
  assert.deepEqual([...bytes.subarray(bytes.indexOf(0xe2), bytes.indexOf(0xe2) + 3)], [0xe2, 0x82, 0xac], '€ is UTF-8 encoded, not escaped');
  assert.equal(canonicalDigest(value), createHash('sha256').update(bytes).digest('hex'));

  const sorting = parseJson(
    [
      '{',
      '  "\\u20ac": "Euro Sign",',
      '  "\\r": "Carriage Return",',
      '  "\\ufb33": "Hebrew Letter Dalet With Dagesh",',
      '  "1": "One",',
      '  "\\ud83d\\ude00": "Emoji: Grinning Face",',
      '  "\\u0080": "Control",',
      '  "\\u00f6": "Latin Small Letter O With Diaeresis"',
      '}',
    ].join('\n'),
  );
  // Read the member order from the canonical text itself (a JS object would
  // list the integer-like name "1" first).
  const sortedText = canonicalize(sorting);
  const order = Object.values(sorting).sort((a, b) => sortedText.indexOf(a) - sortedText.indexOf(b));
  assert.deepEqual(order, [
    'Carriage Return',
    'One',
    'Control',
    'Latin Small Letter O With Diaeresis',
    'Euro Sign',
    'Emoji: Grinning Face',
    'Hebrew Letter Dalet With Dagesh',
  ]);
  assert.ok(canonicalize(sorting).startsWith('{"\\r":"Carriage Return","1":"One","\u0080":"Control"'));
  assert.equal(canonicalize({ b: 1, a: { d: [], c: {} } }), '{"a":{"c":{},"d":[]},"b":1}');
});

test('[JCS-02] numbers follow the ECMAScript serialization of the RFC 8785 Appendix B table', () => {
  const table = [
    ['0000000000000000', '0'],
    ['8000000000000000', '0'],
    ['0000000000000001', '5e-324'],
    ['8000000000000001', '-5e-324'],
    ['7fefffffffffffff', '1.7976931348623157e+308'],
    ['ffefffffffffffff', '-1.7976931348623157e+308'],
    ['4340000000000000', '9007199254740992'],
    ['c340000000000000', '-9007199254740992'],
    ['4430000000000000', '295147905179352830000'],
    ['44b52d02c7e14af5', '9.999999999999997e+22'],
    ['44b52d02c7e14af6', '1e+23'],
    ['44b52d02c7e14af7', '1.0000000000000001e+23'],
    ['444b1ae4d6e2ef4e', '999999999999999700000'],
    ['444b1ae4d6e2ef4f', '999999999999999900000'],
    ['444b1ae4d6e2ef50', '1e+21'],
    ['3eb0c6f7a0b5ed8c', '9.999999999999997e-7'],
    ['3eb0c6f7a0b5ed8d', '0.000001'],
    ['41b3de4355555553', '333333333.3333332'],
    ['41b3de4355555554', '333333333.33333325'],
    ['41b3de4355555555', '333333333.3333333'],
    ['41b3de4355555556', '333333333.3333334'],
    ['41b3de4355555557', '333333333.33333343'],
    ['becbf647612f3696', '-0.0000033333333333333333'],
    ['43143ff3c1cb0959', '1424953923781206.2'],
  ];
  for (const [bits, expected] of table) {
    const value = doubleFromBits(bits);
    assert.equal(serializeNumber(value), expected, bits);
    assert.equal(canonicalize([value]), `[${expected}]`, bits);
  }
  for (const bits of ['7fffffffffffffff', '7ff0000000000000', 'fff0000000000000']) {
    refuses(() => canonicalize(doubleFromBits(bits)), `${bits} (NaN or Infinity)`);
  }
  assert.equal(canonicalize(parseJson('[-0, 0.0, 1.0, 100, 1e2, 0.1e1, 12345678901234567890]')), '[0,0,1,100,100,1,12345678901234567000]');
});

test('[JCS-03] strings escape exactly the RFC 8785 set, keep other characters literal, and refuse lone surrogates', () => {
  const named = { 0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f', 0x0d: '\\r' };
  for (let code = 0; code < 0x20; code += 1) {
    const expected = named[code] ?? `\\u${code.toString(16).padStart(4, '0')}`;
    assert.equal(canonicalize(String.fromCharCode(code)), `"${expected}"`, `U+${code.toString(16)}`);
  }
  assert.equal(canonicalize('"\\'), '"\\"\\\\"');
  for (const literal of ['/', '\u007f', '\u0080', 'é', ' ', ' ', '﻿', '￿', '\u{1f600}', '\u{10ffff}', "'<>&"]) {
    assert.equal(canonicalize(literal), `"${literal}"`, `literal ${JSON.stringify(literal)}`);
  }
  assert.deepEqual(canonicalBytes('\u{1f600}'), Buffer.from([0x22, 0xf0, 0x9f, 0x98, 0x80, 0x22]));
  for (const lone of ['\ud800', '\udfff', 'a\ud83d', '\ude00\ud83d', '\ud83dx']) {
    refuses(() => canonicalize(lone), `lone surrogate ${JSON.stringify(lone)}`);
    refuses(() => canonicalize({ [lone]: 1 }), 'lone surrogate in a member name');
  }
  // Member names are compared as UTF-16 code units, not code points.
  assert.equal(canonicalize({ 'דּ': 1, '\u{1f600}': 2 }), '{"\u{1f600}":2,"דּ":1}');
  assert.equal(canonicalize({ aa: 1, a: 2, B: 3, '': 4 }), '{"":4,"B":3,"a":2,"aa":1}');
});

test('[JCS-04] values outside the JSON data model are refused, never dropped or converted', () => {
  class Envelope {
    constructor() {
      this.id = 'x';
    }
  }
  const cyclic = { a: 1 };
  cyclic.self = cyclic;
  const sparse = [1, , 3]; // eslint-disable-line no-sparse-arrays
  const extra = [1, 2];
  extra.note = 'x';
  const accessor = Object.defineProperty({}, 'computed', { get: () => 1, enumerable: true });
  const hidden = Object.defineProperty({ a: 1 }, 'hidden', { value: 2, enumerable: false });
  let deep = 'leaf';
  for (let i = 0; i <= MAX_DEPTH; i += 1) deep = [deep];
  const cases = [
    ['undefined', undefined],
    ['undefined member', { a: undefined }],
    ['undefined element', [undefined]],
    ['function', () => 1],
    ['symbol', Symbol('s')],
    ['bigint', 10n],
    ['NaN member', { n: Number.NaN }],
    ['Date', new Date(0)],
    ['Map', new Map()],
    ['class instance', new Envelope()],
    ['typed array', new Uint8Array(2)],
    ['symbol key', { [Symbol('k')]: 1 }],
    ['accessor', accessor],
    ['non-enumerable member', hidden],
    ['sparse array', sparse],
    ['array with extra property', extra],
    ['cycle', cyclic],
    ['too deep', deep],
  ];
  for (const [label, value] of cases) refuses(() => canonicalize(value), label);

  const nullPrototype = Object.assign(Object.create(null), { b: 2, a: 1 });
  assert.equal(canonicalize(nullPrototype), '{"a":1,"b":2}');
  assert.equal(canonicalize(Object.freeze({ list: Object.freeze([true, null]) })), '{"list":[true,null]}');
  const shared = { s: 1 };
  assert.equal(canonicalize({ x: shared, y: shared }), '{"x":{"s":1},"y":{"s":1}}', 'a repeated reference is not a cycle');
});

test('[JCS-05] the strict parser refuses duplicates, lone surrogates, non-double numbers and malformed text', () => {
  const text = '{ "b" : [ 1 , 2.5e0 , "x" ] , "a" : { "__proto__" : { "p" : true } } }';
  const value = parseJson(text);
  assert.equal(Object.getPrototypeOf(value.a), Object.prototype, '__proto__ is an own member, not a prototype change');
  assert.deepEqual(Object.keys(value.a), ['__proto__']);
  const canonical = canonicalize(value);
  assert.equal(canonical, '{"a":{"__proto__":{"p":true}},"b":[1,2.5,"x"]}');
  assert.equal(canonicalize(parseJson(canonical)), canonical, 'canonicalization is idempotent');

  const bad = [
    ['duplicate member', '{"a":1,"a":2}'],
    ['duplicate after unescaping', '{"a":1,"\\u0061":2}'],
    ['lone high surrogate escape', '"\\ud800"'],
    ['lone low surrogate escape', '["\\udc00"]'],
    ['number overflow', '1e400'],
    ['negative overflow', '-1e400'],
    ['byte order mark', '﻿{}'],
    ['trailing comma', '[1,]'],
    ['leading zero', '01'],
    ['bare fraction', '.5'],
    ['unescaped control', '"a\u0001b"'],
    ['single quotes', "{'a':1}"],
    ['invalid escape', '"\\x41"'],
    ['short unicode escape', '"\\u12"'],
    ['trailing content', '{} {}'],
    ['empty text', ''],
    ['NaN literal', 'NaN'],
    ['comment', '[1 /* c */]'],
  ];
  for (const [label, input] of bad) refuses(() => parseJson(input), label);
  assert.deepEqual(parseJson(' \t\r\n[\n true , false , null ]\n'), [true, false, null]);
  assert.equal(parseJson('"\\ud83d\\ude00"'), '\u{1f600}');
  assert.equal(parseJson('-0'), -0);
  refuses(() => parseJson(42), 'non-string input');
});

function sourceFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(path));
    else if (/\.(?:ts|mts|mjs|js)$/.test(entry.name)) out.push(path);
  }
  return out;
}

test('[JCS-06] src/ has exactly one canonicalizer and exactly one importer of the restricted audit writer', () => {
  const files = sourceFiles(join(REPO_ROOT, 'src')).map((path) => ({ rel: relative(REPO_ROOT, path), text: readFileSync(path, 'utf8') }));
  const definition = /\b(?:function|const|let|var|class)\s+(?:\w*[Cc]anonical(?:i[sz]e|Json|JSON|Bytes|Digest|Form)?\w*|\w*[Jj]cs\w*)\b/;
  const outside = files.filter((file) => !file.rel.startsWith('src/domain/canonical/') && definition.test(file.text));
  assert.deepEqual(outside.map((file) => file.rel), [], 'no canonicalizer is defined outside src/domain/canonical/');

  const canonicalImports = files
    .filter((file) => file.rel.startsWith('src/domain/canonical/'))
    .flatMap((file) => [...file.text.matchAll(/from\s+'([^']+)'/g)].map((match) => match[1]));
  assert.ok(canonicalImports.length > 0);
  for (const specifier of canonicalImports) {
    assert.ok(specifier.startsWith('node:') || /^\.\/[a-z-]+\.ts$/.test(specifier), `canonical module import ${specifier} stays self-contained`);
  }

  const restricted = files.filter((file) => /from\s+'[^']*restricted-writer\.ts'/.test(file.text)).map((file) => file.rel);
  assert.deepEqual(restricted, ['src/storage/audit/writer.ts'], 'only the audit writer uses the restricted write path');
  const users = files.filter((file) => /\bcanonical(?:Digest|Bytes|ize)\b/.test(file.text) && !file.rel.startsWith('src/domain/canonical/'));
  for (const file of users) {
    assert.match(file.text, /from\s+'[./]*domain\/canonical\/index\.ts'/, `${file.rel} imports the canonical module`);
  }
});
