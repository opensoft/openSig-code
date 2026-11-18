// SPDX-License-Identifier: Apache-2.0
//
// T039 deterministic ZIP writer: refusals and limits (plan.md § Case catalogs, ZIP:
// ZIP-05 and ZIP-06; extra case IDs, the frozen registry requires none). Names are flat
// ASCII, an empty list is refused, and ZIP64 is never written: a limit is an inclusive
// maximum (request #44), the defaults are the ZIP64 escape values minus one, and a limit
// can be lowered but never raised. Archives that are accepted are read back by the independent
// reader in ./reader.mjs. Non-ASCII and control characters are built with
// String.fromCharCode and String.fromCodePoint so no source file carries them.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { writeZip, ZIP_LIMITS, ZipError } from '../../src/artifacts/zip.ts';
import { bytesOf, readZip } from './reader.mjs';

const entry = (name, data = bytesOf('x')) => ({ name, data });

function assertRefusal(code, build, message) {
  assert.throws(
    build,
    (error) => {
      assert.ok(error instanceof ZipError, `${message}: a ZipError, not ${error?.constructor?.name}`);
      assert.equal(error.code, code, `${message}: the refusal code`);
      return true;
    },
    message,
  );
}

/** A byte array that claims `size` bytes without holding them; the writer must refuse it unread. */
function claiming(size) {
  const data = new Uint8Array(0);
  Object.defineProperty(data, 'byteLength', { value: size });
  Object.defineProperty(data, 'length', { value: size });
  return data;
}

/** Archive length for entries of the given name lengths and sizes: headers, names twice, data, end record. */
const archiveLength = (items) => items.reduce((sum, [nameLength, size]) => sum + 30 + 46 + 2 * nameLength + size, 22);

test('[ZIP-05] a name that is not flat ASCII is refused under its own code', () => {
  const refused = [
    ['', 'name-empty'],
    ['a'.repeat(256), 'name-too-long'],
    ['a'.repeat(1000), 'name-too-long'],
    ['.hidden', 'name-leading-dot'],
    ['.', 'name-leading-dot'],
    ['..', 'name-leading-dot'],
    ['...', 'name-leading-dot'],
    ['.a.b', 'name-leading-dot'],
    ['a/b', 'name-invalid'],
    ['/a', 'name-invalid'],
    ['a/', 'name-invalid'],
    ['dir/sub/file.txt', 'name-invalid'],
    ['../x', 'name-invalid'],
    ['./a', 'name-invalid'],
    ['a\\b', 'name-invalid'],
    ['C:x', 'name-invalid'],
    ['a b', 'name-invalid'],
    ['a\tb', 'name-invalid'],
    ['a\nb', 'name-invalid'],
    ['a.txt\n', 'name-invalid'],
    ['a*b', 'name-invalid'],
    ['a?b', 'name-invalid'],
    ["a'b", 'name-invalid'],
    ['a~b', 'name-invalid'],
    ['a@b', 'name-invalid'],
    ['a' + String.fromCharCode(0) + 'b', 'name-invalid'],
    ['a' + String.fromCharCode(0x7f), 'name-invalid'],
    ['caf' + String.fromCharCode(0xe9), 'name-invalid'],
    [String.fromCharCode(0xff41) + '.txt', 'name-invalid'],
    [String.fromCodePoint(0x1f4c4) + '.txt', 'name-invalid'],
    [String.fromCharCode(0xd800) + '.txt', 'name-invalid'],
    ['x' + String.fromCharCode(0xdc00), 'name-invalid'],
  ];
  for (const [name, code] of refused) {
    const shown = JSON.stringify(name.length > 24 ? `${name.slice(0, 8)}... (${name.length} characters)` : name);
    assertRefusal(code, () => writeZip([entry('ok.txt'), entry(name)]), `${shown} is ${code}`);
  }
});

test('[ZIP-05] flat ASCII names of letters, digits, ".", "_" and "-" are accepted, up to 255 characters', () => {
  const accepted = ['final.pdf', 'approval-manifest.json', 'a', 'A_b-c.d', 'x..y', 'a.', '0', '-', '_', '-a', '_x', 'a'.repeat(255)];
  for (const name of accepted) {
    const { entries } = readZip(writeZip([entry(name)]));
    assert.equal(entries.length, 1);
    assert.equal(entries[0].name, name);
  }
  const all = readZip(writeZip(accepted.map((name) => entry(name)))).entries;
  assert.equal(all.length, accepted.length);
});

test('[ZIP-05] two names equal when ASCII case is ignored are refused', () => {
  const data = bytesOf('same');
  assertRefusal('name-duplicate', () => writeZip([entry('a.txt', data), entry('a.txt', data)]), 'an exact duplicate with identical data');
  assertRefusal('name-duplicate', () => writeZip([entry('a.txt', bytesOf('one')), entry('a.txt', bytesOf('two'))]), 'an exact duplicate with different data');
  assertRefusal('name-duplicate', () => writeZip([entry('A.txt'), entry('a.TXT')]), 'a case-insensitive duplicate');
  assertRefusal('name-duplicate', () => writeZip([entry('a.txt'), entry('A.txt')]), 'a case-insensitive duplicate, either way round');
  assertRefusal(
    'name-duplicate',
    () => writeZip([entry('Final.PDF'), entry('b'), entry('c'), entry('d'), entry('final.pdf')]),
    'a case-insensitive duplicate at the ends of a longer list',
  );
  const { entries } = readZip(writeZip([entry('a.txt'), entry('a-txt'), entry('a_txt'), entry('a.txt2')]));
  assert.equal(entries.length, 4, 'names that differ by more than case are separate entries');
  assert.throws(
    () => writeZip([entry('distinctive-name.txt'), entry('distinctive-name.txt')]),
    (error) => error instanceof ZipError && error.code === 'name-duplicate' && !error.message.includes('distinctive-name'),
    'the message carries an index, never the name',
  );
});

test('[ZIP-05] an empty entry list is refused, and so is anything that is not a list of { name, data } entries', () => {
  assertRefusal('no-entries', () => writeZip([]), 'an empty list');
  for (const bad of [null, undefined, {}, 'a.txt', new Set([entry('a')])]) {
    assertRefusal('entries-invalid', () => writeZip(bad), `entries ${String(bad)}`);
  }
  const malformed = [
    [null],
    [undefined],
    [42],
    ['a.txt'],
    [{ name: 1, data: new Uint8Array(1) }],
    [{ data: new Uint8Array(1) }],
    [{ name: 'a' }],
    [{ name: 'a', data: 'text' }],
    [{ name: 'a', data: [1, 2, 3] }],
    [{ name: 'a', data: new ArrayBuffer(4) }],
    [{ name: 'a', data: new Uint16Array(2) }],
    [entry('fine'), null],
    // a hole in the middle of the array
    [entry('fine'), , entry('also-fine')],
  ];
  for (const [index, bad] of malformed.entries()) assertRefusal('entries-invalid', () => writeZip(bad), `malformed list ${index}`);
});

test('[ZIP-06] the defaults are the ZIP64 escape values minus one, each an inclusive maximum', () => {
  // The defaults accept 65,534 entries and 0xFFFFFFFE bytes; the escape values are one above.
  assert.deepEqual({ ...ZIP_LIMITS }, { entryCountLimit: 65534, entryBytesLimit: 4294967294, archiveBytesLimit: 4294967294 });
  assert.ok(Object.isFrozen(ZIP_LIMITS));
  assert.equal(ZIP_LIMITS.entryCountLimit + 1, 0xffff, 'the 16-bit escape value is one above the default');
  assert.equal(ZIP_LIMITS.entryBytesLimit + 1, 0xffffffff, 'the 32-bit escape value is one above the default');
  assert.equal(ZIP_LIMITS.archiveBytesLimit + 1, 0xffffffff);
});

test('[ZIP-06] at the default count limit 65534 entries are written and 65535 are refused, so no 16-bit escape value appears', () => {
  const empty = new Uint8Array(0);
  const make = (count) => Array.from({ length: count }, (_, index) => ({ name: `n${String(index).padStart(5, '0')}`, data: empty }));
  assertRefusal('too-many-entries', () => writeZip(make(65535)), '65535 entries, one above the limit');
  assertRefusal('too-many-entries', () => writeZip(make(70000)), '70000 entries');
  const archive = writeZip(make(65534));
  const { entries, end } = readZip(archive);
  assert.equal(entries.length, 65534);
  assert.equal(end.entriesTotal, 65534);
  assert.equal(end.entriesOnDisk, 65534);
  assert.notEqual(end.entriesTotal, 0xffff, 'the 16-bit escape value is never written');
  assert.equal(entries[0].name, 'n00000');
  assert.equal(entries[65533].name, 'n65533');
  assert.equal(archive.length, archiveLength(Array.from({ length: 65534 }, () => [6, 0])));
});

test('[ZIP-06] at the default size limits, a size one above a limit is refused before any byte is read', () => {
  // The inputs claim a size without holding it, so refusing them reads and allocates nothing.
  // The accepting side at these two limits is not exercised: an archive of 0xFFFFFFFE bytes
  // would be a 4 GiB buffer. The accept-at-the-limit and refuse-one-above cases for all three
  // limits are proved with lowered limits below.
  assertRefusal('entry-too-large', () => writeZip([entry('a', claiming(0xffffffff))]), 'an entry one above the entry limit, the escape value');
  assertRefusal('entry-too-large', () => writeZip([entry('a', claiming(2 ** 32))]), 'an entry of 4 GiB');
  assertRefusal('entry-too-large', () => writeZip([entry('a', claiming(2 ** 40))]), 'an entry of 1 TiB');
  // An entry exactly at the entry limit passes the entry check; its archive (the data plus
  // 100 bytes of headers and end record for a one-character name) passes the archive limit.
  assertRefusal('archive-too-large', () => writeZip([entry('a', claiming(0xfffffffe))]), 'an entry at the entry limit, in an archive over the archive limit');
  // 0xFFFFFF9B + 100 = 0xFFFFFFFF: an archive exactly one byte above the archive limit.
  assertRefusal('archive-too-large', () => writeZip([entry('a', claiming(0xffffff9b))]), 'an archive one byte above the archive limit');
  assertRefusal(
    'archive-too-large',
    () => writeZip([entry('a', claiming(0x80000000)), entry('b', claiming(0x80000000))]),
    'two entries that each fit but together pass 4 GiB',
  );
});

test('[ZIP-06] a lowered limit is an inclusive maximum: it accepts its own value and refuses one above it', () => {
  // entry size: a limit of 10 accepts 10 (and 9) and refuses 11
  assert.equal(readZip(writeZip([entry('a', new Uint8Array(10))], { entryBytesLimit: 10 })).entries[0].size, 10, 'an entry at the entry limit');
  assert.equal(readZip(writeZip([entry('a', new Uint8Array(9))], { entryBytesLimit: 10 })).entries[0].size, 9, 'an entry one below the entry limit');
  assertRefusal('entry-too-large', () => writeZip([entry('a', new Uint8Array(11))], { entryBytesLimit: 10 }), 'an entry one above the entry limit');

  // archive size: the finished archive is exactly as long as a limit that accepts it
  const exact = archiveLength([
    [1, 7],
    [2, 9],
  ]);
  const pair = [entry('a', new Uint8Array(7)), entry('bb', new Uint8Array(9))];
  assert.equal(writeZip(pair, { archiveBytesLimit: exact }).length, exact, 'an archive at the archive limit');
  assert.equal(writeZip(pair, { archiveBytesLimit: exact + 1 }).length, exact, 'an archive one below the archive limit');
  assertRefusal('archive-too-large', () => writeZip(pair, { archiveBytesLimit: exact - 1 }), 'an archive one above the archive limit');

  // entry count: a limit of 3 accepts 3 entries (and 2) and refuses 4
  assert.equal(readZip(writeZip([entry('a'), entry('b'), entry('c')], { entryCountLimit: 3 })).entries.length, 3, 'a count at the count limit');
  assert.equal(readZip(writeZip([entry('a'), entry('b')], { entryCountLimit: 3 })).entries.length, 2, 'a count one below the count limit');
  assertRefusal('too-many-entries', () => writeZip([entry('a'), entry('b'), entry('c'), entry('d')], { entryCountLimit: 3 }), 'a count one above the count limit');

  // lowering one limit leaves the others at their defaults
  assert.equal(readZip(writeZip([entry('a', new Uint8Array(100_000))], { entryCountLimit: 2 })).entries[0].size, 100_000);
});

test('[ZIP-06] a limit can never be raised past the defaults, and a limit must be a sound number', () => {
  const one = [entry('a')];
  assertRefusal('limits-invalid', () => writeZip(one, { entryCountLimit: 0xffff }), 'a count limit one above the default');
  assertRefusal('limits-invalid', () => writeZip(one, { entryBytesLimit: 0xffffffff }), 'an entry limit one above the default');
  assertRefusal('limits-invalid', () => writeZip(one, { archiveBytesLimit: 0xffffffff }), 'an archive limit one above the default');
  assertRefusal('limits-invalid', () => writeZip(one, { archiveBytesLimit: 2 ** 32 }), 'an archive limit of 4 GiB');
  assertRefusal('limits-invalid', () => writeZip(one, { entryBytesLimit: Number.MAX_SAFE_INTEGER }), 'an enormous entry limit');
  for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '5', null]) {
    assertRefusal('limits-invalid', () => writeZip(one, { entryCountLimit: bad }), `entryCountLimit ${String(bad)}`);
  }
  assertRefusal('limits-invalid', () => writeZip(one, null), 'null limits');
  assertRefusal('limits-invalid', () => writeZip(one, 5), 'a number for the limits');
  assertRefusal('limits-invalid', () => writeZip(one, { maxEntries: 5 }), 'a key that is not a limit');
  assert.equal(readZip(writeZip(one, ZIP_LIMITS)).entries.length, 1, 'the defaults themselves are valid limits');
  assert.equal(readZip(writeZip(one, {})).entries.length, 1, 'no limit given means the defaults');
  assert.equal(readZip(writeZip(one, { entryCountLimit: undefined })).entries.length, 1, 'an absent limit means the default');
});
