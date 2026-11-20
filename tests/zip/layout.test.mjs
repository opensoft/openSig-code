// SPDX-License-Identifier: Apache-2.0
//
// T039 deterministic ZIP writer: round trip, determinism, header fields, CRC-32, a
// known-answer archive and ordering (plan.md § Case catalogs, ZIP: ZIP-01..ZIP-04; extra
// case IDs, the frozen registry requires none). Every archive is read back by the
// independent reader in ./reader.mjs, which imports nothing from src/ and computes
// CRC-32 with its own table. Expected bytes come from the format, never from the writer.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { writeZip } from '../../src/artifacts/zip.ts';
import {
  bytesOf,
  decodeDosDate,
  decodeDosTime,
  packageEntries,
  patterned,
  permutations,
  readZip,
  referenceArchive,
  referenceCrc32,
} from './reader.mjs';

const SORTED_PACKAGE_NAMES = ['approval-manifest.json', 'audit-receipt.json', 'final.pdf', 'package-index.json', 'verification.json'];

const sameBytes = (left, right) => Buffer.compare(left, right) === 0;
const hex = (bytes) => Buffer.from(bytes).toString('hex');

/** Run `body` while every read of the clock throws; the body is synchronous, so nothing else sees the stub. */
function withoutClock(body) {
  const RealDate = globalThis.Date;
  const stop = () => {
    throw new Error('the writer read the clock');
  };
  globalThis.Date = new Proxy(RealDate, {
    construct: stop,
    apply: stop,
    get(target, property, receiver) {
      if (property === 'now' || property === 'UTC' || property === 'parse') return stop;
      return Reflect.get(target, property, receiver);
    },
  });
  try {
    return body();
  } finally {
    globalThis.Date = RealDate;
  }
}

test('[ZIP-01] the five package files round-trip byte for byte through the independent reader', () => {
  const input = packageEntries();
  const { entries, end } = readZip(writeZip(input));
  assert.deepEqual(
    entries.map((entry) => entry.name),
    SORTED_PACKAGE_NAMES,
  );
  assert.equal(end.entriesTotal, 5);
  for (const entry of entries) {
    const source = input.find((candidate) => candidate.name === entry.name);
    assert.ok(source, `${entry.name} was one of the inputs`);
    assert.ok(sameBytes(entry.data, source.data), `${entry.name} comes back byte for byte`);
    assert.equal(entry.method, 0, `${entry.name} is stored`);
    assert.equal(entry.compressedSize, entry.size, `${entry.name} has equal compressed and plain sizes`);
    assert.equal(entry.size, source.data.length);
  }
});

test('[ZIP-01] empty, one-byte, all-byte-value and large entries round-trip byte for byte', () => {
  const everyByte = Uint8Array.from({ length: 256 }, (_, index) => index);
  const input = [
    { name: 'empty.bin', data: new Uint8Array(0) },
    { name: 'one.bin', data: Uint8Array.of(0) },
    { name: 'all-values.bin', data: everyByte },
    { name: 'big.bin', data: patterned(300_000, 5) },
    { name: 'short.txt', data: bytesOf('short') },
  ];
  const { entries } = readZip(writeZip(input));
  assert.equal(entries.length, input.length);
  for (const source of input) {
    const entry = entries.find((candidate) => candidate.name === source.name);
    assert.ok(entry, `${source.name} is present`);
    assert.ok(sameBytes(entry.data, source.data), `${source.name} comes back byte for byte`);
  }
});

test('[ZIP-02] any listing order of the same entries gives identical bytes, and so do repeated builds and copied buffers', () => {
  const orders = permutations(packageEntries());
  assert.equal(orders.length, 120);
  const reference = writeZip(orders[0]);
  for (const order of orders) assert.ok(sameBytes(writeZip(order), reference), `order ${order.map((entry) => entry.name[0]).join('')}`);
  assert.ok(sameBytes(writeZip(orders[0]), reference), 'a repeated build is identical');
  const copied = packageEntries().map((entry) => ({ name: entry.name, data: Uint8Array.from(entry.data) }));
  assert.ok(sameBytes(writeZip(copied), reference), 'fresh copies of the same bytes give the same archive');
});

test('[ZIP-02] no clock is read', () => {
  const outside = writeZip(packageEntries());
  const inside = withoutClock(() => writeZip(packageEntries()));
  assert.ok(sameBytes(inside, outside), 'building with every clock read forbidden gives the same archive');
  assert.equal(typeof Date.now(), 'number', 'the real clock is back');
});

test('[ZIP-02] the writer leaves its inputs alone and returns memory of its own', () => {
  const input = Object.freeze(packageEntries().map((entry) => Object.freeze({ ...entry })));
  const names = input.map((entry) => entry.name);
  const copies = input.map((entry) => Uint8Array.from(entry.data));
  const archive = writeZip(input);
  assert.deepEqual(
    input.map((entry) => entry.name),
    names,
    'the caller keeps its order',
  );
  for (const [index, entry] of input.entries()) assert.ok(sameBytes(entry.data, copies[index]), `${entry.name} is unchanged`);

  const before = Uint8Array.from(archive);
  for (const entry of input) entry.data.fill(0xaa);
  assert.ok(sameBytes(archive, before), 'changing the inputs afterwards does not change the archive');
  assert.equal(archive.byteOffset, 0);
  assert.equal(archive.buffer.byteLength, archive.length, 'the result is not a window onto a larger shared buffer');
  for (const entry of input) assert.notEqual(archive.buffer, entry.data.buffer, `${entry.name} shares no memory with the archive`);
  assert.notEqual(writeZip(input).buffer, archive.buffer, 'each call returns a fresh buffer');
});

test('[ZIP-03] every header has the fixed fields, and no extra field, data descriptor, comment or ZIP64 record appears', () => {
  const textOnly = packageEntries().map((entry, index) => ({ name: entry.name, data: bytesOf(`text entry ${index}\n`) }));
  const archive = writeZip(textOnly);
  const { entries, end } = readZip(archive);
  assert.equal(entries.length, 5);
  for (const entry of entries) {
    for (const [where, header] of [
      ['central', entry],
      ['local', entry.local],
    ]) {
      assert.equal(header.method, 0, `${entry.name} ${where} method (store)`);
      assert.deepEqual(decodeDosDate(header.date), { year: 1980, month: 1, day: 1 }, `${entry.name} ${where} date`);
      assert.deepEqual(decodeDosTime(header.time), { hour: 0, minute: 0, second: 0 }, `${entry.name} ${where} time`);
      assert.equal(header.flags, 0x0800, `${entry.name} ${where} flags: only the UTF-8 name flag, also for an ASCII name`);
      assert.equal(header.versionNeeded, 20, `${entry.name} ${where} version needed 2.0`);
      assert.equal(header.compressedSize, header.size, `${entry.name} ${where} sizes`);
    }
    assert.equal(entry.versionMadeBy, 0x0314, `${entry.name} version made by (Unix, 2.0)`);
    assert.equal(entry.externalAttributes, 0x81a40000, `${entry.name} external attributes (regular file, 0644)`);
    assert.equal(entry.internalAttributes, 0, `${entry.name} internal attributes`);
    assert.equal(entry.extraLength, 0, `${entry.name} central extra field`);
    assert.equal(entry.local.extraLength, 0, `${entry.name} local extra field`);
    assert.equal(entry.commentLength, 0, `${entry.name} comment`);
    assert.equal(entry.diskStart, 0, `${entry.name} disk`);
    assert.notEqual(entry.crc, 0xffffffff);
    assert.notEqual(entry.size, 0xffffffff);
    assert.notEqual(entry.offset, 0xffffffff);
  }
  assert.equal(end.commentLength, 0, 'no archive comment');
  assert.equal(end.entriesOnDisk, 5);
  assert.equal(end.entriesTotal, 5);
  assert.equal(end.position + 22, archive.length, 'the end record is the last 22 bytes');

  const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
  for (let at = 0; at + 4 <= archive.length; at += 1) {
    const signature = view.getUint32(at, true);
    assert.notEqual(signature, 0x06064b50, `no ZIP64 end record at ${at}`);
    assert.notEqual(signature, 0x07064b50, `no ZIP64 locator at ${at}`);
    assert.notEqual(signature, 0x08074b50, `no data descriptor at ${at}`);
  }
});

test('[ZIP-03] every CRC-32 equals an independent table-driven computation and the standard check values', () => {
  assert.equal(referenceCrc32(bytesOf('123456789')), 0xcbf43926, 'the reference CRC matches the standard check value');
  assert.equal(referenceCrc32(bytesOf('hello')), 0x3610a686);
  assert.equal(referenceCrc32(new Uint8Array(0)), 0);

  // A view into a larger buffer: only the viewed bytes may be summed.
  const backing = Buffer.concat([bytesOf('xxxx'), bytesOf('123456789'), bytesOf('yyyy')]);
  const input = [
    { name: 'check.txt', data: bytesOf('123456789') },
    { name: 'view.txt', data: backing.subarray(4, 13) },
    { name: 'empty.bin', data: new Uint8Array(0) },
    { name: 'one.bin', data: Uint8Array.of(255) },
    { name: 'big.bin', data: patterned(1 << 20, 7) },
    ...packageEntries(),
  ];
  const { entries } = readZip(writeZip(input));
  assert.equal(entries.length, input.length);
  for (const source of input) {
    const entry = entries.find((candidate) => candidate.name === source.name);
    assert.ok(entry, `${source.name} is present`);
    assert.equal(entry.crc, referenceCrc32(source.data), `${source.name} central CRC`);
    assert.equal(entry.local.crc, entry.crc, `${source.name} local CRC`);
    assert.equal(entry.computedCrc, entry.crc, `${source.name} CRC over the bytes it carries`);
  }
  const byName = new Map(entries.map((entry) => [entry.name, entry]));
  assert.equal(byName.get('check.txt').crc, 0xcbf43926);
  assert.equal(byName.get('view.txt').crc, 0xcbf43926);
  assert.equal(byName.get('empty.bin').crc, 0);
});

test('[ZIP-03] one known-answer archive matches byte for byte', () => {
  // Derived by hand from the format (APPNOTE field order and widths), never from the writer.
  // The archive holds one entry, a.txt with the data "hello". CRC-32("hello") = 0x3610A686,
  // stored little-endian as 86 a6 10 36; the reader's table-driven CRC confirms that value.
  const crcBytes = Buffer.alloc(4);
  crcBytes.writeUInt32LE(referenceCrc32(bytesOf('hello')));
  assert.equal(crcBytes.toString('hex'), '86a61036');
  const fields = [
    // local file header: signature, version needed 2.0, flags (bit 11), method 0, time 00:00:00,
    // date 1980-01-01, CRC-32, compressed size 5, size 5, name length 5, extra length 0
    '504b0304', '1400', '0008', '0000', '0000', '2100', '86a61036', '05000000', '05000000', '0500', '0000',
    // the name "a.txt" and the data "hello"
    '612e747874', '68656c6c6f',
    // central header: signature, made by (Unix, 2.0), needed 2.0, flags, method, time, date, CRC-32,
    // sizes, name length 5, extra length 0, comment length 0, disk 0, internal attributes 0,
    // external attributes 0x81A40000, local header offset 0
    '504b0102', '1403', '1400', '0008', '0000', '0000', '2100', '86a61036', '05000000', '05000000', '0500',
    '0000', '0000', '0000', '0000', '0000a481', '00000000',
    // the name again
    '612e747874',
    // end record: signature, disk 0, central directory disk 0, one entry here and in total,
    // central directory size 51, central directory offset 40, comment length 0
    '504b0506', '0000', '0000', '0100', '0100', '33000000', '28000000', '0000',
  ];
  const archive = writeZip([{ name: 'a.txt', data: bytesOf('hello') }]);
  assert.equal(archive.length, 40 + 51 + 22);
  assert.equal(Buffer.from(archive).toString('hex'), fields.join(''));
});

test('[ZIP-03] larger archives equal the reference encoder byte for byte', () => {
  const sets = [
    packageEntries(),
    [
      { name: 'empty.bin', data: new Uint8Array(0) },
      { name: 'big.bin', data: patterned(70_000, 3) },
      { name: 'B', data: Uint8Array.of(1, 2, 3) },
      { name: 'a-b_c.d', data: bytesOf('x') },
    ],
  ];
  for (const [index, entries] of sets.entries()) {
    assert.ok(sameBytes(writeZip(entries), referenceArchive(entries)), `entry set ${index}`);
  }
});

test('[ZIP-04] entries are sorted by the bytes of their names, not by case or locale', () => {
  // Byte order: "-" (0x2d) < "." (0x2e) < digits (0x30..) < "A".."Z" (0x41..) < "_" (0x5f) < "a".."z"
  // (0x61..), and a shorter prefix sorts first, so "a" < "a-b" < "a.b" < "a0" < "a_b" < "aa".
  // No two names are equal when case is ignored, which the writer refuses; "B" and "Y" tell byte order from case-insensitive order.
  const expected = ['-a', '0', '9z', 'B', 'Y', '_x', 'a', 'a-b', 'a.b', 'a0', 'a_b', 'aa', 'c', 'z'];
  const forward = expected.map((name) => ({ name, data: bytesOf(name) }));
  const reversed = [...forward].reverse();
  const rotated = [...forward.slice(5), ...forward.slice(0, 5)];
  for (const [label, order] of [
    ['sorted input', forward],
    ['reversed input', reversed],
    ['rotated input', rotated],
  ]) {
    const { entries } = readZip(writeZip(order));
    assert.deepEqual(
      entries.map((entry) => entry.name),
      expected,
      label,
    );
  }
  const names = readZip(writeZip(packageEntries())).entries.map((entry) => hex(entry.nameBytes));
  assert.deepEqual(names, [...names].sort(), 'the stored name bytes ascend');
});
