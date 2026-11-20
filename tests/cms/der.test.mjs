// SPDX-License-Identifier: Apache-2.0
//
// T013 DER encoder and strict reader: known-answer vectors for the structure
// cases DER-01..DER-05 (plan.md § Case catalogs, CMS; A-010, request #39).
// Expected encodings come from X.690 and from an independent computation, not
// from the encoder under test.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  children,
  compareDer,
  DerError,
  encodeLength,
  integer,
  objectIdentifier,
  octetString,
  readWhole,
  sequence,
  setOf,
  sortedSetContent,
  tlv,
} from '../../src/cryptograph/cms/index.ts';
import { hex, OID_HEX, toHex } from './support.mjs';

const derError = (code) => (error) => error instanceof DerError && error.code === code;

test('[DER-01] lengths are definite and minimal', () => {
  const vectors = [
    [0, '00'],
    [1, '01'],
    [127, '7f'],
    [128, '8180'],
    [255, '81ff'],
    [256, '820100'],
    [65535, '82ffff'],
    [65536, '83010000'],
    [0xffffffff, '84ffffffff'],
  ];
  for (const [length, expected] of vectors) assert.equal(toHex(encodeLength(length)), expected, `length ${length}`);
  for (const bad of [-1, 1.5, 2 ** 32, Number.NaN]) assert.throws(() => encodeLength(bad), derError('length-out-of-range'));
  assert.equal(toHex(tlv(0x04, new Uint8Array(200))).slice(0, 6), '0481c8');
  assert.throws(() => tlv(0x1f, new Uint8Array(0)), derError('tag-unsupported'));
  assert.throws(() => tlv(0x100, new Uint8Array(0)), derError('tag-unsupported'));
});

test('[DER-02] an INTEGER is minimal two\'s complement', () => {
  const vectors = [
    [0, '020100'],
    [1, '020101'],
    [127, '02017f'],
    [128, '02020080'],
    [255, '020200ff'],
    [256, '02020100'],
    [-1, '0201ff'],
    [-128, '020180'],
    [-129, '0202ff7f'],
    [2n ** 64n, '0209010000000000000000'],
    [-(2n ** 64n), '0209ff0000000000000000'],
  ];
  for (const [value, expected] of vectors) assert.equal(toHex(integer(value)), expected, `integer ${value}`);
  for (const bad of [1.5, 2 ** 53, Number.NaN]) assert.throws(() => integer(bad), derError('integer-invalid'));
});

test('[DER-03] OBJECT IDENTIFIER arcs are base 128, including the 2.25 arc of the approval-evidence attribute', () => {
  const vectors = [
    ['1.2.840.113549.1.7.1', OID_HEX.data],
    ['1.2.840.113549.1.7.2', OID_HEX.signedData],
    ['1.2.840.113549.1.9.3', OID_HEX.contentType],
    ['1.2.840.113549.1.9.4', OID_HEX.messageDigest],
    ['1.2.840.113549.1.9.16.2.47', OID_HEX.signingCertificateV2],
    ['2.16.840.1.101.3.4.2.1', OID_HEX.sha256],
    ['1.2.840.113549.1.1.11', OID_HEX.sha256WithRSAEncryption],
    ['2.25.254263291653419018820250361524609646248', OID_HEX.approvalEvidenceDigest],
    ['2.999.3', '0603883703'],
    ['0.39', '060127'],
    ['2.40', '060178'],
  ];
  for (const [dotted, expected] of vectors) assert.equal(toHex(objectIdentifier(dotted)), expected, dotted);
  for (const bad of ['3.1', '1.40', '0.40', '1', '1.2.', '.1.2', '1.02', '1..2', 'a.b', '1.2.-3', '']) {
    assert.throws(() => objectIdentifier(bad), derError('oid-invalid'), `refuses ${JSON.stringify(bad)}`);
  }
});

test('[DER-04] SET OF sorts element encodings ascending, whatever the input order', () => {
  const a = hex('020105');
  const b = hex('040101');
  const c = hex('040102');
  const expected = '3109020105040101040102';
  const orders = [
    [a, b, c],
    [a, c, b],
    [b, a, c],
    [b, c, a],
    [c, a, b],
    [c, b, a],
  ];
  for (const order of orders) {
    const before = order.map(toHex);
    assert.equal(toHex(setOf(order)), expected);
    assert.deepEqual(order.map(toHex), before, 'the input array is not reordered');
  }
  assert.equal(toHex(setOf([c, a, b], 0xa0)), 'a009020105040101040102', 'an IMPLICIT tag keeps the same sorted content');
  assert.equal(toHex(sortedSetContent([c, b, a])), '020105040101040102');
  assert.equal(compareDer(hex('0401'), hex('040100')), 0, 'the shorter encoding is padded with zero octets');
  assert.ok(compareDer(hex('0401'), hex('040101')) < 0);
  assert.ok(compareDer(hex('3018'), hex('302f')) < 0);
});

test('[DER-05] the reader accepts only minimal definite DER inside its parent', () => {
  const encoded = sequence(integer(5), octetString(hex('0102')));
  const top = readWhole(encoded);
  assert.equal(top.tag, 0x30);
  assert.deepEqual(children(encoded, top).map((child) => child.tag), [0x02, 0x04]);
  assert.throws(() => readWhole(hex('30800000')), derError('indefinite-length'));
  assert.throws(() => readWhole(hex('0481050102030405')), derError('length-not-minimal'));
  assert.throws(() => readWhole(Buffer.concat([hex('04820081'), Buffer.alloc(0x81)])), derError('length-not-minimal'));
  assert.throws(() => readWhole(hex('04050102')), derError('truncated'));
  assert.throws(() => readWhole(hex('040000')), derError('trailing-data'));
  assert.throws(() => readWhole(hex('1f0100')), derError('tag-unsupported'));
  const overrun = hex('3003020501');
  assert.throws(() => children(overrun, readWhole(overrun)), derError('truncated'), 'a child may not run past its parent');
  const primitive = readWhole(hex('0400'));
  assert.throws(() => children(hex('0400'), primitive), derError('not-constructed'));
});
