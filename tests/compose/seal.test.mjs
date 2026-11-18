// SPDX-License-Identifier: Apache-2.0
//
// Compose tests (T036): the /Sig dictionary and its placeholders (CP-05). The
// /Contents placeholder holds exactly 2 x signedDataLength(certificate) hex
// digits with no padding (request #39, Part F); the /ByteRange is filled by the
// composer in a fixed-width slot and covers everything but the hex string,
// delimiters included; /M carries the unsigned server time and /Reason labels
// it as such (data-model.md, Global rules; spec.md FR-006).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { signedDataLength } from '../../src/cryptograph/cms/index.ts';
import { checkRequest } from '../../src/cryptograph/compose/compose.ts';
import { ComposeError, composeSealRevision, signedRanges } from '../../src/cryptograph/compose/index.ts';
import { fixture, largestCertificate, lastSection, latin1, literalOf, sectionObjects, sha256, simpleRequest, syntheticCertificate } from './support.mjs';

test('[CP-05] the /Sig dictionary is ETSI.CAdES.detached, labels /M as unsigned server time, and holds exact /Contents and /ByteRange placeholders', async () => {
  const base = fixture('single-page.pdf');
  const length = signedDataLength(syntheticCertificate());
  const revision = await composeSealRevision(simpleRequest(base));
  const { bytes } = revision;
  const sig = sectionObjects(bytes, lastSection(bytes)).get(revision.objects.signature);

  assert.match(sig, /\/Type \/Sig\b/);
  assert.match(sig, /\/Filter \/Adobe\.PPKLite\b/);
  assert.match(sig, /\/SubFilter \/ETSI\.CAdES\.detached\b/);
  assert.match(sig, /\/M \(D:20261118093000Z\)/, '/M is the given server time');
  assert.equal(literalOf(sig, 'Reason'), 'Organization seal. The signing time is unsigned server time, not a trusted timestamp.', 'the exact label');
  assert.doesNotMatch(sig, /adbe\.pkcs7/);

  assert.equal(revision.signedDataLength, length);
  const [zero, first, start, second] = revision.byteRange;
  const text = latin1(bytes);
  assert.equal(zero, 0);
  assert.ok(first > revision.documentLength, 'the placeholder is in the update');
  assert.equal(text[first], '<');
  assert.equal(text[start - 1], '>');
  assert.equal(start - first, 2 * length + 2, 'exactly 2 x signedDataLength digits, no padding');
  assert.match(text.slice(first + 1, start - 1), /^0+$/);
  assert.equal(text.slice(first - '/Contents '.length, first), '/Contents ');
  assert.deepEqual(revision.contents, { offset: first + 1, hexLength: 2 * length });
  assert.equal(start + second, bytes.length, 'the second span runs to the end of the file');

  const slot = /\/ByteRange (\[[^\]]*\])/.exec(text.slice(revision.documentLength));
  assert.equal(slot[1].length, 36, 'a fixed-width slot');
  assert.deepEqual(slot[1].slice(1, -1).trim().split(/\s+/).map(Number), [0, first, start, second], 'the file states the same ranges');

  const [head, tail] = signedRanges(revision);
  assert.equal(head.length + tail.length, bytes.length - (start - first));
  assert.ok(Buffer.from(head).equals(Buffer.from(bytes.subarray(0, first))));
  assert.ok(Buffer.from(tail).equals(Buffer.from(bytes.subarray(start))));
  assert.equal(revision.digest, sha256(bytes), 'the digest is of the composed bytes (approved_composition_digest)');

  // Writing digits of the same length (the sealing worker's step) leaves both spans unchanged.
  const spliced = Buffer.from(bytes);
  spliced.write('ab'.repeat(length), first + 1, 'latin1');
  const [splicedHead, splicedTail] = signedRanges({ bytes: spliced, byteRange: revision.byteRange });
  assert.ok(Buffer.from(splicedHead).equals(Buffer.from(head)));
  assert.ok(Buffer.from(splicedTail).equals(Buffer.from(tail)));
});

test('[CP-05] the /Sig dictionary is one object with a direct /ByteRange and /Contents, and under 4 KiB of text on each side of the hex string (T037, A4)', async () => {
  // T037 relies on this layout to find and fill the placeholder (request #44, T036-FIXES).
  for (const certificateDer of [syntheticCertificate(), largestCertificate()]) {
    const revision = await composeSealRevision(simpleRequest(fixture('single-page.pdf'), 1, { certificateDer }));
    const text = latin1(revision.bytes);
    const begin = lastSection(revision.bytes).entries.get(revision.objects.signature).offset;
    const end = text.indexOf('endobj', begin) + 'endobj'.length;
    const [, first, start] = revision.byteRange;
    assert.ok(begin < first && start < end, 'the hex string lies inside the /Sig object');
    const object = text.slice(begin, end);
    assert.equal(object.match(/\bobj\b/g).length, 1, 'one object');
    assert.match(object, /\/ByteRange \[/, 'a direct /ByteRange');
    assert.equal(text.slice(first - '/Contents '.length, first), '/Contents ', 'a direct /Contents');
    assert.ok(first - begin < 4096, `${first - begin} bytes before the hex string`);
    assert.ok(end - start < 4096, `${end - start} bytes after it`);
  }
});

test('[CP-05] the /Contents placeholder follows the configured certificate, and a bad seal time or certificate is refused', async () => {
  const base = fixture('single-page.pdf');
  const short = syntheticCertificate('openSig seal');
  const long = syntheticCertificate('openSig compose test seal with a considerably longer subject common name');
  assert.notEqual(signedDataLength(short), signedDataLength(long));
  for (const certificate of [short, long]) {
    const revision = await composeSealRevision(simpleRequest(base, 1, { certificateDer: certificate }));
    assert.equal(revision.contents.hexLength, 2 * signedDataLength(certificate));
    assert.equal(revision.byteRange[2] - revision.byteRange[1], 2 * signedDataLength(certificate) + 2);
  }
  for (const sealTime of ['2026-02-30T00:00:00Z', '2026-11-18T09:30:00+01:00', '2026-11-18 09:30:00Z', '2026-11-18T24:00:00Z', 20261118]) {
    assert.throws(
      () => checkRequest(simpleRequest(base, 1, { sealTime })),
      (error) => error instanceof ComposeError && error.status === 400 && error.details[0].code === 'invalid_time',
      String(sealTime),
    );
  }
  assert.throws(
    () => checkRequest(simpleRequest(base, 1, { certificateDer: Uint8Array.of(0x30, 0x00) })),
    (error) => error instanceof ComposeError && error.status === 500 && error.reason === 'certificate-invalid',
  );
});
