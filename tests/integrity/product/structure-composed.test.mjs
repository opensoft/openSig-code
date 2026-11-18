// SPDX-License-Identifier: Apache-2.0
//
// VB-06 (extended; request #49, row T014-XREFSTART): bases with the loose
// section starts T033 accepts, composed through T033's parser and T036's
// composer (the landed exports), are read by T014's structure reader. A base
// T033 accepts and T036 composes must never fail T014's structure check on its
// layout alone, or it would strand at T038's verify step.
//
// What each case needs:
// - T033's parse sandbox (bubblewrap or unshare), because composeSealRevision
//   parses the base in the isolated parse service. The `verification` mode
//   declares only `openssl`, so these four cases FAIL on a host without the
//   sandbox, as VB-05 does, and are never CAPABILITY_ABSENT or skipped (request
//   #56 B5). Nothing here probes for it or catches its absence; a guard test in
//   structure.test.mjs keeps it so. Each case that composed writes one
//   diagnostic line recording that the parse sandbox was present (request #56
//   Part A (7));
// - an in-memory RSA-3072 certificate (helpers/cert-build.mjs) to size the
//   placeholder. No key file, no OpenSSL, no T037: the compositions stay
//   unsealed. Their zero /Contents makes integrity invalid, but the structure
//   and ByteRange checks pass and coverage is complete, which is what VB-06
//   asserts here.
// VB-05's runs keep to bases the oracle reads; these loose starts need not be
// read by the oracle (request #49), so no agreement is asserted on them.
//
// Mutants killed here (and by the builder-only cases in structure.test.mjs): a
// comment after `xref` refused (E1); tables read as fixed 20-byte records (the
// token case); white-space before an object header refused (E2, the entry case);
// leading zeros refused (the token case).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readRevisionStructure, verifyPdf } from '../../../src/verifier/index.ts';
import { checkOf } from './helpers/agreement.mjs';
import { testPki } from './helpers/cert-build.mjs';
import { buildBase } from './helpers/pdf-build.mjs';
import { composeWithProduct } from './helpers/product-compose.mjs';

const at = new Date();
const pki = testPki(at);

async function composeAndRead(t, base, kinds) {
  const composed = await composeWithProduct({ document: base.bytes, certificateDer: pki.leaf.der });
  t.diagnostic('VB-06 parse sandbox present: T033 parsed the base and T036 composed it');
  const structure = readRevisionStructure(composed.bytes);
  assert.equal(structure.ok, true, structure.ok ? '' : `structure failed: ${structure.detail}`);
  assert.deepEqual(structure.revisions.map((r) => r.kind), kinds);
  const outcome = verifyPdf(composed.bytes, { validationTime: at });
  assert.equal(checkOf(outcome, 'revision-structure').result, 'pass');
  assert.equal(checkOf(outcome, 'byte-range').result, 'pass');
  assert.equal(outcome.revision_coverage, 'complete');
  assert.equal(outcome.signed_revision, 1);
  return composed;
}

test('[VB-06] E1 composed: a base whose `xref` is directly followed by a comment', async (t) => {
  const base = buildBase({ tableStyle: 'tokens' });
  assert.ok(base.bytes.toString('latin1').includes('xref% '));
  await composeAndRead(t, base, ['table', 'table']);
});

test('[VB-06] E2 composed: the base startxref names the end-of-line byte before its stream header', async (t) => {
  const base = buildBase({ xref: 'stream', startxrefDelta: -1 });
  const composed = await composeAndRead(t, base, ['stream', 'stream']);
  const text = Buffer.from(composed.bytes).toString('latin1');
  const prevs = [...text.matchAll(/\/Prev\s+(\d+)/g)].map((m) => Number(m[1]));
  const prev = prevs[prevs.length - 1];
  assert.equal(composed.bytes[prev], 0x0a, 'the seal revision /Prev names the same end-of-line byte');
});

test('[VB-06] token-form table entries composed: comments between tokens, leading zeros, entries naming comments', async (t) => {
  await composeAndRead(t, buildBase({ tableStyle: 'tokens', commentBeforeObjects: true, pointAtComment: true }), ['table', 'table']);
});

test('[VB-06] a type-1 entry naming white-space before its header, composed', async (t) => {
  await composeAndRead(t, buildBase({ entryDelta: { num: 3, delta: -1 } }), ['table', 'table']);
  await composeAndRead(t, buildBase({ xref: 'stream', entryDelta: { num: 4, delta: -1 } }), ['stream', 'stream']);
});
