// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-09 and PL-10: nesting depth, object count and cross-reference
// section limits, and the decompression-ratio and total-inflated-byte limits. Hostile
// variants are generated at test runtime from structural descriptions.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { DEFAULT_PARSER_LIMITS } from '../../src/pdf/limits.ts';
import { parsePdf } from '../../src/pdf/service.ts';
import { basicObjects, classicPdf, heavyDocument, noiseText, xrefStreamPdf } from './pdf-builder.mjs';

function limitRejection(outcome, limit, label) {
  assert.equal(outcome.ok, false, `${label} must be rejected`);
  assert.equal(outcome.reason, 'limit-exceeded', `${label}: ${outcome.reason} ${outcome.detail}`);
  assert.equal(outcome.detail, limit, label);
  assert.equal(outcome.status, 422);
}

const nested = (depth) => `${'['.repeat(depth)}${']'.repeat(depth)}`;

test('[PL-09] nesting depth is bounded at the configured limit without exhausting the stack', async () => {
  assert.equal(DEFAULT_PARSER_LIMITS.maxDepth, 64);
  // The page dictionary is one level; /Deep adds `k` nested arrays inside it.
  const [atLimit, overLimit, hostile, inObjectStream] = await Promise.all([
    parsePdf(classicPdf(basicObjects({ page: `/Deep ${nested(63)}` }))),
    parsePdf(classicPdf(basicObjects({ page: `/Deep ${nested(64)}` }))),
    parsePdf(classicPdf(basicObjects({ page: `/Deep ${nested(200_000)}` }))),
    parsePdf(xrefStreamPdf(basicObjects({ page: `/Deep ${nested(5_000)}` }), { packed: [[1, 2, 3]] })),
  ]);
  assert.equal(atLimit.ok, true, atLimit.ok ? '' : atLimit.detail);
  assert.equal(atLimit.report.stats.max_depth, 64);
  limitRejection(overLimit, 'nesting-depth', '65 levels');
  limitRejection(hostile, 'nesting-depth', '200000 levels');
  limitRejection(inObjectStream, 'nesting-depth', 'deep object inside an object stream');
  const nestedDicts = await parsePdf(classicPdf(basicObjects({ page: `/D ${'<< /D '.repeat(40)}1${' >>'.repeat(40)}` })), { limits: { maxDepth: 16 } });
  limitRejection(nestedDicts, 'nesting-depth', 'nested dictionaries under maxDepth 16');
});

test('[PL-09] object count and cross-reference section limits are enforced', async () => {
  assert.equal(DEFAULT_PARSER_LIMITS.maxObjects, 100_000);
  const heavy = heavyDocument(100_000);
  assert.ok(heavy.length < 10 * 1024 * 1024);
  limitRejection(await parsePdf(heavy), 'object-count', '100004 objects under the default limit');

  // basicObjects() has 3 objects plus the free entry 0: 4 cross-reference entries.
  const small = classicPdf(basicObjects());
  const [fits, exceeds] = await Promise.all([parsePdf(small, { limits: { maxObjects: 4 } }), parsePdf(small, { limits: { maxObjects: 3 } })]);
  assert.equal(fits.ok, true, fits.ok ? '' : fits.detail);
  limitRejection(exceeds, 'object-count', 'maxObjects 3');

  // A chain of incremental updates longer than maxXrefSections.
  let chained = small;
  for (let i = 0; i < 4; i += 1) {
    const text = chained.toString('latin1');
    const prev = Number(/startxref\n(\d+)\n%%EOF\n$/.exec(text)[1]);
    const update = `xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 4 /Root 1 0 R /Prev ${prev} >>\nstartxref\n${chained.length}\n%%EOF\n`;
    chained = Buffer.concat([chained, Buffer.from(update, 'latin1')]);
  }
  const [allowed, tooMany] = await Promise.all([parsePdf(chained), parsePdf(chained, { limits: { maxXrefSections: 4 } })]);
  assert.equal(allowed.ok, true, allowed.ok ? '' : allowed.detail);
  assert.equal(allowed.report.xref.sections, 5);
  limitRejection(tooMany, 'xref-sections', 'five sections under maxXrefSections 4');
});

test('[PL-10] a decompression bomb in an object stream exceeds the ratio limit without being inflated', async () => {
  assert.equal(DEFAULT_PARSER_LIMITS.maxRatio, 200);
  // About 8 MiB of spaces compress to a few KiB: a ratio near 1000.
  const bomb = xrefStreamPdf(basicObjects(), { packed: [[1, 2, 3]], objstmTail: () => ' '.repeat(8 * 1024 * 1024) });
  assert.ok(bomb.length < 64 * 1024, 'the bomb is small on the wire');
  limitRejection(await parsePdf(bomb), 'decompression-ratio', 'zlib bomb');

  // The same structure within the ratio is accepted, so the rejection is the ratio alone.
  const mild = xrefStreamPdf(basicObjects(), { packed: [[1, 2, 3]], objstmTail: () => noiseText(4096) });
  const outcome = await parsePdf(mild);
  assert.equal(outcome.ok, true, outcome.ok ? '' : outcome.detail);
  assert.ok(outcome.report.stats.inflated_bytes > 4096);
});

test('[PL-10] total inflated bytes across object streams are capped', async () => {
  const bodies = [...basicObjects(), '<< /A 1 >>', '<< /B 2 >>'];
  // Two object streams, each inflating about 40 KiB of poorly compressible text.
  const doc = xrefStreamPdf(bodies, { packed: [[1, 2, 3, 4], [5]], objstmTail: (index) => noiseText(40 * 1024, index + 7) });
  const [capped, ample] = await Promise.all([
    parsePdf(doc, { limits: { maxInflatedBytes: 64 * 1024 } }),
    parsePdf(doc, { limits: { maxInflatedBytes: 1024 * 1024 } }),
  ]);
  limitRejection(capped, 'inflated-bytes', 'two object streams under a 64 KiB budget');
  assert.equal(ample.ok, true, ample.ok ? '' : ample.detail);
  assert.ok(ample.report.stats.inflated_bytes > 64 * 1024 && ample.report.stats.inflated_bytes <= 1024 * 1024);
  assert.equal(ample.report.stats.object_streams, 2);

  // Corrupt Flate data and unsupported structural filters are rejected, not repaired.
  const corrupt = xrefStreamPdf(basicObjects(), { packed: [[1, 2, 3]], compress: false, objstmExtra: '/Filter /FlateDecode' });
  const lzw = xrefStreamPdf(basicObjects(), { packed: [[1, 2, 3]], compress: false, objstmExtra: '/Filter /LZWDecode' });
  const [corruptOutcome, lzwOutcome] = await Promise.all([parsePdf(corrupt), parsePdf(lzw)]);
  assert.equal(corruptOutcome.reason, 'malformed', corruptOutcome.detail);
  assert.match(corruptOutcome.detail, /FlateDecode/);
  assert.equal(lzwOutcome.reason, 'unsupported-feature', lzwOutcome.detail);
});
