// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-17 (A-008 P09) and PL-20 (A-009 LBR-4): the parent validates the
// child's report and never trusts it. Deliberately lying children (test-only entry modules
// written to a mkdtemp directory and launched through createParseServiceForTests exactly as
// the real worker is: same sandbox, permission flags and limits) report impossible page
// counts, sizes, rotations, boxes, isolation flags, byte counts, trailers, page references
// and objects; every such report is a fail-closed 500 service-failure. An honest copy of a
// real report passes, which shows the lying children run through the same path.
//
// PL-22 (re-check LBR2-1): the parent's bounds are the parser's own, so an honest child's
// report of any document the parser accepts is accepted, and a document the parser refuses
// is a 422, never a 500 service failure.

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';

import * as service from '../../src/pdf/service.ts';
import { basicObjects, classicPdf, numberedPdf, xrefStreamPdf } from './pdf-builder.mjs';
import { fixtureBytes, sha256 } from './support.mjs';

const dir = mkdtempSync(join(tmpdir(), 'opensig-pl17-'));
after(() => rmSync(dir, { recursive: true, force: true }));
let children = 0;

/** A child entry that ignores its input and prints `text` as its one result line. */
function lyingChild(text) {
  children += 1;
  const entry = join(dir, `child-${children}.mjs`);
  writeFileSync(entry, `process.stdout.write(${JSON.stringify(`${text}\n`)});\n`, { mode: 0o600 });
  return entry;
}

const clone = (value) => JSON.parse(JSON.stringify(value));
const viaChild = (input, text) => service.createParseServiceForTests({ workerEntry: lyingChild(text) }).parse(input);

test('[PL-17] a lying parse child is never trusted: impossible reports are fail-closed service failures', async () => {
  const input = fixtureBytes('single-page.pdf');
  const real = await service.parsePdf(input);
  assert.equal(real.ok, true, real.ok ? '' : real.detail);
  const honest = clone(real.report);
  delete honest.digest;
  delete honest.network_sandbox;
  const page = honest.pages[0];
  const forge = (mutate) => {
    const report = clone(honest);
    mutate(report);
    return JSON.stringify({ ok: true, report });
  };

  // Control: an honest copy of the real report, from a test child, is accepted unchanged.
  const control = await viaChild(input, JSON.stringify({ ok: true, report: honest }));
  assert.equal(control.ok, true, control.ok ? '' : `${control.reason} ${control.detail}`);
  assert.equal(control.report.digest, sha256(input));
  assert.deepEqual(control.report.pages, honest.pages);
  assert.equal(control.network_sandbox, real.network_sandbox);

  const lies = {
    'zero pages': forge((r) => (r.pages = [])),
    '51 pages': forge((r) => (r.pages = Array.from({ length: 51 }, (_, i) => ({ ...page, number: i + 1 })))),
    'pages out of order': forge((r) => (r.pages[0].number = 2)),
    'zero width': forge((r) => (r.pages[0].width = 0)),
    'negative height': forge((r) => (r.pages[0].height = -page.height)),
    'non-numeric width': forge((r) => (r.pages[0].width = String(page.width))),
    'NaN width (serialized as null)': forge((r) => (r.pages[0].width = Number.NaN)),
    'infinite height': forge((r) => (r.pages[0].height = 1)).replace('"height":1,', '"height":1e999,'),
    'width that disagrees with the box': forge((r) => (r.pages[0].width = page.width - 1)),
    'rotate 45': forge((r) => (r.pages[0].rotate = 45)),
    'rotate -90': forge((r) => (r.pages[0].rotate = -90)),
    'rotate as a string': forge((r) => (r.pages[0].rotate = '0')),
    'crop box differing from the media box': forge((r) => {
      r.pages[0].crop_box = [10, 10, page.media_box[2] - 10, page.media_box[3] - 10];
      r.pages[0].width = page.media_box[2] - 20;
      r.pages[0].height = page.media_box[3] - 20;
    }),
    'media box without area': forge((r) => (r.pages[0].media_box = [0, 0, 0, 0])),
    'byte count one more than the input': forge((r) => (r.bytes = input.length + 1)),
    'byte count one less than the input': forge((r) => (r.bytes = input.length - 1)),
    'no byte count': forge((r) => delete r.bytes),
    'permission model reported off': forge((r) => (r.isolation.permission_model = false)),
    'fs-write reported granted': forge((r) => (r.isolation.fs_write = true)),
    'wrong schema': forge((r) => (r.schema = 'opensig.pdf.parse-report.v0')),
    'unknown rejection reason': JSON.stringify({ ok: false, reason: 'all-clear', detail: 'synthetic' }),
    'overlong rejection detail': JSON.stringify({ ok: false, reason: 'malformed', detail: 'x'.repeat(500) }),
    'non-JSON output': 'synthetic garbage',
  };
  const names = Object.keys(lies);
  const outcomes = await Promise.all(names.map((name) => viaChild(input, lies[name])));
  names.forEach((name, index) => {
    const outcome = outcomes[index];
    assert.equal(outcome.ok, false, `${name} must not be accepted`);
    assert.equal(outcome.status, 500, `${name}: ${outcome.status} ${outcome.reason} ${outcome.detail}`);
    assert.equal(outcome.code, 'internal', name);
    assert.equal(outcome.reason, 'service-failure', name);
    assert.match(outcome.detail, /invalid report|no valid result/, name);
    assert.equal(outcome.report, undefined, name);
  });

  // A well-formed rejection from the child is passed through as a 422.
  const rejection = await viaChild(input, JSON.stringify({ ok: false, reason: 'malformed', detail: 'synthetic' }));
  assert.deepEqual([rejection.status, rejection.reason, rejection.detail], [422, 'malformed', 'synthetic']);

  // The page ceiling follows the configured limit as well as the FR-002 ceiling.
  const twoPages = JSON.parse(
    forge((r) => {
      const second = r.xref.size;
      r.xref.size = second + 1;
      r.objects[String(second)] = { gen: 0, value: clone(r.objects[String(page.ref[0])].value) };
      r.pages = [page, { ...page, number: 2, ref: [second, 0] }];
    }),
  );
  assert.notEqual(service.validateChildResult(twoPages, input.length, 2), null);
  assert.equal(service.validateChildResult(twoPages, input.length, 1), null);
});

test('[PL-20] the parent shape-checks and bounds the reported objects, trailer and page references', async () => {
  const input = fixtureBytes('single-page.pdf');
  const real = await service.parsePdf(input);
  assert.equal(real.ok, true, real.ok ? '' : real.detail);
  const honest = clone(real.report);
  delete honest.digest;
  delete honest.network_sandbox;
  const rootNum = String(honest.trailer.root[0]);
  const pageNum = String(honest.pages[0].ref[0]);
  const size = honest.xref.size;
  const check = (mutate) => {
    const report = clone(honest);
    mutate(report);
    return service.validateChildResult({ ok: true, report }, input.length, 50);
  };
  assert.notEqual(check(() => {}), null, 'control: the honest report is valid');
  const pageDict = (r) => r.objects[pageNum].value.dict;
  const catalogDict = (r) => r.objects[rootNum].value.dict;

  const lies = {
    // trailer
    'root beyond the cross-reference size': (r) => (r.trailer.root = [size + 98, 0]),
    'root naming an object the report does not carry': (r) => (r.trailer.root = [Number(pageNum) + 1 < size ? Number(pageNum) + 1 : 2, 0]),
    'root naming the page object': (r) => (r.trailer.root = [...r.pages[0].ref]),
    'root generation that differs from the object': (r) => (r.trailer.root = [Number(rootNum), 7]),
    'root object 0': (r) => (r.trailer.root = [0, 0]),
    'extra trailer member': (r) => (r.trailer.encrypt = null),
    'info that is not a reference pair': (r) => (r.trailer.info = [1]),
    'id that is not hex': (r) => (r.trailer.id = ['zz', '00']),
    'id of three parts': (r) => (r.trailer.id = ['00', '00', '00']),
    // page references
    'page ref beyond the cross-reference size': (r) => (r.pages[0].ref = [size + 98, 0]),
    'page ref naming the catalog': (r) => (r.pages[0].ref = [...r.trailer.root]),
    'page ref with an impossible generation': (r) => (r.pages[0].ref = [Number(pageNum), 70000]),
    'page ref as a string': (r) => (r.pages[0].ref = 'x'),
    'extra page member': (r) => (r.pages[0].uri = 'synthetic'),
    // objects map
    'objects emptied': (r) => (r.objects = {}),
    'object key that is not a number': (r) => (r.objects.catalog = r.objects[rootNum]),
    'object key 0': (r) => (r.objects['0'] = { gen: 0, value: null }),
    'object entry with an extra member': (r) => (r.objects[rootNum].stream = true),
    'object generation out of range': (r) => (r.objects[rootNum].gen = 70000),
    'name that is not a string': (r) => (catalogDict(r).Type = { name: 7 }),
    'hex string with non-hex characters': (r) => (pageDict(r).Synthetic = { hex: 'zz' }),
    'reference of one element': (r) => (pageDict(r).Synthetic = { ref: [1] }),
    'dictionary that is not an object': (r) => (pageDict(r).Synthetic = { dict: 'x' }),
    'value with two tags': (r) => (pageDict(r).Synthetic = { name: 'A', hex: '00' }),
    'non-finite number': (r) => (pageDict(r).Synthetic = '1e999'),
    'nesting beyond the bound': (r) => {
      let value = null;
      for (let i = 0; i < 200; i += 1) value = [value];
      pageDict(r).Synthetic = value;
    },
    'more objects than pages allow': (r) => {
      for (let i = 0; i < 10; i += 1) r.objects[String(size + i)] = { gen: 0, value: null };
      r.xref.size = size + 20;
    },
    // features and stats
    'unknown feature name': (r) => (r.features = [...r.features, 'all-clear']),
    'acroform claimed without an AcroForm': (r) => (r.features = [...r.features.filter((f) => f !== 'acroform'), 'acroform']),
    'incremental updates claimed for one section': (r) => (r.features = [...r.features, 'incremental-updates']),
    'duplicate feature': (r) => (r.features = ['jpx', 'jpx']),
    'stats with an extra member': (r) => (r.stats.trusted = 1),
    // policy re-applied to what the child reports
    'page gains a Rendition additional action': (r) => (pageDict(r).AA = { dict: { O: { dict: { S: { name: 'Rendition' } } } } }),
    'catalog gains a JavaScript open action': (r) => (catalogDict(r).OpenAction = { dict: { S: { name: 'JavaScript' }, JS: { hex: '766f69642030' } } }),
    'catalog gains signature permissions': (r) => (catalogDict(r).Perms = { dict: { DocMDP: { ref: [Number(rootNum), 0] } } }),
    'page gains a Named additional action': (r) => (pageDict(r).AA = { dict: { O: { dict: { S: { name: 'Named' }, N: { name: 'NextPage' } } } } }),
  };
  for (const [name, mutate] of Object.entries(lies)) {
    const report = clone(honest);
    mutate(report);
    const text = JSON.stringify({ ok: true, report }).replace('"1e999"', '1e999');
    assert.equal(service.validateChildResult(JSON.parse(text), input.length, 50), null, name);
  }

  // Same-document navigation in a reported object stays valid.
  assert.notEqual(check((r) => (pageDict(r).AA = { dict: { O: { dict: { S: { name: 'GoTo' }, D: [{ ref: [Number(pageNum), 0] }, { name: 'Fit' }] } } } })), null);

  // End to end: a lying child that adds an action to the page object is refused.
  const forged = clone(honest);
  pageDict(forged).AA = { dict: { O: { dict: { S: { name: 'Rendition' } } } } };
  const outcome = await viaChild(input, JSON.stringify({ ok: true, report: forged }));
  assert.deepEqual([outcome.ok, outcome.status, outcome.reason], [false, 500, 'service-failure']);
  assert.match(outcome.detail, /invalid report/);
});

test('[PL-22] documents the parser accepts are never refused by the parent, and parser refusals stay 422', async () => {
  const nested = (levels) => `${'['.repeat(levels)}${']'.repeat(levels)}`;
  const big = 12_345_678_901;
  const name = 'N'.repeat(1500);
  // [document, parse options, check on the accepted report]
  const legal = {
    'reference to an object beyond /Size (legal; it means null)': [
      classicPdf(basicObjects({ page: '/Foo 99 0 R' })),
      {},
      (r) => assert.deepEqual(r.objects[String(r.pages[0].ref[0])].value.dict.Foo, { ref: [99, 0] }),
    ],
    'trailer /Info beyond /Size': [classicPdf(basicObjects(), { trailer: '/Info 99 0 R' }), {}, (r) => assert.deepEqual(r.trailer.info, [99, 0])],
    '/ID of 300 bytes per part': [
      classicPdf(basicObjects(), { trailer: `/ID [<${'ab'.repeat(300)}> <${'cd'.repeat(300)}>]` }),
      {},
      (r) => assert.deepEqual(r.trailer.id, ['ab'.repeat(300), 'cd'.repeat(300)]),
    ],
    'name key of 1500 characters': [
      classicPdf(basicObjects({ page: `/${name} 1` })),
      {},
      (r) => assert.equal(r.objects[String(r.pages[0].ref[0])].value.dict[name], 1),
    ],
    'name value of 1500 characters': [
      classicPdf(basicObjects({ page: `/Foo /${name}` })),
      {},
      (r) => assert.deepEqual(r.objects[String(r.pages[0].ref[0])].value.dict.Foo, { name }),
    ],
    'string of 70000 bytes': [
      classicPdf(basicObjects({ page: `/Foo <${'ab'.repeat(70_000)}>` })),
      {},
      (r) => assert.equal(r.objects[String(r.pages[0].ref[0])].value.dict.Foo.hex.length, 140_000),
    ],
    'array of 200001 numbers': [
      classicPdf(basicObjects({ page: `/Foo [${'0 '.repeat(200_001)}]` })),
      {},
      (r) => assert.equal(r.objects[String(r.pages[0].ref[0])].value.dict.Foo.length, 200_001),
    ],
    'nesting at the default depth limit': [classicPdf(basicObjects({ page: `/Foo ${nested(63)}` })), {}, (r) => assert.equal(r.stats.max_depth, 64)],
    'nesting of 199 under a configured maxDepth of 200': [
      classicPdf(basicObjects({ page: `/Foo ${nested(199)}` })),
      { limits: { maxDepth: 200 } },
      (r) => assert.equal(r.stats.max_depth, 200),
    ],
    'page object number of eleven digits': [
      numberedPdf(
        [
          [1, '<< /Type /Catalog /Pages 2 0 R >>'],
          [2, `<< /Type /Pages /Kids [${big} 0 R] /Count 1 /MediaBox [0 0 612 792] >>`],
          [big, '<< /Type /Page /Parent 2 0 R >>'],
        ],
        { root: 1 },
      ),
      {},
      (r) => assert.deepEqual(r.pages[0].ref, [big, 0]),
    ],
    'cross-reference stream with a non-zero generation': [
      xrefStreamPdf([...basicObjects({ page: '/Annots 4 7 R' }), '[]'], { gens: { 4: 7 } }),
      {},
      (r) => assert.equal(r.objects['4'].gen, 7),
    ],
  };
  const refused = {
    'nesting one beyond the default depth limit': [classicPdf(basicObjects({ page: `/Foo ${nested(64)}` })), {}, 'limit-exceeded'],
    'cross-reference stream generation above 65535': [
      xrefStreamPdf([...basicObjects({ page: '/Annots 4 0 R' }), '[]'], { gens: { 4: 70_000 } }),
      {},
      'malformed',
    ],
  };
  const run = (table) => Promise.all(Object.values(table).map(([input, options]) => service.parsePdf(input, options)));
  const [accepted, rejected] = await Promise.all([run(legal), run(refused)]);
  Object.entries(legal).forEach(([label, [input, , check]], index) => {
    const outcome = accepted[index];
    assert.equal(outcome.ok, true, `${label}: ${outcome.ok ? '' : `${outcome.status} ${outcome.reason} ${outcome.detail}`}`);
    assert.equal(outcome.status, 200, label);
    assert.equal(outcome.report.digest, sha256(input), label);
    check(outcome.report);
  });
  Object.entries(refused).forEach(([label, [, , reason]], index) => {
    const outcome = rejected[index];
    assert.deepEqual([outcome.ok, outcome.status, outcome.reason], [false, 422, reason], `${label}: ${outcome.detail}`);
  });

  // The reported nesting bound follows the configured parser limit, not a fixed one.
  const deepInput = classicPdf(basicObjects({ page: `/Foo ${nested(150)}` }));
  const deep = await service.parsePdf(deepInput, { limits: { maxDepth: 200 } });
  assert.equal(deep.ok, true, deep.ok ? '' : deep.detail);
  const report = clone(deep.report);
  delete report.digest;
  delete report.network_sandbox;
  assert.notEqual(service.validateChildResult({ ok: true, report }, deepInput.length, 50, 200), null);
  assert.equal(service.validateChildResult({ ok: true, report }, deepInput.length, 50, 64), null);
});
