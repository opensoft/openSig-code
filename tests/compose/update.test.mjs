// SPDX-License-Identifier: Apache-2.0
//
// Compose tests (T036): the incremental update (CP-01), the AcroForm signature
// field and its widgets (CP-02), and determinism (CP-06). Structure is read back
// with this directory's own cross-reference reader, and the T033 parse service
// reads every composed file in full: it checks the whole cross-reference chain
// and parses every in-use object before it detects the new signature, so
// `422 already-signed` is the structural round trip.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { checkRequest, composeFromReport } from '../../src/cryptograph/compose/compose.ts';
import { ComposeError, composeSealRevision, UPDATE_BOUND, UPDATE_REQUEST_BOUND } from '../../src/cryptograph/compose/index.ts';
import { parsePdf } from '../../src/pdf/service.ts';
import {
  approval,
  composeRequest,
  composeSources,
  dated,
  drawn,
  field,
  fixture,
  formDocument,
  hybridDocument,
  largestCertificate,
  lastSection,
  latin1,
  literalOf,
  maximalRequest,
  objectText,
  plainDocument,
  sharedAnnotsDocument,
  sigFlagsDocument,
  RECIPIENT_1,
  RECIPIENT_2,
  refList,
  refOf,
  roundTripReason,
  sectionObjects,
  sha256,
  simpleRequest,
  streamBody,
  tailOffset,
  typed,
  withPriorUpdate,
  ZIGZAG,
} from './support.mjs';

const samePrefix = (bytes, base) => Buffer.from(bytes.subarray(0, base.length)).equals(Buffer.from(base));

test('[CP-01] a table base keeps every byte and gains one classic section chained by /Prev, its objects numbered from the base /Size', async () => {
  const base = fixture('single-page.pdf');
  const baseSection = lastSection(base);
  assert.equal(baseSection.kind, 'table');
  const revision = await composeSealRevision(simpleRequest(base));
  const { bytes } = revision;

  assert.ok(samePrefix(bytes, base), 'the base bytes are untouched');
  assert.equal(revision.documentLength, base.length);
  assert.equal(revision.documentDigest, sha256(base));
  assert.equal(revision.digest, sha256(bytes));
  assert.equal(revision.xrefKind, 'table');

  const section = lastSection(bytes);
  assert.equal(section.kind, 'table');
  assert.ok(section.at > base.length, 'the new section is in the update');
  assert.equal(section.prev, tailOffset(base), '/Prev is the base startxref');
  assert.deepEqual(section.root, baseSection.root, '/Root is unchanged');
  assert.deepEqual(section.info, baseSection.info, '/Info is carried');
  assert.equal(section.id[0], baseSection.id[0], 'the permanent identifier is kept');
  assert.match(section.id[1], /^[0-9a-f]{32}$/);
  assert.notEqual(section.id[1], baseSection.id[1], 'the changing identifier changes');

  const numbers = [...section.entries.keys()].sort((a, b) => a - b);
  const rewritten = numbers.filter((num) => num < baseSection.size);
  const created = numbers.filter((num) => num >= baseSection.size);
  assert.deepEqual(rewritten, [1, 4], 'only the catalog and the page are rewritten');
  assert.deepEqual(created, Array.from({ length: created.length }, (_, i) => baseSection.size + i), 'new objects are consecutive from the base /Size');
  assert.equal(section.size, baseSection.size + created.length);
  for (const [num, entry] of section.entries) {
    assert.ok(entry.offset >= base.length, `object ${num} is written in the update`);
    assert.equal(entry.gen, 0);
    objectText(bytes, num, entry);
  }
  assert.equal(roundTripReason(await parsePdf(bytes)), '422 already-signed', 'the T033 parser reads the whole chain');
});

test('[CP-01] a cross-reference-stream base gains a cross-reference stream that lists itself, and object-stream members it rewrites become plain objects', async () => {
  const base = fixture('agreement-xref-stream.pdf');
  const baseSection = lastSection(base);
  assert.equal(baseSection.kind, 'stream');
  const revision = await composeSealRevision(simpleRequest(base, 3));
  const section = lastSection(revision.bytes);

  assert.ok(samePrefix(revision.bytes, base));
  assert.equal(revision.xrefKind, 'stream');
  assert.equal(section.kind, 'stream');
  assert.deepEqual(section.widths, [1, 4, 2]);
  assert.equal(section.prev, tailOffset(base));
  assert.equal(section.self, section.size - 1, 'the stream object is numbered last');
  assert.deepEqual(section.entries.get(section.self), { offset: section.at, gen: 0 }, 'the stream lists itself');
  assert.deepEqual(section.root, baseSection.root);
  assert.deepEqual(section.info, baseSection.info);
  assert.equal(section.id[0], baseSection.id[0]);
  // The catalog (1) and page 3 (8) were compressed in the base's object stream.
  const objects = sectionObjects(revision.bytes, section);
  assert.match(objects.get(1), /\/Type \/Catalog/);
  assert.match(objects.get(1), /\/AcroForm \d+ 0 R/);
  assert.match(objects.get(8), /\/Type \/Page\b/);
  assert.equal(roundTripReason(await parsePdf(revision.bytes)), '422 already-signed');
});

test('[CP-01] a hybrid base gets a classic table, a twice-revised base chains to its newest section, and bases without /ID or a final end-of-line keep their bytes', async () => {
  const plainBodies = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
    '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
    streamBody('', 'BT /F1 11 Tf 72 720 Td (Hybrid.) Tj ET'),
  ];
  const hybrid = hybridDocument(plainBodies, { trailer: '/ID [<0f0e0d0c0b0a09080706050403020100> <0f0e0d0c0b0a09080706050403020100>]' });
  const hybridReport = await parsePdf(hybrid);
  assert.ok(hybridReport.ok && hybridReport.report.xref.hybrid && hybridReport.report.xref.kind === 'table', 'the base is a hybrid whose last section is a table');
  const afterHybrid = await composeSealRevision(simpleRequest(hybrid));
  const hybridSection = lastSection(afterHybrid.bytes);
  assert.equal(hybridSection.kind, 'table', 'a table follows a hybrid base');
  assert.equal(hybridSection.xrefStm, null, 'the new table carries no /XRefStm');
  assert.equal(hybridSection.prev, tailOffset(hybrid));
  assert.equal(roundTripReason(await parsePdf(afterHybrid.bytes)), '422 already-signed');

  const revised = withPriorUpdate(plainDocument(), 6, '<< /Title (Revised synthetic fixture) >>');
  const afterRevised = await composeSealRevision(simpleRequest(revised));
  const revisedSection = lastSection(afterRevised.bytes);
  assert.equal(revisedSection.prev, tailOffset(revised), '/Prev names the newest base section');
  assert.ok(Math.min(...[...revisedSection.entries.keys()].filter((num) => num > 5)) >= 7, 'new objects start above the revised /Size');
  assert.equal(roundTripReason(await parsePdf(afterRevised.bytes)), '422 already-signed');

  const noId = plainDocument();
  const afterNoId = lastSection((await composeSealRevision(simpleRequest(noId))).bytes);
  assert.match(afterNoId.id[0], /^[0-9a-f]{32}$/);
  assert.equal(afterNoId.id[0], afterNoId.id[1], 'a base without /ID gets one identifier twice');

  const noEol = plainDocument({ finalEol: false });
  assert.notEqual(noEol[noEol.length - 1], 0x0a);
  const afterNoEol = await composeSealRevision(simpleRequest(noEol));
  assert.ok(samePrefix(afterNoEol.bytes, noEol), 'the base bytes are untouched');
  assert.equal(afterNoEol.bytes[noEol.length], 0x0a, 'one end-of-line separates the update');
  assert.equal(roundTripReason(await parsePdf(afterNoEol.bytes)), '422 already-signed');

  // Two pages share one indirect /Annots array (7): each rewritten page gets its own inline copy.
  const shared = sharedAnnotsDocument();
  const rect = { x: 0.1, y: 0.7, width: 0.35, height: 0.08 };
  const afterShared = await composeSealRevision(
    composeRequest(shared, [field('sig_1', 1, rect), field('sig_2', 2, rect)], [approval(RECIPIENT_1, [drawn('sig_1', ZIGZAG), drawn('sig_2', ZIGZAG)])]),
  );
  const sharedSection = lastSection(afterShared.bytes);
  const sharedObjects = sectionObjects(afterShared.bytes, sharedSection);
  assert.ok(!sharedSection.entries.has(7), 'the shared array is never rewritten');
  assert.deepEqual(refList(sharedObjects.get(3), 'Annots'), [6, afterShared.objects.widgets[0]]);
  assert.deepEqual(refList(sharedObjects.get(4), 'Annots'), [6, afterShared.objects.widgets[1]]);
  assert.ok(samePrefix(afterShared.bytes, shared));
  assert.equal(roundTripReason(await parsePdf(afterShared.bytes)), '422 already-signed');
});

test('[CP-01] the largest request the budgets allow, on the largest page box a report admits, stays under the update bound the module header states', async () => {
  // 20 fields across the page width, a 16 KiB certificate, and per approval 15,000 points
  // (10,000 + 5,000 in 50-stroke values) plus 8 typed 80-character values (maximalRequest),
  // on a 14,400-point page and on the largest box report.ts admits (+-1,000,000 points),
  // whose coordinates are the longest the appearance streams can carry (T036-FIXES).
  const certificate = largestCertificate();
  assert.ok(certificate.length > 16_000 && certificate.length <= 16_384, `a certificate of ${certificate.length} bytes`);
  for (const box of ['[0 0 14400 14400]', '[-1000000 -1000000 1000000 1000000]']) {
    const base = plainDocument({ page: `/MediaBox ${box}` });
    const revision = await composeSealRevision(maximalRequest(base, 1, { certificateDer: certificate }));
    const update = revision.bytes.length - revision.documentLength;
    const baseSize = lastSection(base).size;
    const text = latin1(revision.bytes);
    let rewritten = 0;
    for (const [num, entry] of lastSection(revision.bytes).entries) {
      if (num < baseSize) rewritten += text.indexOf('endobj\n', entry.offset) + 'endobj\n'.length - entry.offset;
    }
    const pathLines = (text.slice(revision.documentLength).match(/^\S+ \S+ [ml]$/gm) ?? []).length;
    assert.equal(pathLines, 30_000, `${box}: every point of both approvals is drawn`);
    assert.ok(update - rewritten <= UPDATE_REQUEST_BOUND, `${box}: the request part is ${update - rewritten} bytes`);
    assert.ok(update <= UPDATE_BOUND, `${box}: the update is ${update} bytes`);
  }
});

test('[CP-02] a base without a form gains an AcroForm holding one signature field, whose widgets sit in their page /Annots', async () => {
  const base = fixture('agreement-multipage.pdf');
  const parsed = await parsePdf(base);
  assert.ok(parsed.ok);
  const page3 = parsed.report.pages[2].ref[0];
  const recipient2 = { recipient: RECIPIENT_2, ordinal: 2 };
  const request = composeRequest(
    base,
    [
      field('sig_1', 3, { x: 0.1, y: 0.6, width: 0.3, height: 0.06 }),
      field('date_1', 3, { x: 0.5, y: 0.6, width: 0.25, height: 0.04 }, { type: 'date' }),
      field('sig_2', 3, { x: 0.1, y: 0.75, width: 0.3, height: 0.06 }, recipient2),
      field('date_2', 3, { x: 0.5, y: 0.75, width: 0.25, height: 0.04 }, { type: 'date', ...recipient2 }),
    ],
    [
      approval(RECIPIENT_1, [drawn('sig_1', ZIGZAG), dated('date_1')], [{ key: 'date_1', value: '2026-11-17' }]),
      approval(RECIPIENT_2, [typed('sig_2', 'Sam Example'), dated('date_2')], [{ key: 'date_2', value: '2026-11-18' }]),
    ],
  );
  const revision = await composeSealRevision(request);
  const baseSection = lastSection(base);
  const section = lastSection(revision.bytes);
  const objects = sectionObjects(revision.bytes, section);

  const rewritten = [...section.entries.keys()].filter((num) => num < baseSection.size).sort((a, b) => a - b);
  assert.deepEqual(rewritten, [baseSection.root[0], page3].sort((a, b) => a - b), 'only the catalog and page 3 are rewritten');

  const catalog = objects.get(baseSection.root[0]);
  assert.equal(refOf(catalog, 'AcroForm'), revision.objects.acroForm);
  const form = objects.get(revision.objects.acroForm);
  assert.deepEqual(refList(form, 'Fields'), [revision.objects.signatureField]);
  assert.match(form, /\/SigFlags 3\b/);

  const seal = objects.get(revision.objects.signatureField);
  assert.match(seal, /\/FT \/Sig\b/);
  assert.equal(literalOf(seal, 'T'), `opensig-seal-${sha256(base).slice(0, 16)}`, 'the name carries the document digest');
  assert.equal(refOf(seal, 'V'), revision.objects.signature);
  const widgets = refList(seal, 'Kids');
  assert.deepEqual(widgets, [...revision.objects.widgets]);
  assert.equal(widgets.length, 4, 'one widget per field, in manifest order');
  widgets.forEach((widget, index) => {
    const text = objects.get(widget);
    assert.match(text, /\/Type \/Annot/);
    assert.match(text, /\/Subtype \/Widget/);
    assert.equal(refOf(text, 'Parent'), revision.objects.signatureField);
    assert.equal(refOf(text, 'P'), page3);
    assert.match(text, /\/F 132\b/);
    assert.equal(Number(/\/AP << \/N (\d+) 0 R >>/.exec(text)[1]), revision.objects.appearances[index]);
    // Fields 1 and 3 are dates.
    assert.equal(literalOf(text, 'Contents'), index % 2 === 1 ? 'Date from unsigned server time (UTC)' : null);
  });
  assert.deepEqual(refList(objects.get(page3), 'Annots'), widgets, 'page 3 lists the widgets');
});

test('[CP-02] an existing form keeps its fields, keys and flags combined with 3; existing fields stay untouched; a dangling form reference is refused', async () => {
  // Indirect AcroForm (8) with an indirect /Fields array (9); inline page /Annots.
  const first = formDocument({ form: 'indirect', fields: 'indirect', annots: 'inline' });
  const one = await composeSealRevision(simpleRequest(first));
  const oneSection = lastSection(one.bytes);
  const oneObjects = sectionObjects(one.bytes, oneSection);
  assert.equal(one.objects.acroForm, 8, 'the existing AcroForm object is rewritten');
  assert.ok(!oneSection.entries.has(1), 'the catalog is untouched');
  assert.ok(!oneSection.entries.has(9), 'the indirect /Fields array is untouched');
  assert.ok(!oneSection.entries.has(6) && !oneSection.entries.has(11), 'existing fields, the unsigned signature field among them, are untouched');
  const form = oneObjects.get(8);
  assert.deepEqual(refList(form, 'Fields'), [6, 11, one.objects.signatureField], 'existing fields first, then the seal');
  assert.match(form, /\/DA </, 'other AcroForm keys are kept');
  assert.match(form, /\/NeedAppearances true\b/, '/NeedAppearances is left as it is');
  assert.match(form, /\/SigFlags 7\b/, 'the base flags (4) are combined with 3');
  assert.deepEqual(refList(oneObjects.get(3), 'Annots'), [6, 7, 11, ...one.objects.widgets], 'existing annotations first, then the widgets');
  assert.equal(roundTripReason(await parsePdf(one.bytes)), '422 already-signed');

  // Inline AcroForm in the catalog; an indirect page /Annots array (10).
  const second = formDocument({ form: 'inline', fields: 'inline', annots: 'indirect' });
  const two = await composeSealRevision(simpleRequest(second));
  const twoSection = lastSection(two.bytes);
  const twoObjects = sectionObjects(two.bytes, twoSection);
  assert.equal(two.objects.acroForm, 1, 'the inline AcroForm lives in the rewritten catalog');
  assert.ok(!twoSection.entries.has(8) && !twoSection.entries.has(10), 'no other form or array object is rewritten');
  const catalog = twoObjects.get(1);
  assert.deepEqual(refList(catalog, 'Fields'), [6, 11, two.objects.signatureField]);
  assert.match(catalog, /\/SigFlags 7\b/);
  assert.match(catalog, /\/NeedAppearances true\b/);
  assert.deepEqual(refList(twoObjects.get(3), 'Annots'), [6, 7, 11, ...two.objects.widgets]);
  assert.equal(roundTripReason(await parsePdf(two.bytes)), '422 already-signed');

  // A form reference that resolves to nothing is refused, not repaired. The parse service
  // resolves /AcroForm itself and refuses a dangling one as malformed (422, not retryable).
  await assert.rejects(
    composeSealRevision(simpleRequest(plainDocument({ catalog: '/AcroForm 99 0 R' }))),
    (error) => error instanceof ComposeError && error.status === 422 && error.code === 'unsupported_pdf' && error.reason === 'malformed' && error.retryable === false,
    'acroform',
  );
  // It only lists /Fields and /Annots references, so the composer refuses those itself.
  const dangling = [
    [plainDocument({ catalog: '/AcroForm << /Fields 97 0 R >>' }), 'fields'],
    [plainDocument({ page: '/Annots 98 0 R' }), 'annots'],
  ];
  for (const [document, what] of dangling) {
    await assert.rejects(
      composeSealRevision(simpleRequest(document)),
      (error) =>
        error instanceof ComposeError &&
        error.status === 422 &&
        error.code === 'unsupported_pdf' &&
        error.detail === 'dangling_form_reference' &&
        error.details[0].field === what &&
        error.retryable === false,
      what,
    );
  }
});

test('[CP-02] /SigFlags keeps every base bit and adds 3; a value that is not a 32-bit flag word is written as 3', async () => {
  // Request #44 (T036-FIXES): flags are combined with a bitwise OR, never replaced by 3.
  const cases = [
    ['4', 7],
    ['3', 3],
    ['2147483648', 2_147_483_651],
    ['4294967295', 4_294_967_295],
    ['4294967296', 3],
    ['-1', 3],
    ['1.5', 3],
    ['/Four', 3],
  ];
  for (const [base, written] of cases) {
    const document = plainDocument({ catalog: `/AcroForm << /Fields [] /SigFlags ${base} >>` });
    const revision = await composeSealRevision(simpleRequest(document));
    const catalog = sectionObjects(revision.bytes, lastSection(revision.bytes)).get(1);
    assert.equal(Number(/\/SigFlags (\d+)\b/.exec(catalog)?.[1]), written, `/SigFlags ${base}`);
    assert.equal(roundTripReason(await parsePdf(revision.bytes)), '422 already-signed', `/SigFlags ${base} round trip`);
  }

  // An indirect /SigFlags, through the actual parse service and the public entry point
  // (request #45): the report carries a non-negative integer target and nothing else it
  // could name, at the object cap (catalog, AcroForm, /Fields, /SigFlags, page, /Annots),
  // and the flags are combined with 3 exactly as a direct value is. Any other target: 3.
  const indirect = [
    [4, 4, 7],
    [2_147_483_648, 2_147_483_648, 2_147_483_651],
    ['<< /V 4 >>', undefined, 3],
    ['[4]', undefined, 3],
    ['-4', undefined, 3],
  ];
  for (const [body, reported, written] of indirect) {
    const document = sigFlagsDocument(body, { indirect: true });
    const parsed = await parsePdf(document);
    assert.ok(parsed.ok, `indirect ${body} parses`);
    assert.deepEqual(parsed.report.objects['8'], reported === undefined ? undefined : { gen: 0, value: reported }, `indirect ${body}: reported`);
    assert.equal(Object.keys(parsed.report.objects).length, reported === undefined ? 5 : 6, `indirect ${body}: objects`);
    const revision = await composeSealRevision(simpleRequest(document));
    const form = sectionObjects(revision.bytes, lastSection(revision.bytes)).get(6);
    assert.equal(Number(/\/SigFlags (\d+)\b/.exec(form)?.[1]), written, `indirect ${body}: written`);
    assert.doesNotMatch(form, /\/SigFlags \d+ \d+ R/, 'the flags are written directly');
  }
  const control = await composeSealRevision(simpleRequest(sigFlagsDocument(4)));
  assert.match(sectionObjects(control.bytes, lastSection(control.bytes)).get(6), /\/SigFlags 7\b/, 'the direct control');
});

test('[CP-06] equal inputs give identical bytes with no clock or randomness; value order is irrelevant; the seal time changes only /M and the revision identifier', async (t) => {
  const base = fixture('single-page.pdf');
  const parsed = await parsePdf(base);
  assert.ok(parsed.ok);
  const fields = [
    field('sig_1', 1, { x: 0.1, y: 0.7, width: 0.35, height: 0.08 }),
    field('initials_1', 1, { x: 0.5, y: 0.7, width: 0.1, height: 0.05 }),
    field('date_1', 1, { x: 0.65, y: 0.7, width: 0.25, height: 0.05 }, { type: 'date' }),
  ];
  const values = [drawn('sig_1', ZIGZAG), typed('initials_1', 'S.E.'), dated('date_1')];
  const dates = [{ key: 'date_1', value: '2026-11-18' }];
  const request = composeRequest(base, fields, [approval(RECIPIENT_1, values, dates)]);

  t.mock.method(Date, 'now', () => {
    throw new Error('the composer read the clock');
  });
  t.mock.method(Math, 'random', () => {
    throw new Error('the composer used randomness');
  });
  const first = composeFromReport(checkRequest(structuredClone(request)), structuredClone(parsed.report));
  const second = composeFromReport(checkRequest(structuredClone(request)), structuredClone(parsed.report));
  const permuted = composeFromReport(checkRequest({ ...request, approvals: [approval(RECIPIENT_1, [...values].reverse(), dates)] }), parsed.report);
  const later = composeFromReport(checkRequest({ ...request, sealTime: '2026-11-18T10:45:59.999Z' }), parsed.report);
  t.mock.restoreAll();

  assert.ok(Buffer.from(first.bytes).equals(Buffer.from(second.bytes)), 'identical bytes');
  assert.equal(first.digest, second.digest);
  assert.equal(permuted.digest, first.digest, 'values are placed in field-manifest order');
  assert.equal((await composeSealRevision(request)).digest, first.digest, 'the public path composes the same bytes');

  assert.equal(later.bytes.length, first.bytes.length);
  const text = latin1(first.bytes);
  const mAt = text.indexOf('/M (D:', first.documentLength);
  const idAt = text.lastIndexOf('/ID [');
  const inside = (index) => (index >= mAt && index < mAt + '/M (D:20261118093000Z)'.length) || (index >= idAt && index < text.indexOf(']', idAt));
  let differing = 0;
  for (let index = 0; index < first.bytes.length; index += 1) {
    if (first.bytes[index] !== later.bytes[index]) {
      differing += 1;
      assert.ok(inside(index), `byte ${index} differs outside /M and /ID`);
    }
  }
  assert.ok(differing > 0);
  assert.match(latin1(later.bytes), /\/M \(D:20261118104559Z\)/, 'fractions of a second are dropped');
});

test('[CP-06] the composer sources read no clock, randomness, environment, locale or file', () => {
  for (const { name, text } of composeSources()) {
    const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    // Uses of the Date global, not the word in a ruled string such as the date widget's /Contents.
    assert.doesNotMatch(code, /\bnew\s+Date\b|\bDate\s*[.(]|Math\.random|randomBytes|randomUUID|getRandomValues|performance\.|hrtime|process\.env|node:fs|toLocale|Intl\./, `${name} is deterministic`);
  }
});
