// SPDX-License-Identifier: Apache-2.0
//
// T033 parser-limits PL-06, PL-07 and PL-16: detection of existing digital signatures and
// of active content (JavaScript, Launch actions, embedded files, RichMedia; and, A-008 P08,
// XFA forms, 3D artwork with /OnInstantiate, Screen annotations and Rendition actions),
// including detections hidden in object streams or behind #xx-escaped names. JBIG2 and
// JPX image filters are reported as features. All variants are generated at test runtime.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parsePdf } from '../../src/pdf/service.ts';
import { basicObjects, classicPdf, streamObject, xrefStreamPdf } from './pdf-builder.mjs';
import { fixtureBytes } from './support.mjs';

async function expectRejection(cases, reason) {
  const names = Object.keys(cases);
  const outcomes = await Promise.all(names.map((name) => parsePdf(cases[name].bytes)));
  names.forEach((name, index) => {
    const outcome = outcomes[index];
    assert.equal(outcome.ok, false, `${name} must be rejected`);
    assert.equal(outcome.reason, reason, `${name}: ${outcome.detail}`);
    assert.equal(outcome.status, 422);
    assert.equal(outcome.code, 'unsupported_pdf');
    if (cases[name].detections) assert.deepEqual(outcome.detections, cases[name].detections, `${name} detections`);
  });
}

test('[PL-06] an existing digital signature is rejected as already signed', async () => {
  const signatureDict = '<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0 10 20 30] /Contents <00> >>';
  await expectRejection(
    {
      'already-signed fixture': { bytes: fixtureBytes('already-signed.pdf'), detections: ['signature'] },
      'signature dictionary inside an object stream': {
        bytes: xrefStreamPdf([...basicObjects(), signatureDict], { packed: [[1, 2, 3, 4]] }),
        detections: ['signature'],
      },
      'untyped dictionary with /ByteRange and /Contents': {
        bytes: classicPdf([...basicObjects({ catalog: '/X 4 0 R' }), '<< /ByteRange [0 1 2 3] /Contents <00> >>']),
      },
      'document timestamp': { bytes: classicPdf([...basicObjects(), '<< /Type /DocTimeStamp /ByteRange [0 1 2 3] /Contents <00> >>']) },
      'signed signature field': {
        bytes: classicPdf([
          ...basicObjects({ catalog: '/AcroForm << /Fields [4 0 R] >>' }),
          '<< /FT /Sig /T (F1) /V 5 0 R >>',
          '<< /Filter /Adobe.PPKLite >>',
        ]),
      },
      'DocMDP permissions': { bytes: classicPdf([...basicObjects({ catalog: '/Perms << /DocMDP 4 0 R >>' }), '<< /Filter /Adobe.PPKLite >>']) },
      'UR3 permissions': { bytes: classicPdf([...basicObjects({ catalog: '/Perms << /UR3 4 0 R >>' }), '<< /Filter /Adobe.PPKLite >>']) },
    },
    'already-signed',
  );

  // An empty (unsigned) signature field is not a signature: accepted and reported.
  const unsigned = await parsePdf(classicPdf([...basicObjects({ catalog: '/AcroForm 4 0 R' }), '<< /Fields [5 0 R] >>', '<< /FT /Sig /T (Empty) >>']));
  assert.equal(unsigned.ok, true, unsigned.ok ? '' : unsigned.detail);
  assert.ok(unsigned.report.features.includes('unsigned-signature-field'));
  assert.ok(unsigned.report.features.includes('acroform'));
  assert.ok(unsigned.report.objects['4'], 'an indirect AcroForm is reported for composition');
});

test('[PL-07] JavaScript, Launch, embedded files and RichMedia are rejected as active content', async () => {
  await expectRejection(
    {
      'OpenAction JavaScript': {
        bytes: classicPdf([...basicObjects({ catalog: '/OpenAction 4 0 R' }), '<< /S /JavaScript /JS (void 0) >>']),
        detections: ['javascript'],
      },
      'escaped /J#61vaScript action name': {
        bytes: classicPdf([...basicObjects({ catalog: '/OpenAction 4 0 R' }), '<< /Type /Action /S /J#61vaScript >>']),
        detections: ['javascript'],
      },
      'document-level JavaScript name tree': {
        bytes: classicPdf([...basicObjects({ catalog: '/Names << /JavaScript 4 0 R >>' }), '<< /Names [] >>']),
        detections: ['javascript'],
      },
      'page additional-action script in an object stream': {
        bytes: xrefStreamPdf(basicObjects({ page: '/AA << /O << /JS (void 0) >> >>' }), { packed: [[1, 2, 3]] }),
        detections: ['javascript'],
      },
      'Launch action': {
        bytes: classicPdf(basicObjects({ page: '/AA << /O << /S /Launch /F (synthetic.test) >> >>' })),
        detections: ['launch'],
      },
      'embedded file name tree': {
        bytes: classicPdf([...basicObjects({ catalog: '/Names << /EmbeddedFiles 4 0 R >>' }), '<< /Names [] >>']),
        detections: ['embedded-file'],
      },
      'embedded file stream': {
        bytes: classicPdf([...basicObjects({ catalog: '/X 4 0 R' }), streamObject('/Type /EmbeddedFile', 'synthetic').toString('latin1')]),
        detections: ['embedded-file'],
      },
      'file specification with /EF': {
        bytes: classicPdf([...basicObjects({ catalog: '/X << /Type /Filespec /F (a.test) /EF << /F 4 0 R >> >>' }), '<< /Y 1 >>']),
        detections: ['embedded-file'],
      },
      'RichMedia annotation': {
        bytes: classicPdf([...basicObjects({ page: '/Annots [4 0 R]' }), '<< /Type /Annot /Subtype /RichMedia /Rect [0 0 10 10] >>']),
        detections: ['rich-media'],
      },
      'escaped /R#69chMedia subtype': {
        bytes: classicPdf([...basicObjects({ page: '/Annots [4 0 R]' }), '<< /Type /Annot /Subtype /R#69chMedia /Rect [0 0 10 10] >>']),
        detections: ['rich-media'],
      },
      'several kinds at once': {
        bytes: classicPdf([...basicObjects({ catalog: '/OpenAction << /S /Launch >> /Names << /EmbeddedFiles 4 0 R /JavaScript 4 0 R >>' }), '<< /Names [] >>']),
        detections: ['embedded-file', 'javascript', 'launch'],
      },
    },
    'active-content',
  );
});

test('[PL-07] JBIG2 and JPX image filters are reported as features, not decoded', async () => {
  const image = (filter) =>
    streamObject(`/Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 1 /Filter /${filter}`, 'synthetic-undecoded').toString('latin1');
  const bytes = classicPdf([
    ...basicObjects({ page: '/Resources << /XObject << /I1 4 0 R /I2 5 0 R >> >>' }),
    image('JBIG2Decode'),
    image('JPXDecode'),
  ]);
  const outcome = await parsePdf(bytes);
  assert.equal(outcome.ok, true, outcome.ok ? '' : outcome.detail);
  assert.ok(outcome.report.features.includes('jbig2'));
  assert.ok(outcome.report.features.includes('jpx'));
  assert.equal(outcome.report.stats.inflated_bytes, 0, 'image streams are not decoded');
});

test('[PL-16] XFA forms, 3D artwork with /OnInstantiate, Screen annotations and Rendition actions are rejected as active content', async () => {
  // An XFA template carrying script as XML inside a stream: no /JS key anywhere (A-008 P08).
  const xfa =
    '<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template><subform><event activity="initialize">' +
    '<script contentType="application/x-javascript">void 0</script></event></subform></template></xdp:xdp>';
  await expectRejection(
    {
      'AcroForm /XFA stream with an x-javascript template': {
        bytes: classicPdf([...basicObjects({ catalog: '/AcroForm << /Fields [] /XFA 4 0 R >>' }), streamObject('', xfa).toString('latin1')]),
        detections: ['xfa'],
      },
      'AcroForm /XFA packet array': {
        bytes: classicPdf([...basicObjects({ catalog: '/AcroForm 4 0 R' }), '<< /Fields [] /XFA [(template) 5 0 R] >>', streamObject('', xfa).toString('latin1')]),
        detections: ['xfa'],
      },
      '3D annotation whose artwork runs a stream on /OnInstantiate': {
        bytes: classicPdf([
          ...basicObjects({ page: '/Annots [4 0 R]' }),
          '<< /Type /Annot /Subtype /3D /Rect [0 0 10 10] /3DD 5 0 R >>',
          streamObject('/Type /3D /Subtype /U3D /OnInstantiate 6 0 R', 'synthetic-u3d').toString('latin1'),
          streamObject('', 'void 0').toString('latin1'),
        ]),
        detections: ['3d'],
      },
      '3D stream with /OnInstantiate reached from the catalog only': {
        bytes: classicPdf([
          ...basicObjects({ catalog: '/X 4 0 R' }),
          streamObject('/Subtype /PRC /OnInstantiate 5 0 R', 'synthetic-prc').toString('latin1'),
          streamObject('', 'void 0').toString('latin1'),
        ]),
        detections: ['3d'],
      },
      'escaped /3#44 annotation subtype': {
        bytes: classicPdf([...basicObjects({ page: '/Annots [4 0 R]' }), '<< /Type /Annot /Subtype /3#44 /Rect [0 0 10 10] >>']),
        detections: ['3d'],
      },
      'Screen annotation': {
        bytes: classicPdf([...basicObjects({ page: '/Annots [4 0 R]' }), '<< /Type /Annot /Subtype /Screen /Rect [0 0 10 10] >>']),
        detections: ['screen'],
      },
      'escaped /Sc#72een subtype in an object stream': {
        bytes: xrefStreamPdf([...basicObjects({ page: '/Annots [4 0 R]' }), '<< /Type /Annot /Subtype /Sc#72een /Rect [0 0 10 10] >>'], { packed: [[1, 2, 3, 4]] }),
        detections: ['screen'],
      },
      'Rendition action on page open': {
        bytes: classicPdf(basicObjects({ page: '/AA << /O << /S /Rendition /OP 0 >> >>' })),
        detections: ['rendition'],
      },
      'Rendition action as the document open action, in an object stream': {
        bytes: xrefStreamPdf(basicObjects({ catalog: '/OpenAction << /S /Rendition /OP 0 >>' }), { packed: [[1, 2, 3]] }),
        detections: ['rendition'],
      },
      'Screen annotation with a Rendition action': {
        bytes: classicPdf([...basicObjects({ page: '/Annots [4 0 R]' }), '<< /Type /Annot /Subtype /Screen /Rect [0 0 10 10] /A << /S /Rendition /OP 0 >> >>']),
        detections: ['rendition', 'screen'],
      },
    },
    'active-content',
  );

  // Controls: the same structures without the active-content keys are accepted.
  for (const bytes of [
    classicPdf(basicObjects({ catalog: '/AcroForm << /Fields [] >>' })),
    classicPdf([...basicObjects({ page: '/Annots [4 0 R]' }), '<< /Type /Annot /Subtype /Square /Rect [0 0 10 10] >>']),
    classicPdf(basicObjects({ page: '/AA << /O << /S /GoTo /D [3 0 R /Fit] >> >>' })),
  ]) {
    const outcome = await parsePdf(bytes);
    assert.equal(outcome.ok, true, outcome.ok ? '' : `${outcome.reason} ${outcome.detail}`);
  }
});
