#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig deterministic synthetic fixture generator (T004).
//
//   node scripts/gen-fixtures.mjs                 write the committed set into fixtures/synthetic/
//   node scripts/gen-fixtures.mjs --check         verify fixtures/synthetic/ equals the generator output
//   node scripts/gen-fixtures.mjs --out <dir> [--with-large] [--check]
//                                                 write (or check) the set in another directory;
//                                                 --with-large adds the on-demand size-boundary documents
//
// Output layout (relative to the output directory):
//   documents/<name>.pdf        synthetic PDF documents and structural variants
//   documents/manifest.json     one record per document: kind, digest, size, declared page
//                               geometry, expected outcome and, for malformed variants, the defect
//   identities/identities.json  synthetic tenants, operators, services and recipients
//
// Every byte is a pure function of this file: no clock, no randomness, no locale and no
// environment input, and no compression (so the output does not depend on the zlib build).
// The documents contain no keys, no signature values, no images and no embedded fonts; text
// uses the standard-14 Helvetica font, not embedded. Identities use reserved domains only
// (.test and example.com) and carry no credentials.
//
// The two size-boundary documents (exactly 10 MiB, and 10 MiB + 1 byte) are not committed:
// they are generated on demand (--out <dir> --with-large, or generateDocument()) and the
// manifest records their digests, so on-demand output is still verifiable.
//
// Exit status: 0 success, 1 check found drift, 2 usage error.

import { createHash } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const DEFAULT_OUT = join(REPO_ROOT, 'fixtures', 'synthetic');
export const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;
export const MAX_DOCUMENT_PAGES = 50;
export const DOCUMENTS_DIR = 'documents';
export const IDENTITIES_DIR = 'identities';
export const DOCUMENTS_MANIFEST = 'manifest.json';
export const IDENTITIES_FILE = 'identities.json';

// ---------------------------------------------------------------------------
// PDF primitives
// ---------------------------------------------------------------------------

const LETTER = Object.freeze([0, 0, 612, 792]);
const A4_LANDSCAPE = Object.freeze([0, 0, 842, 595]);
const BINARY_COMMENT = Buffer.from([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]);
const FONT_DICT = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>';
const BYTERANGE_PLACEHOLDER = '[0 0000000000 0000000000 0000000000]';
const SIGNATURE_CONTENTS_BYTES = 1024;

const latin1 = (text) => Buffer.from(text, 'latin1');

function assertAscii(text) {
  if (!/^[\x0a\x20-\x7e]*$/.test(text)) throw new Error('fixture object text must be printable ASCII');
  return text;
}

/** A PDF literal string from printable ASCII. */
function pdfText(text) {
  if (!/^[\x20-\x7e]*$/.test(text)) throw new Error(`fixture text must be printable ASCII: ${JSON.stringify(text)}`);
  return `(${text.replace(/[\\()]/g, (c) => `\\${c}`)})`;
}

function labelHex(label, byteLength) {
  return createHash('sha256').update(`opensig-fixture:${label}`).digest('hex').slice(0, byteLength * 2);
}

function fileId(name) {
  const id = labelHex(`id:${name}`, 16);
  return `[<${id}> <${id}>]`;
}

function infoDict(title) {
  return `<< /Title ${pdfText(title)} /Producer ${pdfText('openSig synthetic fixture generator')} >>`;
}

/** An uncompressed stream object body. */
function streamBody(dictEntries, data) {
  const payload = typeof data === 'string' ? latin1(assertAscii(data)) : data;
  const head = `<< ${dictEntries ? `${dictEntries} ` : ''}/Length ${payload.length} >>\nstream\n`;
  return Buffer.concat([latin1(head), payload, latin1('\nendstream')]);
}

function textContent(lines, { x = 72, y = 720, size = 11, leading = 15 } = {}) {
  const ops = ['BT', `/F1 ${size} Tf`, `${leading} TL`, `${x} ${y} Td`];
  lines.forEach((line, index) => {
    if (index > 0) ops.push('T*');
    ops.push(`${pdfText(line)} Tj`);
  });
  ops.push('ET');
  return ops.join('\n');
}

function boxContent(x, y, width, height) {
  return `q 0.5 w ${x} ${y} ${width} ${height} re S Q`;
}

/** Objects numbered 1..N in allocation order; every allocated number must be set. */
function objectTable() {
  const bodies = [];
  return {
    alloc() {
      bodies.push(null);
      return bodies.length;
    },
    set(num, body) {
      if (bodies[num - 1] !== null) throw new Error(`object ${num} is not an open allocation`);
      bodies[num - 1] = body;
    },
    add(body) {
      bodies.push(body);
      return bodies.length;
    },
    entries() {
      return bodies.map((body, index) => {
        if (body === null) throw new Error(`object ${index + 1} was allocated but never set`);
        return { num: index + 1, body };
      });
    },
  };
}

function normalizeRotate(value) {
  if (!Number.isInteger(value) || value % 90 !== 0) throw new Error(`/Rotate must be a multiple of 90, got ${value}`);
  return ((value % 360) + 360) % 360;
}

/**
 * Build a page tree. A node is either { kids: [...], mediaBox?, rotate? } or a leaf
 * { content(page) -> string, mediaBox?, rotate?, extra? }. /MediaBox and /Rotate are
 * written only where a node declares them, so leaves inherit them as declared.
 * Returns { root, leaves, geometry } with geometry in the contract's PageGeometry
 * shape (displayed size after /Rotate) plus the effective media box.
 */
function buildPageTree(table, tree, fontNum) {
  const leaves = [];
  const geometry = [];

  const walk = (node, parentNum, inherited) => {
    const num = table.alloc();
    const own = [];
    if (node.mediaBox) own.push(`/MediaBox [${node.mediaBox.join(' ')}]`);
    if (node.rotate !== undefined) own.push(`/Rotate ${node.rotate}`);
    const ownText = own.length > 0 ? ` ${own.join(' ')}` : '';
    const parentText = parentNum === null ? '' : ` /Parent ${parentNum} 0 R`;
    const effective = {
      mediaBox: node.mediaBox ?? inherited.mediaBox,
      rotate: node.rotate ?? inherited.rotate,
    };

    if (node.kids) {
      const kids = node.kids.map((kid) => walk(kid, num, effective));
      const count = kids.reduce((sum, kid) => sum + kid.count, 0);
      const kidRefs = kids.map((kid) => `${kid.num} 0 R`).join(' ');
      table.set(num, `<< /Type /Pages${parentText} /Kids [${kidRefs}] /Count ${count}${ownText} >>`);
      return { num, count };
    }

    if (!effective.mediaBox) throw new Error('every page needs an effective /MediaBox');
    const rotate = normalizeRotate(effective.rotate ?? 0);
    const [x1, y1, x2, y2] = effective.mediaBox;
    const width = x2 - x1;
    const height = y2 - y1;
    const page = {
      number: geometry.length + 1,
      width: rotate % 180 === 0 ? width : height,
      height: rotate % 180 === 0 ? height : width,
      rotate,
      media_box: [...effective.mediaBox],
    };
    geometry.push(page);
    const contentNum = table.add(streamBody('', node.content(page)));
    const extra = node.extra ? ` ${node.extra}` : '';
    table.set(
      num,
      `<< /Type /Page${parentText}${ownText} /Resources << /Font << /F1 ${fontNum} 0 R >> >> /Contents ${contentNum} 0 R${extra} >>`,
    );
    leaves.push(num);
    return { num, count: 1 };
  };

  const root = walk(tree, null, { mediaBox: null, rotate: undefined });
  return { root: root.num, leaves, geometry };
}

/** Classic cross-reference table serialization. Objects must be numbered 1..N. */
function writeClassic(entries, trailerEntries) {
  const chunks = [];
  let length = 0;
  const push = (chunk) => {
    const buffer = typeof chunk === 'string' ? latin1(chunk) : chunk;
    chunks.push(buffer);
    length += buffer.length;
  };
  push('%PDF-1.7\n');
  push(BINARY_COMMENT);
  const offsets = [];
  for (const { num, body } of entries) {
    offsets[num] = length;
    push(`${num} 0 obj\n`);
    push(typeof body === 'string' ? assertAscii(body) : body);
    push('\nendobj\n');
  }
  const size = entries.length + 1;
  const xrefOffset = length;
  const lines = [`xref\n0 ${size}\n`, '0000000000 65535 f \n'];
  for (let num = 1; num < size; num += 1) lines.push(`${String(offsets[num]).padStart(10, '0')} 00000 n \n`);
  push(lines.join(''));
  push(`trailer\n<< /Size ${size} ${trailerEntries} >>\nstartxref\n${xrefOffset}\n%%EOF\n`);
  return Buffer.concat(chunks);
}

/**
 * Cross-reference stream serialization (PDF 1.5+), uncompressed. Dictionary objects not
 * named in `topLevel` are packed into one object stream; stream objects stay top level.
 */
function writeXrefStream(entries, trailerEntries, topLevel) {
  const packed = entries.filter((entry) => typeof entry.body === 'string' && !topLevel.has(entry.num));
  const loose = entries.filter((entry) => !packed.includes(entry));
  const objstmNum = entries.length + 1;
  const xrefNum = entries.length + 2;
  const size = entries.length + 3;

  const pairs = [];
  const bodies = [];
  const packedIndex = new Map();
  let relative = 0;
  packed.forEach((entry, index) => {
    pairs.push(`${entry.num} ${relative}`);
    bodies.push(assertAscii(entry.body));
    packedIndex.set(entry.num, index);
    relative += entry.body.length + 1;
  });
  const header = `${pairs.join(' ')}\n`;
  const objstm = streamBody(`/Type /ObjStm /N ${packed.length} /First ${header.length}`, header + bodies.join('\n'));

  const chunks = [];
  let length = 0;
  const push = (chunk) => {
    const buffer = typeof chunk === 'string' ? latin1(chunk) : chunk;
    chunks.push(buffer);
    length += buffer.length;
  };
  push('%PDF-1.7\n');
  push(BINARY_COMMENT);
  const offsets = new Map();
  for (const { num, body } of [...loose, { num: objstmNum, body: objstm }]) {
    offsets.set(num, length);
    push(`${num} 0 obj\n`);
    push(typeof body === 'string' ? assertAscii(body) : body);
    push('\nendobj\n');
  }

  const xrefOffset = length;
  const table = Buffer.alloc(size * 7);
  const put = (num, type, field2, field3) => {
    const at = num * 7;
    table[at] = type;
    table.writeUInt32BE(field2, at + 1);
    table.writeUInt16BE(field3, at + 5);
  };
  put(0, 0, 0, 0xffff);
  for (const [num, offset] of offsets) put(num, 1, offset, 0);
  for (const [num, index] of packedIndex) put(num, 2, objstmNum, index);
  put(xrefNum, 1, xrefOffset, 0);

  push(`${xrefNum} 0 obj\n`);
  push(streamBody(`/Type /XRef /Size ${size} /W [1 4 2] ${trailerEntries}`, table));
  push('\nendobj\n');
  push(`startxref\n${xrefOffset}\n%%EOF\n`);
  return Buffer.concat(chunks);
}

/** Catalog, font, page tree and info for an ordinary document. */
function composeDocument(name, title, tree) {
  const table = objectTable();
  const catalog = table.alloc();
  const font = table.add(FONT_DICT);
  const pages = buildPageTree(table, tree, font);
  table.set(catalog, `<< /Type /Catalog /Pages ${pages.root} 0 R >>`);
  const info = table.add(infoDict(title));
  const trailer = `/Root ${catalog} 0 R /Info ${info} 0 R /ID ${fileId(name)}`;
  return { table, catalog, info, pages, trailer };
}

function singlePageTree(lines) {
  return { mediaBox: LETTER, kids: [{ content: () => textContent(lines) }] };
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

const AGREEMENT_TITLE = 'Synthetic Services Agreement';

function agreementTree() {
  const body = (lines) => textContent(lines, { y: 680 });
  return {
    mediaBox: LETTER,
    kids: [
      {
        content: () =>
          [
            textContent([AGREEMENT_TITLE], { y: 720, size: 18 }),
            body([
              'Synthetic test fixture generated by openSig. It has no legal effect.',
              'Parties (synthetic): Alpha Synthetic Holdings, alpha.test, and',
              'Example Customer Ltd, example.com.',
              '',
              '1. Scope. The supplier provides synthetic document processing services',
              '   for automated tests of the openSig signing flow.',
              '2. Term. The agreement starts on approval by both recipients and ends',
              '   when the test run completes.',
              '3. Fees. No fees are payable. All amounts in this fixture are zero.',
            ]),
          ].join('\n'),
      },
      {
        content: () =>
          [
            textContent([`${AGREEMENT_TITLE} - page 2`], { y: 720, size: 14 }),
            body([
              '4. Confidentiality. This fixture contains no confidential information.',
              '5. Data. No personal data, health information or real identities appear',
              '   in this document. Every party and address is synthetic.',
              '6. Governing terms. This fixture is not governed by any jurisdiction.',
              '7. Counterparts. Each recipient approves the same frozen document bytes.',
            ]),
          ].join('\n'),
      },
      {
        content: () =>
          [
            textContent([`${AGREEMENT_TITLE} - approvals`], { y: 720, size: 14 }),
            textContent(['Recipient 1 (ordinal 1) signature: recipient.one@example.com'], { y: 660 }),
            boxContent(72, 580, 288, 64),
            textContent(['Date (server-filled)'], { x: 396, y: 660 }),
            boxContent(396, 612, 144, 32),
            textContent(['Recipient 2 (ordinal 2) signature: recipient.two@alpha.test'], { y: 520 }),
            boxContent(72, 440, 288, 64),
            textContent(['Date (server-filled)'], { x: 396, y: 520 }),
            boxContent(396, 472, 144, 32),
            textContent(['Dates are filled by the server as unsigned server time.'], { y: 400, size: 9 }),
          ].join('\n'),
      },
    ],
  };
}

function rotatedContent(page) {
  const [x1, , , y2] = page.media_box;
  return textContent(
    [`Rotated page fixture: page ${page.number}`, `Effective /Rotate ${page.rotate}, displayed ${page.width} x ${page.height} points`],
    { x: x1 + 72, y: y2 - 72 },
  );
}

/**
 * Page 1 inherits /Rotate 90 and the media box from the root; page 2 inherits /Rotate 270
 * from an intermediate node; page 3 overrides /Rotate 180; page 4 has its own landscape
 * media box and /Rotate 0; page 5 has a media box with a non-zero origin and /Rotate -90.
 */
function rotatedTree() {
  return {
    mediaBox: LETTER,
    rotate: 90,
    kids: [
      { content: rotatedContent },
      { rotate: 270, kids: [{ content: rotatedContent }, { rotate: 180, content: rotatedContent }] },
      { mediaBox: A4_LANDSCAPE, rotate: 0, content: rotatedContent },
      { mediaBox: [36, 36, 648, 828], rotate: -90, content: rotatedContent },
    ],
  };
}

/** Pages in groups of ten under intermediate nodes, so the count spans a nested tree. */
function pageCountTree(total) {
  const kids = [];
  for (let first = 0; first < total; first += 10) {
    const group = [];
    for (let index = first; index < Math.min(total, first + 10); index += 1) {
      group.push({ content: () => textContent([`Synthetic page-count fixture: page ${index + 1} of ${total}`]) });
    }
    kids.push({ kids: group });
  }
  return { mediaBox: LETTER, kids };
}

function classicDocument(name, title, tree) {
  const doc = composeDocument(name, title, tree);
  return { buffer: writeClassic(doc.table.entries(), doc.trailer), pages: doc.pages.geometry };
}

function buildAgreementXrefStream(name) {
  const doc = composeDocument(name, AGREEMENT_TITLE, agreementTree());
  const buffer = writeXrefStream(doc.table.entries(), doc.trailer, new Set([doc.info]));
  return { buffer, pages: doc.pages.geometry };
}

function buildEncryptedFlag(name) {
  const doc = composeDocument(
    name,
    'Synthetic encrypted-flag fixture',
    singlePageTree(['Encrypted-flag fixture: the trailer names an /Encrypt dictionary.', 'The content itself is not encrypted.']),
  );
  // /O and /U are fixed structural placeholders derived from labels, not from any password.
  const encrypt = doc.table.add(
    `<< /Filter /Standard /V 2 /R 3 /Length 128 /P -3904 /O <${labelHex('encrypt:O', 32)}> /U <${labelHex('encrypt:U', 32)}> >>`,
  );
  return { buffer: writeClassic(doc.table.entries(), `${doc.trailer} /Encrypt ${encrypt} 0 R`), pages: doc.pages.geometry };
}

function buildAlreadySigned(name) {
  const table = objectTable();
  const catalog = table.alloc();
  const font = table.add(FONT_DICT);
  const field = table.alloc();
  const signature = table.alloc();
  const pages = buildPageTree(
    table,
    {
      mediaBox: LETTER,
      kids: [
        {
          content: () => textContent(['Already-signed fixture: an existing signature field with a zero-filled value.']),
          extra: `/Annots [${field} 0 R]`,
        },
      ],
    },
    font,
  );
  table.set(
    field,
    `<< /Type /Annot /Subtype /Widget /FT /Sig /T ${pdfText('SyntheticSignature1')} /V ${signature} 0 R /Rect [0 0 0 0] /F 132 /P ${pages.leaves[0]} 0 R >>`,
  );
  table.set(
    signature,
    `<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange ${BYTERANGE_PLACEHOLDER} /Contents <${'0'.repeat(SIGNATURE_CONTENTS_BYTES * 2)}> /Reason ${pdfText('Synthetic structural fixture; the signature value is all zeros')} >>`,
  );
  table.set(catalog, `<< /Type /Catalog /Pages ${pages.root} 0 R /AcroForm << /Fields [${field} 0 R] /SigFlags 3 >> >>`);
  const info = table.add(infoDict('Synthetic already-signed fixture'));
  const buffer = writeClassic(table.entries(), `/Root ${catalog} 0 R /Info ${info} 0 R /ID ${fileId(name)}`);

  // Point /ByteRange at the real layout: everything except the /Contents hex string.
  const text = buffer.toString('latin1');
  const at = text.indexOf(BYTERANGE_PLACEHOLDER);
  if (at < 0 || text.indexOf(BYTERANGE_PLACEHOLDER, at + 1) >= 0) throw new Error('ByteRange placeholder must occur exactly once');
  const open = text.indexOf('/Contents <', at) + '/Contents '.length;
  const close = text.indexOf('>', open) + 1;
  const range = `[0 ${open} ${close} ${buffer.length - close}`;
  if (range.length + 1 > BYTERANGE_PLACEHOLDER.length) throw new Error('ByteRange does not fit its placeholder');
  latin1(`${range.padEnd(BYTERANGE_PLACEHOLDER.length - 1, ' ')}]`).copy(buffer, at);
  return { buffer, pages: pages.geometry };
}

/** A single-page document padded with an unreferenced stream to exactly `target` bytes. */
function buildPadded(name, title, target) {
  const line = latin1('opensig synthetic padding stream for upload size-limit checks ...\n');
  const build = (padLength) => {
    const doc = composeDocument(name, title, singlePageTree([`${title}: exactly ${target} bytes in total.`]));
    const padding = Buffer.alloc(padLength);
    padding.fill(line);
    doc.table.add(streamBody('', padding));
    return { buffer: writeClassic(doc.table.entries(), doc.trailer), pages: doc.pages.geometry };
  };
  let padLength = target - 2048;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const built = build(padLength);
    if (built.buffer.length === target) return built;
    padLength += target - built.buffer.length;
  }
  throw new Error(`could not pad ${name} to exactly ${target} bytes`);
}

// Malformed variants. Each derives from single-page.pdf (except the page-tree cycle, which
// needs its own objects) and introduces exactly one declared structural defect.

function patchCopy(base, at, replacement) {
  const copy = Buffer.from(base);
  const bytes = latin1(replacement);
  copy.set(bytes, at);
  return copy;
}

function objectSpan(text, marker) {
  const at = text.indexOf(marker);
  if (at < 0) throw new Error(`marker not found: ${marker}`);
  const header = text.lastIndexOf(' 0 obj\n', at);
  const numStart = text.lastIndexOf('\n', header) + 1;
  const num = Number(text.slice(numStart, header));
  const end = text.indexOf('\nendobj', at);
  return { num, start: numStart, end };
}

function classicXref(text) {
  const startxref = Number(/startxref\n(\d+)\n%%EOF\n$/.exec(text)[1]);
  const head = /^xref\n0 (\d+)\n/.exec(text.slice(startxref));
  return { startxref, size: Number(head[1]), entriesStart: startxref + head[0].length };
}

const MALFORMED = {
  'missing-header': (base) => patchCopy(base, 0, '%NOT-PDF'),
  truncated: (base) => Buffer.from(base.subarray(0, Math.floor(base.length / 2))),
  'startxref-out-of-range': (base) => {
    const text = base.toString('latin1');
    const { startxref } = classicXref(text);
    const tail = `startxref\n${startxref}\n%%EOF\n`;
    return Buffer.concat([base.subarray(0, base.length - tail.length), latin1(`startxref\n${base.length + 4096}\n%%EOF\n`)]);
  },
  'xref-offset-mismatch': (base) => {
    const text = base.toString('latin1');
    const page = objectSpan(text, '<< /Type /Page /Parent');
    const { entriesStart } = classicXref(text);
    const at = entriesStart + page.num * 20;
    const offset = Number(text.slice(at, at + 10));
    if (offset !== page.start) throw new Error('xref entry does not match the page object');
    return patchCopy(base, at, String(offset + 3).padStart(10, '0'));
  },
  'unterminated-dictionary': (base) => {
    const text = base.toString('latin1');
    const page = objectSpan(text, '<< /Type /Page /Parent');
    if (text.slice(page.end - 2, page.end) !== '>>') throw new Error('page dictionary does not end the object');
    return patchCopy(base, page.end - 2, '  ');
  },
  'stream-length-overrun': (base) => {
    const text = base.toString('latin1');
    const match = /\/Length (\d+) >>\nstream\n/.exec(text);
    const overrun = '9'.repeat(match[1].length);
    if (Number(overrun) <= Number(match[1])) throw new Error('stream length cannot be overrun at the same width');
    return patchCopy(base, match.index + '/Length '.length, overrun);
  },
  'xref-prev-cycle': (base) => {
    const text = base.toString('latin1');
    const { size } = classicXref(text);
    const root = /\/Root (\d+) 0 R/.exec(text)[1];
    const info = Number(/\/Info (\d+) 0 R/.exec(text)[1]);
    const object = `${info} 0 obj\n${infoDict('Synthetic xref /Prev cycle fixture')}\nendobj\n`;
    const xrefOffset = base.length + object.length;
    const update =
      `${object}xref\n0 1\n0000000000 65535 f \n${info} 1\n${String(base.length).padStart(10, '0')} 00000 n \n` +
      `trailer\n<< /Size ${size} /Root ${root} 0 R /Info ${info} 0 R /ID ${fileId('single-page.pdf')} /Prev ${xrefOffset} >>\n` +
      `startxref\n${xrefOffset}\n%%EOF\n`;
    return Buffer.concat([base, latin1(update)]);
  },
};

function buildPageTreeCycle(name) {
  const table = objectTable();
  const catalog = table.alloc();
  const font = table.add(FONT_DICT);
  const pages = table.alloc();
  const page = table.alloc();
  const content = table.add(streamBody('', textContent(['Page-tree cycle fixture: the root /Kids array lists the root itself.'])));
  table.set(pages, `<< /Type /Pages /Kids [${page} 0 R ${pages} 0 R] /Count 2 /MediaBox [${LETTER.join(' ')}] >>`);
  table.set(page, `<< /Type /Page /Parent ${pages} 0 R /Resources << /Font << /F1 ${font} 0 R >> >> /Contents ${content} 0 R >>`);
  table.set(catalog, `<< /Type /Catalog /Pages ${pages} 0 R >>`);
  const info = table.add(infoDict('Synthetic page-tree cycle fixture'));
  return { buffer: writeClassic(table.entries(), `/Root ${catalog} 0 R /Info ${info} 0 R /ID ${fileId(name)}`), pages: null };
}

const ACCEPT = Object.freeze({ outcome: 'accept', reason: null });
const reject = (reason) => Object.freeze({ outcome: 'reject', reason });

function malformedSpec(defect, description) {
  return {
    file: `malformed-${defect}.pdf`,
    kind: 'malformed',
    committed: true,
    xref: null,
    expect: reject('malformed'),
    defect,
    derived_from: 'single-page.pdf',
    description,
    build: (name, get) => ({ buffer: MALFORMED[defect](get('single-page.pdf').buffer), pages: null }),
  };
}

/** Every document the generator knows, in manifest order. */
export const DOCUMENT_SPECS = Object.freeze([
  {
    file: 'agreement-multipage.pdf',
    kind: 'multi-page',
    committed: true,
    xref: 'table',
    expect: ACCEPT,
    defect: null,
    derived_from: null,
    description: 'Three-page synthetic corporate agreement with signature and date boxes for two recipients on page 3',
    build: (name) => classicDocument(name, AGREEMENT_TITLE, agreementTree()),
  },
  {
    file: 'agreement-xref-stream.pdf',
    kind: 'multi-page',
    committed: true,
    xref: 'stream',
    expect: ACCEPT,
    defect: null,
    derived_from: null,
    description: 'The same agreement serialized with an uncompressed cross-reference stream and object stream',
    build: (name) => buildAgreementXrefStream(name),
  },
  {
    file: 'rotated-pages.pdf',
    kind: 'rotated',
    committed: true,
    xref: 'table',
    expect: ACCEPT,
    defect: null,
    derived_from: null,
    description: 'Five pages with inherited and overridden /Rotate and /MediaBox, a landscape page, a non-zero media box origin and /Rotate -90',
    build: (name) => classicDocument(name, 'Synthetic rotated-pages fixture', rotatedTree()),
  },
  {
    file: 'single-page.pdf',
    kind: 'single-page',
    committed: true,
    xref: 'table',
    expect: ACCEPT,
    defect: null,
    derived_from: null,
    description: 'Minimal valid single-page document; the base of the malformed variants',
    build: (name) =>
      classicDocument(name, 'Synthetic single-page fixture', singlePageTree(['Synthetic single-page fixture generated by openSig.'])),
  },
  {
    file: 'pages-50.pdf',
    kind: 'page-limit',
    committed: true,
    xref: 'table',
    expect: ACCEPT,
    defect: null,
    derived_from: null,
    description: 'Exactly 50 pages (the limit) in a nested page tree',
    build: (name) => classicDocument(name, 'Synthetic 50-page fixture', pageCountTree(50)),
  },
  {
    file: 'pages-51.pdf',
    kind: 'page-limit',
    committed: true,
    xref: 'table',
    expect: reject('page-limit'),
    defect: null,
    derived_from: null,
    description: '51 pages, one over the limit, in a nested page tree',
    build: (name) => classicDocument(name, 'Synthetic 51-page fixture', pageCountTree(51)),
  },
  {
    file: 'encrypted-flag.pdf',
    kind: 'encrypted-flag',
    committed: true,
    xref: 'table',
    expect: reject('encrypted'),
    defect: null,
    derived_from: null,
    description: 'Single page whose trailer names a Standard security handler /Encrypt dictionary',
    build: (name) => buildEncryptedFlag(name),
  },
  {
    file: 'already-signed.pdf',
    kind: 'already-signed',
    committed: true,
    xref: 'table',
    expect: reject('already-signed'),
    defect: null,
    derived_from: null,
    description: 'Single page with an AcroForm signature field whose /Sig value has a real /ByteRange and a zero-filled /Contents',
    build: (name) => buildAlreadySigned(name),
  },
  malformedSpec('missing-header', 'The %PDF- header is replaced by same-length bytes; every offset is unchanged'),
  malformedSpec('truncated', 'The first half of single-page.pdf: no cross-reference section, trailer or %%EOF'),
  malformedSpec('startxref-out-of-range', 'startxref points beyond the end of the file'),
  malformedSpec('xref-offset-mismatch', 'The page object cross-reference entry is shifted by three bytes'),
  malformedSpec('unterminated-dictionary', 'The page dictionary closing >> is replaced by spaces'),
  malformedSpec('stream-length-overrun', 'The content stream /Length overruns the stream data'),
  malformedSpec('xref-prev-cycle', 'An appended update whose trailer /Prev names its own cross-reference section'),
  {
    file: 'malformed-page-tree-cycle.pdf',
    kind: 'malformed',
    committed: true,
    xref: null,
    expect: reject('malformed'),
    defect: 'page-tree-cycle',
    derived_from: null,
    description: 'The root page tree node lists itself in /Kids',
    build: (name) => buildPageTreeCycle(name),
  },
  {
    file: 'size-at-limit.pdf',
    kind: 'size-limit',
    committed: false,
    xref: 'table',
    expect: ACCEPT,
    defect: null,
    derived_from: null,
    description: `Valid single page padded to exactly ${MAX_DOCUMENT_BYTES} bytes (the limit); generated on demand`,
    build: (name) => buildPadded(name, 'Synthetic size-at-limit fixture', MAX_DOCUMENT_BYTES),
  },
  {
    file: 'oversized.pdf',
    kind: 'oversized',
    committed: false,
    xref: 'table',
    expect: reject('size-limit'),
    defect: null,
    derived_from: null,
    description: `Valid single page padded to ${MAX_DOCUMENT_BYTES + 1} bytes, one over the limit; generated on demand`,
    build: (name) => buildPadded(name, 'Synthetic oversized fixture', MAX_DOCUMENT_BYTES + 1),
  },
]);

const built = new Map();

function buildCached(file) {
  if (!built.has(file)) {
    const spec = DOCUMENT_SPECS.find((candidate) => candidate.file === file);
    if (!spec) throw new Error(`unknown fixture document: ${file}`);
    built.set(file, spec.build(file, buildCached));
  }
  return built.get(file);
}

/** The bytes of one document (a fresh copy). */
export function generateDocument(file) {
  return Buffer.from(buildCached(file).buffer);
}

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function json(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

/** The documents manifest (always describes every document, committed or not). */
export function buildDocumentsManifest() {
  return {
    schema: 'opensig.fixtures.documents.v1',
    generator: 'scripts/gen-fixtures.mjs',
    synthetic: true,
    notice:
      'Synthetic documents generated deterministically for tests. No keys, no signature values, no images and no embedded fonts. Documents with committed=false are generated on demand.',
    limits: { max_bytes: MAX_DOCUMENT_BYTES, max_pages: MAX_DOCUMENT_PAGES },
    documents: DOCUMENT_SPECS.map((spec) => {
      const { buffer, pages } = buildCached(spec.file);
      return {
        file: spec.file,
        kind: spec.kind,
        committed: spec.committed,
        bytes: buffer.length,
        sha256: sha256(buffer),
        xref: spec.xref,
        pages,
        expect: { ...spec.expect },
        defect: spec.defect,
        derived_from: spec.derived_from,
        description: spec.description,
      };
    }),
  };
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

function tenantIdentities(key, label, recipients) {
  return {
    id: `tenant_${key}_synthetic01`,
    name: `${label} Synthetic Holdings (synthetic)`,
    oidc: {
      issuer: `https://issuer.${key}.test`,
      audience: `opensig-local-${key}`,
      claims: { tenant: 'opensig_tenant', roles: 'opensig_roles', principal_kind: 'opensig_principal_kind' },
    },
    operators: [
      {
        id: `op_${key}_sender_000001`,
        subject: `${key}-sender-0001`,
        kind: 'human-operator',
        roles: ['sender'],
        display_name: `${label} Sender (synthetic)`,
        email: `sender@${key}.test`,
      },
      {
        id: `op_${key}_admin_0000001`,
        subject: `${key}-admin-0001`,
        kind: 'human-operator',
        roles: ['tenant_admin'],
        display_name: `${label} Tenant Admin (synthetic)`,
        email: `admin@${key}.test`,
      },
      {
        id: `svc_${key}_hermes_000001`,
        subject: `${key}-hermes-service`,
        kind: 'service',
        roles: ['service'],
        display_name: `${label} Hermes service (synthetic)`,
        email: null,
      },
    ],
    recipients,
  };
}

export function buildIdentities() {
  return {
    schema: 'opensig.fixtures.identities.v1',
    generator: 'scripts/gen-fixtures.mjs',
    synthetic: true,
    notice:
      'Synthetic identities for local tests only. Reserved domains (.test and example.com); no keys, credentials or real people.',
    reserved_domains: ['.test', 'example.com'],
    tenants: [
      tenantIdentities('alpha', 'Alpha', [
        {
          id: 'rcp_alpha_one_00000001',
          ordinal: 1,
          role: 'Approver',
          display_name: 'Recipient One (synthetic)',
          email: 'recipient.one@example.com',
        },
        {
          id: 'rcp_alpha_two_00000001',
          ordinal: 2,
          role: 'Countersigner',
          display_name: 'Recipient Two (synthetic)',
          email: 'recipient.two@alpha.test',
        },
      ]),
      tenantIdentities('beta', 'Beta', [
        {
          id: 'rcp_beta_one_000000001',
          ordinal: 1,
          role: 'Approver',
          display_name: 'Recipient Three (synthetic)',
          email: 'recipient.three@example.com',
        },
        {
          id: 'rcp_beta_two_000000001',
          ordinal: 2,
          role: 'Countersigner',
          display_name: 'Recipient Four (synthetic)',
          email: 'recipient.four@beta.test',
        },
      ]),
    ],
  };
}

// ---------------------------------------------------------------------------
// Fixture set: generate, write, check
// ---------------------------------------------------------------------------

/**
 * The complete fixture set as Map<relative path, Buffer>. On-demand documents are
 * included only when `includeLarge` is set; the manifest always describes all of them.
 */
export function generateFixtureSet({ includeLarge = false } = {}) {
  const files = new Map();
  for (const spec of DOCUMENT_SPECS) {
    if (spec.committed || includeLarge) files.set(`${DOCUMENTS_DIR}/${spec.file}`, buildCached(spec.file).buffer);
  }
  files.set(`${DOCUMENTS_DIR}/${DOCUMENTS_MANIFEST}`, json(buildDocumentsManifest()));
  files.set(`${IDENTITIES_DIR}/${IDENTITIES_FILE}`, json(buildIdentities()));
  return files;
}

export function writeFixtureSet(outDir, set) {
  for (const [path, buffer] of set) {
    const target = join(outDir, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, buffer);
  }
}

function listFiles(dir, base = dir) {
  let names;
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const files = [];
  for (const name of names.sort()) {
    const abs = join(dir, name);
    if (statSync(abs).isDirectory()) files.push(...listFiles(abs, base));
    else files.push(relative(base, abs).split('\\').join('/'));
  }
  return files;
}

/** Problems as [{ problem: 'missing'|'differs'|'unexpected', path }], sorted by path. */
export function checkFixtureDir(outDir, set) {
  const problems = [];
  for (const [path, expected] of set) {
    let actual;
    try {
      actual = readFileSync(join(outDir, path));
    } catch {
      problems.push({ problem: 'missing', path });
      continue;
    }
    if (!actual.equals(expected)) problems.push({ problem: 'differs', path });
  }
  for (const sub of [DOCUMENTS_DIR, IDENTITIES_DIR]) {
    for (const path of listFiles(join(outDir, sub))) {
      const rel = `${sub}/${path}`;
      if (!set.has(rel)) problems.push({ problem: 'unexpected', path: rel });
    }
  }
  return problems.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE = 'usage: node scripts/gen-fixtures.mjs [--check] [--out <dir> [--with-large]]';

function parseCli(argv) {
  const options = { out: null, withLarge: false, check: false, help: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--check' && !options.check) options.check = true;
    else if (arg === '--with-large' && !options.withLarge) options.withLarge = true;
    else if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--out' && options.out === null && index + 1 < argv.length && argv[index + 1] !== '') {
      options.out = argv[index + 1];
      index += 1;
    } else return { error: `unknown, repeated or incomplete argument: ${arg}` };
  }
  return { options };
}

function samePath(a, b) {
  try {
    return realpathSync(a) === realpathSync(b);
  } catch {
    return resolve(a) === resolve(b);
  }
}

function main(argv) {
  const parsed = parseCli(argv);
  if (parsed.error || parsed.options.help) {
    if (parsed.error) process.stderr.write(`gen-fixtures: ${parsed.error}\n`);
    process.stderr.write(`gen-fixtures: ${USAGE}\n`);
    process.exitCode = parsed.error ? 2 : 0;
    return;
  }
  const { options } = parsed;
  const outDir = options.out === null ? DEFAULT_OUT : resolve(options.out);
  if (options.withLarge && samePath(outDir, DEFAULT_OUT)) {
    process.stderr.write('gen-fixtures: --with-large writes uncommitted documents and needs --out <dir> outside fixtures/synthetic/\n');
    process.exitCode = 2;
    return;
  }
  const set = generateFixtureSet({ includeLarge: options.withLarge });
  if (options.check) {
    const problems = checkFixtureDir(outDir, set);
    for (const { problem, path } of problems) process.stdout.write(`gen-fixtures: ${problem} ${path}\n`);
    process.stdout.write(`gen-fixtures: ${problems.length === 0 ? 'PASS' : 'FAIL'} problems=${problems.length} expected=${set.size}\n`);
    process.exitCode = problems.length === 0 ? 0 : 1;
    return;
  }
  writeFixtureSet(outDir, set);
  process.stdout.write(`gen-fixtures: wrote ${set.size} files to ${outDir}\n`);
  process.exitCode = 0;
}

function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) main(process.argv.slice(2));
