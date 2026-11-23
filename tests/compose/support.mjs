// SPDX-License-Identifier: Apache-2.0
//
// Shared helpers for the compose tests (T036). Written from the specification,
// independently of src/cryptograph/compose/: the cross-reference reader, the PDF
// builders and the decimal formatter here share no code with the composer.
//
// - Base documents: the committed T004 synthetic fixtures, plus structural
//   variants generated at runtime (a hybrid file, a file with a prior incremental
//   update, files with an existing AcroForm and annotations). Nothing is
//   downloaded, and nothing generated is written to disk.
// - The seal certificate: a synthetic self-signed RSA-3072 certificate built in
//   memory at runtime with node:crypto and T013's DER encoder. It only sizes the
//   /Contents placeholder; its key pair lives in this process's memory and is
//   never exported, written or reused outside these tests.

import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { concat, contextConstructed, derNull, integer, objectIdentifier, sequence, setOf, tlv } from '../../src/cryptograph/cms/index.ts';

export const REPO = resolve(fileURLToPath(new URL('../..', import.meta.url)));
export const DOCUMENTS = join(REPO, 'fixtures', 'synthetic', 'documents');
export const COMPOSE_SOURCES = join(REPO, 'src', 'cryptograph', 'compose');

export const fixture = (file) => new Uint8Array(readFileSync(join(DOCUMENTS, file)));
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const latin1 = (bytes) => Buffer.from(bytes.buffer, bytes.byteOffset, bytes.length).toString('latin1');
const enc = (text) => Buffer.from(text, 'latin1');

/** Every TypeScript source of the composer, by name. */
export function composeSources() {
  return readdirSync(COMPOSE_SOURCES)
    .filter((name) => name.endsWith('.ts'))
    .sort()
    .map((name) => ({ name, text: readFileSync(join(COMPOSE_SOURCES, name), 'utf8') }));
}

// --- the synthetic seal certificate ------------------------------------------------------------

let keyPair = null;
const certificates = new Map();

/** A synthetic self-signed RSA-3072 (e = 65537) certificate whose subject is `commonName`. */
export function syntheticCertificate(commonName = 'openSig compose test seal') {
  const cached = certificates.get(commonName);
  if (cached) return cached;
  keyPair ??= generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
  const algorithm = sequence(objectIdentifier('1.2.840.113549.1.1.11'), derNull());
  const name = sequence(setOf([sequence(objectIdentifier('2.5.4.3'), tlv(0x0c, enc(commonName)))]));
  const validity = sequence(tlv(0x17, enc('260101000000Z')), tlv(0x17, enc('360101000000Z')));
  const spki = new Uint8Array(keyPair.publicKey.export({ type: 'spki', format: 'der' }));
  const tbs = sequence(contextConstructed(0, integer(2)), integer(1), algorithm, name, validity, name, spki);
  const signature = new Uint8Array(sign('sha256', tbs, keyPair.privateKey));
  const certificate = sequence(tbs, algorithm, tlv(0x03, concat([Uint8Array.of(0), signature])));
  certificates.set(commonName, certificate);
  return certificate;
}

/** A synthetic certificate as close to the 16 KiB limit as a long subject (and issuer) name makes it. */
export function largestCertificate() {
  let length = 7_600;
  const size = syntheticCertificate('C'.repeat(length)).length;
  length += Math.floor((16_384 - size) / 2);
  return syntheticCertificate('C'.repeat(length));
}

// --- requests ----------------------------------------------------------------------------------

export const RECIPIENT_1 = 'recipient-one-000001';
export const RECIPIENT_2 = 'recipient-two-000002';
export const SEAL_TIME = '2026-11-18T09:30:00.000Z';

/** A contract Field. */
export function field(key, page, rect, { type = 'signature', recipient = RECIPIENT_1, ordinal = 1 } = {}) {
  return { key, recipient_id: recipient, recipient_ordinal: ordinal, page, type, rect };
}

/** The ApprovalRecord members the composer reads. */
export function approval(recipient, fieldValues, dateValues = []) {
  return { recipient: { id: recipient }, field_values: fieldValues, date_values: dateValues };
}

export const drawn = (key, strokes) => ({ key, type: 'signature', mode: 'drawn', strokes });
export const typed = (key, text) => ({ key, type: 'signature', mode: 'typed', text });
export const dated = (key) => ({ key, type: 'date' });

/** A zigzag signature: two strokes, five points. */
export const ZIGZAG = [
  [
    [500, 8000],
    [2500, 2000],
    [5000, 8000],
  ],
  [
    [6000, 5000],
    [9500, 5000],
  ],
];

/** A composition request over `document`. */
export function composeRequest(document, fields, approvals, overrides = {}) {
  return {
    document,
    fieldManifest: { schema: 'opensig.field-manifest/1', envelope_id: 'envelope-compose-000001', document_digest: sha256(document), fields },
    approvals,
    sealTime: SEAL_TIME,
    certificateDer: syntheticCertificate(),
    ...overrides,
  };
}

/** The usual one-recipient request: a drawn signature and a date on page `page`. */
export function simpleRequest(document, page = 1, overrides = {}) {
  return composeRequest(
    document,
    [field('sig_1', page, { x: 0.1, y: 0.7, width: 0.35, height: 0.08 }), field('date_1', page, { x: 0.55, y: 0.7, width: 0.3, height: 0.05 }, { type: 'date' })],
    [approval(RECIPIENT_1, [drawn('sig_1', ZIGZAG), dated('date_1')], [{ key: 'date_1', value: '2026-11-18' }])],
    overrides,
  );
}

// --- structural PDF builders -------------------------------------------------------------------

/** An uncompressed stream object body. */
export const streamBody = (dict, data) => `<< ${dict ? `${dict} ` : ''}/Length ${enc(data).length} >>\nstream\n${data}\nendstream`;

const HEADER = '%PDF-1.7\n%\xe2\xe3\xcf\xd3\n';

function objectsOf(bodies) {
  const chunks = [enc(HEADER)];
  let length = chunks[0].length;
  const offsets = [];
  bodies.forEach((body, index) => {
    offsets.push(length);
    const chunk = enc(`${index + 1} 0 obj\n${body}\nendobj\n`);
    chunks.push(chunk);
    length += chunk.length;
  });
  return { chunks, offsets, length };
}

const tableOf = (offsets, head = 'xref\n') => [`${head}0 ${offsets.length + 1}\n`, '0000000000 65535 f \n', ...offsets.map((offset) => `${String(offset).padStart(10, '0')} 00000 n \n`)].join('');

/**
 * A classic one-section document; `bodies[i]` is object i + 1. `size` overrides the
 * trailer /Size; `head` replaces the table's first line (`xref` and its end of line);
 * `lead` is written just before the table, and startxref names the start of `lead`.
 */
export function classicDocument(bodies, { root = 1, trailer = '', finalEol = true, size, head = 'xref\n', lead = '' } = {}) {
  const { chunks, offsets, length } = objectsOf(bodies);
  chunks.push(
    enc(`${lead}${tableOf(offsets, head)}trailer\n<< /Size ${size ?? offsets.length + 1} /Root ${root} 0 R${trailer ? ` ${trailer}` : ''} >>\nstartxref\n${length}\n%%EOF${finalEol ? '\n' : ''}`),
  );
  return new Uint8Array(Buffer.concat(chunks));
}

/**
 * A cross-reference-stream document: `bodies[i]` is object i + 1, then the unfiltered
 * cross-reference stream as the last object, whose header text is `head(num)` (by default
 * `${num} 0 obj`). `lead` is written just before that header, and startxref names the
 * start of `lead`, so the bytes at startxref are `lead` followed by the header.
 */
export function xrefStreamDocument(bodies, { root = 1, head = (num) => `${num} 0 obj`, lead = '' } = {}) {
  const { chunks, offsets, length: objectsEnd } = objectsOf(bodies);
  const self = bodies.length + 1;
  const rows = Buffer.alloc(7 * (self + 1));
  rows[0] = 0;
  rows.writeUInt16BE(0xffff, 5);
  const headerAt = objectsEnd + enc(lead).length;
  [...offsets, headerAt].forEach((offset, index) => {
    const at = 7 * (index + 1);
    rows[at] = 1;
    rows.writeUInt32BE(offset, at + 1);
  });
  chunks.push(
    enc(`${lead}${head(self)}\n<< /Type /XRef /Size ${self + 1} /W [1 4 2] /Root ${root} 0 R /Length ${rows.length} >>\nstream\n`),
    rows,
    enc(`\nendstream\nendobj\nstartxref\n${objectsEnd}\n%%EOF\n`),
  );
  return new Uint8Array(Buffer.concat(chunks));
}

/** A hybrid document: a classic table whose trailer's /XRefStm names a stream listing object 2. */
export function hybridDocument(bodies, { root = 1, trailer = '' } = {}) {
  const { chunks, offsets, length: objectsEnd } = objectsOf(bodies);
  const self = bodies.length + 1;
  const row = Buffer.alloc(7);
  row[0] = 1;
  row.writeUInt32BE(offsets[1], 1);
  const stream = Buffer.concat([enc(`${self} 0 obj\n<< /Type /XRef /Size ${self + 1} /W [1 4 2] /Index [2 1] /Length 7 >>\nstream\n`), row, enc('\nendstream\nendobj\n')]);
  chunks.push(stream);
  offsets.push(objectsEnd);
  const at = objectsEnd + stream.length;
  chunks.push(enc(`${tableOf(offsets)}trailer\n<< /Size ${self + 1} /Root ${root} 0 R /XRefStm ${objectsEnd}${trailer ? ` ${trailer}` : ''} >>\nstartxref\n${at}\n%%EOF\n`));
  return new Uint8Array(Buffer.concat(chunks));
}

/** `base` plus one classic incremental update that adds object `num` with `body` (an Info dictionary). */
export function withPriorUpdate(base, num, body, { root = 1 } = {}) {
  const prev = Number(/startxref\s+(\d+)\s+%%EOF\s*$/.exec(latin1(base).slice(-64))[1]);
  const at = base.length;
  const object = enc(`${num} 0 obj\n${body}\nendobj\n`);
  const tail = enc(`xref\n${num} 1\n${String(at).padStart(10, '0')} 00000 n \ntrailer\n<< /Size ${num + 1} /Root ${root} 0 R /Info ${num} 0 R /Prev ${prev} >>\nstartxref\n${at + object.length}\n%%EOF\n`);
  return new Uint8Array(Buffer.concat([base, object, tail]));
}

const PAGE_TEXT = 'BT /F1 11 Tf 72 720 Td (Synthetic compose fixture.) Tj ET';

/**
 * A one-page document with an existing form: a text field 6 and an unsigned signature
 * field 11 (each its own widget on the page), and a link annotation 7. The AcroForm
 * carries /SigFlags 4 (a reserved bit, so a combination with 3 is visible as 7) and
 * /NeedAppearances true. `form` is 'indirect' (AcroForm object 8) or 'inline';
 * `fields` and `annots` are 'inline' or 'indirect' (arrays 9 and 10).
 */
export function formDocument({ form = 'indirect', fields = 'inline', annots = 'inline' } = {}) {
  const fieldsValue = fields === 'indirect' ? '9 0 R' : '[6 0 R 11 0 R]';
  const annotsValue = annots === 'indirect' ? '10 0 R' : '[6 0 R 7 0 R 11 0 R]';
  const formDict = `<< /Fields ${fieldsValue} /DA (/Helv 0 Tf 0 g) /SigFlags 4 /NeedAppearances true >>`;
  const bodies = [
    `<< /Type /Catalog /Pages 2 0 R /AcroForm ${form === 'indirect' ? '8 0 R' : formDict} >>`,
    '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
    `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /Annots ${annotsValue} >>`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
    streamBody('', PAGE_TEXT),
    '<< /Type /Annot /Subtype /Widget /FT /Tx /T (existing_text) /Rect [72 600 272 620] /P 3 0 R /F 4 >>',
    '<< /Type /Annot /Subtype /Link /Rect [72 560 172 580] /Border [0 0 0] >>',
    formDict,
    '[6 0 R 11 0 R]',
    '[6 0 R 7 0 R 11 0 R]',
    '<< /Type /Annot /Subtype /Widget /FT /Sig /T (unsigned_base) /Rect [300 600 400 620] /P 3 0 R /F 4 >>',
  ];
  return classicDocument(bodies, { trailer: '/ID [<00112233445566778899aabbccddeeff> <00112233445566778899aabbccddeeff>]' });
}

/**
 * An ordinary form whose report reaches the object cap (4 + 2 x pages, request #45): catalog
 * 1 with an indirect AcroForm 6 whose indirect /Fields array 9 holds one unsigned text field
 * 7, also in page 3's indirect /Annots array 10. `sigFlags` is written directly, or, with
 * `indirect`, as object 8 holding it (an integer, or any other body).
 */
export function sigFlagsDocument(sigFlags, { indirect = false } = {}) {
  return classicDocument([
    '<< /Type /Catalog /Pages 2 0 R /AcroForm 6 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
    '<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R /Annots 10 0 R >>',
    streamBody('', PAGE_TEXT),
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
    `<< /Fields 9 0 R /DA (/Helv 0 Tf 0 g) /SigFlags ${indirect ? '8 0 R' : sigFlags} >>`,
    '<< /Type /Annot /Subtype /Widget /FT /Tx /T (existing_text) /Rect [72 600 272 620] /P 3 0 R /F 4 >>',
    indirect ? String(sigFlags) : '<< >>',
    '[7 0 R]',
    '[7 0 R]',
  ]);
}

/** Two pages (3 and 4) whose /Annots is one shared indirect array (object 7) holding link 6. */
export function sharedAnnotsDocument() {
  return classicDocument([
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 612 792] >>',
    '<< /Type /Page /Parent 2 0 R /Contents 5 0 R /Annots 7 0 R >>',
    '<< /Type /Page /Parent 2 0 R /Contents 5 0 R /Annots 7 0 R >>',
    streamBody('', 'q 0.5 w 72 72 m 540 72 l S Q'),
    '<< /Type /Annot /Subtype /Link /Rect [72 560 172 580] /Border [0 0 0] >>',
    '[6 0 R]',
  ]);
}

/** `count` points in 50 strokes, with coordinates spread over 0..10000. */
export function strokesOf(count) {
  return Array.from({ length: 50 }, (_, s) => Array.from({ length: count / 50 }, (_, i) => [(i * 7919 + s * 104729) % 10001, (i * 6007 + s * 3001) % 10001]));
}

/**
 * The largest request the budgets allow on a document of `pageCount` pages: 20 fields,
 * spread over the pages in turn (so min(pageCount, 20) widget pages), 10 per recipient;
 * per approval 15,000 points (10,000 + 5,000 in 50-stroke values) and 8 typed
 * 80-character values; fields across the page width.
 */
export function maximalRequest(document, pageCount, overrides = {}) {
  const fields = [];
  const approvals = [];
  [RECIPIENT_1, RECIPIENT_2].forEach((recipient, a) => {
    const values = [];
    for (let i = 0; i < 10; i += 1) {
      const n = a * 10 + i;
      const key = `f_${n}`;
      fields.push(field(key, (n % pageCount) + 1, { x: 0, y: n * 0.05, width: 0.99999, height: 0.0499 }, { recipient, ordinal: a + 1 }));
      values.push(i === 0 ? drawn(key, strokesOf(10_000)) : i === 1 ? drawn(key, strokesOf(5_000)) : typed(key, 'W'.repeat(80)));
    }
    approvals.push(approval(recipient, values));
  });
  return composeRequest(document, fields, approvals, overrides);
}

/**
 * An adversarial base: 20 pages and the AcroForm's /Fields all name one shared array (5)
 * holding one name of `length` '(' characters, each written back as three bytes (#28),
 * so a maximal request makes the composer copy the array 21 times.
 */
export function adversarialDocument(length) {
  const kids = Array.from({ length: 20 }, (_, i) => `${6 + i} 0 R`).join(' ');
  return classicDocument([
    '<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>',
    `<< /Type /Pages /Kids [${kids}] /Count 20 /MediaBox [0 0 612 792] >>`,
    streamBody('', ''),
    '<< /Fields 5 0 R >>',
    `[/${'#28'.repeat(length)}]`,
    ...Array.from({ length: 20 }, () => '<< /Type /Page /Parent 2 0 R /Contents 3 0 R /Annots 5 0 R >>'),
  ]);
}

/**
 * Two pages (3 and 4) with an indirect /Annots array (6) on page 4 holding link 7;
 * `numbers` places a number entry `/X <value>` on 'catalog', 'page2', 'annots' (as an
 * extra array item) or 'info' (object 8, never reported).
 */
export function numberDocument(numbers = {}) {
  const x = (where) => (numbers[where] === undefined ? '' : ` /X ${numbers[where]}`);
  return classicDocument(
    [
      `<< /Type /Catalog /Pages 2 0 R${x('catalog')} >>`,
      '<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 612 792] >>',
      '<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>',
      `<< /Type /Page /Parent 2 0 R /Contents 5 0 R /Annots 6 0 R${x('page2')} >>`,
      streamBody('', 'q 0.5 w 72 72 m 540 72 l S Q'),
      `[7 0 R${numbers.annots === undefined ? '' : ` ${numbers.annots}`}]`,
      '<< /Type /Annot /Subtype /Link /Rect [72 560 172 580] /Border [0 0 0] >>',
      `<< /Producer (synthetic)${x('info')} >>`,
    ],
    { trailer: '/Info 8 0 R' },
  );
}

/** The bodies of plainDocument (catalog 1, pages 2, page 3, font 4, contents 5). */
export function plainBodies({ page = '', catalog = '', font = '' } = {}) {
  return [
    `<< /Type /Catalog /Pages 2 0 R${catalog ? ` ${catalog}` : ''} >>`,
    '<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>',
    `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R${page ? ` ${page}` : ''} >>`,
    `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding${font ? ` ${font}` : ''} >>`,
    streamBody('', PAGE_TEXT),
  ];
}

/** A plain one-page document (catalog 1, pages 2, page 3, font 4, contents 5). */
export function plainDocument({ trailer = '', finalEol = true, page = '', catalog = '', font = '', size } = {}) {
  return classicDocument(plainBodies({ page, catalog, font }), { trailer, finalEol, size });
}

/** Two pages (3 and 6) sharing contents 5; `page1` and `page2` add entries to each. */
export function twoPageDocument({ page1 = '', page2 = '', catalog = '' } = {}) {
  return classicDocument([
    `<< /Type /Catalog /Pages 2 0 R${catalog ? ` ${catalog}` : ''} >>`,
    '<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 /MediaBox [0 0 612 792] >>',
    `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R${page1 ? ` ${page1}` : ''} >>`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
    streamBody('', PAGE_TEXT),
    `<< /Type /Page /Parent 2 0 R /Contents 5 0 R${page2 ? ` ${page2}` : ''} >>`,
  ]);
}

// --- an independent cross-reference reader -----------------------------------------------------

const TRAILER_REF = (dict, key) => {
  const match = new RegExp(`/${key}\\s+(\\d+)\\s+(\\d+)\\s+R`).exec(dict);
  return match ? [Number(match[1]), Number(match[2])] : null;
};
const TRAILER_INT = (dict, key) => {
  const match = new RegExp(`/${key}\\s+(\\d+)`).exec(dict);
  return match ? Number(match[1]) : null;
};
const TRAILER_ID = (dict) => {
  const match = /\/ID\s*\[\s*<([0-9A-Fa-f]*)>\s*<([0-9A-Fa-f]*)>\s*\]/.exec(dict);
  return match ? [match[1].toLowerCase(), match[2].toLowerCase()] : null;
};

/** The offset after the last `startxref` of `bytes`. */
export function tailOffset(bytes) {
  const match = /startxref[\s]+(\d+)[\s]+%%EOF[\s]*$/.exec(latin1(bytes).slice(-128));
  if (!match) throw new Error('no startxref at the end of the file');
  return Number(match[1]);
}

/**
 * Read the cross-reference section at `at`: its kind, its in-use entries
 * (number -> {offset, gen}) and its trailer fields.
 */
export function readSection(bytes, at) {
  const text = latin1(bytes);
  const entries = new Map();
  if (text.startsWith('xref', at)) {
    let pos = at + 4;
    const header = /[\r\n ]*(\d+) (\d+)[ ]*\r?\n/y;
    for (;;) {
      const rest = /[\r\n ]*/y;
      rest.lastIndex = pos;
      rest.exec(text);
      if (text.startsWith('trailer', rest.lastIndex)) {
        pos = rest.lastIndex;
        break;
      }
      header.lastIndex = pos;
      const head = header.exec(text);
      if (!head) throw new Error(`bad subsection header at ${pos}`);
      pos = header.lastIndex;
      for (let k = 0; k < Number(head[2]); k += 1) {
        const entry = /^(\d{10}) (\d{5}) ([nf])(\r\n| \n| \r)$/.exec(text.slice(pos, pos + 20));
        if (!entry) throw new Error(`bad 20-byte entry at ${pos}`);
        if (entry[3] === 'n') entries.set(Number(head[1]) + k, { offset: Number(entry[1]), gen: Number(entry[2]) });
        pos += 20;
      }
    }
    const dict = text.slice(pos, text.indexOf('startxref', pos));
    return { kind: 'table', at, entries, dict, ...trailerFields(dict) };
  }
  const head = /^(\d+) (\d+) obj\s*<<([\s\S]*?)>>\s*stream\r?\n/.exec(text.slice(at, at + 4096));
  if (!head || !/\/Type\s*\/XRef/.test(head[3])) throw new Error(`no cross-reference stream at ${at}`);
  const dict = head[3];
  const widths = /\/W\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(dict).slice(1, 4).map(Number);
  const size = TRAILER_INT(dict, 'Size');
  const indexMatch = /\/Index\s*\[([\d\s]*)\]/.exec(dict);
  const index = indexMatch ? indexMatch[1].trim().split(/\s+/).map(Number) : [0, size];
  const length = TRAILER_INT(dict, 'Length');
  if (/\/Filter/.test(dict)) throw new Error('this reader takes uncompressed cross-reference streams only');
  const dataStart = at + head[0].length;
  const data = bytes.subarray(dataStart, dataStart + length);
  const field = (row, from, width) => {
    let value = 0;
    for (let i = 0; i < width; i += 1) value = value * 256 + data[row + from + i];
    return value;
  };
  const rowLength = widths[0] + widths[1] + widths[2];
  let row = 0;
  for (let i = 0; i < index.length; i += 2) {
    for (let k = 0; k < index[i + 1]; k += 1, row += rowLength) {
      const type = widths[0] === 0 ? 1 : field(row, 0, widths[0]);
      if (type === 1) entries.set(index[i] + k, { offset: field(row, widths[0], widths[1]), gen: field(row, widths[0] + widths[1], widths[2]) });
    }
  }
  return { kind: 'stream', at, self: Number(head[1]), entries, dict, widths, index, ...trailerFields(dict) };
}

function trailerFields(dict) {
  return {
    size: TRAILER_INT(dict, 'Size'),
    prev: TRAILER_INT(dict, 'Prev'),
    root: TRAILER_REF(dict, 'Root'),
    info: TRAILER_REF(dict, 'Info'),
    id: TRAILER_ID(dict),
    xrefStm: TRAILER_INT(dict, 'XRefStm'),
  };
}

/** The last section of `bytes`. */
export const lastSection = (bytes) => readSection(bytes, tailOffset(bytes));

/** The text of object `num` written at `offset`, from `num gen obj` to before `endobj`. */
export function objectText(bytes, num, entry) {
  const text = latin1(bytes);
  const head = `${num} ${entry.gen} obj`;
  if (!text.startsWith(head, entry.offset)) throw new Error(`object ${num} is not at offset ${entry.offset}`);
  const end = text.indexOf('endobj', entry.offset);
  return text.slice(entry.offset + head.length, end).trim();
}

/** Every object of a section, by number, as text. */
export function sectionObjects(bytes, section) {
  const out = new Map();
  for (const [num, entry] of section.entries) if (!(section.kind === 'stream' && num === section.self)) out.set(num, objectText(bytes, num, entry));
  return out;
}

/** The reference numbers listed in `/Key [ ... ]` of a dictionary text. */
export function refList(text, key) {
  const match = new RegExp(`/${key}\\s*\\[([^\\]]*)\\]`).exec(text);
  if (!match) return null;
  return [...match[1].matchAll(/(\d+)\s+(\d+)\s+R/g)].map((m) => Number(m[1]));
}

/** The numbers of `/Key [ ... ]` in a dictionary text. */
export function numberList(text, key) {
  const match = new RegExp(`/${key}\\s*\\[([^\\]]*)\\]`).exec(text);
  return match ? match[1].trim().split(/\s+/).map(Number) : null;
}

/** The object number of `/Key n g R` in a dictionary text. */
export function refOf(text, key) {
  const match = new RegExp(`/${key}\\s+(\\d+)\\s+(\\d+)\\s+R`).exec(text);
  return match ? Number(match[1]) : null;
}

// --- an independent exact decimal --------------------------------------------------------------

/** `numerator / 10^scale` as the shortest exact decimal, computed with BigInt. */
export function exactDecimal(numerator, scale) {
  const value = BigInt(numerator);
  const unit = 10n ** BigInt(scale);
  const sign = value < 0n ? '-' : '';
  const magnitude = value < 0n ? -value : value;
  const whole = magnitude / unit;
  let fraction = (magnitude % unit).toString().padStart(scale, '0');
  while (fraction.endsWith('0')) fraction = fraction.slice(0, -1);
  return `${sign}${whole}${fraction ? `.${fraction}` : ''}`;
}

/** A plain decimal (as the composer writes numbers) in micro units, as a BigInt. */
export function micro(text) {
  const match = /^(-?)(\d+)(?:\.(\d{1,6}))?$/.exec(text);
  if (!match) throw new Error(`not a plain decimal with at most six places: ${text}`);
  const value = BigInt(match[2]) * 1_000_000n + BigInt((match[3] ?? '').padEnd(6, '0') || '0');
  return match[1] === '-' ? -value : value;
}

/** The decoded text of the literal string after `/Key` in a dictionary text (escapes \( \) \\ only). */
export function literalOf(text, key) {
  const at = text.indexOf(`/${key} (`);
  if (at < 0) return null;
  let out = '';
  for (let i = at + key.length + 3; i < text.length; i += 1) {
    const char = text[i];
    if (char === '\\') {
      out += text[i + 1];
      i += 1;
    } else if (char === ')') {
      return out;
    } else {
      out += char;
    }
  }
  throw new Error(`unterminated literal string after /${key}`);
}

/** Assert-friendly: the parse-service outcome of composed bytes is the structural round trip. */
export function roundTripReason(outcome) {
  return outcome.ok ? 'accepted' : `${outcome.status} ${outcome.reason}`;
}
