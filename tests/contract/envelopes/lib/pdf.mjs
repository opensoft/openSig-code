// SPDX-License-Identifier: Apache-2.0
//
// Envelope conformance harness (T006): synthetic PDF documents built in-test
// from structural descriptors, and an independent structural inspector that
// checks what the builder claims. Nothing is downloaded and no document file
// is committed: fixtures/synthetic/envelopes/ holds descriptors only.
//
// The documents carry no keys and no real signatures. The "signature" feature
// writes an existing-signature dictionary whose /Contents placeholder is all
// zero bytes, which is what post-signing revision detection looks for.
//
// Descriptor (every key optional):
//   variant     "pdf" (default) | "not-a-pdf" | "truncated"
//   pages       page count, 1..200 (default 1)
//   rotate      /Rotate on every page dictionary: a number, or one value per page
//   mediaBox    page-level /MediaBox (default [0 0 612 792]) unless inherit.mediaBox
//   cropBox     page-level /CropBox on every page
//   inherit     { rotate?, mediaBox?, cropBox? } written on the /Pages node only
//   xref        "table" (default) | "stream" (an uncompressed cross-reference stream)
//   features    any of PDF_FEATURES
//   targetBytes exact output size; a whitespace content stream on page 1 pads it

const DESCRIPTOR_KEYS = new Set(['variant', 'pages', 'rotate', 'mediaBox', 'cropBox', 'inherit', 'xref', 'features', 'targetBytes']);
const INHERIT_KEYS = new Set(['rotate', 'mediaBox', 'cropBox']);
const ROTATIONS = new Set([0, 90, 180, 270]);

export const DEFAULT_MEDIA_BOX = Object.freeze([0, 0, 612, 792]);

export const PDF_FEATURES = Object.freeze([
  'encrypt',
  'signature',
  'javascript-open-action',
  'launch-open-action',
  'embedded-file',
  'rich-media',
  'xfa',
]);

const SIG_CONTENTS_HEX_BYTES = 256;
const BYTE_RANGE_SLOT = 11;

function fail(message) {
  throw new Error(`pdf descriptor: ${message}`);
}

function isBox(value) {
  return Array.isArray(value) && value.length === 4 && value.every((n) => typeof n === 'number' && Number.isFinite(n)) && value[2] > value[0] && value[3] > value[1];
}

function normalize(descriptor) {
  const d = descriptor ?? {};
  if (typeof d !== 'object' || Array.isArray(d)) fail('must be an object');
  for (const key of Object.keys(d)) if (!DESCRIPTOR_KEYS.has(key)) fail(`unknown key ${key}`);
  const variant = d.variant ?? 'pdf';
  if (!['pdf', 'not-a-pdf', 'truncated'].includes(variant)) fail(`unknown variant ${variant}`);
  const pages = d.pages ?? 1;
  if (!Number.isInteger(pages) || pages < 1 || pages > 200) fail('pages must be an integer in 1..200');
  let rotations = new Array(pages).fill(null);
  if (d.rotate !== undefined) {
    rotations = Array.isArray(d.rotate) ? [...d.rotate] : new Array(pages).fill(d.rotate);
    if (rotations.length !== pages) fail('rotate list length must equal pages');
    for (const r of rotations) if (!ROTATIONS.has(r)) fail(`rotate ${r} is not 0, 90, 180 or 270`);
  }
  const inherit = d.inherit ?? {};
  if (typeof inherit !== 'object' || Array.isArray(inherit)) fail('inherit must be an object');
  for (const key of Object.keys(inherit)) if (!INHERIT_KEYS.has(key)) fail(`unknown inherit key ${key}`);
  if (inherit.rotate !== undefined && !ROTATIONS.has(inherit.rotate)) fail('inherit.rotate must be 0, 90, 180 or 270');
  if (inherit.mediaBox !== undefined && !isBox(inherit.mediaBox)) fail('inherit.mediaBox must be [llx lly urx ury]');
  if (inherit.cropBox !== undefined && !isBox(inherit.cropBox)) fail('inherit.cropBox must be [llx lly urx ury]');
  if (d.mediaBox !== undefined && !isBox(d.mediaBox)) fail('mediaBox must be [llx lly urx ury]');
  if (d.cropBox !== undefined && !isBox(d.cropBox)) fail('cropBox must be [llx lly urx ury]');
  if (d.mediaBox !== undefined && inherit.mediaBox !== undefined) fail('mediaBox and inherit.mediaBox are exclusive');
  const xref = d.xref ?? 'table';
  if (!['table', 'stream'].includes(xref)) fail(`unknown xref form ${xref}`);
  const features = [...(d.features ?? [])];
  for (const f of features) if (!PDF_FEATURES.includes(f)) fail(`unknown feature ${f}`);
  if (new Set(features).size !== features.length) fail('duplicate feature');
  if (features.includes('javascript-open-action') && features.includes('launch-open-action')) fail('only one open action');
  if (d.targetBytes !== undefined && (!Number.isInteger(d.targetBytes) || d.targetBytes < 1)) fail('targetBytes must be a positive integer');
  if (variant !== 'pdf' && d.targetBytes !== undefined) fail('targetBytes applies to the pdf variant only');
  return { variant, pages, rotations, inherit, mediaBox: d.mediaBox, cropBox: d.cropBox, xref, features, targetBytes: d.targetBytes };
}

function box(values) {
  return `[${values.join(' ')}]`;
}

function hexOf(label, bytes) {
  // Deterministic synthetic filler, not key material: repeated label bytes as hex.
  const out = [];
  for (let i = 0; i < bytes; i += 1) out.push((label.charCodeAt(i % label.length) & 0xff).toString(16).padStart(2, '0'));
  return out.join('');
}

/** Assemble the document for a normalized descriptor with `padding` bytes of whitespace content (or none when null). */
function assemble(desc, padding) {
  const bodies = [null];
  const alloc = () => {
    bodies.push(null);
    return bodies.length - 1;
  };
  const set = (id, body) => {
    bodies[id] = body;
  };

  const catalogId = alloc();
  const pagesId = alloc();
  const pageIds = desc.rotations.map(() => alloc());
  const contentIds = desc.rotations.map(() => alloc());
  const padId = padding === null ? null : alloc();

  const catalogExtra = [];
  const page1Annots = [];
  const acroFields = [];
  let acroExtra = '';
  const trailerExtra = [];

  if (desc.features.includes('javascript-open-action')) catalogExtra.push('/OpenAction << /S /JavaScript /JS (void 0) >>');
  if (desc.features.includes('launch-open-action')) catalogExtra.push('/OpenAction << /S /Launch /F (placeholder.txt) >>');
  if (desc.features.includes('embedded-file')) {
    const efId = alloc();
    const fsId = alloc();
    const data = 'synthetic attachment\n';
    set(efId, `<< /Type /EmbeddedFile /Length ${data.length} >>\nstream\n${data}\nendstream`);
    set(fsId, `<< /Type /Filespec /F (attachment.txt) /UF (attachment.txt) /EF << /F ${efId} 0 R >> >>`);
    catalogExtra.push(`/Names << /EmbeddedFiles << /Names [(attachment.txt) ${fsId} 0 R] >> >>`);
  }
  if (desc.features.includes('rich-media')) {
    const annotId = alloc();
    set(annotId, '<< /Type /Annot /Subtype /RichMedia /Rect [72 72 144 144] /RichMediaContent << /Assets << /Names [] >> >> >>');
    page1Annots.push(`${annotId} 0 R`);
  }
  if (desc.features.includes('xfa')) {
    const xfaId = alloc();
    const xml = '<?xml version="1.0"?><xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"></xdp:xdp>';
    set(xfaId, `<< /Length ${xml.length} >>\nstream\n${xml}\nendstream`);
    acroExtra += ` /XFA ${xfaId} 0 R`;
  }
  if (desc.features.includes('signature')) {
    const sigId = alloc();
    const fieldId = alloc();
    const slots = new Array(4).fill('0'.padEnd(BYTE_RANGE_SLOT, ' ')).join('');
    set(
      sigId,
      `<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [${slots}] /Contents <${'0'.repeat(SIG_CONTENTS_HEX_BYTES * 2)}> >>`,
    );
    set(fieldId, `<< /Type /Annot /Subtype /Widget /FT /Sig /T (seal_1) /V ${sigId} 0 R /Rect [0 0 0 0] /F 132 /P ${pageIds[0]} 0 R >>`);
    acroFields.push(`${fieldId} 0 R`);
    page1Annots.push(`${fieldId} 0 R`);
    acroExtra += ' /SigFlags 3';
  }
  if (acroFields.length > 0 || acroExtra !== '') catalogExtra.push(`/AcroForm << /Fields [${acroFields.join(' ')}]${acroExtra} >>`);
  if (desc.features.includes('encrypt')) {
    const encId = alloc();
    set(encId, `<< /Filter /Standard /V 1 /R 2 /O <${hexOf('synthetic-owner-entry', 32)}> /U <${hexOf('synthetic-user-entry', 32)}> /P -3904 >>`);
    trailerExtra.push(`/Encrypt ${encId} 0 R`, `/ID [<${hexOf('synthetic-id-a', 16)}> <${hexOf('synthetic-id-b', 16)}>]`);
  }

  set(catalogId, `<< /Type /Catalog /Pages ${pagesId} 0 R${catalogExtra.map((e) => ` ${e}`).join('')} >>`);
  const inherited = [];
  if (desc.inherit.mediaBox) inherited.push(`/MediaBox ${box(desc.inherit.mediaBox)}`);
  if (desc.inherit.cropBox) inherited.push(`/CropBox ${box(desc.inherit.cropBox)}`);
  if (desc.inherit.rotate !== undefined) inherited.push(`/Rotate ${desc.inherit.rotate}`);
  set(
    pagesId,
    `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageIds.length}${inherited.map((e) => ` ${e}`).join('')} >>`,
  );
  desc.rotations.forEach((rotate, i) => {
    const parts = [`/Type /Page /Parent ${pagesId} 0 R`];
    if (!desc.inherit.mediaBox) parts.push(`/MediaBox ${box(desc.mediaBox ?? DEFAULT_MEDIA_BOX)}`);
    if (desc.cropBox) parts.push(`/CropBox ${box(desc.cropBox)}`);
    if (rotate !== null) parts.push(`/Rotate ${rotate}`);
    parts.push('/Resources << >>');
    parts.push(i === 0 && padId !== null ? `/Contents [${contentIds[i]} 0 R ${padId} 0 R]` : `/Contents ${contentIds[i]} 0 R`);
    if (i === 0 && page1Annots.length > 0) parts.push(`/Annots [${page1Annots.join(' ')}]`);
    set(pageIds[i], `<< ${parts.join(' ')} >>`);
    const content = `q 0.5 g 72 72 144 36 re f Q\n% synthetic page ${i + 1}\n`;
    set(contentIds[i], `<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
  });
  if (padId !== null) set(padId, `<< /Length ${padding} >>\nstream\n${' '.repeat(padding)}\nendstream`);

  const chunks = [Buffer.from('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n', 'latin1')];
  let offset = chunks[0].length;
  const offsets = [0];
  for (let id = 1; id < bodies.length; id += 1) {
    if (bodies[id] === null) throw new Error(`object ${id} has no body`);
    const chunk = Buffer.from(`${id} 0 obj\n${bodies[id]}\nendobj\n`, 'latin1');
    offsets.push(offset);
    chunks.push(chunk);
    offset += chunk.length;
  }
  const trailerKeys = [`/Root ${catalogId} 0 R`, ...trailerExtra];
  if (desc.xref === 'table') {
    const lines = [`xref\n0 ${bodies.length}\n`, '0000000000 65535 f \n'];
    for (let id = 1; id < bodies.length; id += 1) lines.push(`${String(offsets[id]).padStart(10, '0')} 00000 n \n`);
    chunks.push(Buffer.from(`${lines.join('')}trailer\n<< /Size ${bodies.length} ${trailerKeys.join(' ')} >>\nstartxref\n${offset}\n%%EOF\n`, 'latin1'));
  } else {
    const xrefId = bodies.length;
    const size = xrefId + 1;
    const rows = Buffer.alloc(size * 7);
    rows.writeUInt8(0, 0);
    rows.writeUInt32BE(0, 1);
    rows.writeUInt16BE(0xffff, 5);
    for (let id = 1; id < size; id += 1) {
      rows.writeUInt8(1, id * 7);
      rows.writeUInt32BE(id === xrefId ? offset : offsets[id], id * 7 + 1);
      rows.writeUInt16BE(0, id * 7 + 5);
    }
    chunks.push(
      Buffer.from(`${xrefId} 0 obj\n<< /Type /XRef /Size ${size} /W [1 4 2] ${trailerKeys.join(' ')} /Length ${rows.length} >>\nstream\n`, 'latin1'),
      rows,
      Buffer.from(`\nendstream\nendobj\nstartxref\n${offset}\n%%EOF\n`, 'latin1'),
    );
  }
  const bytes = Buffer.concat(chunks);
  if (desc.features.includes('signature')) patchByteRange(bytes);
  return bytes;
}

/** Fill the fixed-width /ByteRange slots with the ranges around the /Contents placeholder. */
function patchByteRange(bytes) {
  const marker = Buffer.from('/ByteRange [', 'latin1');
  const start = bytes.indexOf(marker);
  const contents = bytes.indexOf(Buffer.from('/Contents <', 'latin1'), start);
  if (start < 0 || contents < 0) throw new Error('signature placeholder not found');
  const open = contents + '/Contents '.length;
  const close = bytes.indexOf(0x3e, open) + 1;
  const ranges = [0, open, close, bytes.length - close];
  const text = ranges.map((n) => String(n).padEnd(BYTE_RANGE_SLOT, ' ')).join('');
  bytes.write(text, start + marker.length, 'latin1');
}

/** Build a synthetic document from a descriptor. Deterministic: equal descriptors give equal bytes. */
export function buildPdf(descriptor) {
  const desc = normalize(descriptor);
  if (desc.variant === 'not-a-pdf') {
    return Buffer.from('synthetic plain text body; this upload is not a PDF document.\n'.repeat(4), 'latin1');
  }
  if (desc.variant === 'truncated') {
    const full = assemble(desc, null);
    // Keep the header, the catalog and the page tree root; drop every page, the cross-reference data, the trailer and %%EOF.
    const cut = full.indexOf(Buffer.from('\nendobj\n', 'latin1'), full.indexOf(Buffer.from('2 0 obj', 'latin1')));
    return Buffer.from(full.subarray(0, cut + '\nendobj\n'.length));
  }
  if (desc.targetBytes === undefined) return assemble(desc, null);
  let padding = 0;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const bytes = assemble(desc, padding);
    const delta = desc.targetBytes - bytes.length;
    if (delta === 0) return bytes;
    padding += delta;
    if (padding < 0) fail(`targetBytes ${desc.targetBytes} is smaller than the unpadded document`);
  }
  fail(`could not reach exactly ${desc.targetBytes} bytes`);
  return Buffer.alloc(0);
}

// ---------------------------------------------------------------------------
// Independent structural inspector
// ---------------------------------------------------------------------------

function refList(text) {
  return [...text.matchAll(/(\d+)\s+(\d+)\s+R/g)].map((m) => Number(m[1]));
}

function numberList(text) {
  return text
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map(Number);
}

function dictEntry(body, key) {
  const match = new RegExp(`/${key}(?![A-Za-z0-9])\\s*(\\[[^\\]]*\\]|\\d+\\s+\\d+\\s+R|-?\\d+(?:\\.\\d+)?|/[A-Za-z0-9.]+)`).exec(body);
  return match ? match[1] : undefined;
}

/**
 * Inspect bytes as a PDF without trusting the builder: header, %%EOF,
 * startxref, the cross-reference table or stream, every in-use object offset,
 * the trailer, the page tree with inherited attributes, and the features a
 * PDF upload policy rejects.
 * Returns { ok, problems[], version, xrefKind, objectCount, pageCount, pages[], features[], bytes }.
 */
export function inspectPdf(input) {
  const bytes = Buffer.from(input);
  const text = bytes.toString('latin1');
  const report = { ok: false, problems: [], version: null, xrefKind: null, objectCount: 0, pageCount: 0, pages: [], features: [], bytes: bytes.length };
  const header = /^%PDF-(\d\.\d)/.exec(text);
  if (!header) {
    report.problems.push('no %PDF- header');
    return report;
  }
  report.version = header[1];
  if (!text.slice(-1024).includes('%%EOF')) report.problems.push('no %%EOF marker');
  const sx = text.lastIndexOf('startxref');
  if (sx < 0) {
    report.problems.push('no startxref');
    return report;
  }
  const xrefOffset = Number(/startxref\s+(\d+)/.exec(text.slice(sx))?.[1]);
  if (!Number.isInteger(xrefOffset) || xrefOffset >= bytes.length) {
    report.problems.push('startxref does not point into the file');
    return report;
  }
  const offsets = new Map();
  let trailer = '';
  if (text.startsWith('xref', xrefOffset)) {
    report.xrefKind = 'table';
    let pos = xrefOffset + 4;
    const lineAt = () => {
      while (text[pos] === '\r' || text[pos] === '\n' || text[pos] === ' ') pos += 1;
      const end = text.indexOf('\n', pos);
      const line = text.slice(pos, end).trim();
      return { line, end };
    };
    for (;;) {
      const { line, end } = lineAt();
      if (line.startsWith('trailer')) {
        trailer = text.slice(pos, text.indexOf('startxref', pos));
        break;
      }
      const sub = /^(\d+)\s+(\d+)$/.exec(line);
      if (!sub) {
        report.problems.push('malformed cross-reference subsection');
        return report;
      }
      pos = end + 1;
      const first = Number(sub[1]);
      const count = Number(sub[2]);
      for (let i = 0; i < count; i += 1) {
        const entry = text.slice(pos, pos + 20);
        const m = /^(\d{10}) (\d{5}) ([nf])/.exec(entry);
        if (!m) {
          report.problems.push('malformed cross-reference entry');
          return report;
        }
        if (m[3] === 'n') offsets.set(first + i, Number(m[1]));
        pos += 20;
      }
    }
  } else {
    const head = /^(\d+)\s+0\s+obj\s*<<([\s\S]*?)>>\s*stream\r?\n/.exec(text.slice(xrefOffset));
    if (!head || !/\/Type\s*\/XRef/.test(head[2])) {
      report.problems.push('startxref points at neither a table nor a cross-reference stream');
      return report;
    }
    report.xrefKind = 'stream';
    trailer = head[2];
    const widths = numberList(/\/W\s*\[([^\]]*)\]/.exec(head[2])?.[1] ?? '');
    const size = Number(dictEntry(head[2], 'Size'));
    const length = Number(dictEntry(head[2], 'Length'));
    if (widths.length !== 3 || !Number.isInteger(size) || !Number.isInteger(length)) {
      report.problems.push('cross-reference stream dictionary lacks /W, /Size or /Length');
      return report;
    }
    const rowWidth = widths[0] + widths[1] + widths[2];
    const dataStart = xrefOffset + head[0].length;
    if (rowWidth * size !== length) report.problems.push('cross-reference stream length does not match /W and /Size');
    const readField = (at, width) => {
      let n = 0;
      for (let k = 0; k < width; k += 1) n = n * 256 + bytes[at + k];
      return n;
    };
    for (let id = 0; id < size; id += 1) {
      const at = dataStart + id * rowWidth;
      const type = widths[0] === 0 ? 1 : readField(at, widths[0]);
      const field2 = readField(at + widths[0], widths[1]);
      if (type === 1) offsets.set(id, field2);
    }
  }
  const objects = new Map();
  for (const [id, offset] of offsets) {
    const headText = text.slice(offset, offset + 32);
    if (!new RegExp(`^${id}\\s+\\d+\\s+obj`).test(headText)) {
      report.problems.push(`object ${id} is not at its cross-reference offset`);
      continue;
    }
    const end = text.indexOf('endobj', offset);
    if (end < 0) {
      report.problems.push(`object ${id} has no endobj`);
      continue;
    }
    const body = text.slice(offset, end);
    const streamAt = body.indexOf('stream');
    objects.set(id, streamAt >= 0 ? body.slice(0, streamAt) : body);
  }
  report.objectCount = objects.size;
  const rootId = Number(/\/Root\s+(\d+)\s+\d+\s+R/.exec(trailer)?.[1]);
  const catalog = objects.get(rootId);
  if (!catalog || !/\/Type\s*\/Catalog/.test(catalog)) {
    report.problems.push('trailer /Root does not name a catalog');
    return report;
  }
  const features = new Set();
  if (/\/Encrypt\s+\d+\s+\d+\s+R/.test(trailer)) features.add('encrypt');
  const pagesId = Number(/\/Pages\s+(\d+)\s+\d+\s+R/.exec(catalog)?.[1]);
  const pagesNode = objects.get(pagesId);
  if (!pagesNode || !/\/Type\s*\/Pages/.test(pagesNode)) {
    report.problems.push('catalog /Pages does not name a page tree');
    return report;
  }
  const kids = refList(/\/Kids\s*\[([^\]]*)\]/.exec(pagesNode)?.[1] ?? '');
  const count = Number(dictEntry(pagesNode, 'Count'));
  if (count !== kids.length) report.problems.push('/Count differs from the number of /Kids');
  const inheritedMedia = dictEntry(pagesNode, 'MediaBox');
  const inheritedCrop = dictEntry(pagesNode, 'CropBox');
  const inheritedRotate = dictEntry(pagesNode, 'Rotate');
  for (const kid of kids) {
    const page = objects.get(kid);
    if (!page || !/\/Type\s*\/Page(?![s])/.test(page)) {
      report.problems.push(`kid ${kid} is not a page`);
      continue;
    }
    const mediaText = dictEntry(page, 'MediaBox') ?? inheritedMedia;
    if (!mediaText) {
      report.problems.push(`page ${kid} has no effective /MediaBox`);
      continue;
    }
    const mediaBox = numberList(mediaText.slice(1, -1));
    const cropText = dictEntry(page, 'CropBox') ?? inheritedCrop;
    const cropBox = cropText ? numberList(cropText.slice(1, -1)) : [...mediaBox];
    const rotate = Number(dictEntry(page, 'Rotate') ?? inheritedRotate ?? 0);
    const width = mediaBox[2] - mediaBox[0];
    const height = mediaBox[3] - mediaBox[1];
    const swapped = rotate === 90 || rotate === 270;
    const cropDiffers = cropBox.some((v, i) => v !== mediaBox[i]);
    if (cropDiffers) features.add('cropbox-differs');
    report.pages.push({ mediaBox, cropBox, rotate, displayed: { width: swapped ? height : width, height: swapped ? width : height } });
  }
  report.pageCount = report.pages.length;
  if (report.pageCount > 50) features.add('pages-over-50');
  for (const body of objects.values()) {
    if (/\/S\s*\/JavaScript/.test(body) || /\/JS\s*[(<]/.test(body)) features.add('javascript');
    if (/\/S\s*\/Launch/.test(body)) features.add('launch');
    if (/\/EmbeddedFiles/.test(body) || /\/Type\s*\/EmbeddedFile/.test(body)) features.add('embedded-file');
    if (/\/Subtype\s*\/RichMedia/.test(body)) features.add('rich-media');
    if (/\/XFA\s+\d+\s+\d+\s+R/.test(body)) features.add('xfa');
    if (/\/FT\s*\/Sig/.test(body)) {
      const valueId = Number(/\/V\s+(\d+)\s+\d+\s+R/.exec(body)?.[1]);
      const value = objects.get(valueId);
      if (value && /\/ByteRange\s*\[/.test(value) && /\/Contents\s*</.test(value)) features.add('signature');
    }
  }
  report.features = [...features].sort();
  report.ok = report.problems.length === 0;
  return report;
}
