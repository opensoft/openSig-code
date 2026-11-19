// SPDX-License-Identifier: Apache-2.0
//
// Synthetic PDFs for EA-07 (T034 follow-up; A-010 requests #44, #45 and #46), built at run
// time from structural descriptions. Nothing is committed or downloaded. The builder was
// written independently for these tests. Each document is one the real isolated parse service
// (T033) accepts, and each carries exactly the structure that one of the predicate's eight
// refusals reads (src/cryptograph/compose/bounds.ts, as landed at 574de5e).
//
// Layout of every document:
// - object 1 is the catalog;
// - object 2 is the page tree root, with a 612 x 792 MediaBox that every page inherits;
// - objects 3 .. 2 + n are the n pages;
// - after them come the extra objects, in order. A null extra is a free cross-reference
//   entry, so a reference to it resolves to nothing.
// There is one classic cross-reference table, no /ID and no stream.
//
// Why each refusal document passes the parse service:
// - the parser resolves an /AcroForm reference, so a dangling one is its own malformed
//   refusal (the ordering case uses that). Page /Annots and /Fields references are only
//   collected into the report, never resolved, so they can dangle;
// - neither the parser nor the active-content policy checks the shape of /Annots, /AcroForm
//   or /Fields;
// - a number is any decimal of at most 32 characters, so 0.0000001 and a 22-digit integer
//   are accepted, and JavaScript prints both in exponent form;
// - the trailer /Size needs only to exceed every cross-reference entry, so it may be huge;
// - a page box needs only four finite numbers with a positive area, so a coordinate above
//   1,000,000 and a side of 0.004 point both pass;
// - a name may hold #00, so a NUL can sit in a name or a dictionary key. Both the child and
//   the parent keep a key named __proto__ as an own property.

const latin1 = (text) => Buffer.from(text, 'latin1');

/** Object number of the `index`-th extra object (0-based) after `pages` pages. */
export const extraRef = (pages, index = 0) => pages + 3 + index;

/**
 * A classic-table PDF. `catalog` adds entries to the catalog, `pages` holds the added entries
 * of each page (one string per page), and `extras` are further object bodies, where null is a
 * free entry. `size` replaces the trailer /Size, which defaults to the number of entries.
 */
export function syntheticPdf({ catalog = '', pages = [''], extras = [], size } = {}) {
  const kids = pages.map((_, index) => `${index + 3} 0 R`).join(' ');
  const bodies = [
    `<< /Type /Catalog /Pages 2 0 R${catalog ? ` ${catalog}` : ''} >>`,
    `<< /Type /Pages /Kids [${kids}] /Count ${pages.length} /MediaBox [0 0 612 792] >>`,
    ...pages.map((entries) => `<< /Type /Page /Parent 2 0 R${entries ? ` ${entries}` : ''} >>`),
    ...extras,
  ];
  const head = latin1('%PDF-1.7\n%\xe2\xe3\xcf\xd3\n');
  const chunks = [head];
  let at = head.length;
  const rows = ['0000000000 65535 f \n'];
  bodies.forEach((body, index) => {
    if (body === null) {
      rows.push('0000000000 00001 f \n');
      return;
    }
    rows.push(`${String(at).padStart(10, '0')} 00000 n \n`);
    const chunk = latin1(`${index + 1} 0 obj\n${body}\nendobj\n`);
    chunks.push(chunk);
    at += chunk.length;
  });
  if (size !== undefined && !(Number.isSafeInteger(size) && size >= rows.length)) throw new RangeError('the trailer /Size must cover every cross-reference entry');
  chunks.push(latin1(`xref\n0 ${rows.length}\n${rows.join('')}trailer\n<< /Size ${size ?? rows.length} /Root 1 0 R >>\nstartxref\n${at}\n%%EOF\n`));
  return Buffer.concat(chunks);
}

// --- sealable controls ------------------------------------------------------------------------

/**
 * A well-formed form document that the composer can seal. It has an indirect AcroForm with an
 * indirect /Fields array, one page with an indirect /Annots array and one with a direct one,
 * and numbers just inside the plain-decimal range: 0.000001 and the 21-digit 10^20.
 * JavaScript prints both without an exponent.
 */
export function sealableFormPdf() {
  return syntheticPdf({
    catalog: '/AcroForm 5 0 R',
    pages: ['/Annots 7 0 R /X 0.000001', '/Annots [] /Y 100000000000000000000'],
    extras: ['<< /Fields 6 0 R >>', '[]', '[]'],
  });
}

// --- one refusal each -------------------------------------------------------------------------

/** number_range: a nonzero number below 10^-6 on a page (row T036-NUMRANGE's example). */
export function exponentPagePdf() {
  return syntheticPdf({ pages: ['/X 0.0000001'] });
}

/** number_range: a 22-digit integer, at least 10^21, in the catalog (row T036-NUMRANGE's example). */
export function exponentCatalogPdf() {
  return syntheticPdf({ catalog: '/X 1000000000000000000000' });
}

/**
 * number_range: an exponent-form number under a page key named __proto__. The predicate treats
 * every key as data (row T036-RESIDUAL (1); request #46 Part A(1): no new detail).
 */
export function exponentProtoKeyPdf() {
  return syntheticPdf({ pages: ['/__proto__ 0.0000001'] });
}

/** dangling_form_reference: a page's /Annots refers to a free object. */
export function danglingAnnotsPdf() {
  return syntheticPdf({ pages: ['/Annots 4 0 R'], extras: [null] });
}

/** dangling_form_reference: a direct AcroForm's /Fields refers to a free object. */
export function danglingFieldsPdf() {
  return syntheticPdf({ catalog: '/AcroForm << /Fields 4 0 R >>', extras: [null] });
}

/** annots_shape: a page's /Annots is a dictionary, not an array. */
export function annotsShapePdf() {
  return syntheticPdf({ pages: ['/Annots << >>'] });
}

/** acroform_shape: the catalog's /AcroForm is an array, not a dictionary. */
export function acroformShapePdf() {
  return syntheticPdf({ catalog: '/AcroForm []' });
}

/** acroform_shape: a direct AcroForm whose /Fields is not an array (request #46 Part C(1)). */
export function fieldsShapePdf() {
  return syntheticPdf({ catalog: '/AcroForm << /Fields 0 >>' });
}

/** acroform_shape: the AcroForm object is also the page (request #46 Part B). */
export function acroformIsPagePdf() {
  return syntheticPdf({ catalog: '/AcroForm 3 0 R' });
}

/** The trailer /Size of the xref_size document: MAX_OBJECT_NUMBER + 1. */
export const HUGE_XREF_SIZE = 8_388_608;

/**
 * xref_size: a trailer /Size so large that the largest request's new objects would pass the
 * object-number limit. The predicate refuses when /Size - 1 plus the new objects exceeds
 * 8,388,607, the new objects being 1 + 2 x 20 + 2, plus 1 with no AcroForm, plus 1 after a
 * stream section. For this document (no AcroForm, a table) that is 44, so any /Size above
 * 8,388,564 is refused.
 */
export function xrefSizePdf() {
  return syntheticPdf({ size: HUGE_XREF_SIZE });
}

/** page_box: a page MediaBox coordinate above MAX_BOX_COORDINATE (1,000,000 points). */
export function pageBoxCoordinatePdf() {
  return syntheticPdf({ pages: ['/MediaBox [0 0 1000001 792]'] });
}

/** page_box: a page side of 0.004 point, which rounds to no whole centipoint (centipointBox). */
export function pageBoxSidePdf() {
  return syntheticPdf({ pages: ['/MediaBox [0 0 0.004 792]'] });
}

/** Pages of manyPageBoxesPdf(): more than the 16 references one request-log record holds. */
export const MANY_PAGE_BOX_PAGES = 20;

/**
 * page_box on every one of 20 pages (objects 3 .. 22), so the refusal names 20 objects. The
 * request-log record holds the first 16, [3, 0] .. [18, 0] (the predicate sorts them by
 * number), and the total of 20. The document is under 3 KB.
 */
export function manyPageBoxesPdf() {
  return syntheticPdf({ pages: Array.from({ length: MANY_PAGE_BOX_PAGES }, () => '/MediaBox [0 0 1000001 792]') });
}

/** name_character: a NUL (#00) in a name, as a page entry's value. */
export function nulNamePdf() {
  return syntheticPdf({ pages: ['/X /a#00b'] });
}

/** name_character: a NUL (#00) in a dictionary key, on a page. */
export function nulKeyPdf() {
  return syntheticPdf({ pages: ['/K#00ey 1'] });
}

// --- ordering ---------------------------------------------------------------------------------

/** The seven details of manyRefusalsPdf(): every detail except composition_too_large. */
export const MANY_REFUSALS = Object.freeze(['number_range', 'dangling_form_reference', 'annots_shape', 'acroform_shape', 'xref_size', 'page_box', 'name_character']);

/**
 * Seven refusals, mostly on different objects:
 * - catalog: acroform_shape (/AcroForm []) and name_character (a NUL in a name);
 * - page 1: number_range;
 * - page 2: annots_shape;
 * - page 3: dangling_form_reference (its /Annots refers to the free object 7);
 * - page 4: page_box;
 * - trailer /Size: xref_size.
 * The first refusal in SEAL_REFUSAL_DETAILS order is number_range. Taking the last, or
 * reordering, gives another detail.
 */
export function manyRefusalsPdf() {
  return syntheticPdf({
    catalog: '/AcroForm [] /N /a#00b',
    pages: ['/X 0.0000001', '/Annots << >>', '/Annots 7 0 R', '/MediaBox [0 0 1000001 792]'],
    extras: [null],
    size: HUGE_XREF_SIZE,
  });
}

/**
 * A parse-service refusal together with a sealability defect: an effective CropBox that
 * differs from the MediaBox (cropbox_differs), on a page that also holds an exponent-form
 * number.
 */
export function croppedExponentPdf() {
  return syntheticPdf({ pages: ['/CropBox [0 0 300 300] /X 0.0000001'] });
}

/** An /AcroForm reference to a free object: the parse service's own malformed refusal, never EA-07's. */
export function danglingAcroFormPdf() {
  return syntheticPdf({ catalog: '/AcroForm 4 0 R', extras: [null] });
}

// --- shared-array bases (row SIZE-BOUND) ------------------------------------------------------

/** Pages of a shared-array base: the most pages a field manifest can place widgets on (20 fields). */
export const SHARED_ARRAY_PAGES = 20;
/** Characters per name in a shared-array base. */
export const SHARED_NAME_LENGTH = 1000;
/** Names in the base the predicate must refuse (composition_too_large). */
export const TOO_LARGE_NAMES = 1000;
/** Names in the honest shared-array base under the bound (a sealable control). */
export const UNDER_BOUND_NAMES = 600;

/**
 * A shared-array base, modelled on the 4,082,540-byte base from the T036 recheck (row
 * SIZE-BOUND). One indirect array is both the direct AcroForm's /Fields and every page's
 * /Annots, so the composer copies it inline 21 times: once into the AcroForm and once into
 * each of the 20 widget pages. The array holds `names` names of `length` characters. Each
 * character is written #28, because a delimiter must be escaped, so it costs 3 bytes in the
 * base and in every copy, and 1 byte in the parse report's JSON.
 *
 * Sizes, with J the array's JSON size (each name costs `length` + 11 bytes, plus a comma),
 * under the cost model of bounds.ts as landed at 574de5e (estimateSealedSize). A direct
 * AcroForm adds no rewrite of its own, but its /Fields copy counts 3J; each page counts 3 x its
 * JSON + 400 + 3J for its /Annots copy; and the base has no /ID.
 * - worst case = bytes + 1 + UPDATE_REQUEST_BOUND + 3 x (catalog JSON) + 400 + 3J
 *   + 20 x (3 x (page JSON) + 400 + 3J), which is about bytes + 63J + 1,113,500;
 * - 1,000 names: bytes about 3.0 MB, J = 1,012,001, so the worst case is about 67.9 MB,
 *   17.5 MB over MAX_SEALED_PDF_BYTES (50,331,648). A real composition with widgets on all
 *   20 pages would be about 66 MB, so the composer genuinely could not seal it. The report
 *   is about 1.02 MB, under its 1,376,256-byte budget, with about 1,200 of its 266,240
 *   nodes;
 * - 600 names: bytes about 1.8 MB, J = 607,201, so the worst case is about 41.2 MB, 9.2 MB
 *   (18%) under the bound;
 * - the threshold is about 737 names. 600 and 1,000 bracket it with margins of 19% and 36%.
 * Runtime cost: a few milliseconds to build. Each upload is one parse-service run over 3.0 MB
 * or 1.8 MB, well inside the parse limits (10 s CPU, 20 s wall time, 128 MiB heap). T034
 * never composes, so the 66 MB never exists.
 */
export function sharedArrayPdf(names, length = SHARED_NAME_LENGTH) {
  const ref = extraRef(SHARED_ARRAY_PAGES);
  const name = `/${'#28'.repeat(length)}`;
  return syntheticPdf({
    catalog: `/AcroForm << /Fields ${ref} 0 R >>`,
    pages: Array.from({ length: SHARED_ARRAY_PAGES }, () => `/Annots ${ref} 0 R`),
    extras: [`[${Array.from({ length: names }, () => name).join(' ')}]`],
  });
}
