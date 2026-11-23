// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// The page-outline schematic (T009; research.md, review rendering): an original SVG drawing of
// every page's displayed outline (PageGeometry, /Rotate already applied, in PDF points) with
// this recipient's field boxes (Rect, normalized to the displayed page, origin top-left)
// placed and labelled on them. It is a map of where the fields are, not a rendering of the
// document: the document itself is shown by the browser's own PDF viewer. A text list repeats
// every field for screen readers.

import { el, num, svg } from './dom.js';
import type { Field, PageGeometry } from './types.js';

export function fieldName(field: Field): string {
  return field.type === 'signature' ? 'Signature' : 'Date';
}

export function fieldDescription(field: Field): string {
  const what = field.type === 'signature' ? 'Signature' : 'Date, set by the server when you approve';
  return `${what} (field ${field.key}) on page ${field.page}`;
}

function pageOutline(page: PageGeometry, total: number, fields: readonly Field[]): SVGSVGElement {
  const titleId = `schematic-page-${page.number}`;
  const width = page.width;
  const height = page.height;
  const label = fields.length === 0 ? 'no field for you' : `${fields.length} field${fields.length === 1 ? '' : 's'} for you`;
  const rotated = page.rotate === 0 ? '' : `, shown rotated ${page.rotate} degrees`;
  const outline = svg(
    'svg',
    { class: 'page-outline', viewBox: `0 0 ${num(width)} ${num(height)}`, role: 'img', 'aria-labelledby': titleId, 'data-page': page.number },
    svg('title', { id: titleId }, `Page ${page.number} of ${total}${rotated}: ${label}`),
    svg('rect', { class: 'page', x: 0, y: 0, width: num(width), height: num(height) }),
  );
  const fontSize = Math.max(6, Math.min(width, height) / 18);
  for (const field of fields) {
    const x = field.rect.x * width;
    const y = field.rect.y * height;
    const boxWidth = field.rect.width * width;
    const boxHeight = field.rect.height * height;
    outline.append(
      svg('rect', { class: `field field-${field.type}`, 'data-field': field.key, x: num(x), y: num(y), width: num(boxWidth), height: num(boxHeight) }),
      svg('text', { class: 'field-label', x: num(x + fontSize / 3), y: num(Math.max(fontSize, y - fontSize / 3)), 'font-size': num(fontSize) }, fieldName(field)),
    );
  }
  return outline;
}

/** The schematic of `pages` with `fields` (this recipient's only). */
export function schematic(pages: readonly PageGeometry[], fields: readonly Field[]): HTMLElement {
  const items = pages.map((page) =>
    el(
      'li',
      { class: fields.some((field) => field.page === page.number) ? 'schematic-page has-fields' : 'schematic-page' },
      pageOutline(page, pages.length, fields.filter((field) => field.page === page.number)),
      el('span', { class: 'page-number', 'aria-hidden': 'true' }, `Page ${page.number}`),
    ),
  );
  const list = el('ul', { class: 'field-list' }, ...fields.map((field) => el('li', { 'data-field': field.key }, fieldDescription(field))));
  return el(
    'figure',
    { class: 'schematic', 'aria-labelledby': 'schematic-caption' },
    el('figcaption', { id: 'schematic-caption' }, 'Where your fields are: an outline of each page with your fields marked. This is a map, not the document itself.'),
    el('ol', { class: 'schematic-pages' }, ...items),
    el('h3', {}, 'Your fields'),
    list,
  );
}
