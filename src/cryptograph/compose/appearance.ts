// SPDX-License-Identifier: Apache-2.0
//
// Field placement and appearance streams (T036).
//
// Placement. A field rectangle is normalized to the displayed (rotation-applied)
// page: origin top-left, x rightward, y downward, each value in [0, 1] (contract
// Rect). The displayed page equals the MediaBox with /Rotate applied, because a
// page whose effective CropBox differs is refused (CP-07). Everything is computed
// in integer centipoints (1/100 point): the MediaBox corners are rounded once to
// centipoints, and the field's displayed corners are rounded once from the
// normalized values, so the widget /Rect, the appearance /BBox and /Matrix are
// exact decimals with at most two places, and equal inputs give equal bytes.
//
// For /Rotate r the displayed point (dx, dy), measured from the displayed top-left
// with y downward, maps to user space, with MediaBox [L B R T], as
//   r = 0:   (L + dx, T - dy)        r = 90:  (L + dy, B + dx)
//   r = 180: (R - dx, B + dy)        r = 270: (R - dy, T - dx)
// The appearance is drawn upright in field-local form space (BBox [0 0 w h], y up)
// and its /Matrix turns it counterclockwise by r, so that the viewer's clockwise
// page rotation shows it upright; the matrix's translation keeps the transformed
// BBox at the origin (ISO 32000-1 12.5.5 then maps it onto /Rect at scale 1).
//
// Drawn strokes (contract 0.2.3, A-010 S5, CP-09). A point is an integer pair
// (px, py) in 0..10000: px/10000 of the field width from the left and py/10000
// of its height from the top. In form space (points, y up) it is
//   x = px * w / 1,000,000     y = (10000 - py) * h / 1,000,000
// with w and h the field size in centipoints. Both numerators are exact integers,
// written with six decimal places at most (syntax.ts decimal): no floating-point
// formatting, so the path is exact and deterministic. Each stroke is a subpath
// (m, then l for every further point) painted with S; nothing is an image.
//
// Typed text and dates (research.md; spec.md clarification). Standard-14
// Helvetica, not embedded, with WinAnsiEncoding; the text is written as a hex
// string of its WinAnsi bytes, so it is never interpreted as markup and needs no
// escaping. No font metrics ship: every character is budgeted at one em, an upper
// bound on any Helvetica advance in WinAnsiEncoding, so the text never overflows
// the field; it is left-aligned and vertically centred.

import { WINANSI_HIGH_CODE_POINTS } from '../../domain/approval/winansi.ts';
import type { CentipointBox } from './bounds.ts';
import { decimal } from './syntax.ts';

export interface NormalizedRect {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

export type Matrix = readonly [number, number, number, number, number, number];

export interface Placement {
  /** The widget /Rect in user space, in centipoints: [llx, lly, urx, ury]. */
  readonly rect: readonly [number, number, number, number];
  /** The field's displayed width and height, in centipoints (the appearance BBox). */
  readonly width: number;
  readonly height: number;
  readonly rotate: 0 | 90 | 180 | 270;
  /** The appearance /Matrix; the rotation part is -1, 0 or 1 and the translation is in centipoints. */
  readonly matrix: Matrix;
}

const isUnitNumber = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;

/** A contract Rect, or null when it is not one (bounds as the server enforces them). */
export function checkRect(value: unknown): NormalizedRect | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join(',') !== 'height,width,x,y') return null;
  const { x, y, width, height } = record;
  if (!isUnitNumber(x) || !isUnitNumber(y) || !isUnitNumber(width) || !isUnitNumber(height)) return null;
  if (width <= 0 || height <= 0 || x + width > 1 || y + height > 1) return null;
  return Object.freeze({ x, y, width, height });
}

/** A page as placement sees it: its rotation and its MediaBox in centipoints (bounds.ts centipointBox). */
export interface PageGeometry {
  readonly rotate: 0 | 90 | 180 | 270;
  readonly box: CentipointBox;
}

/**
 * The field-placement rule (request #46): where a field with normalized rectangle `rect`
 * lands on `page`, or null when it rounds to less than one centipoint in width or height
 * (the composer's 400 field_too_small). Pure. The composer places every field with this
 * function, and T007's prepare check calls it over the stored page geometry:
 * placeField({ rotate, box: centipointBox(media_box) }, rect) === null means
 * field_too_small.
 */
export function placeField(page: PageGeometry, rect: NormalizedRect): Placement | null {
  const [left, bottom, right, top] = page.box;
  const upright = page.rotate % 180 === 0;
  const shownWidth = upright ? right - left : top - bottom;
  const shownHeight = upright ? top - bottom : right - left;
  const x0 = Math.round(rect.x * shownWidth);
  const x1 = Math.round((rect.x + rect.width) * shownWidth);
  const y0 = Math.round(rect.y * shownHeight);
  const y1 = Math.round((rect.y + rect.height) * shownHeight);
  const width = x1 - x0;
  const height = y1 - y0;
  if (width < 1 || height < 1) return null;
  let placed: readonly [number, number, number, number];
  let matrix: Matrix;
  switch (page.rotate) {
    case 0:
      placed = [left + x0, top - y1, left + x1, top - y0];
      matrix = [1, 0, 0, 1, 0, 0];
      break;
    case 90:
      placed = [left + y0, bottom + x0, left + y1, bottom + x1];
      matrix = [0, 1, -1, 0, height, 0];
      break;
    case 180:
      placed = [right - x1, bottom + y0, right - x0, bottom + y1];
      matrix = [-1, 0, 0, -1, width, height];
      break;
    case 270:
      placed = [right - y1, top - x1, right - y0, top - x0];
      matrix = [0, -1, 1, 0, 0, width];
      break;
    default:
      throw new RangeError('a page rotation is 0, 90, 180 or 270');
  }
  return Object.freeze({ rect: Object.freeze(placed), width, height, rotate: page.rotate, matrix: Object.freeze(matrix) });
}

/** A centipoint array as PDF numbers, for example a /Rect or a /BBox. */
export function centipointArray(values: readonly number[]): string {
  return `[${values.map((value) => decimal(value, 2)).join(' ')}]`;
}

/** An appearance /Matrix as a PDF array. */
export function matrixArray(matrix: Matrix): string {
  const [a, b, c, d, e, f] = matrix;
  return `[${a} ${b} ${c} ${d} ${decimal(e, 2)} ${decimal(f, 2)}]`;
}

// --- drawn strokes (CP-09) -------------------------------------------------------------------

/** The field-local fixed-point scale of contract 0.2.3. */
export const STROKE_SCALE = 10_000;

export type StrokePoint = readonly [number, number];

/** Stroke width in micropoints: 4% of the field height, kept within 0.5 to 2 points. */
export function strokeWidth(height: number): number {
  return Math.min(2_000_000, Math.max(500_000, height * 400));
}

/** The content stream of a drawn signature in a field of `width` x `height` centipoints. */
export function drawnAppearance(strokes: ReadonlyArray<ReadonlyArray<StrokePoint>>, width: number, height: number): string {
  const lines = ['q', '0 G', '1 J', '1 j', `${decimal(strokeWidth(height), 6)} w`];
  for (const stroke of strokes) {
    stroke.forEach((point, index) => {
      const [px, py] = point;
      lines.push(`${decimal(px * width, 6)} ${decimal((STROKE_SCALE - py) * height, 6)} ${index === 0 ? 'm' : 'l'}`);
    });
    lines.push('S');
  }
  lines.push('Q');
  return lines.join('\n');
}

// --- typed text and dates ----------------------------------------------------------------------

/** The resource name of the shared non-embedded Helvetica font in every text appearance. */
export const TEXT_FONT_RESOURCE = 'Helv';

/** The font dictionary: standard-14 Helvetica, WinAnsiEncoding, no font file. */
export const TEXT_FONT_DICT = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>';

/** The WinAnsiEncoding codes 128..159 that are defined (ISO 32000-1, Annex D.2). */
const UNDEFINED_HIGH_CODES = new Set([129, 141, 143, 144, 157]);
const HIGH_CODES = new Map<number, number>();
{
  const codes: number[] = [];
  for (let code = 128; code <= 159; code += 1) if (!UNDEFINED_HIGH_CODES.has(code)) codes.push(code);
  if (codes.length !== WINANSI_HIGH_CODE_POINTS.length) throw new Error('the WinAnsiEncoding table does not have 27 high codes');
  codes.forEach((code, index) => {
    const codePoint = WINANSI_HIGH_CODE_POINTS[index];
    if (codePoint === undefined) throw new Error('the WinAnsiEncoding table is short');
    HIGH_CODES.set(codePoint, code);
  });
}

/**
 * The WinAnsiEncoding bytes of `text`, or null when a character is outside the
 * encoding (the same set T010 accepts: src/domain/approval/winansi.ts).
 */
export function encodeWinAnsi(text: string): Uint8Array | null {
  const bytes: number[] = [];
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined) return null;
    if ((codePoint >= 0x20 && codePoint <= 0x7e) || (codePoint >= 0xa0 && codePoint <= 0xff)) {
      bytes.push(codePoint);
      continue;
    }
    const code = HIGH_CODES.get(codePoint);
    if (code === undefined) return null;
    bytes.push(code);
  }
  return Uint8Array.from(bytes);
}

/** Micropoints per centipoint: text is sized in micropoints (1/1,000,000 point). */
const MICRO_PER_CENTI = 10_000;

/**
 * The content stream of one line of WinAnsi text in a field of `width` x `height`
 * centipoints. The field geometry stays in centipoints; the font size, the padding
 * and the baseline are computed in micropoints and rounded down, never clamped up,
 * so the one-em-per-character bound count x size <= width - 2 x pad holds exactly
 * for every field. The narrowest field (one centipoint) with the longest text (80
 * characters) still gets 125 micropoints (Addendum 1 to request #43).
 */
export function textAppearance(encoded: Uint8Array, width: number, height: number): string {
  const pad = Math.min(200, Math.floor(width / 20)) * MICRO_PER_CENTI;
  const count = Math.max(1, encoded.length);
  const available = width * MICRO_PER_CENTI - 2 * pad;
  const tall = height * MICRO_PER_CENTI;
  const size = Math.min(Math.floor((tall * 6) / 10), Math.floor(available / count));
  const baseline = Math.floor((tall - size) / 2) + Math.floor(size / 5);
  const hex = Buffer.from(encoded).toString('hex').toUpperCase();
  return ['q', 'BT', `/${TEXT_FONT_RESOURCE} ${decimal(size, 6)} Tf`, '0 g', `${decimal(pad, 6)} ${decimal(baseline, 6)} Td`, `<${hex}> Tj`, 'ET', 'Q'].join('\n');
}
