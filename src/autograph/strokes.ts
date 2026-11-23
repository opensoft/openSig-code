// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// Drawn-signature arithmetic (T009; contract 0.2.3, A-010 S5). Pure functions, no DOM use.
//
// - Quantization. A pointer position inside a field, as fractions of the field's width and
//   height (origin top-left), becomes integers 0..10000: round(fraction * 10000), clamped.
// - Limits (DrawnSignatureValue and Approval): at most 50 strokes per value, 2..1000 points
//   per stroke, 10,000 points per value and 15,000 drawn points per approval.
// - Budget. Each signature field gets min(10000, floor(15000 / signature fields)) points, so
//   any mix of drawn fields stays within the approval budget and one field's simplification
//   never changes another field's preview: one field 10,000, two fields 7,500 each.
// - Simplification. Ramer-Douglas-Peucker on the quantized points with point-to-segment
//   distance, endpoints kept, ties broken by the lowest index, so the result is a pure
//   function of the input. The kept set never grows as the tolerance grows, so the smallest
//   integer tolerance that fits the per-stroke and per-value limits is found by binary search;
//   at tolerance 20000 every stroke is its two endpoints (no distance in the field exceeds
//   14143), which always fits. A one-point stroke (a tap) becomes the point twice.
// - What is previewed is what is submitted: the pad renders fitStrokes()'s output, and the
//   approval carries the same arrays.

import type { Point, Stroke } from './types.js';

export const COORDINATE_MAX = 10_000;
export const MAX_STROKES_PER_VALUE = 50;
export const MIN_POINTS_PER_STROKE = 2;
export const MAX_POINTS_PER_STROKE = 1000;
export const MAX_POINTS_PER_VALUE = 10_000;
export const MAX_POINTS_PER_APPROVAL = 15_000;
/** Raw capture bound per stroke, before simplification (keeps the fit fast on any input). */
export const MAX_RAW_POINTS_PER_STROKE = 4000;
/** A tolerance at which every stroke collapses to its endpoints. */
export const COLLAPSE_TOLERANCE = 2 * COORDINATE_MAX;

/** One coordinate: a fraction of the field's extent to an integer 0..10000 (NaN is 0). */
export function quantize(fraction: number): number {
  if (Number.isNaN(fraction) || fraction <= 0) return 0;
  if (fraction >= 1) return COORDINATE_MAX;
  return Math.round(fraction * COORDINATE_MAX);
}

export function toPoint(fractionX: number, fractionY: number): Point {
  return [quantize(fractionX), quantize(fractionY)];
}

/** The point budget of one signature field when the approval has `signatureFields` of them. */
export function budgetPerValue(signatureFields: number): number {
  const fields = Math.max(1, Math.floor(signatureFields));
  return Math.min(MAX_POINTS_PER_VALUE, Math.floor(MAX_POINTS_PER_APPROVAL / fields));
}

export function countPoints(strokes: readonly Stroke[]): number {
  let total = 0;
  for (const stroke of strokes) total += stroke.length;
  return total;
}

function segmentDistance(point: Point, start: Point, end: Point): number {
  const dx = end[0] - start[0];
  const dy = end[1] - start[1];
  const length2 = dx * dx + dy * dy;
  if (length2 === 0) return Math.hypot(point[0] - start[0], point[1] - start[1]);
  const t = Math.max(0, Math.min(1, ((point[0] - start[0]) * dx + (point[1] - start[1]) * dy) / length2));
  return Math.hypot(point[0] - (start[0] + t * dx), point[1] - (start[1] + t * dy));
}

/** Ramer-Douglas-Peucker at `tolerance` (quantized units); always at least two points. */
export function simplifyStroke(stroke: Stroke, tolerance: number): Point[] {
  const first = stroke[0];
  if (first === undefined) return [];
  if (stroke.length === 1) return [first, first];
  const keep = new Uint8Array(stroke.length);
  keep[0] = 1;
  keep[stroke.length - 1] = 1;
  const pending: Array<readonly [number, number]> = [[0, stroke.length - 1]];
  for (let span = pending.pop(); span !== undefined; span = pending.pop()) {
    const [from, to] = span;
    const start = stroke[from];
    const end = stroke[to];
    if (start === undefined || end === undefined) continue;
    let farthest = -1;
    let distance = -1;
    for (let index = from + 1; index < to; index += 1) {
      const point = stroke[index];
      if (point === undefined) continue;
      const d = segmentDistance(point, start, end);
      if (d > distance) {
        distance = d;
        farthest = index;
      }
    }
    if (farthest !== -1 && distance > tolerance) {
      keep[farthest] = 1;
      pending.push([from, farthest], [farthest, to]);
    }
  }
  const kept: Point[] = [];
  stroke.forEach((point, index) => {
    if (keep[index] === 1) kept.push(point);
  });
  return kept;
}

export interface Fit {
  /** The strokes to preview and submit. */
  readonly strokes: Point[][];
  /** The smallest integer tolerance that fits (0 when nothing had to be removed but collinear points). */
  readonly tolerance: number;
  readonly points: number;
}

function attempt(raw: readonly Stroke[], tolerance: number, limit: number): Point[][] | null {
  const strokes: Point[][] = [];
  let total = 0;
  for (const stroke of raw) {
    const simplified = simplifyStroke(stroke, tolerance);
    if (simplified.length > MAX_POINTS_PER_STROKE) return null;
    total += simplified.length;
    if (total > limit) return null;
    strokes.push(simplified);
  }
  return strokes;
}

/** Fit `raw` strokes (already quantized) into the stroke, point and `budget` limits. */
export function fitStrokes(raw: readonly Stroke[], budget: number): Fit {
  if (raw.length > MAX_STROKES_PER_VALUE) throw new RangeError(`at most ${MAX_STROKES_PER_VALUE} strokes`);
  const limit = Math.min(Math.floor(budget), MAX_POINTS_PER_VALUE);
  const exact = attempt(raw, 0, limit);
  if (exact !== null) return { strokes: exact, tolerance: 0, points: countPoints(exact) };
  let low = 0;
  let high = COLLAPSE_TOLERANCE;
  let best = attempt(raw, high, limit);
  if (best === null) throw new RangeError('the budget cannot hold two points per stroke');
  while (high - low > 1) {
    const middle = Math.floor((low + high) / 2);
    const fitted = attempt(raw, middle, limit);
    if (fitted === null) low = middle;
    else {
      high = middle;
      best = fitted;
    }
  }
  return { strokes: best, tolerance: high, points: countPoints(best) };
}

/** SVG path data for one stroke in field-local units: "M x y L x y ...". */
export function pathData(stroke: Stroke): string {
  return stroke.map((point, index) => `${index === 0 ? 'M' : 'L'}${point[0]} ${point[1]}`).join(' ');
}
