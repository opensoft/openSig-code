// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// The drawing pad of one signature field (T009): pointer input (mouse, pen or touch, through
// Pointer Events) to vector strokes in field-local fixed point (strokes.ts).
// - The surface is an SVG whose viewBox has the field's own proportions on the page, so what
//   is drawn keeps its shape in the field; it has no border or padding and does not preserve
//   its aspect ratio, so its box is exactly the field. A position becomes fractions of that box,
//   then integers 0..10000; repeated points are dropped and a raw stroke stops growing at
//   MAX_RAW_POINTS_PER_STROKE. A 51st stroke is refused with a spoken notice.
// - While a stroke is drawn, its raw trace is shown. When it ends, all strokes are fitted to
//   the field's budget (fitStrokes) and the preview is redrawn from the fitted strokes alone:
//   the preview shows exactly what an approval submits (strokes()).
// - The pad is not focusable, so it never holds keyboard focus; the field's Type option is the
//   keyboard path. Touch scrolling is off on the surface only (touch-action: none in CSS).

import { el, replace, svg } from './dom.js';
import { COORDINATE_MAX, MAX_RAW_POINTS_PER_STROKE, MAX_STROKES_PER_VALUE, countPoints, fitStrokes, pathData, toPoint } from './strokes.js';
import type { Point } from './types.js';

export interface PadOptions {
  readonly key: string;
  /** The field's displayed size on its page, in points (only the proportion matters). */
  readonly width: number;
  readonly height: number;
  /** The field's point budget (budgetPerValue). */
  readonly budget: number;
  readonly announce: (text: string) => void;
  readonly onChange: () => void;
}

export class DrawingPad {
  readonly element: HTMLElement;
  readonly #options: PadOptions;
  readonly #surface: SVGSVGElement;
  readonly #preview: SVGGElement;
  readonly #ink: SVGPathElement;
  readonly #status: HTMLElement;
  #raw: Point[][] = [];
  #fitted: Point[][] = [];
  #current: Point[] | null = null;
  #pointer: number | null = null;

  constructor(options: PadOptions) {
    this.#options = options;
    const width = Math.max(1, options.width);
    const height = Math.max(1, options.height);
    const scale = `scale(${width / COORDINATE_MAX} ${height / COORDINATE_MAX})`;
    this.#preview = svg('g', { class: 'preview', transform: scale, 'data-field': options.key });
    this.#ink = svg('path', { class: 'ink', d: '', 'vector-effect': 'non-scaling-stroke' });
    this.#surface = svg(
      'svg',
      {
        class: 'pad-surface',
        viewBox: `0 0 ${width} ${height}`,
        preserveAspectRatio: 'none',
        role: 'img',
        'aria-label': `Drawing area for the signature in field ${options.key}. Draw with a mouse, pen or finger. To sign with the keyboard, choose Type my name.`,
        'data-field': options.key,
      },
      svg('rect', { class: 'pad-frame', x: 0, y: 0, width, height }),
      this.#preview,
      svg('g', { transform: scale }, this.#ink),
    );
    this.#status = el('p', { class: 'pad-status', 'aria-live': 'polite', id: `pad-status-${options.key}` }, this.#describe());
    const clear = el('button', { type: 'button', class: 'secondary', 'aria-label': `Clear the drawing in field ${options.key}`, 'aria-describedby': `pad-status-${options.key}` }, 'Clear the drawing');
    clear.addEventListener('click', () => this.clear());
    this.element = el('div', { class: 'pad' }, this.#surface, this.#status, clear);
    this.#surface.addEventListener('pointerdown', (event) => this.#down(event));
    this.#surface.addEventListener('pointermove', (event) => this.#move(event));
    this.#surface.addEventListener('pointerup', (event) => this.#end(event));
    this.#surface.addEventListener('pointercancel', (event) => this.#end(event));
    this.#surface.addEventListener('lostpointercapture', (event) => this.#end(event));
  }

  /** The fitted strokes: exactly what the preview shows and what an approval submits. */
  strokes(): readonly (readonly Point[])[] {
    return this.#fitted;
  }

  points(): number {
    return countPoints(this.#fitted);
  }

  clear(): void {
    this.#raw = [];
    this.#fitted = [];
    this.#current = null;
    this.#pointer = null;
    this.#ink.setAttribute('d', '');
    replace(this.#preview);
    this.#status.textContent = this.#describe();
    this.#options.onChange();
  }

  #describe(): string {
    if (this.#fitted.length === 0) return 'Nothing drawn yet.';
    const strokes = this.#fitted.length;
    return `${strokes} stroke${strokes === 1 ? '' : 's'} drawn (${this.points()} of at most ${this.#options.budget} points).`;
  }

  #add(event: PointerEvent): void {
    const current = this.#current;
    if (current === null || current.length >= MAX_RAW_POINTS_PER_STROKE) return;
    const box = this.#surface.getBoundingClientRect();
    if (box.width <= 0 || box.height <= 0) return;
    const point = toPoint((event.clientX - box.left) / box.width, (event.clientY - box.top) / box.height);
    const last = current[current.length - 1];
    if (last !== undefined && last[0] === point[0] && last[1] === point[1]) return;
    current.push(point);
  }

  #down(event: PointerEvent): void {
    if (!event.isPrimary || (event.pointerType === 'mouse' && event.button !== 0)) return;
    if (this.#current !== null) return;
    if (this.#raw.length >= MAX_STROKES_PER_VALUE) {
      this.#options.announce(`This field holds at most ${MAX_STROKES_PER_VALUE} strokes. Clear the drawing to start again.`);
      return;
    }
    event.preventDefault();
    this.#pointer = event.pointerId;
    try {
      this.#surface.setPointerCapture(event.pointerId);
    } catch {
      // A pointer the browser no longer tracks: the stroke still ends on pointerup.
    }
    this.#current = [];
    this.#add(event);
    this.#drawInk();
  }

  #move(event: PointerEvent): void {
    if (this.#current === null || event.pointerId !== this.#pointer) return;
    const coalesced = typeof event.getCoalescedEvents === 'function' ? event.getCoalescedEvents() : [];
    for (const sample of coalesced.length > 0 ? coalesced : [event]) this.#add(sample);
    this.#drawInk();
  }

  #end(event: PointerEvent): void {
    const current = this.#current;
    if (current === null || event.pointerId !== this.#pointer) return;
    if (event.type === 'pointerup') this.#add(event);
    this.#current = null;
    this.#pointer = null;
    if (current.length > 0) this.#raw.push(current);
    this.#ink.setAttribute('d', '');
    this.#fitted = fitStrokes(this.#raw, this.#options.budget).strokes;
    replace(this.#preview, ...this.#fitted.map((stroke, index) => svg('path', { class: 'stroke', d: pathData(stroke), 'vector-effect': 'non-scaling-stroke', 'data-stroke': index })));
    this.#status.textContent = this.#describe();
    this.#options.onChange();
  }

  #drawInk(): void {
    const current = this.#current;
    this.#ink.setAttribute('d', current === null || current.length === 0 ? '' : pathData(current.length === 1 ? [current[0] ?? [0, 0], current[0] ?? [0, 0]] : current));
  }
}
