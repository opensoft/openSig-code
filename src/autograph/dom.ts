// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// Element builders for the review shell. Text always goes in as text nodes (never parsed as
// markup), and attributes go through setAttribute, which refuses style, event-handler and
// srcdoc names: the page's policy (script-src and style-src 'self') blocks them anyway, and
// the T035 build refuses them in source.

export const SVG_NS = 'http://www.w3.org/2000/svg';

export type Child = Node | string | null | undefined | false;
export type Attributes = Readonly<Record<string, string | number | boolean | undefined>>;

function setAttributes(element: Element, attributes: Attributes): void {
  for (const [name, value] of Object.entries(attributes)) {
    if (value === undefined || value === false) continue;
    const lower = name.toLowerCase();
    if (lower === 'style' || lower === 'srcdoc' || lower.startsWith('on')) throw new Error(`the attribute ${name} is not allowed`);
    element.setAttribute(name, value === true ? '' : String(value));
  }
}

function append(parent: Node, children: readonly Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
}

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, attributes: Attributes = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  setAttributes(element, attributes);
  append(element, children);
  return element;
}

export function svg<K extends keyof SVGElementTagNameMap>(tag: K, attributes: Attributes = {}, ...children: Child[]): SVGElementTagNameMap[K] {
  const element = document.createElementNS(SVG_NS, tag);
  setAttributes(element, attributes);
  append(element, children);
  return element;
}

/** Replace the children of `parent` with `children`. */
export function replace(parent: Element, ...children: Child[]): void {
  parent.replaceChildren();
  append(parent, children);
}

/** A number for an SVG attribute: at most two decimals, no exponent. */
export function num(value: number): string {
  return String(Math.round(value * 100) / 100);
}
