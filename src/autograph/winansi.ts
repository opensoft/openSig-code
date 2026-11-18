// SPDX-License-Identifier: Apache-2.0
/// <reference lib="dom" />
//
// Typed signatures are rendered in standard-14 Helvetica with WinAnsiEncoding, not embedded
// (spec.md clarification; contract TypedSignatureValue). The server refuses any other
// character with 422 unsupported_characters; the shell checks first, so the person typing
// hears about it before anything is sent. WinAnsiEncoding (ISO 32000-1, Annex D.2) represents
// U+0020..U+007E, U+00A0..U+00FF and the 27 characters of codes 128..159 below; no control
// character, no lone surrogate, nothing else.

const CODES_128_TO_159: ReadonlySet<number> = new Set([
  0x20ac, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0x017d, 0x2018, 0x2019, 0x201c, 0x201d, 0x2022, 0x2013,
  0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x017e, 0x0178,
]);

export function isWinAnsiCodePoint(codePoint: number): boolean {
  return (codePoint >= 0x20 && codePoint <= 0x7e) || (codePoint >= 0xa0 && codePoint <= 0xff) || CODES_128_TO_159.has(codePoint);
}

/** The characters of `text` that WinAnsiEncoding cannot represent, each once, in order. */
export function unsupportedCharacters(text: string): string[] {
  const found: string[] = [];
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    if ((codePoint === undefined || !isWinAnsiCodePoint(codePoint)) && !found.includes(character)) found.push(character);
  }
  return found;
}

/** Length in code points, as the contract's maxLength counts it. */
export function codePointLength(text: string): number {
  let length = 0;
  for (const _character of text) length += 1;
  return length;
}
