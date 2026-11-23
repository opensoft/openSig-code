// SPDX-License-Identifier: Apache-2.0
//
// The characters a typed signature may hold (T010; spec.md clarification on
// typed signatures; research.md, standard-14 Helvetica): those WinAnsiEncoding
// can represent, because the composer (T036) renders typed text and dates in
// non-embedded Helvetica with WinAnsiEncoding. Anything else is refused at
// approval with 422 unsupported_characters, before an approval is recorded.
//
// WinAnsiEncoding (ISO 32000-1:2008, Annex D.2) represents:
// - U+0020..U+007E, the printable ASCII range (codes 32..126);
// - U+00A0..U+00FF, the Latin-1 supplement (codes 160..255; 160 is the
//   no-break space and 173 the soft hyphen, which the encoding also defines);
// - the 27 characters at codes 128..159 listed below.
// Codes 129, 141, 143, 144 and 157 are undefined, and every C0 or C1 control
// character (U+0000..U+001F, U+007F..U+009F) is outside the encoding, as is
// every code point above U+00FF that is not listed, and every lone surrogate.
// This module only decides representability; encoding the bytes is T036's.

/** Code points of WinAnsiEncoding codes 128..159, in code order (5 codes are undefined). */
export const WINANSI_HIGH_CODE_POINTS: readonly number[] = Object.freeze([
  0x20ac, // 128 Euro
  0x201a, // 130 quotesinglbase
  0x0192, // 131 florin
  0x201e, // 132 quotedblbase
  0x2026, // 133 ellipsis
  0x2020, // 134 dagger
  0x2021, // 135 daggerdbl
  0x02c6, // 136 circumflex
  0x2030, // 137 perthousand
  0x0160, // 138 Scaron
  0x2039, // 139 guilsinglleft
  0x0152, // 140 OE
  0x017d, // 142 Zcaron
  0x2018, // 145 quoteleft
  0x2019, // 146 quoteright
  0x201c, // 147 quotedblleft
  0x201d, // 148 quotedblright
  0x2022, // 149 bullet
  0x2013, // 150 endash
  0x2014, // 151 emdash
  0x02dc, // 152 tilde
  0x2122, // 153 trademark
  0x0161, // 154 scaron
  0x203a, // 155 guilsinglright
  0x0153, // 156 oe
  0x017e, // 158 zcaron
  0x0178, // 159 Ydieresis
]);

const HIGH: ReadonlySet<number> = new Set(WINANSI_HIGH_CODE_POINTS);

/** True when WinAnsiEncoding represents the code point. */
export function isWinAnsiCodePoint(codePoint: number): boolean {
  return (codePoint >= 0x20 && codePoint <= 0x7e) || (codePoint >= 0xa0 && codePoint <= 0xff) || HIGH.has(codePoint);
}

/** True when every character of `text` is WinAnsi-representable (a lone surrogate never is). */
export function isWinAnsiText(text: string): boolean {
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined || !isWinAnsiCodePoint(codePoint)) return false;
  }
  return true;
}
