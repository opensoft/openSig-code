// SPDX-License-Identifier: Apache-2.0
//
// VB-06, the fault map (request #62 (4); the T014 line). Every structure fault
// code T014's reader can emit stands beside the T033 refusal that covers it on
// the same base, by function name in src/pdf/ (parser.ts, filters.ts,
// lexer.ts), or beside the one-line reason it cannot arise in a base T033
// accepted. A recheck then checks this closed list against T033's code.
//
// How the emitted codes are derived (never from a hand-typed list here):
// structure.ts is read as text with its comments removed. Its
// STRUCTURE_DETAILS declaration gives the declared codes (and must equal the
// exported array); a declared code is EMITTED when the rest of the code names
// it as a string literal (a fault() call, a DecodeFaults table, an
// optionalOffset detail or the start-of-chain choice). Every literal passed to
// fault() must be declared, every declared code must be emitted, and the map's
// codes must equal the emitted ones. So a new code fails until it is mapped,
// and a code that no longer exists fails until its entry goes. Each cited T033
// function must be defined in src/pdf/.
//
// The list keeps no exception (request #63): every entry is covered on the
// same base, and the third case fails if an entry names one.
//
// Mutants killed here: one map entry deleted; one unmapped code added; and,
// for request #63, the inflate-budget exception restored.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { STRUCTURE_DETAILS } from '../../../src/verifier/index.ts';
import { stripComments } from './helpers/import-scan.mjs';

const FAULT_MAP = Object.freeze({
  'input-too-large': { t033: ['parseDocument'], why: 'size-limit above maxBytes, whose ceiling (10 MiB) is below MAX_SEALED_PDF_BYTES' },
  'no-header': { t033: ['header'], why: 'no %PDF-1.0 to 1.7 or %PDF-2.0 at byte 0; T014 asks only %PDF-d.d' },
  'no-final-startxref-eof': { t033: ['findStartxref'], why: 'no last startxref in the final 1024 bytes followed by white-space, 1 to 15 digits, white-space and %%EOF; T014 also allows comments and trailing bytes' },
  'startxref-not-xref': { t033: ['readChain', 'readXrefStream', 'readIndirect'], why: 'the offset is past the file, or holds neither `xref` nor a /Type /XRef stream object' },
  'prev-not-xref': { t033: ['readChain', 'readXrefStream', 'readIndirect'], why: 'a /Prev past the file, or holding neither `xref` nor a /Type /XRef stream object' },
  'prev-revisited': { t033: ['readChain'], why: 'an offset seen again; a new offset reaching a section already read leads on to that section\'s /Prev, already seen (a section without /Prev ends the chain)' },
  'too-many-revisions': { t033: ['readChain'], why: 'xref-sections past maxXrefSections (ceiling 256); T014 allows 257, one more for T036\'s revision' },
  'too-many-xref-entries': { t033: ['addLocal', 'addEntry'], why: 'object-count past maxObjects (ceiling 1,000,000) in one section or in all; T014 allows 1,048,576 of each' },
  'too-much-work': { t033: ['loadObjectStream', 'decodeStructuralStream', 'inflate', 'readIndirect'], why: 'an object stream whose output is larger than the bytes the budget still allows, the comparison inflate makes (T014 spends T033\'s ceiling on no stream T033 does not decode, nor more often), or a /Length past the end of the file' },
  'xref-table-malformed': { t033: ['readXrefTable'], why: 'a subsection header or entry that is not unsigned numbers and `n` or `f`, or a generation above 65535' },
  'trailer-malformed': { t033: ['readXrefTable', 'readChain'], why: 'the trailer is not a dictionary, or its /Prev or /XRefStm is not a non-negative integer' },
  'xref-stream-malformed': { t033: ['readXrefStream', 'readIndirect', 'decodeStructuralStream'], why: 'bad /W, /Size, /Index, data length, stream framing or direct /Length, or invalid FlateDecode data' },
  'xref-stream-too-large': { t033: ['readIndirect', 'inflate'], why: 'a /Length past the end of the file, or an output larger than the bytes the budget still allows, the comparison inflate makes' },
  'xref-stream-filter-unsupported': { t033: ['decodeStructuralStream', 'filterNames'], why: 'a filter other than one /FlateDecode' },
  'xref-stream-predictor-unsupported': { t033: ['decodeStructuralStream', 'unpredictPng'], why: 'a predictor other than 1 or PNG 10 to 15, or PNG parameters other than 8 bits, 1 to 4 colours and at least 1 column' },
  'png-filter-unknown': { t033: ['unpredictPng'], why: 'a PNG row filter byte above 4' },
  'xrefstm-not-xref-stream': { t033: ['readChain', 'readXrefStream'], why: '/XRefStm past the file, or not a /Type /XRef stream object' },
  'xref-entry-mismatch': { t033: ['readIndirect', 'readCompressed'], why: 'no header at an entry\'s offset, a header with another number or generation, or an object-stream header naming another object' },
  'xref-type2-not-object-stream': { t033: ['readCompressed', 'loadObjectStream', 'streamLength', 'decodeStructuralStream'], why: 'the stream\'s entry not in use, no /Type /ObjStm stream, a bad /N, /First, /Length or header, an index at or past /N, or a refused filter' },
  'object-malformed': { t033: ['readIndirect', 'readCompressed', 'readValue'], why: 'an effective object whose value does not parse; T014\'s tokenizer reads every form T033\'s lexer reads' },
  'revision-order': { cannot: 'walk refuses a start already read and every start lies inside the file, so each start is below the next; no lower bound remains (request #62 (1))' },
});

const STRUCTURE = new URL('../../../src/verifier/structure.ts', import.meta.url);
const T033 = ['parser.ts', 'filters.ts', 'lexer.ts'].map((name) => new URL(`../../../src/pdf/${name}`, import.meta.url));

/** The declared and emitted codes of structure.ts, and the literals its fault() calls pass. */
function codesFromSource() {
  const code = stripComments(readFileSync(STRUCTURE, 'utf8'));
  const declaration = /export const STRUCTURE_DETAILS = \[[^\]]*\] as const;/.exec(code);
  assert.ok(declaration, 'the STRUCTURE_DETAILS declaration is found');
  const declared = [...declaration[0].matchAll(/'([a-z0-9-]+)'/g)].map((m) => m[1]);
  const rest = code.slice(0, declaration.index) + code.slice(declaration.index + declaration[0].length);
  const literals = new Set([...rest.matchAll(/'([a-z0-9-]+)'/g)].map((m) => m[1]));
  const faultLiterals = [...rest.matchAll(/\bfault\('([a-z0-9-]+)'\)/g)].map((m) => m[1]);
  return { declared, emitted: declared.filter((c) => literals.has(c)), faultLiterals };
}

test('[VB-06] the fault map covers exactly the structure fault codes derived from the source (request #62 (4))', () => {
  const { declared, emitted, faultLiterals } = codesFromSource();
  assert.deepEqual(declared, [...STRUCTURE_DETAILS], 'the declaration read from the source is the exported list');
  assert.ok(faultLiterals.length >= 20, 'the scan read the fault() calls');
  assert.deepEqual([...new Set(faultLiterals)].filter((c) => !declared.includes(c)), [], 'every code passed to fault() is declared');
  assert.deepEqual(declared.filter((c) => !emitted.includes(c)), [], 'every declared code is emitted');
  const mapped = Object.keys(FAULT_MAP);
  assert.deepEqual(emitted.filter((c) => !mapped.includes(c)), [], 'unmapped fault codes');
  assert.deepEqual(mapped.filter((c) => !emitted.includes(c)), [], 'mapped codes that no longer exist');
});

test('[VB-06] each fault map entry names T033 functions defined in src/pdf/, or gives a reason (request #62 (4))', () => {
  const t033 = T033.map((url) => stripComments(readFileSync(url, 'utf8'))).join('\n');
  for (const [code, entry] of Object.entries(FAULT_MAP)) {
    if (entry.cannot !== undefined) {
      assert.equal(entry.t033, undefined, `${code}: a reason or T033 functions, not both`);
      assert.ok(entry.cannot.length > 20, `${code}: a reason`);
      continue;
    }
    assert.ok(Array.isArray(entry.t033) && entry.t033.length > 0, `${code}: T033 functions`);
    assert.ok(entry.why.length > 10, `${code}: what T033 refuses`);
    for (const name of entry.t033) {
      const defined = new RegExp(`^\\s*(?:export\\s+)?(?:function\\s+)?${name}\\s*\\(`, 'm');
      assert.match(t033, defined, `${code}: ${name} is defined in src/pdf/`);
    }
  }
});

test('[VB-06] the fault map keeps no exception: every entry is covered on the same base (request #63)', () => {
  for (const [code, entry] of Object.entries(FAULT_MAP)) {
    assert.deepEqual(Object.keys(entry).filter((key) => !['t033', 'why', 'cannot'].includes(key)), [], `${code}: only t033 and why, or cannot`);
    assert.doesNotMatch(entry.why ?? entry.cannot, /\bexcept/i, `${code} names an exception`);
  }
});
