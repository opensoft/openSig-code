// SPDX-License-Identifier: Apache-2.0
//
// VB-06, the fault map (requests #62 (4) and #64; the T014 line; row
// T014-TESTS). Its question: can this emission site refuse a PRODUCT OUTPUT,
// that is, T036's composition of a base T033 accepts, sealed by T037? Each site
// answers with the T033 refusal of the base that covers it, by function name
// in src/pdf/ (parser.ts, filters.ts, lexer.ts, policy.ts), or with the
// one-line reason it cannot arise on such an output, which may name T036's
// composition or verifyPdf's own bound. A recheck then checks this closed list
// against T033's code.
//
// How the sites are derived (never from a hand-typed list here): structure.ts
// is read as text with its comments removed. The declared codes are its
// STRUCTURE_DETAILS (equal to the exported array) and the signature scan's
// details in its SignatureScan type. A SITE is a pair of a function or method
// and a code its body names, as a string literal or as a DecodeFaults key (one
// site for each table that binds that key); a top-level function or a method
// of a top-level class runs to the next declaration. The map's keys must equal
// the derived sites, so a new site, even of an old code, fails until it is
// mapped, and a site that no longer exists fails until its entry goes. Where a
// function serves several kinds of caller (a chain or a hidden cross-reference
// stream, a cross-reference or an object stream), its entry covers each. Every
// cited T033 function must be defined in src/pdf/, and the list keeps no
// exception (request #63).
//
// So that a code can reach fault() or a scan detail only as a literal tsc has
// checked, structure.ts may hold no type assertion but `as const`, no `any`
// and no TypeScript suppression comment (request #64 (4)).
//
// Mutants killed here: one site entry deleted; a new emission site added
// without an entry; one signature-scan entry deleted; a code passed through a
// `string` cast to StructureDetail (the reviewer's MR1); a `ts-ignore`
// comment added; an `any` added; and, from requests #62 (4) and #63, one map
// entry deleted, one unmapped code added and the inflate-budget exception
// restored.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { STRUCTURE_DETAILS } from '../../../src/verifier/index.ts';
import { stripComments } from './helpers/import-scan.mjs';

const FAULT_MAP = Object.freeze({
  'addLocal: too-many-xref-entries': { t033: ['addLocal'], why: 'a section\'s own entries past maxObjects (ceiling 1,000,000); T014 allows 1,048,576, room for T036\'s section' },
  'checkHeader: no-header': { t033: ['header'], why: 'no %PDF-1.0 to 1.7 or %PDF-2.0 at byte 0, which T036 keeps; T014 asks only %PDF-d.d' },
  'decodeStream: too-much-work': { t033: ['loadObjectStream', 'decodeStructuralStream', 'inflate'], why: 'an object stream whose output is larger than the bytes the budget still allows, the comparison inflate makes; T014 spends T033\'s ceiling on no stream T033 does not decode, nor more often, and T036 appends no filtered stream' },
  'decodeStream: xref-stream-filter-unsupported': { t033: ['decodeStructuralStream', 'filterNames'], why: 'a chain or hidden cross-reference stream with a filter other than one /FlateDecode; T036\'s stream has none' },
  'decodeStream: xref-stream-malformed': { t033: ['decodeStructuralStream', 'inflate'], why: 'a chain or hidden cross-reference stream with invalid FlateDecode data, or /DecodeParms neither a dictionary, null nor a one-element array' },
  'decodeStream: xref-stream-predictor-unsupported': { t033: ['decodeStructuralStream', 'unpredictPng'], why: 'a chain or hidden cross-reference stream with a predictor other than 1 or PNG 10 to 15, or PNG parameters other than 8 bits, 1 to 4 colours and at least 1 column' },
  'decodeStream: xref-stream-too-large': { t033: ['inflate'], why: 'a chain or hidden cross-reference stream whose output is larger than the bytes the budget still allows, the comparison inflate makes' },
  'decodeStream: xref-type2-not-object-stream': { t033: ['decodeStructuralStream', 'filterNames', 'unpredictPng', 'inflate'], why: 'an object stream with a refused filter, predictor or /DecodeParms, or invalid FlateDecode data' },
  'decodeXrefStreamAt: xref-stream-malformed': { t033: ['readXrefStream', 'readIndirect'], why: 'a /Type /XRef object, chain or hidden, that is no stream or has no direct /Length; T036\'s stream has both' },
  'finalStartxref: no-final-startxref-eof': { cannot: 'T036 writes the output\'s tail, startxref with its own section\'s offset and %%EOF, after its appended section' },
  'headerPair: xref-type2-not-object-stream': { t033: ['loadObjectStream'], why: 'an object-stream header pair that is not two unsigned numbers before /First' },
  'locateRevisions: revision-order': { cannot: 'walk refuses a start already read and every start lies inside the file, so each start is below the next; no lower bound remains (request #62 (1))' },
  'mergeSection: too-many-xref-entries': { t033: ['addEntry'], why: 'more distinct entries than maxObjects (ceiling 1,000,000); T014 allows 1,048,576, room for T036\'s few' },
  'readCompressedObject: object-malformed': { t033: ['readCompressed', 'readValue'], why: 'a compressed object whose value does not parse within its window; T014\'s tokenizer reads every form T033\'s lexer reads' },
  'readCompressedObject: xref-entry-mismatch': { t033: ['readCompressed'], why: 'the object-stream header pair at the entry\'s index names another object' },
  'readCompressedObject: xref-type2-not-object-stream': { t033: ['readCompressed', 'loadObjectStream', 'readIndirect'], why: 'the stream\'s entry not in use, an object of another number at its offset, an index at or past /N, or an offset at or past the data' },
  'readInUseObject: object-malformed': { t033: ['readIndirect', 'readValue'], why: 'an in-use object whose value does not parse; T014\'s tokenizer reads every form T033\'s lexer reads' },
  'readInUseObject: xref-entry-mismatch': { t033: ['readIndirect'], why: 'no object header at the entry\'s offset, or one with another number or generation' },
  'readObjectStream: xref-type2-not-object-stream': { t033: ['loadObjectStream', 'readIndirect'], why: 'no /Type /ObjStm stream, a bad /N or /First, or /First past the data' },
  'readSection: prev-not-xref': { t033: ['readChain', 'readXrefStream', 'readIndirect'], why: 'a /Prev past the file, or naming neither `xref` nor a /Type /XRef stream object; T036\'s /Prev names the base\'s startxref, which T033 read' },
  'readSection: startxref-not-xref': { cannot: 'the final startxref names the section T036 appends and writes itself' },
  'readSection: xref-stream-malformed': { t033: ['readChain'], why: 'a chain stream\'s /Prev that is not a non-negative integer; a hidden /XRefStm stream\'s /Prev is never read (request #64 (1))' },
  'readTableEntry: xref-table-malformed': { t033: ['readXrefTable'], why: 'a table entry that is not an offset, a generation of at most 65535 and `n` or `f`' },
  'readTableSection: trailer-malformed': { t033: ['readXrefTable', 'readChain'], why: 'the trailer is not a dictionary, or its /Prev or /XRefStm is not a non-negative integer' },
  'readTableSection: xref-table-malformed': { t033: ['readXrefTable'], why: 'a subsection header that is not two unsigned numbers, or a table that never reaches `trailer`' },
  'readTableSection: xrefstm-not-xref-stream': { t033: ['readChain', 'readXrefStream'], why: '/XRefStm past the file, or not a /Type /XRef stream object' },
  'streamBody: too-much-work': { t033: ['readIndirect'], why: 'an object stream /Length past the end of the file (the input bound holds the stream bound)' },
  'streamBody: xref-stream-malformed': { t033: ['readIndirect'], why: 'a chain or hidden cross-reference stream /Length that is negative, runs past the file, or does not end at `endstream`' },
  'streamBody: xref-stream-too-large': { t033: ['readIndirect'], why: 'a chain or hidden cross-reference stream /Length past the end of the file' },
  'streamBody: xref-type2-not-object-stream': { t033: ['readIndirect', 'streamLength'], why: 'an object stream /Length that is negative, runs past the file, or does not end at `endstream`' },
  'streamLength: xref-type2-not-object-stream': { t033: ['streamLength', 'readIndirect'], why: 'an object stream /Length absent, not an integer, or a reference to no in-use integer object read with its entry\'s generation' },
  'undoPngPredictor: png-filter-unknown': { t033: ['unpredictPng'], why: 'a chain or hidden cross-reference stream with a PNG row filter byte above 4' },
  'undoPngPredictor: xref-stream-malformed': { t033: ['unpredictPng'], why: 'a chain or hidden cross-reference stream whose data is not a whole number of PNG rows' },
  'undoPngPredictor: xref-type2-not-object-stream': { t033: ['unpredictPng'], why: 'an object stream whose data is not whole PNG rows, or with a row filter byte above 4' },
  'walk: input-too-large': { cannot: 'verifyPdf refuses an input above MAX_SEALED_PDF_BYTES before the reader runs, and T036 refuses a composition above 48 MiB' },
  'walk: prev-revisited': { t033: ['readChain'], why: 'an offset seen again; a new offset reaching a section already read leads on to that section\'s /Prev, already seen (a section without /Prev ends the chain)' },
  'walk: too-many-revisions': { t033: ['readChain'], why: 'more than maxXrefSections sections (ceiling 256); T014 allows 257, one more for T036\'s section' },
  'widths: xref-stream-malformed': { t033: ['readXrefStream'], why: 'a chain or hidden cross-reference stream whose /W is not three non-negative integers, is all zero, or is wider than 8 bytes (T033 allows 6)' },
  'xrefStreamEntries: xref-stream-malformed': { t033: ['readXrefStream'], why: 'a chain or hidden cross-reference stream with a bad /Size or /Index (an absent or null /Index is [0 /Size]), or data whose length is not the rows\'' },
  'SignatureCollector.result: multiple-signatures': { t033: ['classifyDict', 'classifyValue'], why: 'a base signature or timestamp dictionary, /ByteRange with /Contents, /DocMDP or /UR3, or signed /FT /Sig field makes T033 refuse it as already-signed, so T036\'s signature is the only one' },
  'SignatureCollector.result: signature-compressed': { t033: ['classifyDict', 'classifyValue'], why: 'a signature dictionary in a base object stream makes T033 refuse it as already-signed; T036 writes its own signature dictionary uncompressed' },
});

const STRUCTURE = new URL('../../../src/verifier/structure.ts', import.meta.url);
const T033 = ['parser.ts', 'filters.ts', 'lexer.ts', 'policy.ts'].map((name) => new URL(`../../../src/pdf/${name}`, import.meta.url));

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

/** The code a site key names: `function: code`. */
const codeOfSite = (site) => site.slice(site.indexOf(': ') + 2);

/** The signature scan's details: the literals of the detail member in structure.ts's SignatureScan type. */
function scanDetailsFromSource(code) {
  const type = /export type SignatureScan =((?:\n\s+\|[^\n]*)+)/.exec(code);
  assert.ok(type, 'the SignatureScan type is found');
  return [...new Set([...type[1].matchAll(/detail: ([^}]*)\}/g)].flatMap((m) => [...m[1].matchAll(/'([a-z0-9-]+)'/g)].map((x) => x[1])))];
}

/**
 * The emission sites of structure.ts: `function: code` for each function or
 * method and each declared code or scan detail its body names, as a literal or
 * as a DecodeFaults key (one site per table binding the key).
 */
function sitesFromSource() {
  const code = stripComments(readFileSync(STRUCTURE, 'utf8'));
  const { declared } = codesFromSource();
  const known = new Set([...declared, ...scanDetailsFromSource(code)]);
  const tables = new Map();
  for (const m of code.matchAll(/const (\w+): DecodeFaults = \{([^}]*)\};/g)) {
    tables.set(m[1], new Map([...m[2].matchAll(/(\w+): '([a-z0-9-]+)'/g)].map((x) => [x[1], x[2]])));
  }
  assert.deepEqual([...tables.keys()].sort(), ['OBJECT_STREAM_FAULTS', 'XREF_STREAM_FAULTS'], 'the DecodeFaults tables are found');
  const sites = new Set();
  let current = null;
  let owner = null;
  for (const line of code.split('\n')) {
    const top = /^(?:export\s+)?(function|class|const|let|interface|type)\s+(\w+)/.exec(line);
    if (top) {
      owner = top[1] === 'class' ? top[2] : null;
      current = top[1] === 'function' ? top[2] : null;
      continue;
    }
    const method = owner === null ? null : /^ {2}(?:(?:private|public|static|readonly)\s+)*(\w+)\s*\(.*\)\s*(?::[^{]*)?\{\s*$/.exec(line);
    if (method) {
      current = `${owner}.${method[1]}`;
      continue;
    }
    if (current === null) continue;
    for (const m of line.matchAll(/'([a-z0-9-]+)'/g)) if (known.has(m[1])) sites.add(`${current}: ${m[1]}`);
    for (const m of line.matchAll(/\bfaults\.(\w+)/g)) {
      for (const table of tables.values()) if (table.has(m[1])) sites.add(`${current}: ${table.get(m[1])}`);
    }
  }
  return [...sites].sort();
}

/** structure.ts's code with comments, string and template literal contents, and the import statement removed. */
function bareCode() {
  return stripComments(readFileSync(STRUCTURE, 'utf8'))
    .replace(/^import\s*\{[^}]*\}\s*from\s*'[^']*';$/gm, '')
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''")
    .replace(/`(?:[^`\\]|\\.)*`/g, '``');
}

test('[VB-06] the fault map covers exactly the structure fault codes derived from the source (request #62 (4))', () => {
  const { declared, emitted, faultLiterals } = codesFromSource();
  assert.deepEqual(declared, [...STRUCTURE_DETAILS], 'the declaration read from the source is the exported list');
  assert.ok(faultLiterals.length >= 20, 'the scan read the fault() calls');
  assert.deepEqual([...new Set(faultLiterals)].filter((c) => !declared.includes(c)), [], 'every code passed to fault() is declared');
  assert.deepEqual(declared.filter((c) => !emitted.includes(c)), [], 'every declared code is emitted');
  // Per site since request #64 (6): the structure codes the site keys name.
  const mapped = [...new Set(Object.keys(FAULT_MAP).map(codeOfSite))].filter((c) => declared.includes(c));
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

test('[VB-06] the fault map is per emission site: its keys are exactly the function and code pairs derived from structure.ts (request #64 (6))', () => {
  const sites = sitesFromSource();
  assert.ok(sites.length >= 40, `the scan read the emission sites (${sites.length})`);
  const mapped = Object.keys(FAULT_MAP);
  assert.deepEqual(sites.filter((s) => !mapped.includes(s)), [], 'unmapped emission sites');
  assert.deepEqual(mapped.filter((s) => !sites.includes(s)), [], 'mapped sites that no longer exist');
  const { declared } = codesFromSource();
  const code = stripComments(readFileSync(STRUCTURE, 'utf8'));
  const named = new Set(sites.map(codeOfSite));
  assert.deepEqual([...declared, ...scanDetailsFromSource(code)].filter((c) => !named.has(c)), [], 'every code and scan detail has a site');
});

test('[VB-06] the signature scan outcomes are in the map, each covered by T033\'s classifyDict (request #64 (2))', () => {
  const details = scanDetailsFromSource(stripComments(readFileSync(STRUCTURE, 'utf8')));
  assert.ok(details.length >= 2, 'the scan details are derived');
  for (const detail of details) {
    const entries = Object.entries(FAULT_MAP).filter(([site]) => codeOfSite(site) === detail);
    assert.ok(entries.length > 0, `${detail} is mapped`);
    for (const [site, entry] of entries) assert.ok(entry.t033?.includes('classifyDict'), `${site} cites classifyDict`);
  }
});

test('[VB-06] structure.ts holds no type assertion but as const, no any and no TypeScript suppression comment (request #64 (4))', () => {
  const raw = readFileSync(STRUCTURE, 'utf8');
  assert.doesNotMatch(raw, /ts-(?:ignore|expect-error|nocheck)/, 'a TypeScript suppression comment');
  const code = bareCode();
  assert.ok(code.includes('as const'), 'the scan reads the declaration');
  assert.deepEqual([...code.matchAll(/\bas\s+(?!const\b)[\w{[(]+/g)].map((m) => m[0]), [], 'a type assertion other than as const');
  assert.deepEqual([...code.matchAll(/(?:^|[=(,:?&|!]|\breturn)\s*<[A-Za-z_]/gm)].map((m) => m[0].trim()), [], 'an angle-bracket type assertion');
  assert.deepEqual([...code.matchAll(/[\w)\]]!(?!=)/g)].map((m) => m[0]), [], 'a non-null assertion');
  assert.doesNotMatch(code, /\bany\b/, 'an any type');
});
