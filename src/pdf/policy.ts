// SPDX-License-Identifier: Apache-2.0
//
// Active-content and signature policy of the bounded PDF parser (T033). One definition,
// applied by the parser to every object of a document and by the parse service (parent
// side) to the objects a child reports, so the two can never disagree.
//
// Rejected as active content (detection names in parentheses):
// - JavaScript (javascript), Launch actions (launch), embedded files (embedded-file) and
//   RichMedia (rich-media);
// - A-008 P08: XFA forms (xfa), 3D artwork and its /OnInstantiate scripts (3d), Screen
//   annotations (screen) and Rendition actions or dictionaries (rendition);
// - A-009 LBR-5: SubmitForm (submit-form), ImportData (import-data), GoToR (remote-goto)
//   and GoToE (embedded-goto) actions, Movie annotations or actions (movie) and Sound
//   annotations, actions or objects (sound);
// - any /OpenAction (open-action) or /AA additional action (additional-action) other than
//   same-document navigation: a destination array, or a /GoTo action whose /Next chain is
//   also /GoTo only. An action already covered by a specific detection above is reported
//   under that name only.
// Plain /URI link actions (/A on a link annotation) stay allowed.
//
// Existing digital signatures: signature and timestamp dictionaries, /ByteRange with
// /Contents, /DocMDP or /UR3 permissions, and signed /FT /Sig fields.

import { isDict, nameOf, type PdfDict, type PdfValue } from './lexer.ts';

export interface PolicyFindings {
  signatures: number;
  readonly active: Set<string>;
  readonly features: Set<string>;
}

/** Resolves an indirect reference; returns undefined when the target is not available. */
export type Resolver = (value: PdfValue | undefined) => PdfValue | undefined;

const MAX_ACTION_CHAIN = 32;

export function createFindings(): PolicyFindings {
  return { signatures: 0, active: new Set(), features: new Set() };
}

/** Specific active-content detections of one dictionary on its own (no recursion). */
export function activeKinds(dict: PdfDict): Set<string> {
  const map = dict.map;
  const type = nameOf(dict, 'Type');
  const subtype = nameOf(dict, 'Subtype');
  const action = nameOf(dict, 'S');
  const found = new Set<string>();
  if (map.has('JS') || action === 'JavaScript' || map.has('JavaScript')) found.add('javascript');
  if (action === 'Launch') found.add('launch');
  if (type === 'EmbeddedFile' || map.has('EmbeddedFiles') || map.has('EF')) found.add('embedded-file');
  if (subtype === 'RichMedia' || map.has('RichMediaContent') || map.has('RichMediaSettings')) found.add('rich-media');
  if (map.has('XFA')) found.add('xfa');
  if (subtype === '3D' || type === '3D' || map.has('3DD') || map.has('OnInstantiate')) found.add('3d');
  if (subtype === 'Screen') found.add('screen');
  if (action === 'Rendition' || type === 'Rendition') found.add('rendition');
  if (action === 'SubmitForm') found.add('submit-form');
  if (action === 'ImportData') found.add('import-data');
  if (action === 'GoToR') found.add('remote-goto');
  if (action === 'GoToE') found.add('embedded-goto');
  if (subtype === 'Movie' || action === 'Movie') found.add('movie');
  if (subtype === 'Sound' || action === 'Sound' || type === 'Sound') found.add('sound');
  return found;
}

/** Report a non-navigation action reached from /OpenAction or /AA under `generic`. */
function checkNavigation(value: PdfValue | undefined, resolve: Resolver, generic: string, findings: PolicyFindings): void {
  const seen = new Set<PdfDict>();
  const visit = (raw: PdfValue | undefined, depth: number): void => {
    const action = resolve(raw);
    if (action === undefined) return;
    if (!isDict(action)) {
      findings.active.add(generic);
      return;
    }
    if (seen.has(action)) return;
    seen.add(action);
    if (depth > MAX_ACTION_CHAIN) {
      findings.active.add(generic);
      return;
    }
    if (activeKinds(action).size > 0) return;
    if (nameOf(action, 'S') !== 'GoTo') {
      findings.active.add(generic);
      return;
    }
    const next = action.map.get('Next');
    if (next === undefined) return;
    const resolved = resolve(next);
    if (Array.isArray(resolved)) for (const item of resolved) visit(item, depth + 1);
    else visit(next, depth + 1);
  };
  visit(value, 0);
}

/** Apply the policy to one dictionary (callers recurse into nested values themselves). */
export function classifyDict(dict: PdfDict, resolve: Resolver, findings: PolicyFindings): void {
  const map = dict.map;
  const type = nameOf(dict, 'Type');
  if (type === 'Sig' || type === 'DocTimeStamp' || (map.has('ByteRange') && map.has('Contents')) || map.has('DocMDP') || map.has('UR3')) {
    findings.signatures += 1;
  }
  if (nameOf(dict, 'FT') === 'Sig') {
    const signed = map.get('V');
    if (signed !== undefined && signed !== null) findings.signatures += 1;
    else findings.features.add('unsigned-signature-field');
  }
  for (const kind of activeKinds(dict)) findings.active.add(kind);

  if (map.has('OpenAction')) {
    const open = resolve(map.get('OpenAction'));
    if (open !== undefined && !Array.isArray(open)) checkNavigation(open, resolve, 'open-action', findings);
  }
  if (map.has('AA')) {
    const additional = resolve(map.get('AA'));
    if (additional === undefined) return;
    if (!isDict(additional)) {
      findings.active.add('additional-action');
      return;
    }
    for (const trigger of additional.map.values()) checkNavigation(trigger, resolve, 'additional-action', findings);
  }
}

/** Apply the policy to a value and everything nested in it (references are not followed). */
export function classifyValue(value: PdfValue, resolve: Resolver, findings: PolicyFindings, depth = 0): void {
  if (depth > 512) return;
  if (Array.isArray(value)) {
    for (const item of value) classifyValue(item, resolve, findings, depth + 1);
    return;
  }
  if (!isDict(value)) return;
  classifyDict(value, resolve, findings);
  for (const inner of value.map.values()) classifyValue(inner, resolve, findings, depth + 1);
}

