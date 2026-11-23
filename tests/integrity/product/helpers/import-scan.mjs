// SPDX-License-Identifier: Apache-2.0
//
// A static import-boundary scanner for VB-01: src/verifier/ imports only node:*
// and src/verifier/**. T014 narrows node:* to an allowlist (no file, process,
// network or TLS module), and denies the names of default trust stores, the
// process environment and the clock, so the verifier stays pure and judges
// trust against configured anchors only.
//
// The scanner strips comments first, then reads every static import, side-effect
// import and `export ... from`. Any dynamic import, require, createRequire or
// import.meta, and any `import`/`from` it cannot account for, is a violation.

import { existsSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';

export const ALLOWED_NODE_MODULES = Object.freeze(['node:buffer', 'node:crypto', 'node:zlib']);

export const DENIED_TEXT = Object.freeze([
  'rootCertificates',
  'getCACertificates',
  'setDefaultCACertificates',
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
  'SSL_CERT_DIR',
  'process.',
  'Date.now',
  'new Date(',
  'performance.now',
]);

/** Remove // and block comments outside string and template literals. */
export function stripComments(source) {
  let out = '';
  let i = 0;
  let quote = null;
  while (i < source.length) {
    const c = source[i];
    const next = source[i + 1];
    if (quote !== null) {
      out += c;
      if (c === '\\') {
        out += next ?? '';
        i += 2;
        continue;
      }
      if (c === quote) quote = null;
      i += 1;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      quote = c;
      out += c;
      i += 1;
    } else if (c === '/' && next === '/') {
      while (i < source.length && source[i] !== '\n') i += 1;
    } else if (c === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2);
      i = end < 0 ? source.length : end + 2;
      out += ' ';
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

const STATIC_IMPORT = /\bimport\s+(?:type\s+)?[\w$*{},\s]+?\s+from\s*(['"])([^'"\n]+)\1/g;
const SIDE_EFFECT_IMPORT = /\bimport\s*(['"])([^'"\n]+)\1/g;
const EXPORT_FROM = /\bexport\s+(?:type\s+)?(?:\*(?:\s+as\s+[\w$]+)?|\{[^}]*\})\s*from\s*(['"])([^'"\n]+)\1/g;

/** Every module specifier in `source`, plus any form the scanner cannot vouch for. */
export function readSpecifiers(source) {
  const code = stripComments(source);
  const specifiers = [];
  const problems = [];
  let importStatements = 0;
  let fromClauses = 0;
  for (const match of code.matchAll(STATIC_IMPORT)) {
    specifiers.push(match[2]);
    importStatements += 1;
    fromClauses += 1;
  }
  for (const match of code.matchAll(SIDE_EFFECT_IMPORT)) {
    specifiers.push(match[2]);
    importStatements += 1;
  }
  for (const match of code.matchAll(EXPORT_FROM)) {
    specifiers.push(match[2]);
    fromClauses += 1;
  }
  if (/\bimport\s*\(/.test(code)) problems.push('dynamic import');
  if (/\brequire\s*\(/.test(code) || /\bcreateRequire\b/.test(code)) problems.push('require');
  if (/\bimport\s*\.\s*meta\b/.test(code)) problems.push('import.meta');
  if ((code.match(/\bimport\b/g) ?? []).length !== importStatements + (code.match(/\bimport\s*[(.]/g) ?? []).length) {
    problems.push('unrecognised import form');
  }
  if ((code.match(/\bfrom\s*['"]/g) ?? []).length !== fromClauses) problems.push('unrecognised from clause');
  for (const text of DENIED_TEXT) if (code.includes(text)) problems.push(`denied text ${text}`);
  return { specifiers, problems };
}

/** Violations of the boundary for one file under `root` (src/verifier/). */
export function scanFile(file, source, root) {
  const { specifiers, problems } = readSpecifiers(source);
  const violations = [...problems];
  for (const specifier of specifiers) {
    if (specifier.startsWith('node:')) {
      if (!ALLOWED_NODE_MODULES.includes(specifier)) violations.push(`node module outside the allowlist: ${specifier}`);
      continue;
    }
    if (!specifier.startsWith('./') && !specifier.startsWith('../')) {
      violations.push(`bare or absolute specifier: ${specifier}`);
      continue;
    }
    const target = resolve(dirname(file), specifier);
    const rel = relative(root, target);
    if (rel === '' || rel.startsWith('..') || rel.split(sep).includes('..')) {
      violations.push(`outside src/verifier: ${specifier}`);
    } else if (!target.endsWith('.ts')) {
      violations.push(`not a .ts module: ${specifier}`);
    } else if (!existsSync(target)) {
      violations.push(`missing module: ${specifier}`);
    }
  }
  return violations.map((v) => `${relative(root, file) || file}: ${v}`);
}

/** Every file under `root`, recursively. */
export function listFiles(root) {
  const out = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir).sort()) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else out.push(path);
    }
  };
  walk(root);
  return out;
}
