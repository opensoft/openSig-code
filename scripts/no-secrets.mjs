#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// openSig no-secrets gate (T026): secret-hygiene scan of what Git tracks.
//
//   node scripts/no-secrets.mjs [repository-dir]
//
// Paths scanned: `git ls-files` plus `git diff --cached --name-only`. For each
// path the staged (index) content is scanned and, where it differs, the
// working-tree content too. Untracked files are not scanned.
//
// Rules (stable names):
//   private-key-pem    PEM private-key blocks of any type: on their own lines,
//                      indented, inside strings with escaped newlines, split
//                      across concatenated or joined string pieces, flattened
//                      onto one line, and base64-encoded as a whole (for
//                      example a Kubernetes Secret value)
//   pkcs12-content     PKCS#12/PFX by extension, by DER or BER structure
//                      (definite or indefinite length), or as base64-embedded
//                      DER/BER
//   sqlite-database    SQLite database, WAL or rollback-journal headers
//   fixture-image      raster or SVG images under any fixture directory
//                      (fixtures/, Fixtures/, __fixtures__/, test-fixtures/ ...)
//   env-file           .env, .envrc, .env.*, .env-*, .env_* and *.env files
//   secret-assignment  a known secret name assigned a literal value, including
//                      typed declarations (TypeScript, Python, Rust, Go), Go
//                      ":=", command-line flags (--password=..., -Dx.password=...)
//                      and a password in URL userinfo (scheme://user:pw@host)
//
// Content encodings. The PEM and PKCS#12 rules run on every file, binary or
// not, and also on its UTF-16 decoding whenever it contains a NUL byte. Text
// files and UTF-16 text files (with or without a byte-order mark) get every
// text rule; other binary content gets the secret-assignment rule for quoted
// values only.
//
// Output names the rule, the file, the content source (index, worktree or
// path) and a line number where one applies. Matched content is never printed.
// Exit status: 0 clean, 1 findings, 2 usage or repository error.

import { spawnSync } from 'node:child_process';
import { lstatSync, readFileSync, readlinkSync, realpathSync } from 'node:fs';
import { basename, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const RULES = Object.freeze([
  'private-key-pem',
  'pkcs12-content',
  'sqlite-database',
  'fixture-image',
  'env-file',
  'secret-assignment',
]);

const MAX_BUFFER = 1024 * 1024 * 1024;
const TEXT_PROBE_BYTES = 8192;
const MAX_MATCHES_PER_RULE = 1000;

class GateError extends Error {}

// ---------------------------------------------------------------------------
// Git access
// ---------------------------------------------------------------------------

function git(cwd, args, input) {
  const run = spawnSync('git', ['-C', cwd, ...args], { encoding: 'buffer', maxBuffer: MAX_BUFFER, input });
  if (run.error) throw new GateError(`git ${args[0]} could not run: ${run.error.message}`);
  if (run.status !== 0) throw new GateError(`git ${args[0]} failed: ${run.stderr.toString('utf8').trim().split('\n')[0]}`);
  return run.stdout;
}

/** Index entries: { mode, sha, path } (all stages). */
function indexEntries(root) {
  const entries = [];
  for (const record of git(root, ['ls-files', '-s', '-z']).toString('utf8').split('\0')) {
    if (record === '') continue;
    const tab = record.indexOf('\t');
    const [mode, sha] = record.slice(0, tab).split(' ');
    entries.push({ mode, sha, path: record.slice(tab + 1) });
  }
  return entries;
}

function stagedPaths(root) {
  return git(root, ['diff', '--cached', '--name-only', '-z']).toString('utf8').split('\0').filter(Boolean);
}

/** Read blob contents by object id through one `git cat-file --batch` call. */
function readBlobs(root, shas) {
  const blobs = new Map();
  if (shas.length === 0) return blobs;
  const out = git(root, ['cat-file', '--batch'], Buffer.from(`${shas.join('\n')}\n`));
  let pos = 0;
  while (pos < out.length) {
    const newline = out.indexOf(0x0a, pos);
    if (newline < 0) break;
    const [sha, type, size] = out.toString('latin1', pos, newline).split(' ');
    if (type === 'missing' || size === undefined) {
      pos = newline + 1;
      continue;
    }
    const length = Number(size);
    blobs.set(sha, out.subarray(newline + 1, newline + 1 + length));
    pos = newline + 1 + length + 1;
  }
  return blobs;
}

function readWorktree(root, path) {
  const abs = join(root, path);
  let stat;
  try {
    stat = lstatSync(abs);
  } catch {
    return null;
  }
  if (stat.isSymbolicLink()) return Buffer.from(readlinkSync(abs), 'utf8');
  if (stat.isFile()) return readFileSync(abs);
  return null;
}

// ---------------------------------------------------------------------------
// Path rules
// ---------------------------------------------------------------------------

const PKCS12_EXTENSIONS = new Set(['.p12', '.pfx']);
const IMAGE_EXTENSIONS = new Set([
  '.png',
  '.apng',
  '.jpg',
  '.jpeg',
  '.jfif',
  '.gif',
  '.bmp',
  '.webp',
  '.tif',
  '.tiff',
  '.ico',
  '.avif',
  '.heic',
  '.heif',
  '.svg',
  '.svgz',
]);

/** .env, .envrc, .env.<x>, .env-<x>, .env_<x> and <x>.env (for example prod.env). */
function isEnvFile(path) {
  const name = basename(path).toLowerCase();
  return name === '.envrc' || name.endsWith('.env') || /^\.env[._-]/.test(name);
}

// A directory whose name is the word "fixture(s)", alone or delimited by
// "_", "-" or "." in any letter case: fixtures/, Fixtures/, __fixtures__/,
// test-fixtures/, fixtures.v2/.
const FIXTURE_DIRECTORY = /^(?:.*[._-])?_*fixtures?_*(?:[._-].*)?$/i;

function underFixtures(path) {
  return path.split('/').slice(0, -1).some((segment) => FIXTURE_DIRECTORY.test(segment));
}

function pathFindings(path) {
  const found = [];
  const extension = extname(path).toLowerCase();
  if (isEnvFile(path)) found.push({ rule: 'env-file' });
  if (PKCS12_EXTENSIONS.has(extension)) found.push({ rule: 'pkcs12-content' });
  if (underFixtures(path) && IMAGE_EXTENSIONS.has(extension)) found.push({ rule: 'fixture-image' });
  return found;
}

// ---------------------------------------------------------------------------
// Binary content rules
// ---------------------------------------------------------------------------

function startsWithBytes(buffer, bytes, offset = 0) {
  if (buffer.length < offset + bytes.length) return false;
  for (let i = 0; i < bytes.length; i += 1) if (buffer[offset + i] !== bytes[i]) return false;
  return true;
}

function ascii(buffer, start, end) {
  return buffer.length >= end ? buffer.toString('latin1', start, end) : '';
}

const SQLITE_DATABASE = [...Buffer.from('SQLite format 3\0', 'latin1')];
const SQLITE_WAL = [
  [0x37, 0x7f, 0x06, 0x82],
  [0x37, 0x7f, 0x06, 0x83],
];
const SQLITE_JOURNAL = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];

function isSqlite(buffer) {
  return startsWithBytes(buffer, SQLITE_DATABASE) || SQLITE_WAL.some((magic) => startsWithBytes(buffer, magic)) || startsWithBytes(buffer, SQLITE_JOURNAL);
}

function imageKind(buffer) {
  if (startsWithBytes(buffer, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'png';
  if (startsWithBytes(buffer, [0xff, 0xd8, 0xff])) return 'jpeg';
  const head6 = ascii(buffer, 0, 6);
  if (head6 === 'GIF87a' || head6 === 'GIF89a') return 'gif';
  if (ascii(buffer, 0, 4) === 'RIFF' && ascii(buffer, 8, 12) === 'WEBP') return 'webp';
  if (startsWithBytes(buffer, [0x49, 0x49, 0x2a, 0x00]) || startsWithBytes(buffer, [0x4d, 0x4d, 0x00, 0x2a])) return 'tiff';
  if (buffer.length >= 26 && ascii(buffer, 0, 2) === 'BM' && buffer.readUInt32LE(2) === buffer.length) return 'bmp';
  if (buffer.length >= 22 && startsWithBytes(buffer, [0x00, 0x00, 0x01, 0x00]) && buffer.readUInt16LE(4) > 0) return 'ico';
  if (ascii(buffer, 4, 8) === 'ftyp' && /^(avif|avis|heic|heix|mif1|msf1)$/.test(ascii(buffer, 8, 12))) return 'heif';
  return null;
}

/** DER/BER length at `pos`: { next } or null. BER indefinite length (0x80) is accepted. */
function derLength(buffer, pos) {
  if (pos >= buffer.length) return null;
  const first = buffer[pos];
  if (first < 0x80) return { next: pos + 1 };
  if (first === 0x80) return { next: pos + 1 };
  const count = first & 0x7f;
  if (count > 4 || pos + 1 + count > buffer.length) return null;
  return { next: pos + 1 + count };
}

// PKCS #7 content types data (1.2.840.113549.1.7.1) and signedData (...7.2).
const PKCS7_OID_PREFIX = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07];

/** PFX ::= SEQUENCE { version INTEGER (3), authSafe ContentInfo, macData OPTIONAL }. */
function isPfx(buffer) {
  if (buffer.length < 22 || buffer[0] !== 0x30) return false;
  const outer = derLength(buffer, 1);
  if (!outer) return false;
  let pos = outer.next;
  if (!startsWithBytes(buffer, [0x02, 0x01, 0x03], pos)) return false;
  pos += 3;
  if (buffer[pos] !== 0x30) return false;
  const contentInfo = derLength(buffer, pos + 1);
  if (!contentInfo) return false;
  pos = contentInfo.next;
  if (!startsWithBytes(buffer, PKCS7_OID_PREFIX, pos)) return false;
  const last = buffer[pos + PKCS7_OID_PREFIX.length];
  return last === 0x01 || last === 0x02;
}

// ---------------------------------------------------------------------------
// Text content rules
// ---------------------------------------------------------------------------

// --- private-key PEM ---------------------------------------------------------

const PEM_HEADER = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g;

// A real line break, or an escaped one (\n or \r\n) inside a string literal.
const NEWLINE = String.raw`(?:\r?\n|(?:\\r)?\\n)`;

// The classic layout after a header: a line break, optional "Name: value"
// header lines and a blank line, then a base64 run.
const PEM_BODY_LINES = new RegExp(
  `${NEWLINE}(?:[ \\t]*[A-Za-z0-9-]+: [^\\r\\n\\\\]*${NEWLINE})*(?:[ \\t]*${NEWLINE})?[ \\t]*[A-Za-z0-9+/=]{16,}`,
  'y',
);

// Any other layout: the key body is looked for in the text that follows the
// header, up to the next "-----" (the END line) or PEM_WINDOW characters,
// after collapsing escaped line breaks and the joins between string pieces
// ('a' + 'b', "a" "b", 'a', 'b', "a" . "b").
const PEM_WINDOW = 1024;
const ESCAPED_BREAK = /\\\\[rnt]|\\[rnt]/g;
const STRING_JOIN = /["'`]\s*(?:\+|\.{1,2}|,|&|\|\|)?\s*["'`]/g;
const BASE64_RUN = /[A-Za-z0-9+/]{24,}/g;

/** A key-body run: base64 alphabet with lower case, upper case and a digit or "+" or "/". */
function looksLikeKeyBody(run) {
  return /[a-z]/.test(run) && /[A-Z]/.test(run) && /[0-9+/]/.test(run);
}

function hasKeyBody(text, from) {
  PEM_BODY_LINES.lastIndex = from;
  if (PEM_BODY_LINES.test(text)) return true;
  let window = text.slice(from, from + PEM_WINDOW);
  const end = window.indexOf('-----');
  if (end >= 0) window = window.slice(0, end);
  const collapsed = window.replace(ESCAPED_BREAK, ' ').replace(STRING_JOIN, '');
  for (const run of collapsed.matchAll(BASE64_RUN)) if (looksLikeKeyBody(run[0])) return true;
  return false;
}

/** Indexes of private-key PEM headers followed by key material. */
function privateKeyIndexes(text) {
  const indexes = [];
  for (const match of text.matchAll(PEM_HEADER)) {
    if (!hasKeyBody(text, match.index + match[0].length)) continue;
    indexes.push(match.index);
    if (indexes.length >= MAX_MATCHES_PER_RULE) break;
  }
  return indexes;
}

// --- base64-encoded PEM -----------------------------------------------------------

/**
 * The base64 text of `bytes` at each of the three byte alignments, cut to the
 * characters that depend on those bytes only. `lead` is the number of
 * characters between the start of the base64 quantum and the marker text.
 */
function base64Markers(bytes) {
  return [0, 1, 2].map((shift) => {
    const encoded = Buffer.concat([Buffer.alloc(shift), bytes]).toString('base64');
    const lead = Math.ceil((8 * shift) / 6);
    return { lead, text: encoded.slice(lead, Math.floor((8 * (shift + bytes.length)) / 6)) };
  });
}

// "-----BEGIN" encoded once (LS0tLS1CRUdJT... at alignment 0), and encoded twice.
const BASE64_PEM_MARKERS = base64Markers(Buffer.from('-----BEGIN', 'latin1'));
const BASE64_PEM_MARKERS_TWICE = BASE64_PEM_MARKERS.flatMap((marker) => base64Markers(Buffer.from(marker.text, 'latin1')));
// Enough base64 text for a header and the start of its body, encoded twice.
const BASE64_PEM_SPAN = 4096;
const BASE64_NESTING = 2;

/** Decode the base64 text starting at `start`, across line breaks and indentation. */
function decodeBase64At(text, start) {
  const segment = text.slice(start, start + BASE64_PEM_SPAN).replace(/\\[rn]/g, '');
  const run = /^[A-Za-z0-9+/\s]*/.exec(segment)[0].replace(/\s+/g, '');
  return Buffer.from(run.slice(0, run.length - (run.length % 4)), 'base64').toString('latin1');
}

/** Indexes of base64 text that decodes to a private-key PEM (encoded up to BASE64_NESTING times). */
function base64PrivateKeyIndexes(text, depth = 1) {
  const indexes = [];
  const markers = depth < BASE64_NESTING ? [...BASE64_PEM_MARKERS, ...BASE64_PEM_MARKERS_TWICE] : BASE64_PEM_MARKERS;
  for (const marker of markers) {
    for (let i = text.indexOf(marker.text); i !== -1; i = text.indexOf(marker.text, i + 1)) {
      const start = i - marker.lead;
      if (start < 0) continue;
      const decoded = decodeBase64At(text, start);
      if (privateKeyIndexes(decoded).length > 0 || (depth < BASE64_NESTING && base64PrivateKeyIndexes(decoded, depth + 1).length > 0)) {
        indexes.push(i);
        if (indexes.length >= MAX_MATCHES_PER_RULE) return indexes;
      }
    }
  }
  return indexes;
}

// --- base64-embedded PKCS#12 ---------------------------------------------------------

// Base64 of a SEQUENCE tag (0x30) followed by a long-form or indefinite length
// byte 0x80..0x84 starts "MI" and then A..T. Every occurrence is decoded and
// checked structurally.
const BASE64_DER = /MI[A-T](?=[A-Za-z0-9+/]{40})/g;

function base64PfxIndexes(text) {
  const indexes = [];
  for (const match of text.matchAll(BASE64_DER)) {
    if (!isPfx(Buffer.from(text.slice(match.index, match.index + 40), 'base64'))) continue;
    indexes.push(match.index);
    if (indexes.length >= MAX_MATCHES_PER_RULE) break;
  }
  return indexes;
}

// --- secret assignments -----------------------------------------------------------

const SVG_ELEMENT = /<svg[\s>/]/i;

const SECRET_SUFFIXES = Object.freeze([
  'password',
  'passwd',
  'passphrase',
  'secret',
  'api_key',
  'apikey',
  'access_key',
  'secret_key',
  'private_key',
  'signing_key',
  'encryption_key',
  'hmac_key',
  'master_key',
  'access_token',
  'auth_token',
  'refresh_token',
  'bearer_token',
  'session_token',
  'oauth_token',
  'api_token',
  'github_token',
  'gh_token',
  'npm_token',
  'slack_token',
  'bot_token',
  'service_token',
  'mnemonic',
  'seed_phrase',
]);

// A type annotation: TypeScript (string, Record<K, V>, Map<K, Array<V>>,
// string[], A | B), Python (str, Optional[str], dict[str, list[str]],
// str | None) and Rust (&str, &'static str). Generic and subscript arguments
// nest one level; the character classes exclude their own brackets so every
// input has one parse (no catastrophic backtracking).
const TYPE_ARGS = String.raw`<[^=;\r\n<>()]*(?:<[^=;\r\n<>()]*>[^=;\r\n<>()]*)*>|\[(?=[^\]])[^=;\r\n[\]]*(?:\[[^=;\r\n[\]]*\][^=;\r\n[\]]*)*\]`;
const TYPE_TERM = String.raw`&?(?:'[A-Za-z_]+[ \t]+)?(?:mut[ \t]+)?[A-Za-z_$][\w$.]*(?:${TYPE_ARGS})?(?:\[\])*\??`;
const TYPE = String.raw`${TYPE_TERM}(?:[ \t]*\|[ \t]*${TYPE_TERM})*`;

// A value: double-quoted, single-quoted, backtick (no interpolation) or bare.
const VALUE = String.raw`(?:"((?:[^"\\\r\n]|\\.)*)"|'((?:[^'\\\r\n]|\\.)*)'|` + '`((?:[^`\\\\\\r\\n$]|\\\\.)*)`' + String.raw`|([^\s"'` + '`' + String.raw`,;#&|)\]}]+))`;

// An optional "-" or "--" flag prefix, NAME (optionally quoted, optionally
// followed by TypeScript "?" or "!"), then an operator: Go ":=", a typed
// declaration ": TYPE =", ":" or "=" (not "==", "=>", "=~"), then a value.
// Groups: 1 flag prefix, 2 quote, 3 name, 4 operator, 5..8 value.
const ASSIGNMENT = new RegExp(
  String.raw`(?<![A-Za-z0-9_$.-])(--?)?(["'` + '`' + String.raw`]?)([A-Za-z_][A-Za-z0-9_.-]*)\2[?!]?[ \t]*(:=|:[ \t]*${TYPE}[ \t]*=(?![=>~])|:|=(?![=>~]))[ \t]*${VALUE}`,
  'g',
);

// Go typed declarations: var NAME TYPE = "value" (quoted values only).
const GO_TYPED = /\b(?:var|const)[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]+[[\]*A-Za-z_][\w.[\]*]*[ \t]*=(?![=>~])[ \t]*(?:"((?:[^"\\\r\n]|\\.)*)"|`([^`]*)`)/g;

// A password in URL userinfo: scheme://user:password@host.
const URL_CREDENTIALS = /\b[A-Za-z][A-Za-z0-9+.-]{1,31}:\/\/([^\s:/?#@'"`<>\\]{1,128}):([^\s/?#@'"`<>\\]{1,256})@(?=[A-Za-z0-9[])/g;
const URL_PASSWORD_PLACEHOLDER = /^(?:pass(?:word)?|passwd|pwd|secret|token|user(?:name)?|x+|\*+|\.+)$/i;

// Bare (unquoted) values count only in configuration-style files, and in
// command-line flags (--password=..., -Dapp.password=...) everywhere.
const BARE_VALUE_EXTENSIONS = new Set(['', '.ini', '.cfg', '.conf', '.properties', '.yaml', '.yml', '.toml', '.sh', '.bash', '.zsh']);
// Files where a backtick is shell command substitution, not a string literal.
const SHELL_EXTENSIONS = new Set(['', '.sh', '.bash', '.zsh']);

const REFERENCE_VALUE =
  /^(?:\$\{[^}]*\}|\$\(.*\)|\$[A-Za-z_][A-Za-z0-9_]*|\{\{.*\}\}|<[^>]*>|%[A-Za-z_][A-Za-z0-9_]*%|(?:process\.env|import\.meta\.env)\b.*)$/;
// A shell expansion or command substitution at the start of a value ($VAR,
// ${VAR}, $(command)), even when an unquoted value is cut at its first space.
const EXPANSION_PREFIX = /^\$[A-Za-z_({]/;
const PLACEHOLDER_WORDS = /example|placeholder|redacted|changeme|change[_-]me|replace[_-]?me|your[_-]|dummy|sample|not[_-]?a[_-]?secret|xxxx|\*\*\*\*/i;

function normalizeName(name) {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[-.]/g, '_')
    .toLowerCase();
}

export function isSecretName(name) {
  const normalized = normalizeName(name);
  return SECRET_SUFFIXES.some((suffix) => normalized === suffix || normalized.endsWith(`_${suffix}`));
}

/**
 * An upper-case value names another variable (OPENSIG_WEBHOOK_SECRET,
 * PASSWORD) when it contains "_" or is a short word without digits. A long or
 * digit-bearing upper-case value (a base32 TOTP secret) is a literal.
 */
function namesVariable(value) {
  if (!/^[A-Z][A-Z0-9_]*$/.test(value)) return false;
  return value.includes('_') || (value.length < 16 && !/[0-9]/.test(value));
}

function isLiteralSecret(value, name) {
  if (value.length < 8) return false;
  if (value.includes('${') || EXPANSION_PREFIX.test(value)) return false;
  if (REFERENCE_VALUE.test(value) || PLACEHOLDER_WORDS.test(value)) return false;
  if (namesVariable(value)) return false;
  if (/^(?:true|false|null|none|undefined)$/i.test(value)) return false;
  if (value.toLowerCase() === name.toLowerCase()) return false;
  return true;
}

function isLiteralUrlPassword(user, password) {
  if (password.length < 4 || /^\d{1,5}$/.test(password)) return false; // too short, or host:port
  if (password.includes('${') || EXPANSION_PREFIX.test(password) || REFERENCE_VALUE.test(password)) return false;
  if (PLACEHOLDER_WORDS.test(password) || URL_PASSWORD_PLACEHOLDER.test(password)) return false;
  return password.toLowerCase() !== user.toLowerCase();
}

function allowsBareValues(path) {
  return isEnvFile(path) || BARE_VALUE_EXTENSIONS.has(extname(basename(path)).toLowerCase());
}

function isShellLike(path) {
  return isEnvFile(path) || SHELL_EXTENSIONS.has(extname(basename(path)).toLowerCase());
}

/** Indexes of secret assignments with literal values. */
function assignmentIndexes(text, { bare, shell }) {
  const indexes = [];
  const add = (index) => {
    indexes.push(index);
    return indexes.length >= MAX_MATCHES_PER_RULE;
  };
  for (const match of text.matchAll(ASSIGNMENT)) {
    const [, flag, , name, operator] = match;
    if (!isSecretName(name)) continue;
    // `cond ? password : "fallback"`: the literal belongs to the ternary, not to the name.
    if (operator === ':' && /\?[ \t]*$/.test(text.slice(Math.max(0, match.index - 64), match.index))) continue;
    const backtick = match[7];
    if (backtick !== undefined && shell) continue; // shell command substitution
    const quoted = match[5] ?? match[6] ?? backtick;
    const bareCounts = bare || (flag !== undefined && operator === '=');
    const value = quoted ?? (bareCounts ? match[8] : undefined);
    if (value === undefined || !isLiteralSecret(value, name)) continue;
    if (add(match.index)) return indexes;
  }
  for (const match of text.matchAll(GO_TYPED)) {
    const value = match[2] ?? match[3];
    if (!isSecretName(match[1]) || !isLiteralSecret(value, match[1])) continue;
    if (add(match.index)) return indexes;
  }
  for (const match of text.matchAll(URL_CREDENTIALS)) {
    if (!isLiteralUrlPassword(match[1], match[2])) continue;
    if (add(match.index)) return indexes;
  }
  return indexes;
}

// --- per-file text views ---------------------------------------------------------

function lineAt(text, index) {
  let line = 1;
  for (let i = text.indexOf('\n'); i !== -1 && i < index; i = text.indexOf('\n', i + 1)) line += 1;
  return line;
}

function isText(buffer) {
  return !buffer.subarray(0, TEXT_PROBE_BYTES).includes(0x00);
}

function swapBytes(buffer) {
  const copy = Buffer.from(buffer.subarray(0, buffer.length - (buffer.length % 2)));
  return copy.swap16();
}

/**
 * The decoded text of a UTF-16 file: a byte-order mark, or (without one) NUL
 * in nearly every high byte of the first TEXT_PROBE_BYTES. Otherwise null.
 */
function utf16Text(buffer) {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.subarray(2).toString('utf16le');
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) return swapBytes(buffer.subarray(2)).toString('utf16le');
  const pairs = Math.floor(Math.min(buffer.length, TEXT_PROBE_BYTES) / 2);
  if (pairs < 4) return null;
  let evenNul = 0;
  let oddNul = 0;
  for (let i = 0; i < pairs * 2; i += 2) {
    if (buffer[i] === 0) evenNul += 1;
    if (buffer[i + 1] === 0) oddNul += 1;
  }
  if (oddNul >= pairs * 0.6 && evenNul <= pairs * 0.05) return buffer.toString('utf16le');
  if (evenNul >= pairs * 0.6 && oddNul <= pairs * 0.05) return swapBytes(buffer).toString('utf16le');
  return null;
}

/**
 * Findings in one decoded view of a file. `full` views (text, or UTF-16 text)
 * get every rule; other views (binary content and its UTF-16 decodings) get the
 * PEM and PKCS#12 rules and quoted secret assignments.
 */
function viewFindings(path, text, { full }) {
  const found = [];
  const push = (rule, indexes) => {
    for (const index of indexes) found.push({ rule, line: lineAt(text, index) });
  };
  push('private-key-pem', privateKeyIndexes(text));
  push('private-key-pem', base64PrivateKeyIndexes(text));
  push('pkcs12-content', base64PfxIndexes(text));
  if (full && underFixtures(path) && SVG_ELEMENT.test(text)) found.push({ rule: 'fixture-image' });
  push('secret-assignment', assignmentIndexes(text, { bare: full && allowsBareValues(path), shell: isShellLike(path) }));
  return found;
}

function contentFindings(path, buffer) {
  const found = [];
  if (isSqlite(buffer)) found.push({ rule: 'sqlite-database' });
  if (isPfx(buffer)) found.push({ rule: 'pkcs12-content' });
  if (underFixtures(path) && imageKind(buffer)) found.push({ rule: 'fixture-image' });
  const utf16 = utf16Text(buffer);
  if (utf16 !== null) {
    found.push(...viewFindings(path, utf16, { full: true }));
    found.push(...viewFindings(path, buffer.toString('latin1'), { full: false }));
    return found;
  }
  found.push(...viewFindings(path, buffer.toString('latin1'), { full: isText(buffer) }));
  if (buffer.includes(0x00)) {
    // UTF-16 text embedded in binary content, at either byte alignment.
    found.push(...viewFindings(path, buffer.toString('utf16le'), { full: false }));
    found.push(...viewFindings(path, buffer.subarray(1).toString('utf16le'), { full: false }));
  }
  return found;
}

// ---------------------------------------------------------------------------
// Scan and report
// ---------------------------------------------------------------------------

/**
 * Scan the repository containing `dir`.
 * Returns { root, scanned, findings: [{ rule, file, source, line? }] }.
 */
export function scanRepository(dir) {
  const root = git(resolve(dir), ['rev-parse', '--show-toplevel']).toString('utf8').trim();
  if (root === '') throw new GateError('not inside a Git working tree');
  const entries = indexEntries(root).filter((entry) => entry.mode !== '160000');
  const byPath = new Map();
  for (const entry of entries) {
    if (!byPath.has(entry.path)) byPath.set(entry.path, []);
    byPath.get(entry.path).push(entry);
  }
  const paths = [...new Set([...entries.map((entry) => entry.path), ...stagedPaths(root)])].sort();
  const blobs = readBlobs(root, [...new Set(entries.map((entry) => entry.sha))]);

  const findings = [];
  const seen = new Set();
  const add = (finding) => {
    const key = `${finding.rule}\0${finding.file}\0${finding.source}\0${finding.line ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(finding);
  };

  for (const path of paths) {
    for (const finding of pathFindings(path)) add({ ...finding, file: path, source: 'path' });
    const contents = [];
    for (const entry of byPath.get(path) ?? []) {
      const blob = blobs.get(entry.sha);
      if (blob) contents.push({ source: 'index', buffer: blob });
    }
    const worktree = readWorktree(root, path);
    if (worktree && !contents.some((content) => content.buffer.equals(worktree))) contents.push({ source: 'worktree', buffer: worktree });
    for (const content of contents) {
      for (const finding of contentFindings(path, content.buffer)) add({ ...finding, file: path, source: content.source });
    }
  }
  return { root, scanned: paths.length, findings };
}

function printablePath(path) {
  return /^[\x21-\x7e]+$/.test(path) ? path : JSON.stringify(path);
}

export function formatFinding(finding) {
  const line = finding.line === undefined ? '' : ` line=${finding.line}`;
  return `no-secrets: rule=${finding.rule} file=${printablePath(finding.file)} source=${finding.source}${line}`;
}

function main(argv) {
  if (argv.length > 1 || argv.some((arg) => arg.startsWith('-'))) {
    process.stderr.write('no-secrets: usage: node scripts/no-secrets.mjs [repository-dir]\n');
    process.stdout.write('no-secrets: ERROR usage\n');
    process.exitCode = 2;
    return;
  }
  let result;
  try {
    result = scanRepository(argv[0] ?? process.cwd());
  } catch (error) {
    process.stderr.write(`no-secrets: ${error instanceof GateError ? error.message : String(error?.stack ?? error)}\n`);
    process.stdout.write('no-secrets: ERROR repository\n');
    process.exitCode = 2;
    return;
  }
  for (const finding of result.findings) process.stdout.write(`${formatFinding(finding)}\n`);
  if (result.findings.length > 0) {
    const files = new Set(result.findings.map((finding) => finding.file)).size;
    process.stdout.write(`no-secrets: FAIL findings=${result.findings.length} files=${files} scanned=${result.scanned}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`no-secrets: PASS findings=0 scanned=${result.scanned}\n`);
    process.exitCode = 0;
  }
}

function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) main(process.argv.slice(2));
