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
//   private-key-pem    PEM private-key blocks of any type, including indented
//                      blocks and blocks inside strings with escaped newlines
//   pkcs12-content     PKCS#12/PFX by extension, by DER structure, or as
//                      base64-embedded DER
//   sqlite-database    SQLite database, WAL or rollback-journal headers
//   fixture-image      raster or SVG images under any fixtures/ directory
//   env-file           .env, .env.* and .envrc files
//   secret-assignment  a known secret name assigned a literal value
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

function isEnvFile(path) {
  const name = basename(path);
  return name === '.env' || name.startsWith('.env.') || name === '.envrc';
}

function underFixtures(path) {
  return `/${path}`.includes('/fixtures/');
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

/** DER/BER length at `pos`: { next } or null. Indefinite length is accepted. */
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

// A real line break, or an escaped one (\n or \r\n) inside a string literal.
const NEWLINE = String.raw`(?:\r?\n|(?:\\r)?\\n)`;
const PEM_PRIVATE_KEY = new RegExp(
  String.raw`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----` +
    `${NEWLINE}(?:[ \\t]*[A-Za-z0-9-]+: [^\\r\\n\\\\]*${NEWLINE})*(?:[ \\t]*${NEWLINE})?[ \\t]*[A-Za-z0-9+/=]{16,}`,
  'g',
);

// Base64 of a DER SEQUENCE with a long-form length starts "MI" followed by I..Q.
const BASE64_DER = /MI[I-Q][A-Za-z0-9+/]{40,}/g;

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

// NAME (optionally quoted) followed by ":" or "=" (not "==", "=>", "=~") and a
// value: double-quoted, single-quoted, backtick (no interpolation) or bare.
const ASSIGNMENT =
  /(?<![A-Za-z0-9_$.-])(["'`]?)([A-Za-z_][A-Za-z0-9_.-]*)\1[ \t]*(?::|=(?![=>~]))[ \t]*(?:"((?:[^"\\\r\n]|\\.)*)"|'((?:[^'\\\r\n]|\\.)*)'|`((?:[^`\\\r\n$]|\\.)*)`|([^\s"'`,;#&|)\]}]+))/g;

// Bare (unquoted) values count only in configuration-style files.
const BARE_VALUE_EXTENSIONS = new Set(['', '.ini', '.cfg', '.conf', '.properties', '.yaml', '.yml', '.toml', '.sh', '.bash', '.zsh']);

const REFERENCE_VALUE =
  /^(?:\$\{[^}]*\}|\$\(.*\)|\$[A-Za-z_][A-Za-z0-9_]*|\{\{.*\}\}|<[^>]*>|%[A-Za-z_][A-Za-z0-9_]*%|(?:process\.env|import\.meta\.env)\b.*)$/;
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

function isLiteralSecret(value, name) {
  if (value.length < 8) return false;
  if (value.includes('${')) return false;
  if (REFERENCE_VALUE.test(value) || PLACEHOLDER_WORDS.test(value)) return false;
  if (/^[A-Z][A-Z0-9_]*$/.test(value)) return false; // names another variable
  if (/^(?:true|false|null|none|undefined)$/i.test(value)) return false;
  if (value.toLowerCase() === name.toLowerCase()) return false;
  return true;
}

function allowsBareValues(path) {
  return isEnvFile(path) || BARE_VALUE_EXTENSIONS.has(extname(basename(path)).toLowerCase());
}

function lineAt(text, index) {
  let line = 1;
  for (let i = text.indexOf('\n'); i !== -1 && i < index; i = text.indexOf('\n', i + 1)) line += 1;
  return line;
}

function isText(buffer) {
  return !buffer.subarray(0, TEXT_PROBE_BYTES).includes(0x00);
}

function textFindings(path, buffer) {
  const found = [];
  const text = buffer.toString('latin1');

  let count = 0;
  for (const match of text.matchAll(PEM_PRIVATE_KEY)) {
    found.push({ rule: 'private-key-pem', line: lineAt(text, match.index) });
    if ((count += 1) >= MAX_MATCHES_PER_RULE) break;
  }

  count = 0;
  for (const match of text.matchAll(BASE64_DER)) {
    if (isPfx(Buffer.from(match[0].slice(0, 40), 'base64'))) found.push({ rule: 'pkcs12-content', line: lineAt(text, match.index) });
    if ((count += 1) >= MAX_MATCHES_PER_RULE) break;
  }

  if (underFixtures(path) && SVG_ELEMENT.test(text)) found.push({ rule: 'fixture-image' });

  const bare = allowsBareValues(path);
  count = 0;
  for (const match of text.matchAll(ASSIGNMENT)) {
    const name = match[2];
    if (!isSecretName(name)) continue;
    const quoted = match[3] ?? match[4] ?? match[5];
    const value = quoted ?? (bare ? match[6] : undefined);
    if (value === undefined || !isLiteralSecret(value, name)) continue;
    found.push({ rule: 'secret-assignment', line: lineAt(text, match.index) });
    if ((count += 1) >= MAX_MATCHES_PER_RULE) break;
  }
  return found;
}

function contentFindings(path, buffer) {
  const found = [];
  if (isSqlite(buffer)) found.push({ rule: 'sqlite-database' });
  if (isPfx(buffer)) found.push({ rule: 'pkcs12-content' });
  if (underFixtures(path) && imageKind(buffer)) found.push({ rule: 'fixture-image' });
  if (isText(buffer)) found.push(...textFindings(path, buffer));
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
