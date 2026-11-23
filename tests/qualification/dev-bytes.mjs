// SPDX-License-Identifier: Apache-2.0
//
// "Dev bytes not in distributable" check (T027, QL-03): content of a package
// outside the production closure must not appear in dist/.
//
// What it compares. Every regular file in dist/ is examined as raw bytes and
// as the content it decodes to, up to MAX_DECODE_DEPTH levels: each base64 or
// base64url run of MIN_BASE64_CHARS or more characters (a data: URI included),
// each gzip member found anywhere in the bytes (trailing data tolerated), and
// a whole .br file as brotli. Against each of these views it looks for the
// installed files of every non-production package (devDependencies).
//
// Findings:
//   - dist-symlink:    a symbolic link (or other non-regular file) in dist/;
//                      links are never followed;
//   - asset-copy:      a dist/ file byte-identical to a file of a
//                      non-production package (from scripts/license-inventory.mjs,
//                      which classifies such an owner as shipped by asset copy);
//   - embedded-bytes:  a view that contains the complete content of a
//                      non-production file of at least MIN_EMBEDDED_BYTES bytes
//                      (`via` names the decoding: raw, base64, gzip, brotli);
//   - embedded-chunks: a view that contains, after both sides are normalized
//                      (JavaScript, CSS and HTML comments and all whitespace
//                      removed), at least min(MIN_MATCHED_CHUNKS, n) of the n
//                      CHUNK_CHARS-character chunks of a non-production text
//                      file. License texts, and chunks that occur in
//                      COMMON_CHUNK_PACKAGES or more non-production packages
//                      (shared idioms), are not fingerprinted.
//
// What it does not prove: content that was transformed beyond comment and
// whitespace removal (identifiers renamed, code transpiled or minified with
// other rewrites), split below CHUNK_CHARS characters, or encoded in any way
// not listed above (zlib or raw deflate without a gzip header, brotli outside a
// .br file, encryption). Build provenance, which closes that gap, is the
// build's input manifest (docs/qualification.md, "Forward requirement").
//
// Read errors are never skipped: they throw.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { brotliDecompressSync, constants, inflateRawSync } from 'node:zlib';

import { buildInventory, isLicenseText } from '../../scripts/license-inventory.mjs';

export const MIN_EMBEDDED_BYTES = 64;
export const CHUNK_CHARS = 64;
export const MIN_MATCHED_CHUNKS = 2;
export const COMMON_CHUNK_PACKAGES = 3;
export const MAX_DECODE_DEPTH = 3;
export const MIN_BASE64_CHARS = 64;
const MAX_DECODED_BYTES = 64 * 1024 * 1024;
const TEXT_PROBE_BYTES = 8192;
const GZIP_MAGIC = Buffer.from([0x1f, 0x8b, 0x08]);
const BASE64_RUN = new RegExp(`[A-Za-z0-9+/_-]{${MIN_BASE64_CHARS},}={0,2}`, 'g');

export class DevBytesError extends Error {}

function read(path) {
  try {
    return readFileSync(path);
  } catch (error) {
    throw new DevBytesError(`${path} could not be read: ${error.code ?? error.message}`);
  }
}

/** Regular files of an installed package (nested node_modules excluded); read errors throw. */
function packageFiles(dir, rel = '', out = []) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (error) {
    throw new DevBytesError(`${dir} could not be read: ${error.code ?? error.message}`);
  }
  for (const entry of entries) {
    const path = rel === '' ? entry.name : `${rel}/${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules') packageFiles(join(dir, entry.name), path, out);
    } else if (entry.isFile()) {
      out.push(path);
    }
  }
  return out;
}

function isText(bytes) {
  return !bytes.subarray(0, TEXT_PROBE_BYTES).includes(0x00);
}

/** Comments (/* *\/, //, <!-- -->) and all whitespace removed; applied alike to both sides. */
export function normalizeForChunks(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/(^|[^:\\])\/\/[^\r\n]*/gm, '$1')
    .replace(/\s+/g, '');
}

function tooLarge(error) {
  return error?.code === 'ERR_BUFFER_TOO_LARGE' || error instanceof RangeError;
}

/** Inflate the gzip member whose header starts at `at`, or null when it is not one. */
function gunzipAt(bytes, at, label) {
  if (bytes.length < at + 18) return null;
  const flags = bytes[at + 3];
  if (flags & 0xe0) return null;
  let pos = at + 10;
  if (flags & 0x04) pos += 2 + bytes.readUInt16LE(pos);
  for (const bit of [0x08, 0x10]) {
    if (!(flags & bit)) continue;
    const end = bytes.indexOf(0x00, pos);
    if (end < 0) return null;
    pos = end + 1;
  }
  if (flags & 0x02) pos += 2;
  if (pos >= bytes.length) return null;
  try {
    return inflateRawSync(bytes.subarray(pos), { finishFlush: constants.Z_SYNC_FLUSH, maxOutputLength: MAX_DECODED_BYTES });
  } catch (error) {
    if (tooLarge(error)) throw new DevBytesError(`${label}: gzip member at byte ${at} inflates beyond ${MAX_DECODED_BYTES} bytes`);
    return null; // not a deflate stream: these bytes are not gzip
  }
}

/** The raw bytes of a dist/ file and everything they decode to. */
function decodedViews(bytes, via, depth, label, out) {
  out.push({ bytes, via });
  if (depth >= MAX_DECODE_DEPTH) return out;
  for (let at = bytes.indexOf(GZIP_MAGIC); at !== -1; at = bytes.indexOf(GZIP_MAGIC, at + 1)) {
    const inflated = gunzipAt(bytes, at, label);
    if (inflated && inflated.length > 0) decodedViews(inflated, `${via}>gzip`, depth + 1, label, out);
  }
  for (const match of bytes.toString('latin1').matchAll(BASE64_RUN)) {
    const decoded = Buffer.from(match[0], 'base64');
    if (decoded.length > 0) decodedViews(decoded, `${via}>base64`, depth + 1, label, out);
  }
  return out;
}

function distViews(root, file) {
  const label = `dist/${file}`;
  const bytes = read(join(root, 'dist', file));
  const views = decodedViews(bytes, 'raw', 0, label, []);
  if (file.toLowerCase().endsWith('.br')) {
    let decoded = null;
    try {
      decoded = brotliDecompressSync(bytes, { maxOutputLength: MAX_DECODED_BYTES });
    } catch (error) {
      if (tooLarge(error)) throw new DevBytesError(`${label}: brotli content decodes beyond ${MAX_DECODED_BYTES} bytes`);
    }
    if (decoded) decodedViews(decoded, 'raw>brotli', 1, label, views);
  }
  return views;
}

/** Return [{ rule, package, file, dist, via?, chunks? }] for dev-package content found in root/dist. */
export function findDevBytesInDist(root) {
  const inventory = buildInventory(root);
  const findings = inventory.dist.symlinks.map((link) => ({ rule: 'dist-symlink', package: null, file: null, dist: link }));
  const distFiles = inventory.dist.files;
  if (distFiles.length === 0) return findings;

  const devRecords = inventory.records.filter((record) => record.installed && !record.reasons.includes('production-closure'));
  const reported = new Set(); // "package\0dist" (asset copies) and "package\0file\0dist"
  for (const record of devRecords) {
    for (const reason of record.reasons) {
      if (!reason.startsWith('asset copied into ')) continue;
      const dist = reason.slice('asset copied into '.length);
      findings.push({ rule: 'asset-copy', package: `${record.name}@${record.version}`, file: null, dist });
      reported.add(`${record.name}@${record.version}\0${dist}`);
    }
  }

  // Non-production files: their bytes, and normalized chunks of the text files.
  const devFiles = [];
  const chunkIndex = new Map(); // chunk -> { packages: Set, refs: [{ fileIndex, offset }] }
  for (const record of devRecords) {
    const pkg = `${record.name}@${record.version}`;
    for (const file of packageFiles(join(root, record.path))) {
      const bytes = read(join(root, record.path, file));
      const index = devFiles.length;
      const entry = { pkg, file, bytes, chunks: 0 };
      devFiles.push(entry);
      if (isLicenseText(file) || !isText(bytes)) continue;
      const normalized = normalizeForChunks(bytes.toString('latin1'));
      for (let offset = 0; offset + CHUNK_CHARS <= normalized.length; offset += CHUNK_CHARS) {
        const chunk = normalized.slice(offset, offset + CHUNK_CHARS);
        let slot = chunkIndex.get(chunk);
        if (!slot) chunkIndex.set(chunk, (slot = { packages: new Set(), refs: [] }));
        slot.packages.add(pkg);
        slot.refs.push({ fileIndex: index, offset });
        entry.chunks += 1;
      }
    }
  }
  for (const [chunk, slot] of chunkIndex) if (slot.packages.size >= COMMON_CHUNK_PACKAGES) chunkIndex.delete(chunk);

  for (const file of distFiles) {
    const dist = `dist/${file}`;
    const views = distViews(root, file);
    const largest = Math.max(...views.map((view) => view.bytes.length));
    const embedded = new Set();
    for (const [index, dev] of devFiles.entries()) {
      if (reported.has(`${dev.pkg}\0${dist}`)) continue;
      if (dev.bytes.length < MIN_EMBEDDED_BYTES || dev.bytes.length > largest) continue;
      const view = views.find((candidate) => (candidate.via !== 'raw' || candidate.bytes.length > dev.bytes.length) && candidate.bytes.indexOf(dev.bytes) !== -1);
      if (!view) continue;
      findings.push({ rule: 'embedded-bytes', package: dev.pkg, file: dev.file, dist, via: view.via });
      embedded.add(index);
    }

    const matched = new Map(); // fileIndex -> Set of matched chunk offsets
    for (const view of views) {
      if (!isText(view.bytes)) continue;
      const normalized = normalizeForChunks(view.bytes.toString('latin1'));
      for (let at = 0; at + CHUNK_CHARS <= normalized.length; at += 1) {
        const slot = chunkIndex.get(normalized.slice(at, at + CHUNK_CHARS));
        if (!slot) continue;
        for (const ref of slot.refs) {
          if (!matched.has(ref.fileIndex)) matched.set(ref.fileIndex, new Set());
          matched.get(ref.fileIndex).add(ref.offset);
        }
      }
    }
    for (const [index, offsets] of [...matched].sort((a, b) => a[0] - b[0])) {
      const dev = devFiles[index];
      if (embedded.has(index) || reported.has(`${dev.pkg}\0${dist}`)) continue;
      if (offsets.size < Math.min(MIN_MATCHED_CHUNKS, dev.chunks)) continue;
      findings.push({ rule: 'embedded-chunks', package: dev.pkg, file: dev.file, dist, chunks: `${offsets.size}/${dev.chunks}` });
    }
  }
  return findings;
}
