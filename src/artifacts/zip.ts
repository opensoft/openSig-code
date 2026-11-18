// SPDX-License-Identifier: Apache-2.0
//
// Deterministic ZIP writer for the evidence package (T039; research.md § Engine
// decision; plan.md § Project Structure, `src/artifacts/`). It is original code written
// from the ZIP file format (PKWARE APPNOTE 6.3.x: local file header § 4.3.7, central
// directory file header § 4.3.12, end of central directory record § 4.3.16). T016's
// package builder calls it.
//
// `writeZip(entries, limits?)` takes `{ name, data }` entries and returns the archive
// bytes. Equal entries give equal bytes, whatever order the caller lists them in:
//
// - entries are sorted by the bytes of their names (unsigned, byte by byte, a shorter
//   prefix first), so "B" comes before "a";
// - method 0 (store) only, so the compressed size equals the size; the CRC-32 comes from
//   `zlib.crc32`;
// - every entry carries the DOS date and time 1980-01-01 00:00:00 and the general
//   purpose flags with only bit 11 (UTF-8 name) set, always: no data descriptor, no
//   encryption;
// - no extra field, no per-entry comment and no archive comment; one disk only;
// - the same "version needed" (2.0) and "version made by" (Unix host, 2.0) everywhere,
//   internal attributes 0, and the external attributes of a regular file with mode 0644.
//
// Names are flat ASCII: 1 to 255 characters from letters, digits, `.`, `_` and `-`, not
// starting with `.`. So no path, traversal, Unicode-normalization or bidirectional-text
// case can arise. Two names that are equal when ASCII case is ignored are refused. An
// empty entry list is refused. Error messages carry entry indices and numbers, never a
// name or content.
//
// ZIP64 is never written. A limit is an inclusive maximum (request #44): a count, an entry
// size or an archive size equal to its limit is accepted, and one more is refused. The
// defaults are the ZIP64 escape values (0xFFFF for a count, 0xFFFFFFFF for a size) minus
// one, so they accept 65,534 entries and 0xFFFFFFFE bytes and refuse the escape values.
// A caller may lower a limit and never raise it; a raise is refused. The package builder
// passes the product's own bounds. Every check runs before any byte of data is read or
// copied.

import { crc32 } from 'node:zlib';

export type ZipErrorCode =
  | 'entries-invalid'
  | 'no-entries'
  | 'too-many-entries'
  | 'name-empty'
  | 'name-too-long'
  | 'name-invalid'
  | 'name-leading-dot'
  | 'name-duplicate'
  | 'entry-too-large'
  | 'archive-too-large'
  | 'limits-invalid';

export class ZipError extends Error {
  readonly code: ZipErrorCode;

  constructor(code: ZipErrorCode, detail: string) {
    super(`${code}: ${detail}`);
    this.name = 'ZipError';
    this.code = code;
  }
}

export interface ZipEntry {
  /** Flat ASCII: 1 to 255 letters, digits, `.`, `_` or `-`, not starting with `.`. */
  readonly name: string;
  readonly data: Uint8Array;
}

/** Each limit is an inclusive maximum; see the header comment. */
export interface ZipLimits {
  /** The most entries a list may hold. */
  readonly entryCountLimit: number;
  /** The most bytes one entry's data may hold. */
  readonly entryBytesLimit: number;
  /** The most bytes the archive may hold, headers and end record included. */
  readonly archiveBytesLimit: number;
}

/** The ZIP64 escape values (0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF) minus one: the defaults and the ceilings, each inclusive. */
export const ZIP_LIMITS: ZipLimits = Object.freeze({
  entryCountLimit: 0xfffe,
  entryBytesLimit: 0xfffffffe,
  archiveBytesLimit: 0xfffffffe,
});

const LIMIT_KEYS: readonly (keyof ZipLimits)[] = ['entryCountLimit', 'entryBytesLimit', 'archiveBytesLimit'];

const LOCAL_HEADER_SIGNATURE = 0x04034b50;
const CENTRAL_HEADER_SIGNATURE = 0x02014b50;
const END_RECORD_SIGNATURE = 0x06054b50;

const LOCAL_HEADER_BYTES = 30;
const CENTRAL_HEADER_BYTES = 46;
const END_RECORD_BYTES = 22;

/** 2.0: the default for a stored entry that needs no ZIP64 and no other feature. */
const VERSION_NEEDED = 20;
/** The high byte of "version made by": 3 is a Unix host; the low byte repeats 2.0. */
const VERSION_MADE_BY = (3 << 8) | VERSION_NEEDED;
/** General purpose bit 11: the name is UTF-8. No other bit is ever set. */
const FLAG_UTF8_NAME = 0x0800;
const METHOD_STORE = 0;
/** 00:00:00 in the MS-DOS time format. */
const DOS_TIME = 0x0000;
/** 1980-01-01 in the MS-DOS date format: ((1980 - 1980) << 9) | (1 << 5) | 1. */
const DOS_DATE = 0x0021;
/** Unix mode 0100644 (a regular file, rw-r--r--) in the high 16 bits: 0o100644 << 16. */
const EXTERNAL_ATTRIBUTES = 0x81a40000;

const MAX_NAME_LENGTH = 255;
const NAME_CHARACTERS = /^[A-Za-z0-9._-]+$/;

interface PlannedEntry {
  readonly nameBytes: Uint8Array;
  readonly data: Uint8Array;
  readonly size: number;
}

/** The effective limits: the defaults, lowered by `limits`. A raise, a bad value or an unknown key is refused. */
function resolveLimits(limits: Partial<ZipLimits>): ZipLimits {
  if (typeof limits !== 'object' || limits === null) throw new ZipError('limits-invalid', 'limits must be an object');
  for (const key of Object.keys(limits)) {
    if (!(LIMIT_KEYS as readonly string[]).includes(key)) throw new ZipError('limits-invalid', `${key} is not a limit`);
  }
  const resolved: { -readonly [Key in keyof ZipLimits]: number } = { ...ZIP_LIMITS };
  for (const key of LIMIT_KEYS) {
    const value: unknown = limits[key];
    if (value === undefined) continue;
    const ceiling = ZIP_LIMITS[key];
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > ceiling) {
      throw new ZipError('limits-invalid', `${key} must be an integer from 1 to ${ceiling}`);
    }
    resolved[key] = value;
  }
  return resolved;
}

/** The bytes of a valid name; throws the refusal for an invalid one. */
function encodeName(name: string, index: number): Uint8Array {
  if (name.length === 0) throw new ZipError('name-empty', `entry ${index} has an empty name`);
  if (name.length > MAX_NAME_LENGTH) throw new ZipError('name-too-long', `entry ${index} has a name over ${MAX_NAME_LENGTH} characters`);
  if (!NAME_CHARACTERS.test(name)) {
    throw new ZipError('name-invalid', `entry ${index} has a name with a character outside letters, digits, ".", "_" and "-"`);
  }
  if (name.startsWith('.')) throw new ZipError('name-leading-dot', `entry ${index} has a name that starts with "."`);
  return Buffer.from(name, 'utf8');
}

/** Validate every entry and every limit before any byte is read; return the plan sorted by name bytes. */
function planEntries(entries: unknown, bounds: ZipLimits): PlannedEntry[] {
  if (!Array.isArray(entries)) throw new ZipError('entries-invalid', 'entries must be an array');
  const list: readonly unknown[] = entries;
  if (list.length === 0) throw new ZipError('no-entries', 'an archive needs at least one entry');
  if (list.length > bounds.entryCountLimit) {
    throw new ZipError('too-many-entries', `${list.length} entries exceed the limit of ${bounds.entryCountLimit}`);
  }
  const planned: PlannedEntry[] = [];
  const seen = new Set<string>();
  let archiveBytes = END_RECORD_BYTES;
  for (const [index, candidate] of list.entries()) {
    if (typeof candidate !== 'object' || candidate === null) {
      throw new ZipError('entries-invalid', `entry ${index} is not an object`);
    }
    const { name, data } = candidate as { readonly name?: unknown; readonly data?: unknown };
    if (typeof name !== 'string') throw new ZipError('entries-invalid', `entry ${index} has no string name`);
    if (!(data instanceof Uint8Array)) throw new ZipError('entries-invalid', `entry ${index} has no Uint8Array data`);
    const nameBytes = encodeName(name, index);
    const folded = name.toLowerCase();
    if (seen.has(folded)) throw new ZipError('name-duplicate', `entry ${index} repeats an earlier name, ignoring ASCII case`);
    seen.add(folded);
    const size = data.byteLength;
    if (size > bounds.entryBytesLimit) {
      throw new ZipError('entry-too-large', `entry ${index} has ${size} bytes, over the limit of ${bounds.entryBytesLimit}`);
    }
    archiveBytes += LOCAL_HEADER_BYTES + CENTRAL_HEADER_BYTES + 2 * nameBytes.length + size;
    if (archiveBytes > bounds.archiveBytesLimit) {
      throw new ZipError('archive-too-large', `the archive would pass ${bounds.archiveBytesLimit} bytes at entry ${index}`);
    }
    planned.push({ nameBytes, data, size });
  }
  planned.sort((left, right) => Buffer.compare(left.nameBytes, right.nameBytes));
  return planned;
}

/**
 * Build a ZIP archive of `entries`. Equal entries (by name and data) give equal bytes in
 * any listing order. Throws a {@link ZipError} for an invalid entry, a duplicate name, an
 * empty list, a raised limit, or an input that would need ZIP64; the caller's array and
 * buffers are never changed, and the result shares no memory with them.
 */
export function writeZip(entries: readonly ZipEntry[], limits: Partial<ZipLimits> = ZIP_LIMITS): Uint8Array {
  const bounds = resolveLimits(limits);
  const planned = planEntries(entries, bounds);

  let totalBytes = END_RECORD_BYTES;
  for (const entry of planned) totalBytes += LOCAL_HEADER_BYTES + CENTRAL_HEADER_BYTES + 2 * entry.nameBytes.length + entry.size;

  const out = new Uint8Array(totalBytes);
  const view = new DataView(out.buffer);
  let position = 0;
  const u16 = (value: number): void => {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new Error('zip: internal error: a 16-bit field overflowed');
    view.setUint16(position, value, true);
    position += 2;
  };
  const u32 = (value: number): void => {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error('zip: internal error: a 32-bit field overflowed');
    view.setUint32(position, value, true);
    position += 4;
  };
  const raw = (bytes: Uint8Array): void => {
    out.set(bytes, position);
    position += bytes.length;
  };

  const written: { readonly entry: PlannedEntry; readonly crc: number; readonly offset: number }[] = [];
  for (const entry of planned) {
    const crc = crc32(entry.data);
    written.push({ entry, crc, offset: position });
    u32(LOCAL_HEADER_SIGNATURE);
    u16(VERSION_NEEDED);
    u16(FLAG_UTF8_NAME);
    u16(METHOD_STORE);
    u16(DOS_TIME);
    u16(DOS_DATE);
    u32(crc);
    u32(entry.size); // compressed size: store keeps the bytes as they are
    u32(entry.size); // uncompressed size
    u16(entry.nameBytes.length);
    u16(0); // extra field length
    raw(entry.nameBytes);
    raw(entry.data);
  }

  const centralOffset = position;
  for (const { entry, crc, offset } of written) {
    u32(CENTRAL_HEADER_SIGNATURE);
    u16(VERSION_MADE_BY);
    u16(VERSION_NEEDED);
    u16(FLAG_UTF8_NAME);
    u16(METHOD_STORE);
    u16(DOS_TIME);
    u16(DOS_DATE);
    u32(crc);
    u32(entry.size);
    u32(entry.size);
    u16(entry.nameBytes.length);
    u16(0); // extra field length
    u16(0); // file comment length
    u16(0); // disk number start
    u16(0); // internal file attributes
    u32(EXTERNAL_ATTRIBUTES);
    u32(offset); // offset of the local header
    raw(entry.nameBytes);
  }
  const centralSize = position - centralOffset;

  u32(END_RECORD_SIGNATURE);
  u16(0); // number of this disk
  u16(0); // disk where the central directory starts
  u16(written.length); // entries on this disk
  u16(written.length); // entries in total
  u32(centralSize);
  u32(centralOffset);
  u16(0); // archive comment length

  if (position !== totalBytes) throw new Error('zip: internal error: the archive length differs from its plan');
  return out;
}
