// SPDX-License-Identifier: Apache-2.0
//
// T039 test support: an independent minimal ZIP reader and a table-driven CRC-32.
// Both are written from the ZIP file format (APPNOTE local file header 4.3.7, central
// directory file header 4.3.12, end of central directory record 4.3.16). This module
// imports nothing from src/ and never calls zlib's crc32, so it cannot share a defect
// with the writer under test.
//
// The reader is strict about everything it needs in order to read a layout without
// guessing. It throws on a ZIP64 record or escape value, a multi-disk archive, a gap or
// overlap between entries, a central header that disagrees with its local header, and
// a name that is not valid UTF-8. It only reports, and leaves to the tests, the fields
// the writer must keep at fixed values (flags, times, extra and comment lengths).

const SIGNATURE = Object.freeze({
  local: 0x04034b50,
  central: 0x02014b50,
  end: 0x06054b50,
  zip64End: 0x06064b50,
  zip64Locator: 0x07064b50,
});

const nameDecoder = new TextDecoder('utf-8', { fatal: true });

function fail(message) {
  throw new Error(`zip reader: ${message}`);
}

function u16(bytes, offset) {
  if (offset < 0 || offset + 2 > bytes.length) fail(`a 16-bit read at ${offset} is outside the archive`);
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function u32(bytes, offset) {
  if (offset < 0 || offset + 4 > bytes.length) fail(`a 32-bit read at ${offset} is outside the archive`);
  return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
}

function slice(bytes, start, length) {
  if (start < 0 || length < 0 || start + length > bytes.length) fail(`a ${length}-byte slice at ${start} is outside the archive`);
  return bytes.slice(start, start + length);
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

/** CRC-32 (the zlib/PKZIP polynomial 0xEDB88320, reflected), computed bit by bit from the table. */
export function referenceCrc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Read `archive` (a Uint8Array) and return `{ entries, end }`. `entries` follow the central
 * directory order. Each entry reports its names, bytes, the central and local header fields
 * and `computedCrc`, the CRC-32 of the bytes it carries.
 */
export function readZip(archive) {
  const bytes = archive instanceof Uint8Array ? archive : fail('the archive is not a Uint8Array');
  if (bytes.length < 22) fail('the archive is shorter than an end of central directory record');

  // The end record sits last, before an optional comment of at most 0xFFFF bytes.
  let endAt = -1;
  for (let at = bytes.length - 22; at >= Math.max(0, bytes.length - 22 - 0xffff); at -= 1) {
    if (u32(bytes, at) === SIGNATURE.end && at + 22 + u16(bytes, at + 20) === bytes.length) {
      endAt = at;
      break;
    }
  }
  if (endAt < 0) fail('no end of central directory record');

  const end = {
    diskNumber: u16(bytes, endAt + 4),
    centralDirectoryDisk: u16(bytes, endAt + 6),
    entriesOnDisk: u16(bytes, endAt + 8),
    entriesTotal: u16(bytes, endAt + 10),
    centralSize: u32(bytes, endAt + 12),
    centralOffset: u32(bytes, endAt + 16),
    commentLength: u16(bytes, endAt + 20),
    position: endAt,
  };
  if (end.diskNumber !== 0 || end.centralDirectoryDisk !== 0) fail('a multi-disk archive');
  if (end.entriesOnDisk !== end.entriesTotal) fail('the per-disk and total entry counts differ');
  if (end.entriesTotal === 0xffff || end.centralSize === 0xffffffff || end.centralOffset === 0xffffffff) {
    fail('an end record field holds a ZIP64 escape value');
  }
  if (endAt >= 20 && u32(bytes, endAt - 20) === SIGNATURE.zip64Locator) fail('a ZIP64 end of central directory locator');
  if (endAt >= 76 && u32(bytes, endAt - 76) === SIGNATURE.zip64End) fail('a ZIP64 end of central directory record');
  if (end.centralOffset + end.centralSize !== endAt) fail('the central directory does not end where the end record starts');

  const entries = [];
  let at = end.centralOffset;
  for (let index = 0; index < end.entriesTotal; index += 1) {
    if (u32(bytes, at) !== SIGNATURE.central) fail(`central header ${index} has no signature`);
    const central = {
      versionMadeBy: u16(bytes, at + 4),
      versionNeeded: u16(bytes, at + 6),
      flags: u16(bytes, at + 8),
      method: u16(bytes, at + 10),
      time: u16(bytes, at + 12),
      date: u16(bytes, at + 14),
      crc: u32(bytes, at + 16),
      compressedSize: u32(bytes, at + 20),
      size: u32(bytes, at + 24),
      nameLength: u16(bytes, at + 28),
      extraLength: u16(bytes, at + 30),
      commentLength: u16(bytes, at + 32),
      diskStart: u16(bytes, at + 34),
      internalAttributes: u16(bytes, at + 36),
      externalAttributes: u32(bytes, at + 38),
      offset: u32(bytes, at + 42),
    };
    const nameBytes = slice(bytes, at + 46, central.nameLength);
    at += 46 + central.nameLength + central.extraLength + central.commentLength;

    const local = { position: central.offset };
    if (u32(bytes, central.offset) !== SIGNATURE.local) fail(`local header ${index} has no signature`);
    local.versionNeeded = u16(bytes, central.offset + 4);
    local.flags = u16(bytes, central.offset + 6);
    local.method = u16(bytes, central.offset + 8);
    local.time = u16(bytes, central.offset + 10);
    local.date = u16(bytes, central.offset + 12);
    local.crc = u32(bytes, central.offset + 14);
    local.compressedSize = u32(bytes, central.offset + 18);
    local.size = u32(bytes, central.offset + 22);
    local.nameLength = u16(bytes, central.offset + 26);
    local.extraLength = u16(bytes, central.offset + 28);
    for (const field of ['versionNeeded', 'flags', 'method', 'time', 'date', 'crc', 'compressedSize', 'size', 'nameLength']) {
      if (local[field] !== central[field]) fail(`entry ${index}: the local and central ${field} differ`);
    }
    const localName = slice(bytes, central.offset + 30, local.nameLength);
    if (Buffer.compare(localName, nameBytes) !== 0) fail(`entry ${index}: the local and central names differ`);
    const dataStart = central.offset + 30 + local.nameLength + local.extraLength;
    const data = slice(bytes, dataStart, central.compressedSize);

    entries.push({
      name: nameDecoder.decode(nameBytes),
      nameBytes,
      data,
      computedCrc: referenceCrc32(data),
      ...central,
      local,
      dataStart,
      dataEnd: dataStart + central.compressedSize,
    });
  }
  if (at !== end.centralOffset + end.centralSize) fail('the central headers do not fill the central directory');

  // Local entries must tile the space before the central directory, in central order.
  let expected = 0;
  for (const [index, entry] of entries.entries()) {
    if (entry.offset !== expected) fail(`entry ${index} starts at ${entry.offset}, not at ${expected}`);
    expected = entry.dataEnd;
  }
  if (expected !== end.centralOffset) fail('the entries do not end where the central directory starts');

  return { entries, end };
}

function le(width, value) {
  const bytes = Buffer.alloc(width);
  if (width === 2) bytes.writeUInt16LE(value);
  else bytes.writeUInt32LE(value);
  return bytes;
}

/**
 * The reference encoder: the archive the format prescribes for `entries`, built field by
 * field from the APPNOTE layout with this module's own CRC-32 (never zlib's, never the
 * writer under test). Entries are ordered by name bytes; every header carries version 2.0
 * (made by: Unix, 2.0), flags 0x0800, method 0, 00:00:00 on 1980-01-01, no extra field or
 * comment, internal attributes 0 and external attributes 0x81A40000 (a 0644 regular file).
 */
export function referenceArchive(entries) {
  const ordered = [...entries].sort((left, right) => Buffer.compare(Buffer.from(left.name, 'utf8'), Buffer.from(right.name, 'utf8')));
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const { name, data } of ordered) {
    const nameBytes = Buffer.from(name, 'utf8');
    const body = Buffer.from(data);
    const crc = referenceCrc32(body);
    const local = Buffer.concat([
      le(4, SIGNATURE.local), le(2, 20), le(2, 0x0800), le(2, 0), le(2, 0), le(2, 0x0021),
      le(4, crc), le(4, body.length), le(4, body.length), le(2, nameBytes.length), le(2, 0),
      nameBytes, body,
    ]);
    const central = Buffer.concat([
      le(4, SIGNATURE.central), le(2, 0x0314), le(2, 20), le(2, 0x0800), le(2, 0), le(2, 0), le(2, 0x0021),
      le(4, crc), le(4, body.length), le(4, body.length), le(2, nameBytes.length), le(2, 0), le(2, 0),
      le(2, 0), le(2, 0), le(4, 0x81a40000), le(4, offset),
      nameBytes,
    ]);
    locals.push(local);
    centrals.push(central);
    offset += local.length;
  }
  const centralDirectory = Buffer.concat(centrals);
  const end = Buffer.concat([
    le(4, SIGNATURE.end), le(2, 0), le(2, 0), le(2, ordered.length), le(2, ordered.length),
    le(4, centralDirectory.length), le(4, offset), le(2, 0),
  ]);
  return Buffer.concat([...locals, centralDirectory, end]);
}

/** MS-DOS date (year since 1980, month, day) as an object. */
export function decodeDosDate(date) {
  return { year: 1980 + (date >> 9), month: (date >> 5) & 0x0f, day: date & 0x1f };
}

/** MS-DOS time (hours, minutes, seconds in two-second steps) as an object. */
export function decodeDosTime(time) {
  return { hour: time >> 11, minute: (time >> 5) & 0x3f, second: (time & 0x1f) * 2 };
}

/** Deterministic pseudo-random bytes (xorshift32); no clock, no crypto. */
export function patterned(length, seed = 1) {
  const out = new Uint8Array(length);
  let state = seed >>> 0 || 1;
  for (let index = 0; index < length; index += 1) {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out[index] = state & 0xff;
  }
  return out;
}

export const bytesOf = (text) => Buffer.from(text, 'utf8');

/** Synthetic stand-ins for the five package files, in a deliberately unsorted order. */
export function packageEntries() {
  return [
    { name: 'verification.json', data: bytesOf('{"synthetic":"verification"}\n') },
    { name: 'final.pdf', data: patterned(4096, 11) },
    { name: 'package-index.json', data: bytesOf('{"synthetic":"index"}\n') },
    { name: 'approval-manifest.json', data: bytesOf('{"synthetic":"manifest"}\n') },
    { name: 'audit-receipt.json', data: bytesOf('{"synthetic":"receipt"}\n') },
  ];
}

/** Every ordering of `items`; five items give 120. */
export function permutations(items) {
  if (items.length <= 1) return [[...items]];
  const result = [];
  for (const [index, item] of items.entries()) {
    const rest = [...items.slice(0, index), ...items.slice(index + 1)];
    for (const tail of permutations(rest)) result.push([item, ...tail]);
  }
  return result;
}
