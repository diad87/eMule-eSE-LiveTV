'use strict';
//
// met_fixtures.js — synthetic eMule .met buffer builder for parser tests.
//
// Builds .met files byte-for-byte the way eMule's PartFile.cpp::SavePartFile
// serialises them, so met_parser.test.js can exercise every tag type and
// edge case without needing a real eMule install.
//
// CTag wire format (see met_parser.js header for the full spec):
//   type byte (bit 7 set ⇒ 1-byte name id; else 2-byte namelen + name)
//   value, length depends on type.

// ─── Tag encoders ──────────────────────────────────────────────────────────

// Named-by-id tag (bit 7 of type set). nameId is a single byte.
function tagById(type, nameId, valueBuf) {
  const head = Buffer.from([type | 0x80, nameId]);
  return Buffer.concat([head, valueBuf]);
}

// Named-by-string tag. name is a string (≥ 2 chars, else eMule uses nameId).
function tagByName(type, name, valueBuf) {
  const nameBuf = Buffer.from(name, 'latin1');
  const head = Buffer.alloc(3);
  head.writeUInt8(type, 0);
  head.writeUInt16LE(nameBuf.length, 1);
  return Buffer.concat([head, nameBuf, valueBuf]);
}

// ─── Value encoders ────────────────────────────────────────────────────────

function valUint32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

function valUint64(n) {
  const b = Buffer.alloc(8);
  b.writeUInt32LE(n >>> 0, 0);
  b.writeUInt32LE(Math.floor(n / 0x100000000), 4);
  return b;
}

function valUint16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n & 0xFFFF, 0);
  return b;
}

function valUint8(n) {
  return Buffer.from([n & 0xFF]);
}

function valString(s) {
  const sb = Buffer.from(s, 'latin1');
  const len = Buffer.alloc(2);
  len.writeUInt16LE(sb.length, 0);
  return Buffer.concat([len, sb]);
}

// BLOB: 4-byte LE length + payload. This is the v8.0.19 bug-trigger:
// FT_AICH_HASHSET ships as a BLOB in nearly every modern .met.
function valBlob(payloadLen) {
  const len = Buffer.alloc(4);
  len.writeUInt32LE(payloadLen >>> 0, 0);
  const payload = Buffer.alloc(payloadLen, 0xCC);
  return Buffer.concat([len, payload]);
}

// BSOB: 1-byte length + payload.
function valBsob(payloadLen) {
  const len = Buffer.from([payloadLen & 0xFF]);
  const payload = Buffer.alloc(payloadLen & 0xFF, 0xDD);
  return Buffer.concat([len, payload]);
}

// BOOLARRAY: 2-byte LE length-in-bits + ceil(n/8) bytes.
function valBoolArray(nbits) {
  const len = Buffer.alloc(2);
  len.writeUInt16LE(nbits, 0);
  const payload = Buffer.alloc(Math.ceil(nbits / 8), 0xFF);
  return Buffer.concat([len, payload]);
}

// HASH16: 16 raw bytes.
function valHash16() {
  return Buffer.alloc(16, 0xAB);
}

// FLOAT32: 4 bytes.
function valFloat32() {
  const b = Buffer.alloc(4);
  b.writeFloatLE(1.5, 0);
  return b;
}

// ─── Tag-type / id constants ───────────────────────────────────────────────

const TYPE = {
  HASH16: 0x01, STRING: 0x02, UINT32: 0x03, FLOAT32: 0x04,
  BOOL: 0x05, BOOLARRAY: 0x06, BLOB: 0x07, UINT16: 0x08,
  UINT8: 0x09, BSOB: 0x0A, UINT64: 0x0B,
};
const FT_FILESIZE     = 0x02;   // tag name-id for total file size
const FT_AICH_HASHSET = 0x18;   // tag name-id usually carrying a BLOB
const GAPSTART_PREFIX = 0x09;   // gap tags are name-string \x09<idx> / \x0A<idx>
const GAPEND_PREFIX   = 0x0A;

// ─── .met assembler ────────────────────────────────────────────────────────
//
// buildMet({ fileSize, gaps, extraTags, partCount, tagCountOverride,
//            truncateAt, version })
//
//   fileSize         — total file size; emitted as a UINT64 FT_FILESIZE tag
//                      (set to null to omit the FILESIZE tag entirely).
//   gaps             — array of [start, end] pairs (bytes NOT downloaded).
//   extraTags        — array of raw tag Buffers inserted BEFORE the gap tags
//                      (use this to place a BLOB before the gaps — the exact
//                      ordering that triggered the v8.0.19 bug).
//   partCount        — value written in the partCount field (default 0).
//                      partCount × 16 bytes of part hashes are emitted.
//   tagCountOverride — if set, writes this as the tagCount instead of the
//                      real count (used to simulate a corrupt header).
//   truncateAt       — if set, the returned buffer is sliced to this length
//                      (simulates a half-written .met).
//   version          — header version byte (default 0xE1).
//
function buildMet(opts) {
  opts = opts || {};
  const version   = opts.version != null ? opts.version : 0xE1;
  const partCount = opts.partCount || 0;
  const gaps      = opts.gaps || [];
  const extraTags = opts.extraTags || [];

  // Header: version(1) + date(4) + md4(16)
  const header = Buffer.alloc(21);
  header.writeUInt8(version, 0);
  header.writeUInt32LE(1715000000, 1);              // arbitrary date
  for (let i = 5; i < 21; i++) header.writeUInt8(0xAB, i);

  // partCount(2) + partCount × 16 part hashes
  const partHdr = Buffer.alloc(2);
  partHdr.writeUInt16LE(partCount, 0);
  const partHashes = Buffer.alloc(partCount * 16, 0x55);

  // Tags: [FILESIZE?] + extraTags + gap tags
  const tags = [];
  if (opts.fileSize != null) {
    tags.push(tagById(TYPE.UINT64, FT_FILESIZE, valUint64(opts.fileSize)));
  }
  for (const t of extraTags) tags.push(t);
  gaps.forEach(([start, end], idx) => {
    // Gap tags: name string is one prefix byte + ASCII index digits.
    tags.push(tagByName(TYPE.UINT64,
      String.fromCharCode(GAPSTART_PREFIX) + String(idx),
      valUint64(start)));
    tags.push(tagByName(TYPE.UINT64,
      String.fromCharCode(GAPEND_PREFIX) + String(idx),
      valUint64(end)));
  });

  const realTagCount = tags.length;
  const tagCountField = Buffer.alloc(4);
  tagCountField.writeUInt32LE(
    opts.tagCountOverride != null ? opts.tagCountOverride : realTagCount, 0);

  const full = Buffer.concat([header, partHdr, partHashes, tagCountField].concat(tags));
  return (opts.truncateAt != null) ? full.slice(0, opts.truncateAt) : full;
}

module.exports = {
  buildMet,
  tagById, tagByName,
  valUint32, valUint64, valUint16, valUint8, valString,
  valBlob, valBsob, valBoolArray, valHash16, valFloat32,
  TYPE, FT_FILESIZE, FT_AICH_HASHSET,
};
