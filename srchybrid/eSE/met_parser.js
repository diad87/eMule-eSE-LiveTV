'use strict';
//
// met_parser.js — eMule .met partial-download metadata parser.
//
// v8.0.20: extracted verbatim from routes/emule_routes.js into its own
// module so it can be unit-tested in isolation (see tests/met_parser.test.js).
// The function is pure — input Buffer, output plain object, no I/O, no _ctx.
// The v8.0.19 tag-type bug ("39000 MB de 39000") would have been caught by a
// unit test; this extraction is the price of admission for that test.
//
// ─────────────────────────────────────────────────────────────────────────
//
// v8.0.14 — minimal eMule .met file parser focused on extracting the data the
// monitor needs to decide "is enough actually downloaded to start playing":
//
//   - FT_FILESIZE (tag id 0x02)        : true total file size in bytes
//   - FT_GAPSTART (0x09) / FT_GAPEND (0x0A) string-named tags : pairs of byte
//     offsets describing ranges that HAVE NOT been downloaded yet
//
// downloadedBytes = fileSize - sum(gapEnd - gapStart for each pair).
//
// v8.0.16 — extended return shape for the smart-playback state machine:
//   - headContiguousBytes : number of bytes contiguously downloaded starting
//                           at offset 0 (= firstGapStart, or fileSize if no
//                           gaps at all = file complete from head onward).
//                           This is the ground-truth "how much of the start
//                           of the movie is actually available to stream".
//   - firstGapStart       : byte offset where the FIRST missing range begins.
//                           Same as headContiguousBytes, exposed separately
//                           for symmetry with firstGapEnd.
//   - firstGapEnd         : byte offset where the FIRST missing range ends.
//                           Useful to know "after how big a hole does the
//                           next available chunk start".
//   - gapCount            : total number of unresolved gap pairs.
//
// .met header layout (matches PartFile.cpp::LoadPartFile):
//   byte 0       : version (0xE0 / 0xE1)
//   byte 1..4    : date (DWORD)
//   byte 5..20   : MD4 file hash (16 bytes)
//   byte 21..22  : part count (WORD LE)
//   byte 23..    : part count × 16 bytes of part hashes
//   then         : tag count (DWORD LE)
//   then         : tag count × CTag-serialised tags
//
// CTag serialisation (from eMule's OpCodes.h):
//   type byte. If bit 7 (0x80) set: 1-byte name id follows, type &= 0x7F.
//   Else: 2-byte LE namelen. namelen==1 → 1-byte name id; namelen>1 → ASCII name.
//   Value depends on type:
//     0x01 HASH16     16 bytes
//     0x02 STRING     2-byte LE length + bytes
//     0x03 UINT32     4 bytes LE
//     0x04 FLOAT32    4 bytes LE
//     0x05 BOOL       1 byte
//     0x06 BOOLARRAY  2-byte LE length-in-bits + ceil(n/8) bytes
//     0x07 BLOB       4-byte LE length + bytes              (NOT 1-byte!)
//     0x08 UINT16     2 bytes LE
//     0x09 UINT8      1 byte
//     0x0A BSOB       1-byte length + bytes                  (NOT 0x07!)
//     0x0B UINT64     8 bytes LE
//     0x11..0x20 STR1..STR16 fixed-length string
//
// v8.0.19 fix: previous version had 0x07 typed as "1-byte BSOB" (the
// correct shape for 0x0A) and never declared 0x0A. A real BLOB tag in
// the .met (FT_AICH_HASHSET, present in nearly every modern .met) would
// be parsed as a 1-byte payload, the parser would then advance way too
// few bytes, misread the next "type byte" as random payload data, and
// eventually hit an unrecognised type → break. fileSize had usually been
// captured by then but the gap tags (which come later) never were, so
// gapBytes=0 and downloaded was reported as fileSize. The user saw
// "headContiguous 39000 MB de 39000" while eMule had only 200 MB.
//
// Unknown types still abort the parse early, but now we set
// parseTruncated so the consumer knows the gap list is suspect. When
// truncated AND we found no gaps, we return downloaded/head as null
// rather than the misleading fileSize.
function parseMetGaps(buf) {
  const out = {
    fileSize: null,
    downloaded: null,
    headContiguousBytes: null,
    firstGapStart: null,
    firstGapEnd: null,
    gapCount: 0,
    parseTruncated: false,
  };
  try {
    if (!buf || buf.length < 25) return out;
    let pos = 21;                                          // skip ver+date+hash
    const partCount = buf.readUInt16LE(pos); pos += 2;
    pos += partCount * 16;                                 // skip part hashes
    if (pos + 4 > buf.length) return out;
    const tagCount = buf.readUInt32LE(pos); pos += 4;

    let fileSize = null;
    const gapStarts = Object.create(null);
    const gapEnds   = Object.create(null);
    let tagsRead = 0;

    for (let i = 0; i < tagCount && pos < buf.length; i++) {
      let type = buf.readUInt8(pos++);
      let nameId = 0, nameStr = '';
      if (type & 0x80) {
        type &= 0x7F;
        if (pos >= buf.length) break;
        nameId = buf.readUInt8(pos++);
      } else {
        if (pos + 2 > buf.length) break;
        const namelen = buf.readUInt16LE(pos); pos += 2;
        if (pos + namelen > buf.length) break;
        if (namelen === 1) {
          nameId = buf.readUInt8(pos++);
        } else {
          nameStr = buf.slice(pos, pos + namelen).toString('latin1');
          pos += namelen;
        }
      }

      let value;
      if (type === 0x01) {           // HASH16
        if (pos + 16 > buf.length) break;
        pos += 16;                   // we don't use the value, skip
        value = null;
      } else if (type === 0x02) {    // STRING
        if (pos + 2 > buf.length) break;
        const slen = buf.readUInt16LE(pos); pos += 2;
        if (pos + slen > buf.length) break;
        value = buf.slice(pos, pos + slen).toString('latin1');
        pos += slen;
      } else if (type === 0x03) {    // UINT32
        if (pos + 4 > buf.length) break;
        value = buf.readUInt32LE(pos); pos += 4;
      } else if (type === 0x04) {    // FLOAT32
        if (pos + 4 > buf.length) break;
        pos += 4; value = null;
      } else if (type === 0x05) {    // BOOL  (v8.0.19)
        if (pos + 1 > buf.length) break;
        value = buf.readUInt8(pos++);
      } else if (type === 0x06) {    // BOOLARRAY  (v8.0.19)
        if (pos + 2 > buf.length) break;
        const nbits = buf.readUInt16LE(pos); pos += 2;
        const nbytes = Math.ceil(nbits / 8);
        if (pos + nbytes > buf.length) break;
        pos += nbytes; value = null;
      } else if (type === 0x07) {    // BLOB  (v8.0.19: 4-byte length, was wrong)
        if (pos + 4 > buf.length) break;
        const blen = buf.readUInt32LE(pos); pos += 4;
        if (pos + blen > buf.length) break;
        pos += blen; value = null;
      } else if (type === 0x08) {    // UINT16
        if (pos + 2 > buf.length) break;
        value = buf.readUInt16LE(pos); pos += 2;
      } else if (type === 0x09) {    // UINT8
        value = buf.readUInt8(pos++);
      } else if (type === 0x0A) {    // BSOB  (v8.0.19: 1-byte length, was missing)
        if (pos + 1 > buf.length) break;
        const blen = buf.readUInt8(pos++);
        if (pos + blen > buf.length) break;
        pos += blen; value = null;
      } else if (type === 0x0B) {    // UINT64
        if (pos + 8 > buf.length) break;
        const lo = buf.readUInt32LE(pos); pos += 4;
        const hi = buf.readUInt32LE(pos); pos += 4;
        value = hi * 4294967296 + lo;
      } else if (type >= 0x11 && type <= 0x20) {   // STR1..STR16
        const slen = type - 0x10;
        if (pos + slen > buf.length) break;
        pos += slen; value = null;
      } else {
        // Unknown type — bail rather than skip a payload of unknown size.
        // Flag the result as suspect so the consumer doesn't trust gap=0.
        break;
      }
      tagsRead++;

      // FT_FILESIZE (id 0x02). Could be UINT32 or UINT64 depending on version.
      if (nameId === 0x02 && typeof value === 'number') {
        fileSize = value;
      }
      // Gap pairs: stored as STRING name like '\x09<n>' / '\x0A<n>' with a
      // numeric value, where <n> is the pair index as ASCII digits.
      if (nameId === 0 && nameStr.length >= 2 && typeof value === 'number') {
        const code = nameStr.charCodeAt(0);
        const idx  = nameStr.substring(1);
        if      (code === 0x09) gapStarts[idx] = value;
        else if (code === 0x0A) gapEnds[idx]   = value;
      }
    }

    // Did we walk the whole tag table, or bail early?
    out.parseTruncated = tagsRead < tagCount;

    if (fileSize == null) return out;
    let gapBytes = 0;
    // Collect valid pairs, then find the one starting closest to offset 0.
    // headContiguousBytes = firstGapStart (everything before that offset is
    // contiguously downloaded).
    const pairs = [];
    for (const idx in gapStarts) {
      if (gapEnds[idx] != null && gapEnds[idx] >= gapStarts[idx]) {
        gapBytes += (gapEnds[idx] - gapStarts[idx]);
        pairs.push({ start: gapStarts[idx], end: gapEnds[idx] });
      }
    }
    out.fileSize   = fileSize;
    out.gapCount   = pairs.length;

    if (pairs.length === 0 && out.parseTruncated) {
      // v8.0.19: parser bailed before reaching the gap entries. We DO know
      // fileSize but downloaded/head are unknown — return null for both so
      // the caller doesn't trust "0 gaps → file complete" when it's really
      // "we couldn't read the .met past the first unknown tag". The state
      // machine treats null as "keep waiting in INIT, don't fast-forward
      // to PROBE".
      out.downloaded = null;
      out.headContiguousBytes = null;
      out.firstGapStart = null;
      out.firstGapEnd   = null;
      return out;
    }

    out.downloaded = Math.max(0, fileSize - gapBytes);
    if (pairs.length === 0) {
      // Genuine zero-gap result AND parser walked the full tag table → the
      // file IS complete from the .met's point of view. Head spans the
      // whole file. (Caller can still distinguish "freshly queued but no
      // chunks" vs "complete" because that scenario writes a single gap
      // pair start=0/end=fileSize — gapBytes would equal fileSize and
      // downloaded would be 0.)
      out.headContiguousBytes = fileSize;
      out.firstGapStart = null;
      out.firstGapEnd   = null;
    } else {
      pairs.sort((a, b) => a.start - b.start);
      const first = pairs[0];
      out.headContiguousBytes = first.start;
      out.firstGapStart       = first.start;
      out.firstGapEnd         = first.end;
    }
  } catch (e) { /* malformed .met — fall back to stat.size */ }
  return out;
}

module.exports = { parseMetGaps };
