'use strict';
//
// met_parser.test.js — unit tests for met_parser.parseMetGaps.
//
// The v8.0.19 bug ("39000 MB de 39000") lived undetected for 5 versions
// because there was no test. This file pins the parser's behaviour against
// every tag type and every edge case the smart-playback path depends on.

const { describe, it, assert, assertEqual } = require('./harness');
const { parseMetGaps } = require('../met_parser');
const F = require('./met_fixtures');

const MB = 1024 * 1024;

describe('met_parser — degenerate inputs', () => {
  it('null buffer → all-null result, no throw', () => {
    const r = parseMetGaps(null);
    assertEqual(r.fileSize, null);
    assertEqual(r.downloaded, null);
    assertEqual(r.headContiguousBytes, null);
  });

  it('empty buffer → all-null', () => {
    const r = parseMetGaps(Buffer.alloc(0));
    assertEqual(r.fileSize, null);
  });

  it('buffer shorter than 25-byte header → all-null', () => {
    const r = parseMetGaps(Buffer.alloc(10, 0xFF));
    assertEqual(r.fileSize, null);
  });

  it('garbage buffer → no throw, all-null', () => {
    const r = parseMetGaps(Buffer.alloc(500, 0xAB));
    assert(r && typeof r === 'object', 'returns an object');
  });
});

describe('met_parser — complete / fresh / partial files', () => {
  it('no gaps + full tag walk → file complete (downloaded = fileSize)', () => {
    const buf = parseMetGaps(F.buildMet({ fileSize: 4000 * MB, gaps: [] }));
    assertEqual(buf.fileSize, 4000 * MB);
    assertEqual(buf.downloaded, 4000 * MB);
    assertEqual(buf.headContiguousBytes, 4000 * MB);
    assertEqual(buf.gapCount, 0);
    assertEqual(buf.parseTruncated, false);
  });

  it('freshly queued (single gap 0..fileSize) → downloaded 0, head 0', () => {
    const size = 4000 * MB;
    const r = parseMetGaps(F.buildMet({ fileSize: size, gaps: [[0, size]] }));
    assertEqual(r.downloaded, 0);
    assertEqual(r.headContiguousBytes, 0);
    assertEqual(r.gapCount, 1);
  });

  it('one gap from 200 MB to end → downloaded 200 MB, head 200 MB', () => {
    const size = 4000 * MB;
    const r = parseMetGaps(F.buildMet({ fileSize: size, gaps: [[200 * MB, size]] }));
    assertEqual(r.downloaded, 200 * MB);
    assertEqual(r.headContiguousBytes, 200 * MB);
    assertEqual(r.firstGapStart, 200 * MB);
    assertEqual(r.firstGapEnd, size);
    assertEqual(r.gapCount, 1);
  });

  it('multiple gaps → downloaded = size - Σgaps, head = min(gapStart)', () => {
    const size = 1000 * MB;
    // gaps: [100..200], [500..600] → 800 MB downloaded, head = 100 MB
    const r = parseMetGaps(F.buildMet({
      fileSize: size,
      gaps: [[100 * MB, 200 * MB], [500 * MB, 600 * MB]],
    }));
    assertEqual(r.downloaded, 800 * MB);
    assertEqual(r.headContiguousBytes, 100 * MB);
    assertEqual(r.gapCount, 2);
  });

  it('gaps out of index order → head still = lowest start', () => {
    const size = 1000 * MB;
    // emit gap index1 first (500..600), then index0 (100..200)
    const r = parseMetGaps(F.buildMet({
      fileSize: size,
      gaps: [[500 * MB, 600 * MB], [100 * MB, 200 * MB]],
    }));
    assertEqual(r.headContiguousBytes, 100 * MB);
  });
});

describe('met_parser — v8.0.19 regression: BLOB before gaps', () => {
  it('FILESIZE → BLOB(AICH) → gaps : parser walks past BLOB, gaps correct', () => {
    // This is the EXACT shape that broke the pre-v8.0.19 parser. The BLOB
    // has a 4-byte length; the old parser read 1 byte, desynced, and the
    // gap tags were never reached → downloaded reported as fileSize.
    const size = 39000 * MB;
    const buf = F.buildMet({
      fileSize: size,
      extraTags: [
        F.tagById(F.TYPE.BLOB, F.FT_AICH_HASHSET, F.valBlob(2048)),
      ],
      gaps: [[200 * MB, size]],
    });
    const r = parseMetGaps(buf);
    assertEqual(r.fileSize, size, 'fileSize');
    assertEqual(r.downloaded, 200 * MB, 'downloaded must be 200 MB, not 39 GB');
    assertEqual(r.headContiguousBytes, 200 * MB, 'head');
    assertEqual(r.gapCount, 1, 'gap must be read despite the BLOB');
    assertEqual(r.parseTruncated, false, 'whole tag table walked');
  });

  it('BLOB with large 64 KB payload still parsed', () => {
    const size = 8000 * MB;
    const r = parseMetGaps(F.buildMet({
      fileSize: size,
      extraTags: [F.tagById(F.TYPE.BLOB, F.FT_AICH_HASHSET, F.valBlob(65536))],
      gaps: [[1000 * MB, size]],
    }));
    assertEqual(r.downloaded, 1000 * MB);
    assertEqual(r.gapCount, 1);
  });
});

describe('met_parser — all tag types skipped correctly', () => {
  const size = 2000 * MB;
  const gap = [[300 * MB, size]];

  it('BSOB (0x0A) before gaps', () => {
    const r = parseMetGaps(F.buildMet({
      fileSize: size,
      extraTags: [F.tagById(F.TYPE.BSOB, 0x30, F.valBsob(120))],
      gaps: gap,
    }));
    assertEqual(r.downloaded, 300 * MB);
  });

  it('BOOL (0x05) before gaps', () => {
    const r = parseMetGaps(F.buildMet({
      fileSize: size,
      extraTags: [F.tagById(F.TYPE.BOOL, 0x31, F.valUint8(1))],
      gaps: gap,
    }));
    assertEqual(r.downloaded, 300 * MB);
  });

  it('BOOLARRAY (0x06) before gaps', () => {
    const r = parseMetGaps(F.buildMet({
      fileSize: size,
      extraTags: [F.tagById(F.TYPE.BOOLARRAY, 0x32, F.valBoolArray(100))],
      gaps: gap,
    }));
    assertEqual(r.downloaded, 300 * MB);
  });

  it('HASH16, STRING, UINT16, UINT32, FLOAT32 all before gaps', () => {
    const r = parseMetGaps(F.buildMet({
      fileSize: size,
      extraTags: [
        F.tagById(F.TYPE.HASH16, 0x33, F.valHash16()),
        F.tagByName(F.TYPE.STRING, 'filename', F.valString('Movie.1080p.mkv')),
        F.tagById(F.TYPE.UINT16, 0x34, F.valUint16(720)),
        F.tagById(F.TYPE.UINT32, 0x35, F.valUint32(123456)),
        F.tagById(F.TYPE.FLOAT32, 0x36, F.valFloat32()),
      ],
      gaps: gap,
    }));
    assertEqual(r.downloaded, 300 * MB);
    assertEqual(r.gapCount, 1);
  });

  it('STR1..STR16 fixed-length string before gaps', () => {
    // type 0x15 = STR5 (5 fixed bytes).
    const str5 = Buffer.from('hello', 'latin1');
    const r = parseMetGaps(F.buildMet({
      fileSize: size,
      extraTags: [F.tagById(0x15, 0x37, str5)],
      gaps: gap,
    }));
    assertEqual(r.downloaded, 300 * MB);
  });
});

describe('met_parser — FILESIZE as UINT32 vs UINT64', () => {
  it('UINT32 FILESIZE (older .met) parsed', () => {
    const size = 700 * MB;   // fits in UINT32
    const buf = F.buildMet({ fileSize: null, gaps: [[100 * MB, size]] });
    // Re-build with a UINT32 FILESIZE tag manually inserted at the front.
    const fsTag = F.tagById(F.TYPE.UINT32, F.FT_FILESIZE, F.valUint32(size));
    const withFs = F.buildMet({ fileSize: null, extraTags: [fsTag], gaps: [[100 * MB, size]] });
    const r = parseMetGaps(withFs);
    assertEqual(r.fileSize, size);
    assertEqual(r.downloaded, 100 * MB);
  });

  it('UINT64 FILESIZE > 4 GB parsed', () => {
    const size = 9000 * MB;   // > UINT32 max
    const r = parseMetGaps(F.buildMet({ fileSize: size, gaps: [[5000 * MB, size]] }));
    assertEqual(r.fileSize, size);
    assertEqual(r.downloaded, 5000 * MB);
  });
});

describe('met_parser — truncation / corruption', () => {
  it('unknown tag type before gaps → parseTruncated, downloaded null', () => {
    const size = 5000 * MB;
    // 0x7F is not a known type → parser bails. extraTag uses a fake type.
    const fakeTag = Buffer.concat([
      Buffer.from([0x7F | 0x80, 0x40]),   // type 0x7F named-by-id
      Buffer.alloc(4, 0x00),
    ]);
    const r = parseMetGaps(F.buildMet({
      fileSize: size, extraTags: [fakeTag], gaps: [[100 * MB, size]],
    }));
    assertEqual(r.fileSize, size, 'fileSize still read (came before the bad tag)');
    assertEqual(r.downloaded, null, 'downloaded null — gaps unreadable');
    assertEqual(r.headContiguousBytes, null, 'head null');
    assertEqual(r.parseTruncated, true, 'flagged truncated');
  });

  it('buffer cut mid-tag → no throw, parseTruncated true', () => {
    const size = 4000 * MB;
    const full = F.buildMet({ fileSize: size, gaps: [[200 * MB, size]] });
    const r = parseMetGaps(full.slice(0, full.length - 5));
    assert(r && typeof r === 'object', 'no throw');
    assertEqual(r.parseTruncated, true);
  });

  it('tagCount header lies high → parseTruncated, no crash', () => {
    const size = 4000 * MB;
    const buf = F.buildMet({
      fileSize: size, gaps: [[200 * MB, size]], tagCountOverride: 9999,
    });
    const r = parseMetGaps(buf);
    assert(r && typeof r === 'object', 'no throw');
    assertEqual(r.parseTruncated, true);
    // fileSize + the one gap pair were still read before running out of buffer
    assertEqual(r.fileSize, size);
  });

  it('no FILESIZE tag at all → fileSize null', () => {
    const r = parseMetGaps(F.buildMet({ fileSize: null, gaps: [[0, 100 * MB]] }));
    assertEqual(r.fileSize, null);
    assertEqual(r.downloaded, null);
  });
});

describe('met_parser — partCount handling', () => {
  it('non-zero partCount: part hashes skipped, tags still found', () => {
    const size = 4000 * MB;
    const r = parseMetGaps(F.buildMet({
      fileSize: size, partCount: 412, gaps: [[200 * MB, size]],
    }));
    assertEqual(r.fileSize, size);
    assertEqual(r.downloaded, 200 * MB);
    assertEqual(r.gapCount, 1);
  });
});
