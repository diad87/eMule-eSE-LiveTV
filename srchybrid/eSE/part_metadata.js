'use strict';

// Read the native eMule e0/e2 .part.met format (PartFile.cpp and packets.cpp).
// A sparse .part's length is not the number of downloaded bytes: use its gaps.
function parsePartMetadata(buffer) {
  let offset = 0;
  function bytes(count) {
    if (!Number.isSafeInteger(count) || count < 0 || offset + count > buffer.length) throw new Error('Truncated part metadata');
    const value = buffer.subarray(offset, offset + count); offset += count; return value;
  }
  const u8 = () => bytes(1).readUInt8(0);
  const u16 = () => bytes(2).readUInt16LE(0);
  const u32 = () => bytes(4).readUInt32LE(0);
  function string(data) {
    return data.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf]))
      ? data.subarray(3).toString('utf8') : new TextDecoder('windows-1252').decode(data);
  }
  const version = u8();
  if (version !== 0xe0 && version !== 0xe2) throw new Error('Unsupported part metadata version');
  bytes(4);
  const hash = bytes(16).toString('hex').toUpperCase();
  bytes(u16() * 16);
  const count = u32();
  if (count > 100000) throw new Error('Invalid metadata tag count');
  let fileName = '', totalSizeBytes = null;
  const gaps = new Map();
  for (let i = 0; i < count; i++) {
    let type = u8();
    const name = type & 0x80 ? Buffer.from([u8()]) : bytes(u16());
    type &= 0x7f;
    let value;
    switch (type) {
      case 0x01: bytes(16); break;
      case 0x02: value = string(bytes(u16())); break;
      case 0x03: value = u32(); break;
      case 0x04: bytes(4); break;
      case 0x05: bytes(1); break;
      case 0x06: bytes(Math.floor(u16() / 8) + 1); break;
      case 0x07: bytes(u32()); break;
      case 0x08: value = u16(); break;
      case 0x09: value = u8(); break;
      case 0x0a: bytes(u8()); break;
      case 0x0b: {
        const integer = bytes(8).readBigUInt64LE(0);
        value = integer <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(integer) : null;
        break;
      }
      default:
        if (type >= 0x11 && type <= 0x20) value = string(bytes(type - 0x10));
        else throw new Error('Unknown metadata tag');
    }
    if (name.length === 1 && name[0] === 1 && typeof value === 'string' && !fileName) fileName = value;
    if (name.length === 1 && name[0] === 2 && Number.isSafeInteger(value) && value > 0) totalSizeBytes = value;
    if (name.length > 1 && (name[0] === 9 || name[0] === 10)) {
      const key = name.subarray(1).toString('ascii');
      if (!/^\d+$/.test(key) || !Number.isSafeInteger(value) || value < 0) throw new Error('Invalid metadata gap');
      const gap = gaps.get(key) || {};
      gap[name[0] === 9 ? 'start' : 'end'] = value;
      gaps.set(key, gap);
    }
  }
  let completedBytes = null;
  if (totalSizeBytes !== null) {
    const ranges = [...gaps.values()].sort((a, b) => a.start - b.start);
    let missing = 0, end = 0;
    for (const gap of ranges) {
      if (!Number.isSafeInteger(gap.start) || !Number.isSafeInteger(gap.end) || gap.start < end || gap.end <= gap.start || gap.end > totalSizeBytes) throw new Error('Invalid metadata gap range');
      missing += gap.end - gap.start; end = gap.end;
    }
    completedBytes = totalSizeBytes - missing;
  }
  return { fileName, hash: /^0{32}$/.test(hash) ? '' : hash, totalSizeBytes, completedBytes, metadataSource: 'part.met' };
}

module.exports = { parsePartMetadata };
