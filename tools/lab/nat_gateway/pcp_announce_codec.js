'use strict';

// D04 implements only the pure ANNOUNCE wire boundary. Source-address
// validation and UDP routing belong to D05 where packet metadata exists.
const { types } = require('node:util');

const objectPrototype = Object.prototype;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayBufferGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const typedArrayByteOffsetGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const typedArrayByteLengthGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const arrayBufferByteLengthGetter =
  Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;

class PcpAnnounceError extends Error {
  constructor(reasonCode, fieldPath, resultCode = 3, requestParsed = false) {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'PcpAnnounceError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
    this.pcp_result_code = resultCode;
    this.request_parsed = requestParsed;
  }
}

function fail(reasonCode, fieldPath, resultCode = 3, requestParsed = false) {
  throw new PcpAnnounceError(
    reasonCode, fieldPath, resultCode, requestParsed);
}

function byteView(packet, errorCode, fieldPath) {
  if (types.isProxy(packet) || !types.isUint8Array(packet)) {
    fail(errorCode, fieldPath);
  }
  let view;
  let byteLength;
  try {
    const backing = typedArrayBufferGetter.call(packet);
    const byteOffset = typedArrayByteOffsetGetter.call(packet);
    byteLength = typedArrayByteLengthGetter.call(packet);
    if (!types.isArrayBuffer(backing)) fail(errorCode, fieldPath);
    const backingLength = arrayBufferByteLengthGetter.call(backing);
    if (!Number.isSafeInteger(byteOffset) ||
      !Number.isSafeInteger(byteLength) ||
      byteOffset < 0 || byteLength < 0 ||
      byteOffset > backingLength ||
      byteLength > backingLength - byteOffset) {
      fail(errorCode, fieldPath);
    }
    view = new Uint8Array(backing, byteOffset, byteLength);
  } catch {
    fail(errorCode, fieldPath);
  }
  return Object.freeze({ view, byteLength });
}

function boundedCopy(packet, mode) {
  const encoding = mode === 'decode'
    ? ['PCP_ANNOUNCE_INPUT_INVALID', '$']
    : ['PCP_ANNOUNCE_REQUEST_WIRE_INVALID', '$.request_wire'];
  const snapshot = byteView(packet, encoding[0], encoding[1]);
  if (snapshot.byteLength < 24 || snapshot.byteLength > 1100 ||
    (snapshot.byteLength & 3) !== 0) {
    const code = mode === 'decode'
      ? (snapshot.byteLength >= 24 && snapshot.byteLength <= 1100
        ? 'PCP_ANNOUNCE_ALIGNMENT_INVALID'
        : 'PCP_ANNOUNCE_SIZE_INVALID')
      : 'PCP_ANNOUNCE_REQUEST_WIRE_SIZE_INVALID';
    const path = mode === 'decode' ? '$' : '$.request_wire';
    fail(code, path);
  }
  const copy = Buffer.alloc(snapshot.byteLength);
  Uint8Array.prototype.set.call(copy, snapshot.view);
  return copy;
}

function u16be(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function allZero(bytes, start, end) {
  for (let offset = start; offset < end; offset += 1) {
    if (bytes[offset] !== 0) return false;
  }
  return true;
}

function addressText(bytes, offset) {
  if (allZero(bytes, offset, offset + 10) &&
    bytes[offset + 10] === 0xff && bytes[offset + 11] === 0xff) {
    return `${bytes[offset + 12]}.${bytes[offset + 13]}.` +
      `${bytes[offset + 14]}.${bytes[offset + 15]}`;
  }
  const groups = [];
  for (let index = 0; index < 8; index += 1) {
    groups.push(u16be(bytes, offset + (index * 2)));
  }
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < groups.length;) {
    if (groups[start] !== 0) {
      start += 1;
      continue;
    }
    let end = start + 1;
    while (end < groups.length && groups[end] === 0) end += 1;
    if (end - start > bestLength) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  if (bestLength < 2) {
    return groups.map((group) => group.toString(16)).join(':');
  }
  const left = groups.slice(0, bestStart)
    .map((group) => group.toString(16)).join(':');
  const right = groups.slice(bestStart + bestLength)
    .map((group) => group.toString(16)).join(':');
  return `${left}::${right}`;
}

function validateOptions(bytes) {
  let offset = 24;
  while (offset < bytes.length) {
    const code = bytes[offset];
    const length = u16be(bytes, offset + 2);
    const optionSize = 4 + ((length + 3) & ~3);
    if (optionSize > bytes.length - offset) {
      fail('PCP_ANNOUNCE_OPTION_MALFORMED', '$[24..]', 6, false);
    }
    for (let padding = offset + 4 + length;
      padding < offset + optionSize; padding += 1) {
      if (bytes[padding] !== 0) {
        fail('PCP_ANNOUNCE_OPTION_MALFORMED', '$[24..]', 6, false);
      }
    }
    if (code === 1 || code === 2 || code === 3) {
      fail('PCP_ANNOUNCE_OPTION_MALFORMED',
        `$[${offset}]`, 6, true);
    }
    if (code < 128) {
      fail('PCP_ANNOUNCE_OPTION_UNSUPPORTED',
        `$[${offset}]`, 5, true);
    }
    offset += optionSize;
  }
}

function decodePcpAnnounceRequest(packet) {
  const bytes = boundedCopy(packet, 'decode');
  if (bytes[0] !== 2) {
    fail('PCP_ANNOUNCE_VERSION_INVALID', '$[0]', 1, false);
  }
  if (bytes[1] !== 0) {
    fail('PCP_ANNOUNCE_OPCODE_INVALID', '$[1]', 4, false);
  }
  validateOptions(bytes);
  return Object.freeze({
    protocol: 'pcp',
    operation: 'announce',
    client_address: addressText(bytes, 8),
  });
}

function ordinary(value, fieldPath) {
  if (value === null || typeof value !== 'object' ||
    types.isProxy(value) || Object.getPrototypeOf(value) !== objectPrototype) {
    fail('PCP_ANNOUNCE_INPUT_INVALID', fieldPath);
  }
}

function discriminator(input) {
  ordinary(input, '$');
  const descriptor = Object.getOwnPropertyDescriptor(input, 'mode');
  if (!descriptor) fail('PCP_ANNOUNCE_FIELD_MISSING', '$.mode');
  if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
    fail('PCP_ANNOUNCE_INPUT_INVALID', '$.mode');
  }
  return descriptor.value;
}

function dataObject(value, allowed, fieldPath) {
  ordinary(value, fieldPath);
  const names = Object.getOwnPropertyNames(value);
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    fail('PCP_ANNOUNCE_UNKNOWN_FIELD', `${fieldPath}.*`);
  }
  for (const name of names) {
    if (!allowed.includes(name)) {
      fail('PCP_ANNOUNCE_UNKNOWN_FIELD', `${fieldPath}.*`);
    }
  }
  const copy = Object.create(null);
  for (const name of allowed) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor) {
      fail('PCP_ANNOUNCE_FIELD_MISSING', `${fieldPath}.${name}`);
    }
    if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      fail('PCP_ANNOUNCE_INPUT_INVALID', `${fieldPath}.${name}`);
    }
    copy[name] = descriptor.value;
  }
  return copy;
}

function uint(value, maximum, fieldPath) {
  if (typeof value !== 'number' || !Number.isInteger(value) ||
    Object.is(value, -0) || value < 0 || value > maximum) {
    fail('PCP_ANNOUNCE_FIELD_INVALID', fieldPath);
  }
  return value;
}

function put32(out, offset, value) {
  out[offset] = value >>> 24;
  out[offset + 1] = value >>> 16;
  out[offset + 2] = value >>> 8;
  out[offset + 3] = value;
}

function semanticResponse(input) {
  const value = dataObject(input,
    ['mode', 'response_type', 'result_code', 'epoch'], '$');
  if (value.response_type !== 'announce') {
    fail('PCP_ANNOUNCE_TYPE_INVALID', '$.response_type');
  }
  const resultCode = uint(value.result_code, 0xff, '$.result_code');
  if (resultCode !== 0) {
    fail('PCP_ANNOUNCE_RESULT_INVALID', '$.result_code');
  }
  const out = Buffer.alloc(24);
  out[0] = 2;
  out[1] = 0x80;
  out[3] = resultCode;
  put32(out, 8, uint(value.epoch, 0xffffffff, '$.epoch'));
  return out;
}

function errorEchoResponse(input) {
  const value = dataObject(input, [
    'mode', 'response_type', 'result_code', 'epoch',
    'request_wire', 'request_parsed',
  ], '$');
  if (value.response_type !== 'announce') {
    fail('PCP_ANNOUNCE_TYPE_INVALID', '$.response_type');
  }
  const resultCode = uint(value.result_code, 0xff, '$.result_code');
  if (resultCode < 1 || resultCode > 13) {
    fail('PCP_ANNOUNCE_RESULT_INVALID', '$.result_code');
  }
  if (typeof value.request_parsed !== 'boolean') {
    fail('PCP_ANNOUNCE_FIELD_INVALID', '$.request_parsed');
  }
  const out = boundedCopy(value.request_wire, 'echo');
  if (out[1] !== 0) {
    fail('PCP_ANNOUNCE_REQUEST_OPCODE_INVALID', '$.request_wire[1]');
  }
  out[0] = 2;
  out[1] = 0x80;
  out[2] = 0;
  out[3] = resultCode;
  out.fill(0, 4, 8);
  put32(out, 8, uint(value.epoch, 0xffffffff, '$.epoch'));
  if (value.request_parsed) out.fill(0, 12, 24);
  return out;
}

function encodePcpAnnounceResponse(input) {
  const mode = discriminator(input);
  if (mode === 'semantic') return semanticResponse(input);
  if (mode === 'error-echo') return errorEchoResponse(input);
  fail('PCP_ANNOUNCE_MODE_INVALID', '$.mode');
}

module.exports = Object.freeze({
  PcpAnnounceError,
  decodePcpAnnounceRequest,
  encodePcpAnnounceResponse,
});
