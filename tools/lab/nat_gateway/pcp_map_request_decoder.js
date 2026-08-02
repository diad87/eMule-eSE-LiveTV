'use strict';

// D02 is a pure wire boundary. It snapshots one PCP MAP datagram and returns
// an immutable domain command. It performs no I/O and does not import the
// productive C++ codec.
const { types } = require('node:util');

const PCP_VERSION = 2;
const MAP_OPCODE = 1;
const BASE_MAP_SIZE = 60;
const MAX_MESSAGE_SIZE = 1100;
const TCP_PROTOCOL = 6;
const UDP_PROTOCOL = 17;
const PREFER_FAILURE_OPTION = 2;
const PORT_SET_OPTION = 130;
const MALFORMED_REQUEST = 3;

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayBufferGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const typedArrayByteOffsetGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const typedArrayByteLengthGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const arrayBufferByteLengthGetter =
  Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;

class PcpRequestError extends Error {
  constructor(reasonCode, fieldPath, resultCode) {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'PcpRequestError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
    this.pcp_result_code = resultCode;
  }
}

function fail(reasonCode, fieldPath, resultCode = MALFORMED_REQUEST) {
  throw new PcpRequestError(reasonCode, fieldPath, resultCode);
}

function malformedOption() {
  fail('PCP_OPTION_MALFORMED', '$[60..]', 6);
}

function inputBytes(packet) {
  if (types.isProxy(packet)) fail('PCP_INPUT_INVALID', '$');
  if (!types.isUint8Array(packet)) fail('PCP_INPUT_INVALID', '$');
  let cleanView;
  let byteLength;
  try {
    const backing = typedArrayBufferGetter.call(packet);
    const byteOffset = typedArrayByteOffsetGetter.call(packet);
    byteLength = typedArrayByteLengthGetter.call(packet);
    if (!types.isArrayBuffer(backing)) fail('PCP_INPUT_INVALID', '$');
    const backingLength = arrayBufferByteLengthGetter.call(backing);
    if (!Number.isSafeInteger(byteOffset) ||
      !Number.isSafeInteger(byteLength) ||
      byteOffset < 0 || byteLength < 0 ||
      byteOffset > backingLength ||
      byteLength > backingLength - byteOffset) {
      fail('PCP_INPUT_INVALID', '$');
    }
    // Constructing a view also distinguishes detached backing storage.
    cleanView = new Uint8Array(backing, byteOffset, byteLength);
  } catch {
    fail('PCP_INPUT_INVALID', '$');
  }
  // Reject before allocating or copying caller-controlled payload volume.
  if (byteLength < BASE_MAP_SIZE || byteLength > MAX_MESSAGE_SIZE) {
    fail('PCP_SIZE_INVALID', '$');
  }
  const copy = Buffer.alloc(byteLength);
  Uint8Array.prototype.set.call(copy, cleanView);
  return copy;
}

function u16be(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function u32be(bytes, offset) {
  return (((bytes[offset] * 0x1000000) +
    (bytes[offset + 1] << 16) +
    (bytes[offset + 2] << 8) +
    bytes[offset + 3]) >>> 0);
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
  if (bestLength < 2) return groups.map((group) => group.toString(16)).join(':');
  const left = groups.slice(0, bestStart)
    .map((group) => group.toString(16)).join(':');
  const right = groups.slice(bestStart + bestLength)
    .map((group) => group.toString(16)).join(':');
  return `${left}::${right}`;
}

function parseOptions(bytes, internalPort) {
  let preferFailure = false;
  let portSet = null;
  let offset = BASE_MAP_SIZE;

  while (offset < bytes.length) {
    const code = bytes[offset];
    const length = u16be(bytes, offset + 2);
    const paddedDataLength = (length + 3) & ~3;
    const optionSize = 4 + paddedDataLength;
    // The reserved byte at offset + 1 is ignored on reception.
    if (optionSize > bytes.length - offset) malformedOption();
    for (let padding = offset + 4 + length;
      padding < offset + optionSize; padding += 1) {
      if (bytes[padding] !== 0) malformedOption();
    }

    if (code === PREFER_FAILURE_OPTION) {
      if (length !== 0 || preferFailure) malformedOption();
      preferFailure = true;
    } else if (code === PORT_SET_OPTION) {
      if (length !== 5 || portSet !== null) malformedOption();
      const size = u16be(bytes, offset + 4);
      const firstInternalPort = u16be(bytes, offset + 6);
      const flags = bytes[offset + 8];
      if (size === 0 || firstInternalPort !== internalPort) malformedOption();
      portSet = Object.freeze({
        size,
        first_internal_port: firstInternalPort,
        preserve_parity: (flags & 1) !== 0,
      });
    } else if (code < 128) {
      fail('PCP_OPTION_UNSUPPORTED', `$[${offset}]`, 5);
    }
    offset += optionSize;
  }

  return Object.freeze({
    prefer_failure: preferFailure,
    port_set: portSet,
  });
}

function decodePcpMapRequest(packet) {
  const bytes = inputBytes(packet);
  if ((bytes.length & 3) !== 0) fail('PCP_ALIGNMENT_INVALID', '$');
  if (bytes[0] !== PCP_VERSION) fail('PCP_VERSION_INVALID', '$[0]', 1);
  if (bytes[1] !== MAP_OPCODE) fail('PCP_OPCODE_INVALID', '$[1]', 4);
  if (bytes[36] !== TCP_PROTOCOL && bytes[36] !== UDP_PROTOCOL) {
    fail('PCP_TRANSPORT_PROTOCOL_INVALID', '$[36]', 9);
  }
  const internalPort = u16be(bytes, 40);
  if (internalPort === 0) {
    fail('PCP_INTERNAL_PORT_INVALID', '$[40..41]');
  }
  const lifetimeSeconds = u32be(bytes, 4);
  const suggestedExternalPort = u16be(bytes, 42);
  const options = parseOptions(bytes, internalPort);
  if (options.prefer_failure &&
    (lifetimeSeconds === 0 || suggestedExternalPort === 0)) {
    malformedOption();
  }
  if (lifetimeSeconds !== 0 &&
    options.prefer_failure && options.port_set !== null) {
    malformedOption();
  }

  return Object.freeze({
    protocol: 'pcp',
    operation: lifetimeSeconds === 0 ? 'delete' : 'map',
    transport: bytes[36] === TCP_PROTOCOL ? 'tcp' : 'udp',
    client_address: addressText(bytes, 8),
    nonce: bytes.subarray(24, 36).toString('hex'),
    internal_port: internalPort,
    suggested_external_port: suggestedExternalPort,
    suggested_external_address: addressText(bytes, 44),
    lifetime_seconds: lifetimeSeconds,
    options,
  });
}

module.exports = Object.freeze({ PcpRequestError, decodePcpMapRequest });
