'use strict';

// C02 is deliberately a small, pure boundary: it turns a single NAT-PMP
// request datagram into an immutable domain command.  It has no socket,
// timer, clock, filesystem, or dependency on the productive C++ codec.
const { types } = require('node:util');

const VERSION = 0;
const EXTERNAL_ADDRESS_OPCODE = 0;
const UDP_MAP_OPCODE = 1;
const TCP_MAP_OPCODE = 2;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayBufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const typedArrayByteOffsetGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const typedArrayByteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const arrayBufferByteLengthGetter = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;

class NatPmpRequestError extends Error {
  constructor(reasonCode, fieldPath) {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'NatPmpRequestError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) {
  throw new NatPmpRequestError(reasonCode, fieldPath);
}

function immutable(value) {
  return Object.freeze(value);
}

function inputBytes(packet) {
  // Check proxy status before any operation which can invoke a proxy trap.
  if (types.isProxy(packet)) fail('NATPMP_INPUT_INVALID', '$');
  // `instanceof Uint8Array` is forgeable through Object.create(); the util
  // brand check is not. Buffers satisfy this check as genuine Uint8Arrays.
  if (!types.isUint8Array(packet)) {
    fail('NATPMP_INPUT_INVALID', '$');
  }
  // Never pass the caller's view to a generic API: a genuine Uint8Array can
  // shadow `length`, `buffer`, the byte metadata or coercion methods. Read
  // metadata only through captured intrinsic getters, then copy its backing
  // segment without ArrayBuffer.slice (which can consult constructor/species).
  try {
    const backing = typedArrayBufferGetter.call(packet);
    const byteOffset = typedArrayByteOffsetGetter.call(packet);
    const byteLength = typedArrayByteLengthGetter.call(packet);
    if (!types.isArrayBuffer(backing)) fail('NATPMP_INPUT_INVALID', '$');
    const backingLength = arrayBufferByteLengthGetter.call(backing);
    if (!Number.isSafeInteger(byteOffset) || !Number.isSafeInteger(byteLength) ||
      byteOffset < 0 || byteLength < 0 || byteOffset > backingLength ||
      byteLength > backingLength - byteOffset) {
      fail('NATPMP_INPUT_INVALID', '$');
    }
    const cleanView = new Uint8Array(backing, byteOffset, byteLength);
    const copy = Buffer.alloc(byteLength);
    Uint8Array.prototype.set.call(copy, cleanView);
    return copy;
  } catch {
    fail('NATPMP_INPUT_INVALID', '$');
  }
}

function u16be(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function u32be(bytes, offset) {
  return (((bytes[offset] * 0x1000000) + (bytes[offset + 1] << 16) +
    (bytes[offset + 2] << 8) + bytes[offset + 3]) >>> 0);
}

function decodeNatPmpRequest(packet) {
  const bytes = inputBytes(packet);
  if (bytes.length < 2) fail('NATPMP_SIZE_INVALID', '$');
  if (bytes[0] !== VERSION) fail('NATPMP_VERSION_INVALID', '$[0]');

  const opcode = bytes[1];
  if (opcode === EXTERNAL_ADDRESS_OPCODE) {
    if (bytes.length !== 2) fail('NATPMP_SIZE_INVALID', '$');
    return immutable({ protocol: 'natpmp', operation: 'external-address' });
  }
  if (opcode !== UDP_MAP_OPCODE && opcode !== TCP_MAP_OPCODE) {
    fail('NATPMP_OPCODE_INVALID', '$[1]');
  }
  if (bytes.length !== 12) fail('NATPMP_SIZE_INVALID', '$');
  if (bytes[2] !== 0 || bytes[3] !== 0) fail('NATPMP_RESERVED_INVALID', '$[2..3]');

  const internalPort = u16be(bytes, 4);
  if (internalPort === 0) fail('NATPMP_INTERNAL_PORT_INVALID', '$[4..5]');
  const suggestedExternalPort = u16be(bytes, 6);
  const lifetimeSeconds = u32be(bytes, 8);
  const operation = lifetimeSeconds === 0 ? 'delete' : 'map';
  if (operation === 'delete' && suggestedExternalPort !== 0) {
    fail('NATPMP_DELETE_EXTERNAL_PORT_INVALID', '$[6..7]');
  }

  return immutable({
    protocol: 'natpmp',
    operation,
    transport: opcode === TCP_MAP_OPCODE ? 'tcp' : 'udp',
    internal_port: internalPort,
    suggested_external_port: suggestedExternalPort,
    lifetime_seconds: lifetimeSeconds,
  });
}

module.exports = Object.freeze({ NatPmpRequestError, decodeNatPmpRequest });
