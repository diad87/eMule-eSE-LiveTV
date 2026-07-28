'use strict';

// D03 has two closed paths: semantic success/fault responses and normative
// errors echoed from the original MAP request wire. It performs no I/O and
// imports no productive codec.
const net = require('node:net');
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

class PcpResponseError extends Error {
  constructor(reasonCode, fieldPath) {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'PcpResponseError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) {
  throw new PcpResponseError(reasonCode, fieldPath);
}

function ordinary(value, fieldPath) {
  if (value === null || typeof value !== 'object' ||
    types.isProxy(value) || Object.getPrototypeOf(value) !== objectPrototype) {
    fail('PCP_RESPONSE_INPUT_INVALID', fieldPath);
  }
}

function discriminator(input) {
  ordinary(input, '$');
  const descriptor = Object.getOwnPropertyDescriptor(input, 'mode');
  if (!descriptor) fail('PCP_RESPONSE_FIELD_MISSING', '$.mode');
  if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
    fail('PCP_RESPONSE_INPUT_INVALID', '$.mode');
  }
  return descriptor.value;
}

function dataObject(value, allowed, fieldPath) {
  ordinary(value, fieldPath);
  const names = Object.getOwnPropertyNames(value);
  if (Object.getOwnPropertySymbols(value).length !== 0) {
    fail('PCP_RESPONSE_UNKNOWN_FIELD', `${fieldPath}.*`);
  }
  for (const name of names) {
    if (!allowed.includes(name)) {
      fail('PCP_RESPONSE_UNKNOWN_FIELD', `${fieldPath}.*`);
    }
  }
  const copy = Object.create(null);
  for (const name of allowed) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor) {
      fail('PCP_RESPONSE_FIELD_MISSING', `${fieldPath}.${name}`);
    }
    if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      fail('PCP_RESPONSE_INPUT_INVALID', `${fieldPath}.${name}`);
    }
    copy[name] = descriptor.value;
  }
  return copy;
}

function uint(value, maximum, fieldPath) {
  if (typeof value !== 'number' || !Number.isInteger(value) ||
    Object.is(value, -0) || value < 0 || value > maximum) {
    fail('PCP_RESPONSE_FIELD_INVALID', fieldPath);
  }
  return value;
}

function requestBytes(packet) {
  if (types.isProxy(packet) || !types.isUint8Array(packet)) {
    fail('PCP_RESPONSE_REQUEST_WIRE_INVALID', '$.request_wire');
  }
  let view;
  let byteLength;
  try {
    const backing = typedArrayBufferGetter.call(packet);
    const byteOffset = typedArrayByteOffsetGetter.call(packet);
    byteLength = typedArrayByteLengthGetter.call(packet);
    if (!types.isArrayBuffer(backing)) {
      fail('PCP_RESPONSE_REQUEST_WIRE_INVALID', '$.request_wire');
    }
    const backingLength = arrayBufferByteLengthGetter.call(backing);
    if (!Number.isSafeInteger(byteOffset) ||
      !Number.isSafeInteger(byteLength) ||
      byteOffset < 0 || byteLength < 0 ||
      byteOffset > backingLength ||
      byteLength > backingLength - byteOffset) {
      fail('PCP_RESPONSE_REQUEST_WIRE_INVALID', '$.request_wire');
    }
    view = new Uint8Array(backing, byteOffset, byteLength);
  } catch {
    fail('PCP_RESPONSE_REQUEST_WIRE_INVALID', '$.request_wire');
  }
  if (byteLength < 60 || byteLength > 1100 || (byteLength & 3) !== 0) {
    fail('PCP_RESPONSE_REQUEST_WIRE_SIZE_INVALID', '$.request_wire');
  }
  const copy = Buffer.alloc(byteLength);
  Uint8Array.prototype.set.call(copy, view);
  if (copy[1] !== 1) {
    fail('PCP_RESPONSE_REQUEST_OPCODE_INVALID', '$.request_wire[1]');
  }
  return copy;
}

function ipv4Bytes(address) {
  const octets = address.split('.').map(Number);
  const bytes = Buffer.alloc(16);
  bytes[10] = 0xff;
  bytes[11] = 0xff;
  bytes.set(octets, 12);
  return bytes;
}

function ipv6Groups(address) {
  let text = address.toLowerCase();
  if (text.includes('.')) {
    const separator = text.lastIndexOf(':');
    const octets = text.slice(separator + 1).split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    text = `${text.slice(0, separator + 1)}${high}:${low}`;
  }
  const halves = text.split('::');
  const head = halves[0] === '' ? [] : halves[0].split(':');
  const tail =
    halves.length === 1 || halves[1] === '' ? [] : halves[1].split(':');
  const missing = 8 - head.length - tail.length;
  const groups = halves.length === 2
    ? [...head, ...Array(missing).fill('0'), ...tail]
    : head;
  return groups.map((group) => Number.parseInt(group, 16));
}

function addressBytes(value) {
  if (typeof value !== 'string' || value.includes('%')) {
    fail('PCP_RESPONSE_ADDRESS_INVALID', '$.external_address');
  }
  const family = net.isIP(value);
  if (family === 0) fail('PCP_RESPONSE_ADDRESS_INVALID', '$.external_address');
  if (family === 4) return ipv4Bytes(value);
  const groups = ipv6Groups(value);
  const bytes = Buffer.alloc(16);
  for (let index = 0; index < 8; index += 1) {
    bytes[index * 2] = groups[index] >>> 8;
    bytes[(index * 2) + 1] = groups[index];
  }
  return bytes;
}

function isIpv4Mapped(bytes) {
  for (let index = 0; index < 10; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  return bytes[10] === 0xff && bytes[11] === 0xff;
}

function nonUsableAddress(bytes) {
  let allZero = true;
  for (const byte of bytes) allZero = allZero && byte === 0;
  if (allZero) return true;
  if (isIpv4Mapped(bytes)) {
    const first = bytes[12];
    return first === 0 || first === 127 || first >= 224 ||
      (first === 169 && bytes[13] === 254);
  }
  let loopback = bytes[15] === 1;
  for (let index = 0; index < 15; index += 1) {
    loopback = loopback && bytes[index] === 0;
  }
  if (loopback || bytes[0] === 0xff) return true;
  return bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80;
}

function snapshotOptions(input, lifetimeSeconds) {
  const options = dataObject(
    input, ['prefer_failure', 'port_set'], '$.options');
  if (typeof options.prefer_failure !== 'boolean') {
    fail('PCP_RESPONSE_OPTION_FIELD_INVALID', '$.options.prefer_failure');
  }
  let portSet = null;
  if (options.port_set !== null) {
    const value = dataObject(options.port_set,
      ['size', 'first_internal_port', 'preserve_parity'],
      '$.options.port_set');
    const size = uint(value.size, 0xffff, '$.options.port_set.size');
    const firstInternalPort = uint(
      value.first_internal_port, 0xffff,
      '$.options.port_set.first_internal_port');
    if (size < 2) {
      fail('PCP_RESPONSE_OPTION_FIELD_INVALID', '$.options.port_set.size');
    }
    if (firstInternalPort === 0) {
      fail('PCP_RESPONSE_OPTION_FIELD_INVALID',
        '$.options.port_set.first_internal_port');
    }
    if (typeof value.preserve_parity !== 'boolean') {
      fail('PCP_RESPONSE_OPTION_FIELD_INVALID',
        '$.options.port_set.preserve_parity');
    }
    portSet = Object.freeze({
      size,
      first_internal_port: firstInternalPort,
      preserve_parity: value.preserve_parity,
    });
  }
  if (options.prefer_failure && portSet !== null) {
    fail('PCP_RESPONSE_OPTIONS_INVALID', '$.options');
  }
  if (lifetimeSeconds === 0 && options.prefer_failure) {
    fail('PCP_RESPONSE_OPTIONS_INVALID', '$.options.prefer_failure');
  }
  return Object.freeze({
    prefer_failure: options.prefer_failure,
    port_set: portSet,
  });
}

function snapshotSemantic(input) {
  const value = dataObject(input, [
    'mode', 'response_type', 'result_code', 'epoch', 'lifetime_seconds',
    'nonce', 'protocol_number', 'internal_port', 'external_port',
    'external_address', 'options',
  ], '$');
  if (value.response_type !== 'map') {
    fail('PCP_RESPONSE_TYPE_INVALID', '$.response_type');
  }
  if (uint(value.result_code, 0xff, '$.result_code') !== 0) {
    fail('PCP_RESPONSE_RESULT_INVALID', '$.result_code');
  }
  const protocolNumber = uint(
    value.protocol_number, 0xff, '$.protocol_number');
  if (protocolNumber !== 6 && protocolNumber !== 17) {
    fail('PCP_RESPONSE_PROTOCOL_INVALID', '$.protocol_number');
  }
  if (typeof value.nonce !== 'string' ||
    !/^[a-f0-9]{24}$/.test(value.nonce) ||
    value.nonce === '0'.repeat(24)) {
    fail('PCP_RESPONSE_NONCE_INVALID', '$.nonce');
  }
  const internalPort = uint(value.internal_port, 0xffff, '$.internal_port');
  if (internalPort === 0) {
    fail('PCP_RESPONSE_INTERNAL_PORT_INVALID', '$.internal_port');
  }
  const externalPort = uint(value.external_port, 0xffff, '$.external_port');
  const lifetimeSeconds = uint(
    value.lifetime_seconds, 0xffffffff, '$.lifetime_seconds');
  const externalAddress = addressBytes(value.external_address);
  if (lifetimeSeconds !== 0 &&
    (externalPort === 0 || nonUsableAddress(externalAddress))) {
    fail('PCP_RESPONSE_MAP_FIELDS_INVALID', '$');
  }
  return Object.freeze({
    epoch: uint(value.epoch, 0xffffffff, '$.epoch'),
    lifetime_seconds: lifetimeSeconds,
    nonce: value.nonce,
    protocol_number: protocolNumber,
    internal_port: internalPort,
    external_port: externalPort,
    external_address: externalAddress,
    options: snapshotOptions(value.options, lifetimeSeconds),
  });
}

function snapshotErrorEcho(input) {
  const value = dataObject(input, [
    'mode', 'response_type', 'result_code', 'epoch', 'lifetime_seconds',
    'request_wire', 'request_parsed',
  ], '$');
  if (value.response_type !== 'map') {
    fail('PCP_RESPONSE_TYPE_INVALID', '$.response_type');
  }
  const resultCode = uint(value.result_code, 0xff, '$.result_code');
  if (resultCode < 1 || resultCode > 13) {
    fail('PCP_RESPONSE_RESULT_INVALID', '$.result_code');
  }
  if (typeof value.request_parsed !== 'boolean') {
    fail('PCP_RESPONSE_FIELD_INVALID', '$.request_parsed');
  }
  return Object.freeze({
    result_code: resultCode,
    epoch: uint(value.epoch, 0xffffffff, '$.epoch'),
    lifetime_seconds: uint(
      value.lifetime_seconds, 0xffffffff, '$.lifetime_seconds'),
    request_wire: requestBytes(value.request_wire),
    request_parsed: value.request_parsed,
  });
}

function put16(out, offset, value) {
  out[offset] = value >>> 8;
  out[offset + 1] = value;
}

function put32(out, offset, value) {
  out[offset] = value >>> 24;
  out[offset + 1] = value >>> 16;
  out[offset + 2] = value >>> 8;
  out[offset + 3] = value;
}

function encodeSemantic(response) {
  const optionSize = (response.options.prefer_failure ? 4 : 0) +
    (response.options.port_set === null ? 0 : 12);
  const out = Buffer.alloc(60 + optionSize);
  out[0] = 2;
  out[1] = 0x81;
  put32(out, 4, response.lifetime_seconds);
  put32(out, 8, response.epoch);
  out.set(Buffer.from(response.nonce, 'hex'), 24);
  out[36] = response.protocol_number;
  put16(out, 40, response.internal_port);
  put16(out, 42, response.external_port);
  out.set(response.external_address, 44);
  let offset = 60;
  if (response.options.prefer_failure) {
    out[offset] = 2;
    offset += 4;
  }
  if (response.options.port_set !== null) {
    out[offset] = 130;
    put16(out, offset + 2, 5);
    put16(out, offset + 4, response.options.port_set.size);
    put16(out, offset + 6, response.options.port_set.first_internal_port);
    out[offset + 8] = response.options.port_set.preserve_parity ? 1 : 0;
  }
  return out;
}

function encodeErrorEcho(response) {
  const out = Buffer.from(response.request_wire);
  out[0] = 2;
  out[1] = 0x81;
  out[2] = 0;
  out[3] = response.result_code;
  put32(out, 4, response.lifetime_seconds);
  put32(out, 8, response.epoch);
  if (response.request_parsed) out.fill(0, 12, 24);
  return out;
}

function encodePcpMapResponse(input) {
  const mode = discriminator(input);
  if (mode === 'semantic') return encodeSemantic(snapshotSemantic(input));
  if (mode === 'error-echo') return encodeErrorEcho(snapshotErrorEcho(input));
  fail('PCP_RESPONSE_MODE_INVALID', '$.mode');
}

module.exports = Object.freeze({ PcpResponseError, encodePcpMapResponse });
