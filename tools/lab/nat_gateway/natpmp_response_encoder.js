'use strict';

// C03 is a pure, independent NAT-PMP response boundary. It has no socket,
// timer, clock or filesystem use, and imports no productive codec.
const { types } = require('node:util');

const RESULT_CODES = new Set([0, 1, 2, 3, 4, 5]);
const objectPrototype = Object.prototype;
const arrayPrototype = Array.prototype;

class NatPmpResponseError extends Error {
  constructor(reasonCode, fieldPath) {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'NatPmpResponseError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) { throw new NatPmpResponseError(reasonCode, fieldPath); }

function ordinary(value, fieldPath) {
  if (value === null || typeof value !== 'object' || types.isProxy(value) || Object.getPrototypeOf(value) !== objectPrototype) {
    fail('NATPMP_RESPONSE_INPUT_INVALID', fieldPath);
  }
}

function dataObject(value, allowed, fieldPath) {
  ordinary(value, fieldPath);
  const names = Object.getOwnPropertyNames(value);
  if (Object.getOwnPropertySymbols(value).length !== 0) fail('NATPMP_RESPONSE_UNKNOWN_FIELD', `${fieldPath}.*`);
  for (const name of names) if (!allowed.includes(name)) fail('NATPMP_RESPONSE_UNKNOWN_FIELD', `${fieldPath}.*`);
  const copy = Object.create(null);
  for (const name of allowed) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor) fail('NATPMP_RESPONSE_FIELD_MISSING', `${fieldPath}.${name}`);
    if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail('NATPMP_RESPONSE_INPUT_INVALID', `${fieldPath}.${name}`);
    copy[name] = descriptor.value;
  }
  return copy;
}

function uint(value, maximum, fieldPath) {
  // Wire integers have one canonical JavaScript representation for zero.
  // Reject -0 rather than silently accepting a second in-memory spelling.
  if (typeof value !== 'number' || !Number.isInteger(value) || Object.is(value, -0) || value < 0 || value > maximum) fail('NATPMP_RESPONSE_FIELD_INVALID', fieldPath);
  return value;
}

function ipv4(value) {
  // A revoked proxy can throw from Array.isArray; proxy status must be tested
  // first just as it is for the enclosing ordinary-object boundary.
  if (types.isProxy(value) || !Array.isArray(value) || Object.getPrototypeOf(value) !== arrayPrototype) {
    fail('NATPMP_RESPONSE_FIELD_INVALID', '$.external_ip');
  }
  const names = Object.getOwnPropertyNames(value);
  if (Object.getOwnPropertySymbols(value).length !== 0) fail('NATPMP_RESPONSE_UNKNOWN_FIELD', '$.external_ip.*');
  for (const name of names) if (name !== 'length' && !/^[0-3]$/.test(name)) fail('NATPMP_RESPONSE_UNKNOWN_FIELD', '$.external_ip.*');
  const length = Object.getOwnPropertyDescriptor(value, 'length');
  if (!length || !Object.hasOwn(length, 'value') || length.enumerable !== false || length.value !== 4) fail('NATPMP_RESPONSE_FIELD_INVALID', '$.external_ip');
  const copy = [];
  for (let index = 0; index < 4; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor) fail('NATPMP_RESPONSE_FIELD_MISSING', `$.external_ip[${index}]`);
    if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail('NATPMP_RESPONSE_FIELD_INVALID', `$.external_ip[${index}]`);
    copy.push(uint(descriptor.value, 0xff, `$.external_ip[${index}]`));
  }
  return copy;
}

function baseType(input) {
  ordinary(input, '$');
  const descriptor = Object.getOwnPropertyDescriptor(input, 'response_type');
  if (!descriptor) fail('NATPMP_RESPONSE_FIELD_MISSING', '$.response_type');
  if (!Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) fail('NATPMP_RESPONSE_INPUT_INVALID', '$.response_type');
  return descriptor.value;
}

function snapshotResponse(input) {
  const type = baseType(input);
  if (type === 'external-address') {
    const value = dataObject(input, ['response_type', 'result_code', 'epoch', 'external_ip'], '$');
    const resultCode = uint(value.result_code, 0xffff, '$.result_code');
    if (!RESULT_CODES.has(resultCode)) fail('NATPMP_RESPONSE_RESULT_INVALID', '$.result_code');
    const result = { response_type: type, result_code: resultCode, epoch: uint(value.epoch, 0xffffffff, '$.epoch'), external_ip: ipv4(value.external_ip) };
    if (resultCode === 0 && result.external_ip.every((octet) => octet === 0)) fail('NATPMP_RESPONSE_EXTERNAL_IP_INVALID', '$.external_ip');
    if (resultCode !== 0 && result.external_ip.some((octet) => octet !== 0)) fail('NATPMP_RESPONSE_REJECT_FIELDS_INVALID', '$.external_ip');
    return result;
  }
  if (type !== 'map') fail('NATPMP_RESPONSE_TYPE_INVALID', '$.response_type');
  const value = dataObject(input, ['response_type', 'transport', 'result_code', 'epoch', 'internal_port', 'external_port', 'lifetime_seconds'], '$');
  if (value.transport !== 'udp' && value.transport !== 'tcp') fail('NATPMP_RESPONSE_TRANSPORT_INVALID', '$.transport');
  const resultCode = uint(value.result_code, 0xffff, '$.result_code');
  if (!RESULT_CODES.has(resultCode)) fail('NATPMP_RESPONSE_RESULT_INVALID', '$.result_code');
  const result = {
    response_type: type, transport: value.transport, result_code: resultCode,
    epoch: uint(value.epoch, 0xffffffff, '$.epoch'), internal_port: uint(value.internal_port, 0xffff, '$.internal_port'),
    external_port: uint(value.external_port, 0xffff, '$.external_port'), lifetime_seconds: uint(value.lifetime_seconds, 0xffffffff, '$.lifetime_seconds'),
  };
  if (result.internal_port === 0) fail('NATPMP_RESPONSE_INTERNAL_PORT_INVALID', '$.internal_port');
  if (resultCode !== 0 && (result.external_port !== 0 || result.lifetime_seconds !== 0)) fail('NATPMP_RESPONSE_REJECT_FIELDS_INVALID', '$');
  if (resultCode === 0 && ((result.external_port === 0) !== (result.lifetime_seconds === 0))) fail('NATPMP_RESPONSE_MAP_FIELDS_INVALID', '$');
  return result;
}

function put16(out, offset, value) { out[offset] = value >>> 8; out[offset + 1] = value; }
function put32(out, offset, value) { out[offset] = value >>> 24; out[offset + 1] = value >>> 16; out[offset + 2] = value >>> 8; out[offset + 3] = value; }

function encodeNatPmpResponse(input) {
  const response = snapshotResponse(input);
  if (response.response_type === 'external-address') {
    const out = Buffer.alloc(12);
    out[1] = 128; put16(out, 2, response.result_code); put32(out, 4, response.epoch); out.set(response.external_ip, 8);
    return out;
  }
  const out = Buffer.alloc(16);
  out[1] = response.transport === 'udp' ? 129 : 130;
  put16(out, 2, response.result_code); put32(out, 4, response.epoch); put16(out, 8, response.internal_port); put16(out, 10, response.external_port); put32(out, 12, response.lifetime_seconds);
  return out;
}

module.exports = Object.freeze({ NatPmpResponseError, encodeNatPmpResponse });
