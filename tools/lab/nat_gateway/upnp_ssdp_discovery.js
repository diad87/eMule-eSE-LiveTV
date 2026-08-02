'use strict';

const net = require('node:net');
const { types } = require('node:util');

const moduleBrand = new WeakSet();
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const bufferGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const byteOffsetGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const byteLengthGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const arrayBufferLengthGetter =
  Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const MAX_DATAGRAM_BYTES = 2048;

class UpnpSsdpBoundaryError extends Error {
  constructor(reasonCode = 'UPNP_SSDP_BOUNDARY_INVALID', fieldPath = '$') {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'UpnpSsdpBoundaryError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) {
  throw new UpnpSsdpBoundaryError(reasonCode, fieldPath);
}

function createUpnpSsdpDiscovery() {
  if (arguments.length !== 0) throw new UpnpSsdpBoundaryError();
  const result = Object.freeze({
    surface: 'ssdp-discovery',
    transport: 'udp',
    operations: Object.freeze(['m-search']),
  });
  moduleBrand.add(result);
  return result;
}

function isUpnpSsdpDiscovery(value) {
  return moduleBrand.has(value);
}

function snapshotBytes(value) {
  if (types.isProxy(value) || !types.isUint8Array(value)) {
    fail('UPNP_SSDP_INPUT_INVALID', '$.wire');
  }
  try {
    const backing = bufferGetter.call(value);
    const offset = byteOffsetGetter.call(value);
    const length = byteLengthGetter.call(value);
    const backingLength = arrayBufferLengthGetter.call(backing);
    if (!types.isArrayBuffer(backing) || length < 1 ||
        length > MAX_DATAGRAM_BYTES || offset < 0 ||
        offset > backingLength || length > backingLength - offset) {
      fail('UPNP_SSDP_INPUT_INVALID', '$.wire');
    }
    return Buffer.from(new Uint8Array(backing, offset, length));
  } catch (error) {
    if (error instanceof UpnpSsdpBoundaryError) throw error;
    fail('UPNP_SSDP_INPUT_INVALID', '$.wire');
  }
}

function requestConfig(input) {
  if (input === null || typeof input !== 'object' || types.isProxy(input) ||
      Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Object.getOwnPropertySymbols(input).length !== 0 ||
      Object.getOwnPropertyNames(input).join('\0') !== 'search_target') {
    fail('UPNP_SSDP_CONFIG_INVALID', '$.config');
  }
  const descriptor = Object.getOwnPropertyDescriptor(input, 'search_target');
  if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
      descriptor.enumerable !== true ||
      typeof descriptor.value !== 'string' ||
      !/^urn:schemas-upnp-org:device:InternetGatewayDevice:[12]$/
        .test(descriptor.value)) {
    fail('UPNP_SSDP_CONFIG_INVALID', '$.config.search_target');
  }
  return descriptor.value;
}

function decodeUpnpMSearch(wireInput, configInput) {
  const wire = snapshotBytes(wireInput);
  const searchTarget = requestConfig(configInput);
  for (const byte of wire) {
    if (byte > 0x7f || byte === 0 ||
        (byte < 0x20 && byte !== 0x09 && byte !== 0x0a && byte !== 0x0d)) {
      fail('UPNP_SSDP_REQUEST_INVALID', '$.wire');
    }
  }
  const text = wire.toString('ascii');
  if (/\r(?!\n)|(^|[^\r])\n/.test(text)) {
    fail('UPNP_SSDP_REQUEST_INVALID', '$.wire');
  }
  if (!text.endsWith('\r\n\r\n') ||
      text.indexOf('\r\n\r\n') !== text.length - 4) {
    fail('UPNP_SSDP_REQUEST_INVALID', '$.wire');
  }
  const lines = text.slice(0, -4).split('\r\n');
  if (lines.shift() !== 'M-SEARCH * HTTP/1.1') {
    fail('UPNP_SSDP_REQUEST_INVALID', '$.request_line');
  }
  const headers = new Map();
  for (const line of lines) {
    if (line.length === 0 || /^[ \t]/.test(line)) {
      fail('UPNP_SSDP_REQUEST_INVALID', '$.headers');
    }
    const colon = line.indexOf(':');
    if (colon < 1) fail('UPNP_SSDP_REQUEST_INVALID', '$.headers');
    const name = line.slice(0, colon).toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (!/^[a-z0-9-]+$/.test(name) || headers.has(name)) {
      fail('UPNP_SSDP_REQUEST_INVALID', '$.headers');
    }
    headers.set(name, value);
  }
  if (headers.get('host') !== '239.255.255.250:1900') {
    fail('UPNP_SSDP_REQUEST_INVALID', '$.headers.host');
  }
  if (headers.get('man') !== '"ssdp:discover"') {
    fail('UPNP_SSDP_MAN_REQUIRED', '$.headers.man');
  }
  if (headers.get('st') !== searchTarget) {
    fail('UPNP_SSDP_ST_UNSUPPORTED', '$.headers.st');
  }
  const mx = headers.get('mx');
  if (!/^[1-9][0-9]*$/.test(mx || '')) {
    fail('UPNP_SSDP_REQUEST_INVALID', '$.headers.mx');
  }
  const requestedMx = BigInt(mx);
  return Object.freeze({
    protocol: 'upnp',
    operation: 'discover',
    search_target: searchTarget,
    mx_seconds: requestedMx > 5n ? 5 : Number(requestedMx),
  });
}

function adapterHost(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const octets = address.split('.').map(Number);
    if (octets[0] === 0 || octets[0] === 127 || octets[0] >= 224 ||
        octets.every((octet) => octet === 255)) {
      fail('UPNP_SSDP_CONFIG_INVALID', '$.config.adapter_address');
    }
    return address;
  }
  if (family !== 6 || address === '::' || address === '::1' ||
      /^ff/i.test(address) || /^::ffff:/i.test(address)) {
    fail('UPNP_SSDP_CONFIG_INVALID', '$.config.adapter_address');
  }
  const zoneIndex = address.lastIndexOf('%');
  const bareAddress = zoneIndex < 0 ? address : address.slice(0, zoneIndex);
  const zone = zoneIndex < 0 ? '' : address.slice(zoneIndex + 1);
  if (/^fe[89ab]/i.test(bareAddress) &&
      !/^[A-Za-z0-9_.-]{1,32}$/.test(zone)) {
    fail('UPNP_SSDP_CONFIG_INVALID', '$.config.adapter_address');
  }
  return `[${address.replace('%', '%25')}]`;
}

function responseConfig(input, command) {
  const required = [
    'adapter_address', 'http_port', 'description_path',
    'usn_uuid', 'max_age_seconds',
  ];
  if (input === null || typeof input !== 'object' || types.isProxy(input) ||
      Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Object.getOwnPropertySymbols(input).length !== 0) {
    fail('UPNP_SSDP_CONFIG_INVALID', '$.config');
  }
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== required.length ||
      names.some((name) => !required.includes(name))) {
    fail('UPNP_SSDP_CONFIG_INVALID', '$.config');
  }
  const result = Object.create(null);
  for (const name of required) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
        descriptor.enumerable !== true) {
      fail('UPNP_SSDP_CONFIG_INVALID', `$.config.${name}`);
    }
    result[name] = descriptor.value;
  }
  if (typeof result.adapter_address !== 'string' ||
      !Number.isInteger(result.http_port) ||
      result.http_port < 1 || result.http_port > 65535 ||
      typeof result.description_path !== 'string' ||
      !/^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,255}$/
        .test(result.description_path) ||
      typeof result.usn_uuid !== 'string' ||
      !/^uuid:[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$/
        .test(result.usn_uuid) ||
      !Number.isInteger(result.max_age_seconds) ||
      result.max_age_seconds < 1 ||
      result.max_age_seconds > 0xffffffff) {
    fail('UPNP_SSDP_CONFIG_INVALID', '$.config');
  }
  result.host = adapterHost(result.adapter_address);
  if (command === null || typeof command !== 'object' ||
      types.isProxy(command) || Array.isArray(command) ||
      Object.getPrototypeOf(command) !== Object.prototype ||
      Object.getOwnPropertySymbols(command).length !== 0) {
    fail('UPNP_SSDP_COMMAND_INVALID', '$.command');
  }
  const commandNames = [
    'protocol', 'operation', 'search_target', 'mx_seconds',
  ];
  const ownCommandNames = Object.getOwnPropertyNames(command);
  if (ownCommandNames.length !== commandNames.length ||
      ownCommandNames.some((name) => !commandNames.includes(name))) {
    fail('UPNP_SSDP_COMMAND_INVALID', '$.command');
  }
  const commandCopy = Object.create(null);
  for (const name of commandNames) {
    const descriptor = Object.getOwnPropertyDescriptor(command, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
        descriptor.enumerable !== true) {
      fail('UPNP_SSDP_COMMAND_INVALID', `$.command.${name}`);
    }
    commandCopy[name] = descriptor.value;
  }
  if (commandCopy.protocol !== 'upnp' ||
      commandCopy.operation !== 'discover' ||
      typeof commandCopy.search_target !== 'string' ||
      !/^urn:schemas-upnp-org:device:InternetGatewayDevice:[12]$/
        .test(commandCopy.search_target) ||
      !Number.isInteger(commandCopy.mx_seconds) ||
      commandCopy.mx_seconds < 1 || commandCopy.mx_seconds > 5) {
    fail('UPNP_SSDP_COMMAND_INVALID', '$.command');
  }
  result.search_target = commandCopy.search_target;
  return result;
}

function encodeUpnpMSearchResponse(command, configInput) {
  const config = responseConfig(configInput, command);
  const location = `http://${config.host}:${config.http_port}` +
    config.description_path;
  const lines = [
    'HTTP/1.1 200 OK',
    `CACHE-CONTROL: max-age=${config.max_age_seconds}`,
    'EXT:',
    `LOCATION: ${location}`,
    'SERVER: eSE-T8/9.2 UPnP/2.0 eSE-IGD/9.2',
    `ST: ${config.search_target}`,
    `USN: ${config.usn_uuid}::${config.search_target}`,
    '',
    '',
  ];
  return Buffer.from(lines.join('\r\n'), 'ascii');
}

module.exports = Object.freeze({
  UpnpSsdpBoundaryError,
  createUpnpSsdpDiscovery,
  decodeUpnpMSearch,
  encodeUpnpMSearchResponse,
  isUpnpSsdpDiscovery,
});
