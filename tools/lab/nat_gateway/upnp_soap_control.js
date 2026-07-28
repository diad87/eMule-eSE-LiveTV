'use strict';

const net = require('node:net');
const { TextDecoder } = require('node:util');
const { types } = require('node:util');

const moduleBrand = new WeakSet();
const commandBrand = new WeakSet();
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const bufferGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const byteOffsetGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;
const byteLengthGetter =
  Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const arrayBufferLengthGetter =
  Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
const MAX_SOAP_BYTES = 8192;
const SERVICE_TYPE =
  'urn:schemas-upnp-org:service:WANIPConnection:1';
const SOAP_ENVELOPE =
  'http://schemas.xmlsoap.org/soap/envelope/';
const SOAP_ENCODING =
  'http://schemas.xmlsoap.org/soap/encoding/';
const CONNECTION_STATUSES = new Set([
  'Unconfigured', 'Connecting', 'Connected', 'PendingDisconnect',
  'Disconnecting', 'Disconnected',
]);
const CONNECTION_ERRORS = new Set([
  'ERROR_NONE', 'ERROR_COMMAND_ABORTED',
  'ERROR_NOT_ENABLED_FOR_INTERNET', 'ERROR_USER_DISCONNECT',
  'ERROR_ISP_DISCONNECT', 'ERROR_IDLE_DISCONNECT',
  'ERROR_FORCED_DISCONNECT', 'ERROR_NO_CARRIER',
  'ERROR_IP_CONFIGURATION', 'ERROR_UNKNOWN',
]);

class UpnpSoapBoundaryError extends Error {
  constructor(reasonCode = 'UPNP_SOAP_BOUNDARY_INVALID', fieldPath = '$') {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'UpnpSoapBoundaryError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath) {
  throw new UpnpSoapBoundaryError(reasonCode, fieldPath);
}

function createUpnpSoapControl() {
  if (arguments.length !== 0) throw new UpnpSoapBoundaryError();
  const result = Object.freeze({
    surface: 'soap-control',
    transport: 'http',
    operations: Object.freeze(['control-action']),
  });
  moduleBrand.add(result);
  return result;
}

function isUpnpSoapControl(value) {
  return moduleBrand.has(value);
}

function snapshotBytes(value) {
  if (types.isProxy(value) || !types.isUint8Array(value)) {
    fail('UPNP_SOAP_INPUT_INVALID', '$.body');
  }
  try {
    const backing = bufferGetter.call(value);
    const offset = byteOffsetGetter.call(value);
    const length = byteLengthGetter.call(value);
    const backingLength = arrayBufferLengthGetter.call(backing);
    if (!types.isArrayBuffer(backing) || length < 1 ||
        length > MAX_SOAP_BYTES || offset < 0 ||
        offset > backingLength || length > backingLength - offset) {
      fail('UPNP_SOAP_INPUT_INVALID', '$.body');
    }
    return new Uint8Array(backing, offset, length).slice();
  } catch (error) {
    if (error instanceof UpnpSoapBoundaryError) throw error;
    fail('UPNP_SOAP_INPUT_INVALID', '$.body');
  }
}

function parseAttributes(raw, fieldPath) {
  const attributes = new Map();
  let remaining = raw;
  const pattern =
    /^\s+([A-Za-z_][A-Za-z0-9_.:-]*)="([^"<>&]*)"/;
  while (remaining.length > 0) {
    const match = pattern.exec(remaining);
    if (!match || attributes.has(match[1])) {
      fail('UPNP_SOAP_REQUEST_INVALID', fieldPath);
    }
    attributes.set(match[1], match[2]);
    remaining = remaining.slice(match[0].length);
  }
  return attributes;
}

function decodeUpnpSoapQuery(soapActionInput, bodyInput) {
  if (typeof soapActionInput !== 'string' ||
      soapActionInput.length > 160 ||
      /[\r\n\0]/.test(soapActionInput)) {
    fail('UPNP_SOAP_ACTION_INVALID', '$.soap_action');
  }
  const actionMatch = /^"([^"#]+)#([A-Za-z][A-Za-z0-9]+)"$/
    .exec(soapActionInput);
  if (!actionMatch || actionMatch[1] !== SERVICE_TYPE ||
      !['GetExternalIPAddress', 'GetStatusInfo'].includes(actionMatch[2])) {
    fail('UPNP_SOAP_ACTION_UNSUPPORTED', '$.soap_action');
  }
  let text;
  try {
    text = utf8Decoder.decode(snapshotBytes(bodyInput));
  } catch (error) {
    if (error instanceof UpnpSoapBoundaryError) throw error;
    fail('UPNP_SOAP_INPUT_INVALID', '$.body');
  }
  if (/[\0\u0001-\u0008\u000b\u000c\u000e-\u001f]/.test(text) ||
      /<!|<\?|&/.test(text.replace(/^<\?xml version="1\.0"\?>/, ''))) {
    fail('UPNP_SOAP_REQUEST_INVALID', '$.body');
  }
  const match =
    /^<\?xml version="1\.0"\?>\s*<([A-Za-z_][A-Za-z0-9_.-]*):Envelope\b([^>]*)>\s*<\1:Body>\s*<([A-Za-z_][A-Za-z0-9_.-]*):(GetExternalIPAddress|GetStatusInfo)\b([^>]*)>\s*<\/\3:\4>\s*<\/\1:Body>\s*<\/\1:Envelope>\s*$/
      .exec(text);
  if (!match || match[1] === match[3] || match[4] !== actionMatch[2]) {
    fail('UPNP_SOAP_REQUEST_INVALID', '$.body');
  }
  const envelopeAttributes = parseAttributes(match[2], '$.body.Envelope');
  const actionAttributes = parseAttributes(match[5], '$.body.action');
  if (envelopeAttributes.size !== 2 ||
      envelopeAttributes.get(`xmlns:${match[1]}`) !== SOAP_ENVELOPE ||
      envelopeAttributes.get(`${match[1]}:encodingStyle`) !== SOAP_ENCODING ||
      actionAttributes.size !== 1 ||
      actionAttributes.get(`xmlns:${match[3]}`) !== SERVICE_TYPE) {
    fail('UPNP_SOAP_REQUEST_INVALID', '$.body');
  }
  const operation = actionMatch[2] === 'GetExternalIPAddress' ?
    'get_external_ip_address' : 'get_status_info';
  const result = Object.freeze({
    protocol: 'upnp',
    operation,
    service_type: SERVICE_TYPE,
  });
  commandBrand.add(result);
  return result;
}

function decodeUpnpAddPortMapping(soapActionInput, bodyInput) {
  const expectedSoapAction = `"${SERVICE_TYPE}#AddPortMapping"`;
  if (typeof soapActionInput !== 'string' ||
      soapActionInput.length > 160 ||
      /[\r\n\0]/.test(soapActionInput) ||
      soapActionInput !== expectedSoapAction) {
    fail('UPNP_SOAP_ACTION_UNSUPPORTED', '$.soap_action');
  }
  let text;
  try {
    text = utf8Decoder.decode(snapshotBytes(bodyInput));
  } catch (error) {
    if (error instanceof UpnpSoapBoundaryError) throw error;
    fail('UPNP_SOAP_INPUT_INVALID', '$.body');
  }
  if (/[\0\u0001-\u0008\u000b\u000c\u000e-\u001f]/.test(text) ||
      /<!|<\?|&/.test(text.replace(/^<\?xml version="1\.0"\?>/, ''))) {
    fail('UPNP_SOAP_REQUEST_INVALID', '$.body');
  }
  const match =
    /^<\?xml version="1\.0"\?>\s*<([A-Za-z_][A-Za-z0-9_.-]*):Envelope\b([^>]*)>\s*<\1:Body>\s*<([A-Za-z_][A-Za-z0-9_.-]*):AddPortMapping\b([^>]*)>([\s\S]*?)<\/\3:AddPortMapping>\s*<\/\1:Body>\s*<\/\1:Envelope>\s*$/
      .exec(text);
  if (!match || match[1] === match[3]) {
    fail('UPNP_SOAP_REQUEST_INVALID', '$.body');
  }
  const envelopeAttributes = parseAttributes(match[2], '$.body.Envelope');
  const actionAttributes = parseAttributes(match[4], '$.body.action');
  if (envelopeAttributes.size !== 2 ||
      envelopeAttributes.get(`xmlns:${match[1]}`) !== SOAP_ENVELOPE ||
      envelopeAttributes.get(`${match[1]}:encodingStyle`) !== SOAP_ENCODING ||
      actionAttributes.size !== 1 ||
      actionAttributes.get(`xmlns:${match[3]}`) !== SERVICE_TYPE) {
    fail('UPNP_SOAP_REQUEST_INVALID', '$.body');
  }
  const argumentsMap = new Map();
  let remaining = match[5];
  const argumentPattern =
    /^\s*<([A-Za-z][A-Za-z0-9]*)>([^<>&]*)<\/\1>/;
  while (remaining.trim().length > 0) {
    const argumentMatch = argumentPattern.exec(remaining);
    if (!argumentMatch || argumentsMap.has(argumentMatch[1])) {
      fail('UPNP_SOAP_REQUEST_INVALID', '$.body.arguments');
    }
    argumentsMap.set(argumentMatch[1], argumentMatch[2]);
    remaining = remaining.slice(argumentMatch[0].length);
  }
  const expected = [
    'NewRemoteHost', 'NewExternalPort', 'NewProtocol', 'NewInternalPort',
    'NewInternalClient', 'NewEnabled', 'NewPortMappingDescription',
    'NewLeaseDuration',
  ];
  if (argumentsMap.size !== expected.length ||
      expected.some((name) => !argumentsMap.has(name))) {
    fail('UPNP_SOAP_REQUEST_INVALID', '$.body.arguments');
  }
  const decimal = /^(0|[1-9][0-9]*)$/;
  const externalPortText = argumentsMap.get('NewExternalPort');
  const internalPortText = argumentsMap.get('NewInternalPort');
  const leaseText = argumentsMap.get('NewLeaseDuration');
  if (argumentsMap.get('NewRemoteHost') !== '' ||
      !decimal.test(externalPortText) ||
      !decimal.test(internalPortText) ||
      !decimal.test(leaseText)) {
    fail('UPNP_SOAP_ARGUMENT_INVALID', '$.body.arguments');
  }
  const externalPort = Number(externalPortText);
  const internalPort = Number(internalPortText);
  const leaseSeconds = Number(leaseText);
  const protocol = argumentsMap.get('NewProtocol');
  const internalClient = argumentsMap.get('NewInternalClient');
  const enabled = argumentsMap.get('NewEnabled');
  const description = argumentsMap.get('NewPortMappingDescription');
  if (!Number.isInteger(externalPort) ||
      externalPort < 1 || externalPort > 65535 ||
      !Number.isInteger(internalPort) ||
      internalPort < 1 || internalPort > 65535 ||
      !Number.isInteger(leaseSeconds) ||
      leaseSeconds < 0 || leaseSeconds > 0xffffffff ||
      !['TCP', 'UDP'].includes(protocol) ||
      net.isIP(internalClient) !== 4 ||
      internalClient === '0.0.0.0' ||
      /^127\./.test(internalClient) ||
      Number(internalClient.split('.')[0]) >= 224 ||
      !['0', '1'].includes(enabled) ||
      !/^[A-Za-z0-9 ._-]{1,64}$/.test(description)) {
    fail('UPNP_SOAP_ARGUMENT_INVALID', '$.body.arguments');
  }
  const result = Object.freeze({
    protocol: 'upnp',
    operation: 'add_port_mapping',
    service_type: SERVICE_TYPE,
    remote_host: '',
    external_port: externalPort,
    transport: protocol.toLowerCase(),
    internal_port: internalPort,
    internal_client: internalClient,
    enabled: enabled === '1',
    description,
    lease_seconds: leaseSeconds,
  });
  commandBrand.add(result);
  return result;
}

function decodeUpnpPortMappingAction(soapActionInput, bodyInput) {
  if (typeof soapActionInput !== 'string' ||
      soapActionInput.length > 160 ||
      /[\r\n\0]/.test(soapActionInput)) {
    fail('UPNP_SOAP_ACTION_INVALID', '$.soap_action');
  }
  const actionMatch =
    /^"urn:schemas-upnp-org:service:WANIPConnection:1#(GetSpecificPortMappingEntry|GetGenericPortMappingEntry|DeletePortMapping)"$/
      .exec(soapActionInput);
  if (!actionMatch) {
    fail('UPNP_SOAP_ACTION_UNSUPPORTED', '$.soap_action');
  }
  let text;
  try {
    text = utf8Decoder.decode(snapshotBytes(bodyInput));
  } catch (error) {
    if (error instanceof UpnpSoapBoundaryError) throw error;
    fail('UPNP_SOAP_INPUT_INVALID', '$.body');
  }
  if (/[\0\u0001-\u0008\u000b\u000c\u000e-\u001f]/.test(text) ||
      /<!|<\?|&/.test(text.replace(/^<\?xml version="1\.0"\?>/, ''))) {
    fail('UPNP_SOAP_REQUEST_INVALID', '$.body');
  }
  const match =
    /^<\?xml version="1\.0"\?>\s*<([A-Za-z_][A-Za-z0-9_.-]*):Envelope\b([^>]*)>\s*<\1:Body>\s*<([A-Za-z_][A-Za-z0-9_.-]*):(GetSpecificPortMappingEntry|GetGenericPortMappingEntry|DeletePortMapping)\b([^>]*)>([\s\S]*?)<\/\3:\4>\s*<\/\1:Body>\s*<\/\1:Envelope>\s*$/
      .exec(text);
  if (!match || match[1] === match[3] || match[4] !== actionMatch[1]) {
    fail('UPNP_SOAP_REQUEST_INVALID', '$.body');
  }
  const envelopeAttributes = parseAttributes(match[2], '$.body.Envelope');
  const actionAttributes = parseAttributes(match[5], '$.body.action');
  if (envelopeAttributes.size !== 2 ||
      envelopeAttributes.get(`xmlns:${match[1]}`) !== SOAP_ENVELOPE ||
      envelopeAttributes.get(`${match[1]}:encodingStyle`) !== SOAP_ENCODING ||
      actionAttributes.size !== 1 ||
      actionAttributes.get(`xmlns:${match[3]}`) !== SERVICE_TYPE) {
    fail('UPNP_SOAP_REQUEST_INVALID', '$.body');
  }
  const argumentsMap = new Map();
  let remaining = match[6];
  const argumentPattern =
    /^\s*<([A-Za-z][A-Za-z0-9]*)>([^<>&]*)<\/\1>/;
  while (remaining.trim().length > 0) {
    const argumentMatch = argumentPattern.exec(remaining);
    if (!argumentMatch || argumentsMap.has(argumentMatch[1])) {
      fail('UPNP_SOAP_REQUEST_INVALID', '$.body.arguments');
    }
    argumentsMap.set(argumentMatch[1], argumentMatch[2]);
    remaining = remaining.slice(argumentMatch[0].length);
  }
  const decimal = /^(0|[1-9][0-9]*)$/;
  let result;
  if (actionMatch[1] !== 'GetGenericPortMappingEntry') {
    const expected = ['NewRemoteHost', 'NewExternalPort', 'NewProtocol'];
    if (argumentsMap.size !== expected.length ||
        expected.some((name) => !argumentsMap.has(name)) ||
        argumentsMap.get('NewRemoteHost') !== '' ||
        !decimal.test(argumentsMap.get('NewExternalPort')) ||
        !['TCP', 'UDP'].includes(argumentsMap.get('NewProtocol'))) {
      fail('UPNP_SOAP_ARGUMENT_INVALID', '$.body.arguments');
    }
    const externalPort = Number(argumentsMap.get('NewExternalPort'));
    if (externalPort < 1 || externalPort > 65535) {
      fail('UPNP_SOAP_ARGUMENT_INVALID', '$.body.arguments.NewExternalPort');
    }
    const operation = actionMatch[1] === 'DeletePortMapping' ?
      'delete_port_mapping' : 'get_specific_port_mapping_entry';
    result = Object.freeze({
      protocol: 'upnp',
      operation,
      service_type: SERVICE_TYPE,
      remote_host: '',
      external_port: externalPort,
      transport: argumentsMap.get('NewProtocol').toLowerCase(),
    });
  } else {
    if (argumentsMap.size !== 1 ||
        !argumentsMap.has('NewPortMappingIndex') ||
        !decimal.test(argumentsMap.get('NewPortMappingIndex'))) {
      fail('UPNP_SOAP_ARGUMENT_INVALID', '$.body.arguments');
    }
    const index = Number(argumentsMap.get('NewPortMappingIndex'));
    if (index > 65535) {
      fail('UPNP_SOAP_ARGUMENT_INVALID',
        '$.body.arguments.NewPortMappingIndex');
    }
    result = Object.freeze({
      protocol: 'upnp',
      operation: 'get_generic_port_mapping_entry',
      service_type: SERVICE_TYPE,
      index,
    });
  }
  commandBrand.add(result);
  return result;
}

function decodeUpnpPortMappingReadback(soapActionInput, bodyInput) {
  const result = decodeUpnpPortMappingAction(soapActionInput, bodyInput);
  if (result.operation === 'delete_port_mapping') {
    fail('UPNP_SOAP_ACTION_UNSUPPORTED', '$.soap_action');
  }
  return result;
}

function decodeUpnpDeletePortMapping(soapActionInput, bodyInput) {
  const result = decodeUpnpPortMappingAction(soapActionInput, bodyInput);
  if (result.operation !== 'delete_port_mapping') {
    fail('UPNP_SOAP_ACTION_UNSUPPORTED', '$.soap_action');
  }
  return result;
}

function readClosedData(input, required, fieldPath) {
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== required.length ||
      names.some((name) => !required.includes(name))) {
    fail('UPNP_SOAP_RESULT_INVALID', fieldPath);
  }
  const result = Object.create(null);
  for (const name of required) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') ||
        descriptor.enumerable !== true) {
      fail('UPNP_SOAP_RESULT_INVALID', `${fieldPath}.${name}`);
    }
    result[name] = descriptor.value;
  }
  return result;
}

function readDiscriminatedResult(input, successFields) {
  if (input === null || typeof input !== 'object' || types.isProxy(input) ||
      Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype ||
      Object.getOwnPropertySymbols(input).length !== 0) {
    fail('UPNP_SOAP_RESULT_INVALID', '$.result');
  }
  const okDescriptor = Object.getOwnPropertyDescriptor(input, 'ok');
  if (!okDescriptor || !Object.hasOwn(okDescriptor, 'value') ||
      okDescriptor.enumerable !== true ||
      typeof okDescriptor.value !== 'boolean') {
    fail('UPNP_SOAP_RESULT_INVALID', '$.result.ok');
  }
  const required = okDescriptor.value ?
    ['ok', ...successFields] :
    ['ok', 'error_code', 'error_description'];
  return readClosedData(input, required, '$.result');
}

function escapeXml(value) {
  return value.replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function encodeFault(result) {
  if (!Number.isInteger(result.error_code) ||
      result.error_code < 400 || result.error_code > 899 ||
      typeof result.error_description !== 'string' ||
      !/^[A-Za-z0-9 ._-]{1,64}$/.test(result.error_description)) {
    fail('UPNP_SOAP_RESULT_INVALID', '$.result');
  }
  const description = escapeXml(result.error_description);
  return {
    status_code: 500,
    body: Buffer.from(
      '<?xml version="1.0"?>' +
      `<s:Envelope xmlns:s="${SOAP_ENVELOPE}" ` +
      `s:encodingStyle="${SOAP_ENCODING}"><s:Body><s:Fault>` +
      '<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>' +
      '<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">' +
      `<errorCode>${result.error_code}</errorCode>` +
      `<errorDescription>${description}</errorDescription>` +
      '</UPnPError></detail></s:Fault></s:Body></s:Envelope>',
      'utf8'),
  };
}

function encodeUpnpSoapQueryResponse(command, resultInput) {
  if (!commandBrand.has(command)) {
    fail('UPNP_SOAP_COMMAND_INVALID', '$.command');
  }
  let successFields = [];
  if (command.operation === 'get_external_ip_address') {
    successFields = ['external_address'];
  } else if (command.operation === 'get_status_info') {
    successFields = [
      'connection_status', 'last_connection_error', 'uptime_seconds',
    ];
  } else if (command.operation === 'get_specific_port_mapping_entry') {
    successFields = [
      'internal_port', 'internal_client', 'enabled', 'description',
      'lease_seconds',
    ];
  } else if (command.operation === 'get_generic_port_mapping_entry') {
    successFields = [
      'remote_host', 'external_port', 'transport', 'internal_port',
      'internal_client', 'enabled', 'description', 'lease_seconds',
    ];
  }
  const result = readDiscriminatedResult(resultInput, successFields);
  if (result.ok === false) {
    return encodeFault(result);
  }
  let action;
  let payload;
  if (command.operation === 'get_external_ip_address') {
    if (typeof result.external_address !== 'string' ||
        (result.external_address !== '' &&
         net.isIP(result.external_address) !== 4)) {
      fail('UPNP_SOAP_RESULT_INVALID', '$.result.external_address');
    }
    action = 'GetExternalIPAddress';
    payload = `<NewExternalIPAddress>${result.external_address}` +
      '</NewExternalIPAddress>';
  } else if (command.operation === 'get_status_info') {
    if (!CONNECTION_STATUSES.has(result.connection_status) ||
        !CONNECTION_ERRORS.has(result.last_connection_error) ||
        !Number.isInteger(result.uptime_seconds) ||
        result.uptime_seconds < 0 || result.uptime_seconds > 0xffffffff) {
      fail('UPNP_SOAP_RESULT_INVALID', '$.result');
    }
    action = 'GetStatusInfo';
    payload =
      `<NewConnectionStatus>${result.connection_status}` +
      '</NewConnectionStatus>' +
      `<NewLastConnectionError>${result.last_connection_error}` +
      '</NewLastConnectionError>' +
      `<NewUptime>${result.uptime_seconds}</NewUptime>`;
  } else if (command.operation === 'add_port_mapping' ||
      command.operation === 'delete_port_mapping') {
    action = command.operation === 'add_port_mapping' ?
      'AddPortMapping' : 'DeletePortMapping';
    payload = '';
  } else {
    const generic =
      command.operation === 'get_generic_port_mapping_entry';
    if (!Number.isInteger(result.internal_port) ||
        result.internal_port < 1 || result.internal_port > 65535 ||
        net.isIP(result.internal_client) !== 4 ||
        typeof result.enabled !== 'boolean' ||
        typeof result.description !== 'string' ||
        Array.from(result.description).length > 64 ||
        !result.description.isWellFormed() ||
        /[\0\u0001-\u0008\u000b\u000c\u000e-\u001f]/u
          .test(result.description) ||
        !Number.isInteger(result.lease_seconds) ||
        Object.is(result.lease_seconds, -0) ||
        result.lease_seconds < 0 ||
        result.lease_seconds > 0xffffffff ||
        (generic && (result.remote_host !== '' ||
          !Number.isInteger(result.external_port) ||
          result.external_port < 1 || result.external_port > 65535 ||
          !['tcp', 'udp'].includes(result.transport)))) {
      fail('UPNP_SOAP_RESULT_INVALID', '$.result');
    }
    action = generic ?
      'GetGenericPortMappingEntry' : 'GetSpecificPortMappingEntry';
    payload =
      (generic ?
        `<NewRemoteHost>${escapeXml(result.remote_host)}</NewRemoteHost>` +
        `<NewExternalPort>${result.external_port}</NewExternalPort>` +
        `<NewProtocol>${result.transport.toUpperCase()}</NewProtocol>` :
        '') +
      `<NewInternalPort>${result.internal_port}</NewInternalPort>` +
      `<NewInternalClient>${escapeXml(result.internal_client)}` +
      '</NewInternalClient>' +
      `<NewEnabled>${result.enabled ? 1 : 0}</NewEnabled>` +
      `<NewPortMappingDescription>${escapeXml(result.description)}` +
      '</NewPortMappingDescription>' +
      `<NewLeaseDuration>${result.lease_seconds}</NewLeaseDuration>`;
  }
  return {
    status_code: 200,
    body: Buffer.from(
      '<?xml version="1.0"?>' +
      `<s:Envelope xmlns:s="${SOAP_ENVELOPE}" ` +
      `s:encodingStyle="${SOAP_ENCODING}"><s:Body>` +
      `<u:${action}Response xmlns:u="${SERVICE_TYPE}">` +
      `${payload}</u:${action}Response></s:Body></s:Envelope>`,
      'utf8'),
  };
}

module.exports = Object.freeze({
  UpnpSoapBoundaryError,
  createUpnpSoapControl,
  decodeUpnpAddPortMapping,
  decodeUpnpDeletePortMapping,
  decodeUpnpPortMappingReadback,
  decodeUpnpSoapQuery,
  encodeUpnpSoapQueryResponse,
  isUpnpSoapControl,
});
