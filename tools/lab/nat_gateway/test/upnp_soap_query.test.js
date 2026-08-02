'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  UpnpSoapBoundaryError,
  decodeUpnpSoapQuery,
  encodeUpnpSoapQueryResponse,
} = require('../upnp_soap_control');

const service =
  'urn:schemas-upnp-org:service:WANIPConnection:1';

function body(action, overrides = {}) {
  const envelopePrefix = overrides.envelope_prefix || 's';
  const actionPrefix = overrides.action_prefix || 'u';
  const envelopeNamespace = overrides.envelope_namespace ||
    'http://schemas.xmlsoap.org/soap/envelope/';
  const encoding = overrides.encoding ||
    'http://schemas.xmlsoap.org/soap/encoding/';
  const actionNamespace = overrides.action_namespace || service;
  return Buffer.from(
    '<?xml version="1.0"?>\r\n' +
    `<${envelopePrefix}:Envelope ` +
    `xmlns:${envelopePrefix}="${envelopeNamespace}" ` +
    `${envelopePrefix}:encodingStyle="${encoding}">` +
    `<${envelopePrefix}:Body>` +
    `<${actionPrefix}:${action} ` +
    `xmlns:${actionPrefix}="${actionNamespace}">` +
    `</${actionPrefix}:${action}>` +
    `</${envelopePrefix}:Body></${envelopePrefix}:Envelope>\r\n`,
    'utf8');
}

function command(action) {
  return decodeUpnpSoapQuery(`"${service}#${action}"`, body(action));
}

test('E04: decodes miniupnpc GetExternalIPAddress and GetStatusInfo', () => {
  assert.deepEqual(command('GetExternalIPAddress'), {
    protocol: 'upnp',
    operation: 'get_external_ip_address',
    service_type: service,
  });
  assert.deepEqual(decodeUpnpSoapQuery(
    `"${service}#GetStatusInfo"`,
    body('GetStatusInfo', {
      envelope_prefix: 'SOAP-ENV',
      action_prefix: 'm',
    })), {
    protocol: 'upnp',
    operation: 'get_status_info',
    service_type: service,
  });
});

test('E04: public, RFC1918 and CGNAT IPv4 are reported exactly', () => {
  const query = command('GetExternalIPAddress');
  for (const address of ['88.11.22.4', '192.168.1.20', '100.64.12.34']) {
    const response = encodeUpnpSoapQueryResponse(query, {
      ok: true,
      external_address: address,
    });
    assert.equal(response.status_code, 200);
    assert.match(response.body.toString('utf8'),
      new RegExp(`<NewExternalIPAddress>${address.replaceAll('.', '\\.')}`));
    assert.match(response.body.toString('utf8'),
      /GetExternalIPAddressResponse/);
  }
});

test('E04: an empty external address remains an explicit successful value', () => {
  const response = encodeUpnpSoapQueryResponse(
    command('GetExternalIPAddress'),
    { ok: true, external_address: '' });
  assert.equal(response.status_code, 200);
  assert.match(response.body.toString('utf8'),
    /<NewExternalIPAddress><\/NewExternalIPAddress>/);
});

test('E04: GetStatusInfo returns the fields miniupnpc requires', () => {
  const response = encodeUpnpSoapQueryResponse(command('GetStatusInfo'), {
    ok: true,
    connection_status: 'Connected',
    last_connection_error: 'ERROR_NONE',
    uptime_seconds: 42,
  });
  assert.equal(response.status_code, 200);
  const xml = response.body.toString('utf8');
  assert.match(xml,
    /<NewConnectionStatus>Connected<\/NewConnectionStatus>/);
  assert.match(xml,
    /<NewLastConnectionError>ERROR_NONE<\/NewLastConnectionError>/);
  assert.match(xml, /<NewUptime>42<\/NewUptime>/);
});

test('E04: GetStatusInfo accepts exactly the WANIPConnection v1 vocabularies', () => {
  const query = command('GetStatusInfo');
  const statuses = [
    'Unconfigured', 'Connecting', 'Connected', 'PendingDisconnect',
    'Disconnecting', 'Disconnected',
  ];
  const errors = [
    'ERROR_NONE', 'ERROR_COMMAND_ABORTED',
    'ERROR_NOT_ENABLED_FOR_INTERNET', 'ERROR_USER_DISCONNECT',
    'ERROR_ISP_DISCONNECT', 'ERROR_IDLE_DISCONNECT',
    'ERROR_FORCED_DISCONNECT', 'ERROR_NO_CARRIER',
    'ERROR_IP_CONFIGURATION', 'ERROR_UNKNOWN',
  ];
  for (const connection_status of statuses) {
    const response = encodeUpnpSoapQueryResponse(query, {
      ok: true,
      connection_status,
      last_connection_error: 'ERROR_NONE',
      uptime_seconds: 0,
    });
    assert.match(response.body.toString('utf8'),
      new RegExp(`<NewConnectionStatus>${connection_status}`));
  }
  for (const last_connection_error of errors) {
    const response = encodeUpnpSoapQueryResponse(query, {
      ok: true,
      connection_status: 'Disconnected',
      last_connection_error,
      uptime_seconds: 0xffffffff,
    });
    assert.match(response.body.toString('utf8'),
      new RegExp(`<NewLastConnectionError>${last_connection_error}`));
  }
});

test('E04: SOAP fault uses HTTP 500 and the UPnP error contract', () => {
  for (const action of ['GetExternalIPAddress', 'GetStatusInfo']) {
    const response = encodeUpnpSoapQueryResponse(command(action), {
      ok: false,
      error_code: 501,
      error_description: 'Action Failed',
    });
    assert.equal(response.status_code, 500);
    const xml = response.body.toString('utf8');
    assert.match(xml, /<s:Fault>/);
    assert.match(xml, /<errorCode>501<\/errorCode>/);
    assert.match(xml,
      /<errorDescription>Action Failed<\/errorDescription>/);
  }
});

test('E04: action header, body action and namespaces must agree exactly', () => {
  for (const [soapAction, packet] of [
    [null, body('GetExternalIPAddress')],
    [`"${service}#GetExternalIPAddress"\r\nX: bad`,
      body('GetExternalIPAddress')],
    [`"${'x'.repeat(161)}"`, body('GetExternalIPAddress')],
    [`${service}#GetExternalIPAddress`,
      body('GetExternalIPAddress')],
    [`"${service}#Unknown"`, body('GetExternalIPAddress')],
    [`"${service}:2#GetExternalIPAddress"`,
      body('GetExternalIPAddress')],
    [`"${service}#GetExternalIPAddress"`, body('GetStatusInfo')],
    [`"${service}#GetExternalIPAddress"`,
      body('GetExternalIPAddress', { envelope_namespace: 'bad' })],
    [`"${service}#GetExternalIPAddress"`,
      body('GetExternalIPAddress', { encoding: 'bad' })],
    [`"${service}#GetExternalIPAddress"`,
      body('GetExternalIPAddress', { action_namespace: `${service}:2` })],
    [`"${service}#GetExternalIPAddress"`,
      body('GetExternalIPAddress', {
        envelope_prefix: 'x',
        action_prefix: 'x',
      })],
    [`"${service}#GetExternalIPAddress"`,
      Buffer.from(body('GetExternalIPAddress').toString('utf8').replace(
        'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"',
        'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:s="x"'))],
    [`"${service}#GetExternalIPAddress"`,
      Buffer.from(body('GetExternalIPAddress').toString('utf8').replace(
        's:encodingStyle=', 'bad s:encodingStyle='))],
  ]) {
    assert.throws(() => decodeUpnpSoapQuery(soapAction, packet),
      UpnpSoapBoundaryError);
  }
});

test('E04: malformed, active and hostile XML input fails closed', () => {
  const valid = body('GetExternalIPAddress');
  const detached = new Uint8Array(valid);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  const proxy = new Proxy(valid, {
    get() { throw new Error('must not execute'); },
  });
  const hostile = [
    null,
    '',
    Buffer.alloc(0),
    Buffer.alloc(8193),
    detached,
    new Uint8Array(new SharedArrayBuffer(8)),
    proxy,
    Buffer.from([0xff]),
    Buffer.from(valid.toString('utf8').replace(
      '<s:Body>', '<!DOCTYPE x><s:Body>')),
    Buffer.from(valid.toString('utf8').replace(
      '</u:GetExternalIPAddress>',
      '&entity;</u:GetExternalIPAddress>')),
    Buffer.from(valid.toString('utf8').replace(
      '<u:GetExternalIPAddress',
      '<u:GetExternalIPAddress extra="yes"')),
    Buffer.from(valid.toString('utf8').replace(
      '</u:GetExternalIPAddress>', '<x/></u:GetExternalIPAddress>')),
  ];
  for (const packet of hostile) {
    assert.throws(() => decodeUpnpSoapQuery(
      `"${service}#GetExternalIPAddress"`, packet),
    UpnpSoapBoundaryError);
  }
});

test('E04: semantic results and command boundary reject open shapes', () => {
  const external = command('GetExternalIPAddress');
  const status = command('GetStatusInfo');
  const accessor = { ok: true };
  Object.defineProperty(accessor, 'external_address', {
    enumerable: true,
    get() { throw new Error('must not execute'); },
  });
  for (const result of [
    null,
    {},
    { ok: true, external_address: '::1' },
    { ok: true, external_address: '999.1.1.1' },
    { ok: true, external_address: '1.2.3.4', extra: true },
    { ok: false, error_code: 399, error_description: 'bad' },
    { ok: false, error_code: 501, error_description: '<inject>' },
    accessor,
    new Proxy({}, {}),
  ]) {
    assert.throws(() => encodeUpnpSoapQueryResponse(external, result),
      UpnpSoapBoundaryError);
  }
  for (const result of [
    { ok: true, connection_status: 'Up',
      last_connection_error: 'ERROR_NONE', uptime_seconds: 1 },
    { ok: true, connection_status: 'Authenticating',
      last_connection_error: 'ERROR_NONE', uptime_seconds: 1 },
    { ok: true, connection_status: 'Connected',
      last_connection_error: 'ERROR_OTHER', uptime_seconds: 1 },
    { ok: true, connection_status: 'Connected',
      last_connection_error: 'ERROR_NONE', uptime_seconds: -1 },
  ]) {
    assert.throws(() => encodeUpnpSoapQueryResponse(status, result),
      UpnpSoapBoundaryError);
  }
  assert.throws(() => encodeUpnpSoapQueryResponse({
    protocol: 'upnp',
    operation: 'get_external_ip_address',
    service_type: service,
  }, { ok: true, external_address: '1.2.3.4' }),
  UpnpSoapBoundaryError);
});
