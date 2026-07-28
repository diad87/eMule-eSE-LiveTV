'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  UpnpSsdpBoundaryError,
  decodeUpnpMSearch,
  encodeUpnpMSearchResponse,
} = require('../upnp_ssdp_discovery');

const target =
  'urn:schemas-upnp-org:device:InternetGatewayDevice:1';
function request(overrides = {}) {
  const fields = {
    host: '239.255.255.250:1900',
    man: '"ssdp:discover"',
    mx: '2',
    st: target,
    ...overrides,
  };
  const lines = ['M-SEARCH * HTTP/1.1'];
  for (const [name, value] of Object.entries(fields)) {
    if (value !== null) lines.push(`${name.toUpperCase()}: ${value}`);
  }
  return Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'ascii');
}
function config(searchTarget = target) {
  return { search_target: searchTarget };
}
function responseConfig(overrides = {}) {
  return {
    adapter_address: '192.0.2.10',
    http_port: 5000,
    description_path: '/rootDesc.xml',
    usn_uuid: 'uuid:12345678-1234-1234-1234-123456789abc',
    max_age_seconds: 1800,
    ...overrides,
  };
}

test('E02: decodes a valid M-SEARCH with case-insensitive header names', () => {
  const packet = request({ 'user-agent': 'test/1.0' });
  const command = decodeUpnpMSearch(packet, config());
  assert.deepEqual(command, {
    protocol: 'upnp',
    operation: 'discover',
    search_target: target,
    mx_seconds: 2,
  });
  assert.ok(Object.isFrozen(command));
  assert.equal(packet.toString('ascii').startsWith('M-SEARCH'), true);
});

test('E02: missing MAN and an incorrect ST fail with stable reasons', () => {
  assert.throws(() => decodeUpnpMSearch(
    request({ man: null }), config()),
  (error) => error instanceof UpnpSsdpBoundaryError &&
    error.reason_code === 'UPNP_SSDP_MAN_REQUIRED' &&
    error.field_path === '$.headers.man');
  assert.throws(() => decodeUpnpMSearch(
    request({ st: 'urn:schemas-upnp-org:device:MediaRenderer:1' }),
    config()),
  (error) => error instanceof UpnpSsdpBoundaryError &&
    error.reason_code === 'UPNP_SSDP_ST_UNSUPPORTED' &&
    error.field_path === '$.headers.st');
});

test('E02: response contains required SSDP fields and adapter-bound LOCATION', () => {
  const command = decodeUpnpMSearch(request(), config());
  const response = encodeUpnpMSearchResponse(command, responseConfig());
  const text = response.toString('ascii');
  assert.equal(text, [
    'HTTP/1.1 200 OK',
    'CACHE-CONTROL: max-age=1800',
    'EXT:',
    'LOCATION: http://192.0.2.10:5000/rootDesc.xml',
    'SERVER: eSE-T8/9.2 UPnP/2.0 eSE-IGD/9.2',
    `ST: ${target}`,
    `USN: uuid:12345678-1234-1234-1234-123456789abc::${target}`,
    '',
    '',
  ].join('\r\n'));
  assert.ok(Buffer.isBuffer(response));
});

test('E02: IPv6 adapter LOCATION is bracketed and IGD v2 target is preserved', () => {
  const targetV2 =
    'urn:schemas-upnp-org:device:InternetGatewayDevice:2';
  const command = decodeUpnpMSearch(
    request({ st: targetV2 }), config(targetV2));
  const response = encodeUpnpMSearchResponse(command,
    responseConfig({ adapter_address: '2001:db8::10' }));
  assert.match(response.toString('ascii'),
    /LOCATION: http:\/\/\[2001:db8::10\]:5000\/rootDesc\.xml\r\n/);
  assert.match(response.toString('ascii'), new RegExp(`ST: ${targetV2}`));
});

test('E02: MX values above five seconds are clamped as required by UDA', () => {
  assert.equal(
    decodeUpnpMSearch(request({ mx: '6' }), config()).mx_seconds,
    5);
  assert.equal(
    decodeUpnpMSearch(request({ mx: '999999999999999999999999' }),
      config()).mx_seconds,
    5);
});

test('E02: malformed request line, framing, headers, host and MX fail closed', () => {
  const body = Buffer.concat([request(), Buffer.from('body')]);
  const duplicate = Buffer.from(request().toString('ascii')
    .replace('HOST:', 'HOST: 239.255.255.250:1900\r\nHOST:'), 'ascii');
  const folded = Buffer.from(request().toString('ascii')
    .replace('MAN:', ' continuation\r\nMAN:'), 'ascii');
  const noColon = Buffer.from(request().toString('ascii')
    .replace('MX: 2', 'MX 2'), 'ascii');
  const nonAscii = request();
  nonAscii[5] = 0xff;
  const whitespaceBeforeColon = Buffer.from(request().toString('ascii')
    .replace('HOST:', 'HOST :'), 'ascii');
  const bareCarriageReturn = Buffer.from(request().toString('ascii')
    .replace('MX: 2', 'X-BAD: one\rX-GOOD: two\r\nMX: 2'), 'ascii');
  const bareLineFeed = Buffer.from(request().toString('ascii')
    .replace('MX: 2', 'X-BAD: one\nX-GOOD: two\r\nMX: 2'), 'ascii');
  for (const packet of [
    Buffer.from(request().toString('ascii')
      .replace('M-SEARCH', 'GET'), 'ascii'),
    Buffer.from(request().toString('ascii').replace(/\r\n\r\n$/, '\n\n'),
      'ascii'),
    body,
    duplicate,
    folded,
    noColon,
    whitespaceBeforeColon,
    bareCarriageReturn,
    bareLineFeed,
    request({ host: '127.0.0.1:1900' }),
    request({ mx: '0' }),
    nonAscii,
  ]) {
    assert.throws(() => decodeUpnpMSearch(packet, config()),
      UpnpSsdpBoundaryError);
  }
});

test('E02: wire and decode config boundaries reject hostile storage and shapes', () => {
  const detached = new Uint8Array(request());
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  const shared = new Uint8Array(new SharedArrayBuffer(8));
  const proxy = new Proxy(request(), {
    get() { throw new Error('must not execute'); },
  });
  for (const wire of [
    null,
    'M-SEARCH',
    Buffer.alloc(0),
    Buffer.alloc(2049),
    detached,
    shared,
    proxy,
  ]) {
    assert.throws(() => decodeUpnpMSearch(wire, config()),
      UpnpSsdpBoundaryError);
  }
  const accessor = {};
  Object.defineProperty(accessor, 'search_target', {
    enumerable: true,
    get() { throw new Error('must not execute'); },
  });
  for (const value of [
    null,
    {},
    { search_target: target, extra: true },
    { search_target: 'ssdp:all' },
    accessor,
    new Proxy({}, {}),
  ]) {
    assert.throws(() => decodeUpnpMSearch(request(), value),
      UpnpSsdpBoundaryError);
  }
});

test('E02: response config and semantic command are closed against injection', () => {
  const command = decodeUpnpMSearch(request(), config());
  const configAccessor = responseConfig();
  Object.defineProperty(configAccessor, 'http_port', {
    enumerable: true,
    get() { throw new Error('must not execute'); },
  });
  for (const broken of [
    null,
    {},
    responseConfig({ adapter_address: '0.0.0.0' }),
    responseConfig({ adapter_address: '::' }),
    responseConfig({ adapter_address: '127.0.0.1' }),
    responseConfig({ adapter_address: '224.0.0.1' }),
    responseConfig({ adapter_address: '255.255.255.255' }),
    responseConfig({ adapter_address: '::1' }),
    responseConfig({ adapter_address: 'ff02::c' }),
    responseConfig({ adapter_address: 'fe80::1' }),
    responseConfig({ adapter_address: 'bad' }),
    responseConfig({ http_port: 0 }),
    responseConfig({ http_port: 65536 }),
    responseConfig({ description_path: '/bad\r\nINJECT: yes' }),
    responseConfig({ usn_uuid: 'uuid:bad' }),
    responseConfig({ max_age_seconds: 0 }),
    responseConfig({ extra: true }),
    configAccessor,
    new Proxy({}, {}),
  ]) {
    assert.throws(() => encodeUpnpMSearchResponse(command, broken),
      UpnpSsdpBoundaryError);
  }
  const scoped = encodeUpnpMSearchResponse(command,
    responseConfig({ adapter_address: 'fe80::1%Ethernet-2' }));
  assert.match(scoped.toString('ascii'),
    /LOCATION: http:\/\/\[fe80::1%25Ethernet-2\]:5000\/rootDesc\.xml/);
  const commandAccessor = { ...command };
  Object.defineProperty(commandAccessor, 'mx_seconds', {
    enumerable: true,
    get() { throw new Error('must not execute'); },
  });
  for (const broken of [
    null,
    {},
    { ...command, extra: true },
    { ...command, protocol: 'pcp' },
    { ...command, search_target: `${target}\r\nINJECT: yes` },
    { ...command, mx_seconds: 0 },
    commandAccessor,
    new Proxy(command, {}),
  ]) {
    assert.throws(() => encodeUpnpMSearchResponse(broken, responseConfig()),
      UpnpSsdpBoundaryError);
  }
});
