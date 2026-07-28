'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  UpnpDescriptionBoundaryError,
  encodeUpnpDeviceDescription,
  encodeUpnpServiceDescription,
  encodeUpnpWanCommonInterfaceConfigDescription,
} = require('../upnp_description_http');

function config(overrides = {}) {
  return {
    adapter_address: '192.0.2.10',
    http_port: 5000,
    igd_version: 1,
    service_version: 1,
    udn_uuid: 'uuid:12345678-1234-1234-1234-123456789abc',
    wan_device_uuid: 'uuid:22345678-1234-1234-1234-123456789abc',
    wan_connection_device_uuid:
      'uuid:32345678-1234-1234-1234-123456789abc',
    cif_scpd_path: '/wancommonifcSCPD.xml',
    cif_control_path: '/control/WANCommonIFC1',
    cif_event_sub_path: null,
    scpd_path: '/wanipconnSCPD.xml',
    control_path: '/control/WANIPConn1',
    event_sub_path: '/event/WANIPConn1',
    ...overrides,
  };
}

function assertFixedXmlIsWellFormed(xml) {
  assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>\n/);
  const stack = [];
  const tags = xml.match(/<[^>]+>/g);
  assert.ok(tags);
  for (const token of tags.slice(1)) {
    if (/^<\//.test(token)) {
      const name = token.slice(2, -1);
      assert.equal(stack.pop(), name);
    } else if (!/^<\?/.test(token) && !/\/>$/.test(token)) {
      stack.push(token.slice(1, -1).split(/[ >]/, 1)[0]);
    }
  }
  assert.deepEqual(stack, []);
}

test('E03: device XML is well formed and exposes the configured IGD service', () => {
  const output = encodeUpnpDeviceDescription(config());
  const xml = output.toString('utf8');
  assertFixedXmlIsWellFormed(xml);
  assert.match(xml,
    /<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1<\/deviceType>/);
  assert.match(xml,
    /InternetGatewayDevice:1[\s\S]*<deviceList>\n<device>[\s\S]*WANDevice:1[\s\S]*<deviceList>\n<device>[\s\S]*WANConnectionDevice:1[\s\S]*<serviceList>\n<service>[\s\S]*WANIPConnection:1/);
  assert.match(xml,
    /<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1<\/serviceType>/);
  assert.match(xml,
    /<controlURL>\/control\/WANIPConn1<\/controlURL>/);
  assert.match(xml,
    /<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1<\/serviceType>/);
  assert.match(xml,
    /<controlURL>\/control\/WANCommonIFC1<\/controlURL>/);
  assert.match(xml,
    /<SCPDURL>\/wancommonifcSCPD\.xml<\/SCPDURL>/);
  assert.match(xml,
    /<eventSubURL>\/event\/WANIPConn1<\/eventSubURL>/);
  assert.match(xml,
    /<URLBase>http:\/\/192\.0\.2\.10:5000\/<\/URLBase>/);
  assert.ok(Buffer.isBuffer(output));
});

test('E03: eventSubURL is absent when the service declares no event endpoint', () => {
  const xml = encodeUpnpDeviceDescription(
    config({ event_sub_path: null })).toString('utf8');
  assertFixedXmlIsWellFormed(xml);
  assert.doesNotMatch(xml, /eventSubURL/);
  assert.match(xml, /<SCPDURL>\/wanipconnSCPD\.xml<\/SCPDURL>/);
});

test('E03: IPv6 URLBase retains its adapter zone in the supported v1 profile', () => {
  const xml = encodeUpnpDeviceDescription(config({
    adapter_address: 'fe80::1%Ethernet-2',
  })).toString('utf8');
  assert.match(xml,
    /<URLBase>http:\/\/\[fe80::1%25Ethernet-2\]:5000\/<\/URLBase>/);
  assert.match(xml, /InternetGatewayDevice:1/);
  assert.match(xml, /WANIPConnection:1/);
});

test('E03: service XML is well formed and declares the later control actions', () => {
  const output = encodeUpnpServiceDescription({ service_version: 1 });
  const xml = output.toString('utf8');
  assertFixedXmlIsWellFormed(xml);
  for (const action of [
    'GetExternalIPAddress',
    'AddPortMapping',
    'DeletePortMapping',
    'GetSpecificPortMappingEntry',
    'GetGenericPortMappingEntry',
  ]) {
    assert.match(xml, new RegExp(`<name>${action}</name>`));
  }
  assert.match(xml, /<serviceStateTable>/);
  const actionBlocks = new Map(
    [...xml.matchAll(/<action><name>([^<]+)<\/name>([\s\S]*?)<\/action>/g)]
      .map((match) => [match[1], match[2]]));
  const contracts = {
    GetStatusInfo: [
      ['NewConnectionStatus', 'out', 'ConnectionStatus'],
      ['NewLastConnectionError', 'out', 'LastConnectionError'],
      ['NewUptime', 'out', 'Uptime'],
    ],
    GetExternalIPAddress: [
      ['NewExternalIPAddress', 'out', 'ExternalIPAddress'],
    ],
    AddPortMapping: [
      ['NewRemoteHost', 'in', 'RemoteHost'],
      ['NewExternalPort', 'in', 'ExternalPort'],
      ['NewProtocol', 'in', 'PortMappingProtocol'],
      ['NewInternalPort', 'in', 'InternalPort'],
      ['NewInternalClient', 'in', 'InternalClient'],
      ['NewEnabled', 'in', 'PortMappingEnabled'],
      ['NewPortMappingDescription', 'in', 'PortMappingDescription'],
      ['NewLeaseDuration', 'in', 'PortMappingLeaseDuration'],
    ],
    DeletePortMapping: [
      ['NewRemoteHost', 'in', 'RemoteHost'],
      ['NewExternalPort', 'in', 'ExternalPort'],
      ['NewProtocol', 'in', 'PortMappingProtocol'],
    ],
    GetSpecificPortMappingEntry: [
      ['NewRemoteHost', 'in', 'RemoteHost'],
      ['NewExternalPort', 'in', 'ExternalPort'],
      ['NewProtocol', 'in', 'PortMappingProtocol'],
      ['NewInternalPort', 'out', 'InternalPort'],
      ['NewInternalClient', 'out', 'InternalClient'],
      ['NewEnabled', 'out', 'PortMappingEnabled'],
      ['NewPortMappingDescription', 'out', 'PortMappingDescription'],
      ['NewLeaseDuration', 'out', 'PortMappingLeaseDuration'],
    ],
    GetGenericPortMappingEntry: [
      ['NewPortMappingIndex', 'in', 'PortMappingNumberOfEntries'],
      ['NewRemoteHost', 'out', 'RemoteHost'],
      ['NewExternalPort', 'out', 'ExternalPort'],
      ['NewProtocol', 'out', 'PortMappingProtocol'],
      ['NewInternalPort', 'out', 'InternalPort'],
      ['NewInternalClient', 'out', 'InternalClient'],
      ['NewEnabled', 'out', 'PortMappingEnabled'],
      ['NewPortMappingDescription', 'out', 'PortMappingDescription'],
      ['NewLeaseDuration', 'out', 'PortMappingLeaseDuration'],
    ],
  };
  for (const [action, argumentsExpected] of Object.entries(contracts)) {
    const block = actionBlocks.get(action);
    assert.ok(block, `missing action ${action}`);
    for (const [name, direction, related] of argumentsExpected) {
      assert.match(block, new RegExp(
        `<argument><name>${name}</name><direction>${direction}</direction>` +
        `<relatedStateVariable>${related}</relatedStateVariable></argument>`));
    }
  }
  const stateNames = new Set(
    [...xml.matchAll(/<stateVariable[^>]*><name>([^<]+)<\/name>/g)]
      .map((match) => match[1]));
  for (const block of actionBlocks.values()) {
    for (const match of block.matchAll(
      /<relatedStateVariable>([^<]+)<\/relatedStateVariable>/g)) {
      assert.ok(stateNames.has(match[1]),
        `missing related state variable ${match[1]}`);
    }
  }
  assert.match(xml,
    /<allowedValue>TCP<\/allowedValue><allowedValue>UDP<\/allowedValue>/);
  function allowedValuesFor(stateName) {
    const match = new RegExp(
      `<stateVariable[^>]*><name>${stateName}</name>` +
      '<dataType>string</dataType><allowedValueList>' +
      '([\\s\\S]*?)</allowedValueList></stateVariable>')
      .exec(xml);
    assert.ok(match, `missing state ${stateName}`);
    return [...match[1].matchAll(
      /<allowedValue>([^<]+)<\/allowedValue>/g)]
      .map((value) => value[1]);
  }
  assert.deepEqual(allowedValuesFor('ConnectionStatus'), [
    'Unconfigured', 'Connecting', 'Connected', 'PendingDisconnect',
    'Disconnecting', 'Disconnected',
  ]);
  assert.deepEqual(allowedValuesFor('LastConnectionError'), [
    'ERROR_NONE', 'ERROR_COMMAND_ABORTED',
    'ERROR_NOT_ENABLED_FOR_INTERNET', 'ERROR_USER_DISCONNECT',
    'ERROR_ISP_DISCONNECT', 'ERROR_IDLE_DISCONNECT',
    'ERROR_FORCED_DISCONNECT', 'ERROR_NO_CARRIER',
    'ERROR_IP_CONFIGURATION', 'ERROR_UNKNOWN',
  ]);
  assert.ok(Buffer.isBuffer(output));
});

test('E03: WANCommonInterfaceConfig SCPD exposes a typed link contract', () => {
  const output = encodeUpnpWanCommonInterfaceConfigDescription({
    service_version: 1,
  });
  const xml = output.toString('utf8');
  assertFixedXmlIsWellFormed(xml);
  const expected = [
    ['NewWANAccessType', 'WANAccessType'],
    ['NewLayer1UpstreamMaxBitRate', 'Layer1UpstreamMaxBitRate'],
    ['NewLayer1DownstreamMaxBitRate', 'Layer1DownstreamMaxBitRate'],
    ['NewPhysicalLinkStatus', 'PhysicalLinkStatus'],
  ];
  assert.match(xml, /<name>GetCommonLinkProperties<\/name>/);
  for (const [argument, related] of expected) {
    assert.match(xml, new RegExp(
      `<argument><name>${argument}</name><direction>out</direction>` +
      `<relatedStateVariable>${related}</relatedStateVariable></argument>`));
    assert.match(xml, new RegExp(
      `<stateVariable[^>]*><name>${related}</name>`));
  }
  assert.ok(Buffer.isBuffer(output));
});

test('E03: device config rejects injection, unsafe adapters and open shapes', () => {
  const accessor = config();
  Object.defineProperty(accessor, 'control_path', {
    enumerable: true,
    get() { throw new Error('must not execute'); },
  });
  for (const broken of [
    null,
    {},
    config({ extra: true }),
    config({ adapter_address: 123 }),
    config({ adapter_address: '0.0.0.0' }),
    config({ adapter_address: '127.0.0.1' }),
    config({ adapter_address: '224.0.0.1' }),
    config({ adapter_address: '255.255.255.255' }),
    config({ adapter_address: '::' }),
    config({ adapter_address: '::1' }),
    config({ adapter_address: 'ff02::c' }),
    config({ adapter_address: 'fe80::1' }),
    config({ http_port: 0 }),
    config({ igd_version: 3 }),
    config({ igd_version: 1, service_version: 2 }),
    config({ igd_version: 2, service_version: 1 }),
    config({ service_version: 0 }),
    config({ udn_uuid: 'uuid:bad' }),
    config({ wan_device_uuid:
      'uuid:12345678-1234-1234-1234-123456789abc' }),
    config({ wan_connection_device_uuid: 'uuid:bad' }),
    config({ cif_scpd_path: '/bad\nINJECT' }),
    config({ cif_control_path: '' }),
    config({ cif_event_sub_path: '/bad</eventSubURL>' }),
    config({ scpd_path: '/bad\nINJECT' }),
    config({ control_path: '/bad</controlURL>' }),
    config({ event_sub_path: '' }),
    accessor,
    new Proxy({}, {}),
  ]) {
    assert.throws(() => encodeUpnpDeviceDescription(broken),
      UpnpDescriptionBoundaryError);
  }
});

test('E03: service config is closed and data-only', () => {
  const accessor = {};
  Object.defineProperty(accessor, 'service_version', {
    enumerable: true,
    get() { throw new Error('must not execute'); },
  });
  for (const broken of [
    null,
    {},
    { service_version: 0 },
    { service_version: 2 },
    { service_version: 1, extra: true },
    accessor,
    new Proxy({}, {}),
  ]) {
    assert.throws(() => encodeUpnpServiceDescription(broken),
      UpnpDescriptionBoundaryError);
    assert.throws(() =>
      encodeUpnpWanCommonInterfaceConfigDescription(broken),
    UpnpDescriptionBoundaryError);
  }
});
