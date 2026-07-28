'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createMappingState } = require('../mapping_model');
const {
  UpnpSoapBoundaryError,
  decodeUpnpPortMappingReadback,
  encodeUpnpSoapQueryResponse,
} = require('../upnp_soap_control');
const {
  UpnpMappingReadbackError,
  projectUpnpReadbackSoapResult,
  readUpnpPortMapping,
} = require('../upnp_mapping_readback');

const service =
  'urn:schemas-upnp-org:service:WANIPConnection:1';
const digestA = 'a'.repeat(64);
const digestB = 'b'.repeat(64);

function body(action, values) {
  const argumentsXml = Object.entries(values)
    .map(([name, value]) => `<${name}>${value}</${name}>`).join('');
  return Buffer.from(
    '<?xml version="1.0"?>' +
    '<s:Envelope ' +
    'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    `<s:Body><u:${action} xmlns:u="${service}">` +
    `${argumentsXml}</u:${action}></s:Body></s:Envelope>`);
}

function decodeSpecific(overrides = {}) {
  return decodeUpnpPortMappingReadback(
    `"${service}#GetSpecificPortMappingEntry"`,
    body('GetSpecificPortMappingEntry', {
      NewRemoteHost: '',
      NewExternalPort: '4662',
      NewProtocol: 'TCP',
      ...overrides,
    }));
}

function decodeGeneric(index = '0') {
  return decodeUpnpPortMappingReadback(
    `"${service}#GetGenericPortMappingEntry"`,
    body('GetGenericPortMappingEntry', {
      NewPortMappingIndex: index,
    }));
}

function mapping(overrides = {}) {
  return {
    mapping_id: 'upnp.tcp.4662',
    protocol: 'upnp',
    transport: 'tcp',
    client_id: 'miniupnpc.client',
    internal_address: '192.168.1.20',
    internal_port: 4662,
    requested_external_port: 4662,
    external_address: '100.64.12.34',
    external_port: 4662,
    lease: {
      lifetime_seconds: 0,
      created_monotonic_ms: 1000,
      expires_monotonic_ms: null,
    },
    owner: {
      kind: 'upnp-journal',
      instance_id_digest: digestB,
      gateway_identity_digest: digestA,
      description: 'eMule TCP',
    },
    epoch: 17,
    generation: 3,
    ...overrides,
  };
}

function state(mappings = [mapping()]) {
  return createMappingState({
    epoch: 17,
    generation: 3,
    mappings,
  });
}

function context(overrides = {}) {
  return {
    readback: 'full',
    gateway_external_address: '100.64.12.34',
    now_monotonic_ms: 2000,
    description_limit: 64,
    ...overrides,
  };
}

test('E06: decodes exact specific and generic miniupnpc requests', () => {
  assert.deepEqual(decodeSpecific(), {
    protocol: 'upnp',
    operation: 'get_specific_port_mapping_entry',
    service_type: service,
    remote_host: '',
    external_port: 4662,
    transport: 'tcp',
  });
  assert.deepEqual(decodeGeneric('65535'), {
    protocol: 'upnp',
    operation: 'get_generic_port_mapping_entry',
    service_type: service,
    index: 65535,
  });
});

test('E06: specific readback returns the complete miniupnpc shape', () => {
  const command = decodeSpecific();
  const result = readUpnpPortMapping(state(), command, context());
  assert.equal(result.ok, true);
  assert.equal(Object.isFrozen(result.entry), true);
  const response = encodeUpnpSoapQueryResponse(
    command, projectUpnpReadbackSoapResult(result));
  assert.equal(response.status_code, 200);
  const xml = response.body.toString();
  assert.match(xml, /GetSpecificPortMappingEntryResponse/);
  assert.match(xml, /<NewInternalPort>4662<\/NewInternalPort>/);
  assert.match(xml,
    /<NewInternalClient>192\.168\.1\.20<\/NewInternalClient>/);
  assert.match(xml, /<NewEnabled>1<\/NewEnabled>/);
  assert.match(xml,
    /<NewPortMappingDescription>eMule TCP<\/NewPortMappingDescription>/);
  assert.match(xml, /<NewLeaseDuration>0<\/NewLeaseDuration>/);
});

test('E06: generic enumeration is deterministic across TCP and UDP', () => {
  const udp = mapping({
    mapping_id: 'upnp.udp.4662',
    transport: 'udp',
    internal_port: 4672,
    owner: {
      kind: 'upnp-journal',
      instance_id_digest: digestB,
      gateway_identity_digest: digestA,
      description: 'eMule UDP',
    },
  });
  const current = state([udp, mapping()]);
  const first = readUpnpPortMapping(current, decodeGeneric('0'), context());
  const second = readUpnpPortMapping(current, decodeGeneric('1'), context());
  assert.equal(first.entry.transport, 'tcp');
  assert.equal(second.entry.transport, 'udp');
  const response = encodeUpnpSoapQueryResponse(
    decodeGeneric('1'), projectUpnpReadbackSoapResult(second));
  const xml = response.body.toString();
  assert.match(xml, /<NewRemoteHost><\/NewRemoteHost>/);
  assert.match(xml, /<NewExternalPort>4662<\/NewExternalPort>/);
  assert.match(xml, /<NewProtocol>UDP<\/NewProtocol>/);
});

test('E06: missing specific and exhausted generic use exact UPnP faults', () => {
  for (const [command, code, description] of [
    [decodeSpecific({ NewExternalPort: '9999' }),
      714, 'NoSuchEntryInArray'],
    [decodeGeneric('1'), 713, 'SpecifiedArrayIndexInvalid'],
  ]) {
    const result = readUpnpPortMapping(state(), command, context());
    assert.equal(result.ok, false);
    assert.equal(result.error_code, code);
    const response = encodeUpnpSoapQueryResponse(
      command, projectUpnpReadbackSoapResult(result));
    assert.equal(response.status_code, 500);
    assert.match(response.body.toString(),
      new RegExp(`<errorCode>${code}</errorCode>`));
    assert.match(response.body.toString(), new RegExp(description));
  }
});

test('E06: unsupported router mode rejects both readback actions', () => {
  for (const command of [decodeSpecific(), decodeGeneric()]) {
    const result = readUpnpPortMapping(
      state(), command, context({ readback: 'unsupported' }));
    assert.equal(result.ok, false);
    assert.equal(result.error_code, 501);
    assert.equal(result.error_description, 'Action Failed');
  }
});

test('E06: descriptions are truncated safely before XML escaping', () => {
  const current = state([mapping({
    owner: {
      kind: 'upnp-journal',
      instance_id_digest: digestB,
      gateway_identity_digest: digestA,
      description: 'abc<def&ghi',
    },
  })]);
  const command = decodeSpecific();
  const result = readUpnpPortMapping(
    current, command, context({ description_limit: 5 }));
  assert.equal(result.entry.description, 'abc<d');
  const xml = encodeUpnpSoapQueryResponse(
    command, projectUpnpReadbackSoapResult(result)).body.toString();
  assert.match(xml,
    /<NewPortMappingDescription>abc&lt;d<\/NewPortMappingDescription>/);
  assert.doesNotMatch(xml, /abc<d/);
});

test('E06: finite leases report remaining time and expire at deadline', () => {
  const finite = mapping({
    protocol: 'pcp',
    lease: {
      lifetime_seconds: 3,
      created_monotonic_ms: 0,
      expires_monotonic_ms: 3000,
    },
    owner: {
      kind: 'pcp-nonce',
      instance_id_digest: digestB,
      nonce: '1'.repeat(24),
    },
  });
  const before = readUpnpPortMapping(
    state([finite]), decodeSpecific(), context({ now_monotonic_ms: 1001 }));
  assert.equal(before.entry.lease_seconds, 2);
  assert.equal(before.entry.description, 'PCP mapping');
  const atDeadline = readUpnpPortMapping(
    state([finite]), decodeSpecific(), context({ now_monotonic_ms: 3000 }));
  assert.equal(atDeadline.ok, false);
  assert.equal(atDeadline.error_code, 714);
  assert.equal(atDeadline.state.mappings.length, 0);
});

test('E06: malformed arguments, action mismatch and hostile storage fail closed',
  () => {
    const valid = body('GetGenericPortMappingEntry', {
      NewPortMappingIndex: '0',
    });
    for (const [header, packet] of [
      [`"${service}#GetSpecificPortMappingEntry"`, valid],
      [`"${service}#DeletePortMapping"`,
        body('DeletePortMapping', {
          NewRemoteHost: '',
          NewExternalPort: '4662',
          NewProtocol: 'TCP',
        })],
      [`"${service}#GetGenericPortMappingEntry"`,
        body('GetGenericPortMappingEntry', {
          NewPortMappingIndex: '65536',
        })],
      [`"${service}#GetGenericPortMappingEntry"`,
        body('GetGenericPortMappingEntry', {
          NewPortMappingIndex: '-0',
        })],
      [`"${service}#GetSpecificPortMappingEntry"`,
        body('GetSpecificPortMappingEntry', {
          NewRemoteHost: '203.0.113.1',
          NewExternalPort: '4662',
          NewProtocol: 'TCP',
        })],
      [`"${service}#GetSpecificPortMappingEntry"`,
        body('GetSpecificPortMappingEntry', {
          NewRemoteHost: '',
          NewExternalPort: '4662',
          NewProtocol: 'SCTP',
        })],
      [null, valid],
      [{ toString() { throw new Error('must not execute'); } }, valid],
      [`"${service}#GetGenericPortMappingEntry"`, Buffer.alloc(0)],
      [`"${service}#GetGenericPortMappingEntry"`,
        new Uint8Array(new SharedArrayBuffer(8))],
      [`"${service}#GetGenericPortMappingEntry"`, new Proxy(valid, {})],
      [`"${service}#GetGenericPortMappingEntry"`,
        Buffer.from(valid.toString().replace(
          '<NewPortMappingIndex>0',
          '<NewPortMappingIndex>&x;'))],
    ]) {
      assert.throws(() => decodeUpnpPortMappingReadback(header, packet),
        UpnpSoapBoundaryError);
    }
  });

test('E06: command, context, state and result boundaries reject forgery', () => {
  const command = decodeSpecific();
  const validContext = context();
  for (const badCommand of [
    null,
    { ...command, extra: true },
    { ...command, external_port: 0 },
    new Proxy(command, {}),
  ]) {
    assert.throws(() => readUpnpPortMapping(
      state(), badCommand, validContext), UpnpMappingReadbackError);
  }
  for (const badContext of [
    null,
    { ...validContext, extra: true },
    { ...validContext, readback: 'partial' },
    { ...validContext, now_monotonic_ms: -0 },
    { ...validContext, description_limit: 0 },
    new Proxy(validContext, {}),
  ]) {
    assert.throws(() => readUpnpPortMapping(
      state(), command, badContext), UpnpMappingReadbackError);
  }
  assert.throws(() => readUpnpPortMapping(
    { epoch: 17, generation: 3, mappings: [] },
    command, validContext), UpnpMappingReadbackError);
  assert.throws(() => projectUpnpReadbackSoapResult({
    ok: true,
    entry: {},
  }), UpnpMappingReadbackError);
});

test('E06: response encoder rejects open or invalid semantic fields', () => {
  const command = decodeSpecific();
  for (const result of [
    null,
    { ok: true, internal_port: 4662, internal_client: '192.168.1.20',
      enabled: true, description: 'ok', lease_seconds: 0, extra: true },
    { ok: true, internal_port: 0, internal_client: '192.168.1.20',
      enabled: true, description: 'ok', lease_seconds: 0 },
    { ok: true, internal_port: 4662, internal_client: '::1',
      enabled: true, description: 'ok', lease_seconds: 0 },
    { ok: true, internal_port: 4662, internal_client: '192.168.1.20',
      enabled: true, description: '\0', lease_seconds: 0 },
    { ok: true, internal_port: 4662, internal_client: '192.168.1.20',
      enabled: true, description: 'ok', lease_seconds: -0 },
  ]) {
    assert.throws(() => encodeUpnpSoapQueryResponse(command, result),
      UpnpSoapBoundaryError);
  }
});
