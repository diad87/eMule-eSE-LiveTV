'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createMappingState } = require('../mapping_model');
const {
  UpnpSoapBoundaryError,
  decodeUpnpDeletePortMapping,
  encodeUpnpSoapQueryResponse,
} = require('../upnp_soap_control');
const {
  UpnpMappingDeleteError,
  applyUpnpDeletePortMapping,
  projectUpnpDeleteSoapResult,
} = require('../upnp_mapping_delete');

const service =
  'urn:schemas-upnp-org:service:WANIPConnection:1';
const digestA = 'a'.repeat(64);
const digestB = 'b'.repeat(64);

function body(overrides = {}) {
  const values = {
    NewRemoteHost: '',
    NewExternalPort: '4662',
    NewProtocol: 'TCP',
    ...overrides,
  };
  const args = Object.entries(values)
    .map(([name, value]) => `<${name}>${value}</${name}>`).join('');
  return Buffer.from(
    '<?xml version="1.0"?>' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    `<s:Body><u:DeletePortMapping xmlns:u="${service}">${args}` +
    '</u:DeletePortMapping></s:Body></s:Envelope>');
}

function actionBody(action, values) {
  const args = Object.entries(values)
    .map(([name, value]) => `<${name}>${value}</${name}>`).join('');
  return Buffer.from(
    '<?xml version="1.0"?>' +
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    `<s:Body><u:${action} xmlns:u="${service}">${args}` +
    `</u:${action}></s:Body></s:Envelope>`);
}

function decoded() {
  return decodeUpnpDeletePortMapping(
    `"${service}#DeletePortMapping"`, body());
}

function command(overrides = {}) {
  return { ...decoded(), ...overrides };
}

function mapping(overrides = {}) {
  return {
    mapping_id: 'upnp.tcp.4662',
    protocol: 'upnp',
    transport: 'tcp',
    client_id: 'client.one',
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
  return createMappingState({ epoch: 17, generation: 3, mappings });
}

function context(overrides = {}) {
  return {
    gateway_external_address: '100.64.12.34',
    now_monotonic_ms: 2000,
    ...overrides,
  };
}

test('E07: decodes and deletes an owned mapping with empty SOAP success', () => {
  const cmd = decoded();
  assert.deepEqual(cmd, {
    protocol: 'upnp',
    operation: 'delete_port_mapping',
    service_type: service,
    remote_host: '',
    external_port: 4662,
    transport: 'tcp',
  });
  const result = applyUpnpDeletePortMapping(state(), cmd, context());
  assert.equal(result.ok, true);
  assert.equal(result.state.mappings.length, 0);
  const response = encodeUpnpSoapQueryResponse(
    cmd, projectUpnpDeleteSoapResult(result));
  assert.equal(response.status_code, 200);
  assert.match(response.body.toString(), /DeletePortMappingResponse/);
});

test('E07: router operation can delete a foreign PCP mapping', () => {
  const foreign = mapping({
    mapping_id: 'pcp.tcp.4662',
    protocol: 'pcp',
    owner: {
      kind: 'pcp-nonce',
      instance_id_digest: digestB,
      nonce: '1'.repeat(24),
    },
  });
  const result = applyUpnpDeletePortMapping(
    state([foreign]), command(), context());
  assert.equal(result.ok, true);
  assert.equal(result.deleted_mapping_id, 'pcp.tcp.4662');
  assert.equal(result.state.mappings.length, 0);
});

test('E07: absent, different protocol and different port return 714', () => {
  for (const [current, cmd] of [
    [state([]), command()],
    [state(), command({ transport: 'udp' })],
    [state(), command({ external_port: 9999 })],
  ]) {
    const result = applyUpnpDeletePortMapping(current, cmd, context());
    assert.equal(result.ok, false);
    assert.equal(result.error_code, 714);
    assert.equal(result.error_description, 'NoSuchEntryInArray');
    assert.equal(result.state, current);
    const response = encodeUpnpSoapQueryResponse(
      decoded(), projectUpnpDeleteSoapResult(result));
    assert.equal(response.status_code, 500);
  }
});

test('E07: ownerless static and expired entries remain bounded', () => {
  const ownerless = state([mapping({ owner: { kind: 'none' } })]);
  const denied = applyUpnpDeletePortMapping(
    ownerless, command(), context());
  assert.equal(denied.error_code, 606);
  assert.equal(denied.state, ownerless);

  const expired = mapping({
    protocol: 'pcp',
    lease: {
      lifetime_seconds: 1,
      created_monotonic_ms: 0,
      expires_monotonic_ms: 1000,
    },
    owner: {
      kind: 'pcp-nonce',
      instance_id_digest: digestB,
      nonce: '2'.repeat(24),
    },
  });
  const absent = applyUpnpDeletePortMapping(
    state([expired]), command(), context());
  assert.equal(absent.error_code, 714);
  assert.equal(absent.state.mappings.length, 0);
});

test('E07: malformed SOAP and hostile semantic boundaries fail closed', () => {
  for (const [header, packet] of [
    [null, body()],
    [`"${service}#GetSpecificPortMappingEntry"`, body()],
    [`"${service}#GetSpecificPortMappingEntry"`,
      actionBody('GetSpecificPortMappingEntry', {
        NewRemoteHost: '',
        NewExternalPort: '4662',
        NewProtocol: 'TCP',
      })],
    [`"${service}#GetGenericPortMappingEntry"`,
      actionBody('GetGenericPortMappingEntry', {
        NewPortMappingIndex: '0',
      })],
    [`"${service}#DeletePortMapping"`, body({ NewRemoteHost: '1.2.3.4' })],
    [`"${service}#DeletePortMapping"`, body({ NewExternalPort: '0' })],
    [`"${service}#DeletePortMapping"`, body({ NewProtocol: 'SCTP' })],
    [`"${service}#DeletePortMapping"`, Buffer.alloc(0)],
    [`"${service}#DeletePortMapping"`, new Proxy(body(), {})],
  ]) {
    assert.throws(() => decodeUpnpDeletePortMapping(header, packet),
      UpnpSoapBoundaryError);
  }
  const validCommand = command();
  const validContext = context();
  for (const bad of [
    null,
    { ...validCommand, extra: true },
    { ...validCommand, external_port: 0 },
    new Proxy(validCommand, {}),
  ]) {
    assert.throws(() => applyUpnpDeletePortMapping(
      state(), bad, validContext), UpnpMappingDeleteError);
  }
  for (const bad of [
    null,
    { ...validContext, extra: true },
    { ...validContext, now_monotonic_ms: -0 },
    { ...validContext, gateway_external_address: '0.0.0.0' },
    new Proxy(validContext, {}),
  ]) {
    assert.throws(() => applyUpnpDeletePortMapping(
      state(), validCommand, bad), UpnpMappingDeleteError);
  }
  assert.throws(() => applyUpnpDeletePortMapping(
    {}, validCommand, validContext), UpnpMappingDeleteError);
  assert.throws(() => projectUpnpDeleteSoapResult({ ok: true }),
    UpnpMappingDeleteError);
});
