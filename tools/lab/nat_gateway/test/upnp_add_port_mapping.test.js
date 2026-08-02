'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createMappingState,
  snapshotInternalMappings,
} = require('../mapping_model');
const {
  UpnpSoapBoundaryError,
  decodeUpnpAddPortMapping,
  encodeUpnpSoapQueryResponse,
} = require('../upnp_soap_control');
const {
  UpnpMappingLifecycleError,
  applyUpnpAddPortMapping,
} = require('../upnp_mapping_lifecycle');

const service =
  'urn:schemas-upnp-org:service:WANIPConnection:1';
const action = `"${service}#AddPortMapping"`;
const digestA = 'a'.repeat(64);
const digestB = 'b'.repeat(64);

function body(overrides = {}) {
  const values = {
    NewRemoteHost: '',
    NewExternalPort: '4662',
    NewProtocol: 'TCP',
    NewInternalPort: '4662',
    NewInternalClient: '192.168.1.20',
    NewEnabled: '1',
    NewPortMappingDescription: 'eMule TCP',
    NewLeaseDuration: '0',
    ...overrides,
  };
  const argumentsXml = Object.entries(values)
    .map(([name, value]) => `<${name}>${value}</${name}>`)
    .join('');
  return Buffer.from(
    '<?xml version="1.0"?>' +
    '<s:Envelope ' +
    'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
    '<s:Body>' +
    `<u:AddPortMapping xmlns:u="${service}">` +
    argumentsXml +
    '</u:AddPortMapping></s:Body></s:Envelope>',
    'utf8');
}

function state(mappings = []) {
  return createMappingState({
    epoch: 17,
    generation: 3,
    mappings,
  });
}

function context(overrides = {}) {
  return {
    client_id: 'miniupnpc.client',
    gateway_external_address: '100.64.12.34',
    gateway_identity_digest: digestA,
    instance_id_digest: digestB,
    now_monotonic_ms: 1000,
    table_capacity: 16,
    ...overrides,
  };
}

function command(overrides = {}) {
  const decoded = decodeUpnpAddPortMapping(action, body());
  return { ...decoded, ...overrides };
}

function mapping(overrides = {}) {
  return {
    mapping_id: 'static.tcp.4662',
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
      created_monotonic_ms: 500,
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

test('E05: decodes the exact miniupnpc AddPortMapping arguments', () => {
  const decoded = decodeUpnpAddPortMapping(action, body());
  assert.deepEqual(decoded, {
    protocol: 'upnp',
    operation: 'add_port_mapping',
    service_type: service,
    remote_host: '',
    external_port: 4662,
    transport: 'tcp',
    internal_port: 4662,
    internal_client: '192.168.1.20',
    enabled: true,
    description: 'eMule TCP',
    lease_seconds: 0,
  });
  assert.equal(Object.isFrozen(decoded), true);
  assert.equal(decodeUpnpAddPortMapping(action, body({
    NewExternalPort: '4672',
    NewProtocol: 'UDP',
    NewInternalPort: '4672',
    NewPortMappingDescription: 'eMule UDP',
  })).transport, 'udp');
});

test('E05: ports, protocol, client, enabled, description and lease fail closed',
  () => {
    const invalid = [
      { NewRemoteHost: '203.0.113.2' },
      { NewExternalPort: '0' },
      { NewExternalPort: '65536' },
      { NewExternalPort: '+4662' },
      { NewExternalPort: '04662' },
      { NewProtocol: 'tcp' },
      { NewProtocol: 'SCTP' },
      { NewInternalPort: '0' },
      { NewInternalPort: '65536' },
      { NewInternalClient: '0.0.0.0' },
      { NewInternalClient: '127.0.0.1' },
      { NewInternalClient: '224.0.0.1' },
      { NewInternalClient: '::1' },
      { NewEnabled: 'true' },
      { NewEnabled: '2' },
      { NewPortMappingDescription: '' },
      { NewPortMappingDescription: 'x'.repeat(65) },
      { NewPortMappingDescription: '<bad>' },
      { NewLeaseDuration: '-1' },
      { NewLeaseDuration: '4294967296' },
    ];
    for (const overrides of invalid) {
      assert.throws(() => decodeUpnpAddPortMapping(action, body(overrides)),
        UpnpSoapBoundaryError);
    }
  });

test('E05: malformed, injected and hostile SOAP storage is rejected', () => {
  const valid = body();
  const detached = new Uint8Array(valid);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  const cases = [
    [null, valid],
    [`${action}\r\nX: injected`, valid],
    [`"${service}:2#AddPortMapping"`, valid],
    [action, Buffer.alloc(0)],
    [action, Buffer.alloc(8193)],
    [action, detached],
    [action, new Uint8Array(new SharedArrayBuffer(8))],
    [action, new Proxy(valid, {})],
    [action, Buffer.from([0xff])],
    [action, Buffer.from(valid.toString().replace(
      '<s:Body>', '<!DOCTYPE x><s:Body>'))],
    [action, Buffer.from(valid.toString().replace(
      '<NewEnabled>1', '<NewEnabled>&entity;'))],
    [action, Buffer.from(valid.toString().replace(
      '<NewEnabled>1</NewEnabled>',
      '<NewEnabled><x/></NewEnabled>'))],
    [action, Buffer.from(valid.toString().replace(
      '<NewEnabled>1</NewEnabled>',
      '<NewEnabled>1</NewEnabled><NewEnabled>1</NewEnabled>'))],
    [action, Buffer.from(valid.toString().replace(
      '</u:AddPortMapping>',
      '<Unexpected>x</Unexpected></u:AddPortMapping>'))],
  ];
  for (const [header, packet] of cases) {
    assert.throws(() => decodeUpnpAddPortMapping(header, packet),
      UpnpSoapBoundaryError);
  }
});

test('E05: a permanent mapping is created and encoded as SOAP success', () => {
  const decoded = decodeUpnpAddPortMapping(action, body());
  const result = applyUpnpAddPortMapping(state(), decoded, context());
  assert.equal(result.ok, true);
  assert.equal(result.disposition, 'created');
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(snapshotInternalMappings(result.state), [{
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
  }]);
  const response = encodeUpnpSoapQueryResponse(decoded, { ok: true });
  assert.equal(response.status_code, 200);
  assert.match(response.body.toString(),
    /<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><\/u:AddPortMappingResponse>/);
});

test('E05: an identical request renews in place without duplication', () => {
  const first = applyUpnpAddPortMapping(state(), command(), context());
  const second = applyUpnpAddPortMapping(first.state, command(),
    context({ now_monotonic_ms: 2000 }));
  assert.equal(second.ok, true);
  assert.equal(second.disposition, 'renewed');
  assert.equal(second.mapping.mapping_id, first.mapping.mapping_id);
  assert.equal(second.mapping.lease.created_monotonic_ms, 2000);
  assert.equal(snapshotInternalMappings(second.state).length, 1);
});

test('E05: the same owned client atomically replaces mutable fields', () => {
  const original = state([mapping()]);
  const result = applyUpnpAddPortMapping(original, command({
    internal_port: 4711,
    description: 'eMule TCP replacement',
  }), context({ now_monotonic_ms: 2000 }));
  assert.equal(result.ok, true);
  assert.equal(result.disposition, 'replaced');
  assert.equal(result.mapping.mapping_id, 'static.tcp.4662');
  assert.equal(result.mapping.internal_port, 4711);
  assert.equal(result.mapping.owner.description, 'eMule TCP replacement');
  assert.equal(result.mapping.lease.created_monotonic_ms, 2000);
  assert.equal(snapshotInternalMappings(result.state).length, 1);
  assert.deepEqual(snapshotInternalMappings(original), [mapping()]);
});

test('E05: replacement preserves a complete TCP and UDP atomic group', () => {
  const tcp = mapping({ atomic_group_id: 'pair-1' });
  const udp = mapping({
    mapping_id: 'static.udp.4672',
    transport: 'udp',
    internal_port: 4672,
    requested_external_port: 4672,
    external_port: 4672,
    atomic_group_id: 'pair-1',
  });
  const result = applyUpnpAddPortMapping(
    state([tcp, udp]),
    command({ internal_port: 4711, description: 'updated pair' }),
    context({ now_monotonic_ms: 2000 }));
  assert.equal(result.ok, true);
  assert.equal(result.mapping.atomic_group_id, 'pair-1');
  assert.deepEqual(snapshotInternalMappings(result.state)
    .map((item) => [item.mapping_id, item.atomic_group_status]), [
    ['static.tcp.4662', 'complete'],
    ['static.udp.4672', 'complete'],
  ]);
});

test('E05: occupied endpoint conflict is deterministic and non-mutating', () => {
  const original = state([mapping({
    protocol: 'natpmp',
    owner: {
      kind: 'natpmp-lease-scope',
      instance_id_digest: digestB,
      scope_id: 'natpmp.client',
    },
  })]);
  const result = applyUpnpAddPortMapping(original, command(), context());
  assert.deepEqual(result, {
    ok: false,
    state: original,
    error_code: 718,
    error_description: 'ConflictInMappingEntry',
  });
  assert.equal(result.state, original);
  const response = encodeUpnpSoapQueryResponse(
    decodeUpnpAddPortMapping(action, body()), {
      ok: false,
      error_code: result.error_code,
      error_description: result.error_description,
    });
  assert.equal(response.status_code, 500);
  assert.match(response.body.toString(),
    /<errorCode>718<\/errorCode>/);
});

test('E05: finite leases and disabled mappings return bounded faults', () => {
  const original = state();
  for (const [overrides, code, description] of [
    [{ lease_seconds: 60 }, 725, 'OnlyPermanentLeasesSupported'],
    [{ enabled: false }, 501, 'Action Failed'],
  ]) {
    const result = applyUpnpAddPortMapping(
      original, command(overrides), context());
    assert.equal(result.ok, false);
    assert.equal(result.error_code, code);
    assert.equal(result.error_description, description);
    assert.equal(result.state, original);
  }
});

test('E05: a full table returns NoPortMapsAvailable without mutation', () => {
  const original = state([mapping({
    mapping_id: 'static.udp.9999',
    transport: 'udp',
    internal_port: 9999,
    requested_external_port: 9999,
    external_port: 9999,
  })]);
  const result = applyUpnpAddPortMapping(
    original, command(), context({ table_capacity: 1 }));
  assert.equal(result.ok, false);
  assert.equal(result.error_code, 728);
  assert.equal(result.error_description, 'NoPortMapsAvailable');
  assert.equal(result.state, original);
});

test('E05: expired foreign leases cannot cause conflict or table-full', () => {
  const expiredConflict = mapping({
    mapping_id: 'pcp.expired.conflict',
    protocol: 'pcp',
    lease: {
      lifetime_seconds: 1,
      created_monotonic_ms: 0,
      expires_monotonic_ms: 1000,
    },
    owner: {
      kind: 'pcp-nonce',
      instance_id_digest: digestB,
      nonce: '1'.repeat(24),
    },
  });
  const afterConflict = applyUpnpAddPortMapping(
    state([expiredConflict]), command(),
    context({ now_monotonic_ms: 1000, table_capacity: 1 }));
  assert.equal(afterConflict.ok, true);
  assert.equal(afterConflict.disposition, 'created');
  assert.deepEqual(snapshotInternalMappings(afterConflict.state)
    .map((item) => item.mapping_id), ['upnp.tcp.4662']);

  const expiredCapacity = mapping({
    mapping_id: 'natpmp.expired.capacity',
    protocol: 'natpmp',
    transport: 'udp',
    internal_port: 9999,
    requested_external_port: 9999,
    external_port: 9999,
    lease: {
      lifetime_seconds: 1,
      created_monotonic_ms: 0,
      expires_monotonic_ms: 1000,
    },
    owner: {
      kind: 'natpmp-lease-scope',
      instance_id_digest: digestB,
      scope_id: 'natpmp.client',
    },
  });
  const afterCapacity = applyUpnpAddPortMapping(
    state([expiredCapacity]), command(),
    context({ now_monotonic_ms: 1001, table_capacity: 1 }));
  assert.equal(afterCapacity.ok, true);
  assert.deepEqual(snapshotInternalMappings(afterCapacity.state)
    .map((item) => item.mapping_id), ['upnp.tcp.4662']);
});

test('E05: TCP and UDP use separate mapping spaces', () => {
  const tcp = applyUpnpAddPortMapping(state(), command(), context());
  const udpCommand = decodeUpnpAddPortMapping(action, body({
    NewProtocol: 'UDP',
    NewInternalPort: '4672',
    NewPortMappingDescription: 'eMule UDP',
  }));
  const udp = applyUpnpAddPortMapping(
    tcp.state, udpCommand, context({ now_monotonic_ms: 1001 }));
  assert.equal(udp.ok, true);
  assert.deepEqual(snapshotInternalMappings(udp.state)
    .map((item) => item.mapping_id),
  ['upnp.tcp.4662', 'upnp.udp.4662']);
});

test('E05: semantic command, context and state boundaries reject open input',
  () => {
    const validCommand = command();
    const validContext = context();
    const commandAccessor = { ...validCommand };
    Object.defineProperty(commandAccessor, 'description', {
      enumerable: true,
      get() { throw new Error('must not execute'); },
    });
    const contextAccessor = { ...validContext };
    Object.defineProperty(contextAccessor, 'client_id', {
      enumerable: true,
      get() { throw new Error('must not execute'); },
    });
    for (const badCommand of [
      null,
      { ...validCommand, extra: true },
      { ...validCommand, internal_client: '127.0.0.1' },
      { ...validCommand, description: '' },
      { ...validCommand, lease_seconds: -0 },
      commandAccessor,
      new Proxy(validCommand, {}),
    ]) {
      assert.throws(() => applyUpnpAddPortMapping(
        state(), badCommand, validContext), UpnpMappingLifecycleError);
    }
    for (const badContext of [
      null,
      { ...validContext, extra: true },
      { ...validContext, gateway_external_address: '0.0.0.0' },
      { ...validContext, gateway_external_address: '224.0.0.1' },
      { ...validContext, table_capacity: 0 },
      { ...validContext, now_monotonic_ms: -0 },
      contextAccessor,
      new Proxy(validContext, {}),
    ]) {
      assert.throws(() => applyUpnpAddPortMapping(
        state(), validCommand, badContext), UpnpMappingLifecycleError);
    }
    assert.throws(() => applyUpnpAddPortMapping(
      { epoch: 17, generation: 3, mappings: [] },
      validCommand, validContext), (error) =>
      error instanceof UpnpMappingLifecycleError &&
      error.reason_code === 'UPNP_MAPPING_STATE_INVALID');
  });

test('E05: time regression and generated mapping-id collision fail safely',
  () => {
    assert.throws(() => applyUpnpAddPortMapping(
      state([mapping()]), command(), context({ now_monotonic_ms: 499 })),
    (error) => error instanceof UpnpMappingLifecycleError &&
      error.field_path === '$.context.now_monotonic_ms');

    const collidingId = mapping({
      mapping_id: 'upnp.tcp.4662',
      external_address: '203.0.113.7',
      external_port: 9999,
      internal_port: 9999,
      requested_external_port: 9999,
    });
    const collision = applyUpnpAddPortMapping(
      state([collidingId]), command(), context());
    assert.equal(collision.ok, false);
    assert.equal(collision.error_code, 718);
  });
