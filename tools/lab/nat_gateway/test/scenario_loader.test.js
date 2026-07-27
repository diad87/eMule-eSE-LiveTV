'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  MAX_SCENARIO_BYTES,
  ScenarioValidationError,
  loadScenarioFromFile,
  loadScenarioFromObject,
  loadScenarioFromText
} = require('../scenario_loader');

const digest = 'a'.repeat(64);

function validScenario() {
  return {
    schema_version: 'ese.v92.t8.scenario/v1',
    scenario_id: 'minimal-scenario',
    seed: 1,
    clock: { mode: 'virtual', start_monotonic_ms: 1000 },
    gateway: {
      gateway_id: 'gateway-1',
      epoch: { initial_seconds: 10, restart_seconds: 1 },
      initial_generation: 1,
      wan_address: '192.0.2.1',
      lan_addresses: ['192.0.2.10']
    },
    listeners: {
      upnp: { interface_id: 'lan-1', bind_address: '192.0.2.10', ssdp_port: 1900, http_port: 5000 },
      pcp: { interface_id: 'lan-1', bind_address: '192.0.2.10', port: 5351 },
      natpmp: { interface_id: 'lan-1', bind_address: '192.0.2.10', port: 5350 }
    },
    protocols: {
      upnp: { enabled: true, igd_version: 'v2-minimal', readback: 'full' },
      pcp: { enabled: false },
      natpmp: { enabled: false }
    },
    allocation: { strategy: 'range', range_start: 40000, range_end: 40010 },
    initial_state: {
      mappings: [],
      request_counters: { total: 0, upnp: 0, pcp: 0, natpmp: 0 },
      response_queue: []
    },
    faults: [],
    privacy: {
      report_mode: 'sanitized',
      address_mode: 'class-only',
      nonce_mode: 'sha256',
      payload_mode: 'omitted',
      allow_credentials: false
    }
  };
}

function clone(value) { return JSON.parse(JSON.stringify(value)); }

function expectError(action, code, fieldPath) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof ScenarioValidationError);
    assert.equal(error.reason_code, code);
    assert.equal(error.field_path, fieldPath);
    assert.ok(error.message.includes(code));
    assert.ok(error.message.includes(fieldPath));
    return true;
  });
}

function mapping(id, transport, group) {
  return {
    mapping_id: id,
    protocol: 'upnp',
    transport,
    client_id: 'client-1',
    internal_address: '192.0.2.10',
    internal_port: 4662,
    requested_external_port: 4662,
    external_address: '192.0.2.1',
    external_port: 4662,
    lease: { lifetime_seconds: 60, created_monotonic_ms: 1000, expires_monotonic_ms: 61000 },
    owner: { kind: 'upnp-journal', instance_id_digest: digest, gateway_identity_digest: digest, description: 'lab-map' },
    epoch: 10,
    generation: 1,
    ...(group ? { atomic_group_id: group } : {})
  };
}

test('loads the smallest valid scenario from object, text and explicit file', () => {
  const input = validScenario();
  const fromObject = loadScenarioFromObject(input);
  assert.equal(fromObject.scenario_id, 'minimal-scenario');
  assert.ok(Object.isFrozen(fromObject));
  assert.ok(Object.isFrozen(fromObject.gateway));

  const fromText = loadScenarioFromText(JSON.stringify(input));
  assert.deepEqual(fromText, fromObject);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ese-v92-loader-'));
  const filePath = path.join(directory, 'scenario.json');
  fs.writeFileSync(filePath, JSON.stringify(input), 'utf8');
  try {
    assert.deepEqual(loadScenarioFromFile(filePath), fromObject);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('never mutates the caller object', () => {
  const input = validScenario();
  const before = clone(input);
  const result = loadScenarioFromObject(input);
  assert.deepEqual(input, before);
  assert.notEqual(result, input);
});

test('accepts only plain, dense JSON data without evaluating object behavior', () => {
  expectError(() => loadScenarioFromObject(null), 'SCENARIO_OBJECT_INVALID', '$');
  expectError(() => loadScenarioFromObject({ toJSON() { return validScenario(); } }), 'SCENARIO_OBJECT_INVALID', '$.toJSON');
  expectError(() => loadScenarioFromObject({ ...validScenario(), extra: undefined }), 'SCENARIO_OBJECT_INVALID', '$.extra');
  expectError(() => loadScenarioFromObject({ ...validScenario(), extra: Number.NaN }), 'SCENARIO_OBJECT_INVALID', '$.extra');
  const accessor = validScenario();
  Object.defineProperty(accessor, 'extra', { enumerable: true, get() { throw new Error('must not execute'); } });
  expectError(() => loadScenarioFromObject(accessor), 'SCENARIO_OBJECT_INVALID', '$.extra');
  const sparse = validScenario(); sparse.gateway.lan_addresses = [];
  sparse.gateway.lan_addresses[1] = '192.0.2.10';
  expectError(() => loadScenarioFromObject(sparse), 'SCENARIO_OBJECT_INVALID', '$.gateway.lan_addresses[0]');
  const custom = Object.create({ inherited: true }); Object.assign(custom, validScenario());
  expectError(() => loadScenarioFromObject(custom), 'SCENARIO_OBJECT_INVALID', '$');
  const cyclic = validScenario(); cyclic.extra = cyclic;
  expectError(() => loadScenarioFromObject(cyclic), 'SCENARIO_OBJECT_INVALID', '$.extra');
});

test('reports deterministic parse and size errors', () => {
  expectError(() => loadScenarioFromText('{'), 'SCENARIO_JSON_INVALID', '$');
  expectError(() => loadScenarioFromText('x'.repeat(1024 * 1024 + 1)), 'SCENARIO_TOO_LARGE', '$');
  expectError(() => loadScenarioFromFile(''), 'SCENARIO_FILE_PATH_INVALID', '$');
});

test('rejects an oversized or invalid UTF-8 scenario file before parsing it', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ese-v92-loader-'));
  try {
    const oversized = path.join(directory, 'oversized.json');
    fs.writeFileSync(oversized, 'x'.repeat(MAX_SCENARIO_BYTES + 1), 'utf8');
    expectError(() => loadScenarioFromFile(oversized), 'SCENARIO_TOO_LARGE', '$');

    const invalidUtf8 = path.join(directory, 'invalid-utf8.json');
    fs.writeFileSync(invalidUtf8, Buffer.from([0xff, 0xfe]));
    expectError(() => loadScenarioFromFile(invalidUtf8), 'SCENARIO_UTF8_INVALID', '$');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('fails closed before effects for missing sections and unknown fields', () => {
  const missing = validScenario(); delete missing.protocols;
  expectError(() => loadScenarioFromObject(missing), 'SCHEMA_REQUIRED', '$.protocols');
  const extra = validScenario(); extra.unexpected = true;
  expectError(() => loadScenarioFromObject(extra), 'SCHEMA_ADDITIONAL_PROPERTY', '$.unexpected');
});

test('selects the active const-discriminated schema branch for required fields', () => {
  const range = validScenario(); delete range.allocation.range_end;
  expectError(() => loadScenarioFromObject(range), 'SCHEMA_REQUIRED', '$.allocation.range_end');

  const virtual = validScenario(); delete virtual.clock.start_monotonic_ms;
  expectError(() => loadScenarioFromObject(virtual), 'SCHEMA_REQUIRED', '$.clock.start_monotonic_ms');

  const delay = validScenario();
  delay.faults = [{ fault_id: 'fault-1', enabled: true, match: { protocol: 'upnp' }, trigger: { after_matches: 0, times: 1 }, action: { type: 'delay', delay_ms: 1 } }];
  expectError(() => loadScenarioFromObject(delay), 'SCHEMA_REQUIRED', '$.faults[0].action.jitter_ms');
});

test('validates scalar ranges and IP addresses with a stable path', () => {
  const negativeLease = validScenario();
  negativeLease.initial_state.mappings = [mapping('map-1', 'tcp')];
  negativeLease.initial_state.mappings[0].lease.lifetime_seconds = -1;
  expectError(() => loadScenarioFromObject(negativeLease), 'SCHEMA_MINIMUM', '$.initial_state.mappings[0].lease.lifetime_seconds');

  const badPort = validScenario(); badPort.listeners.upnp.http_port = 65536;
  expectError(() => loadScenarioFromObject(badPort), 'SCHEMA_MAXIMUM', '$.listeners.upnp.http_port');

  const badIp = validScenario(); badIp.gateway.wan_address = '999.1.1.1';
  expectError(() => loadScenarioFromObject(badIp), 'SCHEMA_FORMAT', '$.gateway.wan_address');

  const ownerNonce = validScenario();
  ownerNonce.initial_state.mappings = [mapping('map-1', 'tcp')];
  ownerNonce.initial_state.mappings[0].owner = { kind: 'pcp-nonce', instance_id_digest: digest };
  expectError(() => loadScenarioFromObject(ownerNonce), 'SCHEMA_REQUIRED', '$.initial_state.mappings[0].owner.nonce');
});

test('enforces allocation and exact finite lease arithmetic without overflow', () => {
  const backwards = validScenario(); backwards.allocation = { strategy: 'range', range_start: 40010, range_end: 40000 };
  expectError(() => loadScenarioFromObject(backwards), 'ALLOCATION_RANGE_INVALID', '$.allocation.range_end');

  const badLease = validScenario(); badLease.initial_state.mappings = [mapping('map-1', 'tcp')];
  badLease.initial_state.mappings[0].lease.expires_monotonic_ms = 61001;
  expectError(() => loadScenarioFromObject(badLease), 'LEASE_EXPIRY_MISMATCH', '$.initial_state.mappings[0].lease.expires_monotonic_ms');

  const overflow = validScenario(); overflow.initial_state.mappings = [mapping('map-1', 'tcp')];
  overflow.initial_state.mappings[0].lease.created_monotonic_ms = Number.MAX_SAFE_INTEGER;
  overflow.initial_state.mappings[0].lease.expires_monotonic_ms = Number.MAX_SAFE_INTEGER;
  expectError(() => loadScenarioFromObject(overflow), 'LEASE_EXPIRY_OVERFLOW', '$.initial_state.mappings[0].lease');
});

test('rejects duplicate IDs and external mapping collisions', () => {
  const duplicate = validScenario();
  duplicate.initial_state.mappings = [mapping('map-1', 'tcp'), mapping('map-1', 'udp')];
  expectError(() => loadScenarioFromObject(duplicate), 'DUPLICATE_MAPPING_ID', '$.initial_state.mappings[1].mapping_id');

  const collision = validScenario();
  collision.initial_state.mappings = [mapping('map-1', 'tcp'), mapping('map-2', 'tcp')];
  expectError(() => loadScenarioFromObject(collision), 'MAPPING_COLLISION', '$.initial_state.mappings[1]');

  const ipv6Collision = validScenario();
  const firstIpv6 = mapping('map-1', 'tcp'); firstIpv6.external_address = '2001:0db8:0:0:0:0:0:1';
  const secondIpv6 = mapping('map-2', 'tcp'); secondIpv6.external_address = '2001:db8::1';
  ipv6Collision.initial_state.mappings = [firstIpv6, secondIpv6];
  expectError(() => loadScenarioFromObject(ipv6Collision), 'MAPPING_COLLISION', '$.initial_state.mappings[1]');

  const responseDuplicate = validScenario();
  responseDuplicate.initial_state.response_queue = [
    { response_id: 'response-1', due_monotonic_ms: 1, protocol: 'upnp', operation: 'map', outcome: 'success' },
    { response_id: 'response-1', due_monotonic_ms: 2, protocol: 'upnp', operation: 'map', outcome: 'success' }
  ];
  expectError(() => loadScenarioFromObject(responseDuplicate), 'DUPLICATE_RESPONSE_ID', '$.initial_state.response_queue[1].response_id');

  const faultDuplicate = validScenario();
  const fault = { fault_id: 'fault-1', enabled: true, match: { protocol: 'upnp' }, trigger: { after_matches: 0, times: 1 }, action: { type: 'drop' } };
  faultDuplicate.faults = [fault, clone(fault)];
  expectError(() => loadScenarioFromObject(faultDuplicate), 'DUPLICATE_FAULT_ID', '$.faults[1].fault_id');
});

test('requires complete and coherent tcp/udp atomic groups', () => {
  const incomplete = validScenario(); incomplete.initial_state.mappings = [mapping('map-1', 'tcp', 'pair-1')];
  expectError(() => loadScenarioFromObject(incomplete), 'ATOMIC_GROUP_INCOMPLETE', '$.initial_state.mappings[0].atomic_group_id');

  const validPair = validScenario(); validPair.protocols.pcp.enabled = true;
  const tcp = mapping('map-1', 'tcp', 'pair-1');
  const udp = mapping('map-2', 'udp', 'pair-1');
  tcp.protocol = 'pcp'; udp.protocol = 'pcp';
  tcp.owner = { kind: 'pcp-nonce', instance_id_digest: digest, nonce: 'b'.repeat(24) };
  udp.owner = { kind: 'pcp-nonce', instance_id_digest: digest, nonce: 'c'.repeat(24) };
  udp.internal_port = 4663;
  udp.requested_external_port = 4663;
  udp.external_port = 4663;
  udp.lease = { lifetime_seconds: 30, created_monotonic_ms: 2000, expires_monotonic_ms: 32000 };
  validPair.initial_state.mappings = [tcp, udp];
  assert.equal(loadScenarioFromObject(validPair).initial_state.mappings.length, 2);

  for (const [property, value, field] of [
    ['protocol', 'pcp', 'protocol'],
    ['client_id', 'client-2', 'client_id'],
    ['generation', 2, 'generation']
  ]) {
    const incoherent = validScenario();
    incoherent.protocols.pcp.enabled = true;
    const first = mapping('map-1', 'tcp', 'pair-1');
    const second = mapping('map-2', 'udp', 'pair-1'); second[property] = value;
    incoherent.initial_state.mappings = [first, second];
    expectError(() => loadScenarioFromObject(incoherent), 'ATOMIC_GROUP_INCOHERENT', `$.initial_state.mappings[1].${field}`);
  }

  const instanceMismatch = validScenario();
  const first = mapping('map-1', 'tcp', 'pair-1');
  const second = mapping('map-2', 'udp', 'pair-1');
  second.owner.instance_id_digest = 'b'.repeat(64);
  instanceMismatch.initial_state.mappings = [first, second];
  expectError(() => loadScenarioFromObject(instanceMismatch), 'ATOMIC_GROUP_INCOHERENT', '$.initial_state.mappings[1].owner.instance_id_digest');

  const kindMismatch = validScenario();
  const kindFirst = mapping('map-1', 'tcp', 'pair-1');
  const kindSecond = mapping('map-2', 'udp', 'pair-1'); kindSecond.owner = { kind: 'none' };
  kindMismatch.initial_state.mappings = [kindFirst, kindSecond];
  expectError(() => loadScenarioFromObject(kindMismatch), 'ATOMIC_GROUP_INCOHERENT', '$.initial_state.mappings[1].owner.kind');

  const gatewayMismatch = validScenario();
  const gatewayFirst = mapping('map-1', 'tcp', 'pair-1');
  const gatewaySecond = mapping('map-2', 'udp', 'pair-1'); gatewaySecond.owner.gateway_identity_digest = 'b'.repeat(64);
  gatewayMismatch.initial_state.mappings = [gatewayFirst, gatewaySecond];
  expectError(() => loadScenarioFromObject(gatewayMismatch), 'ATOMIC_GROUP_INCOHERENT', '$.initial_state.mappings[1].owner.gateway_identity_digest');
});

test('requires coherent enabled protocol listeners and at least one enabled protocol', () => {
  const none = validScenario(); none.protocols.upnp.enabled = false;
  expectError(() => loadScenarioFromObject(none), 'NO_PROTOCOL_ENABLED', '$.protocols');

  const outsideLan = validScenario(); outsideLan.listeners.upnp.bind_address = '192.0.2.11';
  expectError(() => loadScenarioFromObject(outsideLan), 'LISTENER_BIND_NOT_LAN', '$.listeners.upnp.bind_address');

  const conflict = validScenario(); conflict.protocols.pcp.enabled = true; conflict.listeners.pcp.port = 1900;
  expectError(() => loadScenarioFromObject(conflict), 'LISTENER_PORT_COLLISION', '$.listeners.pcp.port');

  const sharedPcpNatPmp = validScenario();
  sharedPcpNatPmp.protocols.pcp.enabled = true;
  sharedPcpNatPmp.protocols.natpmp.enabled = true;
  sharedPcpNatPmp.listeners.pcp.port = 5351;
  sharedPcpNatPmp.listeners.natpmp.port = 5351;
  assert.equal(loadScenarioFromObject(sharedPcpNatPmp).listeners.natpmp.port, 5351);
});

test('rejects state or fault references to disabled protocols and accepts permanent leases', () => {
  const disabledMapping = validScenario();
  disabledMapping.initial_state.mappings = [mapping('map-1', 'tcp')];
  disabledMapping.initial_state.mappings[0].protocol = 'pcp';
  expectError(() => loadScenarioFromObject(disabledMapping), 'MAPPING_PROTOCOL_DISABLED', '$.initial_state.mappings[0].protocol');

  const disabledResponse = validScenario();
  disabledResponse.initial_state.response_queue = [
    { response_id: 'response-1', due_monotonic_ms: 1, protocol: 'pcp', operation: 'map', outcome: 'success' }
  ];
  expectError(() => loadScenarioFromObject(disabledResponse), 'RESPONSE_PROTOCOL_DISABLED', '$.initial_state.response_queue[0].protocol');

  const disabledFault = validScenario();
  disabledFault.faults = [{ fault_id: 'fault-1', enabled: true, match: { protocol: 'pcp' }, trigger: { after_matches: 0, times: 1 }, action: { type: 'drop' } }];
  expectError(() => loadScenarioFromObject(disabledFault), 'FAULT_PROTOCOL_DISABLED', '$.faults[0].match.protocol');

  const permanent = validScenario();
  permanent.initial_state.mappings = [mapping('map-1', 'tcp')];
  permanent.initial_state.mappings[0].lease = { lifetime_seconds: 0, created_monotonic_ms: Number.MAX_SAFE_INTEGER, expires_monotonic_ms: null };
  assert.equal(loadScenarioFromObject(permanent).initial_state.mappings[0].lease.expires_monotonic_ms, null);
});
