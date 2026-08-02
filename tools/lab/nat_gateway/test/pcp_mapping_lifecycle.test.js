'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const {
  createMappingState,
  snapshotInternalMappings,
} = require('../mapping_model');
const { decodePcpMapRequest } = require('../pcp_map_request_decoder');
const { encodePcpMapResponse } = require('../pcp_map_response_encoder');
const { createPcpUdpServer } = require('../pcp_udp_server');
const { PCP_VECTORS } = require('../pcp_vectors');
const {
  PcpMappingLifecycleError,
  applyPcpMapCommand,
  toPcpMapResponse,
} = require('../pcp_mapping_lifecycle');

const digest = 'a'.repeat(64);
function vector(name) { return Buffer.from(PCP_VECTORS[name].hex, 'hex'); }
function command(name = 'map_tcp_request') {
  return decodePcpMapRequest(vector(name));
}
function deletePacket() {
  const packet = vector('map_tcp_request');
  packet.fill(0, 4, 8);
  packet.fill(0, 42, 44);
  packet.fill(0, 44, 60);
  return packet;
}
function deleteCommand() { return decodePcpMapRequest(deletePacket()); }
function loopbackPacket(packet = vector('map_tcp_request')) {
  Buffer.from('00000000000000000000ffff7f000001', 'hex').copy(packet, 8);
  return packet;
}
function state() {
  return createMappingState({
    epoch: 10,
    generation: 4,
    mappings: [],
    baseline_mappings: [],
  });
}
function context(overrides = {}) {
  return {
    now_monotonic_ms: 1000,
    client_id: 'client-1',
    instance_id_digest: digest,
    granted_lifetime_seconds: 3600,
    new_mapping: {
      mapping_id: 'pcp-map-1',
      external_address: '198.51.100.1',
      external_port: 52144,
    },
    ...overrides,
  };
}

test('D06: creates one PCP mapping with nonce-bound ownership and exact lease', () => {
  const initial = state();
  const applied = applyPcpMapCommand(initial, command(), context());
  assert.equal(applied.action, 'created');
  assert.equal(applied.result_code, 0);
  assert.equal(applied.lifetime_seconds, 3600);
  assert.equal(initial.mappings.length, 0);
  const [mapping] = snapshotInternalMappings(applied.state);
  assert.equal(mapping.external_port, 52144);
  assert.equal(mapping.owner.kind, 'pcp-nonce');
  assert.equal(mapping.owner.nonce, command().nonce);
  assert.equal(mapping.lease.expires_monotonic_ms, 3601000);
  assert.ok(Object.isFrozen(applied));
});

test('D06: retransmission with matching nonce renews existing mapping in place', () => {
  const created = applyPcpMapCommand(state(), command(), context());
  const renewed = applyPcpMapCommand(created.state, command(), context({
    now_monotonic_ms: 2000,
    granted_lifetime_seconds: 7200,
    new_mapping: null,
  }));
  assert.equal(renewed.action, 'renewed');
  assert.equal(renewed.mapping.mapping_id, 'pcp-map-1');
  assert.equal(renewed.mapping.external_port, 52144);
  assert.deepEqual(renewed.mapping.lease, {
    lifetime_seconds: 7200,
    created_monotonic_ms: 2000,
    expires_monotonic_ms: 7202000,
  });
});

test('D06: different nonce on the same tuple is NOT_AUTHORIZED with remaining lifetime', () => {
  const created = applyPcpMapCommand(state(), command(), context());
  const packet = vector('map_tcp_request');
  packet[24] ^= 0xff;
  const rejected = applyPcpMapCommand(created.state,
    decodePcpMapRequest(packet), context({
      now_monotonic_ms: 2500,
      new_mapping: null,
    }));
  assert.equal(rejected.action, 'rejected');
  assert.equal(rejected.result_code, 2);
  assert.equal(rejected.lifetime_seconds, 3599);
  assert.equal(rejected.state, created.state);
});

test('D06: matching delete removes mapping and repeated delete is successful noop', () => {
  const created = applyPcpMapCommand(state(), command(), context());
  const deleted = applyPcpMapCommand(created.state,
    deleteCommand(), context({
      now_monotonic_ms: 2000,
      granted_lifetime_seconds: 0,
      new_mapping: null,
    }));
  assert.equal(deleted.action, 'deleted');
  assert.equal(deleted.result_code, 0);
  assert.equal(deleted.state.mappings.length, 0);
  const repeated = applyPcpMapCommand(deleted.state,
    deleteCommand(), context({
      now_monotonic_ms: 2000,
      granted_lifetime_seconds: 0,
      new_mapping: null,
    }));
  assert.equal(repeated.action, 'delete-noop');
  assert.equal(repeated.result_code, 0);
});

test('D06: expired mapping is removed before a fresh nonce creates replacement state', () => {
  const created = applyPcpMapCommand(state(), command(), context({
    granted_lifetime_seconds: 1,
  }));
  const packet = vector('map_tcp_request');
  packet[24] ^= 0xff;
  const replacement = applyPcpMapCommand(created.state,
    decodePcpMapRequest(packet), context({
      now_monotonic_ms: 2000,
      new_mapping: {
        mapping_id: 'pcp-map-2',
        external_address: '198.51.100.1',
        external_port: 52145,
      },
    }));
  assert.equal(replacement.action, 'created');
  assert.deepEqual(replacement.state.mappings.map((item) => item.mapping_id),
    ['pcp-map-2']);
});

test('D06: PREFER_FAILURE rejects an alternate grant without mutating state', () => {
  const prefer = command('map_prefer_failure_request');
  const rejected = applyPcpMapCommand(state(), prefer, context());
  assert.equal(rejected.action, 'rejected');
  assert.equal(rejected.result_code, 11);
  assert.equal(rejected.state.mappings.length, 0);
  assert.equal(rejected.lifetime_seconds, 30);
});

test('D06: PREFER_FAILURE on an existing mapping requires its exact endpoint', () => {
  const created = applyPcpMapCommand(state(), command(), context());
  const base = command();
  const prefer = {
    ...base,
    options: { prefer_failure: true, port_set: null },
  };
  const rejected = applyPcpMapCommand(created.state, prefer, context({
    now_monotonic_ms: 2000,
    new_mapping: null,
  }));
  assert.equal(rejected.result_code, 11);
  assert.equal(rejected.action, 'rejected');

  const accepted = applyPcpMapCommand(created.state, {
    ...prefer,
    suggested_external_port: 52144,
    suggested_external_address: '198.51.100.1',
  }, context({
    now_monotonic_ms: 2000,
    new_mapping: null,
  }));
  assert.equal(accepted.action, 'renewed');
});

test('D06: exhausted allocation returns NO_RESOURCES and leaves state unchanged', () => {
  const initial = state();
  const rejected = applyPcpMapCommand(initial, command(), context({
    new_mapping: null,
  }));
  assert.deepEqual(rejected, {
    state: initial,
    action: 'rejected',
    result_code: 8,
    lifetime_seconds: 30,
    mapping: null,
  });
});

test('D06: static tuple is returned for MAP but cannot be deleted through PCP', () => {
  const created = applyPcpMapCommand(state(), command(), context());
  const original = snapshotInternalMappings(created.state)[0];
  const staticState = createMappingState({
    epoch: 10,
    generation: 4,
    mappings: [{
      ...original,
      owner: { kind: 'none' },
      lease: {
        lifetime_seconds: 0,
        created_monotonic_ms: 1000,
        expires_monotonic_ms: null,
      },
    }],
    baseline_mappings: [],
  });
  const returned = applyPcpMapCommand(staticState, command(), context({
    now_monotonic_ms: 2000,
    new_mapping: null,
  }));
  assert.equal(returned.result_code, 0);
  assert.equal(returned.action, 'static');
  assert.equal(returned.lifetime_seconds, 0xffffffff);
  assert.equal(returned.mapping.external_port, 52144);
  const deletion = applyPcpMapCommand(staticState, deleteCommand(), context({
    now_monotonic_ms: 2000,
    granted_lifetime_seconds: 0,
    new_mapping: null,
  }));
  assert.equal(deletion.result_code, 2);
  assert.equal(deletion.state, staticState);

});

test('D06: ownerless finite tuple cannot masquerade as a static mapping', () => {
  const created = applyPcpMapCommand(state(), command(), context());
  const original = snapshotInternalMappings(created.state)[0];
  const incoherent = createMappingState({
    epoch: 10,
    generation: 4,
    mappings: [{ ...original, owner: { kind: 'none' } }],
    baseline_mappings: [],
  });
  assert.throws(() => applyPcpMapCommand(incoherent, command(), context({
    now_monotonic_ms: 2000,
    new_mapping: null,
  })), (error) => error.reason_code === 'PCP_LIFECYCLE_STATE_INVALID');
});

test('D06: same nonce from a different instance cannot renew or delete', () => {
  const created = applyPcpMapCommand(state(), command(), context());
  const other = {
    ...context({
      now_monotonic_ms: 2000,
      new_mapping: null,
    }),
    instance_id_digest: 'b'.repeat(64),
  };
  const renewal = applyPcpMapCommand(created.state, command(), other);
  assert.equal(renewal.result_code, 2);
  assert.equal(renewal.state, created.state);
  const deletion = applyPcpMapCommand(created.state, deleteCommand(), {
    ...other,
    granted_lifetime_seconds: 0,
  });
  assert.equal(deletion.result_code, 2);
  assert.equal(deletion.state, created.state);
});

test('D06: ambiguous PCP tuple ownership fails closed', () => {
  const created = applyPcpMapCommand(state(), command(), context());
  const original = snapshotInternalMappings(created.state)[0];
  const ambiguous = createMappingState({
    epoch: 10,
    generation: 4,
    mappings: [
      original,
      {
        ...original,
        mapping_id: 'pcp-map-2',
        external_port: 52145,
      },
    ],
    baseline_mappings: [],
  });
  assert.throws(() => applyPcpMapCommand(ambiguous, command(), context({
    now_monotonic_ms: 2000,
    new_mapping: null,
  })), (error) => error.reason_code === 'PCP_LIFECYCLE_STATE_AMBIGUOUS');
});

test('D06: UDP creation remains a separate mapping space', () => {
  const packet = vector('map_tcp_request');
  packet[36] = 17;
  const udp = applyPcpMapCommand(state(), decodePcpMapRequest(packet),
    context());
  assert.equal(udp.mapping.transport, 'udp');
  assert.equal(udp.mapping.internal_port, 4662);
});

test('D06: optional PORT_SET is safely ignored by the single-mapping lifecycle', () => {
  const packet = vector('map_port_set_request');
  const portSet = decodePcpMapRequest(packet);
  const created = applyPcpMapCommand(state(), portSet, context());
  assert.equal(created.action, 'created');
  const response = encodePcpMapResponse(
    toPcpMapResponse(portSet, created, packet));
  assert.equal(response.length, 60);
});

test('D06: context is closed and rejects unsafe grants before model mutation', () => {
  for (const broken of [
    null,
    {},
    context({ secret: true }),
    context({ now_monotonic_ms: -0 }),
    context({ granted_lifetime_seconds: 0 }),
    context({ instance_id_digest: 'bad' }),
    context({ new_mapping: { mapping_id: 'x', external_address: 'bad!', external_port: 1 } }),
    context({ new_mapping: { mapping_id: 'x', external_address: '999.999.999.999', external_port: 1 } }),
    ...['0.0.0.0', '127.0.0.1', '169.254.1.1', '224.0.0.1',
      '255.255.255.255', '::', '::1', 'fe80::1', 'ff02::1']
      .map((external_address) => context({
        new_mapping: {
          mapping_id: 'x',
          external_address,
          external_port: 1,
        },
      })),
    context({ new_mapping: { mapping_id: 'x', external_address: '198.51.100.1', external_port: 0 } }),
    new Proxy(context(), {}),
  ]) {
    assert.throws(() => applyPcpMapCommand(state(), command(), broken),
      PcpMappingLifecycleError);
  }

  const base = command();
  const getter = { ...base };
  Object.defineProperty(getter, 'nonce', {
    enumerable: true,
    get() { throw new Error('secret'); },
  });
  for (const broken of [
    null,
    new Proxy(base, {}),
    { ...base, secret: true },
    getter,
    { ...base, protocol: 'natpmp' },
    { ...base, internal_port: 0 },
    { ...base, suggested_external_port: -1 },
    { ...base, suggested_external_address: {} },
    { ...base, client_address: '::::' },
  ]) {
    assert.throws(() => applyPcpMapCommand(state(), broken, context()),
      PcpMappingLifecycleError);
  }
  assert.throws(() => applyPcpMapCommand(state(), command(), context({
    now_monotonic_ms: Number.MAX_SAFE_INTEGER,
    granted_lifetime_seconds: 2,
  })), PcpMappingLifecycleError);
});

test('D06: address inputs are canonicalized before tuple and allocation use', () => {
  const applied = applyPcpMapCommand(state(), command(), context({
    new_mapping: {
      mapping_id: 'pcp-ipv6',
      external_address: '2001:0db8:0:0:0:0:0:1',
      external_port: 52144,
    },
  }));
  assert.equal(applied.mapping.external_address, '2001:db8::1');
});

test('D06: projects success, rejection and deletion through the strict MAP encoder', () => {
  const request = vector('map_tcp_request');
  const mapCommand = decodePcpMapRequest(request);
  const created = applyPcpMapCommand(state(), mapCommand, context());
  let descriptor = toPcpMapResponse(mapCommand, created, request);
  let wire = encodePcpMapResponse(descriptor);
  assert.deepEqual([...wire.subarray(0, 4)], [2, 0x81, 0, 0]);
  assert.equal(wire.readUInt16BE(42), 52144);
  assert.equal(wire.readUInt32BE(4), 3600);

  const otherPacket = Buffer.from(request);
  otherPacket[24] ^= 0xff;
  const otherCommand = decodePcpMapRequest(otherPacket);
  const rejected = applyPcpMapCommand(created.state, otherCommand,
    context({ now_monotonic_ms: 2000, new_mapping: null }));
  descriptor = toPcpMapResponse(otherCommand, rejected, otherPacket);
  wire = encodePcpMapResponse(descriptor);
  assert.equal(wire[3], 2);
  assert.equal(wire.readUInt32BE(4), 3599);
  assert.equal(wire.subarray(24, 36).toString('hex'), otherCommand.nonce);

  const deletion = deleteCommand();
  const deleted = applyPcpMapCommand(created.state, deletion, context({
    now_monotonic_ms: 2000,
    granted_lifetime_seconds: 0,
    new_mapping: null,
  }));
  descriptor = toPcpMapResponse(deletion, deleted,
    deletePacket());
  wire = encodePcpMapResponse(descriptor);
  assert.equal(wire.readUInt32BE(4), 0);
  assert.equal(wire.readUInt16BE(42), 0);
});

test('D06: response projection rejects forged lifecycle and hostile wire storage', () => {
  const mapCommand = command();
  assert.throws(() => toPcpMapResponse(mapCommand, {
    result_code: 0,
  }, vector('map_tcp_request')), PcpMappingLifecycleError);
  const created = applyPcpMapCommand(state(), mapCommand, context());
  const packet = vector('map_tcp_request');
  packet[24] ^= 0xff;
  const other = decodePcpMapRequest(packet);
  const rejected = applyPcpMapCommand(created.state, other,
    context({ now_monotonic_ms: 2000, new_mapping: null }));
  for (const wire of [
    null,
    Buffer.alloc(59),
    Buffer.alloc(60),
    Buffer.alloc(1104),
    new Proxy(packet, {}),
    new Uint8Array(new SharedArrayBuffer(60)),
  ]) {
    assert.throws(() => toPcpMapResponse(other, rejected, wire),
      PcpMappingLifecycleError);
  }
  assert.throws(() => toPcpMapResponse(other, created, packet),
    PcpMappingLifecycleError);
  assert.throws(() => toPcpMapResponse(other, rejected,
    vector('map_tcp_request')), PcpMappingLifecycleError);
});

test('D06: all-zero nonce completes create, renewal, response and delete', () => {
  const packet = vector('map_tcp_request');
  packet.fill(0, 24, 36);
  const zero = decodePcpMapRequest(packet);
  const created = applyPcpMapCommand(state(), zero, context());
  const renewed = applyPcpMapCommand(created.state, zero, context({
    now_monotonic_ms: 2000,
    new_mapping: null,
  }));
  let wire = encodePcpMapResponse(
    toPcpMapResponse(zero, renewed, packet));
  assert.equal(wire.subarray(24, 36).equals(Buffer.alloc(12)), true);
  const deletionPacket = Buffer.from(packet);
  deletionPacket.fill(0, 4, 8);
  deletionPacket.fill(0, 42, 60);
  const deletion = decodePcpMapRequest(deletionPacket);
  const deleted = applyPcpMapCommand(renewed.state, deletion, context({
    now_monotonic_ms: 3000,
    granted_lifetime_seconds: 0,
    new_mapping: null,
  }));
  wire = encodePcpMapResponse(
    toPcpMapResponse(deletion, deleted, deletionPacket));
  assert.equal(wire[3], 0);
  assert.equal(deleted.state.mappings.length, 0);
});

test('D06: incoherent PREFER_FAILURE command is rejected before mutation', () => {
  const base = command();
  for (const broken of [
    {
      ...base,
      suggested_external_port: 0,
      options: { prefer_failure: true, port_set: null },
    },
    {
      ...deleteCommand(),
      options: { prefer_failure: true, port_set: null },
    },
  ]) {
    const initial = state();
    assert.throws(() => applyPcpMapCommand(initial, broken, context()),
      PcpMappingLifecycleError);
    assert.equal(initial.mappings.length, 0);
  }
});

test('D06: D05 application composition creates, rejects wrong nonce and deletes', async () => {
  const socket = new EventEmitter();
  socket.sent = [];
  socket.bind = () => socket.emit('listening');
  socket.address = () => ({ address: '127.0.0.1', port: 9009 });
  socket.send = (packet, port, address, done) => {
    socket.sent.push(Buffer.from(packet));
    done();
  };
  socket.close = (done) => { if (done) done(); };
  let mappingState = state();
  let sequence = 0;
  const server = createPcpUdpServer({
    bind_address: '127.0.0.1',
    port: 0,
    allow_ephemeral_port_for_test: true,
    allowed_source_addresses: ['127.0.0.1'],
    epoch_provider: () => 42,
    event_sink: () => {},
    application(mapCommand, source, signal, request) {
      const transition = applyPcpMapCommand(mappingState, mapCommand, context({
        now_monotonic_ms: 1000 + sequence,
        granted_lifetime_seconds:
          mapCommand.operation === 'delete' ? 0 : 3600,
        new_mapping: mappingState.mappings.length === 0 &&
          mapCommand.operation === 'map' ? {
            mapping_id: 'pcp-wire-map',
            external_address: '198.51.100.1',
            external_port: 52144,
          } : null,
      }));
      sequence += 1;
      mappingState = transition.state;
      return toPcpMapResponse(mapCommand, transition, request.wire);
    },
  }, { socket_factory: () => socket });
  await server.start();
  const source = { address: '127.0.0.1', port: 1234 };
  socket.emit('message', loopbackPacket(), source);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(socket.sent[0][3], 0);
  assert.equal(mappingState.mappings.length, 1);

  const wrong = loopbackPacket();
  wrong[24] ^= 0xff;
  socket.emit('message', wrong, source);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(socket.sent[1][3], 2);
  assert.equal(mappingState.mappings.length, 1);

  const deletion = loopbackPacket();
  deletion.fill(0, 4, 8);
  deletion.fill(0, 42, 60);
  socket.emit('message', deletion, source);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(socket.sent[2][3], 0);
  assert.equal(socket.sent[2].readUInt32BE(4), 0);
  assert.equal(mappingState.mappings.length, 0);
  await server.close();
});
