'use strict';

const assert = require('node:assert/strict');
const { types } = require('node:util');
const test = require('node:test');
const {
  MappingModelError,
  createMappingState,
  renewMapping,
  restartMappingEpoch,
  snapshotInternalMappings,
} = require('../mapping_model');
const { decodePcpMapRequest } = require('../pcp_map_request_decoder');
const { encodePcpMapResponse } = require('../pcp_map_response_encoder');
const {
  applyPcpMapCommand,
  toPcpMapResponse,
} = require('../pcp_mapping_lifecycle');
const {
  GatewayEpochRestartError,
  completeGatewayResponse,
  createGatewayEpochState,
  restartGatewayEpoch,
} = require('../gateway_epoch_restart');
const { PCP_VECTORS } = require('../pcp_vectors');

const digest = 'a'.repeat(64);
function packet() {
  return Buffer.from(PCP_VECTORS.map_tcp_request.hex, 'hex');
}
function command() { return decodePcpMapRequest(packet()); }
function initialState() {
  return createMappingState({
    epoch: 10,
    generation: 4,
    mappings: [],
    baseline_mappings: [],
  });
}
function context(mappingId, externalPort, now = 1000) {
  return {
    now_monotonic_ms: now,
    client_id: 'client-1',
    instance_id_digest: digest,
    granted_lifetime_seconds: 3600,
    new_mapping: {
      mapping_id: mappingId,
      external_address: '198.51.100.1',
      external_port: externalPort,
    },
  };
}
function wireFor(transition, epoch) {
  const descriptor = toPcpMapResponse(command(), transition, packet());
  return encodePcpMapResponse({ ...descriptor, epoch });
}
function gatewayState(mappingState, pending = []) {
  return createGatewayEpochState(mappingState, pending);
}
function pending(id, epoch = 10, generation = 4) {
  return { response_id: id, epoch, generation };
}

test('D07: epoch restart clears mappings, cancels pending responses and advances generation once', () => {
  const created = applyPcpMapCommand(initialState(), command(),
    context('pcp-old', 52144));
  const current = gatewayState(created.state, [
    pending('response-2'),
    pending('response-1'),
  ]);
  const restarted = restartGatewayEpoch(current, {
    restart_seconds: 1,
  });
  assert.equal(created.state.epoch, 10);
  assert.equal(created.state.generation, 4);
  assert.equal(restarted.state.mapping_state.epoch, 1);
  assert.equal(restarted.state.mapping_state.generation, 5);
  assert.deepEqual(snapshotInternalMappings(restarted.state.mapping_state), []);
  assert.deepEqual(restarted.state.pending_responses, []);
  assert.deepEqual(restarted.effects, [
    { type: 'CANCEL_RESPONSE', response_id: 'response-2' },
    { type: 'CANCEL_RESPONSE', response_id: 'response-1' },
  ]);
  assert.deepEqual(restarted.event, {
    event: 'gateway_restarted',
    previous_epoch: 10,
    epoch: 1,
    previous_generation: 4,
    generation: 5,
    removed_mapping_count: 1,
    invalidated_response_count: 2,
  });
  assert.ok(Object.isFrozen(restarted));
  assert.ok(Object.isFrozen(restarted.effects));
  assert.ok(Object.isFrozen(restarted.event));
});

test('D07: old response remains epoch 10 while recovery creates a fresh epoch 1 mapping', () => {
  const oldMapping = applyPcpMapCommand(initialState(), command(),
    context('pcp-old', 52144));
  const oldWire = wireFor(oldMapping, 10);
  const current = gatewayState(oldMapping.state, [
    pending('response-old'),
  ]);
  const restarted = restartGatewayEpoch(current, {
    restart_seconds: 1,
  });
  const late = completeGatewayResponse(restarted.state,
    pending('response-old'));
  assert.equal(late.accepted, false);
  assert.equal(late.reason_code, 'stale-generation');
  assert.deepEqual(late.effects, []);
  assert.equal(late.state, restarted.state);

  const recovered = applyPcpMapCommand(restarted.state.mapping_state, command(),
    context('pcp-new', 52145, 2000));
  const newWire = wireFor(recovered, 1);

  assert.equal(oldWire.readUInt32BE(8), 10);
  assert.equal(newWire.readUInt32BE(8), 1);
  assert.equal(recovered.action, 'created');
  assert.equal(recovered.mapping.mapping_id, 'pcp-new');
  assert.equal(recovered.mapping.external_port, 52145);
  assert.equal(recovered.mapping.epoch, 1);
  assert.equal(recovered.mapping.generation, 5);
  assert.deepEqual(recovered.state.mappings.map((item) => item.mapping_id),
    ['pcp-new']);
});

test('D07: stale epoch and generation cannot mutate or revive the restarted snapshot', () => {
  const oldMapping = applyPcpMapCommand(initialState(), command(),
    context('pcp-old', 52144));
  const restarted = restartGatewayEpoch(gatewayState(oldMapping.state), {
    restart_seconds: 1,
  });
  assert.throws(() => renewMapping(restarted.state.mapping_state, {
    mapping_id: 'pcp-old',
    epoch: 10,
    generation: 4,
    owner: oldMapping.mapping.owner,
    lifetime_seconds: 3600,
    now_monotonic_ms: 2000,
  }), (error) => error instanceof MappingModelError &&
    error.reason_code === 'STALE_EPOCH');
  assert.deepEqual(snapshotInternalMappings(restarted.state.mapping_state), []);
});

test('D07: baseline is retained only for deterministic reset and is not made active by restart', () => {
  const dynamic = applyPcpMapCommand(initialState(), command(),
    context('pcp-old', 52144));
  const stateWithBaseline = createMappingState({
    epoch: 10,
    generation: 4,
    mappings: dynamic.state.mappings,
    baseline_mappings: dynamic.state.mappings,
  });
  const restarted = restartGatewayEpoch(gatewayState(stateWithBaseline), {
    restart_seconds: 0,
  });
  assert.deepEqual(snapshotInternalMappings(restarted.state.mapping_state), []);
  assert.equal(restarted.state.mapping_state.baseline_mappings.length, 1);
});

test('D07: closed restart input rejects malformed, hostile and ambiguous response queues', () => {
  const state = initialState();
  const hostile = new Proxy({ restart_seconds: 1 },
    { get() { throw new Error('must not execute'); } });
  const sparse = [];
  sparse.length = 1;
  const decorated = [];
  decorated.note = 'not-an-id';
  const hiddenIndex = [];
  hiddenIndex['4294967295'] = pending('hidden');
  const accessorQueue = [];
  Object.defineProperty(accessorQueue, '0', {
    enumerable: true,
    get() { throw new Error('must not execute'); },
  });
  const tooMany = Array.from({ length: 4097 },
    (_, index) => pending(`response-${index}`));
  const revokedObject = Proxy.revocable({}, {});
  revokedObject.revoke();
  const accessor = { restart_seconds: 1 };
  Object.defineProperty(accessor, 'restart_seconds', {
    enumerable: true,
    get() { throw new Error('must not execute'); },
  });
  for (const input of [
    null,
    {},
    { restart_seconds: 1, extra: true },
    { restart_seconds: -0 },
    { restart_seconds: -1 },
    { restart_seconds: 0x100000000 },
    hostile,
    revokedObject.proxy,
    accessor,
  ]) {
    assert.throws(() => restartGatewayEpoch(gatewayState(state), input),
      GatewayEpochRestartError);
  }
  for (const queue of [
    {},
    sparse,
    decorated,
    hiddenIndex,
    accessorQueue,
    [pending('same'), pending('same')],
    [pending('bad', 9, 4)],
    [pending('bad', 10, 3)],
    [{ response_id: 'bad value', epoch: 10, generation: 4 }],
    [{ response_id: 'Uppercase', epoch: 10, generation: 4 }],
    tooMany,
  ]) {
    assert.throws(() => createGatewayEpochState(state, queue),
      GatewayEpochRestartError);
  }
  assert.throws(() => createGatewayEpochState({}, []), MappingModelError);
});

test('D07: generation exhaustion fails closed without touching the prior state', () => {
  const exhausted = createMappingState({
    epoch: 10,
    generation: Number.MAX_SAFE_INTEGER,
    mappings: [],
  });
  assert.throws(() => restartGatewayEpoch(gatewayState(exhausted), {
    restart_seconds: 1,
  }), (error) => error instanceof MappingModelError &&
    error.reason_code === 'GENERATION_EXHAUSTED');
  assert.equal(exhausted.epoch, 10);
  assert.equal(exhausted.generation, Number.MAX_SAFE_INTEGER);
  assert.deepEqual(snapshotInternalMappings(exhausted), []);
  assert.throws(() => restartMappingEpoch(initialState(),
    { restart_seconds: -0 }),
  (error) => error instanceof MappingModelError &&
    error.reason_code === 'MAPPING_FIELD_INVALID');
});

test('D07: foreign typed arrays and proxies are rejected before queue reflection', () => {
  assert.equal(types.isProxy(new Proxy([], {})), true);
  const proxiedQueue = new Proxy([], {
    getOwnPropertyDescriptor() { throw new Error('must not execute'); },
  });
  assert.throws(() => createGatewayEpochState(initialState(), proxiedQueue),
    GatewayEpochRestartError);
  const revokedQueue = Proxy.revocable([], {});
  revokedQueue.revoke();
  assert.throws(() => createGatewayEpochState(initialState(),
    revokedQueue.proxy), GatewayEpochRestartError);
});

test('D07: completion accepts only a currently queued response and consumes it once', () => {
  const current = gatewayState(initialState(), [
    pending('response-current'),
  ]);
  const sent = completeGatewayResponse(current, pending('response-current'));
  assert.equal(sent.accepted, true);
  assert.equal(sent.reason_code, 'none');
  assert.deepEqual(sent.effects, [{
    type: 'SEND_RESPONSE',
    response_id: 'response-current',
  }]);
  assert.deepEqual(sent.state.pending_responses, []);
  const repeated = completeGatewayResponse(sent.state,
    pending('response-current'));
  assert.equal(repeated.accepted, false);
  assert.equal(repeated.reason_code, 'not-found');
  const wrongEpoch = completeGatewayResponse(current,
    pending('response-current', 9, 4));
  assert.equal(wrongEpoch.reason_code, 'stale-epoch');
});
