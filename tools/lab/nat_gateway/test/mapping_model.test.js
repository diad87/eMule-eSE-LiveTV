'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  MappingModelError,
  createMappingState,
  createMapping,
  renewMapping,
  expireMappings,
  deleteMapping,
  resetMappingState,
  snapshotInternalMappings
} = require('../mapping_model');

const digest = 'a'.repeat(64);

function owner(kind = 'upnp-journal') {
  if (kind === 'none') return { kind: 'none' };
  if (kind === 'pcp-nonce') return { kind, instance_id_digest: digest, nonce: 'b'.repeat(24) };
  if (kind === 'natpmp-lease-scope') return { kind, instance_id_digest: digest, scope_id: 'scope-1' };
  return { kind, instance_id_digest: digest, gateway_identity_digest: digest, description: 'lab-map' };
}

function mapping(id, overrides = {}) {
  return {
    mapping_id: id,
    protocol: 'upnp',
    transport: 'tcp',
    client_id: 'client-1',
    internal_address: '192.0.2.10',
    internal_port: 4662,
    requested_external_port: 4662,
    external_address: '192.0.2.1',
    external_port: 4662,
    lease: { lifetime_seconds: 60, created_monotonic_ms: 1000, expires_monotonic_ms: 61000 },
    owner: owner(),
    epoch: 10,
    generation: 4,
    ...overrides
  };
}

function state(mappings = [], baselineMappings = mappings) {
  return createMappingState({ epoch: 10, generation: 4, mappings, baseline_mappings: baselineMappings });
}

function expectError(action, reasonCode, fieldPath) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof MappingModelError);
    assert.equal(error.reason_code, reasonCode);
    assert.equal(error.field_path, fieldPath);
    return true;
  });
}

function hostileProxy(target, secret = 'proxy-secret') {
  let traps = 0;
  const trap = () => { traps += 1; throw new Error(secret); };
  return {
    value: new Proxy(target, {
      get: trap,
      getOwnPropertyDescriptor: trap,
      getPrototypeOf: trap,
      ownKeys: trap,
      has: trap
    }),
    get traps() { return traps; }
  };
}

test('RED: creates a mapping without mutating state or its caller input', () => {
  const initial = state();
  const input = mapping('map-1');
  const before = structuredClone(input);
  const result = createMapping(initial, input);
  assert.equal(result.ok, true);
  assert.equal(result.mapping.mapping_id, 'map-1');
  assert.notEqual(result.state, initial);
  assert.equal(initial.mappings.length, 0);
  assert.deepEqual(input, before);
  assert.ok(Object.isFrozen(result.state));
  assert.ok(Object.isFrozen(result.state.mappings[0]));
});

test('RED: collision is semantic, IPv6 canonical, while TCP and UDP remain separate spaces', () => {
  const first = mapping('map-a', { external_address: '2001:0db8:0:0:0:0:0:1' });
  const initial = state([first]);
  expectError(() => createMapping(initial, mapping('map-b', { external_address: '2001:db8::1' })), 'MAPPING_COLLISION', '$.external_address');
  const udp = createMapping(initial, mapping('map-b', { transport: 'udp', external_address: '2001:db8::1' }));
  assert.equal(udp.ok, true);
  assert.equal(udp.state.mappings.length, 2);
});

test('RED: renewal preserves mapping identity and generation and changes only the lease', () => {
  const initialMapping = mapping('map-1');
  const initial = state([initialMapping]);
  const result = renewMapping(initial, {
    mapping_id: 'map-1', epoch: 10, generation: 4, owner: owner(),
    lifetime_seconds: 30, now_monotonic_ms: 2000
  });
  assert.equal(result.ok, true);
  assert.equal(result.mapping.mapping_id, 'map-1');
  assert.equal(result.mapping.generation, 4);
  assert.deepEqual(result.mapping.lease, { lifetime_seconds: 30, created_monotonic_ms: 2000, expires_monotonic_ms: 32000 });
  assert.deepEqual(initial.mappings[0], initialMapping);
});

test('RED: permanent mappings never expire, and finite mappings expire exactly at their deadline', () => {
  const finite = mapping('finite', { lease: { lifetime_seconds: 1, created_monotonic_ms: 1000, expires_monotonic_ms: 2000 } });
  const permanent = mapping('permanent', { transport: 'udp', external_port: 4663, lease: { lifetime_seconds: 0, created_monotonic_ms: 1000, expires_monotonic_ms: null } });
  const initial = state([finite, permanent]);
  assert.equal(expireMappings(initial, 1999).state.mappings.length, 2);
  const expired = expireMappings(initial, 2000);
  assert.equal(expired.ok, true);
  assert.deepEqual(expired.expired_mapping_ids, ['finite']);
  assert.deepEqual(expired.state.mappings.map((item) => item.mapping_id), ['permanent']);
});

test('RED: renewal and deletion fail closed for mismatched owner, stale epoch and stale generation', () => {
  const initial = state([mapping('map-1')]);
  const wrongOwner = owner(); wrongOwner.description = 'other-map';
  expectError(() => renewMapping(initial, { mapping_id: 'map-1', epoch: 10, generation: 4, owner: wrongOwner, lifetime_seconds: 1, now_monotonic_ms: 2000 }), 'OWNERSHIP_MISMATCH', '$.owner');
  expectError(() => renewMapping(initial, { mapping_id: 'map-1', epoch: 9, generation: 4, owner: owner(), lifetime_seconds: 1, now_monotonic_ms: 2000 }), 'STALE_EPOCH', '$.epoch');
  expectError(() => deleteMapping(initial, { mapping_id: 'map-1', epoch: 10, generation: 3, owner: owner() }), 'STALE_GENERATION', '$.generation');
  const removed = deleteMapping(initial, { mapping_id: 'map-1', epoch: 10, generation: 4, owner: owner() });
  assert.equal(removed.ok, true);
  assert.equal(removed.state.mappings.length, 0);
});

test('RED: ownership comparison is semantic rather than dependent on property insertion order', () => {
  const initial = state([mapping('map-1')]);
  const reorderedOwner = {
    description: 'lab-map',
    gateway_identity_digest: digest,
    instance_id_digest: digest,
    kind: 'upnp-journal'
  };
  const result = renewMapping(initial, {
    mapping_id: 'map-1', epoch: 10, generation: 4, owner: reorderedOwner,
    lifetime_seconds: 1, now_monotonic_ms: 2000
  });
  assert.equal(result.ok, true);
});

test('RED: reset restores the deterministic baseline with a strictly increasing explicitly supplied generation', () => {
  const baseline = [mapping('base')];
  const initial = state([mapping('temporary')], baseline);
  const reset = resetMappingState(initial, { generation: 5, epoch: 11 });
  assert.equal(reset.ok, true);
  assert.equal(reset.state.generation, 5);
  assert.equal(reset.state.epoch, 11);
  assert.deepEqual(snapshotInternalMappings(reset.state).map((item) => item.mapping_id), ['base']);
  assert.equal(snapshotInternalMappings(reset.state)[0].generation, 5);
  assert.equal(snapshotInternalMappings(reset.state)[0].epoch, 11);
  expectError(() => resetMappingState(initial, { generation: 4, epoch: 11 }), 'GENERATION_NOT_INCREASING', '$.generation');
});

test('RED: snapshots are deterministic, ordered and never report a partial atomic group as successful', () => {
  const first = mapping('z-map', { atomic_group_id: 'pair-1' });
  const second = mapping('a-map', { transport: 'udp', external_port: 4663, atomic_group_id: 'pair-1' });
  const partial = state([first]);
  assert.equal(snapshotInternalMappings(partial)[0].atomic_group_status, 'partial');
  const complete = createMapping(partial, second);
  assert.deepEqual(snapshotInternalMappings(complete.state).map((item) => item.mapping_id), ['a-map', 'z-map']);
  assert.ok(snapshotInternalMappings(complete.state).every((item) => item.atomic_group_status === 'complete'));
  assert.notEqual(snapshotInternalMappings(complete.state), snapshotInternalMappings(complete.state));
});

test('RED: atomic groups correlate transports without imposing equal ports, leases or PCP nonces', () => {
  const tcp = mapping('tcp-map', {
    protocol: 'pcp', atomic_group_id: 'pair-1', owner: owner('pcp-nonce')
  });
  const udp = mapping('udp-map', {
    protocol: 'pcp', transport: 'udp', external_port: 4663, internal_port: 4663,
    requested_external_port: 4663, atomic_group_id: 'pair-1',
    owner: { kind: 'pcp-nonce', instance_id_digest: digest, nonce: 'c'.repeat(24) },
    lease: { lifetime_seconds: 7, created_monotonic_ms: 2000, expires_monotonic_ms: 9000 }
  });
  const result = createMapping(state([tcp]), udp);
  assert.equal(result.atomic_group_status, 'complete');
  assert.ok(snapshotInternalMappings(result.state).every((item) => item.atomic_group_status === 'complete'));
});

test('RED: active mapping state cannot lie about its epoch or generation', () => {
  expectError(() => createMappingState({ epoch: 10, generation: 4, mappings: [mapping('map-1', { epoch: 9 })] }), 'STATE_MAPPING_EPOCH_MISMATCH', '$.mappings[0].epoch');
  expectError(() => createMappingState({ epoch: 10, generation: 4, mappings: [mapping('map-1', { generation: 3 })] }), 'STATE_MAPPING_GENERATION_MISMATCH', '$.mappings[0].generation');
});

test('RED: renewal and deletion require demonstrated ownership, never none or an omitted proof', () => {
  const unproven = state([mapping('none-owner', { owner: owner('none') })]);
  expectError(() => renewMapping(unproven, { mapping_id: 'none-owner', epoch: 10, generation: 4, owner: owner('none'), lifetime_seconds: 1, now_monotonic_ms: 2000 }), 'OWNERSHIP_UNPROVEN', '$.owner');
  expectError(() => deleteMapping(unproven, { mapping_id: 'none-owner', epoch: 10, generation: 4, owner: owner('none') }), 'OWNERSHIP_UNPROVEN', '$.owner');
  const proven = state([mapping('proven')]);
  expectError(() => renewMapping(proven, { mapping_id: 'proven', epoch: 10, generation: 4, lifetime_seconds: 1, now_monotonic_ms: 2000 }), 'OWNERSHIP_UNPROVEN', '$.owner');
  expectError(() => deleteMapping(proven, { mapping_id: 'proven', epoch: 10, generation: 4 }), 'OWNERSHIP_UNPROVEN', '$.owner');
  expectError(() => deleteMapping(proven, { mapping_id: 'proven', epoch: 10, generation: 4, owner: owner('none') }), 'OWNERSHIP_UNPROVEN', '$.owner');
  const ownerless = mapping('ownerless'); delete ownerless.owner;
  expectError(() => deleteMapping(state([ownerless]), { mapping_id: 'ownerless', epoch: 10, generation: 4, owner: owner() }), 'OWNERSHIP_UNPROVEN', '$.owner');
});

test('RED: renewals cannot move time backwards or resurrect a finite expired lease', () => {
  const initial = state([mapping('map-1', { lease: { lifetime_seconds: 1, created_monotonic_ms: 1000, expires_monotonic_ms: 2000 } })]);
  const request = { mapping_id: 'map-1', epoch: 10, generation: 4, owner: owner(), lifetime_seconds: 1 };
  expectError(() => renewMapping(initial, { ...request, now_monotonic_ms: 999 }), 'LEASE_TIME_REGRESSION', '$.now_monotonic_ms');
  expectError(() => renewMapping(initial, { ...request, now_monotonic_ms: 2000 }), 'LEASE_EXPIRED', '$.now_monotonic_ms');
});

test('RED: atomic groups reject duplicate transport, more than two members and incoherent completed identity', () => {
  const tcp = mapping('tcp-map', { atomic_group_id: 'pair-1' });
  expectError(() => createMapping(state([tcp]), mapping('tcp-second', { external_port: 4663, atomic_group_id: 'pair-1' })), 'ATOMIC_GROUP_DUPLICATE_TRANSPORT', '$.mappings[1].atomic_group_id');
  const udp = mapping('udp-map', { transport: 'udp', external_port: 4663, atomic_group_id: 'pair-1' });
  const completed = state([tcp, udp]);
  expectError(() => createMapping(completed, mapping('third-map', { transport: 'udp', external_port: 4664, atomic_group_id: 'pair-1' })), 'ATOMIC_GROUP_TOO_MANY', '$.mappings[2].atomic_group_id');
  expectError(() => state([tcp, mapping('bad-client', { transport: 'udp', external_port: 4663, atomic_group_id: 'pair-1', client_id: 'client-2' })]), 'ATOMIC_GROUP_INCOHERENT', '$.mappings[1].client_id');
});

test('RED: internal snapshot ordering is ordinal ASCII and explicitly raw', () => {
  const snapshot = snapshotInternalMappings(state([mapping('z-map'), mapping('a-map', { transport: 'udp', external_port: 4663 }), mapping('a.map', { transport: 'tcp', external_port: 4664 })]));
  assert.deepEqual(snapshot.map((item) => item.mapping_id), ['a-map', 'a.map', 'z-map']);
  assert.equal(snapshot[0].external_address, '192.0.2.1');
});

test('RED: hostile or malformed input is rejected without evaluating behavior or leaking partial state', () => {
  const initial = state();
  expectError(() => createMapping(initial, null), 'MAPPING_INPUT_INVALID', '$');
  const getter = mapping('map-1');
  Object.defineProperty(getter, 'external_address', { enumerable: true, get() { throw new Error('must not execute'); } });
  expectError(() => createMapping(initial, getter), 'MAPPING_INPUT_INVALID', '$.external_address');
  expectError(() => createMapping(initial, mapping('map-1', { lease: { lifetime_seconds: 1, created_monotonic_ms: 1, expires_monotonic_ms: 3 } })), 'LEASE_EXPIRY_MISMATCH', '$.lease.expires_monotonic_ms');
  expectError(() => createMapping(initial, mapping('map-1', { external_port: 65536 })), 'MAPPING_FIELD_INVALID', '$.external_port');
  assert.equal(initial.mappings.length, 0);
});

test('RED: cloning rejects root and nested proxies before any trap executes', () => {
  const root = hostileProxy({ epoch: 10, generation: 4, mappings: [] });
  expectError(() => createMappingState(root.value), 'MAPPING_INPUT_INVALID', '$');
  assert.equal(root.traps, 0);

  const initial = state();
  const input = mapping('map-1');
  const nested = hostileProxy(input.owner);
  input.owner = nested.value;
  let error;
  assert.throws(() => createMapping(initial, input), (caught) => { error = caught; return true; });
  assert.ok(error instanceof MappingModelError);
  assert.equal(error.reason_code, 'MAPPING_INPUT_INVALID');
  assert.equal(error.field_path, '$.owner');
  assert.equal(nested.traps, 0);
  assert.ok(!error.message.includes('proxy-secret'));

  const request = hostileProxy({ mapping_id: 'missing', epoch: 10, generation: 4, owner: owner(), lifetime_seconds: 1, now_monotonic_ms: 2000 });
  expectError(() => renewMapping(initial, request.value), 'MAPPING_INPUT_INVALID', '$');
  assert.equal(request.traps, 0);
});

test('RED: input cloning and structural validation fail closed across hostile JSON shapes', () => {
  const base = { epoch: 10, generation: 4, mappings: [] };
  const customArray = []; customArray.extra = true;
  expectError(() => createMappingState({ ...base, mappings: customArray }), 'MAPPING_INPUT_INVALID', '$.mappings');
  const sparse = []; sparse[1] = mapping('map-1');
  expectError(() => createMappingState({ ...base, mappings: sparse }), 'MAPPING_INPUT_INVALID', '$.mappings[0]');
  const inherited = Object.create({ inherited: true }); Object.assign(inherited, base);
  expectError(() => createMappingState(inherited), 'MAPPING_INPUT_INVALID', '$');
  const symbolInput = { ...base }; symbolInput[Symbol('x')] = true;
  expectError(() => createMappingState(symbolInput), 'MAPPING_INPUT_INVALID', '$');
  const toJson = { ...base, toJSON() { return base; } };
  expectError(() => createMappingState(toJson), 'MAPPING_INPUT_INVALID', '$.toJSON');
  const cycle = { ...base }; cycle.self = cycle;
  expectError(() => createMappingState(cycle), 'MAPPING_INPUT_INVALID', '$.*');
  expectError(() => createMappingState(null), 'MAPPING_FIELD_INVALID', '$');
  expectError(() => createMappingState({ epoch: 10, generation: 4, mappings: {}, unknown: true }), 'MAPPING_FIELD_UNKNOWN', '$.*');
  const secretKey = 'token-secret-payload-credential-123456';
  const secretNamed = { epoch: 10, generation: 4, mappings: [], [secretKey]: true };
  assert.throws(() => createMappingState(secretNamed), (error) => {
    assert.equal(error.reason_code, 'MAPPING_FIELD_UNKNOWN');
    assert.equal(error.field_path, '$.*');
    assert.equal(error.message.includes(secretKey), false);
    return true;
  });
});

test('RED: mapping validation covers IDs, protocols, ownership variants and precise lease arithmetic', () => {
  const initial = state();
  expectError(() => createMapping(initial, mapping('Bad')), 'MAPPING_FIELD_INVALID', '$.mapping_id');
  expectError(() => createMapping(initial, mapping('map-1', { protocol: 'other' })), 'MAPPING_FIELD_INVALID', '$.protocol');
  expectError(() => createMapping(initial, mapping('map-1', { transport: 'sctp' })), 'MAPPING_FIELD_INVALID', '$.transport');
  expectError(() => createMapping(initial, mapping('map-1', { client_id: '' })), 'MAPPING_FIELD_INVALID', '$.client_id');
  expectError(() => createMapping(initial, mapping('map-1', { internal_address: 'not-an-ip' })), 'MAPPING_FIELD_INVALID', '$.internal_address');
  expectError(() => createMapping(initial, mapping('map-1', { external_address: 'not-an-ip' })), 'MAPPING_FIELD_INVALID', '$.external_address');
  expectError(() => createMapping(initial, mapping('map-1', { external_address: 1234 })), 'MAPPING_FIELD_INVALID', '$.external_address');
  expectError(() => createMapping(initial, mapping('map-1', { internal_port: 0 })), 'MAPPING_FIELD_INVALID', '$.internal_port');
  expectError(() => createMapping(initial, mapping('map-1', { requested_external_port: -1 })), 'MAPPING_FIELD_INVALID', '$.requested_external_port');
  expectError(() => createMapping(initial, mapping('map-1', { owner: { kind: 'other' } })), 'MAPPING_FIELD_INVALID', '$.owner.kind');
  expectError(() => createMapping(initial, mapping('map-1', { owner: { kind: 'pcp-nonce', instance_id_digest: 'x', nonce: 'b'.repeat(24) } })), 'MAPPING_FIELD_INVALID', '$.owner.instance_id_digest');
  expectError(() => createMapping(initial, mapping('map-1', { owner: { kind: 'pcp-nonce', instance_id_digest: digest, nonce: 'bad' } })), 'MAPPING_FIELD_INVALID', '$.owner.nonce');
  expectError(() => createMapping(initial, mapping('map-1', { owner: { kind: 'natpmp-lease-scope', instance_id_digest: digest, scope_id: 'Bad' } })), 'MAPPING_FIELD_INVALID', '$.owner.scope_id');
  expectError(() => createMapping(initial, mapping('map-1', { lease: { lifetime_seconds: 0, created_monotonic_ms: 1, expires_monotonic_ms: 1 } })), 'LEASE_EXPIRY_MISMATCH', '$.lease.expires_monotonic_ms');
  expectError(() => createMapping(initial, mapping('map-1', { lease: { lifetime_seconds: 1, created_monotonic_ms: Number.MAX_SAFE_INTEGER, expires_monotonic_ms: Number.MAX_SAFE_INTEGER } })), 'LEASE_EXPIRY_OVERFLOW', '$.lease');
});

test('RED: owner proof is protocol-bound for state, create, renew, and delete while none remains unproven', () => {
  const initial = state();
  expectError(() => createMapping(initial, mapping('map-1', { owner: owner('pcp-nonce') })), 'OWNER_PROTOCOL_MISMATCH', '$.owner.kind');
  expectError(() => createMappingState({ epoch: 10, generation: 4, mappings: [mapping('map-1', { protocol: 'pcp', owner: owner('upnp-journal') })] }), 'OWNER_PROTOCOL_MISMATCH', '$.mappings[0].owner.kind');

  const pcpMapping = mapping('pcp-map', { protocol: 'pcp', owner: owner('pcp-nonce') });
  const pcpState = state([pcpMapping]);
  expectError(() => renewMapping(pcpState, { mapping_id: 'pcp-map', epoch: 10, generation: 4, owner: owner('upnp-journal'), lifetime_seconds: 1, now_monotonic_ms: 2000 }), 'OWNER_PROTOCOL_MISMATCH', '$.owner.kind');
  expectError(() => deleteMapping(pcpState, { mapping_id: 'pcp-map', epoch: 10, generation: 4, owner: owner('natpmp-lease-scope') }), 'OWNER_PROTOCOL_MISMATCH', '$.owner.kind');

  const unproven = createMapping(initial, mapping('none-map', { owner: owner('none') })).state;
  expectError(() => renewMapping(unproven, { mapping_id: 'none-map', epoch: 10, generation: 4, owner: owner('none'), lifetime_seconds: 1, now_monotonic_ms: 2000 }), 'OWNERSHIP_UNPROVEN', '$.owner');
  expectError(() => deleteMapping(unproven, { mapping_id: 'none-map', epoch: 10, generation: 4, owner: owner('none') }), 'OWNERSHIP_UNPROVEN', '$.owner');
});

test('RED: operation error paths stay fail-closed and ownership/delete paths are fully exercised', () => {
  expectError(() => snapshotInternalMappings({}), 'STATE_INVALID', '$');
  const initial = state([mapping('map-1')]);
  expectError(() => createMapping(initial, mapping('map-1')), 'MAPPING_ID_EXISTS', '$.mapping_id');
  expectError(() => createMapping(initial, mapping('map-2', { epoch: 9 })), 'STALE_EPOCH', '$.epoch');
  expectError(() => createMapping(initial, mapping('map-2', { generation: 3 })), 'STALE_GENERATION', '$.generation');
  expectError(() => renewMapping(initial, { mapping_id: 'missing', epoch: 10, generation: 4, owner: owner(), lifetime_seconds: 1, now_monotonic_ms: 2000 }), 'MAPPING_NOT_FOUND', '$.mapping_id');
  expectError(() => deleteMapping(initial, { mapping_id: 'missing', epoch: 10, generation: 4, owner: owner() }), 'MAPPING_NOT_FOUND', '$.mapping_id');
  const permanent = state([mapping('permanent', { lease: { lifetime_seconds: 0, created_monotonic_ms: 1, expires_monotonic_ms: null } })]);
  expectError(() => renewMapping(permanent, { mapping_id: 'permanent', epoch: 10, generation: 4, owner: owner(), lifetime_seconds: 1, now_monotonic_ms: Number.MAX_SAFE_INTEGER }), 'LEASE_EXPIRY_OVERFLOW', '$.lifetime_seconds');
  const pair = state([mapping('tcp-map', { atomic_group_id: 'pair-1' })]);
  const deleted = deleteMapping(pair, { mapping_id: 'tcp-map', epoch: 10, generation: 4, owner: owner() });
  assert.equal(deleted.atomic_group_status, 'partial');
  const ownerMismatch = mapping('udp-map', { transport: 'udp', external_port: 4663, atomic_group_id: 'pair-1', owner: { kind: 'upnp-journal', instance_id_digest: 'b'.repeat(64), gateway_identity_digest: digest, description: 'lab-map' } });
  expectError(() => state([pair.mappings[0], ownerMismatch]), 'ATOMIC_GROUP_INCOHERENT', '$.mappings[1].owner.instance_id_digest');
});
