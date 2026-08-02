'use strict';

const { types } = require('node:util');
const { normalizeAddress } = require('./address');

const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const ID_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const PROTOCOLS = new Set(['upnp', 'pcp', 'natpmp']);
const TRANSPORTS = new Set(['tcp', 'udp']);
const SAFE_FIELD_NAMES = new Set([
  'epoch', 'generation', 'mappings', 'baseline_mappings', 'mapping_id',
  'protocol', 'transport', 'client_id', 'internal_address', 'internal_port',
  'requested_external_port', 'external_address', 'external_port', 'lease',
  'owner', 'atomic_group_id', 'lifetime_seconds', 'created_monotonic_ms',
  'expires_monotonic_ms', 'kind', 'instance_id_digest',
  'gateway_identity_digest', 'description', 'nonce', 'scope_id',
  'now_monotonic_ms', 'toJSON'
]);
const stateBrand = new WeakSet();

class MappingModelError extends Error {
  constructor(reasonCode, fieldPath, detail) {
    super(`${reasonCode} at ${fieldPath}: ${detail}`);
    this.name = 'MappingModelError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath, detail) {
  throw new MappingModelError(reasonCode, fieldPath, detail);
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function cloneJsonData(value, fieldPath, ancestors = new WeakSet()) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('MAPPING_INPUT_INVALID', fieldPath, 'numbers must be finite JSON data');
    return value;
  }
  // Reject before reflection so no Proxy trap can execute or leak its error.
  if (types.isProxy(value)) fail('MAPPING_INPUT_INVALID', fieldPath, 'proxies are not JSON data');
  if (typeof value !== 'object' || value === null) fail('MAPPING_INPUT_INVALID', fieldPath, 'value must be JSON data');
  if (ancestors.has(value)) fail('MAPPING_INPUT_INVALID', fieldPath, 'cyclic input is not accepted');
  ancestors.add(value);
  let copy;
  if (Array.isArray(value)) {
    copy = [];
    const names = Object.getOwnPropertyNames(value);
    if (Object.getOwnPropertySymbols(value).length || names.some((name) => name !== 'length' && !/^(0|[1-9]\d*)$/.test(name))) {
      ancestors.delete(value);
      fail('MAPPING_INPUT_INVALID', fieldPath, 'arrays must contain only dense JSON values');
    }
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !hasOwn(descriptor, 'value')) {
        ancestors.delete(value);
        fail('MAPPING_INPUT_INVALID', `${fieldPath}[${index}]`, 'arrays must contain data properties');
      }
      copy.push(cloneJsonData(descriptor.value, `${fieldPath}[${index}]`, ancestors));
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      ancestors.delete(value);
      fail('MAPPING_INPUT_INVALID', fieldPath, 'objects must have a plain prototype');
    }
    if (Object.getOwnPropertySymbols(value).length) {
      ancestors.delete(value);
      fail('MAPPING_INPUT_INVALID', fieldPath, 'objects cannot have symbol properties');
    }
    copy = {};
    for (const key of Object.getOwnPropertyNames(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      const keyPath = SAFE_FIELD_NAMES.has(key) ? `${fieldPath}.${key}` : `${fieldPath}.*`;
      if (!descriptor || !descriptor.enumerable || !hasOwn(descriptor, 'value') || key === 'toJSON') {
        ancestors.delete(value);
        fail('MAPPING_INPUT_INVALID', keyPath, 'objects must contain enumerable data properties');
      }
      Object.defineProperty(copy, key, {
        value: cloneJsonData(descriptor.value, keyPath, ancestors),
        enumerable: true,
        writable: true,
        configurable: true
      });
    }
  }
  ancestors.delete(value);
  return copy;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function assertExactKeys(value, required, optional, fieldPath) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('MAPPING_FIELD_INVALID', fieldPath, 'must be an object');
  for (const key of required) {
    if (!hasOwn(value, key)) fail('MAPPING_FIELD_REQUIRED', `${fieldPath}.${key}`, 'is required');
  }
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail('MAPPING_FIELD_UNKNOWN', `${fieldPath}.*`, 'unknown field is not allowed');
  }
}

function assertId(value, fieldPath) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64 || !ID_PATTERN.test(value)) {
    fail('MAPPING_FIELD_INVALID', fieldPath, 'must be a stable identifier');
  }
}

function assertPort(value, fieldPath, allowZero) {
  if (!Number.isInteger(value) || value < (allowZero ? 0 : 1) || value > 65535) {
    fail('MAPPING_FIELD_INVALID', fieldPath, 'must be a valid port');
  }
}

function assertUint(value, maximum, fieldPath) {
  if (!Number.isInteger(value) || value < 0 || value > maximum) fail('MAPPING_FIELD_INVALID', fieldPath, 'must be an unsigned safe integer');
}

function validateOwner(value, fieldPath) {
  if (value === undefined) return undefined;
  assertExactKeys(value, ['kind'], ['instance_id_digest', 'gateway_identity_digest', 'description', 'nonce', 'scope_id'], fieldPath);
  if (value.kind === 'none') {
    assertExactKeys(value, ['kind'], [], fieldPath);
    return value;
  }
  if (!['upnp-journal', 'pcp-nonce', 'natpmp-lease-scope'].includes(value.kind)) {
    fail('MAPPING_FIELD_INVALID', `${fieldPath}.kind`, 'is not a supported ownership discriminator');
  }
  if (typeof value.instance_id_digest !== 'string' || !/^[a-f0-9]{64}$/.test(value.instance_id_digest)) {
    fail('MAPPING_FIELD_INVALID', `${fieldPath}.instance_id_digest`, 'must be a digest');
  }
  if (value.kind === 'upnp-journal') {
    assertExactKeys(value, ['kind', 'instance_id_digest', 'gateway_identity_digest', 'description'], [], fieldPath);
    if (typeof value.gateway_identity_digest !== 'string' || !/^[a-f0-9]{64}$/.test(value.gateway_identity_digest)) fail('MAPPING_FIELD_INVALID', `${fieldPath}.gateway_identity_digest`, 'must be a digest');
    if (typeof value.description !== 'string' || value.description.length === 0 || value.description.length > 64) fail('MAPPING_FIELD_INVALID', `${fieldPath}.description`, 'must be a non-empty description');
  } else if (value.kind === 'pcp-nonce') {
    assertExactKeys(value, ['kind', 'instance_id_digest', 'nonce'], [], fieldPath);
    if (typeof value.nonce !== 'string' || !/^[a-f0-9]{24}$/.test(value.nonce)) fail('MAPPING_FIELD_INVALID', `${fieldPath}.nonce`, 'must be a 96-bit hexadecimal nonce');
  } else {
    assertExactKeys(value, ['kind', 'instance_id_digest', 'scope_id'], [], fieldPath);
    assertId(value.scope_id, `${fieldPath}.scope_id`);
  }
  return value;
}

function assertOwnerProtocol(owner, protocol, fieldPath) {
  if (owner === undefined || owner.kind === 'none') return;
  const ownerProtocol = {
    'upnp-journal': 'upnp',
    'pcp-nonce': 'pcp',
    'natpmp-lease-scope': 'natpmp'
  }[owner.kind];
  if (ownerProtocol !== protocol) fail('OWNER_PROTOCOL_MISMATCH', `${fieldPath}.kind`, 'owner kind must match the mapping protocol');
}

function validateLease(value, fieldPath) {
  assertExactKeys(value, ['lifetime_seconds', 'created_monotonic_ms', 'expires_monotonic_ms'], [], fieldPath);
  assertUint(value.lifetime_seconds, 0xffffffff, `${fieldPath}.lifetime_seconds`);
  assertUint(value.created_monotonic_ms, MAX_SAFE, `${fieldPath}.created_monotonic_ms`);
  if (value.lifetime_seconds === 0) {
    if (value.expires_monotonic_ms !== null) fail('LEASE_EXPIRY_MISMATCH', `${fieldPath}.expires_monotonic_ms`, 'permanent leases have null expiry');
    return value;
  }
  assertUint(value.expires_monotonic_ms, MAX_SAFE, `${fieldPath}.expires_monotonic_ms`);
  const expected = value.created_monotonic_ms + value.lifetime_seconds * 1000;
  if (!Number.isSafeInteger(expected)) fail('LEASE_EXPIRY_OVERFLOW', fieldPath, 'finite lease expiry exceeds uint53');
  if (value.expires_monotonic_ms !== expected) fail('LEASE_EXPIRY_MISMATCH', `${fieldPath}.expires_monotonic_ms`, 'must equal created time plus lifetime');
  return value;
}

function normalizeMapping(value, fieldPath = '$') {
  assertExactKeys(value,
    ['mapping_id', 'protocol', 'transport', 'client_id', 'internal_address', 'internal_port', 'requested_external_port', 'external_address', 'external_port', 'lease', 'epoch', 'generation'],
    ['owner', 'atomic_group_id'], fieldPath);
  assertId(value.mapping_id, `${fieldPath}.mapping_id`);
  if (!PROTOCOLS.has(value.protocol)) fail('MAPPING_FIELD_INVALID', `${fieldPath}.protocol`, 'must name a supported protocol');
  if (!TRANSPORTS.has(value.transport)) fail('MAPPING_FIELD_INVALID', `${fieldPath}.transport`, 'must be tcp or udp');
  assertId(value.client_id, `${fieldPath}.client_id`);
  const internalAddress = normalizeAddress(value.internal_address);
  if (!internalAddress) fail('MAPPING_FIELD_INVALID', `${fieldPath}.internal_address`, 'must be an IP address');
  const externalAddress = normalizeAddress(value.external_address);
  if (!externalAddress) fail('MAPPING_FIELD_INVALID', `${fieldPath}.external_address`, 'must be an IP address');
  assertPort(value.internal_port, `${fieldPath}.internal_port`, false);
  assertPort(value.requested_external_port, `${fieldPath}.requested_external_port`, true);
  assertPort(value.external_port, `${fieldPath}.external_port`, false);
  assertUint(value.epoch, 0xffffffff, `${fieldPath}.epoch`);
  if (!Number.isInteger(value.generation) || value.generation < 1 || value.generation > MAX_SAFE) fail('MAPPING_FIELD_INVALID', `${fieldPath}.generation`, 'must be a non-zero uint53');
  if (value.atomic_group_id !== undefined) assertId(value.atomic_group_id, `${fieldPath}.atomic_group_id`);
  validateLease(value.lease, `${fieldPath}.lease`);
  validateOwner(value.owner, `${fieldPath}.owner`);
  assertOwnerProtocol(value.owner, value.protocol, `${fieldPath}.owner`);
  return {
    mapping_id: value.mapping_id,
    protocol: value.protocol,
    transport: value.transport,
    client_id: value.client_id,
    internal_address: internalAddress,
    internal_port: value.internal_port,
    requested_external_port: value.requested_external_port,
    external_address: externalAddress,
    external_port: value.external_port,
    lease: value.lease,
    ...(value.owner === undefined ? {} : { owner: value.owner }),
    epoch: value.epoch,
    generation: value.generation,
    ...(value.atomic_group_id === undefined ? {} : { atomic_group_id: value.atomic_group_id })
  };
}

function mappingCollisionKey(mapping) {
  return `${mapping.external_address}\u0000${mapping.external_port}\u0000${mapping.transport}`;
}

function assertNoCollisions(mappings, fieldPath = '$.mappings') {
  const ids = new Set();
  const occupied = new Set();
  mappings.forEach((mapping, index) => {
    if (ids.has(mapping.mapping_id)) fail('MAPPING_ID_EXISTS', `${fieldPath}[${index}].mapping_id`, 'mapping_id is already present');
    ids.add(mapping.mapping_id);
    const key = mappingCollisionKey(mapping);
    if (occupied.has(key)) fail('MAPPING_COLLISION', `${fieldPath}[${index}].external_address`, 'external address, port and transport are already occupied');
    occupied.add(key);
  });
}

function ownerInstanceIdentity(owner) {
  if (owner === undefined) return undefined;
  return {
    kind: owner.kind,
    ...(owner.instance_id_digest === undefined ? {} : { instance_id_digest: owner.instance_id_digest }),
    ...(owner.gateway_identity_digest === undefined ? {} : { gateway_identity_digest: owner.gateway_identity_digest })
  };
}

function assertAtomicGroups(mappings, fieldPath = '$.mappings') {
  const groups = new Map();
  mappings.forEach((mapping, index) => {
    if (!mapping.atomic_group_id) return;
    const group = groups.get(mapping.atomic_group_id) || [];
    group.push({ mapping, index });
    groups.set(mapping.atomic_group_id, group);
  });
  for (const group of groups.values()) {
    const last = group[group.length - 1];
    const lastPath = `${fieldPath}[${last.index}]`;
    if (group.length > 2) fail('ATOMIC_GROUP_TOO_MANY', `${lastPath}.atomic_group_id`, 'contains more than one tcp and one udp mapping');
    if (group.length !== 2) continue;
    const [first, second] = group;
    if (first.mapping.transport === second.mapping.transport) fail('ATOMIC_GROUP_DUPLICATE_TRANSPORT', `${lastPath}.atomic_group_id`, 'contains duplicate transport');
    for (const key of ['protocol', 'client_id', 'external_address', 'epoch', 'generation']) {
      if (first.mapping[key] !== second.mapping[key]) fail('ATOMIC_GROUP_INCOHERENT', `${lastPath}.${key}`, 'completed members must share gateway and client identity');
    }
    if (stableJson(ownerInstanceIdentity(first.mapping.owner)) !== stableJson(ownerInstanceIdentity(second.mapping.owner))) {
      fail('ATOMIC_GROUP_INCOHERENT', `${lastPath}.owner.instance_id_digest`, 'completed members must share owner instance identity');
    }
  }
}

function assertActiveMappingVersions(mappings, epoch, generation) {
  mappings.forEach((mapping, index) => {
    if (mapping.epoch !== epoch) fail('STATE_MAPPING_EPOCH_MISMATCH', `$.mappings[${index}].epoch`, 'must match state epoch');
    if (mapping.generation !== generation) fail('STATE_MAPPING_GENERATION_MISMATCH', `$.mappings[${index}].generation`, 'must match state generation');
  });
}

function freezeState(epoch, generation, mappings, baselineMappings) {
  assertActiveMappingVersions(mappings, epoch, generation);
  assertNoCollisions(mappings);
  assertNoCollisions(baselineMappings, '$.baseline_mappings');
  assertAtomicGroups(mappings);
  assertAtomicGroups(baselineMappings, '$.baseline_mappings');
  const result = deepFreeze({
    epoch,
    generation,
    mappings,
    baseline_mappings: baselineMappings
  });
  stateBrand.add(result);
  return result;
}

function createMappingState(input) {
  const copy = cloneJsonData(input, '$');
  assertExactKeys(copy, ['epoch', 'generation', 'mappings'], ['baseline_mappings'], '$');
  assertUint(copy.epoch, 0xffffffff, '$.epoch');
  if (!Number.isInteger(copy.generation) || copy.generation < 1 || copy.generation > MAX_SAFE) fail('MAPPING_FIELD_INVALID', '$.generation', 'must be a non-zero uint53');
  if (!Array.isArray(copy.mappings)) fail('MAPPING_FIELD_INVALID', '$.mappings', 'must be an array');
  const mappingList = copy.mappings.map((mapping, index) => normalizeMapping(mapping, `$.mappings[${index}]`));
  const baseline = copy.baseline_mappings === undefined ? copy.mappings : copy.baseline_mappings;
  if (!Array.isArray(baseline)) fail('MAPPING_FIELD_INVALID', '$.baseline_mappings', 'must be an array');
  const baselineList = baseline.map((mapping, index) => normalizeMapping(mapping, `$.baseline_mappings[${index}]`));
  return freezeState(copy.epoch, copy.generation, mappingList, baselineList);
}

function requireState(state) {
  if (!stateBrand.has(state)) fail('STATE_INVALID', '$', 'must be created by createMappingState or a model operation');
  return state;
}

function assertCurrent(state, epoch, generation) {
  if (epoch !== state.epoch) fail('STALE_EPOCH', '$.epoch', 'does not match the current gateway epoch');
  if (generation !== state.generation) fail('STALE_GENERATION', '$.generation', 'does not match the current mapping generation');
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function ownersEqual(left, right) {
  return stableJson(left) === stableJson(right);
}

function atomicGroupStatus(mappings, groupId) {
  if (!groupId) return undefined;
  const transports = new Set(mappings.filter((mapping) => mapping.atomic_group_id === groupId).map((mapping) => mapping.transport));
  return transports.has('tcp') && transports.has('udp') ? 'complete' : 'partial';
}

function createMapping(state, input) {
  requireState(state);
  const copy = cloneJsonData(input, '$');
  if (copy === null || Array.isArray(copy)) fail('MAPPING_INPUT_INVALID', '$', 'mapping must be an object');
  const mapping = normalizeMapping(copy);
  assertCurrent(state, mapping.epoch, mapping.generation);
  if (state.mappings.some((item) => item.mapping_id === mapping.mapping_id)) fail('MAPPING_ID_EXISTS', '$.mapping_id', 'mapping_id is already present');
  if (state.mappings.some((item) => mappingCollisionKey(item) === mappingCollisionKey(mapping))) fail('MAPPING_COLLISION', '$.external_address', 'external address, port and transport are already occupied');
  const next = freezeState(state.epoch, state.generation, [...state.mappings, mapping], state.baseline_mappings);
  return deepFreeze({ ok: true, state: next, mapping, ...(mapping.atomic_group_id ? { atomic_group_status: atomicGroupStatus(next.mappings, mapping.atomic_group_id) } : {}) });
}

function requestCopy(input, required, optional = []) {
  const copy = cloneJsonData(input, '$');
  assertExactKeys(copy, required, optional, '$');
  return copy;
}

function findMapping(state, mappingId) {
  assertId(mappingId, '$.mapping_id');
  const mapping = state.mappings.find((item) => item.mapping_id === mappingId);
  if (!mapping) fail('MAPPING_NOT_FOUND', '$.mapping_id', 'does not identify an active mapping');
  return mapping;
}

function assertOwner(mapping, owner) {
  validateOwner(owner, '$.owner');
  assertOwnerProtocol(owner, mapping.protocol, '$.owner');
  if (mapping.owner === undefined || mapping.owner.kind === 'none' || owner === undefined || owner.kind === 'none') {
    fail('OWNERSHIP_UNPROVEN', '$.owner', 'renewal and deletion require demonstrated ownership');
  }
  if (!ownersEqual(mapping.owner, owner)) fail('OWNERSHIP_MISMATCH', '$.owner', 'does not match the mapping ownership discriminator');
}

function renewMapping(state, input) {
  requireState(state);
  const request = requestCopy(input, ['mapping_id', 'epoch', 'generation', 'lifetime_seconds', 'now_monotonic_ms'], ['owner']);
  assertUint(request.epoch, 0xffffffff, '$.epoch');
  if (!Number.isInteger(request.generation) || request.generation < 1 || request.generation > MAX_SAFE) fail('MAPPING_FIELD_INVALID', '$.generation', 'must be a non-zero uint53');
  assertCurrent(state, request.epoch, request.generation);
  const current = findMapping(state, request.mapping_id);
  assertOwner(current, request.owner);
  assertUint(request.lifetime_seconds, 0xffffffff, '$.lifetime_seconds');
  assertUint(request.now_monotonic_ms, MAX_SAFE, '$.now_monotonic_ms');
  if (request.now_monotonic_ms < current.lease.created_monotonic_ms) fail('LEASE_TIME_REGRESSION', '$.now_monotonic_ms', 'cannot precede the mapping creation time');
  if (current.lease.expires_monotonic_ms !== null && request.now_monotonic_ms >= current.lease.expires_monotonic_ms) fail('LEASE_EXPIRED', '$.now_monotonic_ms', 'cannot revive an expired finite lease');
  const expires = request.lifetime_seconds === 0 ? null : request.now_monotonic_ms + request.lifetime_seconds * 1000;
  if (expires !== null && !Number.isSafeInteger(expires)) fail('LEASE_EXPIRY_OVERFLOW', '$.lifetime_seconds', 'finite lease expiry exceeds uint53');
  const lease = { lifetime_seconds: request.lifetime_seconds, created_monotonic_ms: request.now_monotonic_ms, expires_monotonic_ms: expires };
  const mapping = deepFreeze({ ...current, lease });
  const mappings = state.mappings.map((item) => item.mapping_id === mapping.mapping_id ? mapping : item);
  const next = freezeState(state.epoch, state.generation, mappings, state.baseline_mappings);
  return deepFreeze({ ok: true, state: next, mapping, ...(mapping.atomic_group_id ? { atomic_group_status: atomicGroupStatus(next.mappings, mapping.atomic_group_id) } : {}) });
}

function expireMappings(state, nowMonotonicMs) {
  requireState(state);
  assertUint(nowMonotonicMs, MAX_SAFE, '$.now_monotonic_ms');
  const expired = state.mappings.filter((mapping) => mapping.lease.expires_monotonic_ms !== null && mapping.lease.expires_monotonic_ms <= nowMonotonicMs);
  const expiredIds = expired.map((mapping) => mapping.mapping_id).sort();
  if (expiredIds.length === 0) return deepFreeze({ ok: true, state, expired_mapping_ids: [] });
  const expiredSet = new Set(expiredIds);
  const next = freezeState(state.epoch, state.generation, state.mappings.filter((mapping) => !expiredSet.has(mapping.mapping_id)), state.baseline_mappings);
  return deepFreeze({ ok: true, state: next, expired_mapping_ids: expiredIds });
}

function deleteMapping(state, input) {
  requireState(state);
  const request = requestCopy(input, ['mapping_id', 'epoch', 'generation'], ['owner']);
  assertUint(request.epoch, 0xffffffff, '$.epoch');
  if (!Number.isInteger(request.generation) || request.generation < 1 || request.generation > MAX_SAFE) fail('MAPPING_FIELD_INVALID', '$.generation', 'must be a non-zero uint53');
  assertCurrent(state, request.epoch, request.generation);
  const current = findMapping(state, request.mapping_id);
  assertOwner(current, request.owner);
  const next = freezeState(state.epoch, state.generation, state.mappings.filter((mapping) => mapping.mapping_id !== current.mapping_id), state.baseline_mappings);
  return deepFreeze({ ok: true, state: next, deleted_mapping_id: current.mapping_id, ...(current.atomic_group_id ? { atomic_group_status: atomicGroupStatus(next.mappings, current.atomic_group_id) } : {}) });
}

function resetMappingState(state, input) {
  requireState(state);
  const request = requestCopy(input, ['generation', 'epoch']);
  if (!Number.isInteger(request.generation) || request.generation < 1 || request.generation > MAX_SAFE) fail('MAPPING_FIELD_INVALID', '$.generation', 'must be a non-zero uint53');
  assertUint(request.epoch, 0xffffffff, '$.epoch');
  if (request.generation <= state.generation) fail('GENERATION_NOT_INCREASING', '$.generation', 'must be strictly greater than the current generation');
  const baseline = state.baseline_mappings.map((mapping) => ({ ...mapping, epoch: request.epoch, generation: request.generation }));
  const next = freezeState(request.epoch, request.generation, baseline, state.baseline_mappings);
  return deepFreeze({ ok: true, state: next });
}

function restartMappingEpoch(state, input) {
  requireState(state);
  const request = requestCopy(input, ['restart_seconds']);
  if (Object.is(request.restart_seconds, -0)) {
    fail('MAPPING_FIELD_INVALID', '$.restart_seconds', 'must not be negative zero');
  }
  assertUint(request.restart_seconds, 0xffffffff, '$.restart_seconds');
  if (state.generation === MAX_SAFE) {
    fail('GENERATION_EXHAUSTED', '$.generation', 'cannot advance the mapping generation');
  }
  const next = freezeState(
    request.restart_seconds,
    state.generation + 1,
    [],
    state.baseline_mappings
  );
  return deepFreeze({
    ok: true,
    state: next,
    removed_mapping_count: state.mappings.length
  });
}

/**
 * Raw, in-process snapshot for domain tests only. It intentionally retains
 * addresses and private ownership material and MUST NOT be used for JSONL,
 * reports, or the control-plane list-mappings response.
 */
function snapshotInternalMappings(state) {
  requireState(state);
  return deepFreeze(state.mappings.map((mapping) => ({
    ...mapping,
    ...(mapping.atomic_group_id ? { atomic_group_status: atomicGroupStatus(state.mappings, mapping.atomic_group_id) } : {})
  })).sort((left, right) => left.mapping_id < right.mapping_id ? -1 : left.mapping_id > right.mapping_id ? 1 : 0));
}

module.exports = {
  MappingModelError,
  createMappingState,
  createMapping,
  renewMapping,
  expireMappings,
  deleteMapping,
  resetMappingState,
  restartMappingEpoch,
  snapshotInternalMappings
};
