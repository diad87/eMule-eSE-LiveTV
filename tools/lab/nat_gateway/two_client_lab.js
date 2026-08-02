'use strict';

const crypto = require('node:crypto');
const { types } = require('node:util');
const { normalizeAddress } = require('./address');
const {
  MappingModelError,
  createMappingState,
  createMapping,
  renewMapping,
  expireMappings,
  deleteMapping,
  snapshotInternalMappings
} = require('./mapping_model');

const MAX_UINT32 = 0xffffffff;
const MAX_UINT53 = Number.MAX_SAFE_INTEGER;
const MAX_ARRAY_ITEMS = 256;
const MAX_OBJECT_PROPERTIES = 256;
const MAX_DATA_DEPTH = 32;
const MAX_DATA_NODES = 4096;
const MAX_TOTAL_STRING_BYTES = 1024 * 1024;
const MAX_PROPERTY_NAME_BYTES = 256;
const ID_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const PROTOCOLS = new Set(['upnp', 'pcp', 'natpmp']);
const TRANSPORTS = new Set(['tcp', 'udp']);
const OPERATIONAL_FAILURES = new Set([
  'MAPPING_COLLISION',
  'MAPPING_ID_EXISTS',
  'MAPPING_NOT_FOUND',
  'OWNERSHIP_MISMATCH',
  'OWNERSHIP_UNPROVEN',
  'OWNER_PROTOCOL_MISMATCH',
  'LEASE_TIME_REGRESSION',
  'LEASE_EXPIRY_OVERFLOW',
  'LEASE_EXPIRED'
]);
const labBrand = new WeakSet();

class TwoClientLabError extends Error {
  constructor(reasonCode, fieldPath, detail) {
    super(`${reasonCode} at ${fieldPath}: ${detail}`);
    this.name = 'TwoClientLabError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath, detail) {
  throw new TwoClientLabError(reasonCode, fieldPath, detail);
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function consumeStringBudget(value, fieldPath, budget, maximum = MAX_TOTAL_STRING_BYTES) {
  const remaining = MAX_TOTAL_STRING_BYTES - budget.string_bytes;
  if (value.length > maximum || value.length > remaining) {
    fail('TWO_CLIENT_INPUT_INVALID', fieldPath, 'text exceeds the bounded input budget');
  }
  const bytes = Buffer.byteLength(value, 'utf8');
  if (bytes > maximum || budget.string_bytes + bytes > MAX_TOTAL_STRING_BYTES) {
    fail('TWO_CLIENT_INPUT_INVALID', fieldPath, 'text exceeds the bounded input budget');
  }
  budget.string_bytes += bytes;
}

function cloneData(
  value,
  fieldPath,
  ancestors = new WeakSet(),
  depth = 0,
  budget = { nodes: 0, string_bytes: 0 }
) {
  budget.nodes += 1;
  if (budget.nodes > MAX_DATA_NODES) {
    fail('TWO_CLIENT_INPUT_INVALID', fieldPath, `data graph cannot exceed ${MAX_DATA_NODES} visited nodes`);
  }
  if (typeof value === 'string') {
    consumeStringBudget(value, fieldPath, budget);
    return value;
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('TWO_CLIENT_INPUT_INVALID', fieldPath, 'numbers must be finite');
    return value;
  }
  if (types.isProxy(value)) fail('TWO_CLIENT_INPUT_INVALID', fieldPath, 'proxies are not data');
  if (typeof value !== 'object') fail('TWO_CLIENT_INPUT_INVALID', fieldPath, 'must be JSON-like data');
  if (depth >= MAX_DATA_DEPTH) fail('TWO_CLIENT_INPUT_INVALID', fieldPath, `data nesting cannot exceed ${MAX_DATA_DEPTH} levels`);
  if (ancestors.has(value)) fail('TWO_CLIENT_INPUT_INVALID', fieldPath, 'cyclic data is not allowed');
  ancestors.add(value);
  let copy;
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      ancestors.delete(value);
      fail('TWO_CLIENT_INPUT_INVALID', fieldPath, 'arrays must use the standard Array prototype');
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (!lengthDescriptor || !hasOwn(lengthDescriptor, 'value') ||
        !Number.isInteger(lengthDescriptor.value) || lengthDescriptor.value < 0 ||
        lengthDescriptor.value > MAX_ARRAY_ITEMS) {
      ancestors.delete(value);
      fail('TWO_CLIENT_INPUT_INVALID', fieldPath, `array length must be in 0..${MAX_ARRAY_ITEMS}`);
    }
    const length = lengthDescriptor.value;
    const names = Object.getOwnPropertyNames(value);
    if (Object.getOwnPropertySymbols(value).length || names.length !== length + 1 || !names.includes('length')) {
      ancestors.delete(value);
      fail('TWO_CLIENT_INPUT_INVALID', fieldPath, 'arrays must be dense and contain no custom properties');
    }
    copy = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !descriptor.enumerable || !hasOwn(descriptor, 'value')) {
        ancestors.delete(value);
        fail('TWO_CLIENT_INPUT_INVALID', `${fieldPath}[${index}]`, 'array elements must be enumerable data');
      }
      copy.push(cloneData(descriptor.value, `${fieldPath}[${index}]`, ancestors, depth + 1, budget));
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      ancestors.delete(value);
      fail('TWO_CLIENT_INPUT_INVALID', fieldPath, 'objects must have a plain or null prototype');
    }
    if (Object.getOwnPropertySymbols(value).length) {
      ancestors.delete(value);
      fail('TWO_CLIENT_INPUT_INVALID', fieldPath, 'symbol properties are not allowed');
    }
    copy = Object.create(null);
    const names = Object.getOwnPropertyNames(value);
    if (names.length > MAX_OBJECT_PROPERTIES) {
      ancestors.delete(value);
      fail('TWO_CLIENT_INPUT_INVALID', fieldPath, `objects cannot contain more than ${MAX_OBJECT_PROPERTIES} properties`);
    }
    for (const key of names) {
      consumeStringBudget(key, fieldPath, budget, MAX_PROPERTY_NAME_BYTES);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !hasOwn(descriptor, 'value') || key === 'toJSON') {
        ancestors.delete(value);
        fail('TWO_CLIENT_INPUT_INVALID', `${fieldPath}.${key}`, 'only enumerable data properties are allowed');
      }
      copy[key] = cloneData(descriptor.value, `${fieldPath}.${key}`, ancestors, depth + 1, budget);
    }
  }
  ancestors.delete(value);
  return copy;
}

function exact(value, keys, fieldPath) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('TWO_CLIENT_SHAPE_INVALID', fieldPath, 'must be an object');
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('TWO_CLIENT_SHAPE_INVALID', fieldPath, `expected exactly: ${expected.join(', ')}`);
  }
}

function integer(value, minimum, maximum, fieldPath) {
  if (!Number.isInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) {
    fail('TWO_CLIENT_VALUE_INVALID', fieldPath, `must be an integer in ${minimum}..${maximum}`);
  }
  return value;
}

function id(value, fieldPath) {
  if (typeof value !== 'string' || value.length > 64 || !ID_PATTERN.test(value)) {
    fail('TWO_CLIENT_VALUE_INVALID', fieldPath, 'must be a valid laboratory identifier');
  }
  return value;
}

function digest(value, fieldPath) {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    fail('TWO_CLIENT_VALUE_INVALID', fieldPath, 'must be a lowercase SHA-256 digest');
  }
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function deriveOwner(client, gatewayIdentityDigest) {
  if (client.protocol === 'upnp') {
    return deepFreeze({
      kind: 'upnp-journal',
      instance_id_digest: client.instance_id_digest,
      gateway_identity_digest: gatewayIdentityDigest,
      description: client.client_id
    });
  }
  if (client.protocol === 'pcp') {
    const nonce = crypto
      .createHash('sha256')
      .update(`ese-v92-pcp\0${client.client_id}\0${client.instance_id_digest}`, 'utf8')
      .digest('hex')
      .slice(0, 24);
    return deepFreeze({
      kind: 'pcp-nonce',
      instance_id_digest: client.instance_id_digest,
      nonce
    });
  }
  return deepFreeze({
    kind: 'natpmp-lease-scope',
    instance_id_digest: client.instance_id_digest,
    scope_id: client.client_id
  });
}

function normalizeClient(value, index, gatewayIdentityDigest) {
  const fieldPath = `$.clients[${index}]`;
  exact(value, ['client_id', 'protocol', 'internal_address', 'instance_id_digest'], fieldPath);
  const clientId = id(value.client_id, `${fieldPath}.client_id`);
  if (!PROTOCOLS.has(value.protocol)) fail('TWO_CLIENT_VALUE_INVALID', `${fieldPath}.protocol`, 'unknown protocol');
  const internalAddress = normalizeAddress(value.internal_address);
  if (internalAddress === null) fail('TWO_CLIENT_VALUE_INVALID', `${fieldPath}.internal_address`, 'must be an IP address');
  const client = {
    client_id: clientId,
    protocol: value.protocol,
    internal_address: internalAddress,
    instance_id_digest: digest(value.instance_id_digest, `${fieldPath}.instance_id_digest`),
    used_instance_id_digests: null,
    status: 'running',
    restart_count: 0
  };
  client.used_instance_id_digests = deepFreeze([client.instance_id_digest]);
  return deepFreeze({ ...client, owner: deriveOwner(client, gatewayIdentityDigest) });
}

function makeLab(value) {
  const lab = deepFreeze(value);
  labBrand.add(lab);
  return lab;
}

function createTwoClientLab(input) {
  const copy = cloneData(input, '$');
  exact(copy, ['epoch', 'generation', 'start_monotonic_ms', 'external_address', 'gateway_identity_digest', 'clients'], '$');
  const epoch = integer(copy.epoch, 0, MAX_UINT32, '$.epoch');
  const generation = integer(copy.generation, 1, MAX_UINT53, '$.generation');
  const startMonotonicMs = integer(copy.start_monotonic_ms, 0, MAX_UINT53, '$.start_monotonic_ms');
  const externalAddress = normalizeAddress(copy.external_address);
  if (externalAddress === null) fail('TWO_CLIENT_VALUE_INVALID', '$.external_address', 'must be an IP address');
  const gatewayIdentityDigest = digest(copy.gateway_identity_digest, '$.gateway_identity_digest');
  if (!Array.isArray(copy.clients) || copy.clients.length !== 2) {
    fail('TWO_CLIENT_SHAPE_INVALID', '$.clients', 'must contain exactly two clients');
  }
  const clients = copy.clients.map((client, index) => normalizeClient(client, index, gatewayIdentityDigest));
  if (clients[0].client_id === clients[1].client_id) fail('TWO_CLIENT_DUPLICATE_ID', '$.clients[1].client_id', 'client IDs must differ');
  if (clients[0].internal_address === clients[1].internal_address) {
    fail('TWO_CLIENT_DUPLICATE_ADDRESS', '$.clients[1].internal_address', 'client addresses must differ');
  }
  return makeLab({
    external_address: externalAddress,
    gateway_identity_digest: gatewayIdentityDigest,
    now_monotonic_ms: startMonotonicMs,
    mapping_state: createMappingState({ epoch, generation, mappings: [], baseline_mappings: [] }),
    clients: deepFreeze(clients)
  });
}

function requireLab(lab) {
  if (!lab || typeof lab !== 'object' || !labBrand.has(lab)) {
    fail('TWO_CLIENT_STATE_INVALID', '$.lab', 'must be created by this module');
  }
}

function clientById(lab, clientId) {
  const client = lab.clients.find((item) => item.client_id === clientId);
  if (!client) fail('TWO_CLIENT_UNKNOWN_CLIENT', '$.client_id', 'client is not part of this lab');
  return client;
}

function operationInput(value, keys) {
  const copy = cloneData(value, '$');
  exact(copy, keys, '$');
  return copy;
}

function requireRunning(client) {
  if (client.status !== 'running') {
    return deepFreeze({ ok: false, reason_code: 'CLIENT_NOT_RUNNING' });
  }
  return null;
}

function withMappingState(lab, mappingState, nowMonotonicMs = lab.now_monotonic_ms) {
  return makeLab({
    external_address: lab.external_address,
    gateway_identity_digest: lab.gateway_identity_digest,
    now_monotonic_ms: nowMonotonicMs,
    mapping_state: mappingState,
    clients: lab.clients
  });
}

function advanceLabTime(lab, nowMonotonicMs) {
  if (nowMonotonicMs < lab.now_monotonic_ms) {
    fail('TWO_CLIENT_TIME_REGRESSION', '$.now_monotonic_ms', 'cannot move laboratory time backwards');
  }
  const expired = expireMappings(lab.mapping_state, nowMonotonicMs);
  if (nowMonotonicMs === lab.now_monotonic_ms && expired.state === lab.mapping_state) return lab;
  return withMappingState(lab, expired.state, nowMonotonicMs);
}

function advanceTwoClientTime(lab, input) {
  requireLab(lab);
  const request = operationInput(input, ['now_monotonic_ms']);
  const nowMonotonicMs = integer(request.now_monotonic_ms, 0, MAX_UINT53, '$.now_monotonic_ms');
  return deepFreeze({ ok: true, lab: advanceLabTime(lab, nowMonotonicMs) });
}

function containedMappingOperation(lab, operation) {
  try {
    const result = operation();
    return deepFreeze({ ok: true, lab: withMappingState(lab, result.state) });
  } catch (error) {
    if (error instanceof MappingModelError && OPERATIONAL_FAILURES.has(error.reason_code)) {
      return deepFreeze({ ok: false, reason_code: error.reason_code, lab });
    }
    throw error;
  }
}

function createClientMapping(lab, input) {
  requireLab(lab);
  const request = operationInput(input, [
    'client_id',
    'mapping_id',
    'transport',
    'internal_port',
    'external_port',
    'lifetime_seconds',
    'now_monotonic_ms'
  ]);
  const client = clientById(lab, id(request.client_id, '$.client_id'));
  id(request.mapping_id, '$.mapping_id');
  if (!TRANSPORTS.has(request.transport)) fail('TWO_CLIENT_VALUE_INVALID', '$.transport', 'must be tcp or udp');
  integer(request.internal_port, 1, 65535, '$.internal_port');
  integer(request.external_port, 1, 65535, '$.external_port');
  integer(request.lifetime_seconds, 0, MAX_UINT32, '$.lifetime_seconds');
  integer(request.now_monotonic_ms, 0, MAX_UINT53, '$.now_monotonic_ms');
  const expires = request.lifetime_seconds === 0 ? null : request.now_monotonic_ms + request.lifetime_seconds * 1000;
  if (expires !== null && !Number.isSafeInteger(expires)) {
    fail('TWO_CLIENT_VALUE_INVALID', '$.lifetime_seconds', 'lease expiry exceeds the safe integer range');
  }
  const timedLab = advanceLabTime(lab, request.now_monotonic_ms);
  const unavailable = requireRunning(client);
  if (unavailable) return deepFreeze({ ...unavailable, lab: timedLab });
  if (client.protocol === 'upnp' && request.lifetime_seconds !== 0) {
    return deepFreeze({ ok: false, reason_code: 'UPNP_ONLY_PERMANENT_LEASES', lab: timedLab });
  }
  if (client.protocol !== 'upnp' && request.lifetime_seconds === 0) {
    return containedMappingOperation(timedLab, () => deleteMapping(timedLab.mapping_state, {
      mapping_id: request.mapping_id,
      epoch: timedLab.mapping_state.epoch,
      generation: timedLab.mapping_state.generation,
      owner: client.owner
    }));
  }
  return containedMappingOperation(timedLab, () => createMapping(timedLab.mapping_state, {
    mapping_id: request.mapping_id,
    protocol: client.protocol,
    transport: request.transport,
    client_id: client.client_id,
    internal_address: client.internal_address,
    internal_port: request.internal_port,
    requested_external_port: request.external_port,
    external_address: lab.external_address,
    external_port: request.external_port,
    lease: {
      lifetime_seconds: request.lifetime_seconds,
      created_monotonic_ms: request.now_monotonic_ms,
      expires_monotonic_ms: expires
    },
    owner: client.owner,
    epoch: timedLab.mapping_state.epoch,
    generation: timedLab.mapping_state.generation
  }));
}

function renewClientMapping(lab, input) {
  requireLab(lab);
  const request = operationInput(input, ['client_id', 'mapping_id', 'lifetime_seconds', 'now_monotonic_ms']);
  const client = clientById(lab, id(request.client_id, '$.client_id'));
  id(request.mapping_id, '$.mapping_id');
  integer(request.lifetime_seconds, 0, MAX_UINT32, '$.lifetime_seconds');
  integer(request.now_monotonic_ms, 0, MAX_UINT53, '$.now_monotonic_ms');
  const expires = request.lifetime_seconds === 0 ? null : request.now_monotonic_ms + request.lifetime_seconds * 1000;
  if (expires !== null && !Number.isSafeInteger(expires)) {
    fail('TWO_CLIENT_VALUE_INVALID', '$.lifetime_seconds', 'lease expiry exceeds the safe integer range');
  }
  const timedLab = advanceLabTime(lab, request.now_monotonic_ms);
  const unavailable = requireRunning(client);
  if (unavailable) return deepFreeze({ ...unavailable, lab: timedLab });
  if (client.protocol === 'upnp' && request.lifetime_seconds !== 0) {
    return deepFreeze({ ok: false, reason_code: 'UPNP_ONLY_PERMANENT_LEASES', lab: timedLab });
  }
  if (client.protocol !== 'upnp' && request.lifetime_seconds === 0) {
    return containedMappingOperation(timedLab, () => deleteMapping(timedLab.mapping_state, {
      mapping_id: request.mapping_id,
      epoch: timedLab.mapping_state.epoch,
      generation: timedLab.mapping_state.generation,
      owner: client.owner
    }));
  }
  return containedMappingOperation(timedLab, () => renewMapping(timedLab.mapping_state, {
    mapping_id: request.mapping_id,
    epoch: timedLab.mapping_state.epoch,
    generation: timedLab.mapping_state.generation,
    owner: client.owner,
    lifetime_seconds: request.lifetime_seconds,
    now_monotonic_ms: request.now_monotonic_ms
  }));
}

function deleteClientMapping(lab, input) {
  requireLab(lab);
  const request = operationInput(input, ['client_id', 'mapping_id']);
  const client = clientById(lab, id(request.client_id, '$.client_id'));
  id(request.mapping_id, '$.mapping_id');
  const unavailable = requireRunning(client);
  if (unavailable) return deepFreeze({ ...unavailable, lab });
  return containedMappingOperation(lab, () => deleteMapping(lab.mapping_state, {
    mapping_id: request.mapping_id,
    epoch: lab.mapping_state.epoch,
    generation: lab.mapping_state.generation,
    owner: client.owner
  }));
}

function replaceClient(lab, clientId, replacement) {
  return makeLab({
    external_address: lab.external_address,
    gateway_identity_digest: lab.gateway_identity_digest,
    now_monotonic_ms: lab.now_monotonic_ms,
    mapping_state: lab.mapping_state,
    clients: deepFreeze(lab.clients.map((client) => client.client_id === clientId ? replacement : client))
  });
}

function crashClient(lab, input) {
  requireLab(lab);
  const request = operationInput(input, ['client_id']);
  const client = clientById(lab, id(request.client_id, '$.client_id'));
  if (client.status !== 'running') return deepFreeze({ ok: false, reason_code: 'CLIENT_NOT_RUNNING', lab });
  const replacement = deepFreeze({ ...client, status: 'crashed' });
  return deepFreeze({ ok: true, lab: replaceClient(lab, client.client_id, replacement) });
}

function restartClient(lab, input) {
  requireLab(lab);
  const request = operationInput(input, ['client_id', 'instance_id_digest']);
  const client = clientById(lab, id(request.client_id, '$.client_id'));
  if (client.status !== 'crashed') return deepFreeze({ ok: false, reason_code: 'CLIENT_NOT_CRASHED', lab });
  const instanceIdDigest = digest(request.instance_id_digest, '$.instance_id_digest');
  if (client.used_instance_id_digests.includes(instanceIdDigest)) {
    fail('TWO_CLIENT_INSTANCE_REUSED', '$.instance_id_digest', 'restart identity was already used by this client');
  }
  const nextClient = {
    client_id: client.client_id,
    protocol: client.protocol,
    internal_address: client.internal_address,
    instance_id_digest: instanceIdDigest,
    used_instance_id_digests: deepFreeze([...client.used_instance_id_digests, instanceIdDigest]),
    status: 'running',
    restart_count: client.restart_count + 1
  };
  const replacement = deepFreeze({
    ...nextClient,
    owner: deriveOwner(nextClient, lab.gateway_identity_digest)
  });
  return deepFreeze({ ok: true, lab: replaceClient(lab, client.client_id, replacement) });
}

function snapshotTwoClientLab(lab) {
  requireLab(lab);
  return deepFreeze({
    epoch: lab.mapping_state.epoch,
    generation: lab.mapping_state.generation,
    now_monotonic_ms: lab.now_monotonic_ms,
    clients: lab.clients.map((client) => ({
      client_id: client.client_id,
      protocol: client.protocol,
      status: client.status,
      restart_count: client.restart_count
    })),
    mappings: snapshotInternalMappings(lab.mapping_state).map((mapping) => ({
      mapping_id: mapping.mapping_id,
      client_id: mapping.client_id,
      protocol: mapping.protocol,
      transport: mapping.transport,
      external_port: mapping.external_port,
      lifetime_seconds: mapping.lease.lifetime_seconds
    }))
  });
}

module.exports = {
  TwoClientLabError,
  createTwoClientLab,
  createClientMapping,
  renewClientMapping,
  deleteClientMapping,
  advanceTwoClientTime,
  crashClient,
  restartClient,
  snapshotTwoClientLab
};
