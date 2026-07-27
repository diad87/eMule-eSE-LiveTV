'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { TextDecoder, types } = require('node:util');
const Ajv2020 = require('ajv/dist/2020');
const { normalizeAddress } = require('./address');

const MAX_SCENARIO_BYTES = 1024 * 1024;
const MAX_SAFE_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const schema = require('./scenario.schema.json');

class ScenarioValidationError extends Error {
  constructor(reasonCode, fieldPath, detail) {
    super(`${reasonCode} at ${fieldPath}: ${detail}`);
    this.name = 'ScenarioValidationError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: true });
ajv.addFormat('ipv4', { type: 'string', validate: (value) => typeof value === 'string' && normalizeAddress(value) === value && value.includes('.') });
ajv.addFormat('ipv6', { type: 'string', validate: (value) => typeof value === 'string' && normalizeAddress(value) !== null && value.includes(':') });
const validateSchema = ajv.compile(schema);
const SCHEMA_PROPERTY_NAMES = new Set();

function collectSchemaPropertyNames(node, visited = new Set()) {
  if (!node || typeof node !== 'object' || visited.has(node)) return;
  visited.add(node);
  if (node.properties) {
    for (const key of Object.keys(node.properties)) SCHEMA_PROPERTY_NAMES.add(key);
  }
  for (const value of Object.values(node)) collectSchemaPropertyNames(value, visited);
}

collectSchemaPropertyNames(schema);
SCHEMA_PROPERTY_NAMES.add('toJSON');

function fail(reasonCode, fieldPath, detail) {
  throw new ScenarioValidationError(reasonCode, fieldPath, detail);
}

function displayPath(instancePath) {
  if (!instancePath) return '$';
  return `$${instancePath.replace(/~1/g, '/').replace(/~0/g, '~').replace(/\/(\d+)(?=\/|$)/g, '[$1]').replace(/\/([^/]+)/g, '.$1')}`;
}

function schemaErrorPath(error) {
  if (error.keyword === 'required') return `${displayPath(error.instancePath)}.${error.params.missingProperty}`;
  if (error.keyword === 'additionalProperties') return `${displayPath(error.instancePath)}.*`;
  return displayPath(error.instancePath);
}

function valueAtPointer(value, pointer) {
  if (!pointer) return value;
  return pointer.slice(1).split('/').reduce((current, token) => current == null ? undefined : current[token.replace(/~1/g, '/').replace(/~0/g, '~')], value);
}

function resolveLocalReference(node) {
  let resolved = node;
  while (resolved && resolved.$ref && resolved.$ref.startsWith('#/$defs/')) resolved = schema.$defs[resolved.$ref.slice('#/$defs/'.length)];
  return resolved;
}

function branchMatchesConstants(branch, instance) {
  const resolved = resolveLocalReference(branch);
  if (!resolved || !resolved.properties || !instance || typeof instance !== 'object') return false;
  const constants = Object.entries(resolved.properties).filter(([, property]) => Object.prototype.hasOwnProperty.call(property, 'const'));
  return constants.length > 0 && constants.every(([name, property]) => instance[name] === property.const);
}

function schemaAtPointer(pointer, value) {
  let node = schema;
  let instance = value;
  if (!pointer) return resolveLocalReference(node);
  for (const token of pointer.slice(1).split('/').map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'))) {
    node = resolveLocalReference(node);
    if (node.properties && Object.prototype.hasOwnProperty.call(node.properties, token)) node = node.properties[token];
    else if (node.items && /^\d+$/.test(token)) node = node.items;
    else return undefined;
    instance = instance == null ? undefined : instance[token];
  }
  return resolveLocalReference(node);
}

function activeDiscriminator(error, value) {
  if (error.keyword !== 'required') return false;
  const instance = valueAtPointer(value, error.instancePath);
  const parent = schemaAtPointer(error.instancePath, value);
  if (!parent || !instance || typeof instance !== 'object') return false;
  const branches = [...(parent.oneOf || []), ...(parent.anyOf || [])];
  return branches.some((branch) => {
    const resolved = resolveLocalReference(branch);
    return branchMatchesConstants(resolved, instance) && resolved.required && resolved.required.includes(error.params.missingProperty);
  });
}

function selectSchemaError(errors, value) {
  const relevant = errors.filter((error) => !['oneOf', 'anyOf', 'type', 'const', 'enum'].includes(error.keyword) || error.instancePath !== '');
  const priority = { required: 0, additionalProperties: 1, format: 2, minimum: 3, maximum: 3, pattern: 4, type: 5, const: 6, enum: 6, oneOf: 9, anyOf: 9 };
  const candidates = relevant.length ? relevant : errors;
  const active = candidates.filter((error) => activeDiscriminator(error, value));
  return [...(active.length ? active : candidates)].sort((left, right) => {
    const priorityDelta = (priority[left.keyword] ?? 8) - (priority[right.keyword] ?? 8);
    if (priorityDelta) return priorityDelta;
    const pathDelta = schemaErrorPath(left).localeCompare(schemaErrorPath(right));
    if (pathDelta) return pathDelta;
    return left.keyword.localeCompare(right.keyword);
  })[0];
}

function schemaReason(keyword) {
  if (keyword === 'additionalProperties') return 'SCHEMA_ADDITIONAL_PROPERTY';
  return `SCHEMA_${keyword.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}`;
}

function byteLength(value) {
  return Buffer.byteLength(value, 'utf8');
}

function parseText(text) {
  if (typeof text !== 'string') fail('SCENARIO_TEXT_INVALID', '$', 'scenario text must be a string');
  if (byteLength(text) > MAX_SCENARIO_BYTES) fail('SCENARIO_TOO_LARGE', '$', `scenario exceeds ${MAX_SCENARIO_BYTES} bytes`);
  try {
    return JSON.parse(text);
  } catch {
    fail('SCENARIO_JSON_INVALID', '$', 'scenario is not valid JSON');
  }
}

function childPath(parentPath, key, isArray) {
  return isArray ? `${parentPath}[${key}]` : SCHEMA_PROPERTY_NAMES.has(key) ? `${parentPath}.${key}` : `${parentPath}.*`;
}

function cloneJsonData(value, fieldPath, ancestors) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('SCENARIO_OBJECT_INVALID', fieldPath, 'numbers must be finite JSON numbers');
    return value;
  }
  // Do this before any reflective operation: Proxy traps must never participate
  // in scenario validation or surface their thrown values in an error.
  if (types.isProxy(value)) fail('SCENARIO_OBJECT_INVALID', fieldPath, 'proxies are not JSON data');
  if (typeof value !== 'object') fail('SCENARIO_OBJECT_INVALID', fieldPath, 'value is not JSON data');
  if (ancestors.has(value)) fail('SCENARIO_OBJECT_INVALID', fieldPath, 'cyclic input is not JSON data');
  ancestors.add(value);
  let result;
  if (Array.isArray(value)) {
    const ownNames = Object.getOwnPropertyNames(value);
    const ownSymbols = Object.getOwnPropertySymbols(value);
    if (ownSymbols.length || ownNames.some((name) => name !== 'length' && !/^(0|[1-9]\d*)$/.test(name))) {
      ancestors.delete(value);
      fail('SCENARIO_OBJECT_INVALID', fieldPath, 'array must be dense JSON data without custom properties');
    }
    result = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        ancestors.delete(value);
        fail('SCENARIO_OBJECT_INVALID', `${fieldPath}[${index}]`, 'array must be dense data properties');
      }
      result.push(cloneJsonData(descriptor.value, `${fieldPath}[${index}]`, ancestors));
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      ancestors.delete(value);
      fail('SCENARIO_OBJECT_INVALID', fieldPath, 'object must have a plain or null prototype');
    }
    const symbols = Object.getOwnPropertySymbols(value);
    if (symbols.length) {
      ancestors.delete(value);
      fail('SCENARIO_OBJECT_INVALID', fieldPath, 'object cannot contain symbol properties');
    }
    result = Object.create(null);
    for (const key of Object.getOwnPropertyNames(value)) {
      const keyPath = childPath(fieldPath, key, false);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (key === 'toJSON' || !descriptor.enumerable || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        ancestors.delete(value);
        fail('SCENARIO_OBJECT_INVALID', keyPath, 'object must contain only enumerable data properties without toJSON');
      }
      Object.defineProperty(result, key, { value: cloneJsonData(descriptor.value, keyPath, ancestors), enumerable: true, writable: true, configurable: true });
    }
  }
  ancestors.delete(value);
  return result;
}

function cloneJsonObject(value) {
  if (types.isProxy(value)) fail('SCENARIO_OBJECT_INVALID', '$', 'proxies are not JSON data');
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('SCENARIO_OBJECT_INVALID', '$', 'scenario must be a JSON object');
  return cloneJsonData(value, '$', new WeakSet());
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function assertSchema(value) {
  if (validateSchema(value)) return;
  const error = selectSchemaError(validateSchema.errors || [], value);
  fail(schemaReason(error.keyword), schemaErrorPath(error), error.message || 'schema validation failed');
}

function assertUnique(items, property, code, basePath) {
  const seen = new Set();
  items.forEach((item, index) => {
    if (seen.has(item[property])) fail(code, `${basePath}[${index}].${property}`, `${property} must be unique`);
    seen.add(item[property]);
  });
}

function assertLease(lease, itemPath) {
  if (lease.lifetime_seconds === 0) return;
  const created = BigInt(lease.created_monotonic_ms);
  const expected = created + BigInt(lease.lifetime_seconds) * 1000n;
  if (expected > MAX_SAFE_BIGINT) fail('LEASE_EXPIRY_OVERFLOW', `${itemPath}.lease`, 'finite lease expiry exceeds the safe integer range');
  if (BigInt(lease.expires_monotonic_ms) !== expected) {
    fail('LEASE_EXPIRY_MISMATCH', `${itemPath}.lease.expires_monotonic_ms`, 'expiry must equal created time plus lifetime');
  }
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function assertMappings(scenario) {
  const mappings = scenario.initial_state.mappings;
  assertUnique(mappings, 'mapping_id', 'DUPLICATE_MAPPING_ID', '$.initial_state.mappings');
  const occupied = new Set();
  const groups = new Map();
  mappings.forEach((mapping, index) => {
    const itemPath = `$.initial_state.mappings[${index}]`;
    if (!scenario.protocols[mapping.protocol].enabled) {
      fail('MAPPING_PROTOCOL_DISABLED', `${itemPath}.protocol`, 'mapping protocol must be enabled');
    }
    assertMappingOwnerProtocol(mapping, itemPath);
    if (mapping.epoch !== scenario.gateway.epoch.initial_seconds) {
      fail('INITIAL_MAPPING_EPOCH_MISMATCH', `${itemPath}.epoch`, 'must match gateway.epoch.initial_seconds');
    }
    if (mapping.generation !== scenario.gateway.initial_generation) {
      fail('INITIAL_MAPPING_GENERATION_MISMATCH', `${itemPath}.generation`, 'must match gateway.initial_generation');
    }
    assertLease(mapping.lease, itemPath);
    const collisionKey = `${normalizeAddress(mapping.external_address)}\u0000${mapping.external_port}\u0000${mapping.transport}`;
    if (occupied.has(collisionKey)) fail('MAPPING_COLLISION', itemPath, 'external address, port and transport are already allocated');
    occupied.add(collisionKey);
    if (mapping.atomic_group_id) {
      const group = groups.get(mapping.atomic_group_id) || [];
      group.push({ mapping, index });
      groups.set(mapping.atomic_group_id, group);
    }
  });
  for (const group of groups.values()) {
    const groupPath = `$.initial_state.mappings[${group[0].index}].atomic_group_id`;
    if (group.length !== 2 || new Set(group.map(({ mapping }) => mapping.transport)).size !== 2) {
      fail('ATOMIC_GROUP_INCOMPLETE', groupPath, 'an atomic group must contain exactly one tcp and one udp mapping');
    }
    const [first, second] = group;
    const ownershipIdentity = (owner) => ({
      kind: owner.kind,
      instance_id_digest: owner.instance_id_digest,
      ...(owner.gateway_identity_digest ? { gateway_identity_digest: owner.gateway_identity_digest } : {})
    });
    const fields = ['protocol', 'client_id', 'external_address', 'epoch', 'generation'];
    const mismatch = fields.find((key) => {
      const left = key === 'external_address' ? normalizeAddress(first.mapping[key]) : first.mapping[key];
      const right = key === 'external_address' ? normalizeAddress(second.mapping[key]) : second.mapping[key];
      return stableJson(left) !== stableJson(right);
    });
    if (mismatch) fail('ATOMIC_GROUP_INCOHERENT', `$.initial_state.mappings[${second.index}].${mismatch}`, 'tcp and udp members must agree on mapper identity and gateway epoch');
    if (stableJson(ownershipIdentity(first.mapping.owner)) !== stableJson(ownershipIdentity(second.mapping.owner))) {
      let ownerField = 'kind';
      if (first.mapping.owner.kind === second.mapping.owner.kind) {
        ownerField = first.mapping.owner.instance_id_digest !== second.mapping.owner.instance_id_digest ? 'instance_id_digest' : 'gateway_identity_digest';
      }
      fail('ATOMIC_GROUP_INCOHERENT', `$.initial_state.mappings[${second.index}].owner.${ownerField}`, 'tcp and udp members must have the same owner instance identity');
    }
  }
}

function assertMappingOwnerProtocol(mapping, itemPath) {
  if (mapping.owner.kind === 'none') return;
  const ownerProtocol = {
    'upnp-journal': 'upnp',
    'pcp-nonce': 'pcp',
    'natpmp-lease-scope': 'natpmp'
  }[mapping.owner.kind];
  if (ownerProtocol !== mapping.protocol) {
    fail('OWNER_PROTOCOL_MISMATCH', `${itemPath}.owner.kind`, 'owner kind must match the mapping protocol');
  }
}

function assertListeners(scenario) {
  const protocols = scenario.protocols;
  const enabled = Object.entries(protocols).filter(([, value]) => value.enabled).map(([name]) => name);
  if (enabled.length === 0) fail('NO_PROTOCOL_ENABLED', '$.protocols', 'at least one protocol must be enabled');
  const lanAddresses = new Set(scenario.gateway.lan_addresses.map(normalizeAddress));
  for (const name of ['upnp', 'pcp', 'natpmp']) {
    const listener = scenario.listeners[name];
    if (!lanAddresses.has(normalizeAddress(listener.bind_address))) {
      fail('LISTENER_BIND_NOT_LAN', `$.listeners.${name}.bind_address`, 'listener bind address must belong to gateway.lan_addresses');
    }
  }
  const bindings = new Map();
  const bind = (protocol, transport, address, port, fieldPath) => {
    if (!protocols[protocol].enabled) return;
    const key = `${transport}\u0000${normalizeAddress(address)}\u0000${port}`;
    if (bindings.has(key) && !((protocol === 'pcp' || protocol === 'natpmp') && bindings.get(key) && ['pcp', 'natpmp'].includes(bindings.get(key)))) {
      fail('LISTENER_PORT_COLLISION', fieldPath, 'enabled listeners cannot share a transport, address and port');
    }
    bindings.set(key, protocol);
  };
  bind('upnp', 'udp', scenario.listeners.upnp.bind_address, scenario.listeners.upnp.ssdp_port, '$.listeners.upnp.ssdp_port');
  bind('upnp', 'tcp', scenario.listeners.upnp.bind_address, scenario.listeners.upnp.http_port, '$.listeners.upnp.http_port');
  bind('pcp', 'udp', scenario.listeners.pcp.bind_address, scenario.listeners.pcp.port, '$.listeners.pcp.port');
  bind('natpmp', 'udp', scenario.listeners.natpmp.bind_address, scenario.listeners.natpmp.port, '$.listeners.natpmp.port');
}

function assertCrossFieldInvariants(scenario) {
  if (scenario.allocation.strategy === 'range' && scenario.allocation.range_start > scenario.allocation.range_end) {
    fail('ALLOCATION_RANGE_INVALID', '$.allocation.range_end', 'range_end must be greater than or equal to range_start');
  }
  assertMappings(scenario);
  assertUnique(scenario.initial_state.response_queue, 'response_id', 'DUPLICATE_RESPONSE_ID', '$.initial_state.response_queue');
  assertUnique(scenario.faults, 'fault_id', 'DUPLICATE_FAULT_ID', '$.faults');
  scenario.initial_state.response_queue.forEach((response, index) => {
    if (!scenario.protocols[response.protocol].enabled) {
      fail('RESPONSE_PROTOCOL_DISABLED', `$.initial_state.response_queue[${index}].protocol`, 'queued response protocol must be enabled');
    }
  });
  scenario.faults.forEach((fault, index) => {
    if (fault.match.protocol && !scenario.protocols[fault.match.protocol].enabled) {
      fail('FAULT_PROTOCOL_DISABLED', `$.faults[${index}].match.protocol`, 'fault protocol must be enabled');
    }
  });
  assertListeners(scenario);
}

function loadScenarioFromObject(value) {
  const scenario = cloneJsonObject(value);
  assertSchema(scenario);
  assertCrossFieldInvariants(scenario);
  return deepFreeze(scenario);
}

function loadScenarioFromText(text) {
  const scenario = parseText(text);
  return loadScenarioFromObject(scenario);
}

function loadScenarioFromFile(filePath) {
  if (typeof filePath !== 'string' || filePath.length === 0 || filePath.includes('\0')) {
    fail('SCENARIO_FILE_PATH_INVALID', '$', 'file path must be a non-empty path without NUL');
  }
  const resolvedPath = path.resolve(filePath);
  let stat;
  try {
    stat = fs.statSync(resolvedPath);
  } catch {
    fail('SCENARIO_FILE_UNREADABLE', '$', 'scenario file cannot be read');
  }
  if (!stat.isFile()) fail('SCENARIO_FILE_UNREADABLE', '$', 'scenario path must name a regular file');
  if (stat.size > MAX_SCENARIO_BYTES) fail('SCENARIO_TOO_LARGE', '$', `scenario exceeds ${MAX_SCENARIO_BYTES} bytes`);
  let bytes;
  try {
    bytes = fs.readFileSync(resolvedPath);
  } catch {
    fail('SCENARIO_FILE_UNREADABLE', '$', 'scenario file cannot be read');
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('SCENARIO_UTF8_INVALID', '$', 'scenario file is not valid UTF-8');
  }
  return loadScenarioFromText(text);
}

module.exports = {
  MAX_SCENARIO_BYTES,
  ScenarioValidationError,
  loadScenarioFromFile,
  loadScenarioFromObject,
  loadScenarioFromText
};
