'use strict';

const { types } = require('node:util');
const { normalizeAddress } = require('./address');

const CATALOG_VERSION = 'ese.v92.t8.fault-catalog/v1';
const MAX_FAULTS = 256;
const MAX_UINT32 = 0xffffffff;
const MAX_UINT53 = Number.MAX_SAFE_INTEGER;
const ID_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const RESULT_CODE_PATTERN = /^[a-z0-9_-]+$/;
const PROTOCOLS = new Set(['upnp', 'pcp', 'natpmp']);
const OPERATIONS = new Set([
  'discover',
  'get-external-address',
  'announce',
  'map',
  'renew',
  'delete',
  'readback',
  'enumerate'
]);
const TRANSPORTS = new Set(['tcp', 'udp']);

const ACTION_CONTRACTS = Object.freeze({
  delay: Object.freeze({
    keys: Object.freeze(['type', 'delay_ms', 'jitter_ms']),
    injection_point: 'post-encode-pre-send',
    expected_result: 'response-delayed'
  }),
  drop: Object.freeze({
    keys: Object.freeze(['type']),
    injection_point: 'post-encode-pre-send',
    expected_result: 'response-dropped'
  }),
  duplicate: Object.freeze({
    keys: Object.freeze(['type', 'copies']),
    injection_point: 'post-encode-pre-send',
    expected_result: 'response-duplicated'
  }),
  reorder: Object.freeze({
    keys: Object.freeze(['type', 'release_after_matches']),
    injection_point: 'post-encode-pre-send',
    expected_result: 'response-reordered'
  }),
  'wrong-source': Object.freeze({
    keys: Object.freeze(['type', 'interface_id', 'source_port']),
    injection_point: 'post-encode-pre-send',
    expected_result: 'wrong-source-observed'
  }),
  truncate: Object.freeze({
    keys: Object.freeze(['type', 'length_bytes']),
    injection_point: 'post-encode-pre-send',
    expected_result: 'malformed-response'
  }),
  replay: Object.freeze({
    keys: Object.freeze(['type', 'response_id']),
    injection_point: 'post-encode-pre-send',
    expected_result: 'response-replayed'
  }),
  reject: Object.freeze({
    keys: Object.freeze(['type', 'result_code']),
    injection_point: 'pre-encode-semantic',
    expected_result: 'request-rejected'
  }),
  'cap-lease': Object.freeze({
    keys: Object.freeze(['type', 'lifetime_seconds']),
    injection_point: 'pre-encode-semantic',
    expected_result: 'lease-capped'
  }),
  'remove-mapping': Object.freeze({
    keys: Object.freeze(['type']),
    injection_point: 'state-transition',
    expected_result: 'mapping-removed'
  }),
  'restart-gateway': Object.freeze({
    keys: Object.freeze(['type', 'restart_epoch_seconds']),
    injection_point: 'state-transition',
    expected_result: 'gateway-restarted'
  }),
  'change-wan': Object.freeze({
    keys: Object.freeze(['type', 'wan_address']),
    injection_point: 'state-transition',
    expected_result: 'wan-address-changed'
  }),
  'change-port': Object.freeze({
    keys: Object.freeze(['type', 'external_port']),
    injection_point: 'pre-encode-semantic',
    expected_result: 'external-port-changed'
  }),
  conflict: Object.freeze({
    keys: Object.freeze(['type', 'conflicting_client_id']),
    injection_point: 'state-transition',
    expected_result: 'mapping-conflict'
  })
});

const catalogBrand = new WeakSet();

class FaultCatalogError extends Error {
  constructor(reasonCode, fieldPath, detail) {
    super(`${reasonCode} at ${fieldPath}: ${detail}`);
    this.name = 'FaultCatalogError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath, detail) {
  throw new FaultCatalogError(reasonCode, fieldPath, detail);
}

function assertPlainDataObject(value, fieldPath) {
  if (types.isProxy(value)) fail('FAULT_CATALOG_INPUT_INVALID', fieldPath, 'proxies are not data');
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail('FAULT_CATALOG_INPUT_INVALID', fieldPath, 'must be a plain data object');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    fail('FAULT_CATALOG_INPUT_INVALID', fieldPath, 'must have a plain or null prototype');
  }
  if (Object.getOwnPropertySymbols(value).length) {
    fail('FAULT_CATALOG_INPUT_INVALID', fieldPath, 'symbol properties are not allowed');
  }
  for (const key of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor.enumerable || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      fail('FAULT_CATALOG_INPUT_INVALID', `${fieldPath}.${key}`, 'only enumerable data properties are allowed');
    }
  }
}

function ownData(value, key, fieldPath) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !descriptor.enumerable || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
    fail('FAULT_CATALOG_INPUT_INVALID', `${fieldPath}.${key}`, 'required data property is missing');
  }
  return descriptor.value;
}

function assertExactKeys(value, expected, fieldPath) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail('FAULT_CATALOG_SHAPE_INVALID', fieldPath, `expected exactly: ${wanted.join(', ')}`);
  }
}

function assertInteger(value, minimum, maximum, fieldPath) {
  if (!Number.isInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) {
    fail('FAULT_CATALOG_VALUE_INVALID', fieldPath, `must be an integer in ${minimum}..${maximum}`);
  }
  return value;
}

function assertId(value, fieldPath) {
  if (typeof value !== 'string' || value.length > 64 || !ID_PATTERN.test(value)) {
    fail('FAULT_CATALOG_VALUE_INVALID', fieldPath, 'must be a valid laboratory identifier');
  }
  return value;
}

function freezeRecord(value) {
  return Object.freeze({ ...value });
}

function snapshotMatch(value, fieldPath) {
  assertPlainDataObject(value, fieldPath);
  const allowed = new Set(['protocol', 'operation', 'transport', 'client_id', 'request_ordinal', 'renewal_only']);
  const keys = Object.keys(value);
  if (keys.length === 0 || keys.some((key) => !allowed.has(key))) {
    fail('FAULT_CATALOG_SHAPE_INVALID', fieldPath, 'match must contain one or more known fields');
  }
  const result = {};
  for (const key of keys) {
    const item = ownData(value, key, fieldPath);
    if (key === 'protocol' && !PROTOCOLS.has(item)) fail('FAULT_CATALOG_VALUE_INVALID', `${fieldPath}.protocol`, 'unknown protocol');
    if (key === 'operation' && !OPERATIONS.has(item)) fail('FAULT_CATALOG_VALUE_INVALID', `${fieldPath}.operation`, 'unknown operation');
    if (key === 'transport' && !TRANSPORTS.has(item)) fail('FAULT_CATALOG_VALUE_INVALID', `${fieldPath}.transport`, 'unknown transport');
    if (key === 'client_id') assertId(item, `${fieldPath}.client_id`);
    if (key === 'request_ordinal') assertInteger(item, 1, MAX_UINT53, `${fieldPath}.request_ordinal`);
    if (key === 'renewal_only' && typeof item !== 'boolean') fail('FAULT_CATALOG_VALUE_INVALID', `${fieldPath}.renewal_only`, 'must be boolean');
    result[key] = item;
  }
  return freezeRecord(result);
}

function snapshotTrigger(value, fieldPath) {
  assertPlainDataObject(value, fieldPath);
  assertExactKeys(value, ['after_matches', 'times'], fieldPath);
  return freezeRecord({
    after_matches: assertInteger(ownData(value, 'after_matches', fieldPath), 0, MAX_UINT53, `${fieldPath}.after_matches`),
    times: assertInteger(ownData(value, 'times', fieldPath), 1, 1000000, `${fieldPath}.times`)
  });
}

function snapshotAction(value, fieldPath) {
  assertPlainDataObject(value, fieldPath);
  const type = ownData(value, 'type', fieldPath);
  if (typeof type !== 'string') fail('FAULT_CATALOG_ACTION_UNKNOWN', `${fieldPath}.type`, 'fault action type must be a string');
  const contract = Object.prototype.hasOwnProperty.call(ACTION_CONTRACTS, type) ? ACTION_CONTRACTS[type] : undefined;
  if (!contract) fail('FAULT_CATALOG_ACTION_UNKNOWN', `${fieldPath}.type`, 'unknown fault action');
  assertExactKeys(value, contract.keys, fieldPath);
  const result = { type };
  for (const key of contract.keys.slice(1)) result[key] = ownData(value, key, fieldPath);
  if (type === 'delay') {
    assertInteger(result.delay_ms, 0, MAX_UINT32, `${fieldPath}.delay_ms`);
    assertInteger(result.jitter_ms, 0, MAX_UINT32, `${fieldPath}.jitter_ms`);
  } else if (type === 'duplicate') {
    assertInteger(result.copies, 2, 16, `${fieldPath}.copies`);
  } else if (type === 'reorder') {
    assertInteger(result.release_after_matches, 1, 1000000, `${fieldPath}.release_after_matches`);
  } else if (type === 'wrong-source') {
    assertId(result.interface_id, `${fieldPath}.interface_id`);
    assertInteger(result.source_port, 1, 65535, `${fieldPath}.source_port`);
  } else if (type === 'truncate') {
    assertInteger(result.length_bytes, 0, 65535, `${fieldPath}.length_bytes`);
  } else if (type === 'replay') {
    assertId(result.response_id, `${fieldPath}.response_id`);
  } else if (type === 'reject') {
    if (typeof result.result_code !== 'string' || result.result_code.length > 64 || !RESULT_CODE_PATTERN.test(result.result_code)) {
      fail('FAULT_CATALOG_VALUE_INVALID', `${fieldPath}.result_code`, 'must be a lowercase result code');
    }
  } else if (type === 'cap-lease') {
    assertInteger(result.lifetime_seconds, 0, MAX_UINT32, `${fieldPath}.lifetime_seconds`);
  } else if (type === 'restart-gateway') {
    assertInteger(result.restart_epoch_seconds, 0, MAX_UINT32, `${fieldPath}.restart_epoch_seconds`);
  } else if (type === 'change-wan') {
    const normalized = typeof result.wan_address === 'string' ? normalizeAddress(result.wan_address) : null;
    if (normalized === null) fail('FAULT_CATALOG_VALUE_INVALID', `${fieldPath}.wan_address`, 'must be an IP address');
    result.wan_address = normalized;
  } else if (type === 'change-port') {
    assertInteger(result.external_port, 1, 65535, `${fieldPath}.external_port`);
  } else if (type === 'conflict') {
    assertId(result.conflicting_client_id, `${fieldPath}.conflicting_client_id`);
  }
  return freezeRecord(result);
}

function snapshotRule(value, index) {
  const fieldPath = `$.faults[${index}]`;
  assertPlainDataObject(value, fieldPath);
  assertExactKeys(value, ['fault_id', 'enabled', 'match', 'trigger', 'action'], fieldPath);
  const faultId = assertId(ownData(value, 'fault_id', fieldPath), `${fieldPath}.fault_id`);
  const enabled = ownData(value, 'enabled', fieldPath);
  if (typeof enabled !== 'boolean') fail('FAULT_CATALOG_VALUE_INVALID', `${fieldPath}.enabled`, 'must be boolean');
  const match = snapshotMatch(ownData(value, 'match', fieldPath), `${fieldPath}.match`);
  const trigger = snapshotTrigger(ownData(value, 'trigger', fieldPath), `${fieldPath}.trigger`);
  const action = snapshotAction(ownData(value, 'action', fieldPath), `${fieldPath}.action`);
  const contract = ACTION_CONTRACTS[action.type];
  return Object.freeze({
    fault_id: faultId,
    protocol: match.protocol || 'any',
    injection_point: contract.injection_point,
    configured_times: trigger.times,
    remaining_times: enabled ? trigger.times : 0,
    expected_result: contract.expected_result,
    auto_reset: true,
    match,
    trigger,
    action,
    initial_enabled: enabled,
    match_count: 0,
    application_count: 0,
    active: enabled
  });
}

function assertDenseArray(value, fieldPath) {
  if (types.isProxy(value)) fail('FAULT_CATALOG_INPUT_INVALID', fieldPath, 'proxies are not data');
  if (!Array.isArray(value)) fail('FAULT_CATALOG_INPUT_INVALID', fieldPath, 'must be an array');
  const names = Object.getOwnPropertyNames(value);
  if (Object.getOwnPropertySymbols(value).length || names.some((name) => name !== 'length' && !/^(0|[1-9]\d*)$/.test(name))) {
    fail('FAULT_CATALOG_INPUT_INVALID', fieldPath, 'must be a dense array without custom properties');
  }
  if (value.length > MAX_FAULTS) fail('FAULT_CATALOG_LIMIT_EXCEEDED', fieldPath, `cannot contain more than ${MAX_FAULTS} faults`);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
      fail('FAULT_CATALOG_INPUT_INVALID', `${fieldPath}[${index}]`, 'must be a dense data array');
    }
  }
}

function makeCatalog(faults) {
  const catalog = Object.freeze({
    catalog_version: CATALOG_VERSION,
    faults: Object.freeze(faults)
  });
  catalogBrand.add(catalog);
  return catalog;
}

function compileFaultCatalog(rules) {
  assertDenseArray(rules, '$.faults');
  const seen = new Set();
  const faults = rules.map((rule, index) => {
    const fault = snapshotRule(rule, index);
    if (seen.has(fault.fault_id)) fail('FAULT_CATALOG_DUPLICATE_ID', `$.faults[${index}].fault_id`, 'fault_id must be unique');
    seen.add(fault.fault_id);
    return fault;
  });
  return makeCatalog(faults);
}

function assertCatalog(value) {
  if (!value || typeof value !== 'object' || !catalogBrand.has(value)) {
    fail('FAULT_CATALOG_STATE_INVALID', '$.catalog', 'catalog was not produced by this module');
  }
}

function snapshotEvent(value) {
  const fieldPath = '$.event';
  assertPlainDataObject(value, fieldPath);
  assertExactKeys(value, ['protocol', 'operation', 'transport', 'client_id', 'request_ordinal', 'renewal'], fieldPath);
  const event = {
    protocol: ownData(value, 'protocol', fieldPath),
    operation: ownData(value, 'operation', fieldPath),
    transport: ownData(value, 'transport', fieldPath),
    client_id: ownData(value, 'client_id', fieldPath),
    request_ordinal: ownData(value, 'request_ordinal', fieldPath),
    renewal: ownData(value, 'renewal', fieldPath)
  };
  if (!PROTOCOLS.has(event.protocol)) fail('FAULT_CATALOG_EVENT_INVALID', `${fieldPath}.protocol`, 'unknown protocol');
  if (!OPERATIONS.has(event.operation)) fail('FAULT_CATALOG_EVENT_INVALID', `${fieldPath}.operation`, 'unknown operation');
  if (event.transport !== null && !TRANSPORTS.has(event.transport)) fail('FAULT_CATALOG_EVENT_INVALID', `${fieldPath}.transport`, 'must be tcp, udp or null');
  if (event.client_id !== null) assertId(event.client_id, `${fieldPath}.client_id`);
  assertInteger(event.request_ordinal, 1, MAX_UINT53, `${fieldPath}.request_ordinal`);
  if (typeof event.renewal !== 'boolean') fail('FAULT_CATALOG_EVENT_INVALID', `${fieldPath}.renewal`, 'must be boolean');
  return event;
}

function matchesEvent(match, event) {
  if (match.protocol !== undefined && match.protocol !== event.protocol) return false;
  if (match.operation !== undefined && match.operation !== event.operation) return false;
  if (match.transport !== undefined && match.transport !== event.transport) return false;
  if (match.client_id !== undefined && match.client_id !== event.client_id) return false;
  if (match.request_ordinal !== undefined && match.request_ordinal !== event.request_ordinal) return false;
  if (match.renewal_only === true && !event.renewal) return false;
  return true;
}

function updatedFault(fault, matchCount, applicationCount) {
  const remaining = Math.max(0, fault.configured_times - applicationCount);
  return Object.freeze({
    ...fault,
    remaining_times: remaining,
    match_count: matchCount,
    application_count: applicationCount,
    active: fault.initial_enabled && remaining > 0
  });
}

function evaluateFaultCatalog(catalog, eventValue) {
  assertCatalog(catalog);
  const event = snapshotEvent(eventValue);
  let changed = false;
  const applied = [];
  const faults = catalog.faults.map((fault) => {
    if (!fault.active || !matchesEvent(fault.match, event)) return fault;
    changed = true;
    if (fault.match_count < fault.trigger.after_matches) {
      return updatedFault(fault, fault.match_count + 1, fault.application_count);
    }
    const matchCount = Math.min(MAX_UINT53, fault.match_count + 1);
    const applicationCount = fault.application_count + 1;
    const next = updatedFault(fault, matchCount, applicationCount);
    applied.push(Object.freeze({
      fault_id: fault.fault_id,
      protocol: fault.protocol,
      injection_point: fault.injection_point,
      expected_result: fault.expected_result,
      auto_reset: fault.auto_reset,
      application_ordinal: applicationCount,
      action: fault.action
    }));
    return next;
  });
  return Object.freeze({
    catalog: changed ? makeCatalog(faults) : catalog,
    applied_faults: Object.freeze(applied)
  });
}

function resetFaultCatalog(catalog) {
  assertCatalog(catalog);
  return makeCatalog(catalog.faults.map((fault) => Object.freeze({
    ...fault,
    remaining_times: fault.initial_enabled ? fault.configured_times : 0,
    match_count: 0,
    application_count: 0,
    active: fault.initial_enabled
  })));
}

module.exports = {
  CATALOG_VERSION,
  FaultCatalogError,
  compileFaultCatalog,
  evaluateFaultCatalog,
  resetFaultCatalog
};
