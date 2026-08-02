'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  CATALOG_VERSION,
  FaultCatalogError,
  compileFaultCatalog,
  evaluateFaultCatalog,
  resetFaultCatalog
} = require('../fault_catalog');

const ACTIONS = Object.freeze([
  { type: 'delay', delay_ms: 5, jitter_ms: 0 },
  { type: 'drop' },
  { type: 'duplicate', copies: 2 },
  { type: 'reorder', release_after_matches: 1 },
  { type: 'wrong-source', interface_id: 'lan-2', source_port: 5352 },
  { type: 'truncate', length_bytes: 4 },
  { type: 'replay', response_id: 'response-1' },
  { type: 'reject', result_code: 'network-failure' },
  { type: 'cap-lease', lifetime_seconds: 30 },
  { type: 'remove-mapping' },
  { type: 'restart-gateway', restart_epoch_seconds: 0 },
  { type: 'change-wan', wan_address: '198.51.100.7' },
  { type: 'change-port', external_port: 45000 },
  { type: 'conflict', conflicting_client_id: 'client-b' }
]);

const EXPECTED_RESULTS = Object.freeze([
  'response-delayed',
  'response-dropped',
  'response-duplicated',
  'response-reordered',
  'wrong-source-observed',
  'malformed-response',
  'response-replayed',
  'request-rejected',
  'lease-capped',
  'mapping-removed',
  'gateway-restarted',
  'wan-address-changed',
  'external-port-changed',
  'mapping-conflict'
]);

function rule(overrides = {}) {
  return {
    fault_id: 'fault-1',
    enabled: true,
    match: { protocol: 'natpmp' },
    trigger: { after_matches: 0, times: 1 },
    action: { type: 'drop' },
    ...overrides
  };
}

function event(overrides = {}) {
  return {
    protocol: 'natpmp',
    operation: 'map',
    transport: 'tcp',
    client_id: 'client-a',
    request_ordinal: 1,
    renewal: false,
    ...overrides
  };
}

function expectCatalogError(action, reasonCode, fieldPath) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof FaultCatalogError);
    if (reasonCode !== undefined) assert.equal(error.reason_code, reasonCode);
    if (fieldPath !== undefined) assert.equal(error.field_path, fieldPath);
    return true;
  });
}

test('F01 compiles every typed action with complete execution metadata', () => {
  const rules = ACTIONS.map((action, index) => rule({
    fault_id: `fault-${index + 1}`,
    match: index === 0 ? { operation: 'map' } : { protocol: index % 2 ? 'pcp' : 'upnp' },
    trigger: { after_matches: index, times: index + 1 },
    action
  }));
  const catalog = compileFaultCatalog(rules);
  assert.equal(catalog.catalog_version, CATALOG_VERSION);
  assert.equal(catalog.faults.length, ACTIONS.length);
  catalog.faults.forEach((fault, index) => {
    assert.equal(fault.fault_id, `fault-${index + 1}`);
    assert.equal(fault.protocol, index === 0 ? 'any' : index % 2 ? 'pcp' : 'upnp');
    assert.ok(['pre-encode-semantic', 'post-encode-pre-send', 'state-transition'].includes(fault.injection_point));
    assert.equal(fault.configured_times, index + 1);
    assert.equal(fault.remaining_times, index + 1);
    assert.equal(fault.expected_result, EXPECTED_RESULTS[index]);
    assert.equal(fault.auto_reset, true);
    assert.equal(fault.active, true);
    assert.equal(fault.match_count, 0);
    assert.equal(fault.application_count, 0);
    assert.deepEqual(fault.action, ACTIONS[index]);
    assert.ok(Object.isFrozen(fault));
    assert.ok(Object.isFrozen(fault.action));
  });
  assert.ok(Object.isFrozen(catalog));
  assert.ok(Object.isFrozen(catalog.faults));
});

test('F01 honors after_matches and finite times, then auto-deactivates exactly', () => {
  let catalog = compileFaultCatalog([rule({ trigger: { after_matches: 2, times: 2 } })]);
  let result = evaluateFaultCatalog(catalog, event());
  catalog = result.catalog;
  assert.equal(result.applied_faults.length, 0);
  result = evaluateFaultCatalog(catalog, event());
  catalog = result.catalog;
  assert.equal(result.applied_faults.length, 0);

  result = evaluateFaultCatalog(catalog, event());
  catalog = result.catalog;
  assert.equal(result.applied_faults[0].application_ordinal, 1);
  assert.equal(catalog.faults[0].remaining_times, 1);
  assert.equal(catalog.faults[0].active, true);

  result = evaluateFaultCatalog(catalog, event());
  catalog = result.catalog;
  assert.equal(result.applied_faults[0].application_ordinal, 2);
  assert.equal(catalog.faults[0].remaining_times, 0);
  assert.equal(catalog.faults[0].active, false);
  assert.equal(catalog.faults[0].match_count, 4);
  assert.equal(catalog.faults[0].application_count, 2);

  result = evaluateFaultCatalog(catalog, event());
  assert.equal(result.catalog, catalog);
  assert.deepEqual(result.applied_faults, []);
});

test('F01 matches protocol, operation, transport, client, ordinal and renewal jointly', () => {
  const match = {
    protocol: 'pcp',
    operation: 'renew',
    transport: 'udp',
    client_id: 'client-b',
    request_ordinal: 7,
    renewal_only: true
  };
  const original = compileFaultCatalog([rule({ match, trigger: { after_matches: 0, times: 2 } })]);
  const wrongEvents = [
    event({ protocol: 'natpmp', operation: 'renew', transport: 'udp', client_id: 'client-b', request_ordinal: 7, renewal: true }),
    event({ protocol: 'pcp', operation: 'map', transport: 'udp', client_id: 'client-b', request_ordinal: 7, renewal: true }),
    event({ protocol: 'pcp', operation: 'renew', transport: 'tcp', client_id: 'client-b', request_ordinal: 7, renewal: true }),
    event({ protocol: 'pcp', operation: 'renew', transport: 'udp', client_id: 'client-a', request_ordinal: 7, renewal: true }),
    event({ protocol: 'pcp', operation: 'renew', transport: 'udp', client_id: 'client-b', request_ordinal: 8, renewal: true }),
    event({ protocol: 'pcp', operation: 'renew', transport: 'udp', client_id: 'client-b', request_ordinal: 7, renewal: false })
  ];
  for (const wrong of wrongEvents) {
    const result = evaluateFaultCatalog(original, wrong);
    assert.equal(result.catalog, original);
    assert.equal(result.applied_faults.length, 0);
  }
  const result = evaluateFaultCatalog(original, event({
    protocol: 'pcp',
    operation: 'renew',
    transport: 'udp',
    client_id: 'client-b',
    request_ordinal: 7,
    renewal: true
  }));
  assert.equal(result.applied_faults[0].fault_id, 'fault-1');
  assert.equal(result.catalog.faults[0].match_count, 1);
});

test('F01 keeps disabled rules inert and reset preserves their configured state', () => {
  const catalog = compileFaultCatalog([rule({ enabled: false, trigger: { after_matches: 0, times: 9 } })]);
  assert.equal(catalog.faults[0].configured_times, 9);
  assert.equal(catalog.faults[0].remaining_times, 0);
  assert.equal(catalog.faults[0].active, false);
  const result = evaluateFaultCatalog(catalog, event());
  assert.equal(result.catalog, catalog);
  assert.deepEqual(result.applied_faults, []);
  const reset = resetFaultCatalog(catalog);
  assert.equal(reset.faults[0].active, false);
  assert.equal(reset.faults[0].remaining_times, 0);
});

test('F01 applies overlapping rules in declarative order and advances each independently', () => {
  const catalog = compileFaultCatalog([
    rule({ fault_id: 'fault-first', match: { protocol: 'natpmp' }, action: { type: 'drop' } }),
    rule({ fault_id: 'fault-second', match: { operation: 'map' }, action: { type: 'truncate', length_bytes: 3 } }),
    rule({ fault_id: 'fault-third', match: { protocol: 'pcp' }, action: { type: 'drop' } })
  ]);
  const result = evaluateFaultCatalog(catalog, event());
  assert.deepEqual(result.applied_faults.map((fault) => fault.fault_id), ['fault-first', 'fault-second']);
  assert.equal(result.catalog.faults[0].active, false);
  assert.equal(result.catalog.faults[1].active, false);
  assert.equal(result.catalog.faults[2].active, true);
  assert.equal(result.catalog.faults[2].match_count, 0);
});

test('F01 manual reset restores counters and original enabled state after auto-reset', () => {
  const initial = compileFaultCatalog([
    rule({ fault_id: 'fault-on' }),
    rule({ fault_id: 'fault-off', enabled: false })
  ]);
  const spent = evaluateFaultCatalog(initial, event()).catalog;
  assert.equal(spent.faults[0].active, false);
  const reset = resetFaultCatalog(spent);
  assert.notEqual(reset, spent);
  assert.equal(reset.faults[0].active, true);
  assert.equal(reset.faults[0].remaining_times, 1);
  assert.equal(reset.faults[0].match_count, 0);
  assert.equal(reset.faults[0].application_count, 0);
  assert.equal(reset.faults[1].active, false);
});

test('F01 snapshots caller data and never mutates rules, events or prior catalog versions', () => {
  const inputRule = rule({ action: { type: 'change-port', external_port: 45000 } });
  const inputEvent = event();
  const catalog = compileFaultCatalog([inputRule]);
  inputRule.fault_id = 'changed';
  inputRule.match.protocol = 'pcp';
  inputRule.action.external_port = 45001;
  assert.equal(catalog.faults[0].fault_id, 'fault-1');
  assert.equal(catalog.faults[0].match.protocol, 'natpmp');
  assert.equal(catalog.faults[0].action.external_port, 45000);
  const result = evaluateFaultCatalog(catalog, inputEvent);
  inputEvent.protocol = 'pcp';
  assert.equal(catalog.faults[0].application_count, 0);
  assert.equal(catalog.faults[0].active, true);
  assert.equal(result.catalog.faults[0].application_count, 1);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.applied_faults));
  assert.ok(Object.isFrozen(result.applied_faults[0]));
});

test('F01 rejects duplicate IDs and unknown or structurally invalid actions', () => {
  expectCatalogError(
    () => compileFaultCatalog([rule(), rule()]),
    'FAULT_CATALOG_DUPLICATE_ID',
    '$.faults[1].fault_id'
  );
  for (const action of [
    { type: 'unknown' },
    { type: 'toString' },
    { type: 'drop', extra: true },
    { type: 'delay', delay_ms: 1 },
    { type: 'wrong-source', interface_id: 'Bad', source_port: 1 },
    { type: 'reject', result_code: 'BAD CODE' },
    { type: 'change-wan', wan_address: '999.1.1.1' }
  ]) {
    expectCatalogError(() => compileFaultCatalog([rule({ action })]), ['unknown', 'toString'].includes(action.type)
      ? 'FAULT_CATALOG_ACTION_UNKNOWN'
      : /extra|delay/.test(JSON.stringify(action)) ? 'FAULT_CATALOG_SHAPE_INVALID' : 'FAULT_CATALOG_VALUE_INVALID');
  }
  expectCatalogError(() => compileFaultCatalog([rule({ action: { type: {} } })]), 'FAULT_CATALOG_ACTION_UNKNOWN');
  expectCatalogError(() => compileFaultCatalog([rule({ action: { type: Symbol('drop') } })]), 'FAULT_CATALOG_ACTION_UNKNOWN');
});

test('F01 rejects hostile arrays, proxies, accessors, symbols and sparse input without invoking traps', () => {
  let traps = 0;
  const trap = () => { traps += 1; throw new Error('secret'); };
  const proxy = new Proxy(rule(), {
    get: trap,
    getOwnPropertyDescriptor: trap,
    getPrototypeOf: trap,
    ownKeys: trap
  });
  expectCatalogError(() => compileFaultCatalog([proxy]), 'FAULT_CATALOG_INPUT_INVALID');
  assert.equal(traps, 0);

  const proxyArray = new Proxy([rule()], { get: trap, ownKeys: trap });
  expectCatalogError(() => compileFaultCatalog(proxyArray), 'FAULT_CATALOG_INPUT_INVALID');
  assert.equal(traps, 0);

  const hostileType = new Proxy({}, { get: trap });
  expectCatalogError(
    () => compileFaultCatalog([rule({ action: { type: hostileType } })]),
    'FAULT_CATALOG_ACTION_UNKNOWN'
  );
  assert.equal(traps, 0);

  const accessor = rule();
  Object.defineProperty(accessor, 'enabled', { enumerable: true, get: () => true });
  expectCatalogError(() => compileFaultCatalog([accessor]), 'FAULT_CATALOG_INPUT_INVALID', '$.faults[0].enabled');

  const symbolRule = rule();
  symbolRule[Symbol('hidden')] = true;
  expectCatalogError(() => compileFaultCatalog([symbolRule]), 'FAULT_CATALOG_INPUT_INVALID');

  const sparse = new Array(1);
  expectCatalogError(() => compileFaultCatalog(sparse), 'FAULT_CATALOG_INPUT_INVALID', '$.faults[0]');
  const custom = [rule()];
  custom.extra = true;
  expectCatalogError(() => compileFaultCatalog(custom), 'FAULT_CATALOG_INPUT_INVALID');
});

test('F01 rejects scalar boundaries including negative zero', () => {
  const invalidRules = [
    rule({ trigger: { after_matches: -0, times: 1 } }),
    rule({ trigger: { after_matches: 0, times: 0 } }),
    rule({ trigger: { after_matches: 0, times: 1000001 } }),
    rule({ match: { request_ordinal: -0 } }),
    rule({ action: { type: 'duplicate', copies: 17 } }),
    rule({ action: { type: 'truncate', length_bytes: -0 } }),
    rule({ action: { type: 'change-port', external_port: 65536 } }),
    rule({ action: { type: 'restart-gateway', restart_epoch_seconds: 0x100000000 } })
  ];
  for (const invalid of invalidRules) {
    expectCatalogError(() => compileFaultCatalog([invalid]), 'FAULT_CATALOG_VALUE_INVALID');
  }
});

test('F01 rejects forged catalogs and closed event boundary violations', () => {
  expectCatalogError(() => evaluateFaultCatalog({ catalog_version: CATALOG_VERSION, faults: [] }, event()), 'FAULT_CATALOG_STATE_INVALID');
  expectCatalogError(() => resetFaultCatalog(Object.freeze({ catalog_version: CATALOG_VERSION, faults: Object.freeze([]) })), 'FAULT_CATALOG_STATE_INVALID');
  const catalog = compileFaultCatalog([rule()]);
  for (const invalid of [
    { ...event(), extra: true },
    { ...event(), protocol: 'icmp' },
    { ...event(), transport: 'sctp' },
    { ...event(), client_id: 'Bad' },
    { ...event(), request_ordinal: -0 },
    { ...event(), renewal: 1 }
  ]) {
    expectCatalogError(() => evaluateFaultCatalog(catalog, invalid));
  }
  const hostile = new Proxy(event(), {});
  expectCatalogError(() => evaluateFaultCatalog(catalog, hostile), 'FAULT_CATALOG_INPUT_INVALID');
});

test('F01 is pure: evaluation owns no timers, sockets or process-wide fault state', () => {
  const beforeHandles = process._getActiveHandles().length;
  const first = compileFaultCatalog([rule({ trigger: { after_matches: 0, times: 2 } })]);
  const second = compileFaultCatalog([rule({ trigger: { after_matches: 0, times: 2 } })]);
  const firstResult = evaluateFaultCatalog(first, event());
  assert.equal(firstResult.catalog.faults[0].application_count, 1);
  assert.equal(second.faults[0].application_count, 0);
  assert.equal(process._getActiveHandles().length, beforeHandles);
});
