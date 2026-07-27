'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { EVENT_SCHEMA, StructuredLogError, canonicalJson, createStructuredLog, projectPublicMappings, createCanonicalReport } = require('../structured_log');

function event(overrides = {}) { return { schema: EVENT_SCHEMA, scenario_id: 'scenario-1', run_id: 'run-1', event: 'map-created', monotonic_ms: 10, epoch: 2, generation: 3, protocol: 'pcp', transport: 'udp', mapping_id: 'map-1', outcome: 'applied', reason_code: 'none', gateway_id: 'gateway-1', ...overrides }; }
function mapping(overrides = {}) { return { mapping_id: 'map-1', protocol: 'pcp', transport: 'udp', client_id: 'client-1', internal_address: '192.0.2.10', internal_port: 1, requested_external_port: 0, external_address: '2001:db8::7', external_port: 2, lease: { lifetime_seconds: 1, created_monotonic_ms: 0, expires_monotonic_ms: 1000 }, owner: { kind: 'pcp-nonce', instance_id_digest: 'a'.repeat(64), nonce: 'b'.repeat(24) }, epoch: 2, generation: 3, ...overrides }; }
function err(fn, code, path) { assert.throws(fn, (e) => e instanceof StructuredLogError && e.reason_code === code && e.field_path === path); }

test('B05: events are versioned, sequenced and monotonic from explicit input', () => {
  const log = createStructuredLog(); const first = log.append(event()); const second = log.append(event({ monotonic_ms: 10, event: 'map-renewed' }));
  assert.equal(first.sequence, 1); assert.equal(second.sequence, 2); assert.equal(log.snapshot().length, 2);
  err(() => log.append(event({ monotonic_ms: 9 })), 'STRUCTURED_LOG_TIME_REGRESSION', '$.monotonic_ms');
  err(() => log.append(event({ scenario_id: 'other-scenario' })), 'STRUCTURED_LOG_IDENTITY_MISMATCH', '$.scenario_id');
  err(() => log.append(event({ run_id: 'other-run' })), 'STRUCTURED_LOG_IDENTITY_MISMATCH', '$.run_id');
});

test('B05: canonical events do not depend on property insertion order and unknown fields fail closed', () => {
  const left = createStructuredLog(); const right = createStructuredLog(); const value = event(); const reordered = Object.fromEntries(Object.keys(value).reverse().map((k) => [k, value[k]]));
  left.append(value); right.append(reordered); assert.equal(left.canonicalJson(), right.canonicalJson()); assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  err(() => left.append({ ...event(), future_secret: 'no' }), 'STRUCTURED_LOG_FIELD_UNKNOWN', '$.future_secret');
  const hostile = {}; Object.defineProperty(hostile, 'secret', { enumerable: true, get() { throw new Error('must not execute'); } });
  err(() => canonicalJson(hostile), 'STRUCTURED_LOG_INPUT_INVALID', '$.secret');
});

test('B05: serialized events never expose raw sensitive identifiers or hostile values', () => {
  const log = createStructuredLog(); const secret = '203.0.113.99 nonce-0123456789 payload-password token GUID-123'; const output = JSON.stringify(log.append(event({ gateway_id: 'gateway-secret' })));
  for (const value of ['gateway-secret', secret, '192.0.2.10', 'b'.repeat(24)]) assert.equal(output.includes(value), false);
  assert.match(output, /sha256:t8\.gateway-id\/v1:/);
  const getter = event(); Object.defineProperty(getter, 'event', { enumerable: true, get() { throw new Error('no'); } });
  err(() => log.append(getter), 'STRUCTURED_LOG_INPUT_INVALID', '$.event');
  const missingTransport = event(); delete missingTransport.transport;
  err(() => log.append(missingTransport), 'STRUCTURED_LOG_FIELD_REQUIRED', '$.transport');
  err(() => log.append(event({ schema: 'wrong' })), 'STRUCTURED_LOG_SCHEMA_INVALID', '$.schema');
});

test('B05: public mapping projection is sorted and removes addresses, nonce and owner material', () => {
  const result = projectPublicMappings([mapping({ mapping_id: 'z-map' }), mapping({ mapping_id: 'a-map', external_port: 3, internal_address: '10.0.0.3' })]);
  assert.deepEqual(result.map((m) => m.mapping_id), ['a-map', 'z-map']); const text = JSON.stringify(result);
  for (const secret of ['192.0.2.10', '2001:db8::7', '10.0.0.3', 'b'.repeat(24), 'client-1', 'scope_id', 'description']) assert.equal(text.includes(secret), false);
  assert.match(text, /sha256:t8\.address\/v1:/); assert.match(text, /sha256:t8\.owner-instance\/v1:/);
  err(() => projectPublicMappings([mapping({ payload: 'bad' })]), 'STRUCTURED_LOG_FIELD_UNKNOWN', '$.mappings[0].payload');
});

test('B05: canonical report is whitelist-only, deterministic and carries normalized mapping projection', () => {
  const input = { scenario_id: 'scenario-1', run_id: 'run-1', scenario_hash: 'e'.repeat(64), seed: 7, effective_config: { clock_mode: 'virtual', password: 'no', gateway_id: 'raw' }, initial_state: { epoch: 1, generation: 2, nonce: 'no' }, final_state: { status: 'done', owner_id: 'no' }, counters: { count: 2, token: 'no' }, faults: { applied: 1, payload: 'no' }, mappings: [mapping()], verdict: 'passed' };
  const report = createCanonicalReport(input); const text = canonicalJson(report);
  for (const secret of ['password', 'gateway_id', 'raw', 'owner_id', 'token', 'payload', '192.0.2.10', 'b'.repeat(24)]) assert.equal(text.includes(secret), false);
  assert.equal(report.effective_config.clock_mode, 'virtual'); assert.equal(report.initial_state.epoch, 1); assert.equal(report.mappings.length, 1);
  err(() => createCanonicalReport({ ...input, future: true }), 'STRUCTURED_LOG_FIELD_UNKNOWN', '$.future');
});

test('B05: malformed objects, invalid fields and no-sensitive errors remain stable', () => {
  err(() => createStructuredLog().append(null), 'STRUCTURED_LOG_INPUT_INVALID', '$');
  err(() => createStructuredLog().append(event({ generation: 0 })), 'STRUCTURED_LOG_FIELD_INVALID', '$.generation');
  err(() => projectPublicMappings({}), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings');
  const cyclic = event(); cyclic.self = cyclic; err(() => createStructuredLog().append(cyclic), 'STRUCTURED_LOG_INPUT_INVALID', '$.self');
  try { createStructuredLog().append(event({ gateway_id: 'secret-gateway', bogus: 'secret-password' })); } catch (e) { assert.equal(String(e.message).includes('secret'), false); }
});

test('B05: privacy branches cover optional fields, address classes and mapping owner variants', () => {
  const log = createStructuredLog(); const minimal = event();
  for (const key of ['protocol', 'transport', 'mapping_id', 'fault_id', 'outcome', 'reason_code', 'gateway_id']) delete minimal[key];
  const plain = log.append(minimal);
  assert.equal(own(plain, 'gateway_id_digest'), false); assert.equal(plain.sequence, 1);
  err(() => createStructuredLog().append(event({ protocol: 'bad' })), 'STRUCTURED_LOG_FIELD_INVALID', '$.protocol');
  err(() => createStructuredLog().append(event({ transport: 'bad' })), 'STRUCTURED_LOG_FIELD_INVALID', '$.transport');
  const maps = projectPublicMappings([
    mapping({ mapping_id: 'v4-map', internal_address: '10.1.2.3', external_address: '198.51.100.2', owner: { kind: 'none' }, lease: { lifetime_seconds: 0, created_monotonic_ms: 1, expires_monotonic_ms: null } }),
    mapping({ mapping_id: 'upnp-map', external_port: 4, owner: { kind: 'upnp-journal', instance_id_digest: 'c'.repeat(64), gateway_identity_digest: 'd'.repeat(64), description: 'secret' }, atomic_group_id: 'group-1', atomic_group_status: 'complete' })
  ]);
  assert.equal(maps.find((item) => item.mapping_id === 'v4-map').internal_address.classification, 'private-or-loopback'); assert.equal(maps.find((item) => item.mapping_id === 'upnp-map').owner.kind, 'upnp-journal'); assert.equal(maps.find((item) => item.mapping_id === 'v4-map').external_address.classification, 'ipv4');
  err(() => projectPublicMappings([mapping({ owner: { kind: 'bad' } })]), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings[0].owner.kind');
  err(() => projectPublicMappings([mapping({ atomic_group_status: 'bad' })]), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings[0].atomic_group_status');
  err(() => createCanonicalReport({}), 'STRUCTURED_LOG_FIELD_REQUIRED', '$.scenario_id');
  err(() => projectPublicMappings([mapping({ requested_external_port: 70000 })]), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings[0].requested_external_port');
  err(() => projectPublicMappings([mapping({ internal_address: 'not-an-address' })]), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings[0].internal_address');
  err(() => projectPublicMappings([mapping({ lease: { lifetime_seconds: 1, created_monotonic_ms: 0, expires_monotonic_ms: 'bad' } })]), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings[0].lease.expires_monotonic_ms');
  err(() => projectPublicMappings([mapping({ lease: { lifetime_seconds: 1, created_monotonic_ms: 0, expires_monotonic_ms: 1 } })]), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings[0].lease.expires_monotonic_ms');
  err(() => projectPublicMappings([mapping(), mapping()]), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings[1].mapping_id');
  err(() => projectPublicMappings([mapping({ epoch: 0x100000000 })]), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings[0].epoch');
  err(() => projectPublicMappings([mapping({ lease: { lifetime_seconds: 0x100000000, created_monotonic_ms: 0, expires_monotonic_ms: null } })]), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings[0].lease.lifetime_seconds');
  const doc = projectPublicMappings([mapping({ external_address: '192.0.2.9' })])[0]; assert.equal(doc.external_address.classification, 'documentation');
  const reportInput = { scenario_id: 's-1', run_id: 'r-1', scenario_hash: 'e'.repeat(64), seed: 1, effective_config: {}, initial_state: {}, final_state: {}, counters: {}, faults: {}, mappings: [], verdict: 'ok' };
  err(() => createCanonicalReport({ ...reportInput, counters: [] }), 'STRUCTURED_LOG_FIELD_INVALID', '$.counters');
  err(() => createCanonicalReport({ ...reportInput, seed: 0x100000000 }), 'STRUCTURED_LOG_FIELD_INVALID', '$.seed');
  err(() => createCanonicalReport({ ...reportInput, scenario_hash: 'not-a-digest' }), 'STRUCTURED_LOG_FIELD_INVALID', '$.scenario_hash');
  err(() => createCanonicalReport({ ...reportInput, effective_config: { clock_mode: { password: 'secret' } } }), 'STRUCTURED_LOG_FIELD_INVALID', '$.effective_config.clock_mode');
  err(() => createCanonicalReport({ ...reportInput, effective_config: { enabled_protocols: ['pcp', 'pcp'] } }), 'STRUCTURED_LOG_FIELD_INVALID', '$.effective_config.enabled_protocols');
  const equivalent = projectPublicMappings([mapping({ external_address: '2001:0db8:0:0:0:0:0:7' })])[0]; assert.equal(equivalent.external_address.digest, projectPublicMappings([mapping({ external_address: '2001:db8::7' })])[0].external_address.digest);
  const fullReport = createCanonicalReport({ ...reportInput, effective_config: { clock_mode: 'real', allocation_strategy: 'range', enabled_protocols: ['upnp', 'pcp'] }, initial_state: { epoch: 0, generation: 1, status: 'start' }, final_state: { epoch: 1, generation: 2, status: 'done' }, counters: { count: 1, request_count: 2, mapping_count: 3 }, faults: { count: 1, applied: 2, rejected: 3, applied_ids: ['fault-z', 'fault-a'] } });
  assert.deepEqual(fullReport.effective_config.enabled_protocols, ['pcp', 'upnp']); assert.equal(fullReport.counters.mapping_count, 3); assert.deepEqual(fullReport.faults.applied_ids, ['fault-a', 'fault-z']); assert.equal(fullReport.faults.rejected, 3);
  err(() => createCanonicalReport({ ...reportInput, faults: { applied_ids: ['fault-a', 'fault-a'] } }), 'STRUCTURED_LOG_FIELD_INVALID', '$.faults.applied_ids');
  err(() => createCanonicalReport({ ...reportInput, faults: { applied_ids: [`f${'a'.repeat(64)}`] } }), 'STRUCTURED_LOG_FIELD_INVALID', '$.faults.applied_ids');
  err(() => createStructuredLog().append(event({ epoch: 0x100000000 })), 'STRUCTURED_LOG_FIELD_INVALID', '$.epoch');
  const ownerless = mapping(); delete ownerless.owner; assert.equal(own(projectPublicMappings([ownerless])[0], 'owner'), false);
});

function own(value, key) { return Object.prototype.hasOwnProperty.call(value, key); }
