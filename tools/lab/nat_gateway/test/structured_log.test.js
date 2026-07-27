'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { EVENT_SCHEMA, StructuredLogError, canonicalJson, createStructuredLog, projectPublicMappings, createCanonicalReport } = require('../structured_log');

function event(overrides = {}) { return { schema: EVENT_SCHEMA, scenario_id: 'scenario-1', run_id: 'run-1', event: 'map_created', monotonic_ms: 10, epoch: 2, generation: 3, protocol: 'pcp', transport: 'udp', mapping_id: 'map-1', outcome: 'applied', reason_code: 'none', gateway_id: 'gateway-1', ...overrides }; }
function mapping(overrides = {}) { return { mapping_id: 'map-1', protocol: 'pcp', transport: 'udp', client_id: 'client-1', internal_address: '192.0.2.10', internal_port: 1, requested_external_port: 0, external_address: '2001:db8::7', external_port: 2, lease: { lifetime_seconds: 1, created_monotonic_ms: 0, expires_monotonic_ms: 1000 }, owner: { kind: 'pcp-nonce', instance_id_digest: 'a'.repeat(64), nonce: 'b'.repeat(24) }, epoch: 2, generation: 3, ...overrides }; }
function err(fn, code, path) { assert.throws(fn, (e) => e instanceof StructuredLogError && e.reason_code === code && e.field_path === path); }

test('B05: events are versioned, sequenced and monotonic from explicit input', () => {
  const log = createStructuredLog(); const first = log.append(event()); const second = log.append(event({ monotonic_ms: 10, event: 'map_renewed' }));
  assert.equal(first.sequence, 1); assert.equal(second.sequence, 2); assert.equal(log.snapshot().length, 2);
  assert.match(first.scenario_id_digest, /^sha256:t8\.scenario-id\/v1:/); assert.match(first.run_id_digest, /^sha256:t8\.run-id\/v1:/);
  err(() => log.append(event({ monotonic_ms: 9 })), 'STRUCTURED_LOG_TIME_REGRESSION', '$.monotonic_ms');
  err(() => log.append(event({ scenario_id: 'other-scenario' })), 'STRUCTURED_LOG_IDENTITY_MISMATCH', '$.scenario_id');
  err(() => log.append(event({ run_id: 'other-run' })), 'STRUCTURED_LOG_IDENTITY_MISMATCH', '$.run_id');
});

test('B05: public semantic vocabularies are closed and use documented v1 labels', () => {
  const documentedEvents = ['map_created', 'map_requested', 'map_renewed', 'map_deleted', 'map_expired', 'map_rejected', 'external_address_reported', 'request_received', 'response_sent', 'response_dropped', 'fault_applied', 'gateway_restarted', 'time_advanced', 'run_started', 'run_completed', 'run_failed', 'command_rejected', 'invariant_failed'];
  for (const label of documentedEvents) assert.equal(createStructuredLog().append(event({ event: label })).event, label);
  err(() => createStructuredLog().append(event({ event: 'map-created' })), 'STRUCTURED_LOG_FIELD_INVALID', '$.event');
  const base = { scenario_id: 's-1', run_id: 'r-1', scenario_hash: 'e'.repeat(64), seed: 1, effective_config: {}, initial_state: { status: 'mapped' }, final_state: { status: 'stopped' }, counters: {}, faults: {}, mappings: [], verdict: 'passed' };
  for (const strategy of ['requested-or-next', 'range', 'forced']) assert.equal(createCanonicalReport({ ...base, effective_config: { allocation_strategy: strategy } }).effective_config.allocation_strategy, strategy);
  err(() => createCanonicalReport({ ...base, effective_config: { allocation_strategy: 'sequential' } }), 'STRUCTURED_LOG_FIELD_INVALID', '$.effective_config.allocation_strategy');
});

test('B05: canonical events do not depend on property insertion order and unknown fields fail closed', () => {
  const left = createStructuredLog(); const right = createStructuredLog(); const value = event(); const reordered = Object.fromEntries(Object.keys(value).reverse().map((k) => [k, value[k]]));
  left.append(value); right.append(reordered); assert.equal(left.canonicalJson(), right.canonicalJson()); assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  err(() => left.append({ ...event(), future_secret: 'no' }), 'STRUCTURED_LOG_FIELD_UNKNOWN', '$.*');
  const hostile = {}; Object.defineProperty(hostile, 'secret', { enumerable: true, get() { throw new Error('must not execute'); } });
  err(() => canonicalJson(hostile), 'STRUCTURED_LOG_INPUT_INVALID', '$.*');
});

test('B05: serialized events never expose raw sensitive identifiers or hostile values', () => {
  const log = createStructuredLog(); const secret = '203.0.113.99 nonce-0123456789 payload-password token GUID-123'; const output = JSON.stringify(log.append(event({ gateway_id: 'gateway-secret' })));
  for (const value of ['gateway-secret', 'scenario-1', 'run-1', 'map-1', secret, '192.0.2.10', 'b'.repeat(24)]) assert.equal(output.includes(value), false);
  assert.match(output, /sha256:t8\.gateway-id\/v1:/);
  const getter = event(); Object.defineProperty(getter, 'event', { enumerable: true, get() { throw new Error('no'); } });
  err(() => log.append(getter), 'STRUCTURED_LOG_INPUT_INVALID', '$.event');
  const missingTransport = event(); delete missingTransport.transport;
  err(() => log.append(missingTransport), 'STRUCTURED_LOG_FIELD_REQUIRED', '$.transport');
  err(() => log.append(event({ schema: 'wrong' })), 'STRUCTURED_LOG_SCHEMA_INVALID', '$.schema');
});

test('B05: public mapping projection is sorted and removes addresses, nonce and owner material', () => {
  const result = projectPublicMappings([mapping({ mapping_id: 'z-map' }), mapping({ mapping_id: 'a-map', external_port: 3, internal_address: '10.0.0.3' })]);
  assert.deepEqual(result.map((m) => m.mapping_id_digest), [...result.map((m) => m.mapping_id_digest)].sort()); const text = JSON.stringify(result);
  for (const secret of ['a-map', 'z-map', '192.0.2.10', '2001:db8::7', '10.0.0.3', 'b'.repeat(24), 'client-1', 'scope_id', 'description']) assert.equal(text.includes(secret), false);
  assert.match(text, /sha256:t8\.address\/v1:/); assert.match(text, /sha256:t8\.owner-instance\/v1:/);
  err(() => projectPublicMappings([mapping({ payload: 'bad' })]), 'STRUCTURED_LOG_FIELD_UNKNOWN', '$.mappings[0].*');
});

test('B05: canonical report is whitelist-only, deterministic and carries normalized mapping projection', () => {
  const input = { scenario_id: 'scenario-1', run_id: 'run-1', scenario_hash: 'e'.repeat(64), seed: 7, effective_config: { clock_mode: 'virtual', password: 'no', gateway_id: 'raw' }, initial_state: { epoch: 1, generation: 2, nonce: 'no' }, final_state: { status: 'done', owner_id: 'no' }, counters: { count: 2, token: 'no' }, faults: { applied: 1, payload: 'no' }, mappings: [mapping()], verdict: 'passed' };
  const report = createCanonicalReport(input); const text = canonicalJson(report);
  for (const secret of ['password', 'gateway_id', 'raw', 'owner_id', 'token', 'payload', '192.0.2.10', 'b'.repeat(24)]) assert.equal(text.includes(secret), false);
  assert.equal(report.effective_config.clock_mode, 'virtual'); assert.equal(report.initial_state.epoch, 1); assert.equal(report.mappings.length, 1);
  assert.equal(own(report, 'scenario_id'), false); assert.equal(own(report, 'run_id'), false); assert.match(report.scenario_id_digest, /^sha256:t8\.scenario-id\/v1:/);
  err(() => createCanonicalReport({ ...input, future: true }), 'STRUCTURED_LOG_FIELD_UNKNOWN', '$.*');
});

test('B05: malformed objects, invalid fields and no-sensitive errors remain stable', () => {
  err(() => createStructuredLog().append(null), 'STRUCTURED_LOG_INPUT_INVALID', '$');
  err(() => createStructuredLog().append(event({ generation: 0 })), 'STRUCTURED_LOG_FIELD_INVALID', '$.generation');
  err(() => projectPublicMappings({}), 'STRUCTURED_LOG_FIELD_INVALID', '$.mappings');
  const cyclic = event(); cyclic.self = cyclic; err(() => createStructuredLog().append(cyclic), 'STRUCTURED_LOG_INPUT_INVALID', '$.*');
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
  assert.equal(maps.find((item) => item.internal_address.classification === 'private-or-loopback').internal_address.classification, 'private-or-loopback'); assert.equal(maps.find((item) => item.owner.kind === 'upnp-journal').owner.kind, 'upnp-journal'); assert.equal(maps.find((item) => item.internal_address.classification === 'private-or-loopback').external_address.classification, 'ipv4');
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
  assert.deepEqual(fullReport.effective_config.enabled_protocols, ['pcp', 'upnp']); assert.equal(fullReport.counters.mapping_count, 3); assert.equal(fullReport.faults.applied_id_digests.length, 2); assert.equal(fullReport.faults.rejected, 3);
  err(() => createCanonicalReport({ ...reportInput, faults: { applied_ids: ['fault-a', 'fault-a'] } }), 'STRUCTURED_LOG_FIELD_INVALID', '$.faults.applied_ids');
  err(() => createCanonicalReport({ ...reportInput, faults: { applied_ids: [`f${'a'.repeat(64)}`] } }), 'STRUCTURED_LOG_FIELD_INVALID', '$.faults.applied_ids');
  err(() => createStructuredLog().append(event({ epoch: 0x100000000 })), 'STRUCTURED_LOG_FIELD_INVALID', '$.epoch');
  const ownerless = mapping(); delete ownerless.owner; assert.equal(own(projectPublicMappings([ownerless])[0], 'owner'), false);
});

test('B05: proxies and sparse arrays fail before traps or serialization can disclose a secret', () => {
  const secret = 'token-secret-payload-credential-123456'; let rootTraps = 0; let nestedTraps = 0;
  const root = new Proxy(event(), { ownKeys() { rootTraps += 1; throw new Error(secret); }, getOwnPropertyDescriptor() { rootTraps += 1; throw new Error(secret); } });
  const nested = new Proxy({ value: secret }, { ownKeys() { nestedTraps += 1; throw new Error(secret); }, get() { nestedTraps += 1; throw new Error(secret); } });
  for (const [fn, path] of [[() => createStructuredLog().append(root), '$'], [() => createStructuredLog().append(event({ mapping_id: nested })), '$.mapping_id'], [() => projectPublicMappings([mapping({ lease: nested })]), '$.mappings[0].lease'], [() => canonicalJson(root), '$']]) {
    try { fn(); assert.fail('expected StructuredLogError'); } catch (error) { assert.equal(error instanceof StructuredLogError, true); assert.equal(error.field_path, path); assert.equal(String(error.message).includes(secret), false); }
  }
  assert.equal(rootTraps, 0); assert.equal(nestedTraps, 0);
  for (const sparse of [new Array(3), [, 'present'], Object.assign(new Array(2), { 0: 'present' })]) err(() => canonicalJson(sparse), 'STRUCTURED_LOG_INPUT_INVALID', '$');
});

test('B05: variable identifiers and reviewer probes cannot enter JSONL or reports', () => {
  const token = 'token-secret-payload-credential-123456'; const guid = '123e4567-e89b-12d3-a456-426614174000'; const nonce = 'nonce-secret-123456789';
  for (const override of [{ event: token }, { outcome: guid }, { reason_code: nonce }]) err(() => createStructuredLog().append(event(override)), 'STRUCTURED_LOG_FIELD_INVALID', override.event ? '$.event' : override.outcome ? '$.outcome' : '$.reason_code');
  const eventText = JSON.stringify(createStructuredLog().append(event({ scenario_id: 'scenario-secret-1', run_id: 'run-secret-1', mapping_id: 'mapping-secret-1', fault_id: 'fault-secret-1' })));
  const report = createCanonicalReport({ scenario_id: 'scenario-secret-1', run_id: 'run-secret-1', scenario_hash: 'e'.repeat(64), seed: 1, effective_config: {}, initial_state: {}, final_state: {}, counters: {}, faults: { applied_ids: ['fault-secret-1'] }, mappings: [mapping({ mapping_id: 'mapping-secret-1', atomic_group_id: 'group-secret-1' })], verdict: 'passed' });
  const reportText = canonicalJson(report);
  for (const raw of [token, guid, nonce, 'scenario-secret-1', 'run-secret-1', 'mapping-secret-1', 'fault-secret-1', 'group-secret-1']) { assert.equal(eventText.includes(raw), false); assert.equal(reportText.includes(raw), false); }
  assert.match(report.mappings[0].mapping_id_digest, /^sha256:t8\.mapping-id\/v1:/); assert.match(report.mappings[0].atomic_group_id_digest, /^sha256:t8\.atomic-group-id\/v1:/); assert.match(report.faults.applied_id_digests[0], /^sha256:t8\.fault-id\/v1:/);
});

function own(value, key) { return Object.prototype.hasOwnProperty.call(value, key); }
