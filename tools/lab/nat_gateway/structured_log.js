'use strict';

// Pure, closed projection boundary for the T8 JSONL collector.  This module
// deliberately accepts only data values supplied by its caller; it has no I/O
// and never reads time, randomness, or process state.
const { createHash } = require('node:crypto');
const { types } = require('node:util');
const { normalizeAddress } = require('./address');

const EVENT_SCHEMA = 'ese.v92.t8.event/v1';
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const IDS = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const PROTOCOLS = new Set(['upnp', 'pcp', 'natpmp']);
const TRANSPORTS = new Set(['tcp', 'udp']);
// These v1 vocabularies are intentionally closed.  Additions require a schema
// version review; callers must never use a free-form string as a public label.
const EVENT_NAMES_V1 = new Set(['map_created', 'map_requested', 'map_renewed', 'map_deleted', 'map_expired', 'map_rejected', 'external_address_reported', 'request_received', 'response_sent', 'response_dropped', 'fault_applied', 'gateway_restarted', 'time_advanced', 'run_started', 'run_completed', 'run_failed', 'command_rejected', 'invariant_failed']);
const OUTCOMES_V1 = new Set(['applied', 'rejected', 'succeeded', 'failed', 'none']);
const REASON_CODES_V1 = new Set(['none', 'invalid-request', 'conflict', 'not-found', 'stale-epoch', 'stale-generation', 'ownership-unproven', 'ownership-mismatch', 'lease-expired', 'fault-injected', 'unsupported-protocol']);
const VERDICTS_V1 = new Set(['ok', 'passed', 'failed', 'inconclusive']);
const STATE_STATUSES_V1 = new Set(['disabled', 'discovering', 'mapping', 'candidate', 'verifying', 'direct', 'mapped', 'degraded', 'no-route', 'stopped', 'start', 'running', 'done', 'failed']);
const ALLOCATION_STRATEGIES_V1 = new Set(['requested-or-next', 'range', 'forced']);
const SAFE_PATH_KEYS = new Set([
  'schema', 'scenario_id', 'run_id', 'event', 'monotonic_ms', 'epoch', 'generation',
  'protocol', 'transport', 'mapping_id', 'fault_id', 'outcome', 'reason_code',
  'gateway_id', 'client_id', 'internal_address', 'internal_port',
  'requested_external_port', 'external_address', 'external_port', 'lease', 'owner',
  'atomic_group_id', 'atomic_group_status', 'lifetime_seconds',
  'created_monotonic_ms', 'expires_monotonic_ms', 'kind', 'instance_id_digest',
  'gateway_identity_digest', 'description', 'nonce', 'scope_id', 'scenario_hash',
  'seed', 'effective_config', 'initial_state', 'final_state', 'counters', 'faults',
  'mappings', 'verdict', 'clock_mode', 'allocation_strategy', 'enabled_protocols',
  'status', 'count', 'request_count', 'mapping_count', 'applied', 'rejected',
  'applied_ids'
]);

class StructuredLogError extends Error {
  constructor(reasonCode, fieldPath) {
    super(`${reasonCode} at ${fieldPath}`);
    this.name = 'StructuredLogError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}
function fail(code, path) { throw new StructuredLogError(code, path); }
function own(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
function childPath(path, key, array) { return array ? `${path}[${key}]` : SAFE_PATH_KEYS.has(key) ? `${path}.${key}` : `${path}.*`; }
function exact(value, required, optional, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('STRUCTURED_LOG_INPUT_INVALID', path);
  for (const k of required) if (!own(value, k)) fail('STRUCTURED_LOG_FIELD_REQUIRED', `${path}.${k}`);
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(value)) if (!allowed.has(k)) fail('STRUCTURED_LOG_FIELD_UNKNOWN', childPath(path, k, false));
}
function data(value, path, seen = new WeakSet()) {
  if (value === null || ['string', 'boolean'].includes(typeof value)) return value;
  if (typeof value === 'number') { if (!Number.isFinite(value)) fail('STRUCTURED_LOG_INPUT_INVALID', path); return value; }
  if (!value || typeof value !== 'object' || seen.has(value)) fail('STRUCTURED_LOG_INPUT_INVALID', path);
  // isProxy must run before every operation that could enter a user trap.
  if (types.isProxy(value)) fail('STRUCTURED_LOG_INPUT_INVALID', path);
  const array = Array.isArray(value);
  if ((!array && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) || Object.getOwnPropertySymbols(value).length) fail('STRUCTURED_LOG_INPUT_INVALID', path);
  const propertyNames = Object.getOwnPropertyNames(value);
  const originalLength = array ? value.length : 0;
  // Check density against the source length before inspecting element values.
  if (array && propertyNames.length - 1 !== originalLength) fail('STRUCTURED_LOG_INPUT_INVALID', path);
  seen.add(value);
  const result = array ? [] : Object.create(null);
  for (const key of propertyNames) {
    if (array && key === 'length') continue;
    const d = Object.getOwnPropertyDescriptor(value, key);
    const nextPath = childPath(path, key, array);
    if (!d || !d.enumerable || !own(d, 'value') || key === 'toJSON') fail('STRUCTURED_LOG_INPUT_INVALID', nextPath);
    if (array && !/^(0|[1-9]\d*)$/.test(key)) fail('STRUCTURED_LOG_INPUT_INVALID', path);
    const child = data(d.value, nextPath, seen);
    if (Array.isArray(result)) result[key] = child;
    else Object.defineProperty(result, key, { value: child, enumerable: true, writable: true, configurable: true });
  }
  seen.delete(value); return result;
}
function frozen(value) { if (value && typeof value === 'object') { for (const v of Object.values(value)) frozen(v); Object.freeze(value); } return value; }
function id(value, path) { if (typeof value !== 'string' || value.length > 64 || !IDS.test(value)) fail('STRUCTURED_LOG_FIELD_INVALID', path); return value; }
function vocabulary(value, allowed, path) { if (typeof value !== 'string' || !allowed.has(value)) fail('STRUCTURED_LOG_FIELD_INVALID', path); return value; }
function uint(value, path, zero = true) { if (!Number.isSafeInteger(value) || value < (zero ? 0 : 1) || value > MAX_SAFE) fail('STRUCTURED_LOG_FIELD_INVALID', path); return value; }
function uint32(value, path) { uint(value, path); if (value > 0xffffffff) fail('STRUCTURED_LOG_FIELD_INVALID', path); return value; }
function port(value, path, zero = true) { if (!Number.isInteger(value) || value < (zero ? 0 : 1) || value > 65535) fail('STRUCTURED_LOG_FIELD_INVALID', path); return value; }
function digest(domain, value) { return `sha256:${domain}:${createHash('sha256').update(`${domain}\0${value}`, 'utf8').digest('hex')}`; }
function address(value, path) {
  const normalized = typeof value === 'string' ? normalizeAddress(value) : null;
  if (!normalized) fail('STRUCTURED_LOG_FIELD_INVALID', path);
  const v4 = normalized.includes('.');
  const classification = v4 && /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(normalized) ? 'private-or-loopback' : v4 && /^192\.0\.2\./.test(normalized) ? 'documentation' : v4 ? 'ipv4' : 'ipv6';
  return frozen({ classification, digest: digest('t8.address/v1', normalized) });
}
function canonicalJsonData(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJsonData).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalJsonData(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
function canonicalJson(value) { return canonicalJsonData(data(value, '$')); }
function eventCopy(input, last) {
  const e = data(input, '$');
  exact(e, ['schema', 'scenario_id', 'run_id', 'event', 'monotonic_ms', 'epoch', 'generation'], ['protocol', 'transport', 'mapping_id', 'fault_id', 'outcome', 'reason_code', 'gateway_id'], '$');
  if (e.schema !== EVENT_SCHEMA) fail('STRUCTURED_LOG_SCHEMA_INVALID', '$.schema');
  id(e.scenario_id, '$.scenario_id'); id(e.run_id, '$.run_id'); vocabulary(e.event, EVENT_NAMES_V1, '$.event'); uint(e.monotonic_ms, '$.monotonic_ms'); uint32(e.epoch, '$.epoch'); uint(e.generation, '$.generation', false);
  if ((e.protocol === undefined) !== (e.transport === undefined)) fail('STRUCTURED_LOG_FIELD_REQUIRED', e.protocol === undefined ? '$.protocol' : '$.transport');
  if (e.protocol !== undefined && (!PROTOCOLS.has(e.protocol) || !TRANSPORTS.has(e.transport))) fail('STRUCTURED_LOG_FIELD_INVALID', e.protocol !== undefined && !PROTOCOLS.has(e.protocol) ? '$.protocol' : '$.transport');
  for (const k of ['mapping_id', 'fault_id']) if (e[k] !== undefined) id(e[k], `$.${k}`);
  if (e.outcome !== undefined) vocabulary(e.outcome, OUTCOMES_V1, '$.outcome');
  if (e.reason_code !== undefined) vocabulary(e.reason_code, REASON_CODES_V1, '$.reason_code');
  if (e.gateway_id !== undefined) id(e.gateway_id, '$.gateway_id');
  if (last && e.monotonic_ms < last.monotonic_ms) fail('STRUCTURED_LOG_TIME_REGRESSION', '$.monotonic_ms');
  const result = { schema: EVENT_SCHEMA, sequence: last ? last.sequence + 1 : 1, scenario_id_digest: digest('t8.scenario-id/v1', e.scenario_id), run_id_digest: digest('t8.run-id/v1', e.run_id), event: e.event, monotonic_ms: e.monotonic_ms, epoch: e.epoch, generation: e.generation };
  for (const k of ['protocol', 'transport', 'outcome', 'reason_code']) if (e[k] !== undefined) result[k] = e[k];
  if (e.mapping_id !== undefined) result.mapping_id_digest = digest('t8.mapping-id/v1', e.mapping_id);
  if (e.fault_id !== undefined) result.fault_id_digest = digest('t8.fault-id/v1', e.fault_id);
  if (e.gateway_id !== undefined) result.gateway_id_digest = digest('t8.gateway-id/v1', e.gateway_id);
  return frozen(result);
}

function createStructuredLog() {
  let last; let identity; const events = [];
  return Object.freeze({
    append(input) {
      const source = data(input, '$');
      const event = eventCopy(source, last);
      if (identity && source.scenario_id !== identity.scenario_id) fail('STRUCTURED_LOG_IDENTITY_MISMATCH', '$.scenario_id');
      if (identity && source.run_id !== identity.run_id) fail('STRUCTURED_LOG_IDENTITY_MISMATCH', '$.run_id');
      identity = { scenario_id: source.scenario_id, run_id: source.run_id };
      last = event; events.push(event); return event;
    },
    snapshot() { return frozen(events.slice()); },
    canonicalJson() { return events.map(canonicalJsonData).join('\n'); }
  });
}

function projectOwner(owner, protocol, path) {
  exact(owner, ['kind'], ['instance_id_digest', 'gateway_identity_digest', 'description', 'nonce', 'scope_id'], path);
  const expectedProtocol = {
    'upnp-journal': 'upnp',
    'pcp-nonce': 'pcp',
    'natpmp-lease-scope': 'natpmp'
  }[owner.kind];
  if (owner.kind === 'none') {
    exact(owner, ['kind'], [], path);
    return frozen({ kind: 'none' });
  }
  if (!expectedProtocol) fail('STRUCTURED_LOG_FIELD_INVALID', `${path}.kind`);
  if (expectedProtocol !== protocol) fail('STRUCTURED_LOG_OWNER_PROTOCOL_MISMATCH', `${path}.kind`);
  if (typeof owner.instance_id_digest !== 'string' || !/^[a-f0-9]{64}$/.test(owner.instance_id_digest)) {
    fail('STRUCTURED_LOG_FIELD_INVALID', `${path}.instance_id_digest`);
  }
  const projected = {
    kind: owner.kind,
    instance_id_digest: digest('t8.owner-instance/v1', owner.instance_id_digest)
  };
  if (owner.kind === 'upnp-journal') {
    exact(owner, ['kind', 'instance_id_digest', 'gateway_identity_digest', 'description'], [], path);
    if (typeof owner.gateway_identity_digest !== 'string' || !/^[a-f0-9]{64}$/.test(owner.gateway_identity_digest)) fail('STRUCTURED_LOG_FIELD_INVALID', `${path}.gateway_identity_digest`);
    if (typeof owner.description !== 'string' || owner.description.length === 0 || owner.description.length > 64) fail('STRUCTURED_LOG_FIELD_INVALID', `${path}.description`);
    projected.gateway_identity_digest = digest('t8.owner-gateway/v1', owner.gateway_identity_digest);
  } else if (owner.kind === 'pcp-nonce') {
    exact(owner, ['kind', 'instance_id_digest', 'nonce'], [], path);
    if (typeof owner.nonce !== 'string' || !/^[a-f0-9]{24}$/.test(owner.nonce)) fail('STRUCTURED_LOG_FIELD_INVALID', `${path}.nonce`);
    projected.nonce_digest = digest('t8.pcp-nonce/v1', owner.nonce);
  } else {
    exact(owner, ['kind', 'instance_id_digest', 'scope_id'], [], path);
    id(owner.scope_id, `${path}.scope_id`);
    projected.scope_id_digest = digest('t8.natpmp-scope/v1', owner.scope_id);
  }
  return frozen(projected);
}

function projectPublicMappings(snapshot) {
  const list = data(snapshot, '$.mappings'); if (!Array.isArray(list)) fail('STRUCTURED_LOG_FIELD_INVALID', '$.mappings');
  const sourceIds = [];
  const projected = list.map((m, index) => {
    const p = `$.mappings[${index}]`; exact(m, ['mapping_id', 'protocol', 'transport', 'client_id', 'internal_address', 'internal_port', 'requested_external_port', 'external_address', 'external_port', 'lease', 'epoch', 'generation'], ['owner', 'atomic_group_id', 'atomic_group_status'], p);
    id(m.mapping_id, `${p}.mapping_id`); if (!PROTOCOLS.has(m.protocol) || !TRANSPORTS.has(m.transport)) fail('STRUCTURED_LOG_FIELD_INVALID', !PROTOCOLS.has(m.protocol) ? `${p}.protocol` : `${p}.transport`);
    id(m.client_id, `${p}.client_id`); port(m.internal_port, `${p}.internal_port`, false); port(m.requested_external_port, `${p}.requested_external_port`); port(m.external_port, `${p}.external_port`, false); uint32(m.epoch, `${p}.epoch`); uint(m.generation, `${p}.generation`, false);
    exact(m.lease, ['lifetime_seconds', 'created_monotonic_ms', 'expires_monotonic_ms'], [], `${p}.lease`); uint32(m.lease.lifetime_seconds, `${p}.lease.lifetime_seconds`); uint(m.lease.created_monotonic_ms, `${p}.lease.created_monotonic_ms`);
    if (m.lease.lifetime_seconds === 0) { if (m.lease.expires_monotonic_ms !== null) fail('STRUCTURED_LOG_FIELD_INVALID', `${p}.lease.expires_monotonic_ms`); } else { uint(m.lease.expires_monotonic_ms, `${p}.lease.expires_monotonic_ms`); const expiry = m.lease.created_monotonic_ms + m.lease.lifetime_seconds * 1000; if (!Number.isSafeInteger(expiry) || expiry !== m.lease.expires_monotonic_ms) fail('STRUCTURED_LOG_FIELD_INVALID', `${p}.lease.expires_monotonic_ms`); }
    sourceIds.push(m.mapping_id);
    const out = { mapping_id_digest: digest('t8.mapping-id/v1', m.mapping_id), protocol: m.protocol, transport: m.transport, client_id_digest: digest('t8.client-id/v1', m.client_id), internal_address: address(m.internal_address, `${p}.internal_address`), internal_port: m.internal_port, requested_external_port: m.requested_external_port, external_address: address(m.external_address, `${p}.external_address`), external_port: m.external_port, lease: { lifetime_seconds: m.lease.lifetime_seconds, created_monotonic_ms: m.lease.created_monotonic_ms, expires_monotonic_ms: m.lease.expires_monotonic_ms }, epoch: m.epoch, generation: m.generation };
    if (m.atomic_group_id !== undefined) { id(m.atomic_group_id, `${p}.atomic_group_id`); out.atomic_group_id_digest = digest('t8.atomic-group-id/v1', m.atomic_group_id); }
    if (m.atomic_group_status !== undefined) { if (!['partial', 'complete'].includes(m.atomic_group_status)) fail('STRUCTURED_LOG_FIELD_INVALID', `${p}.atomic_group_status`); out.atomic_group_status = m.atomic_group_status; }
    if (m.owner !== undefined) out.owner = projectOwner(m.owner, m.protocol, `${p}.owner`);
    return frozen(out);
  });
  const ids = new Set();
  for (let index = 0; index < projected.length; index += 1) {
    if (ids.has(sourceIds[index])) fail('STRUCTURED_LOG_FIELD_INVALID', `$.mappings[${index}].mapping_id`);
    ids.add(sourceIds[index]);
  }
  return frozen(projected.sort((a, b) => a.mapping_id_digest < b.mapping_id_digest ? -1 : a.mapping_id_digest > b.mapping_id_digest ? 1 : 0));
}

function createCanonicalReport(input) {
  const r = data(input, '$'); exact(r, ['scenario_id', 'run_id', 'scenario_hash', 'seed', 'effective_config', 'initial_state', 'final_state', 'counters', 'faults', 'mappings', 'verdict'], [], '$');
  id(r.scenario_id, '$.scenario_id'); id(r.run_id, '$.run_id'); if (typeof r.scenario_hash !== 'string' || !/^[a-f0-9]{64}$/.test(r.scenario_hash)) fail('STRUCTURED_LOG_FIELD_INVALID', '$.scenario_hash'); uint32(r.seed, '$.seed'); vocabulary(r.verdict, VERDICTS_V1, '$.verdict');
  for (const k of ['effective_config', 'initial_state', 'final_state', 'counters', 'faults']) { if (!r[k] || typeof r[k] !== 'object' || Array.isArray(r[k])) fail('STRUCTURED_LOG_FIELD_INVALID', `$.${k}`); }
  const put = (out, source, key, check, path) => { if (source[key] !== undefined) { check(source[key], `${path}.${key}`); out[key] = source[key]; } };
  const config = (source, path) => { const out = Object.create(null); put(out, source, 'clock_mode', (v, p) => { if (!['virtual', 'real'].includes(v)) fail('STRUCTURED_LOG_FIELD_INVALID', p); }, path); put(out, source, 'allocation_strategy', (v, p) => vocabulary(v, ALLOCATION_STRATEGIES_V1, p), path); if (source.enabled_protocols !== undefined) { if (!Array.isArray(source.enabled_protocols) || source.enabled_protocols.some((v) => !PROTOCOLS.has(v)) || new Set(source.enabled_protocols).size !== source.enabled_protocols.length) fail('STRUCTURED_LOG_FIELD_INVALID', `${path}.enabled_protocols`); out.enabled_protocols = [...source.enabled_protocols].sort(); } return frozen(out); };
  const state = (source, path) => { const out = Object.create(null); put(out, source, 'epoch', uint32, path); put(out, source, 'generation', (v, p) => uint(v, p, false), path); put(out, source, 'status', (v, p) => vocabulary(v, STATE_STATUSES_V1, p), path); return frozen(out); };
  const counts = (source, path, allowed) => { const out = Object.create(null); for (const key of allowed) put(out, source, key, (v, p) => uint(v, p), path); if (source.applied_ids !== undefined) { if (!Array.isArray(source.applied_ids) || source.applied_ids.some((v) => typeof v !== 'string' || v.length > 64 || !IDS.test(v)) || new Set(source.applied_ids).size !== source.applied_ids.length) fail('STRUCTURED_LOG_FIELD_INVALID', `${path}.applied_ids`); out.applied_id_digests = source.applied_ids.map((v) => digest('t8.fault-id/v1', v)).sort(); } return frozen(out); };
  return frozen({ schema: 'ese.v92.t8.report/v1', scenario_id_digest: digest('t8.scenario-id/v1', r.scenario_id), run_id_digest: digest('t8.run-id/v1', r.run_id), scenario_hash: r.scenario_hash, seed: r.seed, effective_config: config(r.effective_config, '$.effective_config'), initial_state: state(r.initial_state, '$.initial_state'), final_state: state(r.final_state, '$.final_state'), counters: counts(r.counters, '$.counters', ['count', 'request_count', 'mapping_count']), faults: counts(r.faults, '$.faults', ['count', 'applied', 'rejected']), mappings: projectPublicMappings(r.mappings), verdict: r.verdict });
}

module.exports = { EVENT_SCHEMA, StructuredLogError, canonicalJson, createStructuredLog, projectPublicMappings, createCanonicalReport };
