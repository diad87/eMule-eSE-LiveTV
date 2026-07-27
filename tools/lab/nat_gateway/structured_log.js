'use strict';

// Pure, closed projection boundary for the T8 JSONL collector.  This module
// deliberately accepts only data values supplied by its caller; it has no I/O
// and never reads time, randomness, or process state.
const { createHash } = require('node:crypto');
const { normalizeAddress } = require('./address');

const EVENT_SCHEMA = 'ese.v92.t8.event/v1';
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const IDS = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const PROTOCOLS = new Set(['upnp', 'pcp', 'natpmp']);
const TRANSPORTS = new Set(['tcp', 'udp']);

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
function exact(value, required, optional, path) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('STRUCTURED_LOG_INPUT_INVALID', path);
  for (const k of required) if (!own(value, k)) fail('STRUCTURED_LOG_FIELD_REQUIRED', `${path}.${k}`);
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(value)) if (!allowed.has(k)) fail('STRUCTURED_LOG_FIELD_UNKNOWN', `${path}.${k}`);
}
function data(value, path, seen = new WeakSet()) {
  if (value === null || ['string', 'boolean'].includes(typeof value)) return value;
  if (typeof value === 'number') { if (!Number.isFinite(value)) fail('STRUCTURED_LOG_INPUT_INVALID', path); return value; }
  if (!value || typeof value !== 'object' || seen.has(value)) fail('STRUCTURED_LOG_INPUT_INVALID', path);
  if ((!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) || Object.getOwnPropertySymbols(value).length) fail('STRUCTURED_LOG_INPUT_INVALID', path);
  seen.add(value);
  const result = Array.isArray(value) ? [] : Object.create(null);
  for (const key of Object.getOwnPropertyNames(value)) {
    if (Array.isArray(value) && key === 'length') continue;
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !d.enumerable || !own(d, 'value') || key === 'toJSON') fail('STRUCTURED_LOG_INPUT_INVALID', `${path}.${key}`);
    if (Array.isArray(value) && !/^(0|[1-9]\d*)$/.test(key)) fail('STRUCTURED_LOG_INPUT_INVALID', path);
    const child = data(d.value, Array.isArray(value) ? `${path}[${key}]` : `${path}.${key}`, seen);
    if (Array.isArray(result)) result[key] = child;
    else Object.defineProperty(result, key, { value: child, enumerable: true, writable: true, configurable: true });
  }
  if (Array.isArray(value) && result.length !== Object.getOwnPropertyNames(value).filter((k) => k !== 'length').length) fail('STRUCTURED_LOG_INPUT_INVALID', path);
  seen.delete(value); return result;
}
function frozen(value) { if (value && typeof value === 'object') { for (const v of Object.values(value)) frozen(v); Object.freeze(value); } return value; }
function id(value, path) { if (typeof value !== 'string' || value.length > 64 || !IDS.test(value)) fail('STRUCTURED_LOG_FIELD_INVALID', path); return value; }
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
  id(e.scenario_id, '$.scenario_id'); id(e.run_id, '$.run_id'); id(e.event, '$.event'); uint(e.monotonic_ms, '$.monotonic_ms'); uint32(e.epoch, '$.epoch'); uint(e.generation, '$.generation', false);
  if ((e.protocol === undefined) !== (e.transport === undefined)) fail('STRUCTURED_LOG_FIELD_REQUIRED', e.protocol === undefined ? '$.protocol' : '$.transport');
  if (e.protocol !== undefined && (!PROTOCOLS.has(e.protocol) || !TRANSPORTS.has(e.transport))) fail('STRUCTURED_LOG_FIELD_INVALID', e.protocol !== undefined && !PROTOCOLS.has(e.protocol) ? '$.protocol' : '$.transport');
  for (const k of ['mapping_id', 'fault_id', 'outcome', 'reason_code']) if (e[k] !== undefined) id(e[k], `$.${k}`);
  if (e.gateway_id !== undefined) id(e.gateway_id, '$.gateway_id');
  if (last && e.scenario_id !== last.scenario_id) fail('STRUCTURED_LOG_IDENTITY_MISMATCH', '$.scenario_id');
  if (last && e.run_id !== last.run_id) fail('STRUCTURED_LOG_IDENTITY_MISMATCH', '$.run_id');
  if (last && e.monotonic_ms < last.monotonic_ms) fail('STRUCTURED_LOG_TIME_REGRESSION', '$.monotonic_ms');
  const result = { schema: EVENT_SCHEMA, sequence: last ? last.sequence + 1 : 1, scenario_id: e.scenario_id, run_id: e.run_id, event: e.event, monotonic_ms: e.monotonic_ms, epoch: e.epoch, generation: e.generation };
  for (const k of ['protocol', 'transport', 'mapping_id', 'fault_id', 'outcome', 'reason_code']) if (e[k] !== undefined) result[k] = e[k];
  if (e.gateway_id !== undefined) result.gateway_id_digest = digest('t8.gateway-id/v1', e.gateway_id);
  return frozen(result);
}

function createStructuredLog() {
  let last; const events = [];
  return Object.freeze({
    append(input) { const event = eventCopy(input, last); last = event; events.push(event); return event; },
    snapshot() { return frozen(events.slice()); },
    canonicalJson() { return events.map(canonicalJsonData).join('\n'); }
  });
}

function projectPublicMappings(snapshot) {
  const list = data(snapshot, '$.mappings'); if (!Array.isArray(list)) fail('STRUCTURED_LOG_FIELD_INVALID', '$.mappings');
  const projected = list.map((m, index) => {
    const p = `$.mappings[${index}]`; exact(m, ['mapping_id', 'protocol', 'transport', 'client_id', 'internal_address', 'internal_port', 'requested_external_port', 'external_address', 'external_port', 'lease', 'epoch', 'generation'], ['owner', 'atomic_group_id', 'atomic_group_status'], p);
    id(m.mapping_id, `${p}.mapping_id`); if (!PROTOCOLS.has(m.protocol) || !TRANSPORTS.has(m.transport)) fail('STRUCTURED_LOG_FIELD_INVALID', !PROTOCOLS.has(m.protocol) ? `${p}.protocol` : `${p}.transport`);
    id(m.client_id, `${p}.client_id`); port(m.internal_port, `${p}.internal_port`, false); port(m.requested_external_port, `${p}.requested_external_port`); port(m.external_port, `${p}.external_port`, false); uint32(m.epoch, `${p}.epoch`); uint(m.generation, `${p}.generation`, false);
    exact(m.lease, ['lifetime_seconds', 'created_monotonic_ms', 'expires_monotonic_ms'], [], `${p}.lease`); uint32(m.lease.lifetime_seconds, `${p}.lease.lifetime_seconds`); uint(m.lease.created_monotonic_ms, `${p}.lease.created_monotonic_ms`);
    if (m.lease.lifetime_seconds === 0) { if (m.lease.expires_monotonic_ms !== null) fail('STRUCTURED_LOG_FIELD_INVALID', `${p}.lease.expires_monotonic_ms`); } else { uint(m.lease.expires_monotonic_ms, `${p}.lease.expires_monotonic_ms`); const expiry = m.lease.created_monotonic_ms + m.lease.lifetime_seconds * 1000; if (!Number.isSafeInteger(expiry) || expiry !== m.lease.expires_monotonic_ms) fail('STRUCTURED_LOG_FIELD_INVALID', `${p}.lease.expires_monotonic_ms`); }
    const out = { mapping_id: m.mapping_id, protocol: m.protocol, transport: m.transport, client_id_digest: digest('t8.client-id/v1', m.client_id), internal_address: address(m.internal_address, `${p}.internal_address`), internal_port: m.internal_port, requested_external_port: m.requested_external_port, external_address: address(m.external_address, `${p}.external_address`), external_port: m.external_port, lease: { lifetime_seconds: m.lease.lifetime_seconds, created_monotonic_ms: m.lease.created_monotonic_ms, expires_monotonic_ms: m.lease.expires_monotonic_ms }, epoch: m.epoch, generation: m.generation };
    if (m.atomic_group_id !== undefined) { id(m.atomic_group_id, `${p}.atomic_group_id`); out.atomic_group_id = m.atomic_group_id; }
    if (m.atomic_group_status !== undefined) { if (!['partial', 'complete'].includes(m.atomic_group_status)) fail('STRUCTURED_LOG_FIELD_INVALID', `${p}.atomic_group_status`); out.atomic_group_status = m.atomic_group_status; }
    if (m.owner !== undefined) { exact(m.owner, ['kind'], ['instance_id_digest', 'gateway_identity_digest', 'description', 'nonce', 'scope_id'], `${p}.owner`); if (!['none', 'upnp-journal', 'pcp-nonce', 'natpmp-lease-scope'].includes(m.owner.kind)) fail('STRUCTURED_LOG_FIELD_INVALID', `${p}.owner.kind`); out.owner = { kind: m.owner.kind }; if (typeof m.owner.instance_id_digest === 'string') out.owner.instance_id_digest = digest('t8.owner-instance/v1', m.owner.instance_id_digest); }
    return frozen(out);
  });
  const ids = new Set();
  for (let index = 0; index < projected.length; index += 1) {
    const item = projected[index];
    if (ids.has(item.mapping_id)) fail('STRUCTURED_LOG_FIELD_INVALID', `$.mappings[${index}].mapping_id`);
    ids.add(item.mapping_id);
  }
  return frozen(projected.sort((a, b) => a.mapping_id < b.mapping_id ? -1 : a.mapping_id > b.mapping_id ? 1 : 0));
}

function createCanonicalReport(input) {
  const r = data(input, '$'); exact(r, ['scenario_id', 'run_id', 'scenario_hash', 'seed', 'effective_config', 'initial_state', 'final_state', 'counters', 'faults', 'mappings', 'verdict'], [], '$');
  id(r.scenario_id, '$.scenario_id'); id(r.run_id, '$.run_id'); if (typeof r.scenario_hash !== 'string' || !/^[a-f0-9]{64}$/.test(r.scenario_hash)) fail('STRUCTURED_LOG_FIELD_INVALID', '$.scenario_hash'); uint32(r.seed, '$.seed'); id(r.verdict, '$.verdict');
  for (const k of ['effective_config', 'initial_state', 'final_state', 'counters', 'faults']) { if (!r[k] || typeof r[k] !== 'object' || Array.isArray(r[k])) fail('STRUCTURED_LOG_FIELD_INVALID', `$.${k}`); }
  const put = (out, source, key, check, path) => { if (source[key] !== undefined) { check(source[key], `${path}.${key}`); out[key] = source[key]; } };
  const config = (source, path) => { const out = Object.create(null); put(out, source, 'clock_mode', (v, p) => { if (!['virtual', 'real'].includes(v)) fail('STRUCTURED_LOG_FIELD_INVALID', p); }, path); put(out, source, 'allocation_strategy', (v, p) => id(v, p), path); if (source.enabled_protocols !== undefined) { if (!Array.isArray(source.enabled_protocols) || source.enabled_protocols.some((v) => !PROTOCOLS.has(v)) || new Set(source.enabled_protocols).size !== source.enabled_protocols.length) fail('STRUCTURED_LOG_FIELD_INVALID', `${path}.enabled_protocols`); out.enabled_protocols = [...source.enabled_protocols].sort(); } return frozen(out); };
  const state = (source, path) => { const out = Object.create(null); put(out, source, 'epoch', uint32, path); put(out, source, 'generation', (v, p) => uint(v, p, false), path); put(out, source, 'status', id, path); return frozen(out); };
  const counts = (source, path, allowed) => { const out = Object.create(null); for (const key of allowed) put(out, source, key, (v, p) => uint(v, p), path); if (source.applied_ids !== undefined) { if (!Array.isArray(source.applied_ids) || source.applied_ids.some((v) => typeof v !== 'string' || v.length > 64 || !IDS.test(v)) || new Set(source.applied_ids).size !== source.applied_ids.length) fail('STRUCTURED_LOG_FIELD_INVALID', `${path}.applied_ids`); out.applied_ids = [...source.applied_ids].sort(); } return frozen(out); };
  return frozen({ schema: 'ese.v92.t8.report/v1', scenario_id: r.scenario_id, run_id: r.run_id, scenario_hash: r.scenario_hash, seed: r.seed, effective_config: config(r.effective_config, '$.effective_config'), initial_state: state(r.initial_state, '$.initial_state'), final_state: state(r.final_state, '$.final_state'), counters: counts(r.counters, '$.counters', ['count', 'request_count', 'mapping_count']), faults: counts(r.faults, '$.faults', ['count', 'applied', 'rejected']), mappings: projectPublicMappings(r.mappings), verdict: r.verdict });
}

module.exports = { EVENT_SCHEMA, StructuredLogError, canonicalJson, createStructuredLog, projectPublicMappings, createCanonicalReport };
