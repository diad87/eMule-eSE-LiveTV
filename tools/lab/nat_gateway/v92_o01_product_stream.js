'use strict';

const { types } = require('node:util');

const STATES = new Set(['UNAVAILABLE', 'CANDIDATE', 'REACHABLE', 'BLOCKED', 'UNKNOWN', 'OTHER']);
const STARTED_KEYS = Object.freeze([
  'schema', 'sequence', 'elapsed_ms', 'identity_accredited', 'preexisting_processes_unchanged',
]);
const SAMPLE_KEYS = Object.freeze([
  'schema', 'sequence', 'elapsed_ms', 'available', 'tcp_state', 'udp_state',
  'same_generation', 'generation', 'tcp_reason_code', 'udp_reason_code',
  'working_set_bytes', 'handle_count',
]);
const TERMINAL_KEYS = Object.freeze([
  'schema', 'sequence', 'elapsed_ms', 'graceful_exit', 'mappings_absent',
  'ini_restored_byte_exact', 'preexisting_processes_unchanged',
]);

class ProductStreamError extends Error {
  constructor(code) { super(code); this.name = 'ProductStreamError'; this.reason_code = code; }
}
function fail(code) { throw new ProductStreamError(code); }
function plain(value) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    !types.isProxy(value) && Object.getPrototypeOf(value) === Object.prototype;
}
function exact(value, keys) {
  if (!plain(value) || Object.getOwnPropertySymbols(value).length !== 0 ||
      Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) fail('O01_PRODUCT_SHAPE');
}
function uint(value, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) fail('O01_PRODUCT_INTEGER');
}
function parseLine(line) {
  if (typeof line !== 'string' || line.length === 0 || Buffer.byteLength(line, 'utf8') > 2048 ||
      line.includes('\r') || line.includes('\n')) fail('O01_PRODUCT_LINE');
  let value;
  try { value = JSON.parse(line); } catch (_) { fail('O01_PRODUCT_JSON'); }
  if (value?.schema === 'ese.v92.o01-product-started/v1') {
    exact(value, STARTED_KEYS);
    if (value.sequence !== 1 || value.elapsed_ms !== 0 || value.identity_accredited !== true ||
        value.preexisting_processes_unchanged !== true) fail('O01_PRODUCT_STARTED');
    return Object.freeze({ ...value });
  }
  if (value?.schema === 'ese.v92.o01-product-sample/v1') {
    exact(value, SAMPLE_KEYS);
    uint(value.sequence, 10000000); uint(value.elapsed_ms, 32400000);
    uint(value.generation); uint(value.tcp_reason_code, 65535); uint(value.udp_reason_code, 65535);
    uint(value.working_set_bytes); uint(value.handle_count, 65535);
    if (typeof value.available !== 'boolean' || typeof value.same_generation !== 'boolean' ||
        !STATES.has(value.tcp_state) || !STATES.has(value.udp_state)) fail('O01_PRODUCT_SAMPLE');
    if (!value.available && (value.same_generation || value.generation !== 0 ||
        value.tcp_state !== 'UNAVAILABLE' || value.udp_state !== 'UNAVAILABLE')) fail('O01_PRODUCT_SAMPLE');
    return Object.freeze({ ...value });
  }
  if (value?.schema === 'ese.v92.o01-product-terminal/v1') {
    exact(value, TERMINAL_KEYS);
    uint(value.sequence, 10000000); uint(value.elapsed_ms, 32400000);
    for (const key of TERMINAL_KEYS.slice(3)) if (typeof value[key] !== 'boolean') fail('O01_PRODUCT_TERMINAL');
    return Object.freeze({ ...value });
  }
  fail('O01_PRODUCT_SCHEMA');
}

function createProductStreamState(options = {}) {
  const durationMs = options.durationMs;
  const maxGapMs = options.maxGapMs;
  if (!Number.isSafeInteger(durationMs) || durationMs !== 28800000 ||
      !Number.isSafeInteger(maxGapMs) || maxGapMs < 10000 || maxGapMs > 70000) fail('O01_PRODUCT_CONFIG');
  let sequence = 0; let elapsed = -1; let terminal = null; let samples = 0; let available = 0; let started = false;
  return Object.freeze({ accept(line) {
    if (terminal) fail('O01_PRODUCT_AFTER_TERMINAL');
    const value = parseLine(line);
    if (value.sequence !== sequence + 1 || value.elapsed_ms < elapsed ||
        (value.elapsed_ms === elapsed && value.schema !== 'ese.v92.o01-product-terminal/v1')) {
      fail('O01_PRODUCT_ORDER');
    }
    if (value.schema === 'ese.v92.o01-product-started/v1') {
      if (started || sequence !== 0) fail('O01_PRODUCT_STARTED');
      started = true; sequence = value.sequence; elapsed = value.elapsed_ms; return value;
    }
    if (!started) fail('O01_PRODUCT_NOT_STARTED');
    if (elapsed >= 0 && value.elapsed_ms - elapsed > maxGapMs) fail('O01_PRODUCT_GAP');
    sequence = value.sequence; elapsed = value.elapsed_ms;
    if (value.schema === 'ese.v92.o01-product-sample/v1') {
      const ordinal = samples + 1;
      const target = ordinal * 60000;
      if (ordinal > durationMs / 60000 || value.sequence !== ordinal + 1 ||
          value.elapsed_ms < target || value.elapsed_ms > target + 10000) {
        fail('O01_PRODUCT_CADENCE');
      }
      samples += 1; if (value.available) available += 1;
      return value;
    }
    if (value.sequence !== 482 || samples !== 480 || available !== 480 ||
        value.elapsed_ms < durationMs || !value.graceful_exit || !value.mappings_absent ||
        !value.ini_restored_byte_exact || !value.preexisting_processes_unchanged) fail('O01_PRODUCT_TERMINAL');
    terminal = value; return value;
  }, snapshot() { return Object.freeze({ sequence, elapsed_ms: elapsed, started, samples, available, terminal }); } });
}

module.exports = Object.freeze({ STATES, ProductStreamError, parseLine, createProductStreamState });
