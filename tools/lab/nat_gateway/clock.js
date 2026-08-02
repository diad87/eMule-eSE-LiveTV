'use strict';

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

class ClockError extends Error {
  constructor(reasonCode, fieldPath, detail) {
    super(`${reasonCode} at ${fieldPath}: ${detail}`);
    this.name = 'ClockError';
    this.reason_code = reasonCode;
    this.field_path = fieldPath;
  }
}

function fail(reasonCode, fieldPath, detail) {
  throw new ClockError(reasonCode, fieldPath, detail);
}

function assertUint53(value, fieldPath) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('CLOCK_VALUE_INVALID', fieldPath, 'must be an unsigned uint53 millisecond value');
  }
  return value;
}

function assertAdvanceDelta(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('CLOCK_DELTA_INVALID', '$.delta_ms', 'must be a non-negative uint53 millisecond delta');
  }
  return value;
}

/** Deterministic clock for domain tests and the future advance-time command. */
class VirtualMonotonicClock {
  constructor(startMonotonicMs) {
    this._nowMs = assertUint53(startMonotonicMs, '$.start_monotonic_ms');
  }

  now_ms() {
    return this._nowMs;
  }

  advance_ms(deltaMs) {
    const delta = assertAdvanceDelta(deltaMs);
    if (delta > MAX_SAFE - this._nowMs) {
      fail('CLOCK_OVERFLOW', '$.delta_ms', 'advance would exceed uint53 milliseconds');
    }
    this._nowMs += delta;
    return this._nowMs;
  }
}

/**
 * Real monotonic clock. The source is injectable so tests never read a global
 * clock; production may pass a wrapper around performance.now(). It returns
 * integer milliseconds only and refuses a regressing source.
 */
class RealMonotonicClock {
  constructor(sourceNowMs = () => Math.floor(performance.now())) {
    if (typeof sourceNowMs !== 'function') {
      fail('CLOCK_SOURCE_INVALID', '$.source_now_ms', 'must be a monotonic source function');
    }
    this._sourceNowMs = sourceNowMs;
    this._lastMs = undefined;
  }

  now_ms() {
    let value;
    try {
      value = this._sourceNowMs();
    } catch (_) {
      fail('CLOCK_SOURCE_INVALID', '$.source_now_ms', 'source threw instead of returning milliseconds');
    }
    assertUint53(value, '$.source_now_ms');
    if (this._lastMs !== undefined && value < this._lastMs) {
      fail('CLOCK_SOURCE_REGRESSION', '$.source_now_ms', 'monotonic source moved backwards');
    }
    this._lastMs = value;
    return value;
  }

  advance_ms() {
    fail('CLOCK_ADVANCE_UNSUPPORTED', '$.delta_ms', 'real monotonic clocks cannot be advanced');
  }
}

module.exports = {
  ClockError,
  VirtualMonotonicClock,
  RealMonotonicClock
};
