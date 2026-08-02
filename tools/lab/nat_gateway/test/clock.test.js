'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { ClockError, VirtualMonotonicClock, RealMonotonicClock } = require('../clock');
const { createMappingState, renewMapping, expireMappings } = require('../mapping_model');

const digest = 'a'.repeat(64);
const owner = { kind: 'upnp-journal', instance_id_digest: digest, gateway_identity_digest: digest, description: 'lab-map' };

function expectClockError(action, reasonCode, fieldPath) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof ClockError);
    assert.equal(error.reason_code, reasonCode);
    assert.equal(error.field_path, fieldPath);
    return true;
  });
}

function finiteMapping() {
  return {
    mapping_id: 'map-1', protocol: 'upnp', transport: 'tcp', client_id: 'client-1',
    internal_address: '192.0.2.10', internal_port: 4662, requested_external_port: 4662,
    external_address: '192.0.2.1', external_port: 4662,
    lease: { lifetime_seconds: 1, created_monotonic_ms: 1000, expires_monotonic_ms: 2000 },
    owner, epoch: 10, generation: 4
  };
}

test('RED: virtual clock is deterministic, integer-only, and advances without runtime timers', () => {
  const first = new VirtualMonotonicClock(1000);
  const second = new VirtualMonotonicClock(1000);
  assert.equal(first.now_ms(), 1000);
  assert.equal(first.advance_ms(999), 1999);
  assert.equal(second.advance_ms(999), 1999);
  assert.equal(first.advance_ms(0), 1999);
  expectClockError(() => new VirtualMonotonicClock(-1), 'CLOCK_VALUE_INVALID', '$.start_monotonic_ms');
  expectClockError(() => new VirtualMonotonicClock(1.5), 'CLOCK_VALUE_INVALID', '$.start_monotonic_ms');
  expectClockError(() => first.advance_ms(-1), 'CLOCK_DELTA_INVALID', '$.delta_ms');
  expectClockError(() => first.advance_ms(0.5), 'CLOCK_DELTA_INVALID', '$.delta_ms');
  expectClockError(() => new VirtualMonotonicClock(Number.MAX_SAFE_INTEGER).advance_ms(1), 'CLOCK_OVERFLOW', '$.delta_ms');
});

test('RED: real monotonic clock reads only its injected source and fails closed on invalid or regressing values', () => {
  const defaultClock = new RealMonotonicClock();
  assert.ok(Number.isSafeInteger(defaultClock.now_ms()));

  const readings = [500, 500, 501, 499];
  const clock = new RealMonotonicClock(() => readings.shift());
  assert.equal(clock.now_ms(), 500);
  assert.equal(clock.now_ms(), 500);
  assert.equal(clock.now_ms(), 501);
  expectClockError(() => clock.now_ms(), 'CLOCK_SOURCE_REGRESSION', '$.source_now_ms');
  expectClockError(() => new RealMonotonicClock(null), 'CLOCK_SOURCE_INVALID', '$.source_now_ms');
  expectClockError(() => new RealMonotonicClock(() => 1.5).now_ms(), 'CLOCK_VALUE_INVALID', '$.source_now_ms');
  expectClockError(() => new RealMonotonicClock(() => { throw new Error('no source'); }).now_ms(), 'CLOCK_SOURCE_INVALID', '$.source_now_ms');
  expectClockError(() => clock.advance_ms(1), 'CLOCK_ADVANCE_UNSUPPORTED', '$.delta_ms');
});

test('RED: clock-driven mapping expiry is exact, renewal moves deadline, and an expired mapping cannot revive', () => {
  const clock = new VirtualMonotonicClock(1000);
  let state = createMappingState({ epoch: 10, generation: 4, mappings: [finiteMapping()] });
  state = expireMappings(state, clock.now_ms()).state;
  assert.equal(state.mappings.length, 1, 'mapping does not expire before its deadline');
  clock.advance_ms(999);
  state = expireMappings(state, clock.now_ms()).state;
  assert.equal(state.mappings.length, 1, 'mapping remains live one millisecond before deadline');
  const renewed = renewMapping(state, {
    mapping_id: 'map-1', epoch: 10, generation: 4, owner, lifetime_seconds: 2, now_monotonic_ms: clock.now_ms()
  });
  state = renewed.state;
  assert.equal(renewed.mapping.lease.expires_monotonic_ms, 3999, 'renewal bases deadline on injected monotonic time');
  clock.advance_ms(1999);
  state = expireMappings(state, clock.now_ms()).state;
  assert.equal(state.mappings.length, 1, 'renewed mapping remains live before new deadline');
  clock.advance_ms(1);
  assert.throws(() => renewMapping(state, {
    mapping_id: 'map-1', epoch: 10, generation: 4, owner, lifetime_seconds: 1, now_monotonic_ms: clock.now_ms()
  }), (error) => error.reason_code === 'LEASE_EXPIRED');
  state = expireMappings(state, clock.now_ms()).state;
  assert.equal(state.mappings.length, 0, 'mapping expires exactly at renewed deadline');
  assert.throws(() => renewMapping(state, {
    mapping_id: 'map-1', epoch: 10, generation: 4, owner, lifetime_seconds: 1, now_monotonic_ms: clock.now_ms()
  }), (error) => error.reason_code === 'MAPPING_NOT_FOUND');
});
